import { Hono } from 'hono'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { eq, and } from 'drizzle-orm'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { config } from '../config'
import { getDb, IS_SQLITE } from '../db'
import { sqliteUsers, sqliteSessions, pgUsers, pgSessions } from '../db/schema'
import {
  generateRefreshToken,
  buildRefreshCookieHeader,
} from '../auth/jwt'
import { getClientIp } from '../lib/client-ip'
import type { UserRole } from '../db/schema'

const app = new Hono()

// ─── OIDC discovery + JWKS cache ─────────────────────────────────────────────

interface Discovery { authorization_endpoint: string; token_endpoint: string; jwks_uri: string }
let discoveryCache: { endpoint: string; data: Discovery } | null = null

async function getDiscovery(): Promise<Discovery> {
  const issuer = config.OIDC_ISSUER!
  if (discoveryCache?.endpoint === issuer) return discoveryCache.data
  const r = await fetch(issuer.replace(/\/$/, '') + '/.well-known/openid-configuration')
  if (!r.ok) throw new Error(`OIDC discovery failed: ${r.status}`)
  const data = await r.json() as Discovery
  discoveryCache = { endpoint: issuer, data }
  return data
}

// JWKS key set cached per jwks_uri
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()
function getJwks(uri: string) {
  if (!jwksCache.has(uri)) jwksCache.set(uri, createRemoteJWKSet(new URL(uri)))
  return jwksCache.get(uri)!
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function tables() {
  if (IS_SQLITE) return { users: sqliteUsers, sessions: sqliteSessions }
  return { users: pgUsers, sessions: pgSessions }
}

function deriveRole(claims: Record<string, unknown>): UserRole {
  if (!config.OIDC_ROLE_CLAIM) return 'viewer'
  const raw = claims[config.OIDC_ROLE_CLAIM]
  if (!raw) return 'viewer'
  const values = Array.isArray(raw) ? raw.map(String) : [String(raw)]
  return values.includes(config.OIDC_ADMIN_VALUE) ? 'admin' : 'viewer'
}

// ─── GET /web/auth/oidc/config — public ──────────────────────────────────────

app.get('/config', (c) => {
  return c.json({
    mode: config.OIDC_MODE,
    client_id: config.OIDC_CLIENT_ID ?? null,
    issuer: config.OIDC_ISSUER ?? null,
  })
})

// ─── GET /web/auth/oidc/start — redirect to IdP with PKCE + nonce ────────────

app.get('/start', async (c) => {
  if (config.OIDC_MODE === 'disabled' || !config.OIDC_ISSUER || !config.OIDC_CLIENT_ID) {
    return c.text('OIDC not configured', 400)
  }
  let discovery: Discovery
  try { discovery = await getDiscovery() } catch (e) {
    console.error('[oidc] discovery failed:', e)
    return c.text('OIDC discovery failed', 502)
  }

  const codeVerifier = b64url(randomBytes(32))
  const codeChallenge = b64url(createHash('sha256').update(codeVerifier).digest())
  const state = b64url(randomBytes(16))
  const nonce = b64url(randomBytes(16))
  const redirectUri = new URL('/web/auth/oidc/callback', config.ORIGIN).toString()

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.OIDC_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  const cookieValue = Buffer.from(JSON.stringify({ codeVerifier, state, nonce })).toString('base64')
  const secure = config.ORIGIN.startsWith('https') ? '; Secure' : ''
  c.header('Set-Cookie', `oidc_pkce=${cookieValue}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600${secure}`)
  return c.redirect(`${discovery.authorization_endpoint}?${params}`)
})

// ─── GET /web/auth/oidc/callback — verify token, find/create user, issue session

app.get('/callback', async (c) => {
  if (config.OIDC_MODE === 'disabled' || !config.OIDC_ISSUER || !config.OIDC_CLIENT_ID) {
    return c.text('OIDC not configured', 400)
  }

  const { code, state, error: oidcError } = c.req.query()
  if (oidcError) return c.html(errPage(`IdP error: ${String(oidcError).slice(0, 200)}`))
  if (!code) return c.html(errPage('Missing code'))

  // Validate PKCE cookie
  const cookie = c.req.header('cookie') ?? ''
  const pkceMatch = cookie.match(/oidc_pkce=([^;]+)/)
  if (!pkceMatch) return c.html(errPage('Missing PKCE state cookie — try again'))
  let pkceData: { codeVerifier: string; state: string; nonce: string }
  try { pkceData = JSON.parse(Buffer.from(pkceMatch[1], 'base64').toString()) }
  catch { return c.html(errPage('Invalid PKCE cookie')) }
  if (pkceData.state !== state) return c.html(errPage('State mismatch — possible CSRF'))

  const secure = config.ORIGIN.startsWith('https') ? '; Secure' : ''
  c.header('Set-Cookie', `oidc_pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`)

  // Fetch discovery + exchange code for tokens
  let discovery: Discovery
  try { discovery = await getDiscovery() } catch (e) { return c.html(errPage(`Discovery error: ${e}`)) }

  const redirectUri = new URL('/web/auth/oidc/callback', config.ORIGIN).toString()
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: config.OIDC_CLIENT_ID,
    code_verifier: pkceData.codeVerifier,
  })
  if (config.OIDC_CLIENT_SECRET) body.set('client_secret', config.OIDC_CLIENT_SECRET)

  const tokenRes = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!tokenRes.ok) {
    // Avoid leaking full IdP error body (may contain sensitive info); log it server-side only
    const errBody = await tokenRes.text()
    console.error('[oidc] token exchange failed:', tokenRes.status, errBody.slice(0, 500))
    return c.html(errPage(`Token exchange failed (HTTP ${tokenRes.status})`))
  }
  const tokens = await tokenRes.json() as { id_token?: string }
  if (!tokens.id_token) return c.html(errPage('No id_token in response'))

  // ── Verify ID token: signature (JWKS) + iss + aud + exp + nonce ─────────────
  let claims: Record<string, unknown> & { sub: string; preferred_username?: string; email?: string }
  try {
    const jwks = getJwks(discovery.jwks_uri)
    const { payload } = await jwtVerify(tokens.id_token, jwks, {
      issuer: config.OIDC_ISSUER,
      audience: config.OIDC_CLIENT_ID,
    })
    // jwtVerify already checks exp; verify nonce to prevent replay
    if (payload['nonce'] !== pkceData.nonce) {
      return c.html(errPage('Nonce mismatch — possible replay attack'))
    }
    claims = payload as typeof claims
  } catch (e) {
    console.error('[oidc] ID token verification failed:', e)
    return c.html(errPage('ID token verification failed'))
  }

  const iss = config.OIDC_ISSUER
  const sub = claims.sub

  // ── Find or create shadow user by (oidc_iss, oidc_sub) — NOT by username ────
  const db = await getDb()
  const d = db as any
  const { users, sessions } = tables()

  let [user] = await d.select().from(users).where(
    and(eq(users.oidc_iss, iss), eq(users.oidc_sub, sub))
  ).limit(1)

  if (!user) {
    const role = deriveRole(claims)
    // Namespace username to prevent collision with local accounts
    const baseUsername = `sso:${sub.slice(0, 48)}`
    let username = baseUsername
    let suffix = 0
    while (true) {
      const [existing] = await d.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1)
      if (!existing) break
      suffix++
      username = `${baseUsername}_${suffix}`
    }
    await d.insert(users).values({ username, password_hash: null, role, oidc_iss: iss, oidc_sub: sub })
    ;[user] = await d.select().from(users).where(
      and(eq(users.oidc_iss, iss), eq(users.oidc_sub, sub))
    ).limit(1)
  }
  // Subsequent logins use the DB role (admin can override in panel)

  // Create DB session
  const sessionId = randomUUID()
  const { raw: refreshRaw, hash: refreshHash, expiresAt } = generateRefreshToken()
  const ip = getClientIp(c)
  const ua = c.req.header('user-agent')?.slice(0, 512) ?? null

  await d.insert(sessions).values({
    id: sessionId,
    user_id: user.id,
    refresh_token_hash: refreshHash,
    expires_at: expiresAt,
    ip,
    ua,
  })
  await d.update(users).set({ last_login: new Date() }).where(eq(users.id, user.id))

  // append: true — Hono's c.header() REPLACES by default, which silently
  // dropped the oidc_pkce-clearing Set-Cookie emitted above and left the
  // single-use PKCE state cookie in the browser for its full 10-minute TTL.
  c.header('Set-Cookie', buildRefreshCookieHeader(refreshRaw, expiresAt), { append: true })
  return c.html(ssoLandingPage())
})

// No token is handed to the page: the access token is memory-only on the
// client (never in localStorage, where any XSS payload could read it). The
// SPA re-mints it via POST /web/auth/refresh from the httpOnly refresh
// cookie set above, then loads the user via /web/auth/me.
function ssoLandingPage(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Signing in…</title></head><body>
<script>
location.replace('/dashboard');
</script>
<p>Signing in, please wait…</p>
</body></html>`
}

function errPage(msg: string): string {
  const safe = msg.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  return `<!doctype html><html><head><meta charset="utf-8"><title>SSO Error</title></head>
<body style="font-family:sans-serif;padding:2rem"><h2>SSO Error</h2><p>${safe}</p>
<a href="/login">Back to login</a></body></html>`
}

export const oidcRoute = app
