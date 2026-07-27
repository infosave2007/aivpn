import { Hono } from 'hono'
import { z } from 'zod'
import { zValidator } from '@hono/zod-validator'
import { eq, and, gt, ne, or, isNull, lt } from 'drizzle-orm'
import { createHmac, randomUUID } from 'node:crypto'
import { getDb, IS_SQLITE } from '../db'
import {
  sqliteUsers, sqliteSessions, sqlitePasskeys,
  pgUsers, pgSessions, pgPasskeys,
} from '../db/schema'
import { hashPassword, verifyPassword } from '../auth/argon'
import {
  signAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  buildRefreshCookieHeader,
  buildClearRefreshCookieHeader,
  REFRESH_COOKIE_NAME,
} from '../auth/jwt'
import { generateTotpSecret, verifyTotpToken, encryptTotpSecret, decryptTotpSecret } from '../auth/totp'
import {
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication,
  newPasskeyId,
} from '../auth/passkey'
import { requireAuth, requireAdmin } from '../auth/middleware'
import { writeAudit } from '../audit'
import { checkRateLimit, isRateLimited, recordRateLimitEvent } from '../ratelimit'
import { config } from '../config'
import { getClientIp } from '../lib/client-ip'
import type { UserRole } from '../db/schema'

// ─── Zod schemas ──────────────────────────────────────────────────────────────

const LoginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256).optional(),
  totp_token: z.string().length(6).regex(/^\d+$/).optional(),
})

const RegisterSchema = z.object({
  username: z.string().min(3).max(64).regex(/^[a-zA-Z0-9_-]+$/),
  password: z.string().min(12).max(256),
  role: z.enum(['admin', 'viewer']).default('viewer'),
})

const ChangePasswordSchema = z.object({
  current_password: z.string().min(1),
  new_password: z.string().min(12).max(256),
})

const TotpVerifySchema = z.object({
  token: z.string().length(6).regex(/^\d+$/),
})

const PasskeyNameSchema = z.object({
  name: z.string().min(1).max(64).default('Passkey'),
})

const PasskeyRegisterSchema = z.object({
  response: z.record(z.unknown()),
  name: z.string().max(64).optional(),
})

const PasskeyAuthSchema = z.object({
  response: z.object({ id: z.string().min(1) }).passthrough(),
})

// ─── Helpers ──────────────────────────────────────────────────────────────────
// Client IP resolution lives in ../lib/client-ip (honours AIVPN_WEB_TRUST_PROXY).

function getUA(c: { req: { header: (h: string) => string | undefined } }): string | null {
  // Bounded: the UA is client-controlled and stored per session row.
  return c.req.header('user-agent')?.slice(0, 512) ?? null
}

// Argon2id hash of a random unguessable value. Verified on the unknown-user
// login path so response timing is the same whether or not a username exists
// (otherwise the early return is a username-enumeration timing oracle).
const DUMMY_PASSWORD_HASH = await hashPassword(randomUUID())

// Deterministic fake passkey descriptor for unknown usernames: authentication
// options must look the same for existing and non-existing accounts, and be
// stable across repeated queries for the same username (randomising them per
// request would itself be an enumeration signal).
function fakePasskeyFor(username: string): { credential_id: string; transports: string[] } {
  const id = createHmac('sha256', config.JWT_SECRET)
    .update(`fake-passkey:${username}`)
    .digest('base64url')
  return { credential_id: id, transports: ['internal'] }
}

// Universal table accessors — return the right table based on driver
function tables() {
  if (IS_SQLITE) {
    return { users: sqliteUsers, sessions: sqliteSessions, passkeys: sqlitePasskeys }
  }
  return { users: pgUsers, sessions: pgSessions, passkeys: pgPasskeys }
}

// ─── Router ──────────────────────────────────────────────────────────────────

const auth = new Hono()

// POST /web/auth/login
auth.post('/login', zValidator('json', LoginSchema), async (c) => {
  const body = c.req.valid('json')

  // OIDC exclusive mode disables local password login entirely — otherwise an
  // admin who selected SSO-only still has a working password path (incl. the
  // bootstrap admin account), silently not enforcing the policy.
  if (config.OIDC_MODE === 'exclusive') {
    return c.json({ error: 'Password login is disabled (SSO required).' }, 403)
  }

  // Per-username rate limit — cannot be bypassed by rotating source IP.
  // Complements the per-IP rate limit applied by the global middleware in index.ts.
  // Only FAILED credential attempts consume slots (recordLoginFailure below):
  // successful logins and the valid-password-awaiting-TOTP step are free, so a
  // legitimate two-step login costs zero slots and an attacker cannot lock a
  // known username out any faster than by actual failed brute-force attempts.
  // Brute-force protection is unchanged: the check runs before password
  // verification and every wrong password/TOTP still burns a slot.
  const loginRateKey = `login_user:${body.username}`
  if (isRateLimited(loginRateKey, config.AUTH_RATE_MAX, config.AUTH_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests. Please wait before retrying.' }, 429)
  }
  const recordLoginFailure = () => recordRateLimitEvent(loginRateKey, config.AUTH_RATE_MAX)

  const db = await getDb()
  const { users, sessions } = tables()
  const ip = getClientIp(c)
  const ua = getUA(c)

  const d = db as any

  // Find user
  const [user] = await d.select().from(users).where(eq(users.username, body.username)).limit(1)

  if (!user) {
    // Burn the same Argon2id work as the real-user path (timing equalisation).
    await verifyPassword(DUMMY_PASSWORD_HASH, body.password ?? '')
    recordLoginFailure()
    await writeAudit(db, null, 'login', body.username, 'fail', ip)
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  // Passkey-only users cannot use password login.
  // Burn the same Argon2id work as every other failure path: a fast 401 here
  // (and on the branches below) would reveal that the username exists —
  // the same enumeration oracle DUMMY_PASSWORD_HASH exists to prevent.
  if (user.passkey_only) {
    await verifyPassword(DUMMY_PASSWORD_HASH, body.password ?? '')
    recordLoginFailure()
    await writeAudit(db, user.id, 'login', body.username, 'fail', ip)
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  if (!user.password_hash || !body.password) {
    // Same timing equalisation (covers SSO shadow accounts and omitted password).
    await verifyPassword(DUMMY_PASSWORD_HASH, body.password ?? '')
    recordLoginFailure()
    await writeAudit(db, user.id, 'login', body.username, 'fail', ip)
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const passwordOk = await verifyPassword(user.password_hash, body.password)
  if (!passwordOk) {
    recordLoginFailure()
    await writeAudit(db, user.id, 'login', body.username, 'fail', ip)
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  // TOTP 2FA check
  if (user.totp_enabled) {
    if (!body.totp_token) {
      // Not an error: password was correct, a second factor is required.
      // Return 200 so the client can read the flag (apiJson throws on non-2xx).
      return c.json({ totp_required: true })
    }
    let loginDecryptedSecret: string
    try {
      loginDecryptedSecret = decryptTotpSecret(user.totp_secret!)
    } catch {
      return c.json({ error: 'TOTP not configured on this server' }, 503)
    }
    const acceptedStep = verifyTotpToken(loginDecryptedSecret, body.totp_token)
    // One-time use (RFC 6238 §5.2): atomically claim the time step — the
    // conditional update rejects a replayed code (step <= last accepted) and
    // closes the race between two concurrent logins presenting the same code.
    const claimed = acceptedStep === null ? [] : await d
      .update(users)
      .set({ totp_last_step: acceptedStep })
      .where(and(
        eq(users.id, user.id),
        or(isNull(users.totp_last_step), lt(users.totp_last_step, acceptedStep)),
      ))
      .returning({ id: users.id })
    if (acceptedStep === null || claimed.length === 0) {
      // A wrong (or replayed) TOTP code is a failed attempt too — 6-digit
      // codes are brute-forceable, so they must consume rate-limit slots.
      recordLoginFailure()
      await writeAudit(db, user.id, 'login_totp', body.username, 'fail', ip)
      return c.json({ error: 'Invalid TOTP token' }, 401)
    }
  }

  // Issue tokens
  const sessionId = randomUUID()
  const { raw, hash, expiresAt } = generateRefreshToken()

  await d.insert(sessions).values({
    id: sessionId,
    user_id: user.id,
    refresh_token_hash: hash,
    expires_at: expiresAt,
    ip,
    ua,
  })

  // Update last_login
  await d.update(users).set({
    last_login: new Date(),
  }).where(eq(users.id, user.id))

  const accessToken = await signAccessToken({
    sub: String(user.id),
    role: user.role as UserRole,
    session_version: user.session_version,
    session_id: sessionId,
  })

  await writeAudit(db, user.id, 'login', body.username, 'ok', ip)

  c.header('Set-Cookie', buildRefreshCookieHeader(raw, expiresAt))
  return c.json({
    access_token: accessToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      totp_enabled: user.totp_enabled,
    },
  })
})

// POST /web/auth/logout
auth.post('/logout', requireAuth(), async (c) => {
  const user = c.get('user')
  const db = await getDb()
  const { sessions } = tables()
  const d = db as any

  await d.delete(sessions).where(eq(sessions.id, user.session_id))
  await writeAudit(db, user.id, 'logout', null, 'ok', getClientIp(c))

  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true })
})

// POST /web/auth/refresh
//
// Rotation grace: two tabs sharing the same refresh cookie can both POST
// /refresh at browser startup (the in-tab coalescing in client/src/lib/api.ts
// cannot help across tabs). Without grace, the loser presents the
// just-rotated-away token, gets 401 and logs the whole browser out. So each
// rotation remembers the PREVIOUS token hash for a short window; presenting it
// within that window yields a fresh ACCESS token only — no new rotation, no
// Set-Cookie — because the cookie jar already holds the newer refresh token.
// Security: exactly ONE previous generation is honoured (prev_token_hash is
// overwritten on every rotation), the window is 10 s, and a grace hit can
// never mint a new refresh token — so token-theft reuse detection semantics
// are effectively unchanged beyond that tiny window.
const REFRESH_ROTATION_GRACE_MS = 10_000

// Defense in depth alongside the session_id-keyed rate-limit buckets in
// index.ts (which already stop a refresh loop from resetting the /api/v1 and
// /web/metrics counters): cap how often any single session may mint a fresh
// token pair here too, independent of caller IP. The per-IP /web/auth/*
// limiter in index.ts only charges FAILED requests, so a successful refresh
// loop was otherwise completely free. Same generous budget as the other auth
// limits — normal usage is one proactive refresh per access-token TTL (15 min)
// plus the occasional cross-tab burst, both far under this.
function refreshRateLimited(sessionId: string): boolean {
  return !checkRateLimit(`refresh:${sessionId}`, config.AUTH_RATE_MAX, config.AUTH_RATE_WINDOW_MS)
}

auth.post('/refresh', async (c) => {
  const db = await getDb()
  const { users, sessions } = tables()
  const d = db as any

  // Read refresh token from httpOnly cookie
  const cookieHeader = c.req.header('cookie') ?? ''
  const rtRaw = cookieHeader
    .split(';')
    .map((s) => s.trim())
    .find((s) => s.startsWith(`${REFRESH_COOKIE_NAME}=`))
    ?.slice(REFRESH_COOKIE_NAME.length + 1)

  if (!rtRaw) {
    return c.json({ error: 'No refresh token' }, 401)
  }

  const rtHash = hashRefreshToken(rtRaw)
  const now = new Date()

  const [session] = await d
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.refresh_token_hash, rtHash),
        gt(sessions.expires_at, now),
      ),
    )
    .limit(1)

  if (!session) {
    // Cross-tab race grace: accept the immediately previous token for a short
    // window after rotation (see comment above). Access token only — no
    // rotation, no Set-Cookie.
    const [graceSession] = await d
      .select()
      .from(sessions)
      .where(
        and(
          eq(sessions.prev_token_hash, rtHash),
          gt(sessions.prev_expires_at, now),
          gt(sessions.expires_at, now),
        ),
      )
      .limit(1)

    if (!graceSession) {
      c.header('Set-Cookie', buildClearRefreshCookieHeader())
      return c.json({ error: 'Invalid or expired refresh token' }, 401)
    }

    if (refreshRateLimited(graceSession.id)) {
      return c.json({ error: 'Too many requests. Please wait before retrying.' }, 429)
    }

    const [graceUser] = await d.select().from(users).where(eq(users.id, graceSession.user_id)).limit(1)
    if (!graceUser) {
      return c.json({ error: 'User not found' }, 401)
    }

    const graceAccessToken = await signAccessToken({
      sub: String(graceUser.id),
      role: graceUser.role as UserRole,
      session_version: graceUser.session_version,
      session_id: graceSession.id,
    })
    return c.json({ access_token: graceAccessToken })
  }

  if (refreshRateLimited(session.id)) {
    return c.json({ error: 'Too many requests. Please wait before retrying.' }, 429)
  }

  const [user] = await d.select().from(users).where(eq(users.id, session.user_id)).limit(1)
  if (!user) {
    return c.json({ error: 'User not found' }, 401)
  }

  // Rotate refresh token; remember the outgoing hash for the grace window.
  const { raw: newRaw, hash: newHash, expiresAt } = generateRefreshToken()

  await d
    .update(sessions)
    .set({
      refresh_token_hash: newHash,
      expires_at: expiresAt,
      prev_token_hash: session.refresh_token_hash,
      prev_expires_at: new Date(Date.now() + REFRESH_ROTATION_GRACE_MS),
    })
    .where(eq(sessions.id, session.id))

  const accessToken = await signAccessToken({
    sub: String(user.id),
    role: user.role as UserRole,
    session_version: user.session_version,
    session_id: session.id,
  })

  c.header('Set-Cookie', buildRefreshCookieHeader(newRaw, expiresAt))
  return c.json({ access_token: accessToken })
})

// POST /web/auth/register — admin only
auth.post('/register', requireAdmin, zValidator('json', RegisterSchema), async (c) => {
  const body = c.req.valid('json')
  const db = await getDb()
  const { users } = tables()
  const d = db as any
  const ip = getClientIp(c)
  const actor = c.get('user')

  const passwordHash = await hashPassword(body.password)

  try {
    const [created] = await d.insert(users).values({
      username: body.username,
      password_hash: passwordHash,
      role: body.role,
    }).returning({ id: users.id, username: users.username, role: users.role })

    await writeAudit(db, actor.id, 'register_user', body.username, 'ok', ip)
    return c.json({ id: created.id, username: created.username, role: created.role }, 201)
  } catch (err: any) {
    if (err?.message?.includes('UNIQUE') || err?.code === '23505') {
      return c.json({ error: 'Username already exists' }, 409)
    }
    throw err
  }
})

// GET /web/auth/me
auth.get('/me', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { users } = tables()
  const d = db as any

  const [user] = await d.select({
    id: users.id,
    username: users.username,
    role: users.role,
    totp_enabled: users.totp_enabled,
    passkey_only: users.passkey_only,
    created_at: users.created_at,
    last_login: users.last_login,
  }).from(users).where(eq(users.id, u.id)).limit(1)

  if (!user) return c.json({ error: 'User not found' }, 404)
  return c.json(user)
})

// POST /web/auth/change-password
auth.post('/change-password', requireAuth(), zValidator('json', ChangePasswordSchema), async (c) => {
  const u = c.get('user')
  const body = c.req.valid('json')
  const db = await getDb()
  const { users, sessions } = tables()
  const d = db as any
  const ip = getClientIp(c)

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 404)

  if (user.passkey_only) {
    return c.json({ error: 'Passkey-only accounts cannot set a password' }, 400)
  }

  if (!user.password_hash || !(await verifyPassword(user.password_hash, body.current_password))) {
    await writeAudit(db, u.id, 'change_password', null, 'fail', ip)
    return c.json({ error: 'Current password is incorrect' }, 401)
  }

  const newHash = await hashPassword(body.new_password)
  await d.update(users).set({
    password_hash: newHash,
    session_version: user.session_version + 1,
  }).where(eq(users.id, u.id))
  // Revoke ALL refresh tokens so every device must re-authenticate
  await d.delete(sessions).where(eq(sessions.user_id, u.id))

  await writeAudit(db, u.id, 'change_password', null, 'ok', ip)
  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true, logout: true })
})

// ─── TOTP ─────────────────────────────────────────────────────────────────────

// GET /web/auth/totp/setup
auth.get('/totp/setup', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { users } = tables()
  const d = db as any

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 404)
  if (user.totp_enabled) return c.json({ error: 'TOTP is already enabled' }, 409)

  const setup = await generateTotpSecret(user.username)

  // Store AES-256-GCM encrypted secret; confirmed by /totp/verify
  let encryptedSecret: string
  try {
    encryptedSecret = encryptTotpSecret(setup.secret)
  } catch {
    return c.json({ error: 'TOTP not configured on this server' }, 503)
  }
  await d.update(users).set({ totp_secret: encryptedSecret }).where(eq(users.id, u.id))

  return c.json({
    secret: setup.secret,
    otpauth_url: setup.otpauth_url,
    qr_data_url: setup.qr_data_url,
  })
})

// POST /web/auth/totp/verify
auth.post('/totp/verify', requireAuth(), zValidator('json', TotpVerifySchema), async (c) => {
  const u = c.get('user')
  const body = c.req.valid('json')
  const db = await getDb()
  const { users, sessions } = tables()
  const d = db as any
  const ip = getClientIp(c)

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 404)
  if (!user.totp_secret) return c.json({ error: 'Call /totp/setup first' }, 400)
  if (user.totp_enabled) return c.json({ error: 'TOTP is already enabled' }, 409)

  let decryptedSecret: string
  try {
    decryptedSecret = decryptTotpSecret(user.totp_secret)
  } catch {
    return c.json({ error: 'TOTP not configured on this server' }, 503)
  }
  const enableStep = verifyTotpToken(decryptedSecret, body.token)
  if (enableStep === null) {
    await writeAudit(db, u.id, 'totp_enable', null, 'fail', ip)
    return c.json({ error: 'Invalid TOTP token' }, 401)
  }

  await d.update(users).set({
    totp_enabled: true,
    // Consume the setup code too, so it cannot be replayed as the first login code.
    totp_last_step: enableStep,
    session_version: user.session_version + 1,
  }).where(eq(users.id, u.id))
  await d.delete(sessions).where(eq(sessions.user_id, u.id))

  await writeAudit(db, u.id, 'totp_enable', null, 'ok', ip)
  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true, logout: true })
})

// DELETE /web/auth/totp
auth.delete('/totp', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { users, sessions } = tables()
  const d = db as any
  const ip = getClientIp(c)

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 404)

  await d.update(users).set({
    totp_enabled: false,
    totp_secret: null,
    totp_last_step: null,
    session_version: user.session_version + 1,
  }).where(eq(users.id, u.id))
  await d.delete(sessions).where(eq(sessions.user_id, u.id))

  await writeAudit(db, u.id, 'totp_disable', null, 'ok', ip)
  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true, logout: true })
})

// ─── Passkey registration ─────────────────────────────────────────────────────

// GET /web/auth/passkey/registration-options
auth.get('/passkey/registration-options', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { users, passkeys } = tables()
  const d = db as any

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 404)

  const existing = await d.select({
    credential_id: passkeys.credential_id,
    transports: passkeys.transports,
  }).from(passkeys).where(eq(passkeys.user_id, u.id))

  const existingNorm = existing.map((p: any) => ({
    credential_id: p.credential_id,
    transports: IS_SQLITE && typeof p.transports === 'string'
      ? JSON.parse(p.transports)
      : p.transports,
  }))

  const options = await getRegistrationOptions(u.id, user.username, existingNorm)
  return c.json(options)
})

// POST /web/auth/passkey/register
auth.post('/passkey/register', requireAuth(), zValidator('json', PasskeyRegisterSchema), async (c) => {
  const u = c.get('user')
  const body = c.req.valid('json')
  const db = await getDb()
  const { passkeys, users, sessions } = tables()
  const d = db as any
  const ip = getClientIp(c)

  let verification
  try {
    verification = await verifyRegistration(u.id, body.response)
  } catch (err: any) {
    await writeAudit(db, u.id, 'passkey_register', null, 'fail', ip)
    return c.json({ error: err.message ?? 'Registration failed' }, 400)
  }

  const { registrationInfo } = verification
  const cred = registrationInfo!.credential

  const transportsRaw = registrationInfo!.credential.transports ?? []
  const transports = IS_SQLITE ? JSON.stringify(transportsRaw) : transportsRaw

  await d.insert(passkeys).values({
    id: newPasskeyId(),
    user_id: u.id,
    credential_id: cred.id,
    public_key: Buffer.from(cred.publicKey).toString('base64url'),
    counter: cred.counter,
    aaguid: registrationInfo!.aaguid ?? null,
    transports,
    name: (typeof body.name === 'string' ? body.name.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 64) : '') || 'Passkey',
  })

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  await d.update(users).set({ session_version: user.session_version + 1 }).where(eq(users.id, u.id))
  await d.delete(sessions).where(eq(sessions.user_id, u.id))

  await writeAudit(db, u.id, 'passkey_register', cred.id, 'ok', ip)
  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true, logout: true })
})

// ─── Passkey authentication ───────────────────────────────────────────────────

// GET /web/auth/passkey/authentication-options
// Can be called unauthenticated (for passwordless login) or authenticated (2FA)
auth.get('/passkey/authentication-options', async (c) => {
  const username = c.req.query('username')
  const db = await getDb()
  const { users, passkeys } = tables()
  const d = db as any

  // userKey is used to correlate challenge with the verify step
  let userKey = 'anon'
  let allowedPasskeys: { credential_id: string; transports: string[] | null }[] | undefined

  if (username) {
    const [user] = await d.select().from(users).where(eq(users.username, username)).limit(1)
    if (user) {
      userKey = `user:${user.id}`
      const pks = await d.select({
        credential_id: passkeys.credential_id,
        transports: passkeys.transports,
      }).from(passkeys).where(eq(passkeys.user_id, user.id))

      allowedPasskeys = pks.map((p: any) => ({
        credential_id: p.credential_id,
        transports: IS_SQLITE && typeof p.transports === 'string'
          ? JSON.parse(p.transports)
          : p.transports,
      }))
    } else {
      // Unknown username: return an indistinguishable options shape (a stable
      // fake credential) instead of the discoverable-credential shape, which
      // would reveal whether the account exists. Any attempt to authenticate
      // with the fake credential fails at the passkey lookup in /authenticate.
      allowedPasskeys = [fakePasskeyFor(username)]
    }
  }

  const options = await getAuthenticationOptions(userKey, allowedPasskeys)
  return c.json(options)
})

// POST /web/auth/passkey/authenticate
auth.post('/passkey/authenticate', zValidator('json', PasskeyAuthSchema), async (c) => {
  const body = c.req.valid('json')
  const db = await getDb()
  const { users, sessions, passkeys } = tables()
  const d = db as any
  const ip = getClientIp(c)
  const ua = getUA(c)

  const credentialId: string = body.response?.id

  // Find passkey record first — derive challenge key from DB, never trust client-supplied userKey
  const [pk] = await d.select().from(passkeys).where(eq(passkeys.credential_id, credentialId)).limit(1)
  if (!pk) {
    return c.json({ error: 'Passkey not found' }, 401)
  }

  // Build challenge key server-side from the authenticated user in the DB record
  const serverUserKey = `user:${pk.user_id}`

  let verification
  try {
    verification = await verifyAuthentication(serverUserKey, body.response, {
      credential_id: pk.credential_id,
      public_key: pk.public_key,
      counter: pk.counter,
      transports: IS_SQLITE && typeof pk.transports === 'string'
        ? JSON.parse(pk.transports)
        : pk.transports,
    })
  } catch (err: any) {
    await writeAudit(db, pk.user_id, 'passkey_auth', credentialId, 'fail', ip)
    return c.json({ error: err.message ?? 'Authentication failed' }, 401)
  }

  // Update passkey counter and last_used_at
  await d.update(passkeys).set({
    counter: verification.authenticationInfo.newCounter,
    last_used_at: new Date(),
  }).where(eq(passkeys.id, pk.id))

  const [user] = await d.select().from(users).where(eq(users.id, pk.user_id)).limit(1)
  if (!user) return c.json({ error: 'User not found' }, 401)

  // Issue tokens
  const sessionId = randomUUID()
  const { raw, hash, expiresAt } = generateRefreshToken()

  await d.insert(sessions).values({
    id: sessionId,
    user_id: user.id,
    refresh_token_hash: hash,
    expires_at: expiresAt,
    ip,
    ua,
  })

  await d.update(users).set({
    last_login: new Date(),
  }).where(eq(users.id, user.id))

  const accessToken = await signAccessToken({
    sub: String(user.id),
    role: user.role as UserRole,
    session_version: user.session_version,
    session_id: sessionId,
  })

  await writeAudit(db, user.id, 'passkey_auth', credentialId, 'ok', ip)

  c.header('Set-Cookie', buildRefreshCookieHeader(raw, expiresAt))
  return c.json({
    access_token: accessToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      totp_enabled: user.totp_enabled,
    },
  })
})

// GET /web/auth/passkeys — list current user's passkeys
auth.get('/passkeys', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { passkeys } = tables()
  const d = db as any

  const rows = await d.select({
    id: passkeys.id,
    name: passkeys.name,
    aaguid: passkeys.aaguid,
    created_at: passkeys.created_at,
    last_used_at: passkeys.last_used_at,
  }).from(passkeys).where(eq(passkeys.user_id, u.id))

  return c.json(rows)
})

// DELETE /web/auth/passkeys/:id
auth.delete('/passkeys/:id', requireAuth(), async (c) => {
  const u = c.get('user')
  const passkeyId = c.req.param('id')
  const db = await getDb()
  const { passkeys, users, sessions } = tables()
  const d = db as any
  const ip = getClientIp(c)

  const [pk] = await d.select().from(passkeys)
    .where(and(eq(passkeys.id, passkeyId), eq(passkeys.user_id, u.id)))
    .limit(1)

  if (!pk) return c.json({ error: 'Passkey not found' }, 404)

  await d.delete(passkeys).where(and(eq(passkeys.id, passkeyId), eq(passkeys.user_id, u.id)))

  const [user] = await d.select().from(users).where(eq(users.id, u.id)).limit(1)
  await d.update(users).set({ session_version: user.session_version + 1 }).where(eq(users.id, u.id))
  await d.delete(sessions).where(eq(sessions.user_id, u.id))

  await writeAudit(db, u.id, 'passkey_remove', passkeyId, 'ok', ip)
  c.header('Set-Cookie', buildClearRefreshCookieHeader())
  return c.json({ ok: true, logout: true })
})

// ─── Sessions management ──────────────────────────────────────────────────────

// GET /web/auth/sessions
auth.get('/sessions', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { sessions } = tables()
  const d = db as any

  const rows = await d.select({
    id: sessions.id,
    ip: sessions.ip,
    ua: sessions.ua,
    created_at: sessions.created_at,
    expires_at: sessions.expires_at,
  }).from(sessions).where(eq(sessions.user_id, u.id))

  return c.json(rows.map((r: any) => ({ ...r, current: r.id === u.session_id })))
})

// DELETE /web/auth/sessions/:id
auth.delete('/sessions/:id', requireAuth(), async (c) => {
  const u = c.get('user')
  const sessionId = c.req.param('id')
  const db = await getDb()
  const { sessions } = tables()
  const d = db as any

  await d.delete(sessions).where(
    and(eq(sessions.id, sessionId), eq(sessions.user_id, u.id)),
  )

  await writeAudit(db, u.id, 'revoke_session', sessionId, 'ok', getClientIp(c))
  return c.json({ ok: true })
})

// DELETE /web/auth/sessions — revoke all except current
auth.delete('/sessions', requireAuth(), async (c) => {
  const u = c.get('user')
  const db = await getDb()
  const { sessions } = tables()
  const d = db as any

  await d.delete(sessions).where(
    and(
      eq(sessions.user_id, u.id),
      ne(sessions.id, u.session_id),
    ),
  )

  await writeAudit(db, u.id, 'revoke_all_sessions', null, 'ok', getClientIp(c))
  return c.json({ ok: true })
})

export { auth as authRoute }
