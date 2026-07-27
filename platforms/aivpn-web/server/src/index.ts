import { Hono } from 'hono'
import type { Context, Next } from 'hono'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { secureHeaders } from 'hono/secure-headers'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { eq } from 'drizzle-orm'
import { randomBytes } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { config, IS_SQLITE } from './config'
import { getDb } from './db'
import { sqliteUsers, pgUsers } from './db/schema'
import { runMigrations } from './db/migrate'
import { hashPassword } from './auth/argon'
import { authRoute } from './routes/auth'
import { oidcRoute } from './routes/oidc'
import { proxyRoute } from './routes/proxy'
import { metricsRoute } from './routes/metrics'
import { eventsRoute } from './routes/events'
import { checkRateLimit, isRateLimited, recordRateLimitEvent, scheduleRateLimitCleaner } from './ratelimit'
import { getClientIp } from './lib/client-ip'
import { verifyAccessToken } from './auth/jwt'

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Simple in-process sliding window rate limiter (no Redis required).
// For multi-instance deployments, swap this for a Redis-backed limiter.

scheduleRateLimitCleaner(Math.max(config.AUTH_RATE_WINDOW_MS, config.API_RATE_WINDOW_MS))

// ─── App setup ────────────────────────────────────────────────────────────────

const app = new Hono()

// Security headers
app.use('*', secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    // 'unsafe-inline' is deliberate: SvelteKit (adapter-static) emits a
    // per-build inline bootstrap script in every prerendered HTML page, served
    // raw via serveStatic — there is no templating layer to inject a nonce,
    // and dev mode proxies Vite's inline HMR scripts. Hash-based CSP would
    // have to re-hash every dist/*.html at startup and would break dev/HMR;
    // a wrong hash bricks hydration. Revisit if serving moves to SSR.
    // Residual risk, accepted: this CSP does NOT stop inline-script
    // injection (reflected/stored XSS) — it only blocks *externally hosted*
    // script/style origins other than 'self'. It relies entirely on the
    // absence of unsanitized-HTML sinks elsewhere in the app (verified: no
    // XSS sinks found in the client). Any future innerHTML-with-user-data or
    // similar sink would be exploitable despite this header.
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: ["'none'"],
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
  },
}))

// CORS — same-origin only in production; allow the SvelteKit dev server in dev
app.use('*', cors({
  origin: config.DEV_MODE
    ? [`http://localhost:${config.SVELTEKIT_DEV_PORT}`, config.ORIGIN]
    : config.ORIGIN,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
  maxAge: 86400,
}))

// Request logger. Redact SSE credentials in the query string: the dashboard
// opens EventSource('/web/events?ticket=...') and the default logger prints
// the full path incl. query string. Tickets are single-use and expire in
// seconds, but keep them (and any legacy `?token=` from old clients) out of
// stdout and fronting nginx access logs anyway.
const redactToken = (s: string) => s.replace(/([?&](?:token|ticket)=)[^&\s]+/gi, '$1[REDACTED]')
app.use(
  '*',
  logger((str: string, ...rest: unknown[]) => console.log(redactToken(str), ...rest)),
)

// ─── Auth routes — rate limited ───────────────────────────────────────────────

app.use('/web/auth/*', async (c, next) => {
  // getClientIp only honours X-Forwarded-For when AIVPN_WEB_TRUST_PROXY=true;
  // otherwise the socket peer address is used (spoofed XFF would bypass this limit).
  const key = `auth:${getClientIp(c)}`

  if (isRateLimited(key, config.AUTH_RATE_MAX, config.AUTH_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests. Please wait before retrying.' }, 429)
  }

  await next()

  // Only FAILED requests (4xx/5xx) consume per-IP slots. Successful read-only
  // auth traffic (GET /me, POST /refresh, GET /oidc/config, passkey listing…)
  // is free — a browser with several tabs fires many of those on startup and
  // used to burn through the 10-request window, 429-ing legitimate logins.
  // Brute-force protection is unchanged: every failed login/TOTP/passkey
  // attempt still records an event, and the check above rejects before the
  // handler once the window is full.
  if (c.res.status >= 400) {
    recordRateLimitEvent(key, config.AUTH_RATE_MAX)
  }
})

// ─── Stable per-identity rate-limit key ────────────────────────────────────────
//
// Buckets used to be keyed by sha256(raw Authorization header). That put a
// successful POST /web/auth/refresh (which mints a brand-new JWT) in a fresh,
// empty bucket — a refresh→request loop could defeat the /api/v1 and
// /web/metrics|/web/events caps entirely, since every refresh reset the
// attacker's own counter. session_id is stable across access-token refreshes
// (refresh rotates the token but keeps the same `sessions` row / id, including
// during the cross-tab grace path in routes/auth.ts), so keying on it closes
// the loop: no number of refreshes grows or resets the bucket.
//
// The token is verified here (not just decoded) so a forged/expired
// Authorization header can't be used to target an arbitrary victim's bucket.
// On missing/invalid tokens we fall back to an IP-keyed bucket — the request
// still gets rate limited, and requireAuth() downstream independently
// rejects it with 401 regardless of what this middleware decided.
async function stableRateLimitKey(c: Context, prefix: string): Promise<string> {
  const authHeader = c.req.header('authorization')
  if (authHeader?.startsWith('Bearer ')) {
    try {
      const payload = await verifyAccessToken(authHeader.slice(7))
      return `${prefix}:session:${payload.session_id}`
    } catch {
      // fall through to IP-based key
    }
  }
  return `${prefix}:ip:${getClientIp(c)}`
}

// ─── API proxy routes — rate limited per user ─────────────────────────────────

app.use('/api/v1/*', async (c, next) => {
  const key = await stableRateLimitKey(c, 'api')

  if (!checkRateLimit(key, config.API_RATE_MAX, config.API_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests.' }, 429)
  }

  await next()
})

// ─── Metrics + realtime events — rate limited per user ────────────────────────
// These routes matched no limiter before: GET /web/metrics samples uncached CPU
// load per hit and POST /web/events/ticket mints tickets — both are DoS
// amplification vectors for any authenticated user (incl. read-only viewers).
const eventsRateLimit = async (c: Context, next: Next) => {
  const key = await stableRateLimitKey(c, 'evt')
  if (!checkRateLimit(key, config.API_RATE_MAX, config.API_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests.' }, 429)
  }
  await next()
}
app.use('/web/metrics/*', eventsRateLimit)
app.use('/web/events/*', eventsRateLimit)

// ─── Mount routes ─────────────────────────────────────────────────────────────

app.route('/web/auth', authRoute)
app.route('/web/auth/oidc', oidcRoute)
app.route('/web/metrics', metricsRoute)
app.route('/web/events', eventsRoute)
app.route('/api/v1', proxyRoute)

// ─── Frontend serving ─────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url))

if (config.DEV_MODE) {
  // In dev: proxy everything else to SvelteKit dev server
  app.all('*', async (c) => {
    const url = new URL(c.req.url)
    const target = `http://localhost:${config.SVELTEKIT_DEV_PORT}${url.pathname}${url.search}`

    const headers = new Headers(c.req.raw.headers)
    headers.delete('host')

    try {
      const response = await fetch(target, {
        method: c.req.method,
        headers,
        body: ['GET', 'HEAD'].includes(c.req.method) ? undefined : c.req.raw.body,
      })

      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      })
    } catch {
      return c.text('SvelteKit dev server not running on port ' + config.SVELTEKIT_DEV_PORT, 502)
    }
  })
} else {
  // In production: serve built SvelteKit static files
  const clientBuildDir = path.resolve(__dirname, '..', config.CLIENT_BUILD_DIR)
  const indexHtmlPath = path.join(clientBuildDir, 'index.html')

  // Probe the SPA build ONCE at startup: a missing/misconfigured
  // CLIENT_BUILD_DIR must produce one clear log line and a stable 503, not an
  // unhandled throw on every request (which surfaced as opaque 500s with no
  // hint about the actual problem). Docker note: with the server running from
  // /app/server/src, the SPA lives at /app/client/build, so the image must set
  // CLIENT_BUILD_DIR=../client/build (the default resolves to server/client/build).
  const spaAvailable = await Bun.file(indexHtmlPath).exists()
  if (!spaAvailable) {
    console.error(
      `[server] SPA build not found: ${indexHtmlPath} — the API still works but the web UI will return 503. ` +
      `Build the client (bun run --cwd client build) or point CLIENT_BUILD_DIR at the SvelteKit build directory.`,
    )
  }

  app.use('*', serveStatic({ root: clientBuildDir }))
  // SPA fallback: serve index.html for all unmatched routes
  app.get('*', async (c) => {
    if (!spaAvailable) {
      return c.text('Web UI build not found on this server (see server log: CLIENT_BUILD_DIR).', 503)
    }
    return c.html(await Bun.file(indexHtmlPath).text())
  })
}

// ─── Bootstrap: ensure at least one admin user exists ────────────────────────

async function ensureFirstUser(): Promise<void> {
  const db = await getDb()
  const d = db as any
  const usersTable = IS_SQLITE ? sqliteUsers : pgUsers

  const [existing] = await d.select({ id: usersTable.id }).from(usersTable).limit(1)
  if (existing) return

  // Honor an operator-supplied initial password (documented in .env.example);
  // otherwise generate a strong random one and print it once.
  const provided = config.AIVPN_WEB_ADMIN_PASSWORD
  const password = provided ?? randomBytes(16).toString('base64url')
  const hash = await hashPassword(password)

  await d.insert(usersTable).values({
    username: 'admin',
    password_hash: hash,
    role: 'admin',
  })

  if (provided) {
    console.log('[setup] Seeded admin user from AIVPN_WEB_ADMIN_PASSWORD (username: admin)')
  } else {
    console.log('╔══════════════════════════════════════════════════╗')
    console.log('║         FIRST-TIME SETUP — SAVE THESE NOW        ║')
    console.log('╠══════════════════════════════════════════════════╣')
    console.log(`║  Username : admin                                 ║`)
    console.log(`║  Password : ${password.padEnd(36)} ║`)
    console.log('╚══════════════════════════════════════════════════╝')
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

async function main() {
  await runMigrations()
  await ensureFirstUser()

  serve(
    {
      fetch: app.fetch,
      port: config.PORT,
    },
    (info) => {
      console.log(`[server] aivpn-web listening on http://localhost:${info.port}`)
      console.log(`[server] Origin: ${config.ORIGIN}`)
      console.log(`[server] DB: ${IS_SQLITE ? config.DATABASE_URL : 'PostgreSQL'}`)
      console.log(`[server] Unix socket: ${config.UNIX_SOCK}`)
    },
  )
}

main().catch((err) => {
  console.error('[FATAL]', err)
  process.exit(1)
})
