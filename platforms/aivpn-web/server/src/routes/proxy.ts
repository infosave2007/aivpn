import { Hono } from 'hono'
import http from 'node:http'
import type { IncomingMessage } from 'node:http'
import { config } from '../config'
import { requireAuth, requireReadAccess } from '../auth/middleware'
import { writeAudit } from '../audit'
import { getDb } from '../db'
import { getClientIp } from '../lib/client-ip'

const proxy = new Hono()

/** Request whose body exceeded config.PROXY_MAX_BODY_BYTES while streaming. */
class PayloadTooLargeError extends Error {
  constructor() {
    super('request body exceeds configured limit')
    this.name = 'PayloadTooLargeError'
  }
}

// ── Viewer authorization: ALLOWLIST (fail-closed) ───────────────────────────
// A `viewer` is a read-only role. Instead of a denylist of privileged
// endpoints (fail-OPEN: a newly added endpoint is reachable by viewers until
// someone remembers to deny it), we enumerate the EXACT (method, path) surface
// a viewer may reach. Anything not listed is rejected with 403, so new
// endpoints are unreachable by viewers until deliberately allowlisted here.
//
// Non-GET methods are already blocked for viewers by requireReadAccess(); the
// `method` field is kept explicit as defence-in-depth.
//
// Patterns match the CANONICAL path (see canonicalizeForAuthz): lowercase,
// percent-decoded, separators collapsed, trailing slash removed. `:id`/`:name`
// path params match a single non-slash segment, so deeper sub-paths (e.g.
// clients/<id>/connection-key) do NOT match and therefore stay denied.
const VIEWER_ALLOWED: Array<{ method: string; pattern: RegExp }> = [
  // Dashboard: overall server status counters — no secrets.
  { method: 'GET', pattern: /^\/api\/v1\/status$/ },
  // Client list — metadata only; connection keys live at a separate sub-path.
  { method: 'GET', pattern: /^\/api\/v1\/clients$/ },
  // Single client metadata — the trailing-only match excludes the
  // /connection-key sub-path (an extra segment), which stays denied.
  { method: 'GET', pattern: /^\/api\/v1\/clients\/[^/]+$/ },
  // Mask list — non-secret traffic-mimicry profile names/metadata.
  { method: 'GET', pattern: /^\/api\/v1\/masks$/ },
  // Kernel-module status — read-only diagnostic info, no secrets.
  { method: 'GET', pattern: /^\/api\/v1\/kernel$/ },
  // Realtime dashboard event stream (SSE) — read-only status/traffic events.
  { method: 'GET', pattern: /^\/api\/v1\/events$/ },
]

/**
 * True iff a viewer-role user is permitted this (method, canonical path).
 * Fail-closed: anything not explicitly allowlisted returns false.
 *
 * Deliberately EXCLUDED (viewers get 403): config + backup + bootstrap +
 * clients/:id/connection-key (all expose operator or client secrets) and
 * audit-log (admin action history + client IPs — admin-only oversight data).
 */
export function isViewerAllowed(method: string, path: string): boolean {
  return VIEWER_ALLOWED.some((r) => r.method === method && r.pattern.test(path))
}

/**
 * Canonicalize a URL pathname for AUTHORIZATION checks only (the upstream
 * request still forwards the original path untouched).
 *
 * `new URL().pathname` neither percent-decodes nor collapses separators, so a
 * Rust backend that treats `/api/v1/config/`, `/api/v1//config`,
 * `/api/v1/config%2f` or `/api/v1/CONFIG` as `/api/v1/config` would let a
 * viewer slip past anchored regexes like `^\/api\/v1\/config$`.
 *
 * Steps: percent-decode (malformed encoding ⇒ null ⇒ request rejected),
 * resolve `.`/`..` segments, collapse repeated slashes, drop the trailing
 * slash (except root) and lowercase.
 */
export function canonicalizeForAuthz(pathname: string): string | null {
  let decoded: string
  try {
    decoded = decodeURIComponent(pathname)
  } catch {
    return null // malformed percent-encoding — caller must reject
  }
  const out: string[] = []
  for (const seg of decoded.split('/')) {
    if (seg === '' || seg === '.') continue // collapses `//` and trailing `/`
    if (seg === '..') {
      out.pop()
      continue
    }
    out.push(seg)
  }
  return ('/' + out.join('/')).toLowerCase()
}

/**
 * Forward a request to the aivpn Unix socket and return the raw response.
 * Handles streaming for SSE and binary for backup/export.
 */
async function forwardToUnixSocket(
  method: string,
  path: string,
  requestHeaders: Record<string, string>,
  body: ReadableStream | null,
  maxBodyBytes: number,
): Promise<{ status: number; headers: Record<string, string>; body: IncomingMessage }> {
  return new Promise((resolve, reject) => {
    const options: http.RequestOptions = {
      socketPath: config.UNIX_SOCK,
      path,
      method,
      headers: {
        ...requestHeaders,
        host: 'localhost',
      },
    }

    const req = http.request(options, (res) => {
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(res.headers)) {
        if (v !== undefined) {
          headers[k] = Array.isArray(v) ? v.join(', ') : v
        }
      }
      resolve({ status: res.statusCode ?? 502, headers, body: res })
    })

    req.on('error', reject)

    if (body) {
      // Pipe request body to unix socket request, enforcing a hard byte
      // ceiling. This guards the case where Content-Length is absent or lies
      // (chunked / spoofed): as soon as the streamed size exceeds the cap we
      // abort the upstream request and reject → mapped to 413 by the caller.
      const reader = body.getReader()
      let received = 0
      const pump = () => {
        reader.read().then(({ done, value }) => {
          if (done) {
            req.end()
            return
          }
          if (value) {
            received += value.byteLength
            if (received > maxBodyBytes) {
              req.destroy()
              reader.cancel().catch(() => {})
              reject(new PayloadTooLargeError())
              return
            }
            req.write(value)
          }
          pump()
        }).catch(reject)
      }
      pump()
    } else {
      req.end()
    }
  })
}

// Mount all /api/v1/* routes
proxy.all('/*', requireReadAccess(), async (c) => {
  const user = c.get('user')
  const url = new URL(c.req.url)
  const apiPath = url.pathname  // already /api/v1/... — no rewrite needed
  const fullPath = apiPath + (url.search ?? '')

  // Canonical form is used for ALL authorization decisions; the raw path is
  // what gets forwarded upstream. Malformed percent-encoding is rejected.
  const canonicalPath = canonicalizeForAuthz(apiPath)
  if (canonicalPath === null) {
    return c.json({ error: 'Bad request' }, 400)
  }

  // Guard: only allow requests to /api/v1/ prefix (checked on canonical path
  // so encoded/duplicated separators cannot smuggle another prefix through)
  if (!canonicalPath.startsWith('/api/v1/') && canonicalPath !== '/api/v1') {
    return c.json({ error: 'Not found' }, 404)
  }

  // Enforce the viewer ALLOWLIST (fail-closed): a viewer may only reach the
  // explicitly permitted (method, path) surface; everything else is 403.
  if (user.role === 'viewer' && !isViewerAllowed(c.req.method, canonicalPath)) {
    const db = await getDb()
    await writeAudit(db, user.id, 'api_proxy', canonicalPath, 'denied', getClientIp(c))
    return c.json({ error: 'Forbidden: access denied for viewer role' }, 403)
  }

  // Build headers to forward (strip hop-by-hop headers)
  const skipHeaders = new Set([
    'connection', 'keep-alive', 'transfer-encoding', 'te',
    'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate',
    'host',
    // Never forward the panel's own session credentials to the management
    // daemon: the panel already authenticated the caller, and the refresh
    // cookie (__Host-aivpn_rt, Path=/, 7-day) + access JWT would otherwise land
    // in the daemon's request logs, widening the blast radius of a log leak.
    'cookie', 'authorization',
  ])
  const forwardHeaders: Record<string, string> = {}
  // `c.req.raw.headers` is a Web `Headers` object, not a plain object —
  // `Object.entries()` on it yields nothing, which silently dropped EVERY
  // request header (Content-Type, Authorization, …) so POST/PUT bodies reached
  // the backend without a Content-Type and were rejected with 415. Iterate the
  // Headers correctly; `.forEach` already coalesces multi-values into one string.
  c.req.raw.headers.forEach((v, k) => {
    if (!skipHeaders.has(k.toLowerCase()) && v) {
      forwardHeaders[k] = v
    }
  })

  const method = c.req.method
  // DELETE with a body is valid per RFC 9110 §9.3.5; forward if Content-Length > 0
  // or Transfer-Encoding is present (e.g. bulk-delete endpoints).
  const deleteHasBody = method === 'DELETE'
    && (Number(c.req.header('content-length') ?? 0) > 0
      || !!c.req.header('transfer-encoding'))
  const hasBody = (method !== 'GET' && method !== 'HEAD' && method !== 'DELETE') || deleteHasBody

  // Cap the REQUEST body size on this buffered (non-SSE) forward path to bound
  // memory. Reject early when a declared Content-Length exceeds the limit; the
  // streamed guard in forwardToUnixSocket catches an absent/lying length.
  // SSE responses are unaffected — this limits the request body only.
  // Backup imports get their own (much larger) cap: real backups exceed the
  // general-purpose limit by design (the daemon itself accepts up to 50 MB).
  const maxBodyBytes = canonicalPath === '/api/v1/backup/import'
    ? config.PROXY_MAX_BACKUP_BODY_BYTES
    : config.PROXY_MAX_BODY_BYTES
  const tooLargeMsg = `Payload too large (limit ${maxBodyBytes} bytes; raise ${
    canonicalPath === '/api/v1/backup/import' ? 'PROXY_MAX_BACKUP_BODY_BYTES' : 'PROXY_MAX_BODY_BYTES'
  } if this request is legitimate)`
  if (hasBody) {
    const declaredLen = Number(c.req.header('content-length'))
    if (Number.isFinite(declaredLen) && declaredLen > maxBodyBytes) {
      return c.json({ error: tooLargeMsg }, 413)
    }
  }

  const body = hasBody ? c.req.raw.body : null

  try {
    const upstream = await forwardToUnixSocket(method, fullPath, forwardHeaders, body, maxBodyBytes)

    // Determine if this is an SSE stream
    const contentType = upstream.headers['content-type'] ?? ''
    const isSSE = contentType.includes('text/event-stream')
    const isBinary = contentType.includes('application/octet-stream')
      || contentType.includes('application/gzip')
      || apiPath.includes('/backup/export')

    // Build response headers (strip hop-by-hop)
    const responseHeaders = new Headers()
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (!skipHeaders.has(k.toLowerCase())) {
        responseHeaders.set(k, v)
      }
    }

    if (isSSE) {
      // Stream SSE directly — convert Node.js IncomingMessage to Web ReadableStream
      const nodeStream = upstream.body
      const webStream = new ReadableStream({
        start(controller) {
          nodeStream.on('data', (chunk: Buffer) => {
            controller.enqueue(chunk)
          })
          nodeStream.on('end', () => controller.close())
          nodeStream.on('error', (err) => controller.error(err))
        },
        cancel() {
          nodeStream.destroy()
        },
      })

      return new Response(webStream, {
        status: upstream.status,
        headers: responseHeaders,
      })
    }

    // For all other responses, buffer the body
    const chunks: Buffer[] = []
    for await (const chunk of upstream.body) {
      chunks.push(chunk as Buffer)
    }
    const buffer = Buffer.concat(chunks)

    return new Response(buffer, {
      status: upstream.status,
      headers: responseHeaders,
    })
  } catch (err: unknown) {
    if (err instanceof PayloadTooLargeError) {
      return c.json({ error: tooLargeMsg }, 413)
    }
    const message = err instanceof Error ? err.message : String(err)
    // Common case: aivpn daemon not running
    if (message.includes('ENOENT') || message.includes('ECONNREFUSED')) {
      return c.json({ error: 'aivpn daemon is not running or socket is unavailable' }, 502)
    }
    console.error('[proxy] upstream error:', err)
    return c.json({ error: 'Upstream error' }, 502)
  }
})

export { proxy as proxyRoute }
