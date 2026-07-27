import { Hono } from 'hono'
import http from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { requireAuth } from '../auth/middleware'
import { config } from '../config'
import { isViewerAllowed } from './proxy'
import type { UserRole } from '../db/schema'

/**
 * SSE auth: short-lived single-use tickets.
 *
 * EventSource cannot set an Authorization header, so *some* credential must
 * go into the URL. Previously that was the general 15-minute access token —
 * which then leaked into proxy logs / browser history / extensions. Instead:
 *
 *   1. POST /web/events/ticket  — normal Bearer-authenticated request
 *      (requireAuth: JWT signature + session_version + live sessions row),
 *      mints a random 256-bit ticket valid for TICKET_TTL_MS, single use.
 *   2. GET  /web/events?ticket=<ticket> — consumes the ticket and opens the
 *      SSE stream. A leaked ticket is worthless: it expires in seconds and
 *      is burned on first use.
 */

const TICKET_TTL_MS = 60_000

interface TicketEntry { userId: number; role: UserRole; expiresAt: number }
const tickets = new Map<string, TicketEntry>()

function pruneTickets(now: number): void {
  for (const [k, v] of tickets) {
    if (v.expiresAt <= now) tickets.delete(k)
  }
}

// Background sweep so expired tickets are reclaimed even when no mint/consume
// happens for a long time (otherwise the Map only shrinks on those calls).
// unref() keeps the timer from holding the process open.
const ticketSweeper = setInterval(() => pruneTickets(Date.now()), TICKET_TTL_MS)
ticketSweeper.unref?.()

/**
 * Consume (delete) a ticket; returns the entry (incl. the minting user's
 * role, needed for RBAC on the stream) when it existed and was unexpired.
 */
function consumeTicket(ticket: string): TicketEntry | null {
  const now = Date.now()
  pruneTickets(now)
  // Constant-time key lookup: compare against stored keys instead of a direct
  // Map.get so a network attacker cannot probe ticket prefixes via timing.
  const candidate = Buffer.from(ticket)
  for (const [k, v] of tickets) {
    const stored = Buffer.from(k)
    if (stored.length === candidate.length && timingSafeEqual(stored, candidate)) {
      tickets.delete(k) // single use — burn even before the expiry check
      return v.expiresAt > now ? v : null
    }
  }
  return null
}

// ── Concurrent-stream limits ─────────────────────────────────────────────────
// Each SSE stream holds a dedicated connection to the management Unix socket;
// without a cap an authenticated user could exhaust the Rust daemon's
// connections. The max lifetime bounds how long a stream outlives its auth
// check (session revocation is only evaluated at ticket minting) — clients
// already reconnect with a freshly authenticated ticket on stream close.
const MAX_STREAMS_PER_USER = 5
const MAX_STREAM_LIFETIME_MS = 15 * 60_000

const openStreams = new Map<number, number>()

function releaseStream(userId: number): void {
  const n = (openStreams.get(userId) ?? 1) - 1
  if (n <= 0) openStreams.delete(userId)
  else openStreams.set(userId, n)
}

const events = new Hono()

events.post('/ticket', requireAuth(), (c) => {
  const now = Date.now()
  pruneTickets(now)
  const user = c.get('user')
  const ticket = randomBytes(32).toString('base64url')
  tickets.set(ticket, { userId: user.id, role: user.role, expiresAt: now + TICKET_TTL_MS })
  return c.json({ ticket, expires_in: Math.floor(TICKET_TTL_MS / 1000) })
})

events.get('/', async (c) => {
  const ticket = c.req.query('ticket')
  if (!ticket) return c.json({ error: 'Missing ticket' }, 401)
  const entry = consumeTicket(ticket)
  if (!entry) return c.json({ error: 'Unauthorized' }, 401)

  // Apply the SAME viewer RBAC the proxy applies to /api/v1/events — this
  // route bypasses proxy.ts, so without this check a viewer-minted ticket
  // would grant whatever the proxy would have denied. The proxy enforces a
  // fail-closed allowlist; /api/v1/events is on it (viewers may watch the
  // stream). If it is ever removed there, this route stays consistent.
  if (entry.role === 'viewer' && !isViewerAllowed('GET', '/api/v1/events')) {
    return c.json({ error: 'Forbidden: access denied for viewer role' }, 403)
  }

  // Per-user concurrency cap (see MAX_STREAMS_PER_USER above)
  if ((openStreams.get(entry.userId) ?? 0) >= MAX_STREAMS_PER_USER) {
    return c.json({ error: 'Too many concurrent event streams' }, 429)
  }
  openStreams.set(entry.userId, (openStreams.get(entry.userId) ?? 0) + 1)

  let released = false
  const release = () => {
    if (released) return
    released = true
    releaseStream(entry.userId)
  }

  // Auth passed — pipe SSE stream from Unix socket to client
  return new Promise<Response>((resolve) => {
    const req = http.request(
      {
        socketPath: config.UNIX_SOCK,
        path: '/api/v1/events',
        method: 'GET',
        headers: {
          host: 'localhost',
          accept: 'text/event-stream',
          'cache-control': 'no-cache',
        },
      },
      (res) => {
        // Max lifetime: force a clean close so the client reconnects with a
        // freshly authenticated ticket (EventSource retries automatically).
        let ctrl: ReadableStreamDefaultController<Uint8Array> | null = null
        const lifetime = setTimeout(() => {
          try { ctrl?.close() } catch { /* already closed */ }
          res.destroy()
          release()
        }, MAX_STREAM_LIFETIME_MS)
        lifetime.unref?.()

        const stream = new ReadableStream({
          start(controller) {
            ctrl = controller
            res.on('data', (chunk: Buffer) => {
              try { controller.enqueue(chunk) } catch { /* stream closed */ }
            })
            res.on('end', () => {
              clearTimeout(lifetime)
              release()
              try { controller.close() } catch { /* already closed */ }
            })
            res.on('error', (err) => {
              clearTimeout(lifetime)
              release()
              try { controller.error(err) } catch { /* already closed */ }
            })
          },
          cancel() {
            clearTimeout(lifetime)
            release()
            res.destroy()
          },
        })

        resolve(new Response(stream, {
          status: 200,
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
            'X-Accel-Buffering': 'no', // disable nginx response buffering
          },
        }))
      },
    )

    req.on('error', () => {
      release()
      // Emit a NAMED "state" event: every consumer listens via
      // addEventListener('state', …), so an unnamed data-only frame (which
      // only fires onmessage) was invisible — the upstream outage never
      // surfaced client-side. The one-frame body then ends the stream, and
      // EventSource auto-reconnects with a fresh ticket.
      resolve(new Response('event: state\ndata: {"error":"upstream unavailable"}\n\n', {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' },
      }))
    })

    req.end()
  })
})

export { events as eventsRoute }
