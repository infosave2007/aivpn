/**
 * In-process sliding-window rate limiter (exact, timestamp-log based).
 *
 * A request is allowed iff fewer than `maxReqs` requests were ALLOWED in the
 * last `windowMs` milliseconds. Unlike a fixed window (which resets its
 * counter at window boundaries and therefore admits up to 2×maxReqs in any
 * `windowMs` span straddling a boundary), the sliding log enforces the limit
 * over every possible window position.
 *
 * Memory: at most `maxReqs` timestamps per key — rejected requests are not
 * recorded, so an attacker hammering one key cannot grow its entry.
 *
 * For multi-process deployments, swap checkRateLimit for a Redis-backed version.
 */

/** Per-key log of allowed-request timestamps (ms), oldest first. */
const rateLimitMap = new Map<string, number[]>()

// Hard cap on distinct keys tracked at once. Several callers key this limiter
// on unauthenticated, attacker-chosen input (e.g. routes/auth.ts's
// `login_user:${username}` per-username brute-force guard) — without a cap,
// flooding the login endpoint with a fresh random username on every request
// grows this map without bound between periodic sweeps (memory-exhaustion
// DoS). When full, evict the single least-recently-active entry to make room
// (O(map size), but only paid once every MAX_RATE_LIMIT_KEYS insertions).
const MAX_RATE_LIMIT_KEYS = 50_000

function evictStalestIfFull(): void {
  if (rateLimitMap.size < MAX_RATE_LIMIT_KEYS) return
  let stalestKey: string | undefined
  let stalestTs = Infinity
  for (const [k, log] of rateLimitMap) {
    const last = log.at(-1) ?? -Infinity
    if (last < stalestTs) {
      stalestTs = last
      stalestKey = k
    }
  }
  if (stalestKey !== undefined) rateLimitMap.delete(stalestKey)
}

export function checkRateLimit(key: string, maxReqs: number, windowMs: number): boolean {
  const now = Date.now()
  let log = rateLimitMap.get(key)
  if (!log) {
    evictStalestIfFull()
    log = []
    rateLimitMap.set(key, log)
  }

  // Evict timestamps that slid out of the window.
  const cutoff = now - windowMs
  let expired = 0
  while (expired < log.length && log[expired] <= cutoff) expired++
  if (expired > 0) log.splice(0, expired)

  if (log.length >= maxReqs) return false
  log.push(now)
  return true
}

/**
 * Check whether `key` already has >= maxReqs recorded events inside the
 * window WITHOUT recording anything. Pair with recordRateLimitEvent() when
 * only specific outcomes (e.g. FAILED login attempts) should consume slots —
 * a plain checkRateLimit() would let an attacker exhaust a victim's
 * per-username window with junk requests, and would charge a legitimate
 * two-step (password → TOTP) login two slots.
 */
export function isRateLimited(key: string, maxReqs: number, windowMs: number): boolean {
  const log = rateLimitMap.get(key)
  if (!log) return false

  const cutoff = Date.now() - windowMs
  let expired = 0
  while (expired < log.length && log[expired] <= cutoff) expired++
  if (expired > 0) log.splice(0, expired)

  if (log.length === 0) {
    rateLimitMap.delete(key)
    return false
  }
  return log.length >= maxReqs
}

/**
 * Record one event (e.g. a failed password/TOTP attempt) against `key`.
 * The log is bounded to maxReqs entries per key: once full, the oldest
 * timestamp is dropped — keeping the newest ones is exactly what the
 * sliding-window check needs, and memory stays capped per key.
 */
export function recordRateLimitEvent(key: string, maxReqs: number): void {
  let log = rateLimitMap.get(key)
  if (!log) {
    evictStalestIfFull()
    log = []
    rateLimitMap.set(key, log)
  }
  if (log.length >= maxReqs) {
    log.splice(0, log.length - maxReqs + 1)
  }
  log.push(Date.now())
}

/**
 * Start a periodic sweep that removes keys idle for more than maxWindowMs * 2
 * (i.e. whose newest allowed request is older than that).
 * Call once at application startup.
 *
 * Runs every 15s (not 60s): combined with the MAX_RATE_LIMIT_KEYS hard cap
 * above, a shorter sweep interval bounds how large the map can grow during an
 * active many-distinct-keys flood (e.g. per-username login attempts) before
 * stale entries are reclaimed, independent of the hard cap.
 */
export function scheduleRateLimitCleaner(maxWindowMs: number): void {
  setInterval(() => {
    const now = Date.now()
    for (const [key, log] of rateLimitMap.entries()) {
      if (log.length === 0 || now - log[log.length - 1] > maxWindowMs * 2) {
        rateLimitMap.delete(key)
      }
    }
  }, 15_000)
}
