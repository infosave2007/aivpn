/** Скользящее окно запросов. Заполненная таблица не отменяет действующие ограничения. */
interface Bucket {
  times: number[]
  windowMs: number
  pending: number
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>()
  private nextSweep = 0

  constructor(private readonly capacity = 50_000, private readonly now = Date.now) {}

  private prune(bucket: Bucket, now: number): void {
    let expired = 0
    while (expired < bucket.times.length && bucket.times[expired]! <= now - bucket.windowMs) expired++
    if (expired) bucket.times.splice(0, expired)
  }

  sweep(): void {
    const now = this.now()
    for (const [key, bucket] of this.buckets) {
      this.prune(bucket, now)
      if (!bucket.times.length && !bucket.pending) this.buckets.delete(key)
    }
    this.nextSweep = now + 1000
  }

  private bucket(key: string, windowMs: number): Bucket | null {
    const existing = this.buckets.get(key)
    if (existing) {
      existing.windowMs = Math.max(existing.windowMs, windowMs)
      this.prune(existing, this.now())
      return existing
    }
    // Не сканируем всю таблицу на каждом запросе при перегрузке.
    if (this.buckets.size >= this.capacity && this.now() >= this.nextSweep) this.sweep()
    if (this.buckets.size >= this.capacity) return null
    const bucket: Bucket = { times: [], windowMs, pending: 0 }
    this.buckets.set(key, bucket)
    return bucket
  }

  check(key: string, maxReqs: number, windowMs: number): boolean {
    const bucket = this.bucket(key, windowMs)
    if (!bucket || bucket.times.length + bucket.pending >= maxReqs) return false
    bucket.times.push(this.now())
    return true
  }

  limited(key: string, maxReqs: number, windowMs: number): boolean {
    const bucket = this.bucket(key, windowMs)
    return !bucket || bucket.times.length + bucket.pending >= maxReqs
  }

  record(key: string, maxReqs: number, windowMs: number): void {
    const bucket = this.bucket(key, windowMs)
    if (!bucket || maxReqs <= 0) return
    if (bucket.times.length >= maxReqs) bucket.times.splice(0, bucket.times.length - maxReqs + 1)
    bucket.times.push(this.now())
  }

  reserve(key: string, maxReqs: number, windowMs: number): { finish: (failed: boolean) => void } | null {
    const bucket = this.bucket(key, windowMs)
    if (!bucket || bucket.times.length + bucket.pending >= maxReqs) return null
    bucket.pending++
    let finished = false
    return { finish: (failed) => {
      if (finished) return
      finished = true
      if (failed) this.record(key, maxReqs, windowMs)
      bucket.pending--
      if (!bucket.times.length && !bucket.pending) this.buckets.delete(key)
    } }
  }
}

const limiter = new RateLimiter()
export const checkRateLimit = (key: string, maxReqs: number, windowMs: number): boolean =>
  limiter.check(key, maxReqs, windowMs)
export const isRateLimited = (key: string, maxReqs: number, windowMs: number): boolean =>
  limiter.limited(key, maxReqs, windowMs)
export const recordRateLimitEvent = (key: string, maxReqs: number, windowMs: number): void =>
  limiter.record(key, maxReqs, windowMs)
export const reserveRateLimit = (key: string, maxReqs: number, windowMs: number) =>
  limiter.reserve(key, maxReqs, windowMs)

export function scheduleRateLimitCleaner(): void {
  setInterval(() => limiter.sweep(), 15_000).unref()
}
