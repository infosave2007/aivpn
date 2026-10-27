import { expect, test } from 'bun:test'
import { checkRateLimit, isRateLimited, recordRateLimitEvent } from '../src/ratelimit'

test('переполнение таблицы сохраняет активные ограничения и вытесняет старые ключи', () => {
  const prefix = `capacity:${crypto.randomUUID()}:`
  const oldest = prefix + 'oldest'
  const active = prefix + 'active'
  recordRateLimitEvent(oldest, 1)
  recordRateLimitEvent(active, 2)
  for (let i = 0; i < 49_998; i++) recordRateLimitEvent(prefix + i, 1)
  recordRateLimitEvent(active, 2)
  recordRateLimitEvent(prefix + 'new', 1)
  expect(isRateLimited(active, 2, 60_000)).toBe(true)
  expect(isRateLimited(oldest, 1, 60_000)).toBe(false)
  expect(checkRateLimit(active, 2, 60_000)).toBe(false)
})


test('резерв освобождается после успеха и учитывает одновременные проверки', async () => {
  const { reserveRateLimit } = await import('../src/ratelimit')
  const key = `reservation:${Date.now()}`
  const first = reserveRateLimit(key, 2, 60_000)!
  const second = reserveRateLimit(key, 2, 60_000)!
  expect(reserveRateLimit(key, 2, 60_000)).toBeNull()
  first.finish(false)
  first.finish(true)
  const third = reserveRateLimit(key, 2, 60_000)!
  expect(third).not.toBeNull()
  second.finish(true)
  third.finish(true)
  expect(reserveRateLimit(key, 2, 60_000)).toBeNull()
})
