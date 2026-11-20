import { expect, spyOn, test } from 'bun:test'
import { RateLimiter } from '../src/ratelimit'

test('переполнение не отменяет действующее ограничение', () => {
  let now = 0
  const limiter = new RateLimiter(3, () => now)
  for (const key of ['victim', 'second', 'third']) expect(limiter.check(key, 1, 60_000)).toBe(true)
  for (let n = 0; n < 1000; n++) expect(limiter.check(`spray:${n}`, 1, 60_000)).toBe(false)
  expect(limiter.limited('victim', 1, 60_000)).toBe(true)
  expect(limiter.reserve('overflow', 1, 60_000)).toBeNull()
  now = 60_000
  expect(limiter.check('fresh', 1, 60_000)).toBe(true)
  expect(limiter.check('victim', 1, 60_000)).toBe(true)
})

test('резерв освобождается после успеха и учитывает одновременные проверки', () => {
  const limiter = new RateLimiter()
  const first = limiter.reserve('user', 2, 60_000)!
  const second = limiter.reserve('user', 2, 60_000)!
  expect(limiter.reserve('user', 2, 60_000)).toBeNull()
  first.finish(false)
  first.finish(true)
  const third = limiter.reserve('user', 2, 60_000)!
  expect(third).not.toBeNull()
  second.finish(true)
  third.finish(true)
  expect(limiter.reserve('user', 2, 60_000)).toBeNull()
})

test('очистка не теряет незавершенную проверку при переполнении', () => {
  let now = 0
  const limiter = new RateLimiter(1, () => now)
  const active = limiter.reserve('user', 1, 1000)!
  now = 50_000
  limiter.sweep()
  expect(limiter.reserve('another', 1, 1000)).toBeNull()
  expect(limiter.check('user', 1, 1000)).toBe(false)
  active.finish(true)
  expect(limiter.check('user', 1, 1000)).toBe(false)
  now += 1000
  expect(limiter.check('another', 1, 1000)).toBe(true)
})

test('разные окна не вытесняют длинное ограничение', () => {
  let now = 0
  const limiter = new RateLimiter(2, () => now)
  expect(limiter.check('long', 1, 60_000)).toBe(true)
  expect(limiter.check('short', 1, 1000)).toBe(true)
  now = 1000
  expect(limiter.check('fresh', 1, 1000)).toBe(true)
  expect(limiter.limited('long', 1, 60_000)).toBe(true)
  expect(limiter.limited('long', 1, 1000)).toBe(true)
})

test('скользящее окно не выдает двойную порцию на границе', () => {
  let now = 999
  const limiter = new RateLimiter(1, () => now)
  expect(limiter.check('user', 2, 1000)).toBe(true)
  now = 1000
  expect(limiter.check('user', 2, 1000)).toBe(true)
  expect(limiter.check('user', 2, 1000)).toBe(false)
  now = 1999
  expect(limiter.check('user', 2, 1000)).toBe(true)
  expect(limiter.check('user', 2, 1000)).toBe(false)
})

test('успешная проверка освобождает место, повтор finish не записывает отказ', () => {
  const limiter = new RateLimiter(1)
  const attempt = limiter.reserve('user', 1, 1000)!
  attempt.finish(false)
  attempt.finish(true)
  expect(limiter.check('another', 1, 1000)).toBe(true)
})


test('незавершенные проверки входят в запрет входа и сохраняются после успешного соседа', () => {
  const limiter = new RateLimiter(1)
  const first = limiter.reserve('user', 2, 1000)!
  const second = limiter.reserve('user', 2, 1000)!
  expect(limiter.limited('user', 2, 1000)).toBe(true)
  first.finish(false)
  expect(limiter.reserve('other', 2, 1000)).toBeNull()
  expect(limiter.limited('user', 1, 1000)).toBe(true)
  second.finish(false)
  expect(limiter.reserve('other', 1, 1000)).not.toBeNull()
})

test('прямая запись сохраняет последние отказы в пределах заданного лимита', () => {
  let now = 0
  const limiter = new RateLimiter(1, () => now)
  limiter.record('user', 2, 1000)
  now = 100
  limiter.record('user', 2, 1000)
  now = 200
  limiter.record('user', 2, 1000)
  expect(() => limiter.record('overflow', 2, 1000)).not.toThrow()
  now = 1000
  expect(limiter.limited('user', 2, 1000)).toBe(true)
  now = 1100
  expect(limiter.limited('user', 2, 1000)).toBe(false)
  now = 1200
  expect(limiter.limited('user', 1, 1000)).toBe(false)
})

test('наплыв новых ключей не вызывает обход всей таблицы на каждом запросе', () => {
  let now = 0
  const limiter = new RateLimiter(2, () => now)
  const sweep = spyOn(limiter, 'sweep')
  limiter.check('first', 1, 60_000)
  limiter.check('second', 1, 60_000)
  expect(sweep).toHaveBeenCalledTimes(0)
  for (let n = 0; n < 1000; n++) limiter.check(`overflow:${n}`, 1, 60_000)
  expect(sweep).toHaveBeenCalledTimes(1)
  now = 999
  limiter.check('later', 1, 60_000)
  expect(sweep).toHaveBeenCalledTimes(1)
  now = 1000
  limiter.check('later', 1, 60_000)
  expect(sweep).toHaveBeenCalledTimes(2)
})


test('журнал отказов ограничен по памяти даже при прямой записи без предварительной проверки', () => {
  const limiter = new RateLimiter(1)
  limiter.record('user', 0, 1000)
  expect(limiter.limited('user', 1, 1000)).toBe(false)
  // Проверяем размер хранилища: лишние записи могут не менять видимый запрет входа.
  const stored = (limiter as unknown as { buckets: Map<string, { times: number[] }> }).buckets
  for (let n = 0; n < 10_000; n++) {
    limiter.record('user', 2, 1000)
    expect(stored.get('user')!.times.length).toBeLessThanOrEqual(2)
  }
})
