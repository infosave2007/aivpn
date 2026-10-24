import { expect, test } from 'bun:test'
import { ChallengeStore } from '../src/auth/challenge-store'

test('неиспользованные challenges ограничены емкостью и сроком жизни', () => {
  let now = 0
  const store = new ChallengeStore(2, 100, () => now)
  store.set('a', 'one')
  store.set('b', 'two')
  store.set('c', 'three')
  expect(store.size).toBe(2)
  expect(store.consume('a')).toBeNull()
  now = 100
  store.set('d', 'four')
  expect(store.size).toBe(1)
  expect(store.consume('d')).toBe('four')
  expect(store.consume('d')).toBeNull()
})
