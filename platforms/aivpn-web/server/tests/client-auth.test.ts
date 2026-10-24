import { afterEach, expect, mock, test } from 'bun:test'
import { plugin } from 'bun'
import { readFile } from 'node:fs/promises'
import { compileModule } from '../../client/node_modules/svelte/compiler'
import { QueryClient } from '../../client/node_modules/@tanstack/svelte-query'

plugin({
  name: 'auth-test',
  setup(builder) {
    builder.onLoad({ filter: /auth\.svelte\.ts$/ }, async ({ path }) => {
      const source = new Bun.Transpiler({ loader: 'ts' }).transformSync(await readFile(path, 'utf8'))
      return { contents: compileModule(source, { filename: path, generate: 'server' }).js.code, loader: 'js' }
    })
    builder.module('$app/navigation', () => ({ exports: { goto: () => Promise.resolve() }, loader: 'object' }))
  },
})

const { authStore } = await import('../../client/src/lib/stores/auth.svelte')
const { refreshAccessToken, apiFetch, auth } = await import('../../client/src/lib/api')
const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch; authStore.clearToken() })

test('смена пользователя и роли очищает кеш, обычный refresh сохраняет его', () => {
  const cache = new QueryClient()
  const unsubscribe = authStore.onSessionChange(() => cache.clear())
  authStore.startSession('admin-token')
  authStore.setUser({ id: 1, username: 'admin', role: 'admin' })
  cache.setQueryData(['config'], { private: 'old-user-value' })
  authStore.setToken('refreshed-token')
  expect(cache.getQueryData(['config'])).toBeDefined()
  authStore.clearToken()
  authStore.startSession('viewer-token')
  authStore.setUser({ id: 2, username: 'viewer', role: 'viewer' })
  expect(cache.getQueryData(['config'])).toBeUndefined()
  cache.setQueryData(['clients'], ['admin-only-details'])
  authStore.setUser({ id: 2, username: 'viewer', role: 'admin' })
  expect(cache.getQueryData(['clients'])).toBeUndefined()
  unsubscribe()
})

test('запоздавший refresh не восстанавливает завершенную сессию', async () => {
  let finish!: (response: Response) => void
  globalThis.fetch = mock(() => new Promise<Response>((resolve) => { finish = resolve })) as typeof fetch
  authStore.startSession('old-token')
  const pending = refreshAccessToken()
  authStore.clearToken()
  authStore.startSession('new-token')
  finish(Response.json({ access_token: 'stale-token' }))
  await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
  expect(authStore.accessToken).toBe('new-token')
})

test('ответ старой сессии не обновляет данные после нового входа', async () => {
  let finish!: (response: Response) => void
  globalThis.fetch = mock(() => new Promise<Response>((resolve) => { finish = resolve })) as typeof fetch
  authStore.startSession('old-token')
  const pending = apiFetch('/api/v1/config')
  authStore.clearToken()
  authStore.startSession('new-token')
  finish(Response.json({ private: 'old-user-value' }))
  await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
})

test('новая попытка входа отменяет refresh и не повторяет неверный пароль', async () => {
  let signal: AbortSignal | null | undefined
  let loginRequests = 0
  globalThis.fetch = mock((path, options) => {
    if (path === '/web/auth/refresh') {
      signal = options?.signal
      return new Promise<Response>((_, reject) => {
        signal?.addEventListener('abort', () => reject(new DOMException('Session changed', 'AbortError')))
      })
    }
    loginRequests += 1
    return Promise.resolve(new Response('invalid credentials', { status: 401 }))
  }) as typeof fetch
  authStore.startSession('old-token')
  const pending = refreshAccessToken()
  const rejected = pending.then(() => null, (error: unknown) => error)
  await expect(auth.login('another-user', 'wrong-password')).rejects.toThrow('invalid credentials')
  expect(await rejected).toMatchObject({ name: 'AbortError' })
  expect(signal?.aborted).toBe(true)
  expect(loginRequests).toBe(1)
  expect(authStore.accessToken).toBeNull()
})
