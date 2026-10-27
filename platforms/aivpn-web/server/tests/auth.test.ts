import { afterAll, beforeAll, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import http from 'node:http'
import { eq, sql } from 'drizzle-orm'

// Все запросы и миграции используют отдельную временную базу.
const directory = mkdtempSync(join(tmpdir(), 'aivpn-auth-test-'))
process.env.DATABASE_URL = process.env.AIVPN_TEST_DATABASE_URL ?? `file:${join(directory, 'test.db')}`
process.env.JWT_SECRET = randomBytes(48).toString('base64')
process.env.TOTP_ENCRYPTION_KEY = randomBytes(32).toString('base64')
process.env.OIDC_MODE = 'disabled'
process.env.ORIGIN = 'http://localhost:3000'
process.env.AIVPN_WEB_TRUST_PROXY = 'false'
process.env.UNIX_SOCK = join(directory, 'absent.sock')

const { runMigrations } = await import('../src/db/migrate')
const { getDb, IS_SQLITE, sqliteUsers, pgUsers } = await import('../src/db')
const users = IS_SQLITE ? sqliteUsers : pgUsers
const { hashPassword } = await import('../src/auth/argon')
const { authRoute: auth } = await import('../src/routes/auth')
const { proxyRoute: proxy } = await import('../src/routes/proxy')
const { eventsRoute: events } = await import('../src/routes/events')
const { encryptTotpSecret, decryptTotpSecret } = await import('../src/auth/totp')
const { config } = await import('../src/config')
const { default: speakeasy } = await import('speakeasy')
const app = new Hono().route('/web/auth', auth).route('/api/v1', proxy).route('/web/events', events)
const password = randomBytes(24).toString('hex')
let passwordHash: string

beforeAll(async () => {
  await runMigrations()
  passwordHash = await hashPassword(password)
})
afterAll(() => rmSync(directory, { recursive: true, force: true }))

async function newUser(role: 'admin' | 'viewer' = 'viewer', totpSecret?: string) {
  const username = randomUUID()
  const db = await getDb() as any
  await db.insert(users).values({
    username, password_hash: passwordHash, role,
    ...(totpSecret ? { totp_enabled: true, totp_secret: encryptTotpSecret(totpSecret) } : {}),
  })
  return username
}

function post(path: string, body: unknown = {}, headers: Record<string, string> = {}) {
  return app.request(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

async function login(username: string) {
  const response = await post('/web/auth/login', { username, password })
  expect(response.status).toBe(200)
  const body = await response.json() as { access_token: string }
  return {
    token: body.access_token,
    cookie: response.headers.get('set-cookie')!.split(';')[0],
  }
}

test('неверный пароль не создает сессию', async () => {
  const username = await newUser()
  const response = await post('/web/auth/login', { username, password: 'wrong' })
  expect(response.status).toBe(401)
  expect(response.headers.has('set-cookie')).toBe(false)
})

test('выход отзывает access и refresh токены', async () => {
  const session = await login(await newUser())
  const headers = { Authorization: `Bearer ${session.token}` }
  expect((await app.request('/web/auth/me', { headers })).status).toBe(200)
  expect((await post('/web/auth/logout', {}, headers)).status).toBe(200)
  expect((await app.request('/web/auth/me', { headers })).status).toBe(401)
  expect((await post('/web/auth/refresh', {}, { Cookie: session.cookie })).status).toBe(401)
})

test('поздняя запись старой сессии не возвращает доступ после смены настроек', async () => {
  const username = await newUser()
  const session = await login(username)
  const db = await getDb() as any
  await db.update(users).set({ session_version: sql`${users.session_version} + 1` })
    .where(eq(users.username, username))
  expect((await app.request('/web/auth/me', { headers: { Authorization: `Bearer ${session.token}` } })).status).toBe(401)
  expect((await post('/web/auth/refresh', {}, { Cookie: session.cookie })).status).toBe(401)
  const fresh = await login(username)
  expect((await post('/web/auth/refresh', {}, { Cookie: fresh.cookie })).status).toBe(200)
})

test('неизвестная роль в базе не получает административный доступ', async () => {
  const username = await newUser()
  const session = await login(username)
  const db = await getDb() as any
  await db.update(users).set({ role: 'administrator' }).where(eq(users.username, username))
  expect((await app.request('/api/v1/config', { headers: { Authorization: `Bearer ${session.token}` } })).status).toBe(401)
})

test('повторная настройка TOTP не подменяет уже подтвержденный secret', async () => {
  const username = await newUser()
  const session = await login(username)
  const headers = { Authorization: `Bearer ${session.token}` }
  const first = await app.request('/web/auth/totp/setup', { headers })
  const { secret } = await first.json() as { secret: string }
  const token = speakeasy.totp({ secret, encoding: 'base32' })
  const [, verification] = await Promise.all([
    app.request('/web/auth/totp/setup', { headers }),
    post('/web/auth/totp/verify', { token }, headers),
  ])
  const db = await getDb() as any
  const [user] = await db.select().from(users).where(eq(users.username, username))
  if (verification.status === 200) {
    expect(user.totp_enabled).toBe(true)
    expect(decryptTotpSecret(user.totp_secret)).toBe(secret)
  } else {
    expect([401, 409]).toContain(verification.status)
    expect(user.totp_enabled).toBe(false)
  }
})

test('viewer не может читать секреты или изменять клиентов', async () => {
  const session = await login(await newUser())
  const headers = { Authorization: `Bearer ${session.token}` }
  for (const path of ['/api/v1/config', '/api/v1/backup/export', '/api/v1/clients/1/connection-key', '/api/v1/config%2f']) {
    expect((await app.request(path, { headers })).status).toBe(403)
  }
  expect((await post('/api/v1/clients', {}, headers)).status).toBe(403)
  expect((await post('/web/auth/register', { username: 'another', password, role: 'admin' }, headers)).status).toBe(403)
})

test('повторный TOTP код отклоняется', async () => {
  const secret = speakeasy.generateSecret().base32
  const username = await newUser('admin', secret)
  const totp_token = speakeasy.totp({ secret, encoding: 'base32' })
  expect((await post('/web/auth/login', { username, password, totp_token })).status).toBe(200)
  expect((await post('/web/auth/login', { username, password, totp_token })).status).toBe(401)
})

test('одновременное обновление в двух вкладках выдает один новый refresh токен', async () => {
  const session = await login(await newUser())
  const responses = await Promise.all([
    post('/web/auth/refresh', {}, { Cookie: session.cookie }),
    post('/web/auth/refresh', {}, { Cookie: session.cookie }),
  ])
  expect(responses.map(r => r.status)).toEqual([200, 200])
  const cookies = responses.map(r => r.headers.get('set-cookie')).filter((c): c is string => !!c)
  expect(cookies).toHaveLength(1)
  for (const cookie of cookies) {
    expect((await post('/web/auth/refresh', {}, { Cookie: cookie.split(';')[0] })).status).toBe(200)
  }
})

test('exclusive OIDC блокирует обе локальные passkey точки входа', async () => {
  const mode = config.OIDC_MODE
  config.OIDC_MODE = 'exclusive'
  try {
    expect((await app.request('/web/auth/passkey/authentication-options')).status).toBe(403)
    const response = await post('/web/auth/passkey/authenticate', { response: { id: 'existing-key' } })
    expect(response.status).toBe(403)
    expect(response.headers.has('set-cookie')).toBe(false)
  } finally { config.OIDC_MODE = mode }
})

test('выдача passkey challenge ограничена даже для успешных запросов', async () => {
  for (let i = 0; i < config.AUTH_RATE_MAX; i++) {
    expect((await app.request('/web/auth/passkey/authentication-options')).status).toBe(200)
  }
  expect((await app.request('/web/auth/passkey/authentication-options')).status).toBe(429)
})

test('прямой SSE через API не обходит ticket stream policy', async () => {
  for (const role of ['admin', 'viewer'] as const) {
    const session = await login(await newUser(role))
    const response = await app.request('/api/v1/events', { headers: { Authorization: `Bearer ${session.token}` } })
    expect(response.status).toBe(403)
  }
})

test('viewer получает SSE только через одноразовый ticket', async () => {
  const session = await login(await newUser('viewer'))
  const headers = { Authorization: `Bearer ${session.token}` }
  expect((await app.request('/web/events')).status).toBe(401)
  const minted = await post('/web/events/ticket', {}, headers)
  expect(minted.status).toBe(200)
  const { ticket } = await minted.json() as { ticket: string }
  const response = await app.request(`/web/events?ticket=${encodeURIComponent(ticket)}`)
  expect(response.status).toBe(200)
  expect(response.headers.get('content-type')).toBe('text/event-stream')
  // Unix socket в fixture отсутствует, но разрешенный stream должен отдать событие.
  expect(await response.text()).toContain('event: state')
  expect((await app.request(`/web/events?ticket=${encodeURIComponent(ticket)}`)).status).toBe(401)
  expect((await post('/api/v1/clients', {}, headers)).status).toBe(403)
})

test('отозванная сессия не открывает ранее выданный ticket', async () => {
  const session = await login(await newUser())
  const headers = { Authorization: `Bearer ${session.token}` }
  const minted = await post('/web/events/ticket', {}, headers)
  const { ticket } = await minted.json() as { ticket: string }
  await post('/web/auth/logout', {}, headers)
  expect((await app.request(`/web/events?ticket=${ticket}`)).status).toBe(401)
})

test('отзыв сессии закрывает уже открытый SSE', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.write('event: state\ndata: {}\n\n')
  })
  await new Promise<void>((resolve) => upstream.listen(config.UNIX_SOCK, resolve))
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    const session = await login(await newUser())
    const headers = { Authorization: `Bearer ${session.token}` }
    const minted = await post('/web/events/ticket', {}, headers)
    const { ticket } = await minted.json() as { ticket: string }
    const response = await app.request(`/web/events?ticket=${ticket}`)
    reader = response.body!.getReader()
    expect((await reader.read()).done).toBe(false)
    await post('/web/auth/logout', {}, headers)
    expect((await reader.read()).done).toBe(true)
  } finally {
    await reader?.cancel()
    await new Promise<void>((resolve, reject) => upstream.close(error => error ? reject(error) : resolve()))
  }
}, 8_000)

test('proxy отдает начало ответа до завершения upstream и закрывает его при отмене', async () => {
  let closed = false
  const upstream = http.createServer((_req, res) => {
    res.once('close', () => { closed = true })
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
    res.write('first chunk')
  })
  await new Promise<void>(resolve => upstream.listen(config.UNIX_SOCK, resolve))
  try {
    const session = await login(await newUser())
    const response = await Promise.race([
      app.request('/api/v1/status', { headers: { Authorization: `Bearer ${session.token}` } }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Response was buffered')), 1000)),
    ])
    const reader = response.body!.getReader()
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('first chunk')
    await reader.cancel()
    for (let i = 0; i < 100 && !closed; i++) await Bun.sleep(10)
    expect(closed).toBe(true)
  } finally {
    upstream.closeAllConnections()
    await new Promise<void>(resolve => upstream.close(() => resolve()))
  }
})

test('proxy останавливает загрузку без Content-Length при превышении лимита', async () => {
  let cancelled = false
  const upstream = http.createServer((req, res) => {
    req.on('data', () => {})
    req.on('end', () => { res.end('{}') })
  })
  await new Promise<void>(resolve => upstream.listen(config.UNIX_SOCK, resolve))
  try {
    const session = await login(await newUser('admin'))
    const body = new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(128 * 1024)) },
      cancel() { cancelled = true },
    })
    const response = await app.request('/api/v1/clients', {
      method: 'POST', headers: { Authorization: `Bearer ${session.token}` }, body,
    })
    expect(response.status).toBe(413)
    expect(cancelled).toBe(true)
  } finally {
    upstream.closeAllConnections()
    await new Promise<void>(resolve => upstream.close(() => resolve()))
  }
})

async function passwordlessAccount(keyCount: number) {
  const username = await newUser()
  const session = await login(username)
  const db = await getDb() as any
  const { sqlitePasskeys, pgPasskeys } = await import('../src/db/schema')
  const passkeys = IS_SQLITE ? sqlitePasskeys : pgPasskeys
  const [user] = await db.select().from(users).where(eq(users.username, username))
  const ids = Array.from({ length: keyCount }, () => randomUUID())
  for (const id of ids) await db.insert(passkeys).values({
    id, user_id: user.id, credential_id: randomUUID(), public_key: 'test-key', counter: 0,
  })
  await db.update(users).set({ passkey_only: true }).where(eq(users.id, user.id))
  return { session, db, user, ids, passkeys }
}

test('последний passkey нельзя удалить при выключенном входе по паролю', async () => {
  const account = await passwordlessAccount(1)
  const response = await app.request(`/web/auth/passkeys/${account.ids[0]}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${account.session.token}` },
  })
  expect(response.status).toBe(409)
  expect((await account.db.select().from(account.passkeys).where(eq(account.passkeys.user_id, account.user.id))).length).toBe(1)
})

test('параллельное удаление passkeys сохраняет один способ входа', async () => {
  const account = await passwordlessAccount(2)
  const responses = await Promise.all(account.ids.map(id => app.request(`/web/auth/passkeys/${id}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${account.session.token}` },
  })))
  expect(responses.filter(response => response.status === 200).length).toBe(1)
  expect(responses.every(response => [200, 401, 409].includes(response.status))).toBe(true)
  expect((await account.db.select().from(account.passkeys).where(eq(account.passkeys.user_id, account.user.id))).length).toBe(1)
})

test('SSO проверяет cookie и создает одну учетную запись при параллельном первом входе', async () => {
  const { generateKeyPair, exportJWK, SignJWT } = await import('jose')
  const { oidcRoute } = await import('../src/routes/oidc')
  const oidc = new Hono().route('/web/auth/oidc', oidcRoute)
  const { privateKey, publicKey } = await generateKeyPair('ES256')
  const keys = { keys: [{ ...await exportJWK(publicKey), kid: 'test-key' }] }
  const codes = new Map<string, string>()
  const subject = randomUUID()
  let issuer = ''
  const identityProvider = Bun.serve({ hostname: '127.0.0.1', port: 0, async fetch(request) {
    const url = new URL(request.url)
    if (url.pathname === '/.well-known/openid-configuration') return Response.json({
      authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/keys`,
    })
    if (url.pathname === '/keys') return Response.json(keys)
    const form = await request.formData()
    return Response.json({ id_token: codes.get(String(form.get('code'))) })
  } })
  issuer = `http://127.0.0.1:${identityProvider.port}`
  const previous = { mode: config.OIDC_MODE, issuer: config.OIDC_ISSUER, client: config.OIDC_CLIENT_ID, origin: config.ORIGIN }
  Object.assign(config, { OIDC_MODE: 'enabled', OIDC_ISSUER: issuer, OIDC_CLIENT_ID: 'test-panel', ORIGIN: 'https://panel.example' })
  try {
    const invalid = await oidc.request('/web/auth/oidc/callback?code=test&state=test', { headers: { Cookie: '__Host-aivpn_oidc_pkce=bnVsbA==' } })
    expect(invalid.status).toBe(400)
    expect(await invalid.text()).toContain('Invalid PKCE cookie')
    const attempts = await Promise.all([1, 2].map(async () => {
      const start = await oidc.request('/web/auth/oidc/start')
      expect(start.status).toBe(302)
      const cookie = start.headers.get('set-cookie')!.split(';')[0]!
      expect(cookie.startsWith('__Host-aivpn_oidc_pkce=')).toBe(true)
      expect(start.headers.get('set-cookie')).toContain('; Secure')
      const location = new URL(start.headers.get('location')!)
      const state = location.searchParams.get('state')!
      const nonce = location.searchParams.get('nonce')!
      const code = randomUUID()
      codes.set(code, await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
        .setSubject(subject).setIssuer(issuer).setAudience('test-panel').setIssuedAt().setExpirationTime('5m').sign(privateKey))
      return { code, state, cookie }
    }))
    const results = await Promise.all(attempts.map(({ code, state, cookie }) => oidc.request(
      `/web/auth/oidc/callback?${new URLSearchParams({ code, state })}`, { headers: { Cookie: cookie } },
    )))
    for (const response of results) {
      expect(response.status).toBe(200)
      expect(await response.text()).toContain("location.replace('/dashboard')")
      expect(response.headers.get('set-cookie')).toContain('Max-Age=0')
    }
    const db = await getDb() as any
    const created = await db.select().from(users).where(eq(users.oidc_sub, subject))
    expect(created.length).toBe(1)
    expect(created[0].role).toBe('viewer')
  } finally {
    Object.assign(config, { OIDC_MODE: previous.mode, OIDC_ISSUER: previous.issuer, OIDC_CLIENT_ID: previous.client, ORIGIN: previous.origin })
    await identityProvider.stop(true)
  }
})


test('параллельные неверные пароли не обходят ограничение попыток', async () => {
  const username = await newUser()
  const responses = await Promise.all(Array.from({ length: config.AUTH_RATE_MAX + 3 }, () =>
    post('/web/auth/login', { username, password: 'wrong' })))
  expect(responses.filter(response => response.status === 401).length).toBe(config.AUTH_RATE_MAX)
  expect(responses.filter(response => response.status === 429).length).toBe(3)
}, 30000)


test('поздний ответ passkey не откатывает счетчик подписи', async () => {
  const username = await newUser()
  const db = await getDb() as any
  const { sqlitePasskeys, pgPasskeys } = await import('../src/db')
  const passkeys = IS_SQLITE ? sqlitePasskeys : pgPasskeys
  const { claimPasskeyCounter } = await import('../src/auth/passkey-counter')
  const [user] = await db.select().from(users).where(eq(users.username, username))
  const id = randomUUID()
  await db.insert(passkeys).values({ id, user_id: user.id, credential_id: randomUUID(), public_key: 'test', counter: 1 })
  expect(await claimPasskeyCounter(db, passkeys, id, 3)).toBe(true)
  expect(await claimPasskeyCounter(db, passkeys, id, 2)).toBe(false)
  expect(await claimPasskeyCounter(db, passkeys, id, 0)).toBe(false)
  const [stored] = await db.select().from(passkeys).where(eq(passkeys.id, id))
  expect(stored.counter).toBe(3)
  const zeroId = randomUUID()
  await db.insert(passkeys).values({ id: zeroId, user_id: user.id, credential_id: randomUUID(), public_key: 'test', counter: 0 })
  expect(await claimPasskeyCounter(db, passkeys, zeroId, 0)).toBe(true)
  expect(await claimPasskeyCounter(db, passkeys, zeroId, 0)).toBe(true)
})
