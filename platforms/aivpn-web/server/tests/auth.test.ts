import { afterAll, beforeAll, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { Hono } from 'hono'

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
const { encryptTotpSecret } = await import('../src/auth/totp')
const { default: speakeasy } = await import('speakeasy')
const app = new Hono().route('/web/auth', auth).route('/api/v1', proxy)
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
