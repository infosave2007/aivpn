import { expect, test } from 'bun:test'
import { randomBytes } from 'node:crypto'

test('отсутствующие булевы настройки не включают dev proxy и доверие заголовкам', async () => {
  const module = new URL('../src/config.ts', import.meta.url).pathname
  const env: Record<string, string | undefined> = { ...process.env, JWT_SECRET: randomBytes(48).toString('hex') }
  delete env.DEV_MODE
  delete env.AIVPN_WEB_TRUST_PROXY
  const child = Bun.spawn([process.execPath, '-e', `const {config}=await import(${JSON.stringify(module)}); console.log(JSON.stringify([config.DEV_MODE,config.AIVPN_WEB_TRUST_PROXY]))`], {
    env, stdout: 'pipe', stderr: 'pipe',
  })
  const output = await new Response(child.stdout).text()
  await new Response(child.stderr).text()
  expect(await child.exited).toBe(0)
  expect(JSON.parse(output)).toEqual([false, false])
})

test('origin нормализует регистр и завершающий слеш, неверные адреса отклоняются', async () => {
  const module = new URL('../src/config.ts', import.meta.url).pathname
  for (const [origin, expected] of [
    ['HTTPS://PANEL.EXAMPLE:443/', 'https://panel.example'],
    ['http://localhost:3000/', 'http://localhost:3000'],
    ['https://panel.example/path', null],
    ['https://user:password@panel.example', null],
    ['ftp://panel.example', null],
  ] as const) {
    const child = Bun.spawn([process.execPath, '-e', `const {config}=await import(${JSON.stringify(module)}); console.log(config.ORIGIN)`], {
      env: { ...process.env, ORIGIN: origin, JWT_SECRET: randomBytes(48).toString('hex') },
      stdout: 'pipe', stderr: 'pipe',
    })
    const output = await new Response(child.stdout).text()
    await new Response(child.stderr).text()
    const code = await child.exited
    expect(code).toBe(expected === null ? 1 : 0)
    if (expected !== null) expect(output.trim()).toBe(expected)
  }
})

test('OIDC issuer требует HTTPS без учетных данных, query и fragment', async () => {
  const module = new URL('../src/config.ts', import.meta.url).pathname
  for (const [issuer, accepted] of [
    ['https://id.example/realms/vpn', true],
    ['http://id.example', false],
    ['https://user:secret@id.example', false],
    ['https://id.example/?mode=test', false],
    ['https://id.example/#issuer', false],
  ] as const) {
    const child = Bun.spawn([process.execPath, '-e', `await import(${JSON.stringify(module)})`], {
      env: { ...process.env, OIDC_ISSUER: issuer, JWT_SECRET: randomBytes(48).toString('hex') },
      stdout: 'pipe', stderr: 'pipe',
    })
    await new Response(child.stdout).text()
    await new Response(child.stderr).text()
    expect(await child.exited).toBe(accepted ? 0 : 1)
  }
})
