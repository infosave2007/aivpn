import { expect, test } from 'bun:test'
import { randomBytes } from 'node:crypto'

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
