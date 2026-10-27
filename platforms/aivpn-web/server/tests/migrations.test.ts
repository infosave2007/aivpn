import { expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('обновление существующей базы добавляет версии пользователей и сессий без потери данных', () => {
  const directory = mkdtempSync(join(tmpdir(), 'aivpn-migration-test-'))
  try {
    const script = `
      import { Database } from 'bun:sqlite';
      const sqlite = new Database(process.env.DATABASE_URL.replace(/^file:/, ''));
      sqlite.exec(\`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
        password_hash TEXT, role TEXT NOT NULL DEFAULT 'viewer', totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0, passkey_only INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_login INTEGER
      ); INSERT INTO users(username) VALUES ('existing');\`);
      const { runMigrations } = await import('./server/src/db/migrate.ts');
      await runMigrations();
      await runMigrations();
      const rows = sqlite.query('SELECT username, session_version FROM users').all();
      if (rows.length !== 1 || rows[0].username !== 'existing' || rows[0].session_version !== 0) throw Error('migration lost user');
      sqlite.query('SELECT session_version FROM sessions').all();
      sqlite.close();
    `
    const result = Bun.spawnSync([process.execPath, '--eval', script], {
      cwd: join(import.meta.dir, '../..'),
      env: { ...process.env, DATABASE_URL: `file:${join(directory, 'old.db')}`,
        JWT_SECRET: 'migration-test-secret-with-at-least-thirty-two-characters', OIDC_MODE: 'disabled' },
      stdout: 'pipe', stderr: 'pipe',
    })
    expect(result.stderr.toString()).toBe('')
    expect(result.exitCode).toBe(0)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
