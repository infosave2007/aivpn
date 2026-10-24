/**
 * Run database migrations on startup.
 * For SQLite: inline idempotent DDL (CREATE TABLE IF NOT EXISTS + guarded ALTERs).
 * For PostgreSQL: same approach — inline idempotent DDL. drizzle's journal-based
 * migrate() is NOT used: migrations/*.sql have no meta/_journal.json (so the
 * migrator would throw at startup) and no 0000 bootstrap migration exists.
 */

import { IS_SQLITE, config } from '../config'

export async function runMigrations(): Promise<void> {
  console.log('[db] Running migrations…')

  if (IS_SQLITE) {
    const { Database } = await import('bun:sqlite')
    const { drizzle } = await import('drizzle-orm/bun-sqlite')
    const { migrate } = await import('drizzle-orm/bun-sqlite/migrator')
    const {
      sqliteUsers,
      sqliteSessions,
      sqlitePasskeys,
      sqliteWebAudit,
    } = await import('./schema')

    const path = await import('node:path')
    const fs = await import('node:fs')
    const dbPath = config.DATABASE_URL.replace(/^file:/, '')
    const dir = path.dirname(dbPath)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })

    const sqlite = new Database(dbPath)
    sqlite.exec('PRAGMA journal_mode=WAL;')
    sqlite.exec('PRAGMA foreign_keys=ON;')

    const db = drizzle(sqlite, {
      schema: {
        users: sqliteUsers,
        sessions: sqliteSessions,
        passkeys: sqlitePasskeys,
        web_audit: sqliteWebAudit,
      },
    })

    // Use inline DDL for SQLite — no external migration files needed at startup
    sqlite.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'viewer',
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_last_step INTEGER,
        session_version INTEGER NOT NULL DEFAULT 0,
        passkey_only INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        last_login INTEGER
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        refresh_token_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        prev_token_hash TEXT,
        prev_expires_at INTEGER,
        ip TEXT,
        ua TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
      );

      CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        aaguid TEXT,
        transports TEXT,
        name TEXT NOT NULL DEFAULT 'Passkey',
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        last_used_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS web_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        target TEXT,
        result TEXT NOT NULL,
        ip TEXT,
        ts INTEGER NOT NULL DEFAULT (unixepoch())
      );
    `)

    // Add OIDC identity + TOTP replay-protection columns if they don't exist
    // yet (idempotent ALTER TABLE)
    for (const col of ['oidc_iss TEXT', 'oidc_sub TEXT', 'totp_last_step INTEGER']) {
      try { sqlite.exec(`ALTER TABLE users ADD COLUMN ${col}`) } catch { /* already exists */ }
    }
    // Refresh-rotation grace columns (cross-tab refresh race, routes/auth.ts)
    for (const col of ['prev_token_hash TEXT', 'prev_expires_at INTEGER', 'session_version INTEGER NOT NULL DEFAULT 0']) {
      try { sqlite.exec(`ALTER TABLE sessions ADD COLUMN ${col}`) } catch { /* already exists */ }
    }
    try {
      sqlite.exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_idx ON users (oidc_iss, oidc_sub) WHERE oidc_iss IS NOT NULL`)
    } catch { /* already exists */ }

    console.log('[db] SQLite schema ready')
    return
  }

  // PostgreSQL: inline idempotent DDL, mirroring the SQLite path above.
  // Column types match the pg schema in ./schema.ts; the guarded ALTERs mirror
  // migrations/0001-0003 so existing databases pick up later columns too.
  const postgres = (await import('postgres')).default
  const migrationClient = postgres(config.DATABASE_URL, { max: 1 })

  try {
    await migrationClient.unsafe(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) NOT NULL UNIQUE,
        password_hash VARCHAR(255),
        role VARCHAR(16) NOT NULL DEFAULT 'viewer',
        totp_secret VARCHAR(128),
        totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        totp_last_step INTEGER,
        session_version INTEGER NOT NULL DEFAULT 0,
        passkey_only BOOLEAN NOT NULL DEFAULT FALSE,
        oidc_iss VARCHAR(512),
        oidc_sub VARCHAR(256),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_login TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id VARCHAR(64) PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        refresh_token_hash VARCHAR(128) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        prev_token_hash VARCHAR(128),
        prev_expires_at TIMESTAMPTZ,
        ip VARCHAR(64),
        ua VARCHAR(512),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS passkeys (
        id VARCHAR(64) PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id VARCHAR(512) NOT NULL UNIQUE,
        public_key VARCHAR(4096) NOT NULL,
        counter BIGINT NOT NULL DEFAULT 0,
        aaguid VARCHAR(64),
        transports JSONB,
        name VARCHAR(128) NOT NULL DEFAULT 'Passkey',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_used_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS web_audit (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(128) NOT NULL,
        target VARCHAR(256),
        result VARCHAR(16) NOT NULL,
        ip VARCHAR(64),
        ts TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      -- 0001: OIDC identity columns (users created before the column existed)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_iss VARCHAR(512);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub VARCHAR(256);
      CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_idx ON users (oidc_iss, oidc_sub) WHERE oidc_iss IS NOT NULL;

      -- 0002: refresh-rotation grace columns (cross-tab refresh race, routes/auth.ts)
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS prev_token_hash VARCHAR(128);
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS prev_expires_at TIMESTAMPTZ;

      -- 0003: TOTP replay protection — last accepted RFC 6238 time step
      ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step INTEGER;

      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;
    `)
  } finally {
    await migrationClient.end()
  }

  console.log('[db] PostgreSQL schema ready')
}

// Allow running directly: `bun src/db/migrate.ts`
if (import.meta.main) {
  await runMigrations()
  process.exit(0)
}
