import { config, IS_SQLITE } from '../config'
export { IS_SQLITE }

// ─── Types shared by both drivers ────────────────────────────────────────────

export type DbClient = SqliteDb | PgDb

// We use a discriminated-union approach so callers can always narrow by IS_SQLITE.

type SqliteDb = import('drizzle-orm/bun-sqlite').BunSQLiteDatabase<SqliteSchema>
type PgDb = import('drizzle-orm/postgres-js').PostgresJsDatabase<PgSchema>

import type {
  sqliteUsers,
  sqliteSessions,
  sqlitePasskeys,
  sqliteWebAudit,
  pgUsers,
  pgSessions,
  pgPasskeys,
  pgWebAudit,
} from './schema'

type SqliteSchema = {
  users: typeof sqliteUsers
  sessions: typeof sqliteSessions
  passkeys: typeof sqlitePasskeys
  web_audit: typeof sqliteWebAudit
}

type PgSchema = {
  users: typeof pgUsers
  sessions: typeof pgSessions
  passkeys: typeof pgPasskeys
  web_audit: typeof pgWebAudit
}

// ─── Singleton ────────────────────────────────────────────────────────────────
// Promise-based lock prevents double-initialisation under concurrent requests.

let _dbPromise: Promise<DbClient> | null = null

async function initDb(): Promise<DbClient> {
  if (IS_SQLITE) {
    const { Database } = await import('bun:sqlite')
    const { drizzle } = await import('drizzle-orm/bun-sqlite')
    const {
      sqliteUsers,
      sqliteSessions,
      sqlitePasskeys,
      sqliteWebAudit,
    } = await import('./schema')

    const dbPath = config.DATABASE_URL.replace(/^file:/, '')

    const path = await import('node:path')
    const fs = await import('node:fs')
    const dir = path.dirname(dbPath)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })

    const sqlite = new Database(dbPath)
    sqlite.exec('PRAGMA journal_mode=WAL;')
    sqlite.exec('PRAGMA foreign_keys=ON;')

    return drizzle(sqlite, {
      schema: {
        users: sqliteUsers,
        sessions: sqliteSessions,
        passkeys: sqlitePasskeys,
        web_audit: sqliteWebAudit,
      },
    }) as SqliteDb
  } else {
    const postgres = (await import('postgres')).default
    const { drizzle } = await import('drizzle-orm/postgres-js')
    const { pgUsers, pgSessions, pgPasskeys, pgWebAudit } = await import('./schema')

    const client = postgres(config.DATABASE_URL, { max: 10 })
    return drizzle(client, {
      schema: {
        users: pgUsers,
        sessions: pgSessions,
        passkeys: pgPasskeys,
        web_audit: pgWebAudit,
      },
    }) as PgDb
  }
}

export function getDb(): Promise<DbClient> {
  if (!_dbPromise) _dbPromise = initDb()
  return _dbPromise
}

// Convenience re-export so consumers don't need to import from schema separately
export * from './schema'
