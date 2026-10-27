import { sql } from 'drizzle-orm'
import {
  integer,
  sqliteTable,
  text,
} from 'drizzle-orm/sqlite-core'
import {
  pgTable,
  integer as pgInteger,
  serial,
  varchar,
  boolean,
  timestamp,
  bigint,
  jsonb,
} from 'drizzle-orm/pg-core'

// ─── SQLite schema ───────────────────────────────────────────────────────────

export const sqliteUsers = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username').notNull().unique(),
  password_hash: text('password_hash'),
  role: text('role', { enum: ['admin', 'viewer'] }).notNull().default('viewer'),
  totp_secret: text('totp_secret'),
  totp_enabled: integer('totp_enabled', { mode: 'boolean' }).notNull().default(false),
  // Last accepted RFC 6238 time step — one-time-use enforcement (auth/totp.ts)
  totp_last_step: integer('totp_last_step'),
  session_version: integer('session_version').notNull().default(0),
  passkey_only: integer('passkey_only', { mode: 'boolean' }).notNull().default(false),
  oidc_iss: text('oidc_iss'),
  oidc_sub: text('oidc_sub'),
  created_at: integer('created_at', { mode: 'timestamp' })
    .notNull()
    .default(sql`(unixepoch())`),
  last_login: integer('last_login', { mode: 'timestamp' }),
})

export const sqliteSessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  user_id: integer('user_id')
    .notNull()
    .references(() => sqliteUsers.id, { onDelete: 'cascade' }),
  refresh_token_hash: text('refresh_token_hash').notNull(),
  expires_at: integer('expires_at', { mode: 'timestamp' }).notNull(),
  // Previous refresh-token hash, honoured for a short grace window after
  // rotation (cross-tab refresh race — see routes/auth.ts POST /refresh).
  prev_token_hash: text('prev_token_hash'),
  prev_expires_at: integer('prev_expires_at', { mode: 'timestamp' }),
  ip: text('ip'),
  ua: text('ua'),
  created_at: integer('created_at', { mode: 'timestamp' })
    .notNull()
    .default(sql`(unixepoch())`),
})

export const sqlitePasskeys = sqliteTable('passkeys', {
  id: text('id').primaryKey(),
  user_id: integer('user_id')
    .notNull()
    .references(() => sqliteUsers.id, { onDelete: 'cascade' }),
  credential_id: text('credential_id').notNull().unique(),
  public_key: text('public_key').notNull(), // base64url encoded COSE key
  counter: integer('counter').notNull().default(0),
  aaguid: text('aaguid'),
  transports: text('transports'), // JSON array
  name: text('name').notNull().default('Passkey'),
  created_at: integer('created_at', { mode: 'timestamp' })
    .notNull()
    .default(sql`(unixepoch())`),
  last_used_at: integer('last_used_at', { mode: 'timestamp' }),
})

export const sqliteWebAudit = sqliteTable('web_audit', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  user_id: integer('user_id').references(() => sqliteUsers.id, { onDelete: 'set null' }),
  action: text('action').notNull(),
  target: text('target'),
  result: text('result', { enum: ['ok', 'fail', 'denied'] }).notNull(),
  ip: text('ip'),
  ts: integer('ts', { mode: 'timestamp' })
    .notNull()
    .default(sql`(unixepoch())`),
})

// ─── PostgreSQL schema ───────────────────────────────────────────────────────
// Обе схемы строятся независимо и используют типы своего SQL-диалекта.

export const pgUsers = pgTable('users', {
  id: serial('id').primaryKey(),
  username: varchar('username', { length: 64 }).notNull().unique(),
  password_hash: varchar('password_hash', { length: 255 }),
  role: varchar('role', { length: 16 }).notNull().default('viewer'),
  totp_secret: varchar('totp_secret', { length: 128 }),
  totp_enabled: boolean('totp_enabled').notNull().default(false),
  // Last accepted RFC 6238 time step — one-time-use enforcement (auth/totp.ts)
  totp_last_step: pgInteger('totp_last_step'),
  session_version: pgInteger('session_version').notNull().default(0),
  passkey_only: boolean('passkey_only').notNull().default(false),
  oidc_iss: varchar('oidc_iss', { length: 512 }),
  oidc_sub: varchar('oidc_sub', { length: 256 }),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  last_login: timestamp('last_login', { withTimezone: true }),
})

export const pgSessions = pgTable('sessions', {
  id: varchar('id', { length: 64 }).primaryKey(),
  user_id: pgInteger('user_id')
    .notNull()
    .references(() => pgUsers.id, { onDelete: 'cascade' }),
  refresh_token_hash: varchar('refresh_token_hash', { length: 128 }).notNull(),
  expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  prev_token_hash: varchar('prev_token_hash', { length: 128 }),
  prev_expires_at: timestamp('prev_expires_at', { withTimezone: true }),
  ip: varchar('ip', { length: 64 }),
  ua: varchar('ua', { length: 512 }),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const pgPasskeys = pgTable('passkeys', {
  id: varchar('id', { length: 64 }).primaryKey(),
  user_id: pgInteger('user_id')
    .notNull()
    .references(() => pgUsers.id, { onDelete: 'cascade' }),
  credential_id: varchar('credential_id', { length: 512 }).notNull().unique(),
  public_key: varchar('public_key', { length: 4096 }).notNull(),
  counter: bigint('counter', { mode: 'number' }).notNull().default(0),
  aaguid: varchar('aaguid', { length: 64 }),
  transports: jsonb('transports').$type<string[]>(),
  name: varchar('name', { length: 128 }).notNull().default('Passkey'),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  last_used_at: timestamp('last_used_at', { withTimezone: true }),
})

export const pgWebAudit = pgTable('web_audit', {
  id: serial('id').primaryKey(),
  user_id: pgInteger('user_id').references(() => pgUsers.id, { onDelete: 'set null' }),
  action: varchar('action', { length: 128 }).notNull(),
  target: varchar('target', { length: 256 }),
  result: varchar('result', { length: 16 }).notNull(),
  ip: varchar('ip', { length: 64 }),
  ts: timestamp('ts', { withTimezone: true }).notNull().defaultNow(),
})

// ─── Exported aliases ────────────────────────────────────────────────────────
// The db/index.ts picks the right driver; code everywhere uses these type aliases.

export type UserRole = 'admin' | 'viewer'
