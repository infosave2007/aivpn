import type { Context, Next } from 'hono'
import { eq, and, gt } from 'drizzle-orm'
import { verifyAccessToken } from './jwt'
import { getDb, IS_SQLITE, sqliteUsers, sqliteSessions, pgUsers, pgSessions } from '../db'
import type { UserRole } from '../db/schema'

interface AuthUser {
  id: number
  role: UserRole
  session_version: number
  session_id: string
}

declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser
  }
}

/**
 * requireAuth middleware.
 * 1. Verifies Bearer JWT signature.
 * 2. Loads user from DB — rejects if session_version in token != DB value
 *    (catches password change, 2FA toggle, passkey add/remove).
 * 3. Confirms the sessions row still exists and is not expired
 *    (catches explicit logout / session revocation).
 */
export function requireAuth(roles?: UserRole[]) {
  return async (c: Context, next: Next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    const token = authHeader.slice(7)
    try {
      const payload = await verifyAccessToken(token)
      const userId = parseInt(payload.sub!, 10)
      const sessionId: string = payload.session_id
      const tokenVersion: number = payload.session_version

      const db = await getDb()

      let authUser: AuthUser

      if (IS_SQLITE) {
        const d = db as import('drizzle-orm/bun-sqlite').BunSQLiteDatabase<any>
        const [user] = await d
          .select({ id: sqliteUsers.id, role: sqliteUsers.role, session_version: sqliteUsers.session_version })
          .from(sqliteUsers)
          .where(eq(sqliteUsers.id, userId))
          .limit(1)

        if (!user || user.session_version !== tokenVersion) {
          return c.json({ error: 'Unauthorized' }, 401)
        }

        const [session] = await d
          .select({ id: sqliteSessions.id })
          .from(sqliteSessions)
          .where(and(
            eq(sqliteSessions.id, sessionId),
            eq(sqliteSessions.user_id, userId),
            gt(sqliteSessions.expires_at, new Date()),
          ))
          .limit(1)

        if (!session) {
          return c.json({ error: 'Unauthorized' }, 401)
        }

        authUser = { id: user.id, role: user.role as UserRole, session_version: user.session_version, session_id: sessionId }
      } else {
        const d = db as import('drizzle-orm/postgres-js').PostgresJsDatabase<any>
        const [user] = await d
          .select({ id: pgUsers.id, role: pgUsers.role, session_version: pgUsers.session_version })
          .from(pgUsers)
          .where(eq(pgUsers.id, userId))
          .limit(1)

        if (!user || user.session_version !== tokenVersion) {
          return c.json({ error: 'Unauthorized' }, 401)
        }

        const [session] = await d
          .select({ id: pgSessions.id })
          .from(pgSessions)
          .where(and(
            eq(pgSessions.id, sessionId),
            eq(pgSessions.user_id, userId),
            gt(pgSessions.expires_at, new Date()),
          ))
          .limit(1)

        if (!session) {
          return c.json({ error: 'Unauthorized' }, 401)
        }

        authUser = { id: user.id, role: user.role as UserRole, session_version: user.session_version, session_id: sessionId }
      }

      if (roles && !roles.includes(authUser.role)) {
        return c.json({ error: 'Forbidden' }, 403)
      }

      c.set('user', authUser)
      // Return next()'s result so a wrapping middleware (requireReadAccess)
      // that composes requireAuth can propagate the downstream response —
      // otherwise its own return value is undefined and Hono reports a 500
      // "Context is not finalized" instead of the real 401/403.
      return await next()
    } catch {
      return c.json({ error: 'Unauthorized' }, 401)
    }
  }
}

export const requireAdmin = requireAuth(['admin'])

/**
 * Viewer role is read-only: GET requests only, no access to restricted paths.
 */
export function requireReadAccess() {
  return async (c: Context, next: Next) => {
    return await requireAuth()(c, async () => {
      const user = c.get('user')
      if (user.role === 'viewer' && c.req.method !== 'GET') {
        return c.json({ error: 'Forbidden: viewer role is read-only' }, 403)
      }
      return await next()
    })
  }
}
