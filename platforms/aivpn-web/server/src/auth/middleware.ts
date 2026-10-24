import type { Context, Next } from 'hono'
import { eq, and, gt } from 'drizzle-orm'
import { verifyAccessToken } from './jwt'
import { getDb, IS_SQLITE, sqliteUsers, sqliteSessions, pgUsers, pgSessions } from '../db'
import type { UserRole } from '../db/schema'

export interface AuthUser {
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

export async function liveSessionUser(
  userId: number, sessionId: string, sessionVersion: number,
): Promise<AuthUser | null> {
  const db = await getDb()
  const users = IS_SQLITE ? sqliteUsers : pgUsers
  const sessions = IS_SQLITE ? sqliteSessions : pgSessions
  const [user] = await (db as any).select({
    id: users.id, role: users.role, session_version: users.session_version,
  }).from(users).innerJoin(sessions, and(
    eq(sessions.user_id, users.id), eq(sessions.id, sessionId),
    eq(sessions.session_version, users.session_version),
    gt(sessions.expires_at, new Date()),
  )).where(and(eq(users.id, userId), eq(users.session_version, sessionVersion))).limit(1)
  if (!user || !['admin', 'viewer'].includes(user.role)) return null
  return { ...user, session_id: sessionId }
}

export function requireAuth(roles?: UserRole[]) {
  return async (c: Context, next: Next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    let payload
    try {
      payload = await verifyAccessToken(authHeader.slice(7))
    } catch {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    const userId = Number(payload.sub)
    if (!Number.isSafeInteger(userId) || userId <= 0 || typeof payload.session_id !== 'string'
      || !Number.isSafeInteger(payload.session_version)) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    const user = await liveSessionUser(userId, payload.session_id, payload.session_version)
    if (!user) return c.json({ error: 'Unauthorized' }, 401)
    if (roles && !roles.includes(user.role)) return c.json({ error: 'Forbidden' }, 403)
    c.set('user', user)
    return await next()
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
        c.res = c.json({ error: 'Forbidden: viewer role is read-only' }, 403)
        return
      }
      return await next()
    })
  }
}
