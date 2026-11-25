import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import { env } from '../config/env.ts';
import type { AuthContext, AuthenticatedSession, UserRole } from './types.ts';

export const SESSION_TTL_HOURS = 8;

export interface SessionLookupResult {
  status: 'VALID' | 'NOT_FOUND' | 'REVOKED' | 'EXPIRED' | 'USER_INACTIVE';
  auth?: AuthContext;
  userId?: string;
  sessionId?: string;
}

export function generateOpaqueSessionToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashSessionToken(rawToken: string): string {
  return crypto.createHmac('sha256', env.sessionSecret).update(rawToken).digest('hex');
}

export function createSessionRecord(
  db: Database.Database,
  userId: string
): { rawToken: string; session: AuthenticatedSession } {
  const id = crypto.randomUUID();
  const rawToken = generateOpaqueSessionToken();
  const tokenHash = hashSessionToken(rawToken);

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_HOURS * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO sessions (id, user_id, session_token_hash, created_at, expires_at, revoked_at)
    VALUES (?, ?, ?, ?, ?, NULL)
  `).run(id, userId, tokenHash, createdAt, expiresAt);

  return {
    rawToken,
    session: {
      id,
      createdAt,
      expiresAt,
    },
  };
}

interface SessionJoinRow {
  session_id: string;
  session_created_at: string;
  session_expires_at: string;
  session_revoked_at: string | null;
  user_id: string;
  user_name: string;
  user_email: string;
  user_role: UserRole;
  user_department_id: string;
  user_active: number;
  department_name: string;
  department_code: string;
}

export function validateSessionToken(
  db: Database.Database,
  rawToken: string
): SessionLookupResult {
  const tokenHash = hashSessionToken(rawToken);

  const row = db
    .prepare(`
      SELECT
        s.id AS session_id,
        s.created_at AS session_created_at,
        s.expires_at AS session_expires_at,
        s.revoked_at AS session_revoked_at,
        u.id AS user_id,
        u.name AS user_name,
        u.email AS user_email,
        u.role AS user_role,
        u.department_id AS user_department_id,
        u.active AS user_active,
        d.name AS department_name,
        d.code AS department_code
      FROM sessions s
      INNER JOIN users u ON u.id = s.user_id
      INNER JOIN departments d ON d.id = u.department_id
      WHERE s.session_token_hash = ?
      LIMIT 1
    `)
    .get(tokenHash) as SessionJoinRow | undefined;

  if (!row) {
    return { status: 'NOT_FOUND' };
  }

  if (row.session_revoked_at !== null) {
    return {
      status: 'REVOKED',
      userId: row.user_id,
      sessionId: row.session_id,
    };
  }

  const expiresMs = Date.parse(row.session_expires_at);
  if (Number.isNaN(expiresMs) || expiresMs <= Date.now()) {
    return {
      status: 'EXPIRED',
      userId: row.user_id,
      sessionId: row.session_id,
    };
  }

  if (row.user_active !== 1) {
    return {
      status: 'USER_INACTIVE',
      userId: row.user_id,
      sessionId: row.session_id,
    };
  }

  return {
    status: 'VALID',
    userId: row.user_id,
    sessionId: row.session_id,
    auth: {
      user: {
        id: row.user_id,
        name: row.user_name,
        email: row.user_email,
        role: row.user_role,
        departmentId: row.user_department_id,
        departmentName: row.department_name,
        departmentCode: row.department_code,
        active: row.user_active === 1,
      },
      session: {
        id: row.session_id,
        createdAt: row.session_created_at,
        expiresAt: row.session_expires_at,
      },
    },
  };
}

export function revokeSessionByRawToken(
  db: Database.Database,
  rawToken: string
): { revoked: boolean; sessionId?: string; userId?: string } {
  const tokenHash = hashSessionToken(rawToken);

  const existing = db
    .prepare(`
      SELECT id, user_id, revoked_at
      FROM sessions
      WHERE session_token_hash = ?
      LIMIT 1
    `)
    .get(tokenHash) as { id: string; user_id: string; revoked_at: string | null } | undefined;

  if (!existing) {
    return { revoked: false };
  }

  if (existing.revoked_at !== null) {
    return { revoked: false, sessionId: existing.id, userId: existing.user_id };
  }

  const revokedAt = new Date().toISOString();
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(revokedAt, existing.id);

  return {
    revoked: true,
    sessionId: existing.id,
    userId: existing.user_id,
  };
}
