import bcrypt from 'bcryptjs';
import { Router } from 'express';
import { appendAuditLog } from '../db/audit.ts';
import { getDatabase } from '../db/connection.ts';
import {
  clearSessionCookie,
  getCookieNameForRequest,
  parseCookies,
  setSessionCookie,
} from '../auth/cookies.ts';
import { requireAuth } from '../auth/middleware.ts';
import { createSessionRecord, revokeSessionByRawToken } from '../auth/session.ts';
import type { UserRole } from '../auth/types.ts';

interface UserLoginRow {
  id: string;
  name: string;
  email: string;
  password_hash: string;
  role: UserRole;
  department_id: string;
  active: number;
  department_name: string;
  department_code: string;
}

const authRouter = Router();

authRouter.post('/login', async (req, res) => {
  const body = req.body as { email?: unknown; password?: unknown; channel?: unknown } | undefined;
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  const cookieName = getCookieNameForRequest(req, body?.channel);

  if (!email || !password) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Email and password are required.',
    });
    return;
  }

  const db = getDatabase();

  const user = db
    .prepare(`
      SELECT
        u.id,
        u.name,
        u.email,
        u.password_hash,
        u.role,
        u.department_id,
        u.active,
        d.name AS department_name,
        d.code AS department_code
      FROM users u
      INNER JOIN departments d ON d.id = u.department_id
      WHERE LOWER(u.email) = LOWER(?)
      LIMIT 1
    `)
    .get(email) as UserLoginRow | undefined;

  if (!user) {
    appendAuditLog(db, {
      actorId: null,
      action: 'AUTH_LOGIN_FAILED',
      decision: 'DENY',
      denialReason: 'INVALID_CREDENTIALS',
      metadata: { email },
      requestId: req.requestId,
    });

    res.status(401).json({
      error: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password.',
    });
    return;
  }

  const passwordMatches = await bcrypt.compare(password, user.password_hash);
  if (!passwordMatches) {
    appendAuditLog(db, {
      actorId: user.id,
      action: 'AUTH_LOGIN_FAILED',
      decision: 'DENY',
      denialReason: 'INVALID_CREDENTIALS',
      metadata: { email },
      requestId: req.requestId,
    });

    res.status(401).json({
      error: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password.',
    });
    return;
  }

  if (user.active !== 1) {
    appendAuditLog(db, {
      actorId: user.id,
      action: 'AUTH_LOGIN_DENIED',
      decision: 'DENY',
      denialReason: 'USER_INACTIVE',
      metadata: { email },
      requestId: req.requestId,
    });

    res.status(403).json({
      error: 'USER_INACTIVE',
      message: 'User account is inactive. Contact an administrator.',
    });
    return;
  }

  const { rawToken, session } = createSessionRecord(db, user.id);
  setSessionCookie(req, res, rawToken, session.expiresAt, cookieName);

  appendAuditLog(db, {
    actorId: user.id,
    action: 'AUTH_LOGIN_SUCCESS',
    decision: 'ALLOW',
    metadata: {
      sessionId: session.id,
      role: user.role,
      departmentCode: user.department_code,
    },
    requestId: req.requestId,
  });

  res.status(200).json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      departmentId: user.department_id,
      departmentName: user.department_name,
      departmentCode: user.department_code,
      active: user.active === 1,
    },
    session,
  });
});

authRouter.post('/logout', (req, res) => {
  const body = req.body as { channel?: unknown } | undefined;
  const cookieName = getCookieNameForRequest(req, body?.channel);
  const cookies = parseCookies(req.headers.cookie);
  const rawToken = cookies[cookieName];

  if (rawToken && rawToken.trim()) {
    const db = getDatabase();
    const revocation = revokeSessionByRawToken(db, rawToken.trim());

    if (revocation.revoked && revocation.userId) {
      appendAuditLog(db, {
        actorId: revocation.userId,
        action: 'AUTH_LOGOUT',
        decision: 'ALLOW',
        metadata: { sessionId: revocation.sessionId },
        requestId: req.requestId,
      });
    }
  }

  clearSessionCookie(req, res, cookieName);
  res.status(200).json({ message: 'Logged out successfully.' });
});

authRouter.get('/me', requireAuth, (req, res) => {
  res.status(200).json({
    user: req.auth!.user,
    session: req.auth!.session,
  });
});

export { authRouter };
