import type { NextFunction, Request, Response } from 'express';
import { getDatabase } from '../db/connection.ts';
import { getCookieNameForRequest, parseCookies } from './cookies.ts';
import { validateSessionToken } from './session.ts';

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const cookies = parseCookies(req.headers.cookie);
  const cookieName = getCookieNameForRequest(req);
  const rawToken = cookies[cookieName];

  if (!rawToken || !rawToken.trim()) {
    res.status(401).json({
      error: 'USER_UNAUTHENTICATED',
      message: 'Authentication required. No active session cookie was provided.',
    });
    return;
  }

  const db = getDatabase();
  const result = validateSessionToken(db, rawToken.trim());

  if (result.status === 'USER_INACTIVE') {
    res.status(403).json({
      error: 'USER_INACTIVE',
      message: 'Access denied. Your user account has been deactivated.',
    });
    return;
  }

  if (result.status !== 'VALID' || !result.auth) {
    const messageByStatus: Record<string, string> = {
      REVOKED: 'Session has been revoked. Please sign in again.',
      EXPIRED: 'Session has expired. Please sign in again.',
      NOT_FOUND: 'Invalid session. Please sign in again.',
    };

    res.status(401).json({
      error: 'USER_UNAUTHENTICATED',
      message: messageByStatus[result.status] ?? 'Authentication required.',
    });
    return;
  }

  req.auth = result.auth;
  next();
}

function getAllowedHosts(req: Request): Set<string> {
  const hosts = new Set<string>();
  const forwardedHost = req.headers['x-forwarded-host'];
  const hostHeader = req.headers.host;

  for (const candidate of [forwardedHost, hostHeader]) {
    const value = Array.isArray(candidate) ? candidate[0] : candidate;
    if (typeof value === 'string' && value.trim()) {
      hosts.add(value.split(',')[0].trim().toLowerCase());
    }
  }

  const appUrl = process.env.APP_URL?.trim();
  if (appUrl) {
    try {
      hosts.add(new URL(appUrl).host.toLowerCase());
    } catch {
      // Ignore invalid APP_URL
    }
  }

  return hosts;
}

export function verifyMutatingOrigin(req: Request, res: Response, next: NextFunction): void {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    next();
    return;
  }

  const originHeader = req.headers.origin;
  if (typeof originHeader === 'string' && originHeader.trim().length > 0) {
    try {
      const originHost = new URL(originHeader).host.toLowerCase();
      const allowedHosts = getAllowedHosts(req);
      if (!allowedHosts.has(originHost)) {
        res.status(403).json({
          error: 'ORIGIN_MISMATCH',
          message: 'Cross-origin mutating request blocked.',
        });
        return;
      }
      next();
      return;
    } catch {
      res.status(403).json({
        error: 'ORIGIN_MISMATCH',
        message: 'Invalid request origin.',
      });
      return;
    }
  }

  const customHeader = req.headers['x-requested-with'];
  if (typeof customHeader === 'string' && customHeader.trim().length > 0) {
    next();
    return;
  }

  next();
}
