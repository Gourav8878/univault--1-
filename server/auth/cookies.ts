import type { Request, Response } from 'express';
import { env } from '../config/env.ts';

export const SESSION_COOKIE_NAME = 'univault_session';

export type SessionChannel = 'default' | 'demo_faculty' | 'demo_hod';

const COOKIE_BY_CHANNEL: Record<SessionChannel, string> = {
  default: SESSION_COOKIE_NAME,
  demo_faculty: 'univault_demo_faculty_session',
  demo_hod: 'univault_demo_hod_session',
};

export function resolveSessionChannel(rawChannel: unknown): SessionChannel {
  if (rawChannel === 'demo_faculty' || rawChannel === 'demo_hod') {
    return rawChannel;
  }
  return 'default';
}

export function getCookieNameForRequest(req: Request, explicitChannel?: unknown): string {
  const candidate =
    explicitChannel ??
    req.headers['x-session-channel'] ??
    (typeof req.query.channel === 'string' ? req.query.channel : undefined);
  return COOKIE_BY_CHANNEL[resolveSessionChannel(candidate)];
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }

  const parsed: Record<string, string> = {};
  const pairs = cookieHeader.split(';');

  for (const pair of pairs) {
    const separatorIdx = pair.indexOf('=');
    if (separatorIdx <= 0) {
      continue;
    }

    const key = pair.slice(0, separatorIdx).trim();
    const rawValue = pair.slice(separatorIdx + 1).trim();
    if (!key) {
      continue;
    }

    try {
      parsed[key] = decodeURIComponent(rawValue);
    } catch {
      parsed[key] = rawValue;
    }
  }

  return parsed;
}

function isHttpsRequest(req: Request): boolean {
  const forwardedProto = req.headers['x-forwarded-proto'];
  const protoValue = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
  const isForwardedHttps =
    typeof protoValue === 'string' &&
    protoValue.split(',')[0].trim().toLowerCase() === 'https';

  const origin = req.headers.origin;
  const isHttpsOrigin =
    typeof origin === 'string' && origin.trim().toLowerCase().startsWith('https://');

  const referer = req.headers.referer;
  const isHttpsReferer =
    typeof referer === 'string' && referer.trim().toLowerCase().startsWith('https://');

  return (
    req.secure ||
    isForwardedHttps ||
    env.nodeEnv === 'production' ||
    isHttpsOrigin ||
    isHttpsReferer
  );
}

function appendSetCookieHeader(res: Response, cookieString: string): void {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', cookieString);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing.map(String), cookieString]);
  } else {
    res.setHeader('Set-Cookie', [String(existing), cookieString]);
  }
}

export function setSessionCookie(
  req: Request,
  res: Response,
  rawToken: string,
  expiresAtIso: string,
  cookieName = SESSION_COOKIE_NAME
): void {
  const expiresDate = new Date(expiresAtIso);
  const parts = [
    `${cookieName}=${encodeURIComponent(rawToken)}`,
    'Path=/',
    `Expires=${expiresDate.toUTCString()}`,
    'HttpOnly',
  ];

  if (isHttpsRequest(req)) {
    parts.push('SameSite=None', 'Secure', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }

  appendSetCookieHeader(res, parts.join('; '));
}

export function clearSessionCookie(
  req: Request,
  res: Response,
  cookieName = SESSION_COOKIE_NAME
): void {
  const parts = [
    `${cookieName}=`,
    'Path=/',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'Max-Age=0',
    'HttpOnly',
  ];

  if (isHttpsRequest(req)) {
    parts.push('SameSite=None', 'Secure', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }

  appendSetCookieHeader(res, parts.join('; '));
}
