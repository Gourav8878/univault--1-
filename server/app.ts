import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import multer from 'multer';
import { verifyMutatingOrigin } from './auth/middleware.ts';
import { auditLogsRouter } from './routes/auditLogs.ts';
import { authRouter } from './routes/auth.ts';
import { departmentsRouter } from './routes/departments.ts';
import { documentsRouter } from './routes/documents.ts';
import { grantsRouter } from './routes/grants.ts';
import { healthRouter } from './routes/health.ts';

export function createApiApp(): express.Express {
  const app = express();

  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));

  app.use((req, res, next) => {
    const requestId = crypto.randomUUID();
    req.requestId = requestId;
    res.setHeader('X-Request-Id', requestId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.use('/api', verifyMutatingOrigin);

  // Private storage is NEVER mounted via express.static.
  app.use('/api', healthRouter);
  app.use('/api/auth', authRouter);
  app.use('/api/departments', departmentsRouter);
  app.use('/api/documents', documentsRouter);
  app.use('/api/grants', grantsRouter);
  app.use('/api/audit-logs', auditLogsRouter);

  app.use('/api', (_req, res) => {
    res.status(404).json({
      error: 'NOT_FOUND',
      message: 'Requested API endpoint does not exist.',
    });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof multer.MulterError) {
      res.status(400).json({
        error: err.code,
        message:
          err.code === 'LIMIT_FILE_SIZE'
            ? 'Uploaded PDF exceeds the 10 MB size limit.'
            : err.message,
      });
      return;
    }

    console.error('[UniVault] Unhandled API error:', err);
    res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected server error occurred.',
    });
  });

  return app;
}
