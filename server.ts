import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import { createApiApp } from './server/app.ts';
import { env } from './server/config/env.ts';
import { createAuditAnchor } from './server/db/auditAnchors.ts';
import { closeDatabase, getDatabase } from './server/db/connection.ts';
import { initializeSchema } from './server/db/schema.ts';
import { seedDatabase } from './server/db/seed.ts';
import { getStorageProvider } from './server/storage/index.ts';

async function startServer(): Promise<void> {
  const db = getDatabase();
  initializeSchema(db);
  await seedDatabase();

  const storage = getStorageProvider();
  const storageHealth = await storage.healthCheck();
  if (!storageHealth.healthy) {
    console.warn(`[UniVault] Storage check warning: ${storageHealth.message}`);
  }

  let anchorTimer: ReturnType<typeof setInterval> | null = null;
  if (env.auditAnchorIntervalMinutes > 0) {
    const intervalMs = env.auditAnchorIntervalMinutes * 60 * 1000;
    anchorTimer = setInterval(() => {
      void createAuditAnchor(db, {
        triggeredBy: null,
        logEvent: true,
      }).catch((err) => {
        console.warn('[UniVault] Periodic audit anchor failed:', (err as Error).message);
      });
    }, intervalMs);
    anchorTimer.unref();
  }

  const app = createApiApp();

  if (env.nodeEnv !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexHtml = path.join(distDir, 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.sendFile(indexHtml);
      } else {
        res.status(404).send('Production build not found. Run npm run build.');
      }
    });
  }

  const server = app.listen(env.port, '0.0.0.0', () => {
    console.log(`[UniVault] Server listening on http://0.0.0.0:${env.port}`);
    console.log(`[UniVault] Active storage provider: ${storage.providerName}`);
  });

  const shutdown = () => {
    if (anchorTimer) {
      clearInterval(anchorTimer);
    }
    server.close(() => {
      closeDatabase();
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void startServer();
