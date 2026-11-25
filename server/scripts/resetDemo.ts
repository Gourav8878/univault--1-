import { closeDatabase } from '../db/connection.ts';
import { resetDemoDatabase } from '../db/resetDemo.ts';

async function main(): Promise<void> {
  try {
    await resetDemoDatabase();
    console.log('[UniVault] Demo database and private storage safely reset and re-seeded.');
  } catch (error) {
    console.error('[UniVault] Demo reset failed:', error);
    process.exitCode = 1;
  } finally {
    closeDatabase();
  }
}

void main();
