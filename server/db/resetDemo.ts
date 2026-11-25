import { getDatabase } from './connection.ts';
import { resetLocalAnchorCheckpoint } from './auditAnchors.ts';
import { initializeSchema } from './schema.ts';
import { seedDatabase } from './seed.ts';
import { getStorageProvider } from '../storage/index.ts';

export async function resetDemoDatabase(): Promise<void> {
  const db = getDatabase();
  initializeSchema(db);

  const storage = getStorageProvider();
  await storage.resetDemoStorage();
  await resetLocalAnchorCheckpoint();

  const clearTables = db.transaction(() => {
    db.exec(`
      DELETE FROM audit_anchors;
      DELETE FROM audit_logs;
      DELETE FROM sessions;
      DELETE FROM access_requests;
      DELETE FROM access_grants;
      DELETE FROM documents;
      DELETE FROM policies;
      DELETE FROM users;
      DELETE FROM departments;
    `);
  });

  clearTables();
  await seedDatabase();
}
