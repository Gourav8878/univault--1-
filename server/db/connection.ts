import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { env } from '../config/env.ts';

let dbInstance: Database.Database | null = null;

export function getDatabase(): Database.Database {
  if (dbInstance) {
    return dbInstance;
  }

  const dbDir = path.dirname(env.databasePath);
  fs.mkdirSync(dbDir, { recursive: true });

  const db = new Database(env.databasePath);
  db.pragma('foreign_keys = ON');
  db.pragma('journal_mode = WAL');

  dbInstance = db;
  return db;
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
