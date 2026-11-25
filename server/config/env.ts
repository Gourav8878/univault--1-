import crypto from 'node:crypto';
import path from 'node:path';
import dotenv from 'dotenv';

dotenv.config();

export type StorageProviderType = 'local' | 'azure';

export interface AppConfig {
  port: number;
  nodeEnv: string;
  sessionSecret: string;
  classificationHmacKey: string | null;
  databasePath: string;
  auditAnchorIntervalMinutes: number;
  auditAnchorCheckpointPath: string;
  storageProvider: StorageProviderType;
  localStoragePath: string;
  azureStorageConnectionString: string;
  azureStorageAccountName: string;
  azureStorageContainerName: string;
}

const projectRoot = process.cwd();

function parsePort(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
}

function parseIntervalMinutes(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 1440 ? parsed : fallback;
}

function parseStorageProvider(raw: string | undefined): StorageProviderType {
  const normalized = (raw ?? 'local').trim().toLowerCase();
  if (normalized === 'local' || normalized === 'azure') {
    return normalized;
  }
  throw new Error(`Invalid STORAGE_PROVIDER "${raw}". Expected "local" or "azure".`);
}

const runtimeFallbackSecret = crypto.randomBytes(32).toString('hex');
const configuredSessionSecret = process.env.SESSION_SECRET?.trim() || '';
const configuredClassificationKey =
  process.env.CLASSIFICATION_HMAC_SECRET?.trim() || null;
const resolvedDatabasePath = path.resolve(
  projectRoot,
  process.env.DATABASE_PATH ?? './data/univault.db'
);

export const env: AppConfig = {
  port: parsePort(process.env.PORT, 3000),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  sessionSecret: configuredSessionSecret || runtimeFallbackSecret,
  classificationHmacKey: configuredClassificationKey,
  databasePath: resolvedDatabasePath,
  auditAnchorIntervalMinutes: parseIntervalMinutes(process.env.AUDIT_ANCHOR_INTERVAL_MINUTES, 15),
  auditAnchorCheckpointPath: path.join(
    path.dirname(resolvedDatabasePath),
    'audit-anchor-checkpoint.json'
  ),
  storageProvider: parseStorageProvider(process.env.STORAGE_PROVIDER),
  localStoragePath: path.resolve(projectRoot, process.env.LOCAL_STORAGE_PATH ?? './storage/private'),
  azureStorageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING ?? '',
  azureStorageAccountName: process.env.AZURE_STORAGE_ACCOUNT_NAME ?? '',
  azureStorageContainerName: process.env.AZURE_STORAGE_CONTAINER_NAME ?? 'univault-private-docs',
};
