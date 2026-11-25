import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type Database from 'better-sqlite3';
import { env } from '../config/env.ts';
import { getStorageProvider } from '../storage/index.ts';
import { appendAuditLog, verifyAuditLogChain } from './audit.ts';

export type AnchorTargetMode = 'local-checkpoint' | 'azure-blob-configured';

export interface AuditAnchorRecord {
  anchorId: string;
  anchoredAt: string;
  headEntryHash: string;
  chainLength: number;
  targetMode: AnchorTargetMode;
  checkpointRef: string;
  triggeredBy: string | null;
  chainValid: boolean;
}

export interface AuditAnchorVerificationStatus {
  hasAnchor: boolean;
  verified: boolean;
  reason: string;
  latestAnchor: AuditAnchorRecord | null;
  recentAnchors: AuditAnchorRecord[];
  azureImmutableLockStatus: 'Proposed / Env-Gated' | 'Env-Gated (Azure Configured)';
  intervalMinutes: number;
}

interface AuditAnchorRow {
  anchor_id: string;
  anchored_at: string;
  head_entry_hash: string;
  chain_length: number;
  target_mode: AnchorTargetMode;
  checkpoint_ref: string;
  triggered_by: string | null;
  chain_valid: number;
}

const GENESIS_HASH = '0'.repeat(64);

function mapAnchorRow(row: AuditAnchorRow): AuditAnchorRecord {
  return {
    anchorId: row.anchor_id,
    anchoredAt: row.anchored_at,
    headEntryHash: row.head_entry_hash,
    chainLength: row.chain_length,
    targetMode: row.target_mode,
    checkpointRef: row.checkpoint_ref,
    triggeredBy: row.triggered_by,
    chainValid: row.chain_valid === 1,
  };
}

function isAzureConfiguredForAnchoring(): boolean {
  return (
    env.storageProvider === 'azure' &&
    Boolean(
      env.azureStorageContainerName.trim() &&
        (env.azureStorageConnectionString.trim() || env.azureStorageAccountName.trim())
    )
  );
}

export async function createAuditAnchor(
  db: Database.Database,
  options: { triggeredBy: string | null; requestId?: string; logEvent?: boolean }
): Promise<AuditAnchorRecord> {
  const chainResult = verifyAuditLogChain(db);
  const headRow = db
    .prepare('SELECT entry_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1')
    .get() as { entry_hash: string } | undefined;

  const anchorId = crypto.randomUUID();
  const anchoredAt = new Date().toISOString();
  const headEntryHash = headRow?.entry_hash ?? GENESIS_HASH;
  const chainLength = chainResult.totalEntries;
  const chainValidInt = chainResult.valid ? 1 : 0;

  let targetMode: AnchorTargetMode = 'local-checkpoint';
  let checkpointRef = path.basename(env.auditAnchorCheckpointPath);

  const checkpointPayload = {
    anchorId,
    anchoredAt,
    headEntryHash,
    chainLength,
    chainValid: chainResult.valid,
  };

  if (isAzureConfiguredForAnchoring()) {
    const storage = getStorageProvider();
    const blobKey = `audit-anchors/${anchorId}.json`;
    try {
      await storage.putObject(
        blobKey,
        Buffer.from(JSON.stringify(checkpointPayload, null, 2), 'utf8'),
        'application/json'
      );
      targetMode = 'azure-blob-configured';
      checkpointRef = blobKey;
    } catch {
      // Fall back to local checkpoint file if live Azure endpoint is unreachable.
      targetMode = 'local-checkpoint';
    }
  }

  if (targetMode === 'local-checkpoint') {
    await fs.mkdir(path.dirname(env.auditAnchorCheckpointPath), { recursive: true });
    await fs.writeFile(
      env.auditAnchorCheckpointPath,
      JSON.stringify(checkpointPayload, null, 2),
      'utf8'
    );
    checkpointRef = path.basename(env.auditAnchorCheckpointPath);
  }

  db.prepare(`
    INSERT INTO audit_anchors (
      anchor_id, anchored_at, head_entry_hash, chain_length,
      target_mode, checkpoint_ref, triggered_by, chain_valid
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    anchorId,
    anchoredAt,
    headEntryHash,
    chainLength,
    targetMode,
    checkpointRef,
    options.triggeredBy,
    chainValidInt
  );

  if (options.logEvent !== false) {
    appendAuditLog(db, {
      actorId: options.triggeredBy,
      action: 'AUDIT_CHECKPOINT_ANCHORED',
      decision: chainResult.valid ? 'INFO' : 'DENY',
      denialReason: chainResult.valid ? null : 'AUDIT_CHAIN_INVALID',
      metadata: {
        anchorId,
        headEntryHash,
        chainLength,
        targetMode,
        checkpointRef,
      },
      requestId: options.requestId,
    });
  }

  return {
    anchorId,
    anchoredAt,
    headEntryHash,
    chainLength,
    targetMode,
    checkpointRef,
    triggeredBy: options.triggeredBy,
    chainValid: chainResult.valid,
  };
}

export async function verifyLatestAuditAnchor(
  db: Database.Database
): Promise<AuditAnchorVerificationStatus> {
  const rows = db
    .prepare(`
      SELECT
        anchor_id, anchored_at, head_entry_hash, chain_length,
        target_mode, checkpoint_ref, triggered_by, chain_valid
      FROM audit_anchors
      ORDER BY anchored_at DESC, rowid DESC
      LIMIT 10
    `)
    .all() as AuditAnchorRow[];

  const azureImmutableLockStatus = isAzureConfiguredForAnchoring()
    ? 'Env-Gated (Azure Configured)'
    : 'Proposed / Env-Gated';

  if (rows.length === 0) {
    return {
      hasAnchor: false,
      verified: false,
      reason: 'No audit anchor checkpoint recorded yet.',
      latestAnchor: null,
      recentAnchors: [],
      azureImmutableLockStatus,
      intervalMinutes: env.auditAnchorIntervalMinutes,
    };
  }

  const latest = mapAnchorRow(rows[0]);
  const recentAnchors = rows.map(mapAnchorRow);
  const chainResult = verifyAuditLogChain(db);

  if (!chainResult.valid) {
    return {
      hasAnchor: true,
      verified: false,
      reason: `Audit log hash chain integrity failed: ${chainResult.reason}`,
      latestAnchor: latest,
      recentAnchors,
      azureImmutableLockStatus,
      intervalMinutes: env.auditAnchorIntervalMinutes,
    };
  }

  if (latest.chainLength === 0) {
    const validGenesis = latest.headEntryHash === GENESIS_HASH;
    return {
      hasAnchor: true,
      verified: validGenesis,
      reason: validGenesis
        ? 'Verified genesis audit checkpoint.'
        : 'Genesis checkpoint hash mismatch.',
      latestAnchor: latest,
      recentAnchors,
      azureImmutableLockStatus,
      intervalMinutes: env.auditAnchorIntervalMinutes,
    };
  }

  if (chainResult.totalEntries < latest.chainLength) {
    return {
      hasAnchor: true,
      verified: false,
      reason: `Audit log truncation detected: checkpoint expects at least ${latest.chainLength} entries, found ${chainResult.totalEntries}.`,
      latestAnchor: latest,
      recentAnchors,
      azureImmutableLockStatus,
      intervalMinutes: env.auditAnchorIntervalMinutes,
    };
  }

  const entryAtCheckpoint = db
    .prepare('SELECT entry_hash FROM audit_logs ORDER BY rowid ASC LIMIT 1 OFFSET ?')
    .get(latest.chainLength - 1) as { entry_hash: string } | undefined;

  if (!entryAtCheckpoint || entryAtCheckpoint.entry_hash !== latest.headEntryHash) {
    return {
      hasAnchor: true,
      verified: false,
      reason: `Checkpoint head_entry_hash mismatch at audit entry #${latest.chainLength}.`,
      latestAnchor: latest,
      recentAnchors,
      azureImmutableLockStatus,
      intervalMinutes: env.auditAnchorIntervalMinutes,
    };
  }

  if (latest.targetMode === 'local-checkpoint') {
    try {
      const rawFile = await fs.readFile(env.auditAnchorCheckpointPath, 'utf8');
      const parsed = JSON.parse(rawFile) as { anchorId?: string; headEntryHash?: string };
      if (parsed.anchorId === latest.anchorId && parsed.headEntryHash !== latest.headEntryHash) {
        return {
          hasAnchor: true,
          verified: false,
          reason: 'Local checkpoint file hash disagrees with audit_anchors table.',
          latestAnchor: latest,
          recentAnchors,
          azureImmutableLockStatus,
          intervalMinutes: env.auditAnchorIntervalMinutes,
        };
      }
    } catch {
      return {
        hasAnchor: true,
        verified: false,
        reason: 'Local anchor checkpoint file is missing or unreadable.',
        latestAnchor: latest,
        recentAnchors,
        azureImmutableLockStatus,
        intervalMinutes: env.auditAnchorIntervalMinutes,
      };
    }
  }

  return {
    hasAnchor: true,
    verified: true,
    reason: `Verified checkpoint at entry #${latest.chainLength} (${latest.targetMode}); chain now has ${chainResult.totalEntries} valid entries.`,
    latestAnchor: latest,
    recentAnchors,
    azureImmutableLockStatus,
    intervalMinutes: env.auditAnchorIntervalMinutes,
  };
}

export async function resetLocalAnchorCheckpoint(): Promise<void> {
  await fs.rm(env.auditAnchorCheckpointPath, { force: true });
}
