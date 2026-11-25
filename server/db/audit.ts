import crypto from 'node:crypto';
import type Database from 'better-sqlite3';

export type AuditDecision = 'ALLOW' | 'DENY' | 'INFO';

export interface AppendAuditEntryInput {
  id?: string;
  actorId: string | null;
  action: string;
  documentId?: string | null;
  targetUserId?: string | null;
  decision: AuditDecision;
  denialReason?: string | null;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  requestId?: string;
}

export interface AuditChainVerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenAtId: string | null;
  reason: string | null;
}

interface AuditLogVerifyRow {
  id: string;
  actor_id: string | null;
  action: string;
  document_id: string | null;
  target_user_id: string | null;
  decision: AuditDecision;
  denial_reason: string | null;
  metadata_json: string;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  request_id: string;
}

const GENESIS_HASH = '0'.repeat(64);

export function appendAuditLog(db: Database.Database, input: AppendAuditEntryInput): string {
  const id = input.id ?? crypto.randomUUID();
  const timestamp = input.timestamp ?? new Date().toISOString();
  const requestId = input.requestId ?? crypto.randomUUID();
  const documentId = input.documentId ?? null;
  const targetUserId = input.targetUserId ?? null;
  const denialReason = input.denialReason ?? null;
  const metadataJson = JSON.stringify(input.metadata ?? {});

  const latestRow = db
    .prepare('SELECT entry_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1')
    .get() as { entry_hash: string } | undefined;

  const prevHash = latestRow?.entry_hash ?? GENESIS_HASH;

  const canonicalPayload = JSON.stringify({
    id,
    actor_id: input.actorId,
    action: input.action,
    document_id: documentId,
    target_user_id: targetUserId,
    decision: input.decision,
    denial_reason: denialReason,
    metadata_json: metadataJson,
    prev_hash: prevHash,
    timestamp,
    request_id: requestId,
  });

  const entryHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');

  db.prepare(`
    INSERT INTO audit_logs (
      id, actor_id, action, document_id, target_user_id,
      decision, denial_reason, metadata_json, prev_hash, entry_hash,
      timestamp, request_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    input.actorId,
    input.action,
    documentId,
    targetUserId,
    input.decision,
    denialReason,
    metadataJson,
    prevHash,
    entryHash,
    timestamp,
    requestId
  );

  return entryHash;
}

export function verifyAuditLogChain(db: Database.Database): AuditChainVerificationResult {
  const rows = db
    .prepare(`
      SELECT
        id, actor_id, action, document_id, target_user_id,
        decision, denial_reason, metadata_json, prev_hash, entry_hash,
        timestamp, request_id
      FROM audit_logs
      ORDER BY rowid ASC
    `)
    .all() as AuditLogVerifyRow[];

  let expectedPrevHash = GENESIS_HASH;

  for (const row of rows) {
    if (row.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        totalEntries: rows.length,
        brokenAtId: row.id,
        reason: `prev_hash link mismatch at entry ${row.id}.`,
      };
    }

    const canonicalPayload = JSON.stringify({
      id: row.id,
      actor_id: row.actor_id,
      action: row.action,
      document_id: row.document_id,
      target_user_id: row.target_user_id,
      decision: row.decision,
      denial_reason: row.denial_reason,
      metadata_json: row.metadata_json,
      prev_hash: row.prev_hash,
      timestamp: row.timestamp,
      request_id: row.request_id,
    });

    const recomputedHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
    if (recomputedHash !== row.entry_hash) {
      return {
        valid: false,
        totalEntries: rows.length,
        brokenAtId: row.id,
        reason: `SHA-256 entry_hash mismatch at entry ${row.id}.`,
      };
    }

    expectedPrevHash = row.entry_hash;
  }

  return {
    valid: true,
    totalEntries: rows.length,
    brokenAtId: null,
    reason: null,
  };
}
