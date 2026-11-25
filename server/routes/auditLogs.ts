import { Router } from 'express';
import { requireAuth } from '../auth/middleware.ts';
import { appendAuditLog, verifyAuditLogChain } from '../db/audit.ts';
import { createAuditAnchor, verifyLatestAuditAnchor } from '../db/auditAnchors.ts';
import { getDatabase } from '../db/connection.ts';

interface AuditRow {
  id: string;
  actor_id: string | null;
  actor_name: string | null;
  actor_email: string | null;
  action: string;
  document_id: string | null;
  document_name: string | null;
  target_user_id: string | null;
  target_user_name: string | null;
  decision: 'ALLOW' | 'DENY' | 'INFO';
  denial_reason: string | null;
  metadata_json: string;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  request_id: string;
}

const auditLogsRouter = Router();

auditLogsRouter.get('/', requireAuth, async (req, res, next) => {
  try {
    const db = getDatabase();
    const actor = req.auth!.user;

    if (actor.role === 'FACULTY') {
      res.status(403).json({
        error: 'ROLE_NOT_ALLOWED',
        message: 'Faculty users are not authorized to view campus audit logs.',
      });
      return;
    }

    const decisionFilter =
      typeof req.query.decision === 'string' ? req.query.decision.trim().toUpperCase() : '';
    const actionFilter = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    const limitRaw = Number(req.query.limit ?? 100);
    const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 500 ? limitRaw : 100;

    const clauses: string[] = [];
    const params: unknown[] = [];

    if (actor.role === 'HOD') {
      clauses.push('(actor.department_id = ? OR doc.department_id = ? OR a.actor_id = ?)');
      params.push(actor.departmentId, actor.departmentId, actor.id);
    }

    if (decisionFilter === 'ALLOW' || decisionFilter === 'DENY' || decisionFilter === 'INFO') {
      clauses.push('a.decision = ?');
      params.push(decisionFilter);
    }

    if (actionFilter) {
      clauses.push('LOWER(a.action) LIKE ?');
      params.push(`%${actionFilter.toLowerCase()}%`);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(limit);

    const rows = db
      .prepare(`
        SELECT
          a.id,
          a.actor_id,
          actor.name AS actor_name,
          actor.email AS actor_email,
          a.action,
          a.document_id,
          doc.file_name AS document_name,
          a.target_user_id,
          target.name AS target_user_name,
          a.decision,
          a.denial_reason,
          a.metadata_json,
          a.prev_hash,
          a.entry_hash,
          a.timestamp,
          a.request_id
        FROM audit_logs a
        LEFT JOIN users actor ON actor.id = a.actor_id
        LEFT JOIN documents doc ON doc.id = a.document_id
        LEFT JOIN users target ON target.id = a.target_user_id
        ${whereSql}
        ORDER BY a.rowid DESC
        LIMIT ?
      `)
      .all(...params) as AuditRow[];

    const chainIntegrity = verifyAuditLogChain(db);
    const anchorStatus = await verifyLatestAuditAnchor(db);

    const scopeClauses: string[] = [];
    const scopeParams: unknown[] = [];
    if (actor.role === 'HOD') {
      scopeClauses.push('(actor.department_id = ? OR doc.department_id = ? OR a.actor_id = ?)');
      scopeParams.push(actor.departmentId, actor.departmentId, actor.id);
    }

    const fifteenMinAgoIso = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const recentDenySql = `
      SELECT
        COALESCE(actor.email, 'unauthenticated') AS actor_label,
        COUNT(*) AS deny_count,
        MAX(a.timestamp) AS latest_timestamp
      FROM audit_logs a
      LEFT JOIN users actor ON actor.id = a.actor_id
      LEFT JOIN documents doc ON doc.id = a.document_id
      WHERE ${[...scopeClauses, "a.decision = 'DENY'", 'a.timestamp >= ?'].join(' AND ')}
      GROUP BY actor_label
      ORDER BY deny_count DESC
    `;
    const denySpikes = db
      .prepare(recentDenySql)
      .all(...scopeParams, fifteenMinAgoIso) as Array<{
        actor_label: string;
        deny_count: number;
        latest_timestamp: string;
      }>;

    const recentDenies15m = denySpikes.reduce((sum, item) => sum + item.deny_count, 0);

    const integrityFailureSql = `
      SELECT COUNT(*) AS count
      FROM audit_logs a
      LEFT JOIN users actor ON actor.id = a.actor_id
      LEFT JOIN documents doc ON doc.id = a.document_id
      WHERE ${[
        ...scopeClauses,
        "(a.action IN ('DOCUMENT_INTEGRITY_FAILED', 'DOCUMENT_CLASSIFICATION_TAMPERED') OR a.denial_reason = 'CLASSIFICATION_METADATA_TAMPERED')",
      ].join(' AND ')}
    `;
    const integrityFailuresTotal = (
      db.prepare(integrityFailureSql).get(...scopeParams) as { count: number }
    ).count;

    const flaggedActors = denySpikes
      .filter((item) => item.deny_count >= 3)
      .map((item) => ({
        actorLabel: item.actor_label,
        denyCount15m: item.deny_count,
        latestTimestamp: item.latest_timestamp,
      }));

    const alerts: Array<{ code: string; severity: 'ALERT' | 'ELEVATED'; message: string }> = [];
    if (integrityFailuresTotal > 0) {
      alerts.push({
        code: 'INTEGRITY_TAMPER_EVENT',
        severity: 'ALERT',
        message: `${integrityFailuresTotal} document SHA-256 or classification metadata tamper event(s) recorded in audit logs.`,
      });
    }
    if (anchorStatus.hasAnchor && !anchorStatus.verified) {
      alerts.push({
        code: 'ANCHOR_VERIFICATION_FAILED',
        severity: 'ALERT',
        message: anchorStatus.reason,
      });
    }
    for (const flagged of flaggedActors) {
      alerts.push({
        code: 'ACTOR_DENY_SPIKE',
        severity: 'ALERT',
        message: `Actor "${flagged.actorLabel}" triggered ${flagged.denyCount15m} DENY events within the last 15 minutes.`,
      });
    }
    if (alerts.length === 0 && recentDenies15m >= 3) {
      alerts.push({
        code: 'RECENT_DENY_ACTIVITY',
        severity: 'ELEVATED',
        message: `${recentDenies15m} DENY events recorded across monitored principals in the last 15 minutes.`,
      });
    }

    const riskLevel: 'NOMINAL' | 'ELEVATED' | 'ALERT' = alerts.some((a) => a.severity === 'ALERT')
      ? 'ALERT'
      : recentDenies15m >= 2
        ? 'ELEVATED'
        : 'NOMINAL';

    res.status(200).json({
      chainIntegrity,
      anchorStatus,
      anomalySummary: {
        riskLevel,
        recentDenies15m,
        integrityFailuresTotal,
        flaggedActors,
        alerts,
      },
      logs: rows.map((row) => {
        let metadata: Record<string, unknown> = {};
        try {
          metadata = JSON.parse(row.metadata_json) as Record<string, unknown>;
        } catch {
          metadata = {};
        }
        return {
          id: row.id,
          actorId: row.actor_id,
          actorName: row.actor_name,
          actorEmail: row.actor_email,
          action: row.action,
          documentId: row.document_id,
          documentName: row.document_name,
          targetUserId: row.target_user_id,
          targetUserName: row.target_user_name,
          decision: row.decision,
          denialReason: row.denial_reason,
          metadata,
          prevHash: row.prev_hash,
          entryHash: row.entry_hash,
          timestamp: row.timestamp,
          requestId: row.request_id,
        };
      }),
    });
  } catch (error) {
    next(error);
  }
});

auditLogsRouter.post('/anchor', requireAuth, async (req, res, next) => {
  try {
    const db = getDatabase();
    const actor = req.auth!.user;

    if (actor.role !== 'SUPER_ADMIN' && actor.role !== 'HOD') {
      appendAuditLog(db, {
        actorId: actor.id,
        action: 'AUDIT_CHECKPOINT_ANCHORED',
        decision: 'DENY',
        denialReason: 'ROLE_NOT_ALLOWED',
        requestId: req.requestId,
      });
      res.status(403).json({
        error: 'ROLE_NOT_ALLOWED',
        decision: 'DENY',
        message: 'Only HOD or Super Admin principals can trigger audit anchor checkpoints.',
      });
      return;
    }

    const anchor = await createAuditAnchor(db, {
      triggeredBy: actor.id,
      requestId: req.requestId,
      logEvent: true,
    });
    const anchorStatus = await verifyLatestAuditAnchor(db);

    res.status(201).json({
      anchor,
      anchorStatus,
      requestId: req.requestId,
    });
  } catch (error) {
    next(error);
  }
});

export { auditLogsRouter };
