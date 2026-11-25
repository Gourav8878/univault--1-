import crypto from 'node:crypto';
import { Router } from 'express';
import { requireAuth } from '../auth/middleware.ts';
import { appendAuditLog } from '../db/audit.ts';
import { getDatabase } from '../db/connection.ts';
import { evaluateGrantManagement, syncExpiredGrants } from '../pdp/policyEngine.ts';

interface GrantListRow {
  id: string;
  user_id: string;
  user_name: string;
  user_email: string;
  user_role: string;
  user_department_code: string;
  document_id: string;
  document_name: string;
  document_classification: string;
  document_department_id: string;
  document_department_code: string;
  granted_by: string;
  granted_by_name: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  revoked_by_name: string | null;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

const grantsRouter = Router();

grantsRouter.get('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  syncExpiredGrants(db);

  let whereSql = '';
  const params: unknown[] = [];

  if (actor.role === 'HOD') {
    whereSql = 'WHERE (doc.department_id = ? OR u.department_id = ?)';
    params.push(actor.departmentId, actor.departmentId);
  } else if (actor.role === 'FACULTY') {
    whereSql = 'WHERE g.user_id = ?';
    params.push(actor.id);
  }

  const rows = db
    .prepare(`
      SELECT
        g.id,
        g.user_id,
        u.name AS user_name,
        u.email AS user_email,
        u.role AS user_role,
        u_dept.code AS user_department_code,
        g.document_id,
        doc.file_name AS document_name,
        doc.classification AS document_classification,
        doc.department_id AS document_department_id,
        doc_dept.code AS document_department_code,
        g.granted_by,
        gb.name AS granted_by_name,
        g.created_at,
        g.expires_at,
        g.revoked_at,
        g.revoked_by,
        rb.name AS revoked_by_name,
        g.status
      FROM access_grants g
      INNER JOIN users u ON u.id = g.user_id
      INNER JOIN departments u_dept ON u_dept.id = u.department_id
      INNER JOIN documents doc ON doc.id = g.document_id
      INNER JOIN departments doc_dept ON doc_dept.id = doc.department_id
      INNER JOIN users gb ON gb.id = g.granted_by
      LEFT JOIN users rb ON rb.id = g.revoked_by
      ${whereSql}
      ORDER BY g.created_at DESC
    `)
    .all(...params) as GrantListRow[];

  res.status(200).json({
    grants: rows.map((r) => ({
      id: r.id,
      userId: r.user_id,
      userName: r.user_name,
      userEmail: r.user_email,
      userRole: r.user_role,
      userDepartmentCode: r.user_department_code,
      documentId: r.document_id,
      documentName: r.document_name,
      documentClassification: r.document_classification,
      documentDepartmentId: r.document_department_id,
      documentDepartmentCode: r.document_department_code,
      grantedBy: r.granted_by,
      grantedByName: r.granted_by_name,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      revokedAt: r.revoked_at,
      revokedBy: r.revoked_by,
      revokedByName: r.revoked_by_name,
      status: r.status,
    })),
  });
});

grantsRouter.get('/targets', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;

  if (actor.role !== 'SUPER_ADMIN' && actor.role !== 'HOD') {
    res.status(403).json({
      error: 'ROLE_NOT_ALLOWED',
      message: 'Only HOD or Super Admin users may manage access grants.',
    });
    return;
  }

  const users = db
    .prepare(`
      SELECT u.id, u.name, u.email, u.role, u.department_id AS departmentId, d.code AS departmentCode
      FROM users u
      INNER JOIN departments d ON d.id = u.department_id
      WHERE u.active = 1
      ORDER BY u.name ASC
    `)
    .all();

  const docsQuery =
    actor.role === 'SUPER_ADMIN'
      ? db.prepare(`
          SELECT doc.id, doc.file_name AS fileName, doc.classification, doc.department_id AS departmentId, d.code AS departmentCode
          FROM documents doc
          INNER JOIN departments d ON d.id = doc.department_id
          ORDER BY doc.file_name ASC
        `)
      : db.prepare(`
          SELECT doc.id, doc.file_name AS fileName, doc.classification, doc.department_id AS departmentId, d.code AS departmentCode
          FROM documents doc
          INNER JOIN departments d ON d.id = doc.department_id
          WHERE doc.department_id = ?
          ORDER BY doc.file_name ASC
        `);

  const documents = actor.role === 'SUPER_ADMIN' ? docsQuery.all() : docsQuery.all(actor.departmentId);

  res.status(200).json({ users, documents });
});

grantsRouter.post('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const body = req.body as {
    userId?: unknown;
    documentId?: unknown;
    expiresAt?: unknown;
    durationMinutes?: unknown;
  };

  const targetUserId = typeof body?.userId === 'string' ? body.userId.trim() : '';
  const documentId = typeof body?.documentId === 'string' ? body.documentId.trim() : '';

  if (!targetUserId || !documentId) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'userId and documentId are required.',
    });
    return;
  }

  let expiresAtDate: Date | null = null;
  if (typeof body?.expiresAt === 'string' && body.expiresAt.trim()) {
    const parsed = new Date(body.expiresAt.trim());
    if (!Number.isNaN(parsed.getTime())) {
      expiresAtDate = parsed;
    }
  } else if (typeof body?.durationMinutes === 'number' && Number.isFinite(body.durationMinutes)) {
    expiresAtDate = new Date(Date.now() + body.durationMinutes * 60 * 1000);
  }

  if (!expiresAtDate || expiresAtDate.getTime() <= Date.now()) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'A valid future expiration timestamp (expiresAt) is required.',
    });
    return;
  }

  const doc = db
    .prepare(
      'SELECT id, file_name, department_id, classification_status FROM documents WHERE id = ? LIMIT 1'
    )
    .get(documentId) as
    | {
        id: string;
        file_name: string;
        department_id: string;
        classification_status: 'PENDING_APPROVAL' | 'APPROVED';
      }
    | undefined;

  if (!doc) {
    res.status(404).json({
      error: 'DOCUMENT_NOT_FOUND',
      message: 'Target document does not exist.',
    });
    return;
  }

  if (doc.classification_status === 'PENDING_APPROVAL') {
    appendAuditLog(db, {
      actorId: actor.id,
      action: 'ACCESS_GRANT_CREATE',
      documentId: doc.id,
      targetUserId,
      decision: 'DENY',
      denialReason: 'CLASSIFICATION_APPROVAL_REQUIRED',
      metadata: {
        documentName: doc.file_name,
        classificationStatus: doc.classification_status,
      },
      requestId: req.requestId,
    });
    res.status(409).json({
      error: 'CLASSIFICATION_APPROVAL_REQUIRED',
      decision: 'DENY',
      message:
        'Document classification is pending human HOD/Admin approval before sharing grants can be issued.',
    });
    return;
  }

  const decision = evaluateGrantManagement(db, {
    actorId: actor.id,
    action: 'ACCESS_GRANT_CREATE',
    documentId: doc.id,
    documentDepartmentId: doc.department_id,
    targetUserId,
    requestId: req.requestId,
    audit: true,
  });

  if (!decision.allowed) {
    res.status(decision.httpStatus).json({
      error: decision.reason,
      decision: decision.decision,
      message: decision.checks[decision.checks.length - 1]?.detail ?? 'Grant creation denied.',
      checks: decision.checks,
    });
    return;
  }

  const targetUser = db
    .prepare('SELECT id, name, email, active FROM users WHERE id = ? LIMIT 1')
    .get(targetUserId) as { id: string; name: string; email: string; active: number } | undefined;

  if (!targetUser) {
    res.status(404).json({
      error: 'USER_NOT_FOUND',
      message: 'Target user does not exist.',
    });
    return;
  }

  if (targetUser.active !== 1) {
    res.status(400).json({
      error: 'USER_INACTIVE',
      message: 'Cannot issue an access grant to an inactive user.',
    });
    return;
  }

  const grantId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const expiresAtIso = expiresAtDate.toISOString();

  db.prepare(`
    INSERT INTO access_grants (
      id, user_id, document_id, granted_by, created_at, expires_at, revoked_at, revoked_by, status
    ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 'ACTIVE')
  `).run(grantId, targetUser.id, doc.id, actor.id, createdAt, expiresAtIso);

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'ACCESS_GRANT_CREATED',
    documentId: doc.id,
    targetUserId: targetUser.id,
    decision: 'ALLOW',
    metadata: {
      grantId,
      expiresAt: expiresAtIso,
      documentName: doc.file_name,
      targetEmail: targetUser.email,
    },
    requestId: req.requestId,
  });

  res.status(201).json({
    grant: {
      id: grantId,
      userId: targetUser.id,
      documentId: doc.id,
      grantedBy: actor.id,
      createdAt,
      expiresAt: expiresAtIso,
      status: 'ACTIVE',
    },
  });
});

grantsRouter.post('/:id/revoke', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const grantId = String(req.params.id);

  const grant = db
    .prepare(`
      SELECT
        g.id,
        g.user_id,
        g.document_id,
        g.status,
        g.revoked_at,
        doc.department_id AS document_department_id,
        doc.file_name AS document_name
      FROM access_grants g
      INNER JOIN documents doc ON doc.id = g.document_id
      WHERE g.id = ?
      LIMIT 1
    `)
    .get(grantId) as
    | {
        id: string;
        user_id: string;
        document_id: string;
        status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
        revoked_at: string | null;
        document_department_id: string;
        document_name: string;
      }
    | undefined;

  if (!grant) {
    res.status(404).json({
      error: 'GRANT_NOT_FOUND',
      message: 'Access grant not found.',
    });
    return;
  }

  const decision = evaluateGrantManagement(db, {
    actorId: actor.id,
    action: 'ACCESS_GRANT_REVOKE',
    documentId: grant.document_id,
    documentDepartmentId: grant.document_department_id,
    targetUserId: grant.user_id,
    requestId: req.requestId,
    audit: true,
  });

  if (!decision.allowed) {
    res.status(decision.httpStatus).json({
      error: decision.reason,
      decision: decision.decision,
      message: decision.checks[decision.checks.length - 1]?.detail ?? 'Revocation denied.',
      checks: decision.checks,
    });
    return;
  }

  if (grant.status === 'REVOKED') {
    res.status(200).json({
      grant: {
        id: grant.id,
        status: 'REVOKED',
        revokedAt: grant.revoked_at,
      },
      alreadyRevoked: true,
    });
    return;
  }

  const revokedAt = new Date().toISOString();
  db.prepare(`
    UPDATE access_grants
    SET status = 'REVOKED', revoked_at = ?, revoked_by = ?
    WHERE id = ?
  `).run(revokedAt, actor.id, grant.id);

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'ACCESS_GRANT_REVOKED',
    documentId: grant.document_id,
    targetUserId: grant.user_id,
    decision: 'ALLOW',
    metadata: {
      grantId: grant.id,
      documentName: grant.document_name,
      revokedAt,
    },
    requestId: req.requestId,
  });

  res.status(200).json({
    grant: {
      id: grant.id,
      status: 'REVOKED',
      revokedAt,
      revokedBy: actor.id,
    },
  });
});

interface AccessRequestRow {
  id: string;
  requester_id: string;
  requester_name: string;
  requester_email: string;
  requester_role: string;
  requester_department_code: string;
  document_id: string;
  document_name: string;
  document_classification: string;
  document_department_id: string;
  document_department_code: string;
  requested_duration_minutes: number;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  reviewed_by: string | null;
  reviewed_by_name: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  grant_id: string | null;
  created_at: string;
}

grantsRouter.get('/requests', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;

  let whereSql = '';
  const params: unknown[] = [];

  if (actor.role === 'FACULTY') {
    whereSql = 'WHERE r.requester_id = ?';
    params.push(actor.id);
  } else if (actor.role === 'HOD') {
    whereSql = 'WHERE (doc.department_id = ? OR r.requester_id = ?)';
    params.push(actor.departmentId, actor.id);
  }

  const rows = db
    .prepare(`
      SELECT
        r.id,
        r.requester_id,
        req_user.name AS requester_name,
        req_user.email AS requester_email,
        req_user.role AS requester_role,
        req_dept.code AS requester_department_code,
        r.document_id,
        doc.file_name AS document_name,
        doc.classification AS document_classification,
        doc.department_id AS document_department_id,
        doc_dept.code AS document_department_code,
        r.requested_duration_minutes,
        r.justification,
        r.status,
        r.reviewed_by,
        rev_user.name AS reviewed_by_name,
        r.reviewed_at,
        r.review_note,
        r.grant_id,
        r.created_at
      FROM access_requests r
      INNER JOIN users req_user ON req_user.id = r.requester_id
      INNER JOIN departments req_dept ON req_dept.id = req_user.department_id
      INNER JOIN documents doc ON doc.id = r.document_id
      INNER JOIN departments doc_dept ON doc_dept.id = doc.department_id
      LEFT JOIN users rev_user ON rev_user.id = r.reviewed_by
      ${whereSql}
      ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END, r.created_at DESC
    `)
    .all(...params) as AccessRequestRow[];

  const requestableDocuments = db
    .prepare(`
      SELECT
        doc.id,
        doc.file_name AS fileName,
        doc.classification,
        doc.department_id AS departmentId,
        d.code AS departmentCode
      FROM documents doc
      INNER JOIN departments d ON d.id = doc.department_id
      WHERE doc.classification != 'PUBLIC'
      ORDER BY doc.file_name ASC
    `)
    .all();

  res.status(200).json({
    requests: rows.map((r) => ({
      id: r.id,
      requesterId: r.requester_id,
      requesterName: r.requester_name,
      requesterEmail: r.requester_email,
      requesterRole: r.requester_role,
      requesterDepartmentCode: r.requester_department_code,
      documentId: r.document_id,
      documentName: r.document_name,
      documentClassification: r.document_classification,
      documentDepartmentId: r.document_department_id,
      documentDepartmentCode: r.document_department_code,
      requestedDurationMinutes: r.requested_duration_minutes,
      justification: r.justification,
      status: r.status,
      reviewedBy: r.reviewed_by,
      reviewedByName: r.reviewed_by_name,
      reviewedAt: r.reviewed_at,
      reviewNote: r.review_note,
      grantId: r.grant_id,
      createdAt: r.created_at,
    })),
    requestableDocuments,
  });
});

grantsRouter.post('/requests', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const body = req.body as {
    documentId?: unknown;
    durationMinutes?: unknown;
    justification?: unknown;
  };

  const documentId = typeof body?.documentId === 'string' ? body.documentId.trim() : '';
  const durationMinutes =
    typeof body?.durationMinutes === 'number' && Number.isInteger(body.durationMinutes)
      ? body.durationMinutes
      : 60;
  const justification = typeof body?.justification === 'string' ? body.justification.trim() : '';

  if (!documentId) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Target documentId is required.',
    });
    return;
  }

  if (durationMinutes < 5 || durationMinutes > 10080) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Requested duration must be between 5 minutes and 7 days (10080 minutes).',
    });
    return;
  }

  if (justification.length < 5 || justification.length > 400) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Provide a clear justification (5 to 400 characters).',
    });
    return;
  }

  const doc = db
    .prepare('SELECT id, file_name, classification, department_id FROM documents WHERE id = ? LIMIT 1')
    .get(documentId) as
    | { id: string; file_name: string; classification: string; department_id: string }
    | undefined;

  if (!doc) {
    res.status(404).json({
      error: 'DOCUMENT_NOT_FOUND',
      message: 'Requested document does not exist.',
    });
    return;
  }

  const existingPending = db
    .prepare(`
      SELECT id FROM access_requests
      WHERE requester_id = ? AND document_id = ? AND status = 'PENDING'
      LIMIT 1
    `)
    .get(actor.id, doc.id) as { id: string } | undefined;

  if (existingPending) {
    res.status(409).json({
      error: 'DUPLICATE_PENDING_REQUEST',
      message: 'A pending JIT access request already exists for this document.',
    });
    return;
  }

  const requestId = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO access_requests (
      id, requester_id, document_id, requested_duration_minutes, justification,
      status, reviewed_by, reviewed_at, review_note, grant_id, created_at
    ) VALUES (?, ?, ?, ?, ?, 'PENDING', NULL, NULL, NULL, NULL, ?)
  `).run(requestId, actor.id, doc.id, durationMinutes, justification, createdAt);

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'JIT_ACCESS_REQUESTED',
    documentId: doc.id,
    decision: 'INFO',
    metadata: {
      accessRequestId: requestId,
      documentName: doc.file_name,
      durationMinutes,
      justification,
    },
    requestId: req.requestId,
  });

  res.status(201).json({
    request: {
      id: requestId,
      requesterId: actor.id,
      documentId: doc.id,
      requestedDurationMinutes: durationMinutes,
      justification,
      status: 'PENDING',
      createdAt,
    },
  });
});

grantsRouter.post('/requests/:id/decide', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const accessRequestId = String(req.params.id);
  const body = req.body as { decision?: unknown; note?: unknown };

  const decisionChoice = body?.decision === 'APPROVE' || body?.decision === 'REJECT' ? body.decision : null;
  const reviewNote = typeof body?.note === 'string' ? body.note.trim().slice(0, 300) : '';

  if (!decisionChoice) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'decision must be APPROVE or REJECT.',
    });
    return;
  }

  const row = db
    .prepare(`
      SELECT
        r.id,
        r.requester_id,
        r.document_id,
        r.requested_duration_minutes,
        r.status,
        doc.department_id AS document_department_id,
        doc.file_name AS document_name,
        doc.classification_status AS document_classification_status,
        u.email AS requester_email,
        u.active AS requester_active
      FROM access_requests r
      INNER JOIN documents doc ON doc.id = r.document_id
      INNER JOIN users u ON u.id = r.requester_id
      WHERE r.id = ?
      LIMIT 1
    `)
    .get(accessRequestId) as
    | {
        id: string;
        requester_id: string;
        document_id: string;
        requested_duration_minutes: number;
        status: 'PENDING' | 'APPROVED' | 'REJECTED';
        document_department_id: string;
        document_name: string;
        document_classification_status: 'PENDING_APPROVAL' | 'APPROVED';
        requester_email: string;
        requester_active: number;
      }
    | undefined;

  if (!row) {
    res.status(404).json({
      error: 'REQUEST_NOT_FOUND',
      message: 'JIT access request not found.',
    });
    return;
  }

  const authorityDecision = evaluateGrantManagement(db, {
    actorId: actor.id,
    action: 'ACCESS_GRANT_CREATE',
    documentId: row.document_id,
    documentDepartmentId: row.document_department_id,
    targetUserId: row.requester_id,
    requestId: req.requestId,
    audit: true,
  });

  if (!authorityDecision.allowed) {
    res.status(authorityDecision.httpStatus).json({
      error: authorityDecision.reason,
      decision: authorityDecision.decision,
      message: authorityDecision.checks[authorityDecision.checks.length - 1]?.detail ?? 'Decision denied.',
      checks: authorityDecision.checks,
    });
    return;
  }

  if (row.requester_id === actor.id) {
    res.status(403).json({
      error: 'SELF_APPROVAL_BLOCKED',
      message: 'Requesters cannot approve or decide their own JIT access requests.',
    });
    return;
  }

  if (row.status !== 'PENDING') {
    res.status(409).json({
      error: 'REQUEST_ALREADY_DECIDED',
      message: `This JIT access request is already ${row.status}.`,
    });
    return;
  }

  if (decisionChoice === 'APPROVE' && row.requester_active !== 1) {
    res.status(400).json({
      error: 'USER_INACTIVE',
      message: 'Cannot approve a grant for an inactive user account.',
    });
    return;
  }

  if (decisionChoice === 'APPROVE' && row.document_classification_status === 'PENDING_APPROVAL') {
    appendAuditLog(db, {
      actorId: actor.id,
      action: 'JIT_ACCESS_APPROVE_BLOCKED',
      documentId: row.document_id,
      targetUserId: row.requester_id,
      decision: 'DENY',
      denialReason: 'CLASSIFICATION_APPROVAL_REQUIRED',
      metadata: {
        accessRequestId: row.id,
        documentName: row.document_name,
      },
      requestId: req.requestId,
    });
    res.status(409).json({
      error: 'CLASSIFICATION_APPROVAL_REQUIRED',
      decision: 'DENY',
      message:
        'Human HOD/Admin classification approval is required for this document before approving JIT access.',
    });
    return;
  }

  const reviewedAt = new Date().toISOString();

  if (decisionChoice === 'REJECT') {
    db.prepare(`
      UPDATE access_requests
      SET status = 'REJECTED', reviewed_by = ?, reviewed_at = ?, review_note = ?
      WHERE id = ?
    `).run(actor.id, reviewedAt, reviewNote || null, row.id);

    appendAuditLog(db, {
      actorId: actor.id,
      action: 'JIT_ACCESS_REJECTED',
      documentId: row.document_id,
      targetUserId: row.requester_id,
      decision: 'DENY',
      denialReason: 'JIT_REQUEST_REJECTED',
      metadata: {
        accessRequestId: row.id,
        documentName: row.document_name,
        reviewNote: reviewNote || null,
      },
      requestId: req.requestId,
    });

    res.status(200).json({
      request: {
        id: row.id,
        status: 'REJECTED',
        reviewedAt,
        reviewedBy: actor.id,
        reviewNote: reviewNote || null,
        grantId: null,
      },
    });
    return;
  }

  const grantId = crypto.randomUUID();
  const expiresAtIso = new Date(
    Date.now() + row.requested_duration_minutes * 60 * 1000
  ).toISOString();

  const applyApproval = db.transaction(() => {
    db.prepare(`
      INSERT INTO access_grants (
        id, user_id, document_id, granted_by, created_at, expires_at, revoked_at, revoked_by, status
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 'ACTIVE')
    `).run(grantId, row.requester_id, row.document_id, actor.id, reviewedAt, expiresAtIso);

    db.prepare(`
      UPDATE access_requests
      SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ?, review_note = ?, grant_id = ?
      WHERE id = ?
    `).run(actor.id, reviewedAt, reviewNote || null, grantId, row.id);
  });

  applyApproval();

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'JIT_ACCESS_APPROVED',
    documentId: row.document_id,
    targetUserId: row.requester_id,
    decision: 'ALLOW',
    metadata: {
      accessRequestId: row.id,
      grantId,
      expiresAt: expiresAtIso,
      documentName: row.document_name,
      targetEmail: row.requester_email,
      reviewNote: reviewNote || null,
    },
    requestId: req.requestId,
  });

  res.status(200).json({
    request: {
      id: row.id,
      status: 'APPROVED',
      reviewedAt,
      reviewedBy: actor.id,
      reviewNote: reviewNote || null,
      grantId,
      expiresAt: expiresAtIso,
    },
  });
});

export { grantsRouter };
