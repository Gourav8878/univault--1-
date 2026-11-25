import crypto from 'node:crypto';
import path from 'node:path';
import { Router } from 'express';
import multer from 'multer';
import { requireAuth } from '../auth/middleware.ts';
import { appendAuditLog } from '../db/audit.ts';
import { getDatabase } from '../db/connection.ts';
import {
  computeClassificationHash,
  verifyClassificationHash,
} from '../pdp/classificationHash.ts';
import {
  evaluateDocumentAccess,
  evaluateDocumentUpload,
  type DocumentClassification,
} from '../pdp/policyEngine.ts';
import { inspectUploadedPdf, type DlpFindingCount } from '../security/uploadScanner.ts';
import { getStorageProvider } from '../storage/index.ts';

const MAX_PDF_BYTES = 10 * 1024 * 1024; // 10 MB

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_PDF_BYTES,
    files: 1,
  },
});

interface DocumentMetadataRow {
  id: string;
  file_name: string;
  mime_type: string;
  file_size: number;
  department_id: string;
  department_name: string;
  department_code: string;
  classification: DocumentClassification;
  uploaded_by: string;
  uploaded_by_name: string;
  created_at: string;
  sha256_hash: string;
  version: number;
  suggested_classification: DocumentClassification;
  dlp_findings_json: string;
  classification_status: 'PENDING_APPROVAL' | 'APPROVED';
  classification_approved_by: string | null;
  classification_approved_by_name: string | null;
  classification_approved_at: string | null;
  classification_hash: string;
}

interface DocumentStorageRow {
  id: string;
  file_name: string;
  storage_path: string;
  mime_type: string;
  file_size: number;
  department_id: string;
  department_code: string;
  classification: DocumentClassification;
  sha256_hash: string;
  version: number;
  classification_status: 'PENDING_APPROVAL' | 'APPROVED';
  classification_hash: string;
}

function sanitizeDisplayFileName(rawName: string): string {
  const base = path.basename(rawName).replace(/[\r\n\0"\\]/g, '').trim();
  if (!base) {
    return 'document.pdf';
  }
  return base.toLowerCase().endsWith('.pdf') ? base : `${base}.pdf`;
}

function parseClassification(raw: unknown): DocumentClassification | null {
  if (raw === 'PUBLIC' || raw === 'INTERNAL' || raw === 'CONFIDENTIAL') {
    return raw;
  }
  return null;
}

function parseDlpFindings(rawJson: string): DlpFindingCount[] {
  try {
    const parsed = JSON.parse(rawJson) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.filter(
        (item): item is DlpFindingCount =>
          Boolean(item) &&
          typeof (item as DlpFindingCount).pattern === 'string' &&
          typeof (item as DlpFindingCount).count === 'number'
      );
    }
  } catch {
    // Ignore malformed JSON
  }
  return [];
}

function mapDocumentRow(row: DocumentMetadataRow) {
  const classificationHashValid = verifyClassificationHash(
    {
      documentId: row.id,
      departmentId: row.department_id,
      classification: row.classification,
      version: row.version,
    },
    row.classification_hash
  );

  return {
    id: row.id,
    fileName: row.file_name,
    mimeType: row.mime_type,
    fileSize: row.file_size,
    departmentId: row.department_id,
    departmentName: row.department_name,
    departmentCode: row.department_code,
    classification: row.classification,
    uploadedBy: row.uploaded_by,
    uploadedByName: row.uploaded_by_name,
    createdAt: row.created_at,
    sha256Hash: row.sha256_hash,
    version: row.version,
    suggestedClassification: row.suggested_classification,
    dlpFindings: parseDlpFindings(row.dlp_findings_json),
    classificationStatus: row.classification_status,
    classificationApprovedBy: row.classification_approved_by,
    classificationApprovedByName: row.classification_approved_by_name,
    classificationApprovedAt: row.classification_approved_at,
    classificationHash: row.classification_hash,
    classificationHashValid,
  };
}

const documentsRouter = Router();

documentsRouter.get('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;

  const search = typeof req.query.search === 'string' ? req.query.search.trim().toLowerCase() : '';
  const departmentId =
    typeof req.query.departmentId === 'string' ? req.query.departmentId.trim() : '';
  const classificationRaw =
    typeof req.query.classification === 'string' ? req.query.classification.trim() : '';
  const onlyAllowed = req.query.onlyAllowed === 'true';

  const clauses: string[] = [];
  const params: unknown[] = [];

  if (departmentId) {
    clauses.push('d.department_id = ?');
    params.push(departmentId);
  }

  if (classificationRaw) {
    const parsedClass = parseClassification(classificationRaw);
    if (!parsedClass) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Invalid classification filter. Expected PUBLIC, INTERNAL, or CONFIDENTIAL.',
      });
      return;
    }
    clauses.push('d.classification = ?');
    params.push(parsedClass);
  }

  if (search) {
    clauses.push('(LOWER(d.file_name) LIKE ? OR LOWER(dept.name) LIKE ? OR LOWER(dept.code) LIKE ?)');
    const likeTerm = `%${search}%`;
    params.push(likeTerm, likeTerm, likeTerm);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';

  const rows = db
    .prepare(`
      SELECT
        d.id,
        d.file_name,
        d.mime_type,
        d.file_size,
        d.department_id,
        dept.name AS department_name,
        dept.code AS department_code,
        d.classification,
        d.uploaded_by,
        u.name AS uploaded_by_name,
        d.created_at,
        d.sha256_hash,
        d.version,
        d.suggested_classification,
        d.dlp_findings_json,
        d.classification_status,
        d.classification_approved_by,
        approver.name AS classification_approved_by_name,
        d.classification_approved_at,
        d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      INNER JOIN users u ON u.id = d.uploaded_by
      LEFT JOIN users approver ON approver.id = d.classification_approved_by
      ${whereSql}
      ORDER BY d.created_at DESC, d.file_name ASC
    `)
    .all(...params) as DocumentMetadataRow[];

  const evaluated = rows
    .map((row) => {
      const decision = evaluateDocumentAccess(db, {
        actorId: actor.id,
        documentId: row.id,
        action: 'DOCUMENT_METADATA_READ',
        requestId: req.requestId,
        audit: false,
      });

      return {
        ...mapDocumentRow(row),
        access: {
          allowed: decision.allowed,
          decision: decision.decision,
          reason: decision.reason,
          grantId: decision.grantId ?? null,
          grantExpiresAt: decision.grantExpiresAt ?? null,
          checks: decision.checks,
        },
      };
    })
    .filter((doc) => (onlyAllowed ? doc.access.allowed : true));

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'DOCUMENT_CATALOG_VIEW',
    decision: 'ALLOW',
    metadata: {
      returnedCount: evaluated.length,
      filters: {
        search: search || null,
        departmentId: departmentId || null,
        classification: classificationRaw || null,
        onlyAllowed,
      },
    },
    requestId: req.requestId,
  });

  res.status(200).json({ documents: evaluated });
});

documentsRouter.post('/', requireAuth, upload.single('file'), async (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;

  const body = req.body as {
    classification?: unknown;
    departmentId?: unknown;
    fileName?: unknown;
  };

  const classification = parseClassification(body?.classification);
  if (!classification) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Valid classification (PUBLIC, INTERNAL, or CONFIDENTIAL) is required.',
    });
    return;
  }

  const targetDepartmentId =
    typeof body?.departmentId === 'string' && body.departmentId.trim()
      ? body.departmentId.trim()
      : actor.departmentId;

  const dept = db
    .prepare('SELECT id, name, code FROM departments WHERE id = ? LIMIT 1')
    .get(targetDepartmentId) as { id: string; name: string; code: string } | undefined;

  if (!dept) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Selected target department does not exist.',
    });
    return;
  }

  const uploadDecision = evaluateDocumentUpload(db, {
    actorId: actor.id,
    targetDepartmentId: dept.id,
    classification,
    requestId: req.requestId,
    audit: true,
  });

  if (!uploadDecision.allowed) {
    res.status(uploadDecision.httpStatus).json({
      error: uploadDecision.reason,
      decision: uploadDecision.decision,
      message: uploadDecision.checks[uploadDecision.checks.length - 1]?.detail ?? 'Upload denied.',
      checks: uploadDecision.checks,
    });
    return;
  }

  const file = req.file;
  if (!file) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'PDF file is required in form field "file".',
    });
    return;
  }

  const isPdfMime = file.mimetype === 'application/pdf';
  const hasPdfExt = file.originalname.toLowerCase().endsWith('.pdf');
  const inspection = inspectUploadedPdf(file.buffer, classification);
  if (!isPdfMime || !hasPdfExt || !inspection.signatureValid) {
    res.status(400).json({
      error: 'INVALID_FILE_TYPE',
      message: 'Only valid PDF documents (%PDF- signature) up to 10 MB are accepted.',
    });
    return;
  }

  if (inspection.activeContentBlocked) {
    appendAuditLog(db, {
      actorId: actor.id,
      action: 'DOCUMENT_UPLOAD_BLOCKED',
      decision: 'DENY',
      denialReason: 'UNSAFE_PDF_CONTENT',
      metadata: {
        fileName: file.originalname,
        tokens: inspection.activeContentTokens,
      },
      requestId: req.requestId,
    });
    res.status(400).json({
      error: 'UNSAFE_PDF_CONTENT',
      message: `Upload blocked: PDF contains disallowed active content tokens (${inspection.activeContentTokens.join(', ')}).`,
    });
    return;
  }

  const documentId = crypto.randomUUID();
  const safeDisplayName = sanitizeDisplayFileName(
    typeof body?.fileName === 'string' && body.fileName.trim() ? body.fileName : file.originalname
  );
  const serverStorageKey = `${dept.code.toLowerCase()}/${classification.toLowerCase()}/${documentId}.pdf`;

  const storage = getStorageProvider();
  const stored = await storage.putObject(serverStorageKey, file.buffer, 'application/pdf');
  const createdAt = new Date().toISOString();

  const classificationStatus: 'PENDING_APPROVAL' | 'APPROVED' = inspection.approvalRequired
    ? 'PENDING_APPROVAL'
    : 'APPROVED';
  const approvedBy = classificationStatus === 'APPROVED' ? actor.id : null;
  const approvedAt = classificationStatus === 'APPROVED' ? createdAt : null;
  const classificationHash = computeClassificationHash({
    documentId,
    departmentId: dept.id,
    classification,
    version: 1,
  });

  db.prepare(`
    INSERT INTO documents (
      id, file_name, storage_path, mime_type, file_size,
      department_id, classification, uploaded_by, created_at, sha256_hash, version,
      suggested_classification, dlp_findings_json, classification_status,
      classification_approved_by, classification_approved_at, classification_hash
    ) VALUES (?, ?, ?, 'application/pdf', ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
  `).run(
    documentId,
    safeDisplayName,
    stored.storagePath,
    stored.size,
    dept.id,
    classification,
    actor.id,
    createdAt,
    stored.sha256,
    inspection.suggestedClassification,
    JSON.stringify(inspection.dlpFindings),
    classificationStatus,
    approvedBy,
    approvedAt,
    classificationHash
  );

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'DOCUMENT_UPLOADED',
    documentId,
    decision: 'ALLOW',
    metadata: {
      fileName: safeDisplayName,
      departmentCode: dept.code,
      classification,
      suggestedClassification: inspection.suggestedClassification,
      classificationStatus,
      classificationHash,
      fileSize: stored.size,
      sha256: stored.sha256,
      scanStatus: 'CLEAN',
      dlpStatus: inspection.dlpStatus,
      matchedPatterns: inspection.matchedPatterns,
      patternCounts: inspection.patternCounts,
      externalAiClassifier: inspection.externalAiClassifier,
    },
    requestId: req.requestId,
  });

  res.status(201).json({
    document: {
      id: documentId,
      fileName: safeDisplayName,
      mimeType: 'application/pdf',
      fileSize: stored.size,
      departmentId: dept.id,
      departmentName: dept.name,
      departmentCode: dept.code,
      classification,
      uploadedBy: actor.id,
      uploadedByName: actor.name,
      createdAt,
      sha256Hash: stored.sha256,
      version: 1,
      suggestedClassification: inspection.suggestedClassification,
      dlpFindings: inspection.dlpFindings,
      classificationStatus,
      classificationApprovedBy: approvedBy,
      classificationApprovedByName: approvedBy ? actor.name : null,
      classificationApprovedAt: approvedAt,
      classificationHash,
      classificationHashValid: true,
    },
    inspection,
  });
});

documentsRouter.post('/:id/approve-classification', requireAuth, (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const documentId = String(req.params.id);
  const body = req.body as { classification?: unknown; note?: unknown };

  const existing = db
    .prepare(`
      SELECT
        d.id, d.file_name, d.mime_type, d.file_size, d.department_id,
        dept.name AS department_name, dept.code AS department_code,
        d.classification, d.uploaded_by, u.name AS uploaded_by_name,
        d.created_at, d.sha256_hash, d.version,
        d.suggested_classification, d.dlp_findings_json,
        d.classification_status, d.classification_approved_by,
        approver.name AS classification_approved_by_name,
        d.classification_approved_at, d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      INNER JOIN users u ON u.id = d.uploaded_by
      LEFT JOIN users approver ON approver.id = d.classification_approved_by
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(documentId) as DocumentMetadataRow | undefined;

  if (!existing) {
    res.status(404).json({ error: 'DOCUMENT_NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const targetClassification =
    body?.classification !== undefined
      ? parseClassification(body.classification)
      : existing.classification;

  if (!targetClassification) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Classification must be PUBLIC, INTERNAL, or CONFIDENTIAL.',
    });
    return;
  }

  const authDecision = evaluateDocumentUpload(db, {
    actorId: actor.id,
    targetDepartmentId: existing.department_id,
    classification: targetClassification,
    requestId: req.requestId,
    audit: true,
  });

  if (!authDecision.allowed) {
    res.status(authDecision.httpStatus).json({
      error: authDecision.reason,
      decision: authDecision.decision,
      message:
        authDecision.checks[authDecision.checks.length - 1]?.detail ??
        'Only owning HOD or Super Admin can approve document classification.',
      checks: authDecision.checks,
    });
    return;
  }

  const approvedAt = new Date().toISOString();
  const nextClassificationHash = computeClassificationHash({
    documentId: existing.id,
    departmentId: existing.department_id,
    classification: targetClassification,
    version: existing.version,
  });
  const reviewNote = typeof body?.note === 'string' ? body.note.trim().slice(0, 300) : '';

  db.prepare(`
    UPDATE documents
    SET classification = ?,
        classification_status = 'APPROVED',
        classification_approved_by = ?,
        classification_approved_at = ?,
        classification_hash = ?
    WHERE id = ?
  `).run(targetClassification, actor.id, approvedAt, nextClassificationHash, existing.id);

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'DOCUMENT_CLASSIFICATION_APPROVED',
    documentId: existing.id,
    decision: 'ALLOW',
    metadata: {
      fileName: existing.file_name,
      previousClassification: existing.classification,
      suggestedClassification: existing.suggested_classification,
      approvedClassification: targetClassification,
      classificationHash: nextClassificationHash,
      approvedByName: actor.name,
      note: reviewNote || null,
    },
    requestId: req.requestId,
  });

  const updatedRow = {
    ...existing,
    classification: targetClassification,
    classification_status: 'APPROVED' as const,
    classification_approved_by: actor.id,
    classification_approved_by_name: actor.name,
    classification_approved_at: approvedAt,
    classification_hash: nextClassificationHash,
  };

  res.status(200).json({
    document: mapDocumentRow(updatedRow),
    requestId: req.requestId,
  });
});

documentsRouter.get('/:id', requireAuth, (req, res) => {
  const db = getDatabase();
  const documentId = String(req.params.id);
  const decision = evaluateDocumentAccess(db, {
    actorId: req.auth!.user.id,
    documentId,
    action: 'DOCUMENT_METADATA_READ',
    requestId: req.requestId,
    audit: true,
  });

  if (!decision.allowed) {
    res.status(decision.httpStatus).json({
      error: decision.reason,
      decision: decision.decision,
      message: decision.checks[decision.checks.length - 1]?.detail ?? 'Access denied.',
      checks: decision.checks,
      requestId: req.requestId,
    });
    return;
  }

  const row = db
    .prepare(`
      SELECT
        d.id,
        d.file_name,
        d.mime_type,
        d.file_size,
        d.department_id,
        dept.name AS department_name,
        dept.code AS department_code,
        d.classification,
        d.uploaded_by,
        u.name AS uploaded_by_name,
        d.created_at,
        d.sha256_hash,
        d.version,
        d.suggested_classification,
        d.dlp_findings_json,
        d.classification_status,
        d.classification_approved_by,
        approver.name AS classification_approved_by_name,
        d.classification_approved_at,
        d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      INNER JOIN users u ON u.id = d.uploaded_by
      LEFT JOIN users approver ON approver.id = d.classification_approved_by
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(documentId) as DocumentMetadataRow | undefined;

  if (!row) {
    res.status(404).json({ error: 'DOCUMENT_NOT_FOUND', message: 'Document not found.' });
    return;
  }

  res.status(200).json({
    document: mapDocumentRow(row),
    access: decision,
  });
});

async function handleDocumentStream(
  mode: 'download' | 'view',
  req: Parameters<Parameters<typeof documentsRouter.get>[1]>[0],
  res: Parameters<Parameters<typeof documentsRouter.get>[1]>[1]
): Promise<void> {
  const db = getDatabase();
  const documentId = String(req.params.id);
  const action = mode === 'download' ? 'DOCUMENT_DOWNLOAD' : 'DOCUMENT_VIEW';

  const decision = evaluateDocumentAccess(db, {
    actorId: req.auth!.user.id,
    documentId,
    action,
    requestId: req.requestId,
    audit: true,
  });

  if (!decision.allowed) {
    res.status(decision.httpStatus).json({
      error: decision.reason,
      decision: decision.decision,
      message: decision.checks[decision.checks.length - 1]?.detail ?? 'Access denied by Zero-Trust PDP.',
      checks: decision.checks,
      requestId: req.requestId,
    });
    return;
  }

  const doc = db
    .prepare(`
      SELECT d.id, d.file_name, d.storage_path, d.mime_type, d.file_size,
             d.department_id, dept.code AS department_code, d.classification,
             d.sha256_hash, d.version, d.classification_status, d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(documentId) as DocumentStorageRow | undefined;

  if (!doc) {
    res.status(404).json({ error: 'DOCUMENT_NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const storage = getStorageProvider();
  let fileBytes: Buffer;
  try {
    fileBytes = await storage.getObject(doc.storage_path);
  } catch {
    appendAuditLog(db, {
      actorId: req.auth!.user.id,
      action: 'DOCUMENT_INTEGRITY_FAILED',
      documentId: doc.id,
      decision: 'DENY',
      denialReason: 'STORAGE_OBJECT_MISSING',
      metadata: {
        provider: storage.providerName,
        version: doc.version,
        classificationHash: doc.classification_hash,
      },
      requestId: req.requestId,
    });

    res.status(500).json({
      error: 'STORAGE_OBJECT_MISSING',
      message: 'Document file is missing from private storage.',
    });
    return;
  }

  const actualSha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');
  if (actualSha256 !== doc.sha256_hash) {
    appendAuditLog(db, {
      actorId: req.auth!.user.id,
      action: 'DOCUMENT_INTEGRITY_FAILED',
      documentId: doc.id,
      decision: 'DENY',
      denialReason: 'INTEGRITY_CHECK_FAILED',
      metadata: {
        provider: storage.providerName,
        version: doc.version,
        expectedSha256: doc.sha256_hash,
        actualSha256,
        classificationHash: doc.classification_hash,
      },
      requestId: req.requestId,
    });

    res.status(409).json({
      error: 'INTEGRITY_CHECK_FAILED',
      message: 'Document SHA-256 verification failed. Streaming aborted.',
    });
    return;
  }

  const safeName = sanitizeDisplayFileName(doc.file_name);
  const disposition = mode === 'download' ? 'attachment' : 'inline';
  const watermarkText = `UniVault ${doc.classification} · ${req.auth!.user.email} · ${new Date().toISOString()} · req:${(req.requestId ?? 'stream').slice(0, 8)}`;

  res.setHeader('Content-Type', doc.mime_type || 'application/pdf');
  res.setHeader('Content-Length', String(fileBytes.byteLength));
  res.setHeader('Content-Disposition', `${disposition}; filename="${safeName}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Document-Sha256', actualSha256);
  res.setHeader('X-Classification-Hash', doc.classification_hash);
  res.setHeader('X-Document-Version', String(doc.version));
  res.setHeader('X-Storage-Provider', storage.providerName);
  res.setHeader(
    'X-Watermark-Applied',
    doc.classification === 'CONFIDENTIAL' ? 'viewer-overlay-and-headers' : 'headers-only'
  );
  res.setHeader('X-Watermark-Text', watermarkText);

  res.status(200).send(fileBytes);
}

documentsRouter.post('/:id/verify-integrity', requireAuth, async (req, res) => {
  const db = getDatabase();
  const documentId = String(req.params.id);

  const decision = evaluateDocumentAccess(db, {
    actorId: req.auth!.user.id,
    documentId,
    action: 'DOCUMENT_METADATA_READ',
    requestId: req.requestId,
    audit: true,
  });

  if (!decision.allowed) {
    res.status(decision.httpStatus).json({
      verified: false,
      error: decision.reason,
      decision: decision.decision,
      message: decision.checks[decision.checks.length - 1]?.detail ?? 'Access denied by Zero-Trust PDP.',
      checks: decision.checks,
      requestId: req.requestId,
    });
    return;
  }

  const doc = db
    .prepare(`
      SELECT d.id, d.file_name, d.storage_path, d.mime_type, d.file_size,
             d.department_id, dept.code AS department_code, d.classification,
             d.sha256_hash, d.version, d.classification_status, d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(documentId) as DocumentStorageRow | undefined;

  if (!doc) {
    res.status(404).json({ verified: false, error: 'DOCUMENT_NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const classificationVerified = verifyClassificationHash(
    {
      documentId: doc.id,
      departmentId: doc.department_id,
      classification: doc.classification,
      version: doc.version,
    },
    doc.classification_hash
  );

  if (!classificationVerified) {
    appendAuditLog(db, {
      actorId: req.auth!.user.id,
      action: 'DOCUMENT_CLASSIFICATION_TAMPERED',
      documentId: doc.id,
      decision: 'DENY',
      denialReason: 'CLASSIFICATION_METADATA_TAMPERED',
      metadata: {
        version: doc.version,
        classification: doc.classification,
        storedClassificationHash: doc.classification_hash,
      },
      requestId: req.requestId,
    });

    res.status(409).json({
      verified: false,
      classificationVerified: false,
      error: 'CLASSIFICATION_METADATA_TAMPERED',
      message: 'Document classification metadata hash mismatch detected.',
      version: doc.version,
      requestId: req.requestId,
    });
    return;
  }

  const storage = getStorageProvider();
  let fileBytes: Buffer;
  try {
    fileBytes = await storage.getObject(doc.storage_path);
  } catch {
    appendAuditLog(db, {
      actorId: req.auth!.user.id,
      action: 'DOCUMENT_INTEGRITY_FAILED',
      documentId: doc.id,
      decision: 'DENY',
      denialReason: 'STORAGE_OBJECT_MISSING',
      metadata: {
        provider: storage.providerName,
        version: doc.version,
        classificationHash: doc.classification_hash,
      },
      requestId: req.requestId,
    });

    res.status(500).json({
      verified: false,
      error: 'STORAGE_OBJECT_MISSING',
      message: 'Stored object could not be retrieved from private storage.',
      version: doc.version,
      provider: storage.providerName,
    });
    return;
  }

  const actualSha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');
  const matched = actualSha256 === doc.sha256_hash;

  if (!matched) {
    appendAuditLog(db, {
      actorId: req.auth!.user.id,
      action: 'DOCUMENT_INTEGRITY_FAILED',
      documentId: doc.id,
      decision: 'DENY',
      denialReason: 'INTEGRITY_CHECK_FAILED',
      metadata: {
        provider: storage.providerName,
        version: doc.version,
        expectedSha256: doc.sha256_hash,
        actualSha256,
        classificationHash: doc.classification_hash,
      },
      requestId: req.requestId,
    });

    res.status(409).json({
      verified: false,
      classificationVerified: true,
      error: 'INTEGRITY_CHECK_FAILED',
      message: 'SHA-256 mismatch detected between stored file bytes and database metadata.',
      expectedSha256: doc.sha256_hash,
      actualSha256,
      version: doc.version,
      provider: storage.providerName,
      requestId: req.requestId,
    });
    return;
  }

  appendAuditLog(db, {
    actorId: req.auth!.user.id,
    action: 'DOCUMENT_INTEGRITY_VERIFIED',
    documentId: doc.id,
    decision: 'ALLOW',
    metadata: {
      provider: storage.providerName,
      version: doc.version,
      sha256: actualSha256,
      classificationHash: doc.classification_hash,
    },
    requestId: req.requestId,
  });

  res.status(200).json({
    verified: true,
    classificationVerified: true,
    classificationHash: doc.classification_hash,
    sha256: actualSha256,
    version: doc.version,
    provider: storage.providerName,
    requestId: req.requestId,
  });
});

documentsRouter.post('/:id/version', requireAuth, upload.single('file'), async (req, res) => {
  const db = getDatabase();
  const actor = req.auth!.user;
  const documentId = String(req.params.id);

  const existing = db
    .prepare(`
      SELECT d.id, d.file_name, d.storage_path, d.mime_type, d.file_size,
             d.department_id, dept.code AS department_code, d.classification,
             d.sha256_hash, d.version, d.classification_status, d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(documentId) as DocumentStorageRow | undefined;

  if (!existing) {
    res.status(404).json({ error: 'DOCUMENT_NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const uploadDecision = evaluateDocumentUpload(db, {
    actorId: actor.id,
    targetDepartmentId: existing.department_id,
    classification: existing.classification,
    requestId: req.requestId,
    audit: true,
  });

  if (!uploadDecision.allowed) {
    res.status(uploadDecision.httpStatus).json({
      error: uploadDecision.reason,
      decision: uploadDecision.decision,
      message: uploadDecision.checks[uploadDecision.checks.length - 1]?.detail ?? 'Version upload denied.',
      checks: uploadDecision.checks,
    });
    return;
  }

  const file = req.file;
  if (!file) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'PDF file is required in form field "file".',
    });
    return;
  }

  const isPdfMime = file.mimetype === 'application/pdf';
  const hasPdfExt = file.originalname.toLowerCase().endsWith('.pdf');
  const inspection = inspectUploadedPdf(file.buffer, existing.classification);
  if (!isPdfMime || !hasPdfExt || !inspection.signatureValid) {
    res.status(400).json({
      error: 'INVALID_FILE_TYPE',
      message: 'Only valid PDF documents (%PDF- signature) up to 10 MB are accepted.',
    });
    return;
  }

  if (inspection.activeContentBlocked) {
    appendAuditLog(db, {
      actorId: actor.id,
      action: 'DOCUMENT_UPLOAD_BLOCKED',
      documentId: existing.id,
      decision: 'DENY',
      denialReason: 'UNSAFE_PDF_CONTENT',
      metadata: {
        fileName: file.originalname,
        tokens: inspection.activeContentTokens,
      },
      requestId: req.requestId,
    });
    res.status(400).json({
      error: 'UNSAFE_PDF_CONTENT',
      message: `Version upload blocked: PDF contains disallowed active content tokens (${inspection.activeContentTokens.join(', ')}).`,
    });
    return;
  }

  const nextVersion = existing.version + 1;
  const newKey = `${existing.department_code.toLowerCase()}/${existing.classification.toLowerCase()}/${existing.id}-v${nextVersion}-${crypto.randomUUID()}.pdf`;
  const storage = getStorageProvider();
  const stored = await storage.putObject(newKey, file.buffer, 'application/pdf');
  const nowIso = new Date().toISOString();
  const classificationStatus: 'PENDING_APPROVAL' | 'APPROVED' = inspection.approvalRequired
    ? 'PENDING_APPROVAL'
    : existing.classification_status;
  const nextClassificationHash = computeClassificationHash({
    documentId: existing.id,
    departmentId: existing.department_id,
    classification: existing.classification,
    version: nextVersion,
  });

  db.prepare(`
    UPDATE documents
    SET storage_path = ?,
        file_size = ?,
        sha256_hash = ?,
        version = ?,
        suggested_classification = ?,
        dlp_findings_json = ?,
        classification_status = ?,
        classification_approved_by = CASE WHEN ? = 'PENDING_APPROVAL' THEN NULL ELSE COALESCE(classification_approved_by, ?) END,
        classification_approved_at = CASE WHEN ? = 'PENDING_APPROVAL' THEN NULL ELSE COALESCE(classification_approved_at, ?) END,
        classification_hash = ?
    WHERE id = ?
  `).run(
    stored.storagePath,
    stored.size,
    stored.sha256,
    nextVersion,
    inspection.suggestedClassification,
    JSON.stringify(inspection.dlpFindings),
    classificationStatus,
    classificationStatus,
    actor.id,
    classificationStatus,
    nowIso,
    nextClassificationHash,
    existing.id
  );

  appendAuditLog(db, {
    actorId: actor.id,
    action: 'DOCUMENT_VERSION_UPLOADED',
    documentId: existing.id,
    decision: 'ALLOW',
    metadata: {
      fileName: existing.file_name,
      previousVersion: existing.version,
      newVersion: nextVersion,
      previousSha256: existing.sha256_hash,
      newSha256: stored.sha256,
      classificationHash: nextClassificationHash,
      suggestedClassification: inspection.suggestedClassification,
      classificationStatus,
      provider: storage.providerName,
      scanStatus: 'CLEAN',
      dlpStatus: inspection.dlpStatus,
      matchedPatterns: inspection.matchedPatterns,
      patternCounts: inspection.patternCounts,
      externalAiClassifier: inspection.externalAiClassifier,
    },
    requestId: req.requestId,
  });

  res.status(200).json({
    document: {
      id: existing.id,
      fileName: existing.file_name,
      fileSize: stored.size,
      sha256Hash: stored.sha256,
      version: nextVersion,
      suggestedClassification: inspection.suggestedClassification,
      dlpFindings: inspection.dlpFindings,
      classificationStatus,
      classificationHash: nextClassificationHash,
      classificationHashValid: true,
    },
    inspection,
  });
});

documentsRouter.get('/:id/download', requireAuth, (req, res) => {
  void handleDocumentStream('download', req, res);
});

documentsRouter.get('/:id/view', requireAuth, (req, res) => {
  void handleDocumentStream('view', req, res);
});

export { documentsRouter };
