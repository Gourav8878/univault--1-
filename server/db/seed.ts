import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { getDatabase } from './connection.ts';
import { initializeSchema } from './schema.ts';
import { appendAuditLog } from './audit.ts';
import { createAuditAnchor } from './auditAnchors.ts';
import { createSamplePdfBuffer } from './pdfPlaceholder.ts';
import { computeClassificationHash } from '../pdp/classificationHash.ts';
import { getStorageProvider } from '../storage/index.ts';

const DEMO_PASSWORD = 'UniVault@Demo123';

const DEPARTMENTS = [
  { id: 'dept-cse', name: 'Computer Science', code: 'CSE' },
  { id: 'dept-ece', name: 'Electronics', code: 'ECE' },
  { id: 'dept-me', name: 'Mechanical Engineering', code: 'ME' },
  { id: 'dept-ce', name: 'Civil Engineering', code: 'CE' },
  { id: 'dept-admin', name: 'Administration', code: 'ADMIN' },
] as const;

const DEMO_USERS = [
  {
    id: 'user-super-admin',
    name: 'Dr. Kavita Nair (Super Admin)',
    email: 'admin@univault.edu',
    role: 'SUPER_ADMIN',
    departmentId: 'dept-admin',
  },
  {
    id: 'user-cse-hod',
    name: 'Prof. Arvind Menon (CSE HOD)',
    email: 'hod.cse@univault.edu',
    role: 'HOD',
    departmentId: 'dept-cse',
  },
  {
    id: 'user-cse-faculty',
    name: 'Dr. Priya Sharma (CSE Faculty)',
    email: 'faculty.cse@univault.edu',
    role: 'FACULTY',
    departmentId: 'dept-cse',
  },
  {
    id: 'user-ece-faculty',
    name: 'Dr. Rohan Verma (ECE Faculty)',
    email: 'faculty.ece@univault.edu',
    role: 'FACULTY',
    departmentId: 'dept-ece',
  },
] as const;

const DEFAULT_POLICIES = [
  {
    id: 'policy-super-admin',
    role: 'SUPER_ADMIN',
    allowedClassifications: JSON.stringify(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL']),
    departmentRestrictions: JSON.stringify({
      scope: 'ALL',
      allowPublicCrossDepartment: true,
    }),
    active: 1,
  },
  {
    id: 'policy-hod',
    role: 'HOD',
    allowedClassifications: JSON.stringify(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL']),
    departmentRestrictions: JSON.stringify({
      scope: 'OWN_DEPARTMENT',
      allowPublicCrossDepartment: true,
      requireExplicitGrantForCrossDepartment: true,
    }),
    active: 1,
  },
  {
    id: 'policy-faculty',
    role: 'FACULTY',
    allowedClassifications: JSON.stringify(['PUBLIC', 'INTERNAL']),
    departmentRestrictions: JSON.stringify({
      scope: 'OWN_DEPARTMENT',
      allowPublicCrossDepartment: true,
      requireExplicitGrantForConfidential: true,
    }),
    active: 1,
  },
] as const;

const SAMPLE_DOCUMENTS = [
  {
    id: 'doc-cse-exam-confidential',
    fileName: 'CSE Confidential Examination Paper.pdf',
    storageKey: 'cse/confidential/cse-confidential-examination-paper.pdf',
    departmentId: 'dept-cse',
    classification: 'CONFIDENTIAL' as const,
    uploadedBy: 'user-cse-hod',
    subtitle: 'Department: Computer Science (CSE) | Classification: CONFIDENTIAL',
    bodyLines: [
      'UniVault Zero-Trust Placeholder Document',
      'Course: CS401 Distributed Systems & Security',
      'Restricted to authorized CSE HOD and explicitly granted reviewers.',
    ],
  },
  {
    id: 'doc-cse-internal-report',
    fileName: 'CSE Internal Academic Report.pdf',
    storageKey: 'cse/internal/cse-internal-academic-report.pdf',
    departmentId: 'dept-cse',
    classification: 'INTERNAL' as const,
    uploadedBy: 'user-cse-hod',
    subtitle: 'Department: Computer Science (CSE) | Classification: INTERNAL',
    bodyLines: [
      'UniVault Zero-Trust Placeholder Document',
      'Semester Curriculum Review & Lab Infrastructure Summary.',
      'Scoped to Computer Science faculty and explicitly granted users.',
    ],
  },
  {
    id: 'doc-ece-dept-report',
    fileName: 'ECE Department Report.pdf',
    storageKey: 'ece/internal/ece-department-report.pdf',
    departmentId: 'dept-ece',
    classification: 'INTERNAL' as const,
    uploadedBy: 'user-ece-faculty',
    subtitle: 'Department: Electronics (ECE) | Classification: INTERNAL',
    bodyLines: [
      'UniVault Zero-Trust Placeholder Document',
      'VLSI & Embedded Systems Research Audit Summary.',
      'Scoped to Electronics department personnel.',
    ],
  },
  {
    id: 'doc-university-public-notice',
    fileName: 'University Public Notice.pdf',
    storageKey: 'admin/public/university-public-notice.pdf',
    departmentId: 'dept-admin',
    classification: 'PUBLIC' as const,
    uploadedBy: 'user-super-admin',
    subtitle: 'Department: Administration | Classification: PUBLIC',
    bodyLines: [
      'UniVault Zero-Trust Placeholder Document',
      'Academic Calendar & Campus Zero-Trust Security Compliance Notice.',
      'Accessible to all authenticated campus users.',
    ],
  },
];

export async function seedDatabase(): Promise<{ seededNewData: boolean }> {
  const db = getDatabase();
  initializeSchema(db);
  const storage = getStorageProvider();

  const existingDocCount = (
    db.prepare('SELECT COUNT(*) AS count FROM documents').get() as { count: number }
  ).count;

  const storedDocuments: Array<{
    doc: (typeof SAMPLE_DOCUMENTS)[number];
    storagePath: string;
    fileSize: number;
    sha256Hash: string;
  }> = [];

  for (const doc of SAMPLE_DOCUMENTS) {
    const pdfBuffer = createSamplePdfBuffer(doc.fileName, doc.subtitle, doc.bodyLines);
    const alreadyInStorage = await storage.exists(doc.storageKey);

    if (!alreadyInStorage) {
      const stored = await storage.putObject(doc.storageKey, pdfBuffer, 'application/pdf');
      storedDocuments.push({
        doc,
        storagePath: stored.storagePath,
        fileSize: stored.size,
        sha256Hash: stored.sha256,
      });
    } else {
      const existingBytes = await storage.getObject(doc.storageKey);
      storedDocuments.push({
        doc,
        storagePath: doc.storageKey,
        fileSize: existingBytes.byteLength,
        sha256Hash: crypto.createHash('sha256').update(existingBytes).digest('hex'),
      });
    }
  }

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 10);

  const runSeedTransaction = db.transaction(() => {
    const insertDepartment = db.prepare(`
      INSERT OR IGNORE INTO departments (id, name, code)
      VALUES (?, ?, ?)
    `);
    for (const dept of DEPARTMENTS) {
      insertDepartment.run(dept.id, dept.name, dept.code);
    }

    const insertUser = db.prepare(`
      INSERT OR IGNORE INTO users (id, name, email, password_hash, role, department_id, active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `);
    for (const user of DEMO_USERS) {
      insertUser.run(
        user.id,
        user.name,
        user.email,
        passwordHash,
        user.role,
        user.departmentId,
        createdAt
      );
    }

    const insertPolicy = db.prepare(`
      INSERT OR IGNORE INTO policies (id, role, allowed_classifications, department_restrictions, active)
      VALUES (?, ?, ?, ?, ?)
    `);
    for (const policy of DEFAULT_POLICIES) {
      insertPolicy.run(
        policy.id,
        policy.role,
        policy.allowedClassifications,
        policy.departmentRestrictions,
        policy.active
      );
    }

    const insertDocument = db.prepare(`
      INSERT OR IGNORE INTO documents (
        id, file_name, storage_path, mime_type, file_size,
        department_id, classification, uploaded_by, created_at, sha256_hash, version,
        suggested_classification, dlp_findings_json, classification_status,
        classification_approved_by, classification_approved_at, classification_hash
      ) VALUES (?, ?, ?, 'application/pdf', ?, ?, ?, ?, ?, ?, 1, ?, '[]', 'APPROVED', ?, ?, ?)
    `);
    for (const item of storedDocuments) {
      const classificationHash = computeClassificationHash({
        documentId: item.doc.id,
        departmentId: item.doc.departmentId,
        classification: item.doc.classification,
        version: 1,
      });
      insertDocument.run(
        item.doc.id,
        item.doc.fileName,
        item.storagePath,
        item.fileSize,
        item.doc.departmentId,
        item.doc.classification,
        item.doc.uploadedBy,
        createdAt,
        item.sha256Hash,
        item.doc.classification,
        item.doc.uploadedBy,
        createdAt,
        classificationHash
      );
    }

    // Backfill classification_hash safely on migrated databases where existing rows had empty hashes.
    const unhashedDocs = db
      .prepare(`
        SELECT id, department_id, classification, version
        FROM documents
        WHERE classification_hash = '' OR classification_hash IS NULL
      `)
      .all() as Array<{
      id: string;
      department_id: string;
      classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL';
      version: number;
    }>;

    if (unhashedDocs.length > 0) {
      const updateHash = db.prepare('UPDATE documents SET classification_hash = ? WHERE id = ?');
      for (const row of unhashedDocs) {
        updateHash.run(
          computeClassificationHash({
            documentId: row.id,
            departmentId: row.department_id,
            classification: row.classification,
            version: row.version,
          }),
          row.id
        );
      }
    }

    db.prepare(`
      INSERT OR IGNORE INTO access_grants (
        id, user_id, document_id, granted_by, created_at, expires_at, revoked_at, revoked_by, status
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 'ACTIVE')
    `).run(
      'grant-demo-cse-faculty-exam',
      'user-cse-faculty',
      'doc-cse-exam-confidential',
      'user-cse-hod',
      createdAt,
      expiresAt
    );

    const auditCount = (
      db.prepare('SELECT COUNT(*) AS count FROM audit_logs').get() as { count: number }
    ).count;

    if (auditCount === 0) {
      appendAuditLog(db, {
        actorId: 'user-super-admin',
        action: 'SYSTEM_SEED_INITIALIZED',
        decision: 'INFO',
        metadata: { departments: DEPARTMENTS.length, policies: DEFAULT_POLICIES.length },
        timestamp: createdAt,
        requestId: 'seed-bootstrap-000',
      });

      for (const item of storedDocuments) {
        appendAuditLog(db, {
          actorId: item.doc.uploadedBy,
          action: 'DOCUMENT_REGISTERED',
          documentId: item.doc.id,
          decision: 'ALLOW',
          metadata: {
            fileName: item.doc.fileName,
            classification: item.doc.classification,
            sha256: item.sha256Hash,
          },
          timestamp: createdAt,
          requestId: `seed-doc-${item.doc.id}`,
        });
      }

      appendAuditLog(db, {
        actorId: 'user-cse-hod',
        action: 'ACCESS_GRANT_CREATED',
        documentId: 'doc-cse-exam-confidential',
        targetUserId: 'user-cse-faculty',
        decision: 'ALLOW',
        metadata: {
          grantId: 'grant-demo-cse-faculty-exam',
          expiresAt,
        },
        timestamp: createdAt,
        requestId: 'seed-grant-001',
      });
    }
  });

  runSeedTransaction();

  const anchorCount = (
    db.prepare('SELECT COUNT(*) AS count FROM audit_anchors').get() as { count: number }
  ).count;

  if (anchorCount === 0) {
    await createAuditAnchor(db, {
      triggeredBy: 'user-super-admin',
      requestId: 'seed-anchor-001',
      logEvent: false,
    });
  }

  return { seededNewData: existingDocCount === 0 };
}
