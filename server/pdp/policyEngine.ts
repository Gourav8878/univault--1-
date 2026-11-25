import type Database from 'better-sqlite3';
import type { UserRole } from '../auth/types.ts';
import { appendAuditLog } from '../db/audit.ts';
import { verifyClassificationHash } from './classificationHash.ts';

export type DocumentClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL';

export type DenialReasonCode =
  | 'USER_UNAUTHENTICATED'
  | 'USER_INACTIVE'
  | 'ROLE_NOT_ALLOWED'
  | 'CLASSIFICATION_NOT_ALLOWED'
  | 'CLASSIFICATION_APPROVAL_REQUIRED'
  | 'CLASSIFICATION_METADATA_TAMPERED'
  | 'DEPARTMENT_MISMATCH'
  | 'NO_VALID_GRANT'
  | 'GRANT_REVOKED'
  | 'GRANT_EXPIRED'
  | 'DOCUMENT_NOT_FOUND';

export interface PolicyCheckStep {
  rule: string;
  passed: boolean;
  code: string;
  detail: string;
}

export interface PolicyDecision {
  allowed: boolean;
  decision: 'ALLOW' | 'DENY';
  reason: DenialReasonCode | null;
  httpStatus: 200 | 401 | 403 | 404;
  checks: PolicyCheckStep[];
  grantId?: string | null;
  grantExpiresAt?: string | null;
}

interface FreshUserRow {
  id: string;
  role: UserRole;
  department_id: string;
  department_code: string;
  active: number;
}

interface PolicyRow {
  id: string;
  role: UserRole;
  allowed_classifications: string;
  department_restrictions: string;
  active: number;
}

interface DepartmentRestrictions {
  scope?: 'ALL' | 'OWN_DEPARTMENT';
  allowPublicCrossDepartment?: boolean;
  requireExplicitGrantForCrossDepartment?: boolean;
  requireExplicitGrantForConfidential?: boolean;
}

interface DocumentRow {
  id: string;
  file_name: string;
  department_id: string;
  department_code: string;
  classification: DocumentClassification;
  version: number;
  classification_status: 'PENDING_APPROVAL' | 'APPROVED';
  classification_hash: string;
}

interface GrantRow {
  id: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export function syncExpiredGrants(db: Database.Database, nowIso = new Date().toISOString()): number {
  const result = db
    .prepare(`
      UPDATE access_grants
      SET status = 'EXPIRED'
      WHERE status = 'ACTIVE' AND expires_at <= ?
    `)
    .run(nowIso);
  return result.changes;
}

function getFreshUser(db: Database.Database, userId: string): FreshUserRow | undefined {
  return db
    .prepare(`
      SELECT u.id, u.role, u.department_id, d.code AS department_code, u.active
      FROM users u
      INNER JOIN departments d ON d.id = u.department_id
      WHERE u.id = ?
      LIMIT 1
    `)
    .get(userId) as FreshUserRow | undefined;
}

function parsePolicy(row: PolicyRow): {
  allowedClassifications: DocumentClassification[];
  restrictions: DepartmentRestrictions;
} {
  let allowedClassifications: DocumentClassification[] = [];
  let restrictions: DepartmentRestrictions = { scope: 'OWN_DEPARTMENT' };

  try {
    const parsedClass = JSON.parse(row.allowed_classifications) as unknown;
    if (Array.isArray(parsedClass)) {
      allowedClassifications = parsedClass.filter(
        (item): item is DocumentClassification =>
          item === 'PUBLIC' || item === 'INTERNAL' || item === 'CONFIDENTIAL'
      );
    }
  } catch {
    allowedClassifications = [];
  }

  try {
    const parsedRestrictions = JSON.parse(row.department_restrictions) as unknown;
    if (parsedRestrictions && typeof parsedRestrictions === 'object') {
      restrictions = parsedRestrictions as DepartmentRestrictions;
    } else if (parsedRestrictions === 'ALL') {
      restrictions = { scope: 'ALL', allowPublicCrossDepartment: true };
    }
  } catch {
    restrictions = { scope: 'OWN_DEPARTMENT' };
  }

  return { allowedClassifications, restrictions };
}

function finalizeDecision(
  db: Database.Database,
  options: {
    audit: boolean;
    actorId: string | null;
    action: string;
    documentId?: string | null;
    targetUserId?: string | null;
    requestId?: string;
    decision: PolicyDecision;
    metadata?: Record<string, unknown>;
  }
): PolicyDecision {
  if (options.audit) {
    appendAuditLog(db, {
      actorId: options.actorId,
      action: options.action,
      documentId: options.documentId ?? null,
      targetUserId: options.targetUserId ?? null,
      decision: options.decision.decision,
      denialReason: options.decision.reason,
      metadata: {
        ...(options.metadata ?? {}),
        checks: options.decision.checks,
      },
      requestId: options.requestId,
    });
  }

  return options.decision;
}

export function evaluateDocumentAccess(
  db: Database.Database,
  params: {
    actorId: string | null;
    documentId: string;
    action: 'DOCUMENT_VIEW' | 'DOCUMENT_DOWNLOAD' | 'DOCUMENT_METADATA_READ';
    requestId?: string;
    audit?: boolean;
  }
): PolicyDecision {
  const audit = params.audit ?? true;
  const checks: PolicyCheckStep[] = [];

  if (!params.actorId) {
    checks.push({
      rule: 'AUTHENTICATION',
      passed: false,
      code: 'USER_UNAUTHENTICATED',
      detail: 'No authenticated user identity.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: null,
      action: params.action,
      documentId: params.documentId,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'USER_UNAUTHENTICATED',
        httpStatus: 401,
        checks,
      },
    });
  }

  const user = getFreshUser(db, params.actorId);
  if (!user) {
    checks.push({
      rule: 'AUTHENTICATION',
      passed: false,
      code: 'USER_UNAUTHENTICATED',
      detail: 'Actor account was not found in database.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: params.actorId,
      action: params.action,
      documentId: params.documentId,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'USER_UNAUTHENTICATED',
        httpStatus: 401,
        checks,
      },
    });
  }

  if (user.active !== 1) {
    checks.push({
      rule: 'ACCOUNT_STATUS',
      passed: false,
      code: 'USER_INACTIVE',
      detail: 'User account is inactive.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: params.documentId,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'USER_INACTIVE',
        httpStatus: 403,
        checks,
      },
    });
  }

  checks.push({
    rule: 'ACCOUNT_STATUS',
    passed: true,
    code: 'USER_ACTIVE',
    detail: `Verified active ${user.role} in ${user.department_code}.`,
  });

  const doc = db
    .prepare(`
      SELECT
        d.id, d.file_name, d.department_id, dept.code AS department_code,
        d.classification, d.version, d.classification_status, d.classification_hash
      FROM documents d
      INNER JOIN departments dept ON dept.id = d.department_id
      WHERE d.id = ?
      LIMIT 1
    `)
    .get(params.documentId) as DocumentRow | undefined;

  if (!doc) {
    checks.push({
      rule: 'RESOURCE_LOOKUP',
      passed: false,
      code: 'DOCUMENT_NOT_FOUND',
      detail: 'Requested document does not exist.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: null,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'DOCUMENT_NOT_FOUND',
        httpStatus: 404,
        checks,
      },
      metadata: { requestedDocumentId: params.documentId },
    });
  }

  const classificationHashValid = verifyClassificationHash(
    {
      documentId: doc.id,
      departmentId: doc.department_id,
      classification: doc.classification,
      version: doc.version,
    },
    doc.classification_hash
  );

  if (!classificationHashValid) {
    checks.push({
      rule: 'CLASSIFICATION_METADATA_TRUST',
      passed: false,
      code: 'CLASSIFICATION_METADATA_TAMPERED',
      detail: 'Document classification_hash verification failed; access blocked.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'CLASSIFICATION_METADATA_TAMPERED',
        httpStatus: 403,
        checks,
      },
      metadata: {
        classification: doc.classification,
        version: doc.version,
        storedClassificationHash: doc.classification_hash,
      },
    });
  }

  checks.push({
    rule: 'CLASSIFICATION_METADATA_TRUST',
    passed: true,
    code: 'CLASSIFICATION_HASH_VERIFIED',
    detail: `Classification metadata hash verified (${doc.classification}, v${doc.version}).`,
  });

  const policyRow = db
    .prepare(`
      SELECT id, role, allowed_classifications, department_restrictions, active
      FROM policies
      WHERE role = ? AND active = 1
      LIMIT 1
    `)
    .get(user.role) as PolicyRow | undefined;

  if (!policyRow) {
    checks.push({
      rule: 'ROLE_POLICY',
      passed: false,
      code: 'ROLE_NOT_ALLOWED',
      detail: `No active policy configured for role ${user.role}.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'ROLE_NOT_ALLOWED',
        httpStatus: 403,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  const { allowedClassifications, restrictions } = parsePolicy(policyRow);
  const nowIso = new Date().toISOString();
  syncExpiredGrants(db, nowIso);

  const isDepartmentSteward =
    user.role === 'SUPER_ADMIN' ||
    (user.role === 'HOD' && user.department_id === doc.department_id);

  if (doc.classification_status === 'PENDING_APPROVAL' && !isDepartmentSteward) {
    checks.push({
      rule: 'HUMAN_CLASSIFICATION_GATE',
      passed: false,
      code: 'CLASSIFICATION_APPROVAL_REQUIRED',
      detail:
        'Document awaits human HOD or Super Admin classification confirmation before sharing.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'CLASSIFICATION_APPROVAL_REQUIRED',
        httpStatus: 403,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  const grantRows = db
    .prepare(`
      SELECT id, status, expires_at, revoked_at, created_at
      FROM access_grants
      WHERE user_id = ? AND document_id = ?
      ORDER BY created_at DESC
    `)
    .all(user.id, doc.id) as GrantRow[];

  const activeGrant = grantRows.find(
    (g) => g.status === 'ACTIVE' && g.expires_at > nowIso && g.revoked_at === null
  );
  const latestRevokedGrant = grantRows.find((g) => g.status === 'REVOKED');
  const latestExpiredGrant = grantRows.find((g) => g.status === 'EXPIRED');

  // 1. PUBLIC documents permitted when policy includes PUBLIC & cross-dept public is allowed
  if (
    doc.classification === 'PUBLIC' &&
    allowedClassifications.includes('PUBLIC') &&
    (restrictions.scope === 'ALL' || restrictions.allowPublicCrossDepartment !== false)
  ) {
    checks.push({
      rule: 'CLASSIFICATION_PUBLIC',
      passed: true,
      code: 'PUBLIC_POLICY_ALLOW',
      detail: 'PUBLIC classification permitted for authenticated campus users.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: true,
        decision: 'ALLOW',
        reason: null,
        httpStatus: 200,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  const classificationAllowedByRole = allowedClassifications.includes(doc.classification);
  const sameDepartment = user.department_id === doc.department_id;

  // 2. Role baseline permits classification & department scope
  if (classificationAllowedByRole && (restrictions.scope === 'ALL' || sameDepartment)) {
    checks.push({
      rule: 'RBAC_ABAC_POLICY',
      passed: true,
      code: restrictions.scope === 'ALL' ? 'GLOBAL_ADMIN_SCOPE' : 'OWN_DEPARTMENT_SCOPE',
      detail:
        restrictions.scope === 'ALL'
          ? `${user.role} policy permits ${doc.classification} across all departments.`
          : `${user.role} policy permits ${doc.classification} within ${doc.department_code}.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: true,
        decision: 'ALLOW',
        reason: null,
        httpStatus: 200,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  // 3. Explicit time-bound grant path (for cross-department or elevated classification access)
  if (activeGrant) {
    checks.push({
      rule: 'ACCESS_GRANT',
      passed: true,
      code: 'EXPLICIT_GRANT_ACTIVE',
      detail: `Active grant ${activeGrant.id} valid until ${activeGrant.expires_at}.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: true,
        decision: 'ALLOW',
        reason: null,
        httpStatus: 200,
        checks,
        grantId: activeGrant.id,
        grantExpiresAt: activeGrant.expires_at,
      },
      metadata: { grantId: activeGrant.id, classificationHash: doc.classification_hash },
    });
  }

  // 4. Explicit grant previously existed but was revoked or expired
  if (latestRevokedGrant) {
    checks.push({
      rule: 'ACCESS_GRANT',
      passed: false,
      code: 'GRANT_REVOKED',
      detail: `Explicit grant ${latestRevokedGrant.id} was revoked at ${latestRevokedGrant.revoked_at ?? 'unknown time'}.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'GRANT_REVOKED',
        httpStatus: 403,
        checks,
        grantId: latestRevokedGrant.id,
      },
      metadata: { grantId: latestRevokedGrant.id, classificationHash: doc.classification_hash },
    });
  }

  if (latestExpiredGrant) {
    checks.push({
      rule: 'ACCESS_GRANT',
      passed: false,
      code: 'GRANT_EXPIRED',
      detail: `Explicit grant ${latestExpiredGrant.id} expired at ${latestExpiredGrant.expires_at}.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'GRANT_EXPIRED',
        httpStatus: 403,
        checks,
        grantId: latestExpiredGrant.id,
        grantExpiresAt: latestExpiredGrant.expires_at,
      },
      metadata: { grantId: latestExpiredGrant.id, classificationHash: doc.classification_hash },
    });
  }

  // 5. Department mismatch vs classification / missing grant denial reasons
  if (!sameDepartment && restrictions.scope !== 'ALL') {
    checks.push({
      rule: 'DEPARTMENT_BOUNDARY',
      passed: false,
      code: 'DEPARTMENT_MISMATCH',
      detail: `User department (${user.department_code}) does not match document department (${doc.department_code}) and no active grant exists.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'DEPARTMENT_MISMATCH',
        httpStatus: 403,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  if (!classificationAllowedByRole && restrictions.requireExplicitGrantForConfidential) {
    checks.push({
      rule: 'CONFIDENTIAL_GRANT_REQUIRED',
      passed: false,
      code: 'NO_VALID_GRANT',
      detail: `${user.role} requires an active explicit grant to access ${doc.classification} documents.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: doc.id,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'NO_VALID_GRANT',
        httpStatus: 403,
        checks,
      },
      metadata: { classificationHash: doc.classification_hash },
    });
  }

  checks.push({
    rule: 'CLASSIFICATION_POLICY',
    passed: false,
    code: 'CLASSIFICATION_NOT_ALLOWED',
    detail: `Role ${user.role} is not permitted to access ${doc.classification} documents.`,
  });
  return finalizeDecision(db, {
    audit,
    actorId: user.id,
    action: params.action,
    documentId: doc.id,
    requestId: params.requestId,
    decision: {
      allowed: false,
      decision: 'DENY',
      reason: 'CLASSIFICATION_NOT_ALLOWED',
      httpStatus: 403,
      checks,
    },
    metadata: { classificationHash: doc.classification_hash },
  });
}

export function evaluateDocumentUpload(
  db: Database.Database,
  params: {
    actorId: string | null;
    targetDepartmentId: string;
    classification: DocumentClassification;
    requestId?: string;
    audit?: boolean;
  }
): PolicyDecision {
  const audit = params.audit ?? true;
  const checks: PolicyCheckStep[] = [];

  if (!params.actorId) {
    checks.push({
      rule: 'AUTHENTICATION',
      passed: false,
      code: 'USER_UNAUTHENTICATED',
      detail: 'Authentication required to upload documents.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: null,
      action: 'DOCUMENT_UPLOAD',
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'USER_UNAUTHENTICATED',
        httpStatus: 401,
        checks,
      },
    });
  }

  const user = getFreshUser(db, params.actorId);
  if (!user || user.active !== 1) {
    const code = !user ? 'USER_UNAUTHENTICATED' : 'USER_INACTIVE';
    checks.push({
      rule: 'ACCOUNT_STATUS',
      passed: false,
      code,
      detail: !user ? 'Actor not found.' : 'User account is inactive.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: params.actorId,
      action: 'DOCUMENT_UPLOAD',
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: code,
        httpStatus: !user ? 401 : 403,
        checks,
      },
    });
  }

  if (user.role !== 'SUPER_ADMIN' && user.role !== 'HOD') {
    checks.push({
      rule: 'UPLOAD_ROLE',
      passed: false,
      code: 'ROLE_NOT_ALLOWED',
      detail: `Role ${user.role} is not authorized to upload managed campus documents.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: 'DOCUMENT_UPLOAD',
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'ROLE_NOT_ALLOWED',
        httpStatus: 403,
        checks,
      },
      metadata: { targetDepartmentId: params.targetDepartmentId, classification: params.classification },
    });
  }

  if (user.role === 'HOD' && user.department_id !== params.targetDepartmentId) {
    checks.push({
      rule: 'UPLOAD_DEPARTMENT',
      passed: false,
      code: 'DEPARTMENT_MISMATCH',
      detail: 'HOD may only upload documents into their own department.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: 'DOCUMENT_UPLOAD',
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'DEPARTMENT_MISMATCH',
        httpStatus: 403,
        checks,
      },
      metadata: { targetDepartmentId: params.targetDepartmentId, classification: params.classification },
    });
  }

  checks.push({
    rule: 'UPLOAD_AUTHORITY',
    passed: true,
    code: 'UPLOAD_PERMITTED',
    detail: `${user.role} authorized for ${params.classification} upload.`,
  });

  return {
    allowed: true,
    decision: 'ALLOW',
    reason: null,
    httpStatus: 200,
    checks,
  };
}

export function evaluateGrantManagement(
  db: Database.Database,
  params: {
    actorId: string | null;
    action: 'ACCESS_GRANT_CREATE' | 'ACCESS_GRANT_REVOKE';
    documentId: string;
    documentDepartmentId: string;
    targetUserId?: string;
    requestId?: string;
    audit?: boolean;
  }
): PolicyDecision {
  const audit = params.audit ?? true;
  const checks: PolicyCheckStep[] = [];

  if (!params.actorId) {
    checks.push({
      rule: 'AUTHENTICATION',
      passed: false,
      code: 'USER_UNAUTHENTICATED',
      detail: 'Authentication required for grant management.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: null,
      action: params.action,
      documentId: params.documentId,
      targetUserId: params.targetUserId ?? null,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'USER_UNAUTHENTICATED',
        httpStatus: 401,
        checks,
      },
    });
  }

  const user = getFreshUser(db, params.actorId);
  if (!user || user.active !== 1) {
    const code = !user ? 'USER_UNAUTHENTICATED' : 'USER_INACTIVE';
    checks.push({
      rule: 'ACCOUNT_STATUS',
      passed: false,
      code,
      detail: !user ? 'Actor not found.' : 'User account is inactive.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: params.actorId,
      action: params.action,
      documentId: params.documentId,
      targetUserId: params.targetUserId ?? null,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: code,
        httpStatus: !user ? 401 : 403,
        checks,
      },
    });
  }

  if (user.role !== 'SUPER_ADMIN' && user.role !== 'HOD') {
    checks.push({
      rule: 'GRANT_ROLE',
      passed: false,
      code: 'ROLE_NOT_ALLOWED',
      detail: `Role ${user.role} cannot issue or revoke document grants.`,
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: params.documentId,
      targetUserId: params.targetUserId ?? null,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'ROLE_NOT_ALLOWED',
        httpStatus: 403,
        checks,
      },
    });
  }

  if (user.role === 'HOD' && user.department_id !== params.documentDepartmentId) {
    checks.push({
      rule: 'GRANT_DEPARTMENT',
      passed: false,
      code: 'DEPARTMENT_MISMATCH',
      detail: 'HOD may only manage grants for documents owned by their own department.',
    });
    return finalizeDecision(db, {
      audit,
      actorId: user.id,
      action: params.action,
      documentId: params.documentId,
      targetUserId: params.targetUserId ?? null,
      requestId: params.requestId,
      decision: {
        allowed: false,
        decision: 'DENY',
        reason: 'DEPARTMENT_MISMATCH',
        httpStatus: 403,
        checks,
      },
    });
  }

  checks.push({
    rule: 'GRANT_AUTHORITY',
    passed: true,
    code: 'GRANT_MANAGEMENT_PERMITTED',
    detail: `${user.role} authorized to manage grants for this document.`,
  });

  return {
    allowed: true,
    decision: 'ALLOW',
    reason: null,
    httpStatus: 200,
    checks,
  };
}
