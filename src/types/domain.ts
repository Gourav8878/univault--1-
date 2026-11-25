export type DocumentClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL';

export interface DepartmentItem {
  id: string;
  name: string;
  code: string;
}

export interface PolicyCheckStep {
  rule: string;
  passed: boolean;
  code: string;
  detail: string;
}

export interface DocumentAccessEvaluation {
  allowed: boolean;
  decision: 'ALLOW' | 'DENY';
  reason: string | null;
  grantId: string | null;
  grantExpiresAt: string | null;
  checks: PolicyCheckStep[];
}

export interface DlpFindingCount {
  pattern: string;
  count: number;
}

export interface DocumentItem {
  id: string;
  fileName: string;
  mimeType: string;
  fileSize: number;
  departmentId: string;
  departmentName: string;
  departmentCode: string;
  classification: DocumentClassification;
  uploadedBy: string;
  uploadedByName: string;
  createdAt: string;
  sha256Hash: string;
  version: number;
  suggestedClassification: DocumentClassification;
  dlpFindings: DlpFindingCount[];
  classificationStatus: 'PENDING_APPROVAL' | 'APPROVED';
  classificationApprovedBy: string | null;
  classificationApprovedByName: string | null;
  classificationApprovedAt: string | null;
  classificationHash: string;
  classificationHashValid: boolean;
  access: DocumentAccessEvaluation;
}

export interface AccessGrantItem {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  userRole: string;
  userDepartmentCode: string;
  documentId: string;
  documentName: string;
  documentClassification: DocumentClassification;
  documentDepartmentId: string;
  documentDepartmentCode: string;
  grantedBy: string;
  grantedByName: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
  revokedByName: string | null;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

export interface GrantTargetUser {
  id: string;
  name: string;
  email: string;
  role: string;
  departmentId: string;
  departmentCode: string;
}

export interface GrantTargetDocument {
  id: string;
  fileName: string;
  classification: DocumentClassification;
  departmentId: string;
  departmentCode: string;
}

export interface AuditLogItem {
  id: string;
  actorId: string | null;
  actorName: string | null;
  actorEmail: string | null;
  action: string;
  documentId: string | null;
  documentName: string | null;
  targetUserId: string | null;
  targetUserName: string | null;
  decision: 'ALLOW' | 'DENY' | 'INFO';
  denialReason: string | null;
  metadata: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
  timestamp: string;
  requestId: string;
}

export interface AuditChainIntegrity {
  valid: boolean;
  totalEntries: number;
  brokenAtId: string | null;
  reason: string | null;
}

export interface UploadInspectionResult {
  signatureValid: boolean;
  activeContentBlocked: boolean;
  activeContentTokens: string[];
  dlpStatus: 'CLEAN' | 'SENSITIVE_MARKERS_DETECTED';
  matchedPatterns: string[];
  patternCounts: Record<string, number>;
  dlpFindings: DlpFindingCount[];
  suggestedClassification: DocumentClassification;
  approvalRequired: boolean;
  externalAiClassifier: 'OFF_PROPOSED';
  dlpWarning: string | null;
}

export interface AuditAnchorRecord {
  anchorId: string;
  anchoredAt: string;
  headEntryHash: string;
  chainLength: number;
  targetMode: 'local-checkpoint' | 'azure-blob-configured';
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

export interface AccessRequestItem {
  id: string;
  requesterId: string;
  requesterName: string;
  requesterEmail: string;
  requesterRole: string;
  requesterDepartmentCode: string;
  documentId: string;
  documentName: string;
  documentClassification: DocumentClassification;
  documentDepartmentId: string;
  documentDepartmentCode: string;
  requestedDurationMinutes: number;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  reviewedBy: string | null;
  reviewedByName: string | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  grantId: string | null;
  createdAt: string;
}

export interface AuditAnomalySummary {
  riskLevel: 'NOMINAL' | 'ELEVATED' | 'ALERT';
  recentDenies15m: number;
  integrityFailuresTotal: number;
  flaggedActors: Array<{
    actorLabel: string;
    denyCount15m: number;
    latestTimestamp: string;
  }>;
  alerts: Array<{
    code: string;
    severity: 'ALERT' | 'ELEVATED';
    message: string;
  }>;
}
