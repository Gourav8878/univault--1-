import type { AuthResponse, HealthResponse, SessionChannel } from '../types/auth';
import type {
  AccessGrantItem,
  AccessRequestItem,
  AuditAnchorRecord,
  AuditAnchorVerificationStatus,
  AuditAnomalySummary,
  AuditChainIntegrity,
  AuditLogItem,
  DepartmentItem,
  DocumentClassification,
  DocumentItem,
  GrantTargetDocument,
  GrantTargetUser,
  PolicyCheckStep,
  UploadInspectionResult,
} from '../types/domain';

export class ApiError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly checks?: PolicyCheckStep[];
  public readonly requestId?: string;

  constructor(
    status: number,
    code: string,
    message: string,
    checks?: PolicyCheckStep[],
    requestId?: string
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.checks = checks;
    this.requestId = requestId;
  }
}

async function parseJsonSafe(response: Response): Promise<Record<string, unknown>> {
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function buildHeaders(
  channel: SessionChannel = 'default',
  extra?: Record<string, string>
): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'UniVault',
    ...extra,
  };
  if (channel !== 'default') {
    headers['X-Session-Channel'] = channel;
  }
  return headers;
}

function throwApiError(response: Response, payload: Record<string, unknown>, fallbackMsg: string): never {
  throw new ApiError(
    response.status,
    typeof payload.error === 'string' ? payload.error : 'REQUEST_FAILED',
    typeof payload.message === 'string' ? payload.message : fallbackMsg,
    Array.isArray(payload.checks) ? (payload.checks as PolicyCheckStep[]) : undefined,
    typeof payload.requestId === 'string'
      ? payload.requestId
      : (response.headers.get('X-Request-Id') ?? undefined)
  );
}

export async function loginWithCredentials(
  email: string,
  password: string,
  channel: SessionChannel = 'default'
): Promise<AuthResponse> {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({ email, password, channel }),
  });

  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Authentication failed.');
  }

  return payload as unknown as AuthResponse;
}

export async function logoutSession(channel: SessionChannel = 'default'): Promise<void> {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({ channel }),
  });

  if (!response.ok) {
    const payload = await parseJsonSafe(response);
    throwApiError(response, payload, 'Failed to terminate session.');
  }
}

export async function fetchCurrentSession(
  channel: SessionChannel = 'default'
): Promise<AuthResponse> {
  const response = await fetch('/api/auth/me', {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });

  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Session is not authenticated.');
  }

  return payload as unknown as AuthResponse;
}

export async function fetchSystemHealth(): Promise<{
  ok: boolean;
  status: number;
  data: HealthResponse;
}> {
  const response = await fetch('/api/health', {
    method: 'GET',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });

  const data = (await response.json()) as HealthResponse;
  return { ok: response.ok, status: response.status, data };
}

export async function fetchDepartments(
  channel: SessionChannel = 'default'
): Promise<DepartmentItem[]> {
  const response = await fetch('/api/departments', {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load departments.');
  }
  return (payload.departments as DepartmentItem[]) ?? [];
}

export async function fetchDocuments(
  filters: {
    search?: string;
    departmentId?: string;
    classification?: string;
    onlyAllowed?: boolean;
  } = {},
  channel: SessionChannel = 'default'
): Promise<DocumentItem[]> {
  const params = new URLSearchParams();
  if (filters.search?.trim()) params.set('search', filters.search.trim());
  if (filters.departmentId) params.set('departmentId', filters.departmentId);
  if (filters.classification) params.set('classification', filters.classification);
  if (filters.onlyAllowed) params.set('onlyAllowed', 'true');

  const query = params.toString();
  const response = await fetch(`/api/documents${query ? `?${query}` : ''}`, {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load documents.');
  }
  return (payload.documents as DocumentItem[]) ?? [];
}

export async function uploadDocument(
  formData: FormData,
  channel: SessionChannel = 'default'
): Promise<{ document: DocumentItem; inspection?: UploadInspectionResult }> {
  const response = await fetch('/api/documents', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel),
    body: formData,
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to upload document.');
  }
  return {
    document: payload.document as DocumentItem,
    inspection: payload.inspection as UploadInspectionResult | undefined,
  };
}

export async function fetchProtectedDocumentBlob(
  documentId: string,
  mode: 'view' | 'download',
  channel: SessionChannel = 'default'
): Promise<{
  blob: Blob;
  status: number;
  sha256: string | null;
  requestId: string | null;
  contentDisposition: string | null;
  watermarkText: string | null;
  watermarkApplied: string | null;
}> {
  const endpoint = `/api/documents/${encodeURIComponent(documentId)}/${mode}`;
  const response = await fetch(endpoint, {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel, { Accept: 'application/pdf, application/json' }),
  });

  if (!response.ok) {
    const payload = await parseJsonSafe(response);
    throwApiError(response, payload, `Document ${mode} denied.`);
  }

  const blob = await response.blob();
  return {
    blob,
    status: response.status,
    sha256: response.headers.get('X-Document-Sha256'),
    requestId: response.headers.get('X-Request-Id'),
    contentDisposition: response.headers.get('Content-Disposition'),
    watermarkText: response.headers.get('X-Watermark-Text'),
    watermarkApplied: response.headers.get('X-Watermark-Applied'),
  };
}

export async function verifyDocumentIntegrity(
  documentId: string,
  channel: SessionChannel = 'default'
): Promise<{
  verified: boolean;
  classificationVerified?: boolean;
  classificationHash?: string;
  sha256: string;
  version: number;
  provider: string;
  requestId?: string;
}> {
  const response = await fetch(`/api/documents/${encodeURIComponent(documentId)}/verify-integrity`, {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Document integrity check failed.');
  }
  return payload as {
    verified: boolean;
    classificationVerified?: boolean;
    classificationHash?: string;
    sha256: string;
    version: number;
    provider: string;
    requestId?: string;
  };
}

export async function approveDocumentClassification(
  documentId: string,
  input: { classification: DocumentClassification; note?: string },
  channel: SessionChannel = 'default'
): Promise<{ document: DocumentItem; requestId?: string }> {
  const response = await fetch(
    `/api/documents/${encodeURIComponent(documentId)}/approve-classification`,
    {
      method: 'POST',
      credentials: 'include',
      headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
      body: JSON.stringify(input),
    }
  );
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to approve document classification.');
  }
  return {
    document: payload.document as DocumentItem,
    requestId: typeof payload.requestId === 'string' ? payload.requestId : undefined,
  };
}

export async function uploadDocumentVersion(
  documentId: string,
  formData: FormData,
  channel: SessionChannel = 'default'
): Promise<{
  id: string;
  fileName: string;
  fileSize: number;
  sha256Hash: string;
  version: number;
  inspection?: UploadInspectionResult;
}> {
  const response = await fetch(`/api/documents/${encodeURIComponent(documentId)}/version`, {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel),
    body: formData,
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to upload new document version.');
  }
  const doc = payload.document as {
    id: string;
    fileName: string;
    fileSize: number;
    sha256Hash: string;
    version: number;
  };
  return {
    ...doc,
    inspection: payload.inspection as UploadInspectionResult | undefined,
  };
}

export async function fetchGrants(
  channel: SessionChannel = 'default'
): Promise<AccessGrantItem[]> {
  const response = await fetch('/api/grants', {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load access grants.');
  }
  return (payload.grants as AccessGrantItem[]) ?? [];
}

export async function fetchGrantTargets(
  channel: SessionChannel = 'default'
): Promise<{ users: GrantTargetUser[]; documents: GrantTargetDocument[] }> {
  const response = await fetch('/api/grants/targets', {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load grant targets.');
  }
  return {
    users: (payload.users as GrantTargetUser[]) ?? [],
    documents: (payload.documents as GrantTargetDocument[]) ?? [],
  };
}

export async function createAccessGrant(
  input: {
    userId: string;
    documentId: string;
    expiresAt?: string;
    durationMinutes?: number;
  },
  channel: SessionChannel = 'default'
): Promise<{ id: string; expiresAt: string; status: string }> {
  const response = await fetch('/api/grants', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify(input),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to create access grant.');
  }
  return payload.grant as { id: string; expiresAt: string; status: string };
}

export async function revokeAccessGrant(
  grantId: string,
  channel: SessionChannel = 'default'
): Promise<{ id: string; status: string; revokedAt: string }> {
  const response = await fetch(`/api/grants/${encodeURIComponent(grantId)}/revoke`, {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to revoke access grant.');
  }
  return payload.grant as { id: string; status: string; revokedAt: string };
}

export async function fetchAccessRequests(
  channel: SessionChannel = 'default'
): Promise<{ requests: AccessRequestItem[]; requestableDocuments: GrantTargetDocument[] }> {
  const response = await fetch('/api/grants/requests', {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load JIT access requests.');
  }
  return {
    requests: (payload.requests as AccessRequestItem[]) ?? [],
    requestableDocuments: (payload.requestableDocuments as GrantTargetDocument[]) ?? [],
  };
}

export async function createAccessRequest(
  input: { documentId: string; durationMinutes: number; justification: string },
  channel: SessionChannel = 'default'
): Promise<{ id: string; status: string }> {
  const response = await fetch('/api/grants/requests', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify(input),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to submit JIT access request.');
  }
  return payload.request as { id: string; status: string };
}

export async function decideAccessRequest(
  requestId: string,
  decision: 'APPROVE' | 'REJECT',
  note?: string,
  channel: SessionChannel = 'default'
): Promise<{ id: string; status: 'APPROVED' | 'REJECTED'; grantId: string | null }> {
  const response = await fetch(`/api/grants/requests/${encodeURIComponent(requestId)}/decide`, {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({ decision, note }),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to process JIT access request.');
  }
  return payload.request as { id: string; status: 'APPROVED' | 'REJECTED'; grantId: string | null };
}

export async function fetchAuditLogs(
  filters: { decision?: string; action?: string; limit?: number } = {},
  channel: SessionChannel = 'default'
): Promise<{
  chainIntegrity: AuditChainIntegrity;
  anchorStatus: AuditAnchorVerificationStatus;
  anomalySummary: AuditAnomalySummary;
  logs: AuditLogItem[];
}> {
  const params = new URLSearchParams();
  if (filters.decision) params.set('decision', filters.decision);
  if (filters.action?.trim()) params.set('action', filters.action.trim());
  if (filters.limit) params.set('limit', String(filters.limit));

  const query = params.toString();
  const response = await fetch(`/api/audit-logs${query ? `?${query}` : ''}`, {
    method: 'GET',
    credentials: 'include',
    headers: buildHeaders(channel),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to load audit logs.');
  }
  return {
    chainIntegrity: payload.chainIntegrity as AuditChainIntegrity,
    anchorStatus: payload.anchorStatus as AuditAnchorVerificationStatus,
    anomalySummary: payload.anomalySummary as AuditAnomalySummary,
    logs: (payload.logs as AuditLogItem[]) ?? [],
  };
}

export async function triggerAuditAnchor(
  channel: SessionChannel = 'default'
): Promise<{
  anchor: AuditAnchorRecord;
  anchorStatus: AuditAnchorVerificationStatus;
  requestId?: string;
}> {
  const response = await fetch('/api/audit-logs/anchor', {
    method: 'POST',
    credentials: 'include',
    headers: buildHeaders(channel, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });
  const payload = await parseJsonSafe(response);
  if (!response.ok) {
    throwApiError(response, payload, 'Failed to trigger audit anchor checkpoint.');
  }
  return {
    anchor: payload.anchor as AuditAnchorRecord,
    anchorStatus: payload.anchorStatus as AuditAnchorVerificationStatus,
    requestId: typeof payload.requestId === 'string' ? payload.requestId : undefined,
  };
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function classificationTextTone(classification: DocumentClassification): string {
  switch (classification) {
    case 'CONFIDENTIAL':
      return 'text-red-700 font-semibold';
    case 'INTERNAL':
      return 'text-amber-700 font-semibold';
    case 'PUBLIC':
      return 'text-emerald-700 font-semibold';
  }
}
