import type { AuditAnchorVerificationStatus } from './domain';

export type UserRole = 'SUPER_ADMIN' | 'HOD' | 'FACULTY';

export type SessionChannel = 'default' | 'demo_faculty' | 'demo_hod';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  departmentId: string;
  departmentName: string;
  departmentCode: string;
  active: boolean;
}

export interface AuthSession {
  id: string;
  createdAt: string;
  expiresAt: string;
}

export interface AuthResponse {
  user: AuthUser;
  session: AuthSession;
}

export interface TableCounts {
  departments: number;
  users: number;
  documents: number;
  access_grants: number;
  access_requests: number;
  policies: number;
  sessions: number;
  audit_logs: number;
  audit_anchors: number;
}

export interface CapabilityItem {
  name: string;
  status: 'Implemented' | 'Partially Implemented' | 'Proposed';
  detail: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  service: string;
  tagline: string;
  timestamp: string;
  checks: {
    database: {
      healthy: boolean;
      engine: string;
      foreignKeysEnabled: boolean;
      tables: TableCounts | null;
      error?: string;
    };
    storage: {
      healthy: boolean;
      provider: 'local' | 'azure';
      authMode?: string;
      publicAccessBlocked?: boolean;
      targetLabel?: string;
      message: string;
    };
    auditAnchoring?: AuditAnchorVerificationStatus | null;
    classificationIntegrity?: {
      mode: 'hmac-sha256' | 'canonical-sha256';
      hmacKeyConfigured: boolean;
    };
  };
  capabilities?: CapabilityItem[];
}

export type NavSectionId =
  | 'overview'
  | 'documents'
  | 'grants'
  | 'security-demo'
  | 'audit-logs'
  | 'system-health';
