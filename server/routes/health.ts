import { Router } from 'express';
import { verifyLatestAuditAnchor, type AuditAnchorVerificationStatus } from '../db/auditAnchors.ts';
import { getDatabase } from '../db/connection.ts';
import { getClassificationHashMode } from '../pdp/classificationHash.ts';
import { getStorageProvider } from '../storage/index.ts';

const healthRouter = Router();

interface TableCounts {
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

healthRouter.get('/health', async (_req, res, next) => {
  try {
    let dbHealthy = false;
    let foreignKeysEnabled = false;
    let dbError: string | undefined;
    let tables: TableCounts | null = null;
    let anchorStatus: AuditAnchorVerificationStatus | null = null;

    try {
      const db = getDatabase();
      const ping = db.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined;
      const fkPragma = db.pragma('foreign_keys', { simple: true }) as number;

      foreignKeysEnabled = fkPragma === 1;
      dbHealthy = ping?.ok === 1 && foreignKeysEnabled;

      const countOf = (table: keyof TableCounts): number => {
        const row = db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number };
        return row.count;
      };

      tables = {
        departments: countOf('departments'),
        users: countOf('users'),
        documents: countOf('documents'),
        access_grants: countOf('access_grants'),
        access_requests: countOf('access_requests'),
        policies: countOf('policies'),
        sessions: countOf('sessions'),
        audit_logs: countOf('audit_logs'),
        audit_anchors: countOf('audit_anchors'),
      };

      if (dbHealthy) {
        anchorStatus = await verifyLatestAuditAnchor(db);
      }
    } catch (error) {
      dbError = (error as Error).message;
    }

    const storage = getStorageProvider();
    const storageHealth = await storage.healthCheck();
    const classificationHashMode = getClassificationHashMode();

    const capabilities: CapabilityItem[] = [
      {
        name: 'Zero-Trust HttpOnly Cookie Auth & RBAC/ABAC PDP',
        status: 'Implemented',
        detail:
          'HMAC-SHA256 hashed SQLite sessions, SameSite/Secure/Partitioned cookies, origin checks, role/classification/department policies, and immediate revocation.',
      },
      {
        name: 'LocalPrivateStorage (Outside Public Assets)',
        status: 'Implemented',
        detail:
          'Private filesystem directory outside static assets with path-traversal protection and server-generated UUID keys.',
      },
      {
        name: 'AzureBlobStorage (Private Container via @azure/storage-blob)',
        status:
          storageHealth.provider === 'azure' && storageHealth.healthy
            ? 'Implemented'
            : 'Partially Implemented',
        detail:
          'Implemented with @azure/storage-blob and DefaultAzureCredential / connection string for private containers; optional at startup and requires live Azure credentials when STORAGE_PROVIDER=azure.',
      },
      {
        name: 'SHA-256 Upload & Pre-Stream Integrity Verification',
        status: 'Implemented',
        detail:
          'Computes SHA-256 on upload and verifies every stream before sending bytes; aborts mismatched files with HTTP 409 and audits tampering.',
      },
      {
        name: 'Tamper-Evident Classification Metadata Hash (classification_hash)',
        status: 'Implemented',
        detail: `Computes ${classificationHashMode} over {documentId, departmentId, classification, version}, verifies in PDP & integrity checks, and denies mismatched metadata with HTTP 403 CLASSIFICATION_METADATA_TAMPERED.`,
      },
      {
        name: 'Local DLP, Rule-Based Classifier & Human HOD Approval',
        status: 'Implemented',
        detail:
          'Deterministic server-side scanner for STUDENT_ID, EMAIL, PHONE_NUMBER, CONFIDENTIAL_KEYWORD, PRIVATE_KEY, and GOV_ID_FORMAT; suggests classification without logging raw PII and gates sharing until human HOD/Admin approval.',
      },
      {
        name: 'Periodic Audit Anchoring (Local Checkpoint & Env-Gated Azure Hook)',
        status: 'Implemented',
        detail:
          'Records periodic & manually triggered audit_anchors checkpoints (anchor_id, head_entry_hash, chain_length) to SQLite and external checkpoint JSON (or Azure Blob when configured); zero blockchain.',
      },
      {
        name: 'Just-In-Time (JIT) Access Requests & Approval Workflow',
        status: 'Implemented',
        detail:
          'SQLite-persisted access_requests queue allowing requesters to justify time-bound access and HOD/Super Admin to approve (creating an active grant) or reject.',
      },
      {
        name: 'Deterministic DENY-Spike & Integrity Anomaly Summary',
        status: 'Implemented',
        detail:
          'Computes 15-minute DENY bursts per actor, integrity tamper events, and anchor mismatches directly from SQLite audit logs.',
      },
      {
        name: 'Tamper-Evident Hash-Chained Audit Logs & Split-Screen Demo',
        status: 'Implemented',
        detail:
          'Chronological SHA-256 prev_hash -> entry_hash ledger plus dual-session side-by-side revocation verification.',
      },
      {
        name: 'Upload Signature, Active-Script Block & Antivirus Hook',
        status: 'Partially Implemented',
        detail:
          'Blocks non-PDF files and active /JavaScript, /JS, /Launch, /EmbeddedFile PDF tokens; external ClamAV/Defender malware engine is Proposed.',
      },
      {
        name: 'Confidential Preview Watermark Metadata & Viewer Overlay',
        status: 'Partially Implemented',
        detail:
          'Emits requester/timestamp X-Watermark headers and renders a confidential viewer overlay while preserving bit-exact SHA-256 PDF bytes; binary PDF stream stamping is Proposed.',
      },
      {
        name: 'Document Version Tracking',
        status: 'Partially Implemented',
        detail:
          'Tracks version numbers in SQLite and supports uploading replacement versions; multi-revision diff history is Proposed.',
      },
      {
        name: 'Live Azure Immutable Blob Retention Lock',
        status: 'Proposed',
        detail:
          'Proposed / Env-Gated: requires an Azure Storage container with version-level WORM immutability policy and live Azure credentials.',
      },
      {
        name: 'External AI Document Classification',
        status: 'Proposed',
        detail:
          'Explicitly OFF by default; local deterministic rule-based DLP runs on-server so confidential documents never leave campus storage.',
      },
      {
        name: 'Automated 12-Scenario In-App Security Test Runner',
        status: 'Proposed',
        detail:
          'Post-hackathon enhancement for one-click adversarial verification inside the UI.',
      },
    ];

    const overallHealthy = dbHealthy && storageHealth.healthy;

    res.status(overallHealthy ? 200 : 503).json({
      status: overallHealthy ? 'ok' : 'degraded',
      service: 'UniVault API',
      tagline: 'Trust Nothing. Verify Every Access.',
      timestamp: new Date().toISOString(),
      checks: {
        database: {
          healthy: dbHealthy,
          engine: 'sqlite',
          foreignKeysEnabled,
          tables,
          ...(dbError ? { error: dbError } : {}),
        },
        storage: storageHealth,
        auditAnchoring: anchorStatus,
        classificationIntegrity: {
          mode: classificationHashMode,
          hmacKeyConfigured: classificationHashMode === 'hmac-sha256',
        },
      },
      capabilities,
    });
  } catch (error) {
    next(error);
  }
});

export { healthRouter };
