import type Database from 'better-sqlite3';

function ensureDocumentColumn(
  db: Database.Database,
  columnName: string,
  alterSql: string
): void {
  const columns = db.prepare('PRAGMA table_info(documents)').all() as Array<{ name: string }>;
  if (!columns.some((col) => col.name === columnName)) {
    db.exec(alterSql);
  }
}

export function initializeSchema(db: Database.Database): void {
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS departments (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      code TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('SUPER_ADMIN', 'HOD', 'FACULTY')),
      department_id TEXT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
      active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      file_name TEXT NOT NULL,
      storage_path TEXT NOT NULL UNIQUE,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL CHECK (file_size >= 0),
      department_id TEXT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
      classification TEXT NOT NULL CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL')),
      uploaded_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      created_at TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
      suggested_classification TEXT NOT NULL DEFAULT 'PUBLIC' CHECK (suggested_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL')),
      dlp_findings_json TEXT NOT NULL DEFAULT '[]',
      classification_status TEXT NOT NULL DEFAULT 'APPROVED' CHECK (classification_status IN ('PENDING_APPROVAL', 'APPROVED')),
      classification_approved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      classification_approved_at TEXT,
      classification_hash TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS access_grants (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      revoked_by TEXT REFERENCES users(id) ON DELETE RESTRICT,
      status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL UNIQUE CHECK (role IN ('SUPER_ADMIN', 'HOD', 'FACULTY')),
      allowed_classifications TEXT NOT NULL,
      department_restrictions TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      session_token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
      target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'INFO')),
      denial_reason TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL UNIQUE,
      timestamp TEXT NOT NULL,
      request_id TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_anchors (
      anchor_id TEXT PRIMARY KEY,
      anchored_at TEXT NOT NULL,
      head_entry_hash TEXT NOT NULL,
      chain_length INTEGER NOT NULL CHECK (chain_length >= 0),
      target_mode TEXT NOT NULL CHECK (target_mode IN ('local-checkpoint', 'azure-blob-configured')),
      checkpoint_ref TEXT NOT NULL,
      triggered_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      chain_valid INTEGER NOT NULL DEFAULT 1 CHECK (chain_valid IN (0, 1))
    );

    CREATE TABLE IF NOT EXISTS access_requests (
      id TEXT PRIMARY KEY,
      requester_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      requested_duration_minutes INTEGER NOT NULL CHECK (requested_duration_minutes >= 5 AND requested_duration_minutes <= 10080),
      justification TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
      reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TEXT,
      review_note TEXT,
      grant_id TEXT REFERENCES access_grants(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Safe migrations for pre-existing SQLite databases
  ensureDocumentColumn(
    db,
    'suggested_classification',
    "ALTER TABLE documents ADD COLUMN suggested_classification TEXT NOT NULL DEFAULT 'PUBLIC' CHECK (suggested_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL'))"
  );
  ensureDocumentColumn(
    db,
    'dlp_findings_json',
    "ALTER TABLE documents ADD COLUMN dlp_findings_json TEXT NOT NULL DEFAULT '[]'"
  );
  ensureDocumentColumn(
    db,
    'classification_status',
    "ALTER TABLE documents ADD COLUMN classification_status TEXT NOT NULL DEFAULT 'APPROVED' CHECK (classification_status IN ('PENDING_APPROVAL', 'APPROVED'))"
  );
  ensureDocumentColumn(
    db,
    'classification_approved_by',
    'ALTER TABLE documents ADD COLUMN classification_approved_by TEXT REFERENCES users(id) ON DELETE SET NULL'
  );
  ensureDocumentColumn(
    db,
    'classification_approved_at',
    'ALTER TABLE documents ADD COLUMN classification_approved_at TEXT'
  );
  ensureDocumentColumn(
    db,
    'classification_hash',
    "ALTER TABLE documents ADD COLUMN classification_hash TEXT NOT NULL DEFAULT ''"
  );

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_department_id ON users(department_id);
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

    CREATE INDEX IF NOT EXISTS idx_documents_department_id ON documents(department_id);
    CREATE INDEX IF NOT EXISTS idx_documents_classification ON documents(classification);
    CREATE INDEX IF NOT EXISTS idx_documents_uploaded_by ON documents(uploaded_by);
    CREATE INDEX IF NOT EXISTS idx_documents_classification_status ON documents(classification_status);

    CREATE INDEX IF NOT EXISTS idx_access_grants_lookup ON access_grants(user_id, document_id, status);
    CREATE INDEX IF NOT EXISTS idx_access_grants_expires_at ON access_grants(expires_at);

    CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id, document_id);

    CREATE INDEX IF NOT EXISTS idx_policies_role_active ON policies(role, active);

    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_document_id ON audit_logs(document_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);

    CREATE INDEX IF NOT EXISTS idx_audit_anchors_at ON audit_anchors(anchored_at);
  `);
}
