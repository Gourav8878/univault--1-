# UniVault
**"Trust Nothing. Verify Every Access."**

Zero-Trust Campus Document Exchange (Hackathon Problem Statement 07 — PS 07).

---

## Capability Status Summary

| Capability | Status | Scope & Notes |
| --- | --- | --- |
| Zero-Trust `HttpOnly` Cookie Auth & Session Revocation | **Implemented** | `bcryptjs` password verification, `SESSION_SECRET` HMAC-SHA256 hashed session tokens in SQLite, `SameSite=None; Secure; Partitioned` in HTTPS/iframe contexts (`SameSite=Lax` on local HTTP), origin checks on mutating routes, and instant logout revocation. |
| Centralized RBAC + ABAC Policy Decision Point | **Implemented** | Fresh SQLite evaluation per request for role policies, document classifications (`PUBLIC` / `INTERNAL` / `CONFIDENTIAL`), department isolation, and time-bound revocable grants. |
| `LocalPrivateStorage` (Isolated Filesystem) | **Implemented** | Default storage provider outside public web assets with path-traversal segment checks and server-generated UUID keys. |
| `AzureBlobStorage` (`@azure/storage-blob` + `DefaultAzureCredential`) | **Partially Implemented** | Implemented for private Azure Blob containers (`createIfNotExists` with private access, zero SAS URLs or public containers). Optional at startup; requires live Azure credentials only when `STORAGE_PROVIDER=azure`. |
| SHA-256 Upload & Pre-Stream Integrity Verification | **Implemented** | Computed on upload (`POST /api/documents`), verified before every view/download stream (`409 INTEGRITY_CHECK_FAILED` + audit log on mismatch), and verifiable on demand (`POST /api/documents/:id/verify-integrity`). |
| Tamper-Evident `classification_hash` | **Implemented** | Computes HMAC-SHA256 (when `CLASSIFICATION_HMAC_SECRET` is set) or deterministic canonical SHA-256 over `{documentId, departmentId, classification, version}`, verifies in PDP & integrity checks, and blocks tampered rows (`403 CLASSIFICATION_METADATA_TAMPERED`). |
| Local DLP, Rule-Based Classifier & Human HOD Approval | **Implemented** | Scans PDFs locally for `STUDENT_ID`, `EMAIL`, `PHONE_NUMBER`, `CONFIDENTIAL_KEYWORD`, `PRIVATE_KEY`, and `GOV_ID_FORMAT`; logs only pattern names/counts (never raw PII), suggests classification, and gates sharing until human HOD/Super Admin approval (`POST /api/documents/:id/approve-classification`). |
| Periodic Audit Anchoring (No Blockchain) | **Implemented** | Records periodic (`AUDIT_ANCHOR_INTERVAL_MINUTES=15`) and authorized manual (`POST /api/audit-logs/anchor`) checkpoints to SQLite `audit_anchors` and local checkpoint JSON (or Azure Blob when configured), verified against `audit_logs`. |
| Just-In-Time (JIT) Access Requests & Approval Workflow | **Implemented** | SQLite-persisted `access_requests` queue allowing users to submit time-bound requests with justification and HOD/Super Admin to approve (issuing an active grant transactionally) or reject. |
| Deterministic `DENY`-Spike & Integrity Anomaly Summary | **Implemented** | Computes 15-minute `DENY` bursts per actor, SHA-256 / classification tamper events, and anchor mismatches directly from `audit_logs`. |
| Tamper-Evident Hash-Chained Audit Logs | **Implemented** | Chronological SHA-256 `prev_hash -> entry_hash` ledger recording `ALLOW`, `DENY`, and `INFO` events. |
| Split-Screen Live Security Demo | **Implemented** | Side-by-side Faculty and HOD `HttpOnly` sessions executing real grant, view, revocation, and `403 GRANT_REVOKED` URL replay checks. |
| Upload Signature, Active-Script Block & Antivirus Hook | **Partially Implemented** | Validates `%PDF-` signature and blocks active `/JavaScript`, `/JS`, `/Launch`, and `/EmbeddedFile` PDF tokens; external ClamAV/Defender AV scanning is **Proposed**. |
| Confidential Preview Watermark Metadata & Viewer Overlay | **Partially Implemented** | Emits `X-Watermark-Text` / `X-Watermark-Applied` headers and renders a confidential viewer overlay while keeping PDF bytes bit-exact for SHA-256 verification; binary PDF stream stamping is **Proposed**. |
| Document Version Tracking | **Partially Implemented** | Tracks `version` in SQLite and supports uploading replacement versions (`POST /api/documents/:id/version`); multi-revision diff history is **Proposed**. |
| Live Azure Immutable Blob Retention Lock | **Proposed** | **Proposed / Env-Gated**: requires a live Azure Storage account configured with container/version-level WORM immutability policies. |
| External AI Document Classification | **Proposed** | Explicitly **OFF** by default so confidential documents are never transmitted outside UniVault; deterministic local DLP runs on-server. |
| Automated 12-Scenario In-App Security Test Runner | **Proposed** | Post-hackathon enhancement for one-click adversarial verification inside the UI. |

---

## Local Setup (`STORAGE_PROVIDER=local`)

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   ```
   Defaults to `STORAGE_PROVIDER=local`, `LOCAL_STORAGE_PATH=./storage/private`, and `AUDIT_ANCHOR_INTERVAL_MINUTES=15`. Azure credentials are **not** required in local mode. Set strong random values for `SESSION_SECRET` and `CLASSIFICATION_HMAC_SECRET` in production.

3. **Seed demo data (idempotent)**
   ```bash
   npm run seed
   ```
   Seeds:
   - **Departments:** Computer Science (`CSE`), Electronics (`ECE`), Mechanical Engineering (`ME`), Civil Engineering (`CE`), Administration (`ADMIN`)
   - **Demo Users** (local demo password: `UniVault@Demo123`):
     - `admin@univault.edu` (`SUPER_ADMIN`, Administration)
     - `hod.cse@univault.edu` (`HOD`, Computer Science)
     - `faculty.cse@univault.edu` (`FACULTY`, Computer Science)
     - `faculty.ece@univault.edu` (`FACULTY`, Electronics)
   - **Documents:** `CSE Confidential Examination Paper.pdf`, `CSE Internal Academic Report.pdf`, `ECE Department Report.pdf`, `University Public Notice.pdf`

4. **Type-check, build, and run**
   ```bash
   # Type-check TypeScript
   npm run typecheck

   # Development (Express API + Vite middleware on port 3000)
   npm run dev

   # Production build & start (Node 22+ runs server.ts directly)
   npm run lint
   npm run build
   NODE_ENV=production npm start
   ```

---

## Optional Private Azure Blob Storage (`STORAGE_PROVIDER=azure`)

Set these server-only variables in `.env` (never expose them to the frontend and keep the Azure container access level **Private**):

```dotenv
STORAGE_PROVIDER=azure
AZURE_STORAGE_CONTAINER_NAME=univault-private-docs
# Option A: Managed Identity / Entra ID via DefaultAzureCredential
AZURE_STORAGE_ACCOUNT_NAME=yourstorageaccountname
# Option B: Connection String (server-only)
AZURE_STORAGE_CONNECTION_STRING=
```

---

## Safely Resetting Demo Data

```bash
npm run reset-demo
```
Clears demo SQLite tables (`audit_anchors`, `audit_logs`, `sessions`, `access_requests`, `access_grants`, `documents`, `policies`, `users`, `departments`), removes the local anchor checkpoint file and private storage objects, then cleanly re-seeds baseline demo records.
