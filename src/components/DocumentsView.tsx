import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, Download, Eye, FileUp, Search, ShieldCheck, Upload, X } from 'lucide-react';
import {
  ApiError,
  approveDocumentClassification,
  classificationTextTone,
  fetchDepartments,
  fetchDocuments,
  fetchProtectedDocumentBlob,
  fetchSystemHealth,
  formatBytes,
  uploadDocument,
  uploadDocumentVersion,
  verifyDocumentIntegrity,
} from '../api/client';
import type { AuthUser } from '../types/auth';
import type { DepartmentItem, DocumentClassification, DocumentItem, PolicyCheckStep } from '../types/domain';

interface DocumentsViewProps {
  user: AuthUser;
}

interface ActionFeedback {
  type: 'allow' | 'deny' | 'error';
  title: string;
  detail: string;
  checks?: PolicyCheckStep[];
  requestId?: string;
}

export function DocumentsView({ user }: DocumentsViewProps) {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [departments, setDepartments] = useState<DepartmentItem[]>([]);
  const [storageProviderName, setStorageProviderName] = useState<'local' | 'azure'>('local');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('');
  const [onlyAllowed, setOnlyAllowed] = useState(false);
  const [feedback, setFeedback] = useState<ActionFeedback | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  // Upload form state (SUPER_ADMIN and HOD)
  const canUpload = user.role === 'SUPER_ADMIN' || user.role === 'HOD';
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadDisplayName, setUploadDisplayName] = useState('');
  const [uploadClassification, setUploadClassification] =
    useState<DocumentClassification>('INTERNAL');
  const [uploadDepartmentId, setUploadDepartmentId] = useState(user.departmentId);
  const [uploading, setUploading] = useState(false);

  // Version update modal state
  const [versionTarget, setVersionTarget] = useState<DocumentItem | null>(null);
  const [versionFile, setVersionFile] = useState<File | null>(null);
  const [uploadingVersion, setUploadingVersion] = useState(false);

  // Human HOD/Admin classification approval modal state
  const [approvalTarget, setApprovalTarget] = useState<DocumentItem | null>(null);
  const [approvalClassification, setApprovalClassification] =
    useState<DocumentClassification>('CONFIDENTIAL');
  const [approvalNote, setApprovalNote] = useState('');
  const [approvingClassification, setApprovingClassification] = useState(false);

  // Inline PDF Preview Modal state
  const [previewDoc, setPreviewDoc] = useState<{
    fileName: string;
    classification: DocumentClassification;
    blobUrl: string;
    sha256: string | null;
    watermarkText: string | null;
    watermarkApplied: string | null;
  } | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [docs, depts, healthRes] = await Promise.all([
        fetchDocuments({
          search,
          departmentId: departmentFilter,
          classification: classificationFilter,
          onlyAllowed,
        }),
        fetchDepartments(),
        fetchSystemHealth(),
      ]);
      setDocuments(docs);
      setDepartments(depts);
      setStorageProviderName(healthRes.data.checks.storage.provider);
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Failed to load documents',
        detail: err instanceof Error ? err.message : 'Unexpected error loading document catalog.',
      });
    } finally {
      setLoading(false);
    }
  }, [search, departmentFilter, classificationFilter, onlyAllowed]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  useEffect(() => {
    return () => {
      if (previewDoc?.blobUrl) {
        URL.revokeObjectURL(previewDoc.blobUrl);
      }
    };
  }, [previewDoc]);

  const handleClosePreview = () => {
    if (previewDoc?.blobUrl) {
      URL.revokeObjectURL(previewDoc.blobUrl);
    }
    setPreviewDoc(null);
  };

  const handleOpenDocument = async (doc: DocumentItem, mode: 'view' | 'download') => {
    setFeedback(null);
    try {
      const result = await fetchProtectedDocumentBlob(doc.id, mode);

      if (mode === 'view') {
        if (previewDoc?.blobUrl) {
          URL.revokeObjectURL(previewDoc.blobUrl);
        }
        const blobUrl = URL.createObjectURL(result.blob);
        setPreviewDoc({
          fileName: doc.fileName,
          classification: doc.classification,
          blobUrl,
          sha256: result.sha256,
          watermarkText: result.watermarkText,
          watermarkApplied: result.watermarkApplied,
        });
      } else {
        const blobUrl = URL.createObjectURL(result.blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = doc.fileName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
      }

      setFeedback({
        type: 'allow',
        title: `ALLOW · ${mode === 'view' ? 'Inline View' : 'Attachment Download'} Verified`,
        detail: `Streamed "${doc.fileName}" (v${doc.version}) from ${storageProviderName} storage after PDP authorization and SHA-256 verification (${result.sha256?.slice(0, 12) ?? 'ok'}...).${result.watermarkApplied === 'viewer-overlay-and-headers' ? ' Confidential watermark applied.' : ''}`,
        requestId: result.requestId ?? undefined,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'deny',
          title: `DENY (HTTP ${err.status}) · ${err.code}`,
          detail: err.message,
          checks: err.checks,
          requestId: err.requestId,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Stream Failed',
          detail: err instanceof Error ? err.message : 'Unable to stream document.',
        });
      }
    }
  };

  const handleVerifyIntegrity = async (doc: DocumentItem) => {
    setVerifyingId(doc.id);
    setFeedback(null);
    try {
      const result = await verifyDocumentIntegrity(doc.id);
      setFeedback({
        type: 'allow',
        title: `SHA-256 & Classification Hash Verified · v${result.version}`,
        detail: `Bytes retrieved from "${result.provider}" matched sha256_hash (${result.sha256.slice(0, 16)}...) and classification_hash verified (${result.classificationHash?.slice(0, 12) ?? 'ok'}...).`,
        requestId: result.requestId,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'deny',
          title: `Integrity / Access Check Failed (HTTP ${err.status}) · ${err.code}`,
          detail: err.message,
          checks: err.checks,
          requestId: err.requestId,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Verification Error',
          detail: err instanceof Error ? err.message : 'Unable to verify document integrity.',
        });
      }
    } finally {
      setVerifyingId(null);
    }
  };

  const handleUploadSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!uploadFile) {
      setFeedback({
        type: 'error',
        title: 'No file selected',
        detail: 'Choose a PDF file before uploading.',
      });
      return;
    }

    setUploading(true);
    setFeedback(null);

    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      formData.append('classification', uploadClassification);
      formData.append(
        'departmentId',
        user.role === 'HOD' ? user.departmentId : uploadDepartmentId
      );
      if (uploadDisplayName.trim()) {
        formData.append('fileName', uploadDisplayName.trim());
      }

      const uploaded = await uploadDocument(formData);
      setUploadFile(null);
      setUploadDisplayName('');
      const fileInput = document.getElementById('pdf-upload-input') as HTMLInputElement | null;
      if (fileInput) fileInput.value = '';

      const insp = uploaded.inspection;
      const dlpCountsSummary =
        insp && insp.dlpFindings.length > 0
          ? insp.dlpFindings.map((f) => `${f.pattern}(${f.count})`).join(', ')
          : 'none';
      const dlpNote = insp
        ? ` Local DLP: ${insp.dlpStatus} [${dlpCountsSummary}] · Suggested: ${insp.suggestedClassification} · Status: ${uploaded.document.classificationStatus} · External AI Classifier: OFF (Proposed).${insp.dlpWarning ? ` ${insp.dlpWarning}` : ''}`
        : '';

      setFeedback({
        type: 'allow',
        title: `Document Uploaded to ${storageProviderName} Private Storage`,
        detail: `PDF validated (%PDF-), SHA-256 hashed, classification_hash computed (${uploaded.document.classificationHash.slice(0, 12)}...), and audited.${dlpNote}`,
      });
      await loadData();
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'deny',
          title: `Upload Blocked (HTTP ${err.status}) · ${err.code}`,
          detail: err.message,
          checks: err.checks,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Upload Failed',
          detail: err instanceof Error ? err.message : 'Unexpected upload error.',
        });
      }
    } finally {
      setUploading(false);
    }
  };

  const handleVersionSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!versionTarget || !versionFile) return;

    setUploadingVersion(true);
    setFeedback(null);
    try {
      const formData = new FormData();
      formData.append('file', versionFile);
      const updated = await uploadDocumentVersion(versionTarget.id, formData);
      setVersionTarget(null);
      setVersionFile(null);
      const insp = updated.inspection;
      const dlpCountsSummary =
        insp && insp.dlpFindings.length > 0
          ? insp.dlpFindings.map((f) => `${f.pattern}(${f.count})`).join(', ')
          : 'none';
      const dlpNote = insp
        ? ` Local DLP: ${insp.dlpStatus} [${dlpCountsSummary}] · Suggested: ${insp.suggestedClassification} · External AI Classifier: OFF (Proposed).`
        : '';
      setFeedback({
        type: 'allow',
        title: `Updated "${updated.fileName}" to v${updated.version}`,
        detail: `New SHA-256 hash stored (${updated.sha256Hash.slice(0, 16)}...) and audited.${dlpNote}`,
      });
      await loadData();
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'deny',
          title: `Version Upload Blocked (HTTP ${err.status}) · ${err.code}`,
          detail: err.message,
          checks: err.checks,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Version Upload Failed',
          detail: err instanceof Error ? err.message : 'Unable to upload new version.',
        });
      }
    } finally {
      setUploadingVersion(false);
    }
  };

  const handleApprovalSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!approvalTarget) return;

    setApprovingClassification(true);
    setFeedback(null);
    try {
      const res = await approveDocumentClassification(approvalTarget.id, {
        classification: approvalClassification,
        note: approvalNote.trim() || undefined,
      });
      setApprovalTarget(null);
      setApprovalNote('');
      setFeedback({
        type: 'allow',
        title: `Classification Approved · ${res.document.classification}`,
        detail: `Human steward (${user.name}) approved "${res.document.fileName}" as ${res.document.classification} and sealed classification_hash (${res.document.classificationHash.slice(0, 12)}...).`,
        requestId: res.requestId,
      });
      await loadData();
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'deny',
          title: `Classification Approval Blocked (HTTP ${err.status}) · ${err.code}`,
          detail: err.message,
          checks: err.checks,
          requestId: err.requestId,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Approval Failed',
          detail: err instanceof Error ? err.message : 'Unable to approve document classification.',
        });
      }
    } finally {
      setApprovingClassification(false);
    }
  };

  const canUploadNewVersion = (doc: DocumentItem) =>
    user.role === 'SUPER_ADMIN' || (user.role === 'HOD' && user.departmentId === doc.departmentId);

  return (
    <div className="space-y-6">
      {canUpload && (
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div>
              <h3 className="text-base font-semibold text-[#0B1F3A]">
                Upload Protected PDF Document
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                Stored with a server-generated UUID key via{' '}
                <code className="font-mono">{storageProviderName}</code> · Deterministic local DLP
                scans pattern counts only (zero raw PII logged).
              </p>
            </div>
            <span className="text-xs font-mono text-slate-500">
              Max 10 MB · PDF Only · External AI Classifier: OFF (Proposed)
            </span>
          </div>

          <form
            className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end"
            onSubmit={(e) => void handleUploadSubmit(e)}
          >
            <div className="md:col-span-4">
              <label
                htmlFor="pdf-upload-input"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                PDF File
              </label>
              <input
                id="pdf-upload-input"
                type="file"
                accept="application/pdf,.pdf"
                onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
                required
                className="w-full text-xs text-slate-700 file:mr-3 file:py-2 file:px-3 file:rounded-md file:border file:border-slate-300 file:bg-slate-50 file:text-xs file:font-semibold file:text-[#12315C] hover:file:bg-slate-100"
              />
            </div>

            <div className="md:col-span-3">
              <label
                htmlFor="upload-display-name"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Document Title (Optional)
              </label>
              <input
                id="upload-display-name"
                type="text"
                placeholder="e.g. CS502 Audit Policy.pdf"
                value={uploadDisplayName}
                onChange={(e) => setUploadDisplayName(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>

            <div className="md:col-span-2">
              <label
                htmlFor="upload-classification"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Classification
              </label>
              <select
                id="upload-classification"
                value={uploadClassification}
                onChange={(e) => setUploadClassification(e.target.value as DocumentClassification)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              >
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label
                htmlFor="upload-department"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Department
              </label>
              <select
                id="upload-department"
                value={user.role === 'HOD' ? user.departmentId : uploadDepartmentId}
                onChange={(e) => setUploadDepartmentId(e.target.value)}
                disabled={user.role === 'HOD'}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white disabled:bg-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
              >
                {departments.map((dept) => (
                  <option key={dept.id} value={dept.id}>
                    {dept.code} — {dept.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-1">
              <button
                type="submit"
                disabled={uploading}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md disabled:opacity-60 whitespace-nowrap cursor-pointer"
              >
                <FileUp className="w-4 h-4 shrink-0" />
                <span>{uploading ? '...' : 'Upload'}</span>
              </button>
            </div>
          </form>
        </section>
      )}

      {feedback && (
        <section
          className={`p-4 rounded-lg border text-sm ${
            feedback.type === 'allow'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
          role="status"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <strong className="font-semibold">{feedback.title}</strong>
            {feedback.requestId && (
              <span className="font-mono text-xs opacity-80">Request: {feedback.requestId}</span>
            )}
          </div>
          <p className="mt-1">{feedback.detail}</p>
          {feedback.checks && feedback.checks.length > 0 && (
            <ul className="mt-2 pt-2 border-t border-current/15 space-y-1 text-xs font-mono">
              {feedback.checks.map((step, idx) => (
                <li key={`${step.rule}-${idx}`}>
                  [{step.passed ? 'PASS' : 'FAIL'}] {step.rule}: {step.code} — {step.detail}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-[#0B1F3A]">Campus Document Catalog</h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Active storage provider: <code className="font-mono">{storageProviderName}</code> ·
              Every view, download, and SHA-256 verification runs through the server PDP.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search title or dept..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md w-48 focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>

            <select
              aria-label="Filter by department"
              value={departmentFilter}
              onChange={(e) => setDepartmentFilter(e.target.value)}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-md bg-white"
            >
              <option value="">All Departments</option>
              {departments.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.code} — {d.name}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by classification"
              value={classificationFilter}
              onChange={(e) => setClassificationFilter(e.target.value)}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-md bg-white"
            >
              <option value="">All Classifications</option>
              <option value="PUBLIC">PUBLIC</option>
              <option value="INTERNAL">INTERNAL</option>
              <option value="CONFIDENTIAL">CONFIDENTIAL</option>
            </select>

            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              <button
                type="button"
                onClick={() => setOnlyAllowed(false)}
                className={`px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap shrink-0 cursor-pointer ${
                  !onlyAllowed ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                }`}
              >
                All ({documents.length})
              </button>
              <button
                type="button"
                onClick={() => setOnlyAllowed(true)}
                className={`px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap shrink-0 cursor-pointer ${
                  onlyAllowed ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                }`}
              >
                Permitted Only
              </button>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="py-10 text-center text-sm text-slate-500">
            Evaluating document policies...
          </div>
        ) : documents.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            No documents match the selected filters.
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="py-3 pr-4 font-semibold">Document</th>
                  <th className="py-3 px-4 font-semibold">Department</th>
                  <th className="py-3 px-4 font-semibold">Classification</th>
                  <th className="py-3 px-4 font-semibold text-right">Size</th>
                  <th className="py-3 px-4 font-semibold">PDP Decision</th>
                  <th className="py-3 pl-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {documents.map((doc) => (
                  <tr key={doc.id} className="hover:bg-slate-50/70">
                    <td className="py-3.5 pr-4">
                      <div className="font-medium text-[#0B1F3A]">{doc.fileName}</div>
                      <div className="text-xs text-slate-500 font-mono tabular-nums mt-0.5">
                        v{doc.version} · SHA-256 {doc.sha256Hash.slice(0, 12)}... · ClsHash{' '}
                        {doc.classificationHash ? doc.classificationHash.slice(0, 10) : 'missing'}...
                        {!doc.classificationHashValid && (
                          <span className="text-red-700 font-semibold ml-1.5">
                            [TAMPERED]
                          </span>
                        )}
                      </div>
                      {doc.dlpFindings.length > 0 && (
                        <div className="text-[11px] font-mono text-amber-800 mt-0.5">
                          Local DLP:{' '}
                          {doc.dlpFindings.map((f) => `${f.pattern}(${f.count})`).join(', ')} ·
                          Suggested: {doc.suggestedClassification}
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-700 whitespace-nowrap">
                      {doc.departmentCode} · {doc.departmentName}
                    </td>
                    <td className="py-3.5 px-4 text-xs whitespace-nowrap">
                      <div className={classificationTextTone(doc.classification)}>
                        {doc.classification}
                      </div>
                      <div className="text-[11px] mt-0.5">
                        {doc.classificationStatus === 'PENDING_APPROVAL' ? (
                          <span className="text-amber-700 font-semibold">
                            Pending HOD Approval
                          </span>
                        ) : (
                          <span className="text-slate-500">
                            Approved{doc.classificationApprovedByName ? ` · ${doc.classificationApprovedByName}` : ''}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right font-mono tabular-nums text-xs text-slate-600 whitespace-nowrap">
                      {formatBytes(doc.fileSize)}
                    </td>
                    <td className="py-3.5 px-4">
                      {doc.access.allowed ? (
                        <div className="text-xs">
                          <span className="font-semibold text-emerald-700">ALLOW</span>
                          {doc.access.grantId && (
                            <span className="text-slate-500 ml-1.5">
                              (Grant expires{' '}
                              {new Date(doc.access.grantExpiresAt!).toLocaleDateString()})
                            </span>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs">
                          <span className="font-semibold text-red-700">DENY</span>
                          <span className="font-mono text-red-600 ml-1.5">
                            {doc.access.reason}
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 pl-4 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => void handleOpenDocument(doc, 'view')}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[#12315C] bg-blue-50 border border-blue-200 rounded hover:bg-blue-100 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>View</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleOpenDocument(doc, 'download')}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download</span>
                        </button>
                        <button
                          type="button"
                          disabled={verifyingId === doc.id}
                          onClick={() => void handleVerifyIntegrity(doc)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-emerald-800 bg-emerald-50 border border-emerald-200 rounded hover:bg-emerald-100 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>{verifyingId === doc.id ? 'Checking' : 'Verify SHA-256'}</span>
                        </button>
                        {canUploadNewVersion(doc) && (
                          <button
                            type="button"
                            onClick={() => {
                              setApprovalTarget(doc);
                              setApprovalClassification(doc.suggestedClassification);
                              setApprovalNote('');
                            }}
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap shrink-0 cursor-pointer ${
                              doc.classificationStatus === 'PENDING_APPROVAL'
                                ? 'text-amber-900 bg-amber-50 border border-amber-300 hover:bg-amber-100'
                                : 'text-slate-700 bg-white border border-slate-300 hover:bg-slate-50'
                            }`}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>
                              {doc.classificationStatus === 'PENDING_APPROVAL'
                                ? 'Approve Cls'
                                : 'Review Cls'}
                            </span>
                          </button>
                        )}
                        {canUploadNewVersion(doc) && (
                          <button
                            type="button"
                            onClick={() => {
                              setVersionTarget(doc);
                              setVersionFile(null);
                            }}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-300 rounded hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            <Upload className="w-3.5 h-3.5" />
                            <span>New Version</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {approvalTarget && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-label={`Approve classification for ${approvalTarget.fileName}`}
        >
          <div className="bg-white border border-slate-200 rounded-lg w-full max-w-md p-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <h4 className="text-base font-semibold text-[#0B1F3A]">
                Human HOD / Admin Classification Approval
              </h4>
              <button
                type="button"
                onClick={() => setApprovalTarget(null)}
                className="p-1 text-slate-500 hover:text-slate-900 cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="text-xs text-slate-600 mt-3 space-y-1">
              <p>
                Document: <strong>{approvalTarget.fileName}</strong>
              </p>
              <p>
                Current: <span className="font-mono font-semibold">{approvalTarget.classification}</span>{' '}
                · Local DLP Suggested:{' '}
                <span className="font-mono font-semibold">{approvalTarget.suggestedClassification}</span>
              </p>
              {approvalTarget.dlpFindings.length > 0 && (
                <p className="font-mono text-amber-800">
                  DLP Counts:{' '}
                  {approvalTarget.dlpFindings.map((f) => `${f.pattern}(${f.count})`).join(', ')}
                </p>
              )}
              <p className="text-slate-500">
                External AI classification is OFF (Proposed). Confirmation seals a new{' '}
                <code className="font-mono">classification_hash</code>.
              </p>
            </div>
            <form className="mt-4 space-y-4" onSubmit={(e) => void handleApprovalSubmit(e)}>
              <div>
                <label
                  htmlFor="approve-classification-select"
                  className="block text-xs font-medium text-slate-700 mb-1"
                >
                  Final Approved Classification
                </label>
                <select
                  id="approve-classification-select"
                  value={approvalClassification}
                  onChange={(e) =>
                    setApprovalClassification(e.target.value as DocumentClassification)
                  }
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  <option value="PUBLIC">PUBLIC</option>
                  <option value="INTERNAL">INTERNAL</option>
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                </select>
              </div>
              <div>
                <label
                  htmlFor="approve-classification-note"
                  className="block text-xs font-medium text-slate-700 mb-1"
                >
                  Reviewer Note (Optional)
                </label>
                <input
                  id="approve-classification-note"
                  type="text"
                  maxLength={300}
                  placeholder="e.g. Verified student IDs require CONFIDENTIAL isolation"
                  value={approvalNote}
                  onChange={(e) => setApprovalNote(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setApprovalTarget(null)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-700 border border-slate-300 rounded-md hover:bg-slate-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={approvingClassification}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md disabled:opacity-60 cursor-pointer"
                >
                  {approvingClassification ? 'Approving...' : 'Approve & Seal Hash'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {versionTarget && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-label={`Upload new version for ${versionTarget.fileName}`}
        >
          <div className="bg-white border border-slate-200 rounded-lg w-full max-w-md p-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <h4 className="text-base font-semibold text-[#0B1F3A]">
                Upload Version v{versionTarget.version + 1}
              </h4>
              <button
                type="button"
                onClick={() => setVersionTarget(null)}
                className="p-1 text-slate-500 hover:text-slate-900 cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-600 mt-3">
              Target document: <strong>{versionTarget.fileName}</strong> (currently v
              {versionTarget.version})
            </p>
            <form className="mt-4 space-y-4" onSubmit={(e) => void handleVersionSubmit(e)}>
              <div>
                <label
                  htmlFor="version-pdf-input"
                  className="block text-xs font-medium text-slate-700 mb-1"
                >
                  Replacement PDF File
                </label>
                <input
                  id="version-pdf-input"
                  type="file"
                  accept="application/pdf,.pdf"
                  onChange={(e) => setVersionFile(e.target.files?.[0] ?? null)}
                  required
                  className="w-full text-xs text-slate-700 file:mr-3 file:py-2 file:px-3 file:rounded-md file:border file:border-slate-300 file:bg-slate-50 file:text-xs file:font-semibold file:text-[#12315C]"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setVersionTarget(null)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-700 border border-slate-300 rounded-md hover:bg-slate-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploadingVersion || !versionFile}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md disabled:opacity-60 cursor-pointer"
                >
                  {uploadingVersion ? 'Uploading...' : `Commit v${versionTarget.version + 1}`}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {previewDoc && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-label={`Preview ${previewDoc.fileName}`}
        >
          <div className="bg-white border border-slate-200 rounded-lg w-full max-w-4xl h-[82vh] flex flex-col overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between gap-4">
              <div>
                <h4 className="text-sm font-semibold text-[#0B1F3A]">{previewDoc.fileName}</h4>
                <div className="text-xs font-mono text-slate-500 space-y-0.5 mt-0.5">
                  {previewDoc.sha256 && <p>Verified SHA-256: {previewDoc.sha256}</p>}
                  {previewDoc.watermarkText && (
                    <p className="text-red-700">
                      Session Watermark ({previewDoc.classification}): {previewDoc.watermarkText}
                    </p>
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={handleClosePreview}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 border border-slate-300 rounded hover:bg-slate-50 cursor-pointer shrink-0 whitespace-nowrap"
              >
                <X className="w-4 h-4" />
                <span>Close</span>
              </button>
            </div>
            <div className="relative flex-1 w-full bg-slate-100">
              <iframe
                title={previewDoc.fileName}
                src={previewDoc.blobUrl}
                className="w-full h-full bg-slate-100"
              />
              {previewDoc.watermarkApplied === 'viewer-overlay-and-headers' &&
                previewDoc.watermarkText && (
                  <div
                    aria-hidden="true"
                    className="pointer-events-none select-none absolute inset-x-0 bottom-3 flex justify-center px-4"
                  >
                    <span className="bg-[#0B1F3A]/85 text-white font-mono text-[11px] px-3 py-1 rounded">
                      {previewDoc.watermarkText}
                    </span>
                  </div>
                )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
