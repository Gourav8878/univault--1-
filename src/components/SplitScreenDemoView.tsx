import { useCallback, useEffect, useState } from 'react';
import { Ban, Eye, KeyRound, Play, RefreshCw, RotateCw } from 'lucide-react';
import {
  ApiError,
  createAccessGrant,
  fetchAuditLogs,
  fetchCurrentSession,
  fetchDocuments,
  fetchGrants,
  fetchProtectedDocumentBlob,
  loginWithCredentials,
  logoutSession,
  revokeAccessGrant,
} from '../api/client';
import type { AuthResponse } from '../types/auth';
import type {
  AccessGrantItem,
  AuditChainIntegrity,
  AuditLogItem,
  DocumentItem,
  PolicyCheckStep,
} from '../types/domain';

interface FacultyAttemptResult {
  httpStatus: number;
  decision: 'ALLOW' | 'DENY';
  code: string;
  message: string;
  requestId?: string | null;
  sha256?: string | null;
  watermarkText?: string | null;
  checks?: PolicyCheckStep[];
  timestamp: string;
}

export function SplitScreenDemoView() {
  // Left Pane: Real Faculty session via 'demo_faculty' HttpOnly cookie channel
  const [facultyEmail, setFacultyEmail] = useState('faculty.cse@univault.edu');
  const [facultyAuth, setFacultyAuth] = useState<AuthResponse | null>(null);
  const [facultyDocs, setFacultyDocs] = useState<DocumentItem[]>([]);
  const [selectedDocId, setSelectedDocId] = useState('doc-cse-exam-confidential');
  const [capturedDirectUrl, setCapturedDirectUrl] = useState<string>('');
  const [facultyResult, setFacultyResult] = useState<FacultyAttemptResult | null>(null);
  const [facultyBlobUrl, setFacultyBlobUrl] = useState<string | null>(null);
  const [facultyBusy, setFacultyBusy] = useState(false);

  // Right Pane: Real HOD/Admin session via 'demo_hod' HttpOnly cookie channel
  const [hodEmail, setHodEmail] = useState('hod.cse@univault.edu');
  const [hodAuth, setHodAuth] = useState<AuthResponse | null>(null);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [chainIntegrity, setChainIntegrity] = useState<AuditChainIntegrity | null>(null);
  const [hodMessage, setHodMessage] = useState<string | null>(null);
  const [hodBusy, setHodBusy] = useState(false);

  const hydrateChannels = useCallback(async () => {
    try {
      const fAuth = await fetchCurrentSession('demo_faculty');
      setFacultyAuth(fAuth);
      const docs = await fetchDocuments({}, 'demo_faculty');
      setFacultyDocs(docs);
    } catch {
      setFacultyAuth(null);
      setFacultyDocs([]);
    }

    try {
      const hAuth = await fetchCurrentSession('demo_hod');
      setHodAuth(hAuth);
      const [gList, auditRes] = await Promise.all([
        fetchGrants('demo_hod'),
        fetchAuditLogs({ limit: 8 }, 'demo_hod'),
      ]);
      setGrants(gList);
      setAuditLogs(auditRes.logs);
      setChainIntegrity(auditRes.chainIntegrity);
    } catch {
      setHodAuth(null);
      setGrants([]);
      setAuditLogs([]);
    }
  }, []);

  useEffect(() => {
    void hydrateChannels();
  }, [hydrateChannels]);

  useEffect(() => {
    return () => {
      if (facultyBlobUrl) URL.revokeObjectURL(facultyBlobUrl);
    };
  }, [facultyBlobUrl]);

  const handleFacultyLogin = async () => {
    setFacultyBusy(true);
    setFacultyResult(null);
    try {
      const auth = await loginWithCredentials(facultyEmail, 'UniVault@Demo123', 'demo_faculty');
      setFacultyAuth(auth);
      const docs = await fetchDocuments({}, 'demo_faculty');
      setFacultyDocs(docs);
    } catch (err) {
      setFacultyResult({
        httpStatus: err instanceof ApiError ? err.status : 500,
        decision: 'DENY',
        code: err instanceof ApiError ? err.code : 'LOGIN_FAILED',
        message: err instanceof Error ? err.message : 'Faculty sign-in failed.',
        timestamp: new Date().toISOString(),
      });
    } finally {
      setFacultyBusy(false);
    }
  };

  const handleFacultyLogout = async () => {
    await logoutSession('demo_faculty');
    setFacultyAuth(null);
    setFacultyDocs([]);
    setFacultyResult(null);
    if (facultyBlobUrl) {
      URL.revokeObjectURL(facultyBlobUrl);
      setFacultyBlobUrl(null);
    }
  };

  const handleHodLogin = async () => {
    setHodBusy(true);
    setHodMessage(null);
    try {
      const auth = await loginWithCredentials(hodEmail, 'UniVault@Demo123', 'demo_hod');
      setHodAuth(auth);
      const [gList, auditRes] = await Promise.all([
        fetchGrants('demo_hod'),
        fetchAuditLogs({ limit: 8 }, 'demo_hod'),
      ]);
      setGrants(gList);
      setAuditLogs(auditRes.logs);
      setChainIntegrity(auditRes.chainIntegrity);
      setHodMessage(`Signed in as ${auth.user.name}.`);
    } catch (err) {
      setHodMessage(err instanceof Error ? err.message : 'HOD sign-in failed.');
    } finally {
      setHodBusy(false);
    }
  };

  const refreshHodConsole = async () => {
    if (!hodAuth) return;
    const [gList, auditRes] = await Promise.all([
      fetchGrants('demo_hod'),
      fetchAuditLogs({ limit: 8 }, 'demo_hod'),
    ]);
    setGrants(gList);
    setAuditLogs(auditRes.logs);
    setChainIntegrity(auditRes.chainIntegrity);

    if (facultyAuth) {
      const docs = await fetchDocuments({}, 'demo_faculty');
      setFacultyDocs(docs);
    }
  };

  const executeFacultyOpenDocument = async (useDirectUrl: boolean) => {
    setFacultyBusy(true);
    const directPath = `/api/documents/${encodeURIComponent(selectedDocId)}/view?channel=demo_faculty`;
    if (!useDirectUrl) {
      setCapturedDirectUrl(directPath);
    }

    try {
      if (useDirectUrl && capturedDirectUrl) {
        const response = await fetch(capturedDirectUrl, {
          method: 'GET',
          credentials: 'include',
          headers: { Accept: 'application/pdf, application/json' },
        });
        const reqId = response.headers.get('X-Request-Id');

        if (!response.ok) {
          const payload = (await response.json()) as {
            error?: string;
            message?: string;
            checks?: PolicyCheckStep[];
          };
          if (facultyBlobUrl) {
            URL.revokeObjectURL(facultyBlobUrl);
            setFacultyBlobUrl(null);
          }
          setFacultyResult({
            httpStatus: response.status,
            decision: 'DENY',
            code: payload.error ?? 'ACCESS_DENIED',
            message: payload.message ?? 'Direct URL replay denied.',
            requestId: reqId,
            checks: payload.checks,
            timestamp: new Date().toISOString(),
          });
        } else {
          const blob = await response.blob();
          if (facultyBlobUrl) URL.revokeObjectURL(facultyBlobUrl);
          setFacultyBlobUrl(URL.createObjectURL(blob));
          setFacultyResult({
            httpStatus: response.status,
            decision: 'ALLOW',
            code: 'DIRECT_URL_ALLOW',
            message: `Direct URL replay permitted (${capturedDirectUrl}).`,
            requestId: reqId,
            sha256: response.headers.get('X-Document-Sha256'),
            watermarkText: response.headers.get('X-Watermark-Text'),
            timestamp: new Date().toISOString(),
          });
        }
      } else {
        const res = await fetchProtectedDocumentBlob(selectedDocId, 'view', 'demo_faculty');
        if (facultyBlobUrl) URL.revokeObjectURL(facultyBlobUrl);
        setFacultyBlobUrl(URL.createObjectURL(res.blob));
        setFacultyResult({
          httpStatus: res.status,
          decision: 'ALLOW',
          code: 'PDP_ALLOW',
          message: 'Document streamed after PDP approval and SHA-256 verification.',
          requestId: res.requestId,
          sha256: res.sha256,
          watermarkText: res.watermarkText,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err) {
      if (facultyBlobUrl) {
        URL.revokeObjectURL(facultyBlobUrl);
        setFacultyBlobUrl(null);
      }
      if (err instanceof ApiError) {
        setFacultyResult({
          httpStatus: err.status,
          decision: 'DENY',
          code: err.code,
          message: err.message,
          requestId: err.requestId,
          checks: err.checks,
          timestamp: new Date().toISOString(),
        });
      } else {
        setFacultyResult({
          httpStatus: 500,
          decision: 'DENY',
          code: 'REQUEST_ERROR',
          message: err instanceof Error ? err.message : 'Request failed.',
          timestamp: new Date().toISOString(),
        });
      }
    } finally {
      setFacultyBusy(false);
      await refreshHodConsole();
    }
  };

  const handleGrantFromHod = async () => {
    if (!facultyAuth || !hodAuth) return;
    setHodBusy(true);
    setHodMessage(null);
    try {
      const created = await createAccessGrant(
        {
          userId: facultyAuth.user.id,
          documentId: selectedDocId,
          durationMinutes: 15,
        },
        'demo_hod'
      );
      setHodMessage(`Issued 15-min grant (${created.id.slice(0, 8)}...) to ${facultyAuth.user.email}.`);
      await refreshHodConsole();
    } catch (err) {
      setHodMessage(err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to grant.');
    } finally {
      setHodBusy(false);
    }
  };

  const handleRevokeActiveForSelected = async () => {
    if (!facultyAuth || !hodAuth) return;
    const matchingActive = grants.find(
      (g) =>
        g.userId === facultyAuth.user.id &&
        g.documentId === selectedDocId &&
        g.status === 'ACTIVE'
    );
    if (!matchingActive) {
      setHodMessage('No active grant found for the selected Faculty user and document.');
      return;
    }

    setHodBusy(true);
    setHodMessage(null);
    try {
      await revokeAccessGrant(matchingActive.id, 'demo_hod');
      setHodMessage(
        `Revoked grant ${matchingActive.id.slice(0, 8)}... while Faculty remains logged in. Retry the Faculty URL now.`
      );
      await refreshHodConsole();
    } catch (err) {
      setHodMessage(err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to revoke.');
    } finally {
      setHodBusy(false);
    }
  };

  const activeMatchingGrant = facultyAuth
    ? grants.find(
        (g) =>
          g.userId === facultyAuth.user.id &&
          g.documentId === selectedDocId &&
          g.status === 'ACTIVE'
      )
    : undefined;

  return (
    <div className="space-y-6">
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-[#0B1F3A]">
          Live Split-Screen Zero-Trust Security Demo
        </h3>
        <p className="text-sm text-slate-600 mt-1">
          Runs two independent real <code className="font-mono text-xs">HttpOnly</code> sessions side
          by side against SQLite and the PDP: sign in both roles, issue a grant, open the
          confidential PDF as Faculty, revoke the grant as HOD while Faculty stays logged in, and
          replay the captured URL to verify immediate <code className="font-mono text-xs">HTTP 403 GRANT_REVOKED</code>.
        </p>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        {/* LEFT PANE: FACULTY SESSION */}
        <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-200">
            <div>
              <p className="text-xs font-semibold text-blue-700">Left Pane · Requester</p>
              <h4 className="text-base font-semibold text-[#0B1F3A]">Faculty Session</h4>
            </div>
            {facultyAuth ? (
              <button
                type="button"
                onClick={() => void handleFacultyLogout()}
                className="px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 border border-red-200 rounded hover:bg-red-100 cursor-pointer"
              >
                Sign Out Faculty
              </button>
            ) : null}
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[200px]">
              <label
                htmlFor="demo-faculty-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Faculty Account
              </label>
              <select
                id="demo-faculty-select"
                value={facultyEmail}
                onChange={(e) => setFacultyEmail(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                <option value="faculty.cse@univault.edu">CSE Faculty (faculty.cse@univault.edu)</option>
                <option value="faculty.ece@univault.edu">ECE Faculty (faculty.ece@univault.edu)</option>
              </select>
            </div>
            <button
              type="button"
              disabled={facultyBusy}
              onClick={() => void handleFacultyLogin()}
              className="px-4 py-2 text-sm font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md whitespace-nowrap shrink-0 cursor-pointer"
            >
              {facultyAuth ? 'Re-authenticate' : 'Sign In Faculty'}
            </button>
          </div>

          {facultyAuth ? (
            <div className="space-y-4">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs text-slate-700 flex flex-wrap justify-between gap-2">
                <span>
                  Authenticated: <strong>{facultyAuth.user.name}</strong> ({facultyAuth.user.departmentCode})
                </span>
                <span className="font-mono text-emerald-700">
                  Session {facultyAuth.session.id.slice(0, 8)}... ACTIVE
                </span>
              </div>

              <div>
                <label
                  htmlFor="demo-doc-select"
                  className="block text-xs font-medium text-slate-700 mb-1"
                >
                  Target Document
                </label>
                <select
                  id="demo-doc-select"
                  value={selectedDocId}
                  onChange={(e) => setSelectedDocId(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
                >
                  {facultyDocs.map((d) => (
                    <option key={d.id} value={d.id}>
                      [{d.classification}] {d.fileName} ({d.departmentCode}) — Current:{' '}
                      {d.access.decision}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-wrap gap-2.5">
                <button
                  type="button"
                  disabled={facultyBusy}
                  onClick={() => void executeFacultyOpenDocument(false)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-sm font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Eye className="w-4 h-4" />
                  <span>Open Document (Real API)</span>
                </button>

                <button
                  type="button"
                  disabled={facultyBusy || !capturedDirectUrl}
                  onClick={() => void executeFacultyOpenDocument(true)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-sm font-medium text-[#12315C] bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <RotateCw className="w-4 h-4" />
                  <span>Retry Captured URL</span>
                </button>
              </div>

              {capturedDirectUrl && (
                <div className="text-xs font-mono text-slate-600 bg-slate-50 border border-slate-200 rounded px-3 py-2 break-all">
                  Direct URL: GET {capturedDirectUrl}
                </div>
              )}

              {facultyResult && (
                <div
                  className={`p-4 rounded-md border text-xs ${
                    facultyResult.decision === 'ALLOW'
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                      : 'bg-red-50 border-red-200 text-red-950'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 font-mono font-semibold">
                    <span>
                      HTTP {facultyResult.httpStatus} · {facultyResult.decision} ·{' '}
                      {facultyResult.code}
                    </span>
                    <span className="tabular-nums opacity-75">
                      {new Date(facultyResult.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="mt-1 text-sm">{facultyResult.message}</p>
                  {facultyResult.checks && facultyResult.checks.length > 0 && (
                    <ul className="mt-2 pt-2 border-t border-current/15 space-y-1 font-mono">
                      {facultyResult.checks.map((c, idx) => (
                        <li key={`${c.rule}-${idx}`}>
                          [{c.passed ? 'PASS' : 'FAIL'}] {c.code}: {c.detail}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {facultyBlobUrl && (
                <div className="border border-slate-200 rounded-md overflow-hidden">
                  <div className="bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700 flex flex-wrap items-center justify-between gap-2">
                    <span>Streamed Confidential PDF Preview</span>
                    {facultyResult?.watermarkText && (
                      <span className="font-mono text-[11px] text-red-700 truncate max-w-full">
                        {facultyResult.watermarkText}
                      </span>
                    )}
                  </div>
                  <iframe
                    title="Demo Faculty PDF Preview"
                    src={facultyBlobUrl}
                    className="w-full h-56 bg-white"
                  />
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500 py-6 text-center border border-dashed border-slate-200 rounded">
              Click <strong>Sign In Faculty</strong> to establish a real server session for the left
              pane.
            </p>
          )}
        </section>

        {/* RIGHT PANE: HOD / SECURITY CONSOLE */}
        <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-200">
            <div>
              <p className="text-xs font-semibold text-blue-700">Right Pane · Authority &amp; Audit</p>
              <h4 className="text-base font-semibold text-[#0B1F3A]">HOD / Security Console</h4>
            </div>
            {hodAuth && (
              <button
                type="button"
                onClick={() => void refreshHodConsole()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#12315C] bg-blue-50 border border-blue-200 rounded hover:bg-blue-100 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Refresh</span>
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[200px]">
              <label
                htmlFor="demo-hod-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Authority Account
              </label>
              <select
                id="demo-hod-select"
                value={hodEmail}
                onChange={(e) => setHodEmail(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                <option value="hod.cse@univault.edu">CSE HOD (hod.cse@univault.edu)</option>
                <option value="admin@univault.edu">Super Admin (admin@univault.edu)</option>
              </select>
            </div>
            <button
              type="button"
              disabled={hodBusy}
              onClick={() => void handleHodLogin()}
              className="px-4 py-2 text-sm font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md whitespace-nowrap shrink-0 cursor-pointer"
            >
              {hodAuth ? 'Re-authenticate' : 'Sign In Authority'}
            </button>
          </div>

          {hodAuth ? (
            <div className="space-y-4">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs text-slate-700 flex flex-wrap justify-between gap-2">
                <span>
                  Authority: <strong>{hodAuth.user.name}</strong>
                </span>
                {chainIntegrity && (
                  <span
                    className={`font-mono font-semibold ${
                      chainIntegrity.valid ? 'text-emerald-700' : 'text-red-700'
                    }`}
                  >
                    Chain: {chainIntegrity.valid ? 'VALID' : 'BROKEN'} ({chainIntegrity.totalEntries})
                  </span>
                )}
              </div>

              <div className="flex flex-wrap gap-2.5">
                <button
                  type="button"
                  disabled={hodBusy || !facultyAuth}
                  onClick={() => void handleGrantFromHod()}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-sm font-semibold text-white bg-emerald-700 hover:bg-emerald-800 rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <KeyRound className="w-4 h-4" />
                  <span>Grant 15m Access</span>
                </button>

                <button
                  type="button"
                  disabled={hodBusy || !activeMatchingGrant}
                  onClick={() => void handleRevokeActiveForSelected()}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-sm font-semibold text-white bg-red-700 hover:bg-red-800 rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Ban className="w-4 h-4" />
                  <span>Revoke Grant Immediately</span>
                </button>
              </div>

              {hodMessage && (
                <div className="p-3 bg-blue-50 border border-blue-200 rounded text-xs text-slate-900">
                  {hodMessage}
                </div>
              )}

              <div className="border border-slate-200 rounded-md overflow-hidden">
                <div className="bg-slate-50 px-3.5 py-2 border-b border-slate-200 flex items-center justify-between text-xs font-semibold text-[#0B1F3A]">
                  <span>Latest Hash-Chained Audit Entries</span>
                  <span className="font-mono text-slate-500">Live SQLite</span>
                </div>
                <div className="divide-y divide-slate-200 max-h-72 overflow-y-auto">
                  {auditLogs.map((log) => (
                    <div key={log.id} className="px-3.5 py-2.5 text-xs flex items-start justify-between gap-3">
                      <div>
                        <div className="font-mono font-semibold text-[#0B1F3A]">
                          {log.action}{' '}
                          <span
                            className={
                              log.decision === 'ALLOW'
                                ? 'text-emerald-700'
                                : log.decision === 'DENY'
                                  ? 'text-red-700'
                                  : 'text-blue-700'
                            }
                          >
                            · {log.decision}
                          </span>
                          {log.denialReason && (
                            <span className="text-red-700"> ({log.denialReason})</span>
                          )}
                        </div>
                        <div className="text-slate-600 mt-0.5">
                          {log.actorEmail ?? 'anonymous'}
                          {log.documentName ? ` -> ${log.documentName}` : ''}
                        </div>
                      </div>
                      <span className="font-mono tabular-nums text-[11px] text-slate-400 shrink-0">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-sm text-slate-500 py-6 text-center border border-dashed border-slate-200 rounded space-y-2">
              <p>
                Click <strong>Sign In Authority</strong> to issue/revoke grants and stream live audit
                events.
              </p>
              <p className="text-xs text-slate-400 flex items-center justify-center gap-1">
                <Play className="w-3 h-3" /> Uses an isolated HttpOnly cookie channel without logging out
                your main session.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
