import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Ban, Check, Clock, KeyRound, RefreshCw, X } from 'lucide-react';
import {
  ApiError,
  classificationTextTone,
  createAccessGrant,
  createAccessRequest,
  decideAccessRequest,
  fetchAccessRequests,
  fetchGrants,
  fetchGrantTargets,
  revokeAccessGrant,
} from '../api/client';
import type { AuthUser } from '../types/auth';
import type {
  AccessGrantItem,
  AccessRequestItem,
  GrantTargetDocument,
  GrantTargetUser,
} from '../types/domain';

interface GrantsViewProps {
  user: AuthUser;
}

export function GrantsView({ user }: GrantsViewProps) {
  const canManage = user.role === 'SUPER_ADMIN' || user.role === 'HOD';
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [requestableDocs, setRequestableDocs] = useState<GrantTargetDocument[]>([]);
  const [targetUsers, setTargetUsers] = useState<GrantTargetUser[]>([]);
  const [targetDocs, setTargetDocs] = useState<GrantTargetDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'REVOKED' | 'EXPIRED'>('ALL');
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; message: string } | null>(null);

  // Direct grant form state (HOD / SUPER_ADMIN)
  const [selectedUserId, setSelectedUserId] = useState('');
  const [selectedDocId, setSelectedDocId] = useState('');
  const [durationMinutes, setDurationMinutes] = useState(60);
  const [submitting, setSubmitting] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  // JIT request form state (Requester)
  const [jitDocId, setJitDocId] = useState('');
  const [jitDurationMinutes, setJitDurationMinutes] = useState(60);
  const [jitJustification, setJitJustification] = useState('');
  const [submittingJit, setSubmittingJit] = useState(false);
  const [decidingRequestId, setDecidingRequestId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [grantsData, jitData] = await Promise.all([fetchGrants(), fetchAccessRequests()]);
      setGrants(grantsData);
      setRequests(jitData.requests);
      setRequestableDocs(jitData.requestableDocuments);
      setJitDocId((prev) => prev || jitData.requestableDocuments[0]?.id || '');

      if (canManage) {
        const targets = await fetchGrantTargets();
        setTargetUsers(targets.users);
        setTargetDocs(targets.documents);
        setSelectedUserId((prev) => prev || targets.users[0]?.id || '');
        setSelectedDocId((prev) => prev || targets.documents[0]?.id || '');
      }
    } catch (err) {
      setFeedback({
        type: 'err',
        message: err instanceof Error ? err.message : 'Unable to load access grants.',
      });
    } finally {
      setLoading(false);
    }
  }, [canManage]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleCreateGrant = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedUserId || !selectedDocId) return;

    setSubmitting(true);
    setFeedback(null);
    try {
      const created = await createAccessGrant({
        userId: selectedUserId,
        documentId: selectedDocId,
        durationMinutes,
      });
      setFeedback({
        type: 'ok',
        message: `Access grant ${created.id.slice(0, 8)}... issued until ${new Date(created.expiresAt).toLocaleString()}.`,
      });
      await loadData();
    } catch (err) {
      setFeedback({
        type: 'err',
        message: err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to issue grant.',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (grantId: string) => {
    setRevokingId(grantId);
    setFeedback(null);
    try {
      await revokeAccessGrant(grantId);
      setFeedback({
        type: 'ok',
        message: `Grant ${grantId.slice(0, 8)}... revoked immediately. Subsequent document access will return HTTP 403 GRANT_REVOKED.`,
      });
      await loadData();
    } catch (err) {
      setFeedback({
        type: 'err',
        message: err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to revoke grant.',
      });
    } finally {
      setRevokingId(null);
    }
  };

  const handleCreateJitRequest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!jitDocId || !jitJustification.trim()) return;

    setSubmittingJit(true);
    setFeedback(null);
    try {
      const created = await createAccessRequest({
        documentId: jitDocId,
        durationMinutes: jitDurationMinutes,
        justification: jitJustification.trim(),
      });
      setJitJustification('');
      setFeedback({
        type: 'ok',
        message: `Just-In-Time access request ${created.id.slice(0, 8)}... submitted for HOD / Super Admin review.`,
      });
      await loadData();
    } catch (err) {
      setFeedback({
        type: 'err',
        message:
          err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to submit JIT request.',
      });
    } finally {
      setSubmittingJit(false);
    }
  };

  const handleDecideJitRequest = async (
    requestId: string,
    decision: 'APPROVE' | 'REJECT'
  ) => {
    setDecidingRequestId(requestId);
    setFeedback(null);
    try {
      const result = await decideAccessRequest(
        requestId,
        decision,
        decision === 'APPROVE'
          ? 'Approved via UniVault JIT governance queue.'
          : 'Denied by reviewing authority.'
      );
      setFeedback({
        type: 'ok',
        message:
          result.status === 'APPROVED'
            ? `JIT request approved and active grant ${result.grantId?.slice(0, 8) ?? ''}... issued.`
            : `JIT request ${requestId.slice(0, 8)}... rejected and logged to audit trail.`,
      });
      await loadData();
    } catch (err) {
      setFeedback({
        type: 'err',
        message:
          err instanceof ApiError ? `[${err.code}] ${err.message}` : 'Failed to process JIT request.',
      });
    } finally {
      setDecidingRequestId(null);
    }
  };

  const visibleGrants =
    statusFilter === 'ALL' ? grants : grants.filter((g) => g.status === statusFilter);

  return (
    <div className="space-y-6">
      {canManage ? (
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h3 className="text-base font-semibold text-[#0B1F3A]">
                Issue Time-Bound Access Grant
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                {user.role === 'HOD'
                  ? `Scoped to documents owned by ${user.departmentName} (${user.departmentCode}).`
                  : 'Super Admin may issue grants for any department document.'}
              </p>
            </div>
          </div>

          <form
            className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end"
            onSubmit={(e) => void handleCreateGrant(e)}
          >
            <div className="md:col-span-4">
              <label
                htmlFor="grant-user-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Target User
              </label>
              <select
                id="grant-user-select"
                value={selectedUserId}
                onChange={(e) => setSelectedUserId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                {targetUsers.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.name} ({u.departmentCode})
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-4">
              <label
                htmlFor="grant-doc-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Protected Document
              </label>
              <select
                id="grant-doc-select"
                value={selectedDocId}
                onChange={(e) => setSelectedDocId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                {targetDocs.map((d) => (
                  <option key={d.id} value={d.id}>
                    [{d.classification}] {d.fileName} ({d.departmentCode})
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <label
                htmlFor="grant-duration-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Duration
              </label>
              <select
                id="grant-duration-select"
                value={durationMinutes}
                onChange={(e) => setDurationMinutes(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
                <option value={60}>1 hour</option>
                <option value={1440}>24 hours</option>
                <option value={10080}>7 days</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <button
                type="submit"
                disabled={submitting || !selectedUserId || !selectedDocId}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md disabled:opacity-60 whitespace-nowrap cursor-pointer"
              >
                <KeyRound className="w-4 h-4 shrink-0" />
                <span>{submitting ? 'Issuing...' : 'Issue Grant'}</span>
              </button>
            </div>
          </form>
        </section>
      ) : null}

      {user.role !== 'SUPER_ADMIN' && (
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="mb-4">
            <h3 className="text-base font-semibold text-[#0B1F3A]">
              Request Just-In-Time (JIT) Document Access
            </h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Submit a justified, time-bound access request for a restricted or cross-department
              document. Approval creates an audited grant automatically.
            </p>
          </div>

          <form
            className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end"
            onSubmit={(e) => void handleCreateJitRequest(e)}
          >
            <div className="md:col-span-4">
              <label
                htmlFor="jit-doc-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Protected Document
              </label>
              <select
                id="jit-doc-select"
                value={jitDocId}
                onChange={(e) => setJitDocId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                {requestableDocs.map((d) => (
                  <option key={d.id} value={d.id}>
                    [{d.classification}] {d.fileName} ({d.departmentCode})
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <label
                htmlFor="jit-duration-select"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Requested Duration
              </label>
              <select
                id="jit-duration-select"
                value={jitDurationMinutes}
                onChange={(e) => setJitDurationMinutes(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              >
                <option value={15}>15 minutes</option>
                <option value={60}>1 hour</option>
                <option value={240}>4 hours</option>
                <option value={1440}>24 hours</option>
              </select>
            </div>

            <div className="md:col-span-4">
              <label
                htmlFor="jit-justification-input"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Business / Academic Justification
              </label>
              <input
                id="jit-justification-input"
                type="text"
                minLength={5}
                maxLength={400}
                required
                placeholder="e.g. Moderation review for CS401 exam"
                value={jitJustification}
                onChange={(e) => setJitJustification(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md bg-white"
              />
            </div>

            <div className="md:col-span-2">
              <button
                type="submit"
                disabled={submittingJit || !jitDocId || jitJustification.trim().length < 5}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-md disabled:opacity-60 whitespace-nowrap cursor-pointer"
              >
                <Clock className="w-4 h-4 shrink-0" />
                <span>{submittingJit ? 'Sending...' : 'Request JIT'}</span>
              </button>
            </div>
          </form>
        </section>
      )}

      {feedback && (
        <div
          className={`p-3.5 rounded-lg border text-sm ${
            feedback.type === 'ok'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
          role="status"
        >
          {feedback.message}
        </div>
      )}

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-[#0B1F3A]">JIT Access Requests Queue</h3>
            <p className="text-xs text-slate-600 mt-0.5">
              {canManage
                ? 'Review pending time-bound requests from faculty and approve or reject them directly.'
                : 'Track approval decisions for your Just-In-Time access requests.'}
            </p>
          </div>
          <span className="text-xs font-mono tabular-nums text-slate-500">
            Pending: {requests.filter((r) => r.status === 'PENDING').length} · Total: {requests.length}
          </span>
        </div>

        {loading ? (
          <div className="py-8 text-center text-sm text-slate-500">Loading JIT requests...</div>
        ) : requests.length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-500">
            No Just-In-Time access requests recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="py-3 pr-4 font-semibold">Requester</th>
                  <th className="py-3 px-4 font-semibold">Document</th>
                  <th className="py-3 px-4 font-semibold">Justification &amp; Window</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  {canManage && <th className="py-3 pl-4 font-semibold text-right">Review</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {requests.map((reqItem) => {
                  const canDecideThis =
                    canManage &&
                    reqItem.status === 'PENDING' &&
                    reqItem.requesterId !== user.id &&
                    (user.role === 'SUPER_ADMIN' || reqItem.documentDepartmentId === user.departmentId);

                  return (
                    <tr key={reqItem.id} className="hover:bg-slate-50/70">
                      <td className="py-3 pr-4">
                        <div className="font-medium text-[#0B1F3A]">{reqItem.requesterName}</div>
                        <div className="text-xs font-mono text-slate-500">
                          {reqItem.requesterEmail} · {reqItem.requesterDepartmentCode}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-900">{reqItem.documentName}</div>
                        <div className="text-xs text-slate-500">
                          <span className={classificationTextTone(reqItem.documentClassification)}>
                            {reqItem.documentClassification}
                          </span>{' '}
                          · {reqItem.documentDepartmentCode}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-700 max-w-xs">
                        <div>{reqItem.justification}</div>
                        <div className="font-mono tabular-nums text-slate-500 mt-0.5">
                          Requested: {reqItem.requestedDurationMinutes} min ·{' '}
                          {new Date(reqItem.createdAt).toLocaleString()}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        {reqItem.status === 'PENDING' && (
                          <span className="font-semibold text-amber-700">PENDING</span>
                        )}
                        {reqItem.status === 'APPROVED' && (
                          <div>
                            <span className="font-semibold text-emerald-700">APPROVED</span>
                            {reqItem.grantId && (
                              <div className="font-mono text-[11px] text-slate-500">
                                Grant {reqItem.grantId.slice(0, 8)}...
                              </div>
                            )}
                          </div>
                        )}
                        {reqItem.status === 'REJECTED' && (
                          <div>
                            <span className="font-semibold text-red-700">REJECTED</span>
                            {reqItem.reviewedByName && (
                              <div className="text-[11px] text-slate-500">
                                By {reqItem.reviewedByName}
                              </div>
                            )}
                          </div>
                        )}
                      </td>
                      {canManage && (
                        <td className="py-3 pl-4 text-right whitespace-nowrap">
                          {canDecideThis ? (
                            <div className="inline-flex items-center gap-2">
                              <button
                                type="button"
                                disabled={decidingRequestId === reqItem.id}
                                onClick={() => void handleDecideJitRequest(reqItem.id, 'APPROVE')}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200 rounded hover:bg-emerald-100 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
                              >
                                <Check className="w-3.5 h-3.5" />
                                <span>Approve</span>
                              </button>
                              <button
                                type="button"
                                disabled={decidingRequestId === reqItem.id}
                                onClick={() => void handleDecideJitRequest(reqItem.id, 'REJECT')}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-red-700 bg-red-50 border border-red-200 rounded hover:bg-red-100 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
                              >
                                <X className="w-3.5 h-3.5" />
                                <span>Reject</span>
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-400">—</span>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-[#0B1F3A]">Access Grants Ledger</h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Time-bound grants automatically transition to <code className="font-mono">EXPIRED</code>{' '}
              when past <code className="font-mono">expires_at</code>, or{' '}
              <code className="font-mono">REVOKED</code> immediately upon revocation.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(['ALL', 'ACTIVE', 'REVOKED', 'EXPIRED'] as const).map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => setStatusFilter(status)}
                  className={`px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap shrink-0 cursor-pointer ${
                    statusFilter === status ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void loadData()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#12315C] bg-blue-50 border border-blue-200 rounded hover:bg-blue-100 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {loading ? (
          <div className="py-10 text-center text-sm text-slate-500">Loading grants...</div>
        ) : visibleGrants.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            No access grants found for the selected filter.
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="py-3 pr-4 font-semibold">Recipient</th>
                  <th className="py-3 px-4 font-semibold">Document</th>
                  <th className="py-3 px-4 font-semibold">Granted By</th>
                  <th className="py-3 px-4 font-semibold">Expires At</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  {canManage && <th className="py-3 pl-4 font-semibold text-right">Action</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {visibleGrants.map((grant) => (
                  <tr key={grant.id} className="hover:bg-slate-50/70">
                    <td className="py-3.5 pr-4">
                      <div className="font-medium text-[#0B1F3A]">{grant.userName}</div>
                      <div className="text-xs text-slate-500 font-mono">
                        {grant.userEmail} · {grant.userDepartmentCode}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-medium text-slate-900">{grant.documentName}</div>
                      <div className="text-xs text-slate-500">
                        <span className={classificationTextTone(grant.documentClassification)}>
                          {grant.documentClassification}
                        </span>{' '}
                        · {grant.documentDepartmentCode}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-xs text-slate-700">{grant.grantedByName}</td>
                    <td className="py-3.5 px-4 font-mono tabular-nums text-xs text-slate-700 whitespace-nowrap">
                      {new Date(grant.expiresAt).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-xs whitespace-nowrap">
                      {grant.status === 'ACTIVE' && (
                        <span className="font-semibold text-emerald-700">ACTIVE</span>
                      )}
                      {grant.status === 'REVOKED' && (
                        <div>
                          <span className="font-semibold text-red-700">REVOKED</span>
                          {grant.revokedAt && (
                            <div className="text-[11px] font-mono text-slate-500">
                              {new Date(grant.revokedAt).toLocaleTimeString()}
                            </div>
                          )}
                        </div>
                      )}
                      {grant.status === 'EXPIRED' && (
                        <span className="font-semibold text-amber-700">EXPIRED</span>
                      )}
                    </td>
                    {canManage && (
                      <td className="py-3.5 pl-4 text-right whitespace-nowrap">
                        {grant.status === 'ACTIVE' ? (
                          <button
                            type="button"
                            disabled={revokingId === grant.id}
                            onClick={() => void handleRevoke(grant.id)}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-red-700 bg-red-50 border border-red-200 rounded hover:bg-red-100 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            <Ban className="w-3.5 h-3.5" />
                            <span>{revokingId === grant.id ? 'Revoking...' : 'Revoke Now'}</span>
                          </button>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
