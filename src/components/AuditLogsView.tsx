import { useCallback, useEffect, useState } from 'react';
import { Anchor, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ApiError, fetchAuditLogs, triggerAuditAnchor } from '../api/client';
import type { AuthUser } from '../types/auth';
import type {
  AuditAnchorVerificationStatus,
  AuditAnomalySummary,
  AuditChainIntegrity,
  AuditLogItem,
} from '../types/domain';

interface AuditLogsViewProps {
  user: AuthUser;
}

export function AuditLogsView({ user }: AuditLogsViewProps) {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [chain, setChain] = useState<AuditChainIntegrity | null>(null);
  const [anchorStatus, setAnchorStatus] = useState<AuditAnchorVerificationStatus | null>(null);
  const [anomaly, setAnomaly] = useState<AuditAnomalySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [anchoring, setAnchoring] = useState(false);
  const [anchorMessage, setAnchorMessage] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [error, setError] = useState<string | null>(null);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchAuditLogs({
        decision: decisionFilter,
        action: actionFilter,
        limit: 120,
      });
      setLogs(result.logs);
      setChain(result.chainIntegrity);
      setAnchorStatus(result.anchorStatus);
      setAnomaly(result.anomalySummary);
    } catch (err) {
      setLogs([]);
      setChain(null);
      setAnchorStatus(null);
      setAnomaly(null);
      if (err instanceof ApiError) {
        setError(`[HTTP ${err.status} · ${err.code}] ${err.message}`);
      } else {
        setError(err instanceof Error ? err.message : 'Unable to load audit logs.');
      }
    } finally {
      setLoading(false);
    }
  }, [decisionFilter, actionFilter]);

  useEffect(() => {
    void loadLogs();
  }, [loadLogs]);

  const handleTriggerAnchor = async () => {
    setAnchoring(true);
    setAnchorMessage(null);
    setError(null);
    try {
      const res = await triggerAuditAnchor();
      setAnchorStatus(res.anchorStatus);
      setAnchorMessage(
        `Checkpoint ${res.anchor.anchorId.slice(0, 8)}... anchored at chain length ${res.anchor.chainLength} (${res.anchor.targetMode}).`
      );
      await loadLogs();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`[HTTP ${err.status} · ${err.code}] ${err.message}`);
      } else {
        setError(err instanceof Error ? err.message : 'Unable to anchor audit checkpoint.');
      }
    } finally {
      setAnchoring(false);
    }
  };

  const canTriggerAnchor = user.role === 'SUPER_ADMIN' || user.role === 'HOD';

  return (
    <div className="space-y-6">
      {chain && (
        <section
          className={`p-5 rounded-lg border flex flex-wrap items-center justify-between gap-4 ${
            chain.valid
              ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
              : 'bg-red-50 border-red-200 text-red-950'
          }`}
        >
          <div className="flex items-start gap-3">
            {chain.valid ? (
              <ShieldCheck className="w-5 h-5 text-emerald-700 mt-0.5 shrink-0" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-red-700 mt-0.5 shrink-0" />
            )}
            <div>
              <h3 className="text-sm font-semibold">
                {chain.valid
                  ? 'Hash-Chain Integrity Verified'
                  : 'Hash-Chain Tampering Detected'}
              </h3>
              <p className="text-xs mt-0.5">
                {chain.valid
                  ? `Verified ${chain.totalEntries} chronological SHA-256 linked audit entries (prev_hash -> entry_hash).`
                  : chain.reason}
              </p>
            </div>
          </div>
          <span className="text-xs font-mono tabular-nums font-semibold">
            Scope: {user.role === 'SUPER_ADMIN' ? 'All Campus Events' : `${user.departmentCode} Department`}
          </span>
        </section>
      )}

      {anchorStatus && (
        <section className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-[#0B1F3A]">
                  Periodic Audit Anchor Checkpoint (No Blockchain)
                </h3>
                <span
                  className={`text-xs font-semibold ${
                    anchorStatus.verified ? 'text-emerald-700' : 'text-red-700'
                  }`}
                >
                  {anchorStatus.verified ? 'Verified' : 'Attention Required'}
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-0.5">{anchorStatus.reason}</p>
            </div>

            {canTriggerAnchor && (
              <button
                type="button"
                disabled={anchoring}
                onClick={() => void handleTriggerAnchor()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Anchor className="w-3.5 h-3.5" />
                <span>{anchoring ? 'Anchoring...' : 'Anchor Checkpoint Now'}</span>
              </button>
            )}
          </div>

          {anchorMessage && (
            <p className="mt-3 text-xs text-emerald-700 font-medium">{anchorMessage}</p>
          )}

          {anchorStatus.latestAnchor && (
            <dl className="mt-4 pt-3 border-t border-slate-200 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
              <div>
                <dt className="text-slate-500">Latest Anchor ID</dt>
                <dd className="font-mono text-[#0B1F3A] mt-0.5">
                  {anchorStatus.latestAnchor.anchorId.slice(0, 12)}... ·{' '}
                  {new Date(anchorStatus.latestAnchor.anchoredAt).toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Head Entry Hash</dt>
                <dd className="font-mono tabular-nums text-[#0B1F3A] mt-0.5">
                  {anchorStatus.latestAnchor.headEntryHash.slice(0, 16)}... (len{' '}
                  {anchorStatus.latestAnchor.chainLength})
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Checkpoint Target &amp; Cadence</dt>
                <dd className="font-mono text-[#0B1F3A] mt-0.5">
                  {anchorStatus.latestAnchor.targetMode} · Every {anchorStatus.intervalMinutes}m
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Azure Immutable Retention Lock</dt>
                <dd className="font-semibold text-slate-700 mt-0.5">
                  {anchorStatus.azureImmutableLockStatus}
                </dd>
              </div>
            </dl>
          )}
        </section>
      )}

      {anomaly && (
        <section className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-[#0B1F3A]">
                Deterministic Anomaly &amp; DENY-Spike Monitor
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                Calculated directly from SQLite audit records (no heuristic guesswork).
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-6 text-xs">
              <div>
                <span className="text-slate-500">Risk State: </span>
                <span
                  className={`font-mono font-semibold ${
                    anomaly.riskLevel === 'ALERT'
                      ? 'text-red-700'
                      : anomaly.riskLevel === 'ELEVATED'
                        ? 'text-amber-700'
                        : 'text-emerald-700'
                  }`}
                >
                  {anomaly.riskLevel}
                </span>
              </div>
              <div>
                <span className="text-slate-500">15m DENY Events: </span>
                <span className="font-mono tabular-nums font-semibold text-[#0B1F3A]">
                  {anomaly.recentDenies15m}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Integrity Failures: </span>
                <span
                  className={`font-mono tabular-nums font-semibold ${
                    anomaly.integrityFailuresTotal > 0 ? 'text-red-700' : 'text-[#0B1F3A]'
                  }`}
                >
                  {anomaly.integrityFailuresTotal}
                </span>
              </div>
            </div>
          </div>

          {anomaly.alerts.length > 0 && (
            <ul className="mt-3 pt-3 border-t border-slate-200 space-y-1.5 text-xs">
              {anomaly.alerts.map((alertItem) => (
                <li
                  key={`${alertItem.code}-${alertItem.message}`}
                  className={
                    alertItem.severity === 'ALERT'
                      ? 'text-red-700 font-medium'
                      : 'text-amber-700 font-medium'
                  }
                >
                  [{alertItem.severity} · {alertItem.code}] {alertItem.message}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-[#0B1F3A]">Security Audit Trail</h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Immutable append-only log recording authentication, PDP allow/deny decisions, grants,
              and integrity checks.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <input
              type="text"
              placeholder="Filter action (e.g. DOCUMENT_VIEW)..."
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-md w-56"
            />

            <select
              aria-label="Filter by decision"
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-md bg-white"
            >
              <option value="">All Decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DENY">DENY</option>
              <option value="INFO">INFO</option>
            </select>

            <button
              type="button"
              onClick={() => void loadLogs()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#12315C] bg-blue-50 border border-blue-200 rounded hover:bg-blue-100 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Verify &amp; Refresh</span>
            </button>
          </div>
        </div>

        {error ? (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-md text-sm text-red-800" role="alert">
            {error}
          </div>
        ) : loading ? (
          <div className="py-10 text-center text-sm text-slate-500">
            Verifying hash chain and loading audit logs...
          </div>
        ) : logs.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            No audit events match your filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="py-3 pr-3 font-semibold">Timestamp</th>
                  <th className="py-3 px-3 font-semibold">Actor</th>
                  <th className="py-3 px-3 font-semibold">Action</th>
                  <th className="py-3 px-3 font-semibold">Decision</th>
                  <th className="py-3 px-3 font-semibold">Reason / Resource</th>
                  <th className="py-3 pl-3 font-semibold text-right">Entry Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {logs.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-50/70">
                    <td className="py-3 pr-3 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-medium text-slate-900">
                        {entry.actorName ?? 'Unauthenticated'}
                      </div>
                      {entry.actorEmail && (
                        <div className="font-mono text-[11px] text-slate-500">
                          {entry.actorEmail}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono font-medium text-[#0B1F3A] whitespace-nowrap">
                      {entry.action}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      {entry.decision === 'ALLOW' && (
                        <span className="font-semibold text-emerald-700">ALLOW</span>
                      )}
                      {entry.decision === 'DENY' && (
                        <span className="font-semibold text-red-700">DENY</span>
                      )}
                      {entry.decision === 'INFO' && (
                        <span className="font-semibold text-blue-700">INFO</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-700">
                      {entry.denialReason && (
                        <div className="font-mono font-semibold text-red-700">
                          {entry.denialReason}
                        </div>
                      )}
                      {entry.documentName && (
                        <div className="text-slate-700">{entry.documentName}</div>
                      )}
                      {entry.targetUserName && (
                        <div className="text-slate-500">Target: {entry.targetUserName}</div>
                      )}
                      <div className="font-mono text-[11px] text-slate-400">
                        req:{entry.requestId.slice(0, 8)}
                      </div>
                    </td>
                    <td className="py-3 pl-3 text-right font-mono tabular-nums text-slate-600 whitespace-nowrap">
                      <div>{entry.entryHash.slice(0, 12)}...</div>
                      <div className="text-[10px] text-slate-400">
                        prev:{entry.prevHash.slice(0, 8)}
                      </div>
                    </td>
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
