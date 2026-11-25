import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { fetchSystemHealth } from '../api/client';
import type { CapabilityItem, HealthResponse } from '../types/auth';

function capabilityStatusTone(status: CapabilityItem['status']): string {
  switch (status) {
    case 'Implemented':
      return 'text-emerald-700 font-semibold';
    case 'Partially Implemented':
      return 'text-amber-700 font-semibold';
    case 'Proposed':
      return 'text-slate-600 font-semibold';
  }
}

export function HealthCard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchSystemHealth();
      setHealth(result.data);
      if (!result.ok) {
        setError(`Health endpoint reported degraded status (HTTP ${result.status}).`);
      }
    } catch (err) {
      setHealth(null);
      setError(
        err instanceof Error
          ? `Unable to reach UniVault API: ${err.message}`
          : 'Unable to reach UniVault API.'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadHealth();
  }, [loadHealth]);

  const statusText = loading
    ? 'Verifying...'
    : health?.status === 'ok'
      ? 'Operational'
      : health?.status === 'degraded'
        ? 'Degraded'
        : 'Offline';

  const statusColorClass = loading
    ? 'text-slate-600'
    : health?.status === 'ok'
      ? 'text-emerald-700'
      : health?.status === 'degraded'
        ? 'text-amber-700'
        : 'text-red-700';

  return (
    <div className="space-y-6">
      <section className="bg-white border border-slate-200 rounded-lg p-6" aria-live="polite">
        <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-[#0B1F3A]">Live System Health</h3>
            <p className="text-sm text-slate-600 mt-0.5">
              Reads live SQLite and private storage checks from{' '}
              <code className="font-mono text-xs text-[#12315C]">GET /api/health</code>
            </p>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <span className={`text-sm font-semibold whitespace-nowrap ${statusColorClass}`}>
              {statusText}
            </span>
            <button
              type="button"
              onClick={() => void loadHealth()}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-sm font-medium text-[#12315C] bg-blue-50 border border-blue-200 rounded-md hover:bg-blue-100 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              <span>{loading ? 'Checking' : 'Re-verify'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div
            className="mt-4 p-3.5 bg-red-50 border border-red-200 rounded-md text-sm text-red-800"
            role="alert"
          >
            {error}
          </div>
        )}

        {health && (
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-slate-50 border border-slate-200 rounded-md p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-semibold text-[#0B1F3A]">SQLite Database</h4>
                <span
                  className={`text-xs font-semibold ${
                    health.checks.database.healthy ? 'text-emerald-700' : 'text-red-700'
                  }`}
                >
                  {health.checks.database.healthy ? 'Connected' : 'Error'}
                </span>
              </div>

              <dl className="space-y-3 text-sm">
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Engine</dt>
                  <dd className="font-mono tabular-nums text-slate-900">
                    {health.checks.database.engine}
                  </dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Foreign Keys</dt>
                  <dd className="font-mono tabular-nums text-slate-900">
                    {health.checks.database.foreignKeysEnabled ? 'PRAGMA ON' : 'OFF'}
                  </dd>
                </div>
              </dl>

              {health.checks.database.tables && (
                <div className="mt-5 pt-4 border-t border-slate-200">
                  <p className="text-xs font-semibold text-slate-600 mb-2.5">
                    Database Record Counts
                  </p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                    {Object.entries(health.checks.database.tables).map(([name, count]) => (
                      <div
                        key={name}
                        className="flex items-center justify-between py-1 border-b border-slate-200/70"
                      >
                        <span className="text-slate-600">{name}</span>
                        <span className="font-mono tabular-nums font-semibold text-[#12315C]">
                          {count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-md p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-semibold text-[#0B1F3A]">Storage Provider</h4>
                <span
                  className={`text-xs font-semibold ${
                    health.checks.storage.healthy ? 'text-emerald-700' : 'text-red-700'
                  }`}
                >
                  {health.checks.storage.healthy ? 'Ready' : 'Attention'}
                </span>
              </div>

              <dl className="space-y-3 text-sm">
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Active Provider</dt>
                  <dd className="font-mono font-semibold text-slate-900">
                    {health.checks.storage.provider}
                  </dd>
                </div>
                {health.checks.storage.authMode && (
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-500">Auth / Isolation Mode</dt>
                    <dd className="font-mono text-xs text-slate-900">
                      {health.checks.storage.authMode}
                    </dd>
                  </div>
                )}
                {health.checks.storage.targetLabel && (
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-500">Private Target</dt>
                    <dd className="font-mono text-xs text-slate-900">
                      {health.checks.storage.targetLabel}
                    </dd>
                  </div>
                )}
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Public Access</dt>
                  <dd className="text-xs font-semibold text-emerald-700">
                    {health.checks.storage.publicAccessBlocked === false
                      ? 'Public Flag Detected'
                      : 'Blocked (Private Only)'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 mb-1">Status Detail</dt>
                  <dd className="text-slate-800">{health.checks.storage.message}</dd>
                </div>
                <div className="flex justify-between gap-4 pt-2 border-t border-slate-200">
                  <dt className="text-slate-500">Last Checked</dt>
                  <dd className="font-mono tabular-nums text-xs text-slate-700">
                    {new Date(health.timestamp).toLocaleString()}
                  </dd>
                </div>
              </dl>
            </div>
          </div>
        )}

        {health?.checks.auditAnchoring && (
          <div className="mt-6 bg-slate-50 border border-slate-200 rounded-md p-5">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-3">
              <h4 className="text-sm font-semibold text-[#0B1F3A]">
                Audit Anchor Checkpoint &amp; Classification Hash Verification
              </h4>
              <span
                className={`text-xs font-semibold ${
                  health.checks.auditAnchoring.verified ? 'text-emerald-700' : 'text-red-700'
                }`}
              >
                {health.checks.auditAnchoring.verified ? 'Checkpoint Verified' : 'Attention'}
              </span>
            </div>
            <dl className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
              <div>
                <dt className="text-slate-500">Latest Anchor</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {health.checks.auditAnchoring.latestAnchor
                    ? `${health.checks.auditAnchoring.latestAnchor.anchorId.slice(0, 12)}... (len ${health.checks.auditAnchoring.latestAnchor.chainLength})`
                    : 'None'}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Target Mode &amp; Cadence</dt>
                <dd className="font-mono text-slate-900 mt-0.5">
                  {health.checks.auditAnchoring.latestAnchor?.targetMode ?? 'local-checkpoint'} ·{' '}
                  {health.checks.auditAnchoring.intervalMinutes}m
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Azure Immutable Retention Lock</dt>
                <dd className="font-semibold text-slate-700 mt-0.5">
                  {health.checks.auditAnchoring.azureImmutableLockStatus}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Classification Hash Mode</dt>
                <dd className="font-mono text-slate-900 mt-0.5">
                  {health.checks.classificationIntegrity?.mode ?? 'canonical-sha256'}
                </dd>
              </div>
            </dl>
            <p className="text-xs text-slate-600 mt-3">{health.checks.auditAnchoring.reason}</p>
          </div>
        )}
      </section>

      {health?.capabilities && health.capabilities.length > 0 && (
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="pb-4 border-b border-slate-200">
            <h3 className="text-base font-semibold text-[#0B1F3A]">
              Security &amp; Storage Capability Status
            </h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Transparent reporting of implemented controls, optional/partial cloud integrations, and
              proposed post-hackathon capabilities.
            </p>
          </div>

          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="py-3 pr-4 font-semibold">Capability</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 pl-4 font-semibold">Scope &amp; Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {health.capabilities.map((cap) => (
                  <tr key={cap.name} className="hover:bg-slate-50/70">
                    <td className="py-3 pr-4 font-medium text-[#0B1F3A]">{cap.name}</td>
                    <td className={`py-3 px-4 text-xs whitespace-nowrap ${capabilityStatusTone(cap.status)}`}>
                      {cap.status}
                    </td>
                    <td className="py-3 pl-4 text-xs text-slate-600">{cap.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
