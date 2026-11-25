import type { AuthSession, AuthUser, NavSectionId, UserRole } from '../types/auth';

interface RoleDashboardProps {
  user: AuthUser;
  session: AuthSession;
  onNavigate: (section: NavSectionId) => void;
}

const ROLE_BRIEF: Record<
  UserRole,
  {
    headline: string;
    summary: string;
    capabilities: string[];
  }
> = {
  SUPER_ADMIN: {
    headline: 'Super Admin Governance Console',
    summary:
      'Campus-wide administrative authority across all academic departments, document uploads, time-bound grant governance, and full hash-chained audit inspection.',
    capabilities: [
      'View, upload, and stream PUBLIC, INTERNAL, and CONFIDENTIAL documents across all departments',
      'Issue or immediately revoke time-bound access grants across any department',
      'Inspect complete campus audit logs and verify SHA-256 hash-chain integrity',
    ],
  },
  HOD: {
    headline: 'Head of Department Workspace',
    summary:
      'Departmental steward with authority to upload, inspect, and govern INTERNAL and CONFIDENTIAL documents within your own academic department.',
    capabilities: [
      'Upload and download PUBLIC, INTERNAL, and CONFIDENTIAL files within your own department',
      'Issue time-bound access grants to faculty or cross-department reviewers and revoke them immediately',
      'Inspect department-scoped audit decisions and policy enforcement logs',
    ],
  },
  FACULTY: {
    headline: 'Faculty Member Workspace',
    summary:
      'Academic user workspace scoped to campus PUBLIC notices, own-department INTERNAL reports, and explicitly granted CONFIDENTIAL documents.',
    capabilities: [
      'View and download PUBLIC notices and own-department INTERNAL materials',
      'Access CONFIDENTIAL or cross-department files only with an active, non-expired grant',
      'Test live grant enforcement and immediate revocation in the Split-Screen Security Demo',
    ],
  },
};

export function RoleDashboard({ user, session, onNavigate }: RoleDashboardProps) {
  const brief = ROLE_BRIEF[user.role];

  return (
    <div className="space-y-6">
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <p className="text-xs font-semibold text-blue-700 mb-1">Authenticated Role Workspace</p>
        <h2 className="text-2xl font-bold text-[#0B1F3A] text-balance">{brief.headline}</h2>
        <p className="text-sm text-slate-600 mt-2 max-w-3xl">{brief.summary}</p>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <article className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-200">
            <h3 className="text-base font-semibold text-[#0B1F3A]">Verified Identity</h3>
            <span className="text-xs font-semibold text-emerald-700">
              {user.active ? 'Active Account' : 'Inactive'}
            </span>
          </div>
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Full Name</dt>
              <dd className="font-medium text-slate-900 text-right">{user.name}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Campus Email</dt>
              <dd className="font-mono text-slate-900 text-right">{user.email}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Role</dt>
              <dd className="font-mono font-semibold text-[#12315C] text-right">{user.role}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Department</dt>
              <dd className="text-slate-900 text-right">
                {user.departmentName} ({user.departmentCode})
              </dd>
            </div>
          </dl>
        </article>

        <article className="bg-white border border-slate-200 rounded-lg p-6">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-200">
            <h3 className="text-base font-semibold text-[#0B1F3A]">Active Session Status</h3>
            <span className="text-xs font-semibold text-blue-700">HttpOnly Cookie</span>
          </div>
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Verification</dt>
              <dd className="font-medium text-emerald-700 text-right">Verified via SQLite</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Session ID</dt>
              <dd className="font-mono text-xs text-slate-800 truncate max-w-[220px]">
                {session.id}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Issued At</dt>
              <dd className="font-mono tabular-nums text-xs text-slate-800">
                {new Date(session.createdAt).toLocaleString()}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Expires At</dt>
              <dd className="font-mono tabular-nums text-xs text-slate-800">
                {new Date(session.expiresAt).toLocaleString()}
              </dd>
            </div>
          </dl>
        </article>
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <h3 className="text-base font-semibold text-[#0B1F3A] mb-3">
          Permitted Workflows &amp; Quick Navigation
        </h3>
        <ul className="list-disc pl-5 space-y-1.5 text-sm text-slate-600 mb-5">
          {brief.capabilities.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>

        <div className="flex flex-wrap gap-3 pt-4 border-t border-slate-200">
          <button
            type="button"
            onClick={() => onNavigate('documents')}
            className="px-4 py-2 text-sm font-medium text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Open Documents
          </button>
          <button
            type="button"
            onClick={() => onNavigate('grants')}
            className="px-4 py-2 text-sm font-medium text-[#12315C] bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Grants &amp; Revocation
          </button>
          <button
            type="button"
            onClick={() => onNavigate('security-demo')}
            className="px-4 py-2 text-sm font-medium text-[#12315C] bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Split-Screen Security Demo
          </button>
          {user.role !== 'FACULTY' && (
            <button
              type="button"
              onClick={() => onNavigate('audit-logs')}
              className="px-4 py-2 text-sm font-medium text-[#12315C] bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Inspect Audit Logs
            </button>
          )}
        </div>
      </section>
    </div>
  );
}
