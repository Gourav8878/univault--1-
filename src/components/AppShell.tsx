import { useState } from 'react';
import {
  Activity,
  FileText,
  KeyRound,
  LayoutDashboard,
  LogOut,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { AuthSession, AuthUser, NavSectionId } from '../types/auth';
import { AuditLogsView } from './AuditLogsView';
import { DocumentsView } from './DocumentsView';
import { GrantsView } from './GrantsView';
import { HealthCard } from './HealthCard';
import { RoleDashboard } from './RoleDashboard';
import { SplitScreenDemoView } from './SplitScreenDemoView';

interface NavItem {
  id: NavSectionId;
  label: string;
  icon: typeof LayoutDashboard;
  hideForFaculty?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview', label: 'Role Overview', icon: LayoutDashboard },
  { id: 'documents', label: 'Documents', icon: FileText },
  { id: 'grants', label: 'Grants & Revocation', icon: KeyRound },
  { id: 'security-demo', label: 'Security Demo', icon: ShieldAlert },
  { id: 'audit-logs', label: 'Audit Logs', icon: ScrollText, hideForFaculty: true },
  { id: 'system-health', label: 'System Health', icon: Activity },
];

interface AppShellProps {
  user: AuthUser;
  session: AuthSession;
  onLogout: () => Promise<void>;
}

export function AppShell({ user, session, onLogout }: AppShellProps) {
  const [activeSection, setActiveSection] = useState<NavSectionId>('overview');
  const [signingOut, setSigningOut] = useState(false);

  const handleLogoutClick = async () => {
    setSigningOut(true);
    try {
      await onLogout();
    } finally {
      setSigningOut(false);
    }
  };

  const visibleNavItems = NAV_ITEMS.filter(
    (item) => !(item.hideForFaculty && user.role === 'FACULTY')
  );
  const currentTitle =
    NAV_ITEMS.find((item) => item.id === activeSection)?.label ?? 'Role Overview';

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-slate-50">
      <aside
        className="w-full lg:w-64 bg-[#0B1F3A] text-slate-100 flex flex-col shrink-0 border-b lg:border-b-0 lg:border-r border-[#1A355B]"
        aria-label="Primary Navigation"
      >
        <div className="px-5 py-4 border-b border-[#1A355B] flex items-center gap-3">
          <ShieldCheck className="w-6 h-6 text-blue-300 shrink-0" />
          <div>
            <h1 className="text-base font-bold tracking-tight text-white">UniVault</h1>
            <p className="text-[11px] text-slate-300">Trust Nothing. Verify Every Access.</p>
          </div>
        </div>

        <nav className="p-3 flex lg:flex-col gap-1 overflow-x-auto flex-1">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveSection(item.id)}
                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap shrink-0 text-left cursor-pointer ${
                  isActive
                    ? 'bg-blue-600/30 text-white border border-blue-400/40'
                    : 'text-slate-300 hover:bg-white/5 hover:text-white border border-transparent'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-[#1A355B] space-y-3">
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-white truncate">{user.name}</p>
            <p className="text-slate-300 font-mono">
              {user.role} · {user.departmentCode}
            </p>
            <p className="text-emerald-300 font-medium">Session Active</p>
          </div>

          <button
            type="button"
            onClick={() => void handleLogoutClick()}
            disabled={signingOut}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold text-red-200 bg-red-950/50 border border-red-400/30 rounded-md hover:bg-red-900/60 disabled:opacity-60 transition-colors whitespace-nowrap cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5 shrink-0" />
            <span>{signingOut ? 'Revoking Session...' : 'Sign Out'}</span>
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="bg-white border-b border-slate-200 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm whitespace-nowrap shrink-0">
            <span className="text-slate-500">UniVault</span>
            <span className="text-slate-400">/</span>
            <h2 className="font-semibold text-[#0B1F3A]">{currentTitle}</h2>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-600 whitespace-nowrap shrink-0">
            <span className="font-mono font-semibold text-[#12315C]">{user.role}</span>
            <span aria-hidden="true">·</span>
            <span>
              {user.departmentName} ({user.departmentCode})
            </span>
          </div>
        </header>

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {activeSection === 'overview' && (
            <RoleDashboard
              user={user}
              session={session}
              onNavigate={(section) => setActiveSection(section)}
            />
          )}
          {activeSection === 'documents' && <DocumentsView user={user} />}
          {activeSection === 'grants' && <GrantsView user={user} />}
          {activeSection === 'security-demo' && <SplitScreenDemoView />}
          {activeSection === 'audit-logs' && <AuditLogsView user={user} />}
          {activeSection === 'system-health' && <HealthCard />}
        </main>
      </div>
    </div>
  );
}
