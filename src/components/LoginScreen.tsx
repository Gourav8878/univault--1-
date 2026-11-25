import { useEffect, useState, type FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
import { ApiError, fetchSystemHealth, loginWithCredentials } from '../api/client';
import type { AuthResponse, HealthResponse } from '../types/auth';

interface DemoAccountPreset {
  label: string;
  roleLabel: string;
  department: string;
  email: string;
  password: string;
}

const DEMO_ACCOUNTS: DemoAccountPreset[] = [
  {
    label: 'Fill Super Admin',
    roleLabel: 'SUPER_ADMIN',
    department: 'Administration',
    email: 'admin@univault.edu',
    password: 'UniVault@Demo123',
  },
  {
    label: 'Fill CSE HOD',
    roleLabel: 'HOD',
    department: 'Computer Science (CSE)',
    email: 'hod.cse@univault.edu',
    password: 'UniVault@Demo123',
  },
  {
    label: 'Fill CSE Faculty',
    roleLabel: 'FACULTY',
    department: 'Computer Science (CSE)',
    email: 'faculty.cse@univault.edu',
    password: 'UniVault@Demo123',
  },
  {
    label: 'Fill ECE Faculty',
    roleLabel: 'FACULTY',
    department: 'Electronics (ECE)',
    email: 'faculty.ece@univault.edu',
    password: 'UniVault@Demo123',
  },
];

interface LoginScreenProps {
  initialNotice?: string | null;
  onLoginSuccess: (auth: AuthResponse) => void;
}

export function LoginScreen({ initialNotice, onLoginSuccess }: LoginScreenProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(initialNotice ?? null);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    let active = true;
    fetchSystemHealth()
      .then((res) => {
        if (active) setHealth(res.data);
      })
      .catch(() => {
        if (active) setHealth(null);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleFillAccount = (preset: DemoAccountPreset) => {
    // Only fills input fields; authentication always executes via POST /api/auth/login.
    setEmail(preset.email);
    setPassword(preset.password);
    setError(null);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      const auth = await loginWithCredentials(email, password);
      onLoginSuccess(auth);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`[${err.code}] ${err.message}`);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Unable to sign in. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50">
      <header className="bg-[#0B1F3A] text-white border-b border-[#1E3A63]">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between gap-8">
          <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
            <ShieldCheck className="w-6 h-6 text-blue-300 shrink-0" />
            <span className="text-lg font-bold tracking-tight">UniVault</span>
          </div>
          <p className="hidden sm:block text-sm text-slate-300 whitespace-nowrap shrink-0">
            Trust Nothing. Verify Every Access.
          </p>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10">
        <div className="mb-8 max-w-2xl">
          <p className="text-xs font-semibold text-blue-700 mb-1.5">
            Zero-Trust Campus Document Exchange
          </p>
          <h1 className="text-3xl font-bold text-[#0B1F3A] tracking-tight text-balance">
            Verify your campus identity to access protected records
          </h1>
          <p className="text-slate-600 mt-2 text-sm">
            Every request is authenticated against server-side SQLite sessions and evaluated through
            the centralized RBAC + ABAC Policy Decision Point.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-6">
            <h2 className="text-xl font-semibold text-[#0B1F3A]">Sign in to UniVault</h2>
            <p className="text-sm text-slate-600 mt-1">
              Credentials are verified on the server and issued an{' '}
              <code className="font-mono text-xs text-[#12315C]">HttpOnly</code> session cookie.
            </p>

            {error && (
              <div
                className="mt-4 p-3.5 bg-red-50 border border-red-200 rounded-md text-sm text-red-800"
                role="alert"
              >
                {error}
              </div>
            )}

            <form className="mt-6 space-y-5" onSubmit={(e) => void handleSubmit(e)}>
              <div>
                <label
                  htmlFor="email-input"
                  className="block text-sm font-medium text-[#0B1F3A] mb-1.5"
                >
                  Campus Email
                </label>
                <input
                  id="email-input"
                  name="email"
                  type="email"
                  autoComplete="username"
                  placeholder="name@univault.edu"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
              </div>

              <div>
                <label
                  htmlFor="password-input"
                  className="block text-sm font-medium text-[#0B1F3A] mb-1.5"
                >
                  Password
                </label>
                <input
                  id="password-input"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 px-4 text-sm font-semibold text-white bg-[#12315C] hover:bg-[#0B1F3A] rounded-md transition-colors disabled:opacity-60 whitespace-nowrap cursor-pointer"
              >
                {submitting ? 'Verifying Credentials...' : 'Verify & Sign In'}
              </button>
            </form>

            {health && (
              <div className="mt-6 pt-4 border-t border-slate-200 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
                <span
                  className={`font-semibold ${
                    health.status === 'ok' ? 'text-emerald-700' : 'text-amber-700'
                  }`}
                >
                  API {health.status === 'ok' ? 'Operational' : 'Degraded'}
                </span>
                <span aria-hidden="true">·</span>
                <span>SQLite {health.checks.database.foreignKeysEnabled ? 'FK ON' : 'FK OFF'}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono">Storage: {health.checks.storage.provider}</span>
              </div>
            )}
          </section>

          <aside className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-6">
            <h3 className="text-base font-semibold text-[#0B1F3A]">One-Click Role Fill</h3>
            <p className="text-sm text-slate-600 mt-1">
              Populates the email and password fields for seeded accounts. You must still submit
              through <code className="font-mono text-xs text-[#12315C]">POST /api/auth/login</code>.
            </p>

            <div className="mt-4 divide-y divide-slate-200 border border-slate-200 rounded-md overflow-hidden">
              {DEMO_ACCOUNTS.map((preset) => (
                <button
                  key={preset.email}
                  type="button"
                  onClick={() => handleFillAccount(preset)}
                  className="w-full text-left px-4 py-3 bg-slate-50/60 hover:bg-blue-50/70 transition-colors flex flex-col gap-0.5 cursor-pointer"
                >
                  <span className="text-sm font-semibold text-[#12315C]">{preset.label}</span>
                  <span className="text-xs text-slate-600">
                    {preset.roleLabel} · {preset.department}
                  </span>
                  <span className="text-xs font-mono text-blue-700">{preset.email}</span>
                </button>
              ))}
            </div>

            <p className="mt-4 text-xs text-slate-600 leading-relaxed">
              Session tokens are hashed with SHA-256 in SQLite and never stored in browser{' '}
              <code className="font-mono">localStorage</code>.
            </p>
          </aside>
        </div>
      </main>
    </div>
  );
}
