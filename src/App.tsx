import { useCallback, useEffect, useState } from 'react';
import { ApiError, fetchCurrentSession, logoutSession } from './api/client';
import { AppShell } from './components/AppShell';
import { LoginScreen } from './components/LoginScreen';
import type { AuthResponse } from './types/auth';

export default function App() {
  const [auth, setAuth] = useState<AuthResponse | null>(null);
  const [initializing, setInitializing] = useState(true);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const hydrateSession = useCallback(async () => {
    setInitializing(true);
    try {
      const current = await fetchCurrentSession();
      setAuth(current);
      setAuthNotice(null);
    } catch (err) {
      setAuth(null);
      if (err instanceof ApiError && err.status === 403) {
        setAuthNotice(`[${err.code}] ${err.message}`);
      } else {
        setAuthNotice(null);
      }
    } finally {
      setInitializing(false);
    }
  }, []);

  useEffect(() => {
    void hydrateSession();
  }, [hydrateSession]);

  const handleLogout = async () => {
    try {
      await logoutSession();
    } finally {
      setAuth(null);
      setAuthNotice(null);
    }
  };

  if (initializing) {
    return (
      <div className="min-h-screen grid place-items-center bg-slate-50 px-4">
        <div className="bg-white border border-slate-200 rounded-lg p-8 max-w-md w-full text-center">
          <p className="text-xs font-semibold text-blue-700 mb-1">
            UniVault Zero-Trust Verification
          </p>
          <h2 className="text-lg font-semibold text-[#0B1F3A]">Verifying active session...</h2>
          <p className="text-sm text-slate-600 mt-1">
            Checking server-side session state via <code className="font-mono text-xs">GET /api/auth/me</code>
          </p>
        </div>
      </div>
    );
  }

  if (!auth) {
    return (
      <LoginScreen
        initialNotice={authNotice}
        onLoginSuccess={(nextAuth) => {
          setAuth(nextAuth);
          setAuthNotice(null);
        }}
      />
    );
  }

  return <AppShell user={auth.user} session={auth.session} onLogout={handleLogout} />;
}
