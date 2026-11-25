import type { AuthContext } from '../auth/types.ts';

declare global {
  namespace Express {
    interface Request {
      requestId?: string;
      auth?: AuthContext;
    }
  }
}
