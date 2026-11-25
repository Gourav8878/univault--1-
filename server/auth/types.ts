export type UserRole = 'SUPER_ADMIN' | 'HOD' | 'FACULTY';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  departmentId: string;
  departmentName: string;
  departmentCode: string;
  active: boolean;
}

export interface AuthenticatedSession {
  id: string;
  createdAt: string;
  expiresAt: string;
}

export interface AuthContext {
  user: AuthenticatedUser;
  session: AuthenticatedSession;
}
