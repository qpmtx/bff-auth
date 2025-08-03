import {
  AuthUser,
  JwtPayload,
  TokenValidationResult,
} from '../types/auth.types';

export interface IAuthService {
  validateToken(token: string): Promise<TokenValidationResult>;
  validateUser(payload: JwtPayload): Promise<AuthUser | null>;
  generateToken(user: AuthUser): Promise<string>;
  refreshToken(token: string): Promise<string>;
  hasRole(user: AuthUser, role: string): boolean;
  hasPermission(user: AuthUser, permission: string): boolean;
  hasAnyRole(user: AuthUser, roles: string[]): boolean;
  hasAllRoles(user: AuthUser, roles: string[]): boolean;
  hasAnyPermission(user: AuthUser, permissions: string[]): boolean;
  hasAllPermissions(user: AuthUser, permissions: string[]): boolean;
}
