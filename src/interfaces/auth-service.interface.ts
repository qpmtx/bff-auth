import type {
  QPMTXAuthUser,
  QPMTXJwtPayload,
  QPMTXTokenValidationResult,
} from '../types/auth.types';

export interface QPMTXIAuthService {
  validateToken(token: string): Promise<QPMTXTokenValidationResult>;
  validateUser(payload: QPMTXJwtPayload): Promise<QPMTXAuthUser | null>;
  generateToken(user: QPMTXAuthUser): Promise<string>;
  refreshToken(token: string): Promise<string>;
  hasRole(user: QPMTXAuthUser, role: string): boolean;
  hasPermission(user: QPMTXAuthUser, permission: string): boolean;
  hasAnyRole(user: QPMTXAuthUser, roles: string[]): boolean;
  hasAllRoles(user: QPMTXAuthUser, roles: string[]): boolean;
  hasAnyPermission(user: QPMTXAuthUser, permissions: string[]): boolean;
  hasAllPermissions(user: QPMTXAuthUser, permissions: string[]): boolean;
}

// Backward compatibility alias
/** @deprecated Use QPMTXIAuthService instead */
export type IAuthService = QPMTXIAuthService;
