/**
 * Represents an authenticated user in the system
 */
export interface QPMTXAuthUser {
  /** Unique user identifier */
  id: string;
  /** User's email address */
  email?: string;
  /** User's username */
  username?: string;
  /** User's assigned roles */
  roles: string[];
  /** User's permissions */
  permissions?: string[];
  /** Additional user properties */
  [key: string]: unknown;
}

/**
 * JWT token payload structure
 */
export interface QPMTXJwtPayload {
  /** Subject (user ID) */
  sub: string;
  /** User's email address */
  email?: string;
  /** User's username */
  username?: string;
  /** User's roles */
  roles: string[];
  /** User's permissions */
  permissions?: string[];
  /** Token issued at timestamp */
  iat?: number;
  /** Token expiration timestamp */
  exp?: number;
  /** Additional payload properties */
  [key: string]: unknown;
}

/**
 * Base request interface that works with both Express and Fastify
 */
export interface QPMTXBaseRequest {
  /** Authenticated user object */
  user?: QPMTXAuthUser;
  /** Request headers */
  headers: Record<string, string | string[] | undefined>;
  /** Request method */
  method?: string;
  /** Request URL */
  url?: string;
  /** Request body */
  body?: unknown;
  /** Request query parameters */
  query?: Record<string, unknown>;
  /** Request params */
  params?: Record<string, unknown>;
}

/**
 * HTTP request with authenticated user - compatible with Express and Fastify
 */
export interface QPMTXAuthRequest extends QPMTXBaseRequest {
  /** Authenticated user object */
  user: QPMTXAuthUser;
}

/** Type alias for role strings */
export type QPMTXRole = string;

/** Type alias for permission strings */
export type QPMTXPermission = string;

/**
 * Definition of a role with its permissions
 */
export interface QPMTXRoleDefinition {
  /** Role name */
  name: string;
  /** Permissions granted by this role */
  permissions: QPMTXPermission[];
  /** Optional role description */
  description?: string;
}

/**
 * Authentication context information
 */
export interface QPMTXAuthContext {
  /** Authenticated user */
  user: QPMTXAuthUser;
  /** HTTP request object */
  request: unknown;
  /** Request headers */
  headers: Record<string, string>;
}

/**
 * Result of token validation
 */
export interface QPMTXTokenValidationResult {
  /** Whether the token is valid */
  isValid: boolean;
  /** User object if validation successful */
  user?: QPMTXAuthUser;
  /** Error message if validation failed */
  error?: string;
}

/**
 * Options for configuring authentication guards
 */
export interface QPMTXAuthGuardOptions {
  /** Required roles for access */
  roles?: QPMTXRole[];
  /** Required permissions for access */
  permissions?: QPMTXPermission[];
  /** Whether all roles/permissions are required (AND logic) */
  requireAll?: boolean;
  /** Whether to allow anonymous access */
  allowAnonymous?: boolean;
}

// Backward compatibility aliases
/** @deprecated Use QPMTXAuthUser instead */
export type AuthUser = QPMTXAuthUser;
/** @deprecated Use QPMTXJwtPayload instead */
export type JwtPayload = QPMTXJwtPayload;
/** @deprecated Use QPMTXBaseRequest instead */
export type BaseRequest = QPMTXBaseRequest;
/** @deprecated Use QPMTXAuthRequest instead */
export type AuthRequest = QPMTXAuthRequest;
/** @deprecated Use QPMTXRole instead */
export type Role = QPMTXRole;
/** @deprecated Use QPMTXPermission instead */
export type Permission = QPMTXPermission;
/** @deprecated Use QPMTXRoleDefinition instead */
export type RoleDefinition = QPMTXRoleDefinition;
/** @deprecated Use QPMTXAuthContext instead */
export type AuthContext = QPMTXAuthContext;
/** @deprecated Use QPMTXTokenValidationResult instead */
export type TokenValidationResult = QPMTXTokenValidationResult;
/** @deprecated Use QPMTXAuthGuardOptions instead */
export type AuthGuardOptions = QPMTXAuthGuardOptions;
