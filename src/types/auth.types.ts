/**
 * Represents an authenticated user in the system
 */
export interface AuthUser {
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
export interface JwtPayload {
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
export interface BaseRequest {
  /** Authenticated user object */
  user?: AuthUser;
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
export interface AuthRequest extends BaseRequest {
  /** Authenticated user object */
  user: AuthUser;
}

/** Type alias for role strings */
export type Role = string;

/** Type alias for permission strings */
export type Permission = string;

/**
 * Definition of a role with its permissions
 */
export interface RoleDefinition {
  /** Role name */
  name: string;
  /** Permissions granted by this role */
  permissions: Permission[];
  /** Optional role description */
  description?: string;
}

/**
 * Authentication context information
 */
export interface AuthContext {
  /** Authenticated user */
  user: AuthUser;
  /** HTTP request object */
  request: unknown;
  /** Request headers */
  headers: Record<string, string>;
}

/**
 * Result of token validation
 */
export interface TokenValidationResult {
  /** Whether the token is valid */
  isValid: boolean;
  /** User object if validation successful */
  user?: AuthUser;
  /** Error message if validation failed */
  error?: string;
}

/**
 * Options for configuring authentication guards
 */
export interface AuthGuardOptions {
  /** Required roles for access */
  roles?: Role[];
  /** Required permissions for access */
  permissions?: Permission[];
  /** Whether all roles/permissions are required (AND logic) */
  requireAll?: boolean;
  /** Whether to allow anonymous access */
  allowAnonymous?: boolean;
}
