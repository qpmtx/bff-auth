/**
 * Generic types for flexible authentication system
 */

/**
 * Generic user type that can be extended with custom properties
 */
export interface GenericUser<TCustomProperties = Record<string, unknown>> {
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
  /** Custom user properties */
  custom?: TCustomProperties;
}

/**
 * Generic JWT payload that can be extended
 */
export interface GenericJwtPayload<TCustomClaims = Record<string, unknown>> {
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
  /** Token not before timestamp */
  nbf?: number;
  /** Token issuer */
  iss?: string;
  /** Token audience */
  aud?: string | string[];
  /** JWT ID */
  jti?: string;
  /** Custom claims */
  custom?: TCustomClaims;
}

/**
 * Generic request type that works with different frameworks
 */
export interface GenericRequest<
  TUser = GenericUser,
  TBody = unknown,
  TQuery = Record<string, unknown>,
  TParams = Record<string, unknown>,
> {
  /** Authenticated user object */
  user?: TUser;
  /** Request headers */
  headers: Record<string, string | string[] | undefined>;
  /** Request method */
  method?: string;
  /** Request URL */
  url?: string;
  /** Request body */
  body?: TBody;
  /** Request query parameters */
  query?: TQuery;
  /** Request params */
  params?: TParams;
  /** Request IP address */
  ip?: string;
  /** User agent */
  userAgent?: string;
}

/**
 * Type for custom validation functions
 */
export type UserValidator<TUser = GenericUser> = (
  user: TUser,
) => Promise<boolean> | boolean;

/**
 * Type for custom token extraction functions
 */
export type TokenExtractor<TRequest = GenericRequest> = (
  request: TRequest,
) => string | null;

/**
 * Generic auth configuration that can be customized
 */
export interface GenericAuthConfig<
  TUser = GenericUser,
  TRequest = GenericRequest,
> {
  /** JWT configuration */
  jwt?: {
    /** JWT secret key */
    secret?: string;
    /** JWT signing options */
    signOptions?: Record<string, unknown>;
    /** JWT verification options */
    verifyOptions?: Record<string, unknown>;
  };
  /** Whether to apply the auth guard globally */
  globalGuard?: boolean;
  /** Default roles assigned to users if none specified */
  defaultRoles?: string[];
  /** Role hierarchy mapping for role inheritance */
  roleHierarchy?: Record<string, string[]>;
  /** Custom user validation function */
  customUserValidator?: UserValidator<TUser>;
  /** Custom token extraction function */
  tokenExtractor?: TokenExtractor<TRequest>;
  /** Custom unauthorized error message */
  unauthorizedMessage?: string;
  /** Custom forbidden error message */
  forbiddenMessage?: string;
  /** Additional custom configuration */
  custom?: Record<string, unknown>;
}

/**
 * Generic guard options for flexible access control
 */
export interface GenericGuardOptions {
  /** Required roles for access */
  roles?: string[];
  /** Required permissions for access */
  permissions?: string[];
  /** Whether all roles/permissions are required (AND logic) */
  requireAll?: boolean;
  /** Whether to allow anonymous access */
  allowAnonymous?: boolean;
  /** Custom validation function */
  customValidator?: (user: GenericUser, context?: unknown) => boolean;
  /** Additional custom options */
  custom?: Record<string, unknown>;
}

/**
 * Utility types for better type inference
 */
export type ExtractUserType<T> =
  T extends GenericAuthConfig<infer U, unknown> ? U : GenericUser;

export type ExtractRequestType<T> =
  T extends GenericAuthConfig<unknown, infer R> ? R : GenericRequest;

/**
 * Helper type for creating typed configurations
 */
export type TypedAuthConfig<
  TUser extends GenericUser = GenericUser,
  TRequest extends GenericRequest = GenericRequest,
> = GenericAuthConfig<TUser, TRequest>;

/**
 * Branded types for type safety
 */
export type UserId = string & { readonly __brand: 'UserId' };
export type RoleName = string & { readonly __brand: 'RoleName' };
export type PermissionName = string & { readonly __brand: 'PermissionName' };
export type JwtToken = string & { readonly __brand: 'JwtToken' };

/**
 * Type guards for runtime type checking
 */
export const isGenericUser = (value: unknown): value is GenericUser => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'id' in value &&
    'roles' in value &&
    Array.isArray((value as GenericUser).roles)
  );
};

export const isGenericJwtPayload = (
  value: unknown,
): value is GenericJwtPayload => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'sub' in value &&
    'roles' in value &&
    Array.isArray((value as GenericJwtPayload).roles)
  );
};
