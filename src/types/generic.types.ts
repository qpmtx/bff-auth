/**
 * Generic types for flexible authentication system
 */

/**
 * Generic user type that can be extended with custom properties
 */
export interface QPMTXGenericUser<TCustomProperties = Record<string, unknown>> {
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
export interface QPMTXGenericJwtPayload<
  TCustomClaims = Record<string, unknown>,
> {
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
export interface QPMTXGenericRequest<
  TUser = QPMTXGenericUser,
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
export type QPMTXUserValidator<TUser = QPMTXGenericUser> = (
  user: TUser,
) => Promise<boolean> | boolean;

/**
 * Type for custom token extraction functions
 */
export type QPMTXTokenExtractor<TRequest = QPMTXGenericRequest> = (
  request: TRequest,
) => string | null;

/**
 * Generic auth configuration that can be customized
 */
export interface QPMTXGenericAuthConfig<
  TUser = QPMTXGenericUser,
  TRequest = QPMTXGenericRequest,
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
  customUserValidator?: QPMTXUserValidator<TUser>;
  /** Custom token extraction function */
  tokenExtractor?: QPMTXTokenExtractor<TRequest>;
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
export interface QPMTXGenericGuardOptions {
  /** Required roles for access */
  roles?: string[];
  /** Required permissions for access */
  permissions?: string[];
  /** Whether all roles/permissions are required (AND logic) */
  requireAll?: boolean;
  /** Whether to allow anonymous access */
  allowAnonymous?: boolean;
  /** Custom validation function */
  customValidator?: (user: QPMTXGenericUser, context?: unknown) => boolean;
  /** Additional custom options */
  custom?: Record<string, unknown>;
}

/**
 * Utility types for better type inference
 */
export type QPMTXExtractUserType<T> =
  T extends QPMTXGenericAuthConfig<infer U, unknown> ? U : QPMTXGenericUser;

export type QPMTXExtractRequestType<T> =
  T extends QPMTXGenericAuthConfig<unknown, infer R> ? R : QPMTXGenericRequest;

/**
 * Helper type for creating typed configurations
 */
export type QPMTXTypedAuthConfig<
  TUser extends QPMTXGenericUser = QPMTXGenericUser,
  TRequest extends QPMTXGenericRequest = QPMTXGenericRequest,
> = QPMTXGenericAuthConfig<TUser, TRequest>;

/**
 * Branded types for type safety
 */
export type QPMTXUserId = string & { readonly __brand: 'QPMTXUserId' };
export type QPMTXRoleName = string & { readonly __brand: 'QPMTXRoleName' };
export type QPMTXPermissionName = string & {
  readonly __brand: 'QPMTXPermissionName';
};
export type QPMTXJwtToken = string & { readonly __brand: 'QPMTXJwtToken' };

/**
 * Type guards for runtime type checking
 */
export const isQPMTXGenericUser = (
  value: unknown,
): value is QPMTXGenericUser => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'id' in value &&
    'roles' in value &&
    Array.isArray((value as QPMTXGenericUser).roles)
  );
};

export const isQPMTXGenericJwtPayload = (
  value: unknown,
): value is QPMTXGenericJwtPayload => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'sub' in value &&
    'roles' in value &&
    Array.isArray((value as QPMTXGenericJwtPayload).roles)
  );
};

// Backward compatibility aliases
/** @deprecated Use QPMTXGenericUser instead */
export type GenericUser<TCustomProperties = Record<string, unknown>> =
  QPMTXGenericUser<TCustomProperties>;
/** @deprecated Use QPMTXGenericJwtPayload instead */
export type GenericJwtPayload<TCustomClaims = Record<string, unknown>> =
  QPMTXGenericJwtPayload<TCustomClaims>;
/** @deprecated Use QPMTXGenericRequest instead */
export type GenericRequest<
  TUser = QPMTXGenericUser,
  TBody = unknown,
  TQuery = Record<string, unknown>,
  TParams = Record<string, unknown>,
> = QPMTXGenericRequest<TUser, TBody, TQuery, TParams>;
/** @deprecated Use QPMTXUserValidator instead */
export type UserValidator<TUser = QPMTXGenericUser> = QPMTXUserValidator<TUser>;
/** @deprecated Use QPMTXTokenExtractor instead */
export type TokenExtractor<TRequest = QPMTXGenericRequest> =
  QPMTXTokenExtractor<TRequest>;
/** @deprecated Use QPMTXGenericAuthConfig instead */
export type GenericAuthConfig<
  TUser = QPMTXGenericUser,
  TRequest = QPMTXGenericRequest,
> = QPMTXGenericAuthConfig<TUser, TRequest>;
/** @deprecated Use QPMTXGenericGuardOptions instead */
export type GenericGuardOptions = QPMTXGenericGuardOptions;
/** @deprecated Use QPMTXExtractUserType instead */
export type ExtractUserType<T> = QPMTXExtractUserType<T>;
/** @deprecated Use QPMTXExtractRequestType instead */
export type ExtractRequestType<T> = QPMTXExtractRequestType<T>;
/** @deprecated Use QPMTXTypedAuthConfig instead */
export type TypedAuthConfig<
  TUser extends QPMTXGenericUser = QPMTXGenericUser,
  TRequest extends QPMTXGenericRequest = QPMTXGenericRequest,
> = QPMTXTypedAuthConfig<TUser, TRequest>;
/** @deprecated Use QPMTXUserId instead */
export type UserId = QPMTXUserId;
/** @deprecated Use QPMTXRoleName instead */
export type RoleName = QPMTXRoleName;
/** @deprecated Use QPMTXPermissionName instead */
export type PermissionName = QPMTXPermissionName;
/** @deprecated Use QPMTXJwtToken instead */
export type JwtToken = QPMTXJwtToken;
/** @deprecated Use isQPMTXGenericUser instead */
export const isGenericUser = isQPMTXGenericUser;
/** @deprecated Use isQPMTXGenericJwtPayload instead */
export const isGenericJwtPayload = isQPMTXGenericJwtPayload;
