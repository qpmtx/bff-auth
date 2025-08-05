import type {
  InjectionToken,
  ModuleMetadata,
  OptionalFactoryDependency,
  Type,
} from '@nestjs/common';
import type { Algorithm } from 'jsonwebtoken';
import type { Profile } from 'passport';

/**
 * JWT configuration options for the authentication module
 */
export interface QPMTXJwtConfig {
  /** JWT secret key for signing and verifying tokens */
  secret?: string;
  /** Options for signing JWT tokens */
  signOptions?: {
    /** Token expiration time (e.g., '1h', '7d', 3600) */
    expiresIn?: string | number;
    /** Token issuer */
    issuer?: string;
    /** Token audience */
    audience?: string;
    /** Signing algorithm */
    algorithm?: Algorithm;
  };
  /** Options for verifying JWT tokens */
  verifyOptions?: {
    /** Expected issuer */
    issuer?: string;
    /** Expected audience */
    audience?: string;
    /** Allowed algorithms for verification */
    algorithms?: Algorithm[];
    /** Clock tolerance in seconds */
    clockTolerance?: number;
    /** Whether to ignore token expiration */
    ignoreExpiration?: boolean;
    /** Whether to ignore 'not before' claim */
    ignoreNotBefore?: boolean;
  };
}

/**
 * OAuth provider configuration
 */
export interface QPMTXOAuthProviderConfig {
  /** OAuth client ID */
  clientID: string;
  /** OAuth client secret */
  clientSecret: string;
  /** OAuth callback URL */
  callbackURL: string;
  /** OAuth scopes to request */
  scope?: string[];
  /** Additional provider-specific options */
  [key: string]: unknown;
}

/**
 * OAuth configuration options for multiple providers
 */
export interface QPMTXOAuthConfig {
  /** GitHub OAuth configuration */
  github?: QPMTXOAuthProviderConfig;
  /** Google OAuth configuration */
  google?: QPMTXOAuthProviderConfig;
  /** Additional OAuth providers can be added here */
  [provider: string]: QPMTXOAuthProviderConfig | undefined;
}

/**
 * OAuth user mapping function type
 */
export type QPMTXOAuthUserMapper = (
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: (error: Error | null, user?: unknown) => void,
) => void | Promise<void>;

/**
 * Main configuration interface for the authentication module
 */
export interface QPMTXAuthModuleConfig {
  /** JWT configuration */
  jwt?: QPMTXJwtConfig;
  /** OAuth configuration for multiple providers */
  oauth?: QPMTXOAuthConfig;
  /** OAuth user mapping function */
  oauthUserMapper?: QPMTXOAuthUserMapper;
  /** Session configuration for OAuth */
  session?: {
    /** Session secret */
    secret: string;
    /** Session options */
    resave?: boolean;
    saveUninitialized?: boolean;
    cookie?: {
      maxAge?: number;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: boolean | 'lax' | 'strict' | 'none';
    };
  };
  /** Whether to apply the auth guard globally */
  globalGuard?: boolean;
  /** Default roles assigned to users if none specified */
  defaultRoles?: string[];
  /** Role hierarchy mapping for role inheritance */
  roleHierarchy?: Record<string, string[]>;
  /** Custom user validation function */
  customUserValidator?: (user: unknown) => Promise<boolean> | boolean;
  /** Custom token extraction function */
  tokenExtractor?: (request: unknown) => string | null;
  /** Custom unauthorized error message */
  unauthorizedMessage?: string;
  /** Custom forbidden error message */
  forbiddenMessage?: string;
}

/**
 * Async configuration options for the authentication module
 */
export interface QPMTXAuthModuleAsyncConfig
  extends Pick<ModuleMetadata, 'imports'> {
  /** Factory function to create configuration */
  useFactory?: (
    ...args: unknown[]
  ) => Promise<QPMTXAuthModuleConfig> | QPMTXAuthModuleConfig;
  /** Class to create configuration */
  useClass?: Type<QPMTXAuthConfigFactory>;
  /** Existing provider to create configuration */
  useExisting?: Type<QPMTXAuthConfigFactory>;
  /** Dependencies to inject into the factory */
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

/**
 * Interface for auth configuration factory classes
 */
export interface QPMTXAuthConfigFactory {
  /**
   * Creates authentication module configuration
   * @returns Promise<QPMTXAuthModuleConfig> | QPMTXAuthModuleConfig
   */
  createAuthConfig(): Promise<QPMTXAuthModuleConfig> | QPMTXAuthModuleConfig;
}

// Backward compatibility aliases
/** @deprecated Use QPMTXJwtConfig instead */
export type JwtConfig = QPMTXJwtConfig;
/** @deprecated Use QPMTXAuthModuleConfig instead */
export type AuthModuleConfig = QPMTXAuthModuleConfig;
/** @deprecated Use QPMTXAuthModuleAsyncConfig instead */
export type AuthModuleAsyncConfig = QPMTXAuthModuleAsyncConfig;
/** @deprecated Use QPMTXAuthConfigFactory instead */
export type AuthConfigFactory = QPMTXAuthConfigFactory;
