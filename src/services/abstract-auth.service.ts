import type { ExecutionContext } from '@nestjs/common';
import { Injectable } from '@nestjs/common';
import type {
  GenericGuardOptions,
  GenericJwtPayload,
  GenericRequest,
  GenericUser,
} from '../types/generic.types';

/**
 * Abstract authentication service that can be extended by developers
 * Provides base functionality for user authentication and authorization
 */
@Injectable()
export abstract class AbstractAuthService<
  TUser extends GenericUser = GenericUser,
  TJwtPayload extends GenericJwtPayload = GenericJwtPayload,
  TRequest extends GenericRequest = GenericRequest,
> {
  /**
   * Validates a JWT token and returns the user
   * @param token - JWT token to validate
   * @returns Promise resolving to user or null if invalid
   */
  abstract validateToken(token: string): Promise<TUser | null>;

  /**
   * Validates a user from JWT payload
   * @param payload - JWT payload containing user information
   * @returns Promise resolving to user or null if invalid
   */
  abstract validateUser(payload: TJwtPayload): Promise<TUser | null>;

  /**
   * Generates a JWT token for a user
   * @param user - User to generate token for
   * @returns Promise resolving to JWT token
   */
  abstract generateToken(user: TUser): Promise<string>;

  /**
   * Refreshes a JWT token
   * @param token - Current JWT token
   * @returns Promise resolving to new JWT token
   */
  abstract refreshToken(token: string): Promise<string>;

  /**
   * Extracts token from request
   * @param request - HTTP request object
   * @returns Extracted token or null
   */
  abstract extractTokenFromRequest(request: TRequest): string | null;

  /**
   * Checks if user has a specific role
   * @param user - User to check
   * @param role - Role to check for
   * @returns True if user has the role
   */
  hasRole(user: TUser, role: string): boolean {
    return user.roles?.includes(role) ?? false;
  }

  /**
   * Checks if user has any of the specified roles
   * @param user - User to check
   * @param roles - Roles to check for
   * @returns True if user has any of the roles
   */
  hasAnyRole(user: TUser, roles: string[]): boolean {
    return roles.some((role) => this.hasRole(user, role));
  }

  /**
   * Checks if user has all of the specified roles
   * @param user - User to check
   * @param roles - Roles to check for
   * @returns True if user has all of the roles
   */
  hasAllRoles(user: TUser, roles: string[]): boolean {
    return roles.every((role) => this.hasRole(user, role));
  }

  /**
   * Checks if user has a specific permission
   * @param user - User to check
   * @param permission - Permission to check for
   * @returns True if user has the permission
   */
  hasPermission(user: TUser, permission: string): boolean {
    return user.permissions?.includes(permission) ?? false;
  }

  /**
   * Checks if user has any of the specified permissions
   * @param user - User to check
   * @param permissions - Permissions to check for
   * @returns True if user has any of the permissions
   */
  hasAnyPermission(user: TUser, permissions: string[]): boolean {
    return permissions.some((permission) =>
      this.hasPermission(user, permission),
    );
  }

  /**
   * Checks if user has all of the specified permissions
   * @param user - User to check
   * @param permissions - Permissions to check for
   * @returns True if user has all of the permissions
   */
  hasAllPermissions(user: TUser, permissions: string[]): boolean {
    return permissions.every((permission) =>
      this.hasPermission(user, permission),
    );
  }

  /**
   * Expands user roles based on role hierarchy
   * @param userRoles - User's assigned roles
   * @param roleHierarchy - Role hierarchy configuration
   * @returns Expanded roles including inherited ones
   */
  expandRoles(
    userRoles: string[],
    roleHierarchy?: Record<string, string[]>,
  ): string[] {
    if (!roleHierarchy) {
      return userRoles;
    }

    const expandedRoles = new Set(userRoles);

    for (const role of userRoles) {
      const inheritedRoles = roleHierarchy[role] || [];
      inheritedRoles.forEach((inherited) => expandedRoles.add(inherited));
    }

    return Array.from(expandedRoles);
  }

  /**
   * Validates user against guard options
   * @param user - User to validate
   * @param options - Guard options to validate against
   * @param context - Optional execution context
   * @returns True if user passes validation
   */
  validateGuardOptions(
    user: TUser,
    options: GenericGuardOptions,
    context?: ExecutionContext,
  ): boolean {
    // Custom validator takes precedence
    if (options.customValidator) {
      return options.customValidator(user, context);
    }

    // If no roles or permissions required, allow access
    if (!options.roles && !options.permissions) {
      return true;
    }

    const hasValidRoles = this.validateRoles(user, options);
    const hasValidPermissions = this.validatePermissions(user, options);

    // If requireAll is true, user must have both valid roles AND permissions
    if (options.requireAll) {
      return hasValidRoles && hasValidPermissions;
    }

    // Otherwise, user needs either valid roles OR permissions
    return hasValidRoles || hasValidPermissions;
  }

  /**
   * Validates user roles against guard options
   * @param user - User to validate
   * @param options - Guard options containing role requirements
   * @returns True if user has required roles
   */
  protected validateRoles(user: TUser, options: GenericGuardOptions): boolean {
    if (!options.roles || options.roles.length === 0) {
      return true;
    }

    if (options.requireAll) {
      return this.hasAllRoles(user, options.roles);
    }

    return this.hasAnyRole(user, options.roles);
  }

  /**
   * Validates user permissions against guard options
   * @param user - User to validate
   * @param options - Guard options containing permission requirements
   * @returns True if user has required permissions
   */
  protected validatePermissions(
    user: TUser,
    options: GenericGuardOptions,
  ): boolean {
    if (!options.permissions || options.permissions.length === 0) {
      return true;
    }

    if (options.requireAll) {
      return this.hasAllPermissions(user, options.permissions);
    }

    return this.hasAnyPermission(user, options.permissions);
  }

  /**
   * Gets user display name for logging/UI purposes
   * @param user - User to get display name for
   * @returns User's display name
   */
  getUserDisplayName(user: TUser): string {
    return user.username ?? user.email ?? user.id;
  }

  /**
   * Sanitizes user object by removing sensitive fields
   * @param user - User to sanitize
   * @param fieldsToExclude - Fields to exclude from sanitized user
   * @returns Sanitized user object
   */
  sanitizeUser(
    user: TUser,
    fieldsToExclude: (keyof TUser)[] = [],
  ): Partial<TUser> {
    const sanitized = { ...user };
    fieldsToExclude.forEach((field) => delete sanitized[field]);
    return sanitized;
  }

  /**
   * Hook method called before token validation
   * Can be overridden by subclasses for custom logic
   * @param token - Token being validated
   * @returns Promise resolving to modified token or void
   */
  protected beforeTokenValidation(token: string): string | void {
    return token;
  }

  /**
   * Hook method called after successful user validation
   * Can be overridden by subclasses for custom logic
   * @param user - Validated user
   * @returns Promise resolving to modified user or void
   */
  protected afterUserValidation(user: TUser): TUser | void {
    return user;
  }

  /**
   * Hook method called when validation fails
   * Can be overridden by subclasses for custom error handling
   * @param error - Validation error
   * @param context - Optional context information
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  protected onValidationFailure(_error: Error, _context?: string): void {
    // Default implementation does nothing
    // Subclasses can override for logging, monitoring, etc.
  }
}
