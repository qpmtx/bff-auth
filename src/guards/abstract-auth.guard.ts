import type { CanActivate, ExecutionContext } from '@nestjs/common';
import { Injectable } from '@nestjs/common';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { Observable } from 'rxjs';
import type {
  GenericGuardOptions,
  GenericRequest,
  GenericUser,
} from '../types/generic.types';

/**
 * Abstract authentication guard that can be extended by developers
 * Provides base functionality for request authentication and authorization
 */
@Injectable()
export abstract class AbstractAuthGuard<
  TUser extends GenericUser = GenericUser,
  TRequest extends GenericRequest = GenericRequest,
> implements CanActivate
{
  /**
   * Main guard method that determines if request should be allowed
   * @param context - Execution context containing request information
   * @returns Promise/Observable/boolean indicating if access is allowed
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    return this.handleRequest(context);
  }

  /**
   * Handles the authentication request
   * @param context - Execution context
   * @returns Promise indicating if access is allowed
   */
  protected async handleRequest(context: ExecutionContext): Promise<boolean> {
    try {
      // Check if route is marked as public
      if (await this.isPublicRoute(context)) {
        return true;
      }

      // Get guard options from decorators/metadata
      const guardOptions = await this.getGuardOptions(context);

      // Check if anonymous access is allowed
      if (guardOptions.allowAnonymous) {
        return true;
      }

      // Extract and validate token
      const request = this.getRequest(context);
      const token = await this.extractToken(request);

      if (!token) {
        return this.handleUnauthorized(context, 'No token provided');
      }

      // Validate token and get user
      const user = await this.validateToken(token);
      if (!user) {
        return this.handleUnauthorized(context, 'Invalid token');
      }

      // Attach user to request
      this.attachUserToRequest(request, user);

      // Validate user against guard options
      if (!this.validateUserAccess(user, guardOptions, context)) {
        return this.handleForbidden(
          context,
          'Insufficient permissions or roles',
        );
      }

      // Allow additional custom validation
      if (!(await this.customValidation(user, request, context))) {
        return this.handleForbidden(context, 'Custom validation failed');
      }

      return true;
    } catch (error) {
      return this.handleError(context, error);
    }
  }

  /**
   * Extracts the request object from execution context
   * @param context - Execution context
   * @returns Request object
   */
  protected abstract getRequest(context: ExecutionContext): TRequest;

  /**
   * Extracts authentication token from request
   * @param request - HTTP request object
   * @returns Promise resolving to token or null
   */
  protected abstract extractToken(request: TRequest): Promise<string | null>;

  /**
   * Validates authentication token and returns user
   * @param token - Authentication token
   * @returns Promise resolving to user or null
   */
  protected abstract validateToken(token: string): Promise<TUser | null>;

  /**
   * Checks if the current route is marked as public
   * @param context - Execution context
   * @returns Promise resolving to true if route is public
   */
  protected abstract isPublicRoute(context: ExecutionContext): Promise<boolean>;

  /**
   * Gets guard options from decorators or metadata
   * @param context - Execution context
   * @returns Promise resolving to guard options
   */
  protected abstract getGuardOptions(
    context: ExecutionContext,
  ): Promise<GenericGuardOptions>;

  /**
   * Attaches authenticated user to the request object
   * @param request - HTTP request object
   * @param user - Authenticated user
   */
  protected attachUserToRequest(request: TRequest, user: TUser): void {
    (request as GenericRequest).user = user;
  }

  /**
   * Validates user access against guard options
   * @param user - Authenticated user
   * @param options - Guard options
   * @param context - Execution context
   * @returns True if user has access
   */
  protected validateUserAccess(
    user: TUser,
    options: GenericGuardOptions,
    context: ExecutionContext,
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
   * Validates user roles against requirements
   * @param user - User to validate
   * @param options - Guard options containing role requirements
   * @returns True if user has required roles
   */
  protected validateRoles(user: TUser, options: GenericGuardOptions): boolean {
    if (!options.roles || options.roles.length === 0) {
      return true;
    }

    const userRoles = user.roles || [];
    const expandedRoles = this.expandRoles(userRoles);

    if (options.requireAll) {
      return options.roles.every((role) => expandedRoles.includes(role));
    }

    return options.roles.some((role) => expandedRoles.includes(role));
  }

  /**
   * Validates user permissions against requirements
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

    const userPermissions = user.permissions || [];

    if (options.requireAll) {
      return options.permissions.every((permission) =>
        userPermissions.includes(permission),
      );
    }

    return options.permissions.some((permission) =>
      userPermissions.includes(permission),
    );
  }

  /**
   * Expands user roles based on role hierarchy
   * Override this method to implement custom role hierarchy logic
   * @param userRoles - User's assigned roles
   * @returns Expanded roles including inherited ones
   */
  protected expandRoles(userRoles: string[]): string[] {
    // Default implementation returns roles as-is
    // Override in subclasses to implement role hierarchy
    return userRoles;
  }

  /**
   * Custom validation hook that can be overridden by subclasses
   * @param user - Authenticated user
   * @param request - HTTP request
   * @param context - Execution context
   * @returns Promise resolving to true if validation passes
   */
  protected customValidation(
    _user: TUser, // eslint-disable-line @typescript-eslint/no-unused-vars
    _request: TRequest, // eslint-disable-line @typescript-eslint/no-unused-vars
    _context: ExecutionContext, // eslint-disable-line @typescript-eslint/no-unused-vars
  ): Promise<boolean> {
    // Default implementation always allows
    // Override in subclasses for custom validation logic
    return Promise.resolve(true);
  }

  /**
   * Handles unauthorized access attempts
   * @param context - Execution context
   * @param message - Error message
   * @returns Always returns false (denies access)
   * @throws UnauthorizedException
   */
  protected handleUnauthorized(
    context: ExecutionContext,
    message: string,
  ): boolean {
    this.onAuthenticationFailure(context, message);
    throw new UnauthorizedException(message);
  }

  /**
   * Handles forbidden access attempts
   * @param context - Execution context
   * @param message - Error message
   * @returns Always returns false (denies access)
   * @throws ForbiddenException
   */
  protected handleForbidden(
    context: ExecutionContext,
    message: string,
  ): boolean {
    this.onAuthorizationFailure(context, message);
    throw new ForbiddenException(message);
  }

  /**
   * Handles general errors during authentication
   * @param context - Execution context
   * @param error - Error that occurred
   * @returns Always returns false (denies access)
   */
  protected handleError(context: ExecutionContext, error: unknown): boolean {
    this.onError(context, error);

    if (error instanceof UnauthorizedException) {
      throw error;
    }

    if (error instanceof ForbiddenException) {
      throw error;
    }

    // Default to unauthorized for unknown errors
    throw new UnauthorizedException('Authentication failed');
  }

  /**
   * Hook method called when authentication fails
   * Override in subclasses for custom logging/monitoring
   * @param context - Execution context
   * @param message - Failure message
   */
  protected onAuthenticationFailure(
    _context: ExecutionContext, // eslint-disable-line @typescript-eslint/no-unused-vars
    _message: string, // eslint-disable-line @typescript-eslint/no-unused-vars
  ): void {
    // Default implementation does nothing
    // Override in subclasses for logging, monitoring, etc.
  }

  /**
   * Hook method called when authorization fails
   * Override in subclasses for custom logging/monitoring
   * @param context - Execution context
   * @param message - Failure message
   */
  protected onAuthorizationFailure(
    _context: ExecutionContext, // eslint-disable-line @typescript-eslint/no-unused-vars
    _message: string, // eslint-disable-line @typescript-eslint/no-unused-vars
  ): void {
    // Default implementation does nothing
    // Override in subclasses for logging, monitoring, etc.
  }

  /**
   * Hook method called when an error occurs
   * Override in subclasses for custom error handling
   * @param context - Execution context
   * @param error - Error that occurred
   */
  protected onError(
    _context: ExecutionContext, // eslint-disable-line @typescript-eslint/no-unused-vars
    _error: unknown, // eslint-disable-line @typescript-eslint/no-unused-vars
  ): void {
    // Default implementation does nothing
    // Override in subclasses for logging, monitoring, etc.
  }
}
