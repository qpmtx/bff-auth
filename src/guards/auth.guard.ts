import {
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard as PassportAuthGuard } from '@nestjs/passport';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import {
  AUTH_OPTIONS_KEY,
  PERMISSIONS_KEY,
  PUBLIC_KEY,
  ROLES_KEY,
} from '../decorators/metadata.constants';
import {
  QPMTXAuthModuleConfig,
  QPMTXIAuthGuard,
  QPMTXIGuardConfig,
} from '../interfaces';
import {
  QPMTXAuthGuardOptions,
  QPMTXAuthUser,
  QPMTXBaseRequest,
} from '../types';
/**
 * Authentication guard that extends Passport JWT guard
 * Provides role-based and permission-based access control
 */
@Injectable()
export class QPMTXAuthGuard
  extends PassportAuthGuard('jwt')
  implements QPMTXIAuthGuard, QPMTXIGuardConfig
{
  /**
   * Creates an instance of QPMTXAuthGuard
   * @param reflector - NestJS Reflector for metadata access
   * @param config - Authentication module configuration
   */
  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    super();
  }

  /**
   * Determines if the current request should be allowed
   * @param context - Execution context containing request information
   * @returns Promise<boolean> - True if access is allowed
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const guardOptions = this.getGuardOptions(context);

    if (guardOptions.allowAnonymous) {
      return true;
    }

    try {
      const result = await super.canActivate(context);
      if (!result) {
        return false;
      }

      const request = context.switchToHttp().getRequest<QPMTXBaseRequest>();
      const user = request.user as QPMTXAuthUser;

      if (!user) {
        throw new UnauthorizedException(this.config.unauthorizedMessage);
      }

      return this.validateRolesAndPermissions(user, guardOptions);
    } catch (error) {
      return this.handleUnauthorized(context, error);
    }
  }

  /**
   * Extracts guard options from decorators
   * @param context - Execution context
   * @returns QPMTXAuthGuardOptions - Combined guard options
   */
  getGuardOptions(context: ExecutionContext): QPMTXAuthGuardOptions {
    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const permissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    const authOptions = this.reflector.getAllAndOverride<QPMTXAuthGuardOptions>(
      AUTH_OPTIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    return {
      roles: roles || authOptions?.roles,
      permissions: permissions || authOptions?.permissions,
      requireAll: authOptions?.requireAll ?? false,
      allowAnonymous: authOptions?.allowAnonymous ?? false,
    };
  }

  /**
   * Handles unauthorized access attempts
   * @param context - Execution context
   * @param error - Optional error object
   * @returns boolean - Always throws exception
   * @throws {UnauthorizedException}
   */
  handleUnauthorized(_context: ExecutionContext, error?: unknown): boolean {
    if (error instanceof ForbiddenException) {
      throw error;
    }
    throw new UnauthorizedException(
      this.config.unauthorizedMessage ?? 'Unauthorized',
    );
  }

  /**
   * Handles forbidden access attempts
   * @param context - Execution context
   * @param error - Optional error object
   * @returns boolean - Always throws exception
   * @throws {ForbiddenException}
   */

  handleForbidden(_context: ExecutionContext, _error?: unknown): boolean {
    throw new ForbiddenException(this.config.forbiddenMessage ?? 'Forbidden');
  }

  /**
   * Validates user roles and permissions against requirements
   * @param user - Authenticated user
   * @param options - Guard options with role/permission requirements
   * @returns boolean - True if user has required access
   */
  private validateRolesAndPermissions(
    user: QPMTXAuthUser,
    options: QPMTXAuthGuardOptions,
  ): boolean {
    if (!options.roles && !options.permissions) {
      return true;
    }

    const hasValidRoles = this.validateRoles(user, options);
    const hasValidPermissions = this.validatePermissions(user, options);

    if (options.requireAll) {
      return hasValidRoles && hasValidPermissions;
    }

    return hasValidRoles || hasValidPermissions;
  }

  /**
   * Validates user roles against required roles
   * @param user - Authenticated user
   * @param options - Guard options with role requirements
   * @returns boolean - True if user has required roles
   */
  private validateRoles(
    user: QPMTXAuthUser,
    options: QPMTXAuthGuardOptions,
  ): boolean {
    if (!options.roles || options.roles.length === 0) {
      return true;
    }

    const userRoles = user.roles || [];
    const expandedRoles = this.expandRoles(userRoles);

    if (options.requireAll) {
      return options.roles.every(role => expandedRoles.includes(role));
    }

    return options.roles.some(role => expandedRoles.includes(role));
  }

  /**
   * Validates user permissions against required permissions
   * @param user - Authenticated user
   * @param options - Guard options with permission requirements
   * @returns boolean - True if user has required permissions
   */
  private validatePermissions(
    user: QPMTXAuthUser,
    options: QPMTXAuthGuardOptions,
  ): boolean {
    if (!options.permissions || options.permissions.length === 0) {
      return true;
    }

    const userPermissions = user.permissions ?? [];

    if (options.requireAll) {
      return options.permissions.every(permission =>
        userPermissions.includes(permission),
      );
    }

    return options.permissions.some(permission =>
      userPermissions.includes(permission),
    );
  }

  /**
   * Expands user roles based on role hierarchy
   * @param userRoles - User's assigned roles
   * @returns string[] - Expanded roles including inherited ones
   */
  private expandRoles(userRoles: string[]): string[] {
    if (!this.config.roleHierarchy) {
      return userRoles;
    }

    const expandedRoles = new Set(userRoles);

    for (const role of userRoles) {
      const inheritedRoles = this.config.roleHierarchy[role] || [];
      inheritedRoles.forEach(inherited => expandedRoles.add(inherited));
    }

    return Array.from(expandedRoles);
  }
}

// Backward compatibility alias
/** @deprecated Use QPMTXAuthGuard instead */
export const AuthGuard = QPMTXAuthGuard;
