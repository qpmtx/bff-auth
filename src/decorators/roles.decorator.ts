import { SetMetadata } from '@nestjs/common';
import { ROLES_KEY } from './metadata.constants';

/**
 * Decorator to specify required roles for route access
 * @param roles - Array of role names that are allowed to access the route
 * @returns MethodDecorator - NestJS metadata decorator
 *
 * @example
 * ```typescript
 * @QPMTXRoles('admin', 'moderator')
 * @Get('/protected')
 * getProtectedResource() {
 *   return 'Only admins and moderators can access this';
 * }
 * ```
 */
export const QPMTXRoles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

// Backward compatibility alias
/** @deprecated Use QPMTXRoles instead */
export const Roles = QPMTXRoles;
