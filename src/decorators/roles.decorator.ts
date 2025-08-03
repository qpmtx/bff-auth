import { SetMetadata } from '@nestjs/common';
import { ROLES_KEY } from './metadata.constants';

/**
 * Decorator to specify required roles for route access
 * @param roles - Array of role names that are allowed to access the route
 * @returns MethodDecorator - NestJS metadata decorator
 *
 * @example
 * ```typescript
 * @Roles('admin', 'moderator')
 * @Get('/protected')
 * getProtectedResource() {
 *   return 'Only admins and moderators can access this';
 * }
 * ```
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
