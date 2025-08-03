import { SetMetadata } from '@nestjs/common';
import { PERMISSIONS_KEY } from './metadata.constants';

/**
 * Decorator to specify required permissions for route access
 * @param permissions - Array of permission names that are required to access the route
 * @returns MethodDecorator - NestJS metadata decorator
 *
 * @example
 * ```typescript
 * @Permissions('read:users', 'write:users')
 * @Post('/users')
 * createUser() {
 *   return 'Only users with read:users and write:users permissions can access this';
 * }
 * ```
 */
export const Permissions = (...permissions: string[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
