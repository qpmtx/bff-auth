import type { GenericUser } from '../types/generic.types';

/**
 * Checks if user has a specific role
 * @param user - User to check
 * @param role - Role to check for
 * @returns True if user has the role
 */
export const hasRole = <TUser extends GenericUser>(
  user: TUser,
  role: string,
): boolean => {
  return user.roles?.includes(role) ?? false;
};

/**
 * Checks if user has any of the specified roles
 * @param user - User to check
 * @param roles - Roles to check for
 * @returns True if user has any of the roles
 */
export const hasAnyRole = <TUser extends GenericUser>(
  user: TUser,
  roles: string[],
): boolean => {
  return roles.some((role) => hasRole(user, role));
};

/**
 * Checks if user has all of the specified roles
 * @param user - User to check
 * @param roles - Roles to check for
 * @returns True if user has all of the roles
 */
export const hasAllRoles = <TUser extends GenericUser>(
  user: TUser,
  roles: string[],
): boolean => {
  return roles.every((role) => hasRole(user, role));
};

/**
 * Checks if user has a specific permission
 * @param user - User to check
 * @param permission - Permission to check for
 * @returns True if user has the permission
 */
export const hasPermission = <TUser extends GenericUser>(
  user: TUser,
  permission: string,
): boolean => {
  return user.permissions?.includes(permission) ?? false;
};

/**
 * Checks if user has any of the specified permissions
 * @param user - User to check
 * @param permissions - Permissions to check for
 * @returns True if user has any of the permissions
 */
export const hasAnyPermission = <TUser extends GenericUser>(
  user: TUser,
  permissions: string[],
): boolean => {
  return permissions.some((permission) => hasPermission(user, permission));
};

/**
 * Checks if user has all of the specified permissions
 * @param user - User to check
 * @param permissions - Permissions to check for
 * @returns True if user has all of the permissions
 */
export const hasAllPermissions = <TUser extends GenericUser>(
  user: TUser,
  permissions: string[],
): boolean => {
  return permissions.every((permission) => hasPermission(user, permission));
};

/**
 * Expands user roles based on role hierarchy
 * @param userRoles - User's assigned roles
 * @param roleHierarchy - Role hierarchy configuration
 * @returns Expanded roles including inherited ones
 */
export const expandRoles = (
  userRoles: string[],
  roleHierarchy?: Record<string, string[]>,
): string[] => {
  if (!roleHierarchy) {
    return userRoles;
  }

  const expandedRoles = new Set(userRoles);

  for (const role of userRoles) {
    const inheritedRoles = roleHierarchy[role] || [];
    inheritedRoles.forEach((inherited) => expandedRoles.add(inherited));
  }

  return Array.from(expandedRoles);
};

/**
 * Gets user display name for logging/UI purposes
 * @param user - User to get display name for
 * @returns User's display name
 */
export const getUserDisplayName = <TUser extends GenericUser>(
  user: TUser,
): string => {
  return user.username ?? user.email ?? user.id;
};

/**
 * Sanitizes user object by removing sensitive fields
 * @param user - User to sanitize
 * @param fieldsToExclude - Fields to exclude from sanitized user
 * @returns Sanitized user object
 */
export const sanitizeUser = <TUser extends GenericUser>(
  user: TUser,
  fieldsToExclude: (keyof TUser)[] = [],
): Partial<TUser> => {
  const sanitized = { ...user };
  fieldsToExclude.forEach((field) => delete sanitized[field]);
  return sanitized;
};
