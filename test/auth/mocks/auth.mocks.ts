import { Injectable } from '@nestjs/common';

@Injectable()
export class RolePermissionService {
  checkRoles(userRoles: string[], requiredRoles: string[]): boolean {
    if (!requiredRoles || requiredRoles.length === 0) return true;
    return requiredRoles.some(role => userRoles.includes(role));
  }

  checkPermissions(
    userPermissions: string[],
    requiredPermission: string,
  ): boolean {
    if (!requiredPermission) return true;
    return userPermissions.includes(requiredPermission);
  }
}
