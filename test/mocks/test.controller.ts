import {
  Controller,
  ForbiddenException,
  Get,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard, User } from '../../../src';
import { AuthUser } from '../../../src/types';
import { RolePermissionService } from './auth.mocks';

@Controller('test')
export class TestController {
  constructor(private readonly rolePermissionService: RolePermissionService) {}

  @Get('public')
  getPublic() {
    return { message: 'Public endpoint' };
  }

  @UseGuards(AuthGuard)
  @Get('protected')
  getProtected() {
    return { message: 'Protected endpoint' };
  }

  @UseGuards(AuthGuard)
  @Get('admin-only')
  getAdminOnly(@User() user: AuthUser) {
    if (!this.rolePermissionService.checkRoles(user.roles, ['admin'])) {
      throw new ForbiddenException('Insufficient permissions');
    }
    return { message: 'Admin only endpoint' };
  }

  @UseGuards(AuthGuard)
  @Get('permission-required')
  getPermissionRequired(@User() user: AuthUser) {
    if (
      !this.rolePermissionService.checkPermissions(
        user.permissions ?? [],
        'read:users',
      )
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }
    return { message: 'Permission required endpoint' };
  }

  @UseGuards(AuthGuard)
  @Get('multi-role')
  getMultiRole(@User() user: AuthUser) {
    if (
      !this.rolePermissionService.checkRoles(user.roles, ['admin', 'moderator'])
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }
    return { message: 'Multi role endpoint' };
  }

  @UseGuards(AuthGuard)
  @Post('admin-with-permission')
  postAdminWithPermission(@User() user: AuthUser) {
    if (!this.rolePermissionService.checkRoles(user.roles, ['admin'])) {
      throw new ForbiddenException('Insufficient role');
    }

    if (
      !this.rolePermissionService.checkPermissions(
        user.permissions ?? [],
        'write:users',
      )
    ) {
      throw new ForbiddenException('Insufficient permission');
    }

    return { message: 'Admin with permission endpoint' };
  }
}
