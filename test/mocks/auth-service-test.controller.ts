import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import { QPMTXAuthGuardOptions, QPMTXUser } from '../../src';
import type { QPMTXGenericUser } from '../../src/types/generic.types';
import { QPMTXAuthGuard } from '../../src/guards/auth.guard';
import { ConcreteAuthService } from './concrete-auth.service';

@Controller('auth-service-test')
export class AuthServiceTestController {
  constructor(private readonly authService: ConcreteAuthService) {}

  @Post('generate-token')
  async generateToken(
    @Body() body: { userId: string; roles?: string[]; permissions?: string[] },
  ) {
    const user = await this.authService.createTestUser(
      body.userId,
      body.roles,
      body.permissions,
    );
    const token = await this.authService.generateToken(user);
    return { token, user };
  }

  @Post('refresh-token')
  async refreshToken(@Body() body: { token: string }) {
    try {
      const newToken = await this.authService.refreshToken(body.token);
      return { token: newToken };
    } catch (error) {
      return { error: error.message };
    }
  }

  @Get('validate-token')
  async validateToken(@Query('token') token: string) {
    const user = await this.authService.validateToken(token);
    return { user, isValid: !!user };
  }

  @UseGuards(QPMTXAuthGuard)
  @Get('protected')
  getProtected(@QPMTXUser() user: QPMTXGenericUser) {
    return {
      message: 'Access granted to protected resource',
      user: this.authService.sanitizeUser(user, ['permissions']),
      displayName: this.authService.getUserDisplayName(user),
    };
  }

  @UseGuards(QPMTXAuthGuard)
  @Get('role-check')
  checkRoles(@QPMTXUser() user: QPMTXGenericUser, @Query('role') role: string) {
    const hasRole = this.authService.hasRole(user, role);
    const hasAnyRole = this.authService.hasAnyRole(user, [role, 'admin']);
    const hasAllRoles = this.authService.hasAllRoles(user, ['user', role]);

    return {
      user: user.id,
      requestedRole: role,
      hasRole,
      hasAnyRole,
      hasAllRoles,
      userRoles: user.roles,
    };
  }

  @UseGuards(QPMTXAuthGuard)
  @Get('permission-check')
  checkPermissions(
    @QPMTXUser() user: QPMTXGenericUser,
    @Query('permission') permission: string,
  ) {
    const hasPermission = this.authService.hasPermission(user, permission);
    const hasAnyPermission = this.authService.hasAnyPermission(user, [
      permission,
      'admin:all',
    ]);
    const hasAllPermissions = this.authService.hasAllPermissions(user, [
      'read:basic',
      permission,
    ]);

    return {
      user: user.id,
      requestedPermission: permission,
      hasPermission,
      hasAnyPermission,
      hasAllPermissions,
      userPermissions: user.permissions,
    };
  }

  @UseGuards(QPMTXAuthGuard)
  @Post('validate-access')
  async validateAccess(
    @QPMTXUser() user: QPMTXGenericUser,
    @Body() options: QPMTXAuthGuardOptions,
  ) {
    const hasAccess = await this.authService.validateUserAccess(user, options);

    return {
      user: user.id,
      options,
      hasAccess,
      userRoles: user.roles,
      userPermissions: user.permissions,
    };
  }

  @Get('extract-token')
  extractToken(@Req() request: Request) {
    const token = this.authService.extractTokenFromRequest(request as any);
    return {
      token,
      hasToken: !!token,
      headers: {
        authorization: request.headers.authorization,
      },
      query: request.query,
    };
  }

  @UseGuards(QPMTXAuthGuard)
  @Get('role-hierarchy-test')
  testRoleHierarchy(
    @QPMTXUser() user: QPMTXGenericUser,
    @Query('checkRole') checkRole: string,
  ) {
    // Get the original roles from token (before expansion)
    // We'll simulate this by getting the base role for an admin user
    let originalRoles = ['admin']; // For testing purposes
    if (user.roles.includes('user') && !user.roles.includes('admin')) {
      originalRoles = ['user'];
    }

    // Test role expansion
    const expandedRoles = this.authService.expandRoles(originalRoles, {
      admin: ['moderator', 'user'],
      moderator: ['user'],
      editor: ['contributor'],
    });

    const hasRole = this.authService.hasRole(user, checkRole);

    return {
      user: user.id,
      originalRoles,
      expandedRoles,
      checkRole,
      hasRole,
      message: hasRole
        ? `User has role '${checkRole}' (either directly or through hierarchy)`
        : `User does not have role '${checkRole}'`,
    };
  }

  @UseGuards(QPMTXAuthGuard)
  @Get('user-display-info')
  getUserDisplayInfo(@QPMTXUser() user: QPMTXGenericUser) {
    return {
      displayName: this.authService.getUserDisplayName(user),
      sanitizedUser: this.authService.sanitizeUser(user, ['permissions']),
      fullUser: user,
    };
  }

  @Post('test-hooks')
  async testHooks(@Body() body: { token: string }) {
    // This will trigger the hook methods
    const user = await this.authService.validateToken(body.token);

    if (!user) {
      // Trigger validation failure hook
      (this.authService as any).onValidationFailure(
        new Error('Token validation failed'),
        'test-hooks-endpoint',
      );
      return { success: false, message: 'Token validation failed' };
    }

    return {
      success: true,
      user,
      message: 'Hooks executed successfully',
    };
  }

  @Get('health')
  healthCheck() {
    return {
      status: 'ok',
      service: 'ConcreteAuthService',
      timestamp: new Date().toISOString(),
    };
  }
}
