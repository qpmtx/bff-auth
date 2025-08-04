import type { ExecutionContext } from '@nestjs/common';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import { PUBLIC_KEY } from '../decorators/metadata.constants';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import type { QPMTXAuthGuardOptions, QPMTXAuthUser } from '../types';
import { QPMTXAuthGuard } from './auth.guard';

describe('QPMTXAuthGuard', () => {
  let guard: QPMTXAuthGuard;
  let reflector: Reflector;
  let mockConfig: QPMTXAuthModuleConfig;

  const mockExecutionContext = (user?: QPMTXAuthUser) => {
    const mockRequest = {
      user,
      headers: {},
    };

    return {
      switchToHttp: () => ({
        getRequest: () => mockRequest,
      }),
      getHandler: jest.fn(),
      getClass: jest.fn(),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    mockConfig = {
      jwt: {
        secret: 'test-secret',
      },
      defaultRoles: ['user'],
      roleHierarchy: {
        admin: ['moderator', 'user'],
        moderator: ['user'],
      },
      unauthorizedMessage: 'Custom unauthorized message',
      forbiddenMessage: 'Custom forbidden message',
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: QPMTXAuthGuard,
          useFactory: (reflector: Reflector, config: QPMTXAuthModuleConfig) => {
            return new QPMTXAuthGuard(reflector, config);
          },
          inject: [Reflector, AUTH_MODULE_CONFIG],
        },
        Reflector,
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
      ],
    }).compile();

    guard = module.get<QPMTXAuthGuard>(QPMTXAuthGuard);
    reflector = module.get<Reflector>(Reflector);
  });

  describe('canActivate', () => {
    it('should allow access to public routes', async () => {
      const context = mockExecutionContext();
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);

      expect(reflector.getAllAndOverride).toHaveBeenCalledWith(PUBLIC_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);
    });

    it('should allow access when allowAnonymous is true', async () => {
      const context = mockExecutionContext();
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValueOnce(false) // PUBLIC_KEY
        .mockReturnValueOnce(null) // ROLES_KEY
        .mockReturnValueOnce(null) // PERMISSIONS_KEY
        .mockReturnValueOnce({ allowAnonymous: true }); // AUTH_OPTIONS_KEY

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('getGuardOptions', () => {
    it('should extract roles from metadata', () => {
      const context = mockExecutionContext();
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValueOnce(['admin']) // ROLES_KEY
        .mockReturnValueOnce(null) // PERMISSIONS_KEY
        .mockReturnValueOnce(null); // AUTH_OPTIONS_KEY

      const options = guard.getGuardOptions(context);

      expect(options.roles).toEqual(['admin']);
    });

    it('should extract permissions from metadata', () => {
      const context = mockExecutionContext();
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValueOnce(null) // ROLES_KEY
        .mockReturnValueOnce(['read:users']) // PERMISSIONS_KEY
        .mockReturnValueOnce(null); // AUTH_OPTIONS_KEY

      const options = guard.getGuardOptions(context);

      expect(options.permissions).toEqual(['read:users']);
    });

    it('should merge auth options with individual decorators', () => {
      const context = mockExecutionContext();
      const authOptions: QPMTXAuthGuardOptions = {
        roles: ['user'],
        requireAll: true,
      };

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValueOnce(['admin']) // ROLES_KEY (should override authOptions)
        .mockReturnValueOnce(null) // PERMISSIONS_KEY
        .mockReturnValueOnce(authOptions); // AUTH_OPTIONS_KEY

      const options = guard.getGuardOptions(context);

      expect(options.roles).toEqual(['admin']); // Individual decorator takes precedence
      expect(options.requireAll).toBe(true);
    });
  });

  describe('validateRoles', () => {
    const user: QPMTXAuthUser = {
      id: 'user-123',
      roles: ['admin'],
    };

    it('should return true when no roles are required', () => {
      const options: QPMTXAuthGuardOptions = {};
      const result = (
        guard as unknown as {
          validateRoles: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validateRoles(user, options);

      expect(result).toBe(true);
    });

    it('should validate user roles correctly', () => {
      const options: QPMTXAuthGuardOptions = {
        roles: ['admin'],
      };
      const result = (
        guard as unknown as {
          validateRoles: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validateRoles(user, options);

      expect(result).toBe(true);
    });

    it('should handle role hierarchy', () => {
      const options: QPMTXAuthGuardOptions = {
        roles: ['user'], // admin should inherit user role
      };
      const result = (
        guard as unknown as {
          validateRoles: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validateRoles(user, options);

      expect(result).toBe(true);
    });

    it('should require all roles when requireAll is true', () => {
      const userWithMultipleRoles: QPMTXAuthUser = {
        id: 'user-123',
        roles: ['admin', 'moderator'],
      };
      const options: QPMTXAuthGuardOptions = {
        roles: ['admin', 'moderator'],
        requireAll: true,
      };
      const result = (
        guard as unknown as {
          validateRoles: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validateRoles(userWithMultipleRoles, options);

      expect(result).toBe(true);
    });
  });

  describe('validatePermissions', () => {
    const user: QPMTXAuthUser = {
      id: 'user-123',
      roles: ['user'],
      permissions: ['read:users', 'write:posts'],
    };

    it('should return true when no permissions are required', () => {
      const options: QPMTXAuthGuardOptions = {};
      const result = (
        guard as unknown as {
          validatePermissions: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validatePermissions(user, options);

      expect(result).toBe(true);
    });

    it('should validate user permissions correctly', () => {
      const options: QPMTXAuthGuardOptions = {
        permissions: ['read:users'],
      };
      const result = (
        guard as unknown as {
          validatePermissions: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validatePermissions(user, options);

      expect(result).toBe(true);
    });

    it('should handle missing permissions', () => {
      const userWithoutPermissions: QPMTXAuthUser = {
        id: 'user-123',
        roles: ['user'],
      };
      const options: QPMTXAuthGuardOptions = {
        permissions: ['read:users'],
      };
      const result = (
        guard as unknown as {
          validatePermissions: (
            user: QPMTXAuthUser,
            options: QPMTXAuthGuardOptions,
          ) => boolean;
        }
      ).validatePermissions(userWithoutPermissions, options);

      expect(result).toBe(false);
    });
  });

  describe('expandRoles', () => {
    it('should expand roles based on hierarchy', () => {
      const userRoles = ['admin'];
      const expandedRoles = (
        guard as unknown as { expandRoles: (roles: string[]) => string[] }
      ).expandRoles(userRoles);

      expect(expandedRoles).toEqual(
        expect.arrayContaining(['admin', 'moderator', 'user']),
      );
    });

    it('should return original roles when no hierarchy is defined', () => {
      mockConfig.roleHierarchy = undefined;
      const userRoles = ['admin'];
      const expandedRoles = (
        guard as unknown as { expandRoles: (roles: string[]) => string[] }
      ).expandRoles(userRoles);

      expect(expandedRoles).toEqual(['admin']);
    });
  });

  describe('handleUnauthorized', () => {
    it('should throw UnauthorizedException with custom message', () => {
      const context = mockExecutionContext();

      expect(() => guard.handleUnauthorized(context)).toThrow(
        new UnauthorizedException('Custom unauthorized message'),
      );
    });

    it('should re-throw ForbiddenException', () => {
      const context = mockExecutionContext();
      const forbiddenError = new ForbiddenException('Access denied');

      expect(() => guard.handleUnauthorized(context, forbiddenError)).toThrow(
        forbiddenError,
      );
    });
  });

  describe('handleForbidden', () => {
    it('should throw ForbiddenException with custom message', () => {
      const context = mockExecutionContext();

      expect(() => guard.handleForbidden(context)).toThrow(
        new ForbiddenException('Custom forbidden message'),
      );
    });
  });
});
