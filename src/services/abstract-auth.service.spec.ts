import type { ExecutionContext } from '@nestjs/common';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import type {
  QPMTXGenericGuardOptions,
  QPMTXGenericJwtPayload,
  QPMTXGenericRequest,
  QPMTXGenericUser,
} from '../types/generic.types';
import { QPMTXAbstractAuthService } from './abstract-auth.service';

// Concrete implementation for testing
class TestAuthService extends QPMTXAbstractAuthService<
  QPMTXGenericUser,
  QPMTXGenericJwtPayload,
  QPMTXGenericRequest
> {
  async validateToken(token: string): Promise<QPMTXGenericUser | null> {
    if (token === 'valid-token') {
      return {
        id: 'user-123',
        roles: ['user'],
        permissions: ['read:posts'],
      };
    }
    return null;
  }

  async validateUser(
    payload: QPMTXGenericJwtPayload,
  ): Promise<QPMTXGenericUser | null> {
    if (payload.sub === 'valid-user') {
      return {
        id: payload.sub,
        email: payload.email,
        username: payload.username,
        roles: payload.roles,
        permissions: payload.permissions,
      };
    }
    return null;
  }

  async generateToken(user: QPMTXGenericUser): Promise<string> {
    return `token-for-${user.id}`;
  }

  async refreshToken(token: string): Promise<string> {
    return `refreshed-${token}`;
  }

  extractTokenFromRequest(request: QPMTXGenericRequest): string | null {
    const authHeader = request.headers.authorization as string;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return null;
  }
}

describe('QPMTXAbstractAuthService', () => {
  let service: TestAuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TestAuthService],
    }).compile();

    service = module.get<TestAuthService>(TestAuthService);
  });

  describe('abstract methods implementation', () => {
    it('should validate valid token', async () => {
      const result = await service.validateToken('valid-token');
      expect(result).toEqual({
        id: 'user-123',
        roles: ['user'],
        permissions: ['read:posts'],
      });
    });

    it('should return null for invalid token', async () => {
      const result = await service.validateToken('invalid-token');
      expect(result).toBeNull();
    });

    it('should validate user from payload', async () => {
      const payload: QPMTXGenericJwtPayload = {
        sub: 'valid-user',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['admin'],
        permissions: ['write:posts'],
      };

      const result = await service.validateUser(payload);
      expect(result).toEqual({
        id: 'valid-user',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['admin'],
        permissions: ['write:posts'],
      });
    });

    it('should generate token for user', async () => {
      const user: QPMTXGenericUser = {
        id: 'user-123',
        roles: ['user'],
      };

      const result = await service.generateToken(user);
      expect(result).toBe('token-for-user-123');
    });

    it('should refresh token', async () => {
      const result = await service.refreshToken('old-token');
      expect(result).toBe('refreshed-old-token');
    });

    it('should extract token from request', () => {
      const request: QPMTXGenericRequest = {
        headers: {
          authorization: 'Bearer test-token',
        },
      };

      const result = service.extractTokenFromRequest(request);
      expect(result).toBe('test-token');
    });

    it('should return null when no authorization header', () => {
      const request: QPMTXGenericRequest = {
        headers: {},
      };

      const result = service.extractTokenFromRequest(request);
      expect(result).toBeNull();
    });
  });

  describe('hasRole', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['admin', 'user'],
    };

    it('should return true when user has role', () => {
      const result = service.hasRole(user, 'admin');
      expect(result).toBe(true);
    });

    it('should return false when user does not have role', () => {
      const result = service.hasRole(user, 'moderator');
      expect(result).toBe(false);
    });

    it('should return false when user has no roles', () => {
      const userWithoutRoles: QPMTXGenericUser = {
        id: 'user-123',
        roles: [],
      };
      const result = service.hasRole(userWithoutRoles, 'admin');
      expect(result).toBe(false);
    });

    it('should handle undefined roles gracefully', () => {
      const userWithUndefinedRoles = {
        id: 'user-123',
        roles: undefined as unknown as string[],
      };
      const result = service.hasRole(userWithUndefinedRoles, 'admin');
      expect(result).toBe(false);
    });
  });

  describe('hasAnyRole', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['admin', 'user'],
    };

    it('should return true when user has any of the roles', () => {
      const result = service.hasAnyRole(user, ['moderator', 'admin']);
      expect(result).toBe(true);
    });

    it('should return false when user has none of the roles', () => {
      const result = service.hasAnyRole(user, ['moderator', 'guest']);
      expect(result).toBe(false);
    });

    it('should return false for empty roles array', () => {
      const result = service.hasAnyRole(user, []);
      expect(result).toBe(false);
    });
  });

  describe('hasAllRoles', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['admin', 'user', 'moderator'],
    };

    it('should return true when user has all required roles', () => {
      const result = service.hasAllRoles(user, ['admin', 'user']);
      expect(result).toBe(true);
    });

    it('should return false when user is missing some roles', () => {
      const result = service.hasAllRoles(user, ['admin', 'guest']);
      expect(result).toBe(false);
    });

    it('should return true for empty roles array', () => {
      const result = service.hasAllRoles(user, []);
      expect(result).toBe(true);
    });
  });

  describe('hasPermission', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['user'],
      permissions: ['read:posts', 'write:posts'],
    };

    it('should return true when user has permission', () => {
      const result = service.hasPermission(user, 'read:posts');
      expect(result).toBe(true);
    });

    it('should return false when user does not have permission', () => {
      const result = service.hasPermission(user, 'delete:posts');
      expect(result).toBe(false);
    });

    it('should return false when user has no permissions', () => {
      const userWithoutPermissions: QPMTXGenericUser = {
        id: 'user-123',
        roles: ['user'],
      };
      const result = service.hasPermission(
        userWithoutPermissions,
        'read:posts',
      );
      expect(result).toBe(false);
    });
  });

  describe('hasAnyPermission', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['user'],
      permissions: ['read:posts', 'write:posts'],
    };

    it('should return true when user has any of the permissions', () => {
      const result = service.hasAnyPermission(user, [
        'delete:posts',
        'read:posts',
      ]);
      expect(result).toBe(true);
    });

    it('should return false when user has none of the permissions', () => {
      const result = service.hasAnyPermission(user, [
        'delete:posts',
        'admin:all',
      ]);
      expect(result).toBe(false);
    });

    it('should return false for empty permissions array', () => {
      const result = service.hasAnyPermission(user, []);
      expect(result).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['user'],
      permissions: ['read:posts', 'write:posts', 'edit:posts'],
    };

    it('should return true when user has all required permissions', () => {
      const result = service.hasAllPermissions(user, [
        'read:posts',
        'write:posts',
      ]);
      expect(result).toBe(true);
    });

    it('should return false when user is missing some permissions', () => {
      const result = service.hasAllPermissions(user, [
        'read:posts',
        'delete:posts',
      ]);
      expect(result).toBe(false);
    });

    it('should return true for empty permissions array', () => {
      const result = service.hasAllPermissions(user, []);
      expect(result).toBe(true);
    });
  });

  describe('expandRoles', () => {
    it('should return original roles when no hierarchy provided', () => {
      const userRoles = ['admin'];
      const result = service.expandRoles(userRoles);
      expect(result).toEqual(['admin']);
    });

    it('should expand roles based on hierarchy', () => {
      const userRoles = ['admin'];
      const roleHierarchy = {
        admin: ['moderator', 'user'],
        moderator: ['user'],
      };
      const result = service.expandRoles(userRoles, roleHierarchy);
      expect(result).toEqual(
        expect.arrayContaining(['admin', 'moderator', 'user']),
      );
      expect(result).toHaveLength(3);
    });

    it('should handle multiple user roles with hierarchy', () => {
      const userRoles = ['admin', 'editor'];
      const roleHierarchy = {
        admin: ['moderator', 'user'],
        editor: ['writer'],
        moderator: ['user'],
      };
      const result = service.expandRoles(userRoles, roleHierarchy);
      expect(result).toEqual(
        expect.arrayContaining([
          'admin',
          'editor',
          'moderator',
          'user',
          'writer',
        ]),
      );
    });

    it('should handle roles with no defined hierarchy', () => {
      const userRoles = ['custom-role'];
      const roleHierarchy = {
        admin: ['user'],
      };
      const result = service.expandRoles(userRoles, roleHierarchy);
      expect(result).toEqual(['custom-role']);
    });
  });

  describe('validateGuardOptions', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['admin', 'user'],
      permissions: ['read:posts', 'write:posts'],
    };

    it('should return true when no roles or permissions required', () => {
      const options: QPMTXGenericGuardOptions = {};
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(true);
    });

    it('should validate roles correctly', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin'],
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(true);
    });

    it('should validate permissions correctly', () => {
      const options: QPMTXGenericGuardOptions = {
        permissions: ['read:posts'],
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(true);
    });

    it('should require all roles and permissions when requireAll is true', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin'],
        permissions: ['read:posts'],
        requireAll: true,
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(true);
    });

    it('should fail when requireAll is true and user lacks role', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['super-admin'],
        permissions: ['read:posts'],
        requireAll: true,
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(false);
    });

    it('should fail when requireAll is true and user lacks permission', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin'],
        permissions: ['delete:posts'],
        requireAll: true,
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(false);
    });

    it('should use custom validator when provided', () => {
      const customValidator = jest.fn().mockReturnValue(true);
      const options: QPMTXGenericGuardOptions = {
        roles: ['super-admin'], // User doesn't have this role
        customValidator,
      };
      const mockContext = {} as ExecutionContext;

      const result = service.validateGuardOptions(user, options, mockContext);
      expect(result).toBe(true);
      expect(customValidator).toHaveBeenCalledWith(user, mockContext);
    });

    it('should pass with any role or permission when requireAll is false', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['super-admin'], // User doesn't have this
        permissions: ['read:posts'], // User has this
        requireAll: false,
      };
      const result = service.validateGuardOptions(user, options);
      expect(result).toBe(true);
    });
  });

  describe('getUserDisplayName', () => {
    it('should return username when available', () => {
      const user: QPMTXGenericUser = {
        id: 'user-123',
        username: 'john_doe',
        email: 'john@example.com',
        roles: ['user'],
      };
      const result = service.getUserDisplayName(user);
      expect(result).toBe('john_doe');
    });

    it('should return email when username not available', () => {
      const user: QPMTXGenericUser = {
        id: 'user-123',
        email: 'john@example.com',
        roles: ['user'],
      };
      const result = service.getUserDisplayName(user);
      expect(result).toBe('john@example.com');
    });

    it('should return id when neither username nor email available', () => {
      const user: QPMTXGenericUser = {
        id: 'user-123',
        roles: ['user'],
      };
      const result = service.getUserDisplayName(user);
      expect(result).toBe('user-123');
    });
  });

  describe('sanitizeUser', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      username: 'john_doe',
      email: 'john@example.com',
      roles: ['user'],
      permissions: ['read:posts'],
      custom: {
        password: 'secret123',
        apiKey: 'key123',
      },
    };

    it('should return user without excluded fields', () => {
      const result = service.sanitizeUser(user, ['custom']);
      expect(result).toEqual({
        id: 'user-123',
        username: 'john_doe',
        email: 'john@example.com',
        roles: ['user'],
        permissions: ['read:posts'],
      });
      expect(result.custom).toBeUndefined();
    });

    it('should return complete user when no fields excluded', () => {
      const result = service.sanitizeUser(user);
      expect(result).toEqual(user);
    });

    it('should handle multiple excluded fields', () => {
      const result = service.sanitizeUser(user, ['email', 'custom']);
      expect(result).toEqual({
        id: 'user-123',
        username: 'john_doe',
        roles: ['user'],
        permissions: ['read:posts'],
      });
      expect(result.email).toBeUndefined();
      expect(result.custom).toBeUndefined();
    });
  });

  describe('hook methods', () => {
    it('should call beforeTokenValidation hook', () => {
      const spy = jest.spyOn(service as any, 'beforeTokenValidation');
      const token = 'test-token';

      (service as any).beforeTokenValidation(token);
      expect(spy).toHaveBeenCalledWith(token);
    });

    it('should call afterUserValidation hook', () => {
      const spy = jest.spyOn(service as any, 'afterUserValidation');
      const user: QPMTXGenericUser = { id: 'user-123', roles: ['user'] };

      (service as any).afterUserValidation(user);
      expect(spy).toHaveBeenCalledWith(user);
    });

    it('should call onValidationFailure hook', () => {
      const spy = jest.spyOn(service as any, 'onValidationFailure');
      const error = new Error('Validation failed');
      const context = 'test-context';

      (service as any).onValidationFailure(error, context);
      expect(spy).toHaveBeenCalledWith(error, context);
    });
  });

  describe('validateRoles (private method)', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['admin', 'user'],
    };

    it('should return true when no roles required', () => {
      const options: QPMTXGenericGuardOptions = {};
      const result = (service as any).validateRoles(user, options);
      expect(result).toBe(true);
    });

    it('should validate roles with requireAll false', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin', 'moderator'],
        requireAll: false,
      };
      const result = (service as any).validateRoles(user, options);
      expect(result).toBe(true); // User has admin
    });

    it('should validate roles with requireAll true', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin', 'user'],
        requireAll: true,
      };
      const result = (service as any).validateRoles(user, options);
      expect(result).toBe(true); // User has both admin and user
    });

    it('should fail when requireAll true and user lacks roles', () => {
      const options: QPMTXGenericGuardOptions = {
        roles: ['admin', 'moderator'],
        requireAll: true,
      };
      const result = (service as any).validateRoles(user, options);
      expect(result).toBe(false); // User lacks moderator
    });
  });

  describe('validatePermissions (private method)', () => {
    const user: QPMTXGenericUser = {
      id: 'user-123',
      roles: ['user'],
      permissions: ['read:posts', 'write:posts'],
    };

    it('should return true when no permissions required', () => {
      const options: QPMTXGenericGuardOptions = {};
      const result = (service as any).validatePermissions(user, options);
      expect(result).toBe(true);
    });

    it('should validate permissions with requireAll false', () => {
      const options: QPMTXGenericGuardOptions = {
        permissions: ['read:posts', 'delete:posts'],
        requireAll: false,
      };
      const result = (service as any).validatePermissions(user, options);
      expect(result).toBe(true); // User has read:posts
    });

    it('should validate permissions with requireAll true', () => {
      const options: QPMTXGenericGuardOptions = {
        permissions: ['read:posts', 'write:posts'],
        requireAll: true,
      };
      const result = (service as any).validatePermissions(user, options);
      expect(result).toBe(true); // User has both permissions
    });

    it('should fail when requireAll true and user lacks permissions', () => {
      const options: QPMTXGenericGuardOptions = {
        permissions: ['read:posts', 'delete:posts'],
        requireAll: true,
      };
      const result = (service as any).validatePermissions(user, options);
      expect(result).toBe(false); // User lacks delete:posts
    });
  });
});
