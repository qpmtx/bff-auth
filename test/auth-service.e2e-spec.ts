import type { INestApplication } from '@nestjs/common';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { QPMTXAuthModule } from '../src/modules/auth.module';
import { AuthServiceTestController } from './mocks/auth-service-test.controller';
import {
  ConcreteAuthService,
  TEST_JWT_SECRET,
} from './mocks/concrete-auth.service';

describe('ConcreteAuthService E2E', () => {
  let app: INestApplication;
  let _authService: ConcreteAuthService;
  let moduleRef: TestingModule;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [
        QPMTXAuthModule.forRoot({
          globalGuard: false, // We'll use guards selectively
          jwt: {
            secret: TEST_JWT_SECRET,
          },
        }),
      ],
      controllers: [AuthServiceTestController],
      providers: [ConcreteAuthService],
    }).compile();

    app = moduleRef.createNestApplication();
    _authService = moduleRef.get<ConcreteAuthService>(ConcreteAuthService);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const server = () => app.getHttpServer();

  describe('Health Check', () => {
    it('should return health status', () => {
      return request(server())
        .get('/auth-service-test/health')
        .expect(200)
        .expect(res => {
          expect(res.body).toMatchObject({
            status: 'ok',
            service: 'ConcreteAuthService',
          });
          expect(res.body.timestamp).toBeDefined();
        });
    });
  });

  describe('Token Generation and Validation', () => {
    let testToken: string;
    let _adminToken: string;

    it('should generate token for user', async () => {
      const response = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'test-user-123',
          roles: ['user'],
          permissions: ['read:posts'],
        })
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toMatchObject({
        id: 'test-user-123',
        roles: ['user'],
        permissions: ['read:posts'],
      });

      testToken = response.body.token;
    });

    it('should generate token for admin user', async () => {
      const response = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'admin-user',
          roles: ['admin'],
          permissions: ['admin:all'],
        })
        .expect(201);

      _adminToken = response.body.token;
      expect(response.body.user.roles).toEqual(['admin', 'moderator', 'user']); // Role hierarchy expansion
    });

    it('should validate valid token', () => {
      return request(server())
        .get('/auth-service-test/validate-token')
        .query({ token: testToken })
        .expect(200)
        .expect(res => {
          expect(res.body.isValid).toBe(true);
          expect(res.body.user).toMatchObject({
            id: 'test-user-123',
            email: 'test-user-123@test.com',
            username: 'test-user-123',
            roles: ['user'],
          });
        });
    });

    it('should return invalid for malformed token', () => {
      return request(server())
        .get('/auth-service-test/validate-token')
        .query({ token: 'invalid-token' })
        .expect(200)
        .expect(res => {
          expect(res.body.isValid).toBe(false);
          expect(res.body.user).toBeNull();
        });
    });

    it('should refresh token', async () => {
      const response = await request(server())
        .post('/auth-service-test/refresh-token')
        .send({ token: testToken })
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body.token).not.toBe(testToken);

      // Validate the new token
      const validateResponse = await request(server())
        .get('/auth-service-test/validate-token')
        .query({ token: response.body.token })
        .expect(200);

      expect(validateResponse.body.isValid).toBe(true);
      expect(validateResponse.body.user.id).toBe('test-user-123');
    });

    it('should handle refresh token error', () => {
      return request(server())
        .post('/auth-service-test/refresh-token')
        .send({ token: 'invalid-token' })
        .expect(201)
        .expect(res => {
          expect(res.body).toHaveProperty('error');
        });
    });
  });

  describe('Token Extraction', () => {
    it('should extract token from Authorization header', () => {
      return request(server())
        .get('/auth-service-test/extract-token')
        .set('Authorization', 'Bearer test-token-123')
        .expect(200)
        .expect(res => {
          expect(res.body.token).toBe('test-token-123');
          expect(res.body.hasToken).toBe(true);
          expect(res.body.headers.authorization).toBe('Bearer test-token-123');
        });
    });

    it('should extract token from query parameter', () => {
      return request(server())
        .get('/auth-service-test/extract-token')
        .query({ token: 'query-token-456' })
        .expect(200)
        .expect(res => {
          expect(res.body.token).toBe('query-token-456');
          expect(res.body.hasToken).toBe(true);
        });
    });

    it('should return null when no token present', () => {
      return request(server())
        .get('/auth-service-test/extract-token')
        .expect(200)
        .expect(res => {
          expect(res.body.token).toBeNull();
          expect(res.body.hasToken).toBe(false);
        });
    });
  });

  describe('Protected Endpoints', () => {
    let userToken: string;
    let _adminToken: string;

    beforeAll(async () => {
      // Generate tokens for testing
      const userResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'regular-user',
          roles: ['user'],
          permissions: ['read:posts', 'write:posts'],
        });
      userToken = userResponse.body.token;

      const adminResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'admin-user',
          roles: ['admin'],
          permissions: ['admin:all'],
        });
      _adminToken = adminResponse.body.token;
    });

    it('should deny access without token', () => {
      return request(server()).get('/auth-service-test/protected').expect(401);
    });

    it('should allow access with valid token', () => {
      return request(server())
        .get('/auth-service-test/protected')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.message).toBe('Access granted to protected resource');
          expect(res.body.user.id).toBe('regular-user');
          expect(res.body.displayName).toBe('regular-user');
        });
    });

    it('should sanitize user data', () => {
      return request(server())
        .get('/auth-service-test/protected')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          // Permissions should be sanitized (removed)
          expect(res.body.user.permissions).toBeUndefined();
          expect(res.body.user.id).toBe('regular-user');
          expect(res.body.user.roles).toBeDefined();
        });
    });
  });

  describe('Role Checking', () => {
    let userToken: string;
    let _adminToken: string;

    beforeAll(async () => {
      const userResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'role-test-user',
          roles: ['user'],
          permissions: [],
        });
      userToken = userResponse.body.token;

      const adminResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'role-test-admin',
          roles: ['admin'],
          permissions: [],
        });
      _adminToken = adminResponse.body.token;
    });

    it('should check user roles correctly', () => {
      return request(server())
        .get('/auth-service-test/role-check')
        .query({ role: 'user' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasRole).toBe(true);
          expect(res.body.hasAnyRole).toBe(true);
          expect(res.body.hasAllRoles).toBe(true);
          expect(res.body.userRoles).toContain('user');
        });
    });

    it('should handle role not present', () => {
      return request(server())
        .get('/auth-service-test/role-check')
        .query({ role: 'admin' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasRole).toBe(false);
          expect(res.body.hasAnyRole).toBe(false); // User doesn't have admin role
          expect(res.body.hasAllRoles).toBe(false);
        });
    });

    it('should check admin roles with hierarchy', () => {
      return request(server())
        .get('/auth-service-test/role-check')
        .query({ role: 'user' })
        .set('Authorization', `Bearer ${_adminToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasRole).toBe(true); // Admin inherits user role
          expect(res.body.hasAnyRole).toBe(true);
          expect(res.body.userRoles).toEqual(['admin', 'moderator', 'user']);
        });
    });
  });

  describe('Permission Checking', () => {
    let userToken: string;

    beforeAll(async () => {
      const userResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'permission-test-user',
          roles: ['user'],
          permissions: ['read:posts', 'write:posts'],
        });
      userToken = userResponse.body.token;
    });

    it('should check user permissions correctly', () => {
      return request(server())
        .get('/auth-service-test/permission-check')
        .query({ permission: 'read:posts' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasPermission).toBe(true);
          expect(res.body.hasAnyPermission).toBe(true);
          expect(res.body.userPermissions).toContain('read:posts');
        });
    });

    it('should handle permission not present', () => {
      return request(server())
        .get('/auth-service-test/permission-check')
        .query({ permission: 'delete:posts' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasPermission).toBe(false);
          expect(res.body.hasAnyPermission).toBe(false); // User doesn't have admin:all
          expect(res.body.hasAllPermissions).toBe(false);
        });
    });
  });

  describe('Access Validation', () => {
    let userToken: string;
    let _adminToken: string;

    beforeAll(async () => {
      const userResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'access-test-user',
          roles: ['user'],
          permissions: ['read:posts'],
        });
      userToken = userResponse.body.token;

      const adminResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'access-test-admin',
          roles: ['admin'],
          permissions: ['admin:all'],
        });
      _adminToken = adminResponse.body.token;
    });

    it('should validate access with role requirements', () => {
      return request(server())
        .post('/auth-service-test/validate-access')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          roles: ['user'],
          requireAll: false,
        })
        .expect(201)
        .expect(res => {
          expect(res.body.hasAccess).toBe(true);
        });
    });

    it('should validate access with permission requirements', () => {
      return request(server())
        .post('/auth-service-test/validate-access')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          permissions: ['read:posts'],
          requireAll: false,
        })
        .expect(201)
        .expect(res => {
          expect(res.body.hasAccess).toBe(true);
        });
    });

    it('should deny access when requirements not met', () => {
      return request(server())
        .post('/auth-service-test/validate-access')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          roles: ['admin'],
          permissions: ['admin:all'],
          requireAll: true,
        })
        .expect(201)
        .expect(res => {
          expect(res.body.hasAccess).toBe(false);
        });
    });

    it('should allow access when any requirement met (requireAll: false)', () => {
      return request(server())
        .post('/auth-service-test/validate-access')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          roles: ['admin'], // User doesn't have this
          permissions: ['read:posts'], // User has this
          requireAll: false,
        })
        .expect(201)
        .expect(res => {
          expect(res.body.hasAccess).toBe(true);
        });
    });

    it('should validate admin access with hierarchy', () => {
      return request(server())
        .post('/auth-service-test/validate-access')
        .set('Authorization', `Bearer ${_adminToken}`)
        .send({
          roles: ['user'], // Admin inherits user role
          requireAll: true,
        })
        .expect(201)
        .expect(res => {
          expect(res.body.hasAccess).toBe(true);
        });
    });
  });

  describe('Role Hierarchy', () => {
    let _adminToken: string;

    beforeAll(async () => {
      const adminResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'hierarchy-test-admin',
          roles: ['admin'],
          permissions: [],
        });
      _adminToken = adminResponse.body.token;
    });

    it('should demonstrate role hierarchy expansion', () => {
      return request(server())
        .get('/auth-service-test/role-hierarchy-test')
        .query({ checkRole: 'user' })
        .set('Authorization', `Bearer ${_adminToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.originalRoles).toEqual(['admin']);
          expect(res.body.expandedRoles).toEqual([
            'admin',
            'moderator',
            'user',
          ]);
          expect(res.body.hasRole).toBe(true);
          expect(res.body.message).toContain('User has role');
        });
    });

    it('should handle non-inherited roles', () => {
      return request(server())
        .get('/auth-service-test/role-hierarchy-test')
        .query({ checkRole: 'editor' })
        .set('Authorization', `Bearer ${_adminToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.hasRole).toBe(false);
          expect(res.body.message).toContain('does not have role');
        });
    });
  });

  describe('User Display Information', () => {
    let userToken: string;

    beforeAll(async () => {
      const userResponse = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'display-test-user',
          roles: ['user'],
          permissions: ['read:posts', 'write:posts'],
        });
      userToken = userResponse.body.token;
    });

    it('should get user display information', () => {
      return request(server())
        .get('/auth-service-test/user-display-info')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body.displayName).toBe('display-test-user');
          expect(res.body.sanitizedUser.permissions).toBeUndefined();
          expect(res.body.sanitizedUser.id).toBe('display-test-user');
          expect(res.body.fullUser.permissions).toEqual([
            'read:posts',
            'write:posts',
          ]);
        });
    });
  });

  describe('Hook Methods', () => {
    let validToken: string;

    beforeAll(async () => {
      const response = await request(server())
        .post('/auth-service-test/generate-token')
        .send({
          userId: 'hook-test-user',
          roles: ['user'],
          permissions: [],
        });
      validToken = response.body.token;
    });

    it('should execute hooks successfully with valid token', () => {
      return request(server())
        .post('/auth-service-test/test-hooks')
        .send({ token: validToken })
        .expect(201)
        .expect(res => {
          expect(res.body.success).toBe(true);
          expect(res.body.user.id).toBe('hook-test-user');
          expect(res.body.message).toBe('Hooks executed successfully');
        });
    });

    it('should trigger validation failure hook with invalid token', () => {
      return request(server())
        .post('/auth-service-test/test-hooks')
        .send({ token: 'invalid-token' })
        .expect(201)
        .expect(res => {
          expect(res.body.success).toBe(false);
          expect(res.body.message).toBe('Token validation failed');
        });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty token gracefully', () => {
      return request(server())
        .get('/auth-service-test/validate-token')
        .query({ token: '' })
        .expect(200)
        .expect(res => {
          expect(res.body.isValid).toBe(false);
          expect(res.body.user).toBeNull();
        });
    });

    it('should handle malformed JWT token', () => {
      return request(server())
        .get('/auth-service-test/validate-token')
        .query({ token: 'not.a.valid.jwt.token' })
        .expect(200)
        .expect(res => {
          expect(res.body.isValid).toBe(false);
          expect(res.body.user).toBeNull();
        });
    });

    it('should handle role check with empty query', async () => {
      const token = await createTestToken('edge-case-user');
      return request(server())
        .get('/auth-service-test/role-check')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect(res => {
          expect(res.body.requestedRole).toBeUndefined();
          expect(res.body.hasRole).toBe(false);
        });
    });

    it('should handle permission check with empty query', async () => {
      const token = await createTestToken('edge-case-user');
      return request(server())
        .get('/auth-service-test/permission-check')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect(res => {
          expect(res.body.requestedPermission).toBeUndefined();
          expect(res.body.hasPermission).toBe(false);
        });
    });
  });

  // Helper function for creating test tokens
  async function createTestToken(
    userId: string,
    roles: string[] = ['user'],
  ): Promise<string> {
    const response = await request(server())
      .post('/auth-service-test/generate-token')
      .send({ userId, roles });
    return response.body.token;
  }
});
