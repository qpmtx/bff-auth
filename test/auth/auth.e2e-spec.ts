import type { INestApplication } from '@nestjs/common';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import * as jwt from 'jsonwebtoken';
import * as request from 'supertest';

// Import from local files
import { QPMTXAuthModule } from '../../src';
import { RolePermissionService } from './mocks/auth.mocks';
import { TestController } from './mocks/test.controller';
export const jwtSecret = 'test-secret-key';

const createToken = (payload: any): string => {
  return jwt.sign(
    {
      sub: 'user-123',
      roles: ['user'],
      ...payload,
    },
    jwtSecret,
    { expiresIn: '1h' },
  );
};

describe('Authentication E2E', () => {
  let app: INestApplication;
  let moduleRef: TestingModule;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [
        QPMTXAuthModule.forRoot({
          globalGuard: true,
          jwt: {
            secret: jwtSecret,
          },
        }),
      ],
      controllers: [TestController],
      providers: [RolePermissionService],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const server = () => app.getHttpServer();

  describe('Public endpoints', () => {
    it('allows access to public endpoints without authentication', () => {
      return request(server())
        .get('/test/public')
        .expect(200)
        .expect({ message: 'Public endpoint' });
    });
  });

  describe('Protected endpoints', () => {
    it('denies access without token', () => {
      return request(server()).get('/test/protected').expect(401);
    });

    it('denies access with invalid token', () => {
      return request(server())
        .get('/test/protected')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });

    it('allows access with valid token', () => {
      const token = createToken({});
      return request(server())
        .get('/test/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Protected endpoint' });
    });
  });

  describe('Role-based access control', () => {
    it('denies when user lacks required role', () => {
      const token = createToken({ roles: ['user'] });
      return request(server())
        .get('/test/admin-only')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('allows when user has required role', () => {
      const token = createToken({ roles: ['admin'] });
      return request(server())
        .get('/test/admin-only')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Admin only endpoint' });
    });

    it('allows when user has one of multiple required roles', () => {
      const token = createToken({ roles: ['moderator'] });
      return request(server())
        .get('/test/multi-role')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Multi role endpoint' });
    });
  });

  describe('Permission-based access control', () => {
    it('denies when user lacks required permission', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['read:posts'],
      });
      return request(server())
        .get('/test/permission-required')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('allows when user has required permission', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['read:users'],
      });
      return request(server())
        .get('/test/permission-required')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Permission required endpoint' });
    });
  });

  describe('Combined role and permission requirements', () => {
    it('denies when user has role but lacks permission', () => {
      const token = createToken({
        roles: ['admin'],
        permissions: ['read:users'],
      });
      return request(server())
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('denies when user has permission but lacks role', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['write:users'],
      });
      return request(server())
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('allows when user has both required role and permission', () => {
      const token = createToken({
        roles: ['admin'],
        permissions: ['write:users'],
      });
      return request(server())
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(201)
        .expect({ message: 'Admin with permission endpoint' });
    });
  });

  describe('Token expiration', () => {
    it('denies access with expired token', async () => {
      const expiredToken = jwt.sign(
        { sub: 'user-123', roles: ['user'] },
        jwtSecret,
        { expiresIn: '0s' },
      );

      // Add small delay to ensure token expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      return request(server())
        .get('/test/protected')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });
  });

  describe('Custom validation', () => {
    it('works with extra custom claims present', () => {
      const token = createToken({ customField: 'test-value' });
      return request(server())
        .get('/test/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    });
  });
});
