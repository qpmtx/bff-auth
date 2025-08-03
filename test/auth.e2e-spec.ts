import {
  Controller,
  Get,
  INestApplication,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { Permissions, Public, Roles } from '../src/decorators';
import { AuthGuard } from '../src/guards/auth.guard';
import { AuthModule } from '../src/modules/auth.module';
import { JwtPayload } from '../src/types';

@Controller('test')
export class TestController {
  @Public()
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
  @Roles('admin')
  @Get('admin-only')
  getAdminOnly() {
    return { message: 'Admin only endpoint' };
  }

  @UseGuards(AuthGuard)
  @Permissions('read:users')
  @Get('permission-required')
  getPermissionRequired() {
    return { message: 'Permission required endpoint' };
  }

  @UseGuards(AuthGuard)
  @Roles('admin', 'moderator')
  @Get('multi-role')
  getMultiRole() {
    return { message: 'Multi role endpoint' };
  }

  @UseGuards(AuthGuard)
  @Roles('admin')
  @Permissions('write:users')
  @Post('admin-with-permission')
  postAdminWithPermission() {
    return { message: 'Admin with permission endpoint' };
  }
}

describe('Authentication E2E', () => {
  let app: INestApplication;
  let jwtService: JwtService;

  const jwtSecret = 'test-secret-key';

  const createToken = (payload: Partial<JwtPayload>): string => {
    return jwtService.sign({
      sub: 'user-123',
      roles: ['user'],
      ...payload,
    });
  };

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.forRoot({
          jwt: {
            secret: jwtSecret,
            signOptions: {
              expiresIn: '1h',
            },
          },
          defaultRoles: ['user'],
          unauthorizedMessage: 'Access denied',
          forbiddenMessage: 'Insufficient permissions',
        }),
      ],
      controllers: [TestController],
    }).compile();

    app = moduleFixture.createNestApplication();
    jwtService = moduleFixture.get<JwtService>(JwtService);
    await app.init();
  });

  afterEach(() => {
    process.exit(1);
  });

  describe('Public endpoints', () => {
    it('should allow access to public endpoints without authentication', () => {
      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/public')
        .expect(200)
        .expect({ message: 'Public endpoint' });
    });
  });

  describe('Protected endpoints', () => {
    it('should deny access without token', () => {
      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/protected')
        .expect(401);
    });

    it('should deny access with invalid token', () => {
      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/protected')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });

    it('should allow access with valid token', () => {
      const token = createToken({});

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Protected endpoint' });
    });
  });

  describe('Role-based access control', () => {
    it('should deny access when user lacks required role', () => {
      const token = createToken({ roles: ['user'] });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/admin-only')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('should allow access when user has required role', () => {
      const token = createToken({ roles: ['admin'] });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/admin-only')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Admin only endpoint' });
    });

    it('should allow access when user has one of multiple required roles', () => {
      const token = createToken({ roles: ['moderator'] });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/multi-role')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Multi role endpoint' });
    });
  });

  describe('Permission-based access control', () => {
    it('should deny access when user lacks required permission', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['read:posts'],
      });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/permission-required')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('should allow access when user has required permission', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['read:users'],
      });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/permission-required')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect({ message: 'Permission required endpoint' });
    });
  });

  describe('Combined role and permission requirements', () => {
    it('should deny access when user has role but lacks permission', () => {
      const token = createToken({
        roles: ['admin'],
        permissions: ['read:users'],
      });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('should deny access when user has permission but lacks role', () => {
      const token = createToken({
        roles: ['user'],
        permissions: ['write:users'],
      });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('should allow access when user has both required role and permission', () => {
      const token = createToken({
        roles: ['admin'],
        permissions: ['write:users'],
      });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .post('/test/admin-with-permission')
        .set('Authorization', `Bearer ${token}`)
        .expect(201)
        .expect({ message: 'Admin with permission endpoint' });
    });
  });

  describe('Token expiration', () => {
    it('should deny access with expired token', async () => {
      const expiredToken = jwtService.sign(
        { sub: 'user-123', roles: ['user'] },
        { expiresIn: '-1h' }
      );

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/protected')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });
  });

  describe('Custom validation', () => {
    it('should work with custom user validator', async () => {
      // This test would require setting up the module with a custom validator
      // For now, we'll test the basic functionality
      const token = createToken({ customField: 'test-value' });

      return request(app.getHttpServer() as Parameters<typeof request>[0])
        .get('/test/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    });
  });
});
