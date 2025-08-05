import { Controller, Get, INestApplication, UseGuards } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import * as request from 'supertest';
import {
  QPMTXAuthGuard,
  QPMTXAuthModule,
  QPMTXGitHubOAuthService,
  QPMTXOAuthService,
  QPMTXUser,
} from '../src';

// Mock controller to test OAuth integration
@Controller('test')
class TestController {
  @Get('protected')
  @UseGuards(QPMTXAuthGuard)
  getProtected(@QPMTXUser() user: any) {
    return { message: 'Protected route', user };
  }
}

describe('OAuth Flow Integration E2E', () => {
  let app: INestApplication;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        QPMTXAuthModule.forRoot({
          jwt: {
            secret: 'test-secret',
            signOptions: {
              expiresIn: '1h',
            },
          },
          oauth: {
            github: {
              clientID: 'test-github-client-id',
              clientSecret: 'test-github-client-secret',
              callbackURL: 'http://localhost:3000/auth/github/callback',
            },
          },
          session: {
            secret: 'test-session-secret',
            resave: false,
            saveUninitialized: false,
          },
          globalGuard: false,
        }),
      ],
      controllers: [TestController],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    jwtService = moduleFixture.get<JwtService>(JwtService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('OAuth to JWT Flow', () => {
    it('should access protected route with JWT from OAuth', async () => {
      // Simulate OAuth user data
      const oauthUser = {
        id: 'oauth-123',
        email: 'oauth@example.com',
        username: 'oauthuser',
        provider: 'github',
        roles: ['user'],
      };

      // Generate JWT as OAuth callback would
      const token = jwtService.sign({
        sub: oauthUser.id,
        email: oauthUser.email,
        username: oauthUser.username,
        provider: oauthUser.provider,
        roles: oauthUser.roles,
      });

      // Access protected route with the JWT
      const response = await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toEqual({
        message: 'Protected route',
        user: {
          id: 'oauth-123',
          email: 'oauth@example.com',
          username: 'oauthuser',
          roles: ['user'],
        },
      });
    });

    it('should reject invalid JWT token', async () => {
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });

    it('should reject request without token', async () => {
      await request(app.getHttpServer()).get('/test/protected').expect(401);
    });
  });

  describe('OAuth Services Integration', () => {
    it('should have OAuth services available in the app', () => {
      // OAuth services are available through dependency injection
      // Users can access them in their own controllers
      const oauthService = app.get(QPMTXOAuthService);
      const githubService = app.get(QPMTXGitHubOAuthService);

      expect(oauthService).toBeDefined();
      expect(githubService).toBeDefined();
    });

    it('should generate OAuth URLs through services', () => {
      const githubService = app.get(QPMTXGitHubOAuthService);
      const authUrl = githubService.getGitHubAuthUrl();

      expect(authUrl).toContain('github.com/login/oauth/authorize');
    });
  });
});
