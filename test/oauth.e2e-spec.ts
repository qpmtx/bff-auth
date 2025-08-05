import type { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import {
  QPMTXAuthModule,
  QPMTXGitHubOAuthService,
  QPMTXOAuthService,
} from '../src';

describe('OAuth Services E2E Tests', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let oauthService: QPMTXOAuthService;
  let githubOAuthService: QPMTXGitHubOAuthService;

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
        }),
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    jwtService = moduleFixture.get<JwtService>(JwtService);
    oauthService = moduleFixture.get<QPMTXOAuthService>(QPMTXOAuthService);
    githubOAuthService = moduleFixture.get<QPMTXGitHubOAuthService>(
      QPMTXGitHubOAuthService,
    );
  });

  afterAll(async () => {
    await app.close();
  });

  describe('OAuth Services Integration', () => {
    it('should have OAuth services available', () => {
      expect(oauthService).toBeDefined();
      expect(githubOAuthService).toBeDefined();
    });

    it('should check GitHub OAuth configuration', () => {
      expect(githubOAuthService.isGitHubConfigured()).toBe(true);
      expect(oauthService.isOAuthConfigured('github')).toBe(true);
    });

    it('should generate GitHub OAuth URL', () => {
      const authUrl = githubOAuthService.getGitHubAuthUrl();

      expect(authUrl).toContain('https://github.com/login/oauth/authorize');
      expect(authUrl).toContain('client_id=test-github-client-id');
      expect(authUrl).toContain('redirect_uri=');
    });

    it('should validate OAuth configuration', () => {
      expect(() => githubOAuthService.validateGitHubConfig()).not.toThrow();
      expect(() => oauthService.validateOAuthConfig('github')).not.toThrow();
    });
  });

  describe('JWT Generation from OAuth', () => {
    it('should generate JWT token from OAuth user', () => {
      const mockOAuthUser = {
        id: '123456',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: [],
      };

      const token = oauthService.generateJwtFromUser(mockOAuthUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      // Verify the token
      const decoded = jwtService.verify(token);
      expect(decoded.sub).toBe('123456');
      expect(decoded.email).toBe('test@example.com');
      expect(decoded.username).toBe('testuser');
    });

    it('should generate JWT token from OAuth profile', () => {
      const mockProfile = {
        id: '123456',
        displayName: 'Test User',
        username: 'testuser',
        provider: 'github',
        emails: [{ value: 'test@example.com' }],
      };

      const token = oauthService.generateJwtFromProfile(
        mockProfile as any,
        'github',
      );

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      // Verify the token
      const decoded = jwtService.verify(token);
      expect(decoded.sub).toBe('123456');
      expect(decoded.email).toBe('test@example.com');
      expect(decoded.provider).toBe('github');
    });
  });

  describe('OAuth Configuration Management', () => {
    it('should get OAuth config for GitHub', () => {
      const config = oauthService.getOAuthConfig('github');

      expect(config).toBeDefined();
      expect(config?.clientID).toBe('test-github-client-id');
      expect(config?.clientSecret).toBe('test-github-client-secret');
      expect(config?.callbackURL).toBe(
        'http://localhost:3000/auth/github/callback',
      );
    });

    it('should return undefined for non-configured provider', () => {
      const config = oauthService.getOAuthConfig('google');
      expect(config).toBeUndefined();
      expect(oauthService.isOAuthConfigured('google')).toBe(false);
    });

    it('should validate configuration correctly', () => {
      expect(() => oauthService.validateOAuthConfig('github')).not.toThrow();
      expect(() => oauthService.validateOAuthConfig('google')).toThrow();
    });
  });
});
