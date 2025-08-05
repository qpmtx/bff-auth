import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import type { Profile } from 'passport-github2';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXGitHubOAuthService } from './github-oauth.service';
import { QPMTXOAuthService } from './oauth.service';

describe('QPMTXGitHubOAuthService', () => {
  let service: QPMTXGitHubOAuthService;
  let oauthService: QPMTXOAuthService;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(async () => {
    mockConfig = {
      defaultRoles: ['user'],
      oauth: {
        github: {
          clientID: 'test-github-client-id',
          clientSecret: 'test-github-client-secret',
          callbackURL: 'http://localhost:3000/auth/github/callback',
          scope: ['user:email'],
        },
      },
    };

    const mockOAuthService = {
      processOAuthUser: jest.fn(),
      getOAuthConfig: jest.fn(),
      isOAuthConfigured: jest.fn(),
      validateOAuthConfig: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
        {
          provide: QPMTXOAuthService,
          useValue: mockOAuthService,
        },
        QPMTXGitHubOAuthService,
      ],
    }).compile();

    service = module.get<QPMTXGitHubOAuthService>(QPMTXGitHubOAuthService);
    oauthService = module.get<QPMTXOAuthService>(QPMTXOAuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('processGitHubCallback', () => {
    it('should delegate to OAuth service', async () => {
      const mockProfile = {
        id: '123456',
        displayName: 'Test User',
        username: 'testuser',
        provider: 'github',
        emails: [{ value: 'test@example.com' }],
        photos: [],
        profileUrl: 'https://github.com/testuser',
        _raw: '',
        _json: {},
      } as Profile;

      const mockResult = {
        user: {
          id: '123456',
          email: 'test@example.com',
          username: 'testuser',
          roles: ['user'],
          permissions: [],
        },
        token: 'mock-token',
      };

      (oauthService.processOAuthUser as jest.Mock).mockResolvedValue(
        mockResult,
      );

      const result = await service.processGitHubCallback(
        'access-token',
        'refresh-token',
        mockProfile,
      );

      expect(oauthService.processOAuthUser).toHaveBeenCalledWith(
        'access-token',
        'refresh-token',
        mockProfile,
      );
      expect(result).toEqual(mockResult);
    });
  });

  describe('getGitHubConfig', () => {
    it('should delegate to OAuth service', () => {
      const mockConfig = {
        clientID: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
      };

      (oauthService.getOAuthConfig as jest.Mock).mockReturnValue(mockConfig);

      const result = service.getGitHubConfig();

      expect(oauthService.getOAuthConfig).toHaveBeenCalledWith('github');
      expect(result).toEqual(mockConfig);
    });
  });

  describe('isGitHubConfigured', () => {
    it('should delegate to OAuth service', () => {
      (oauthService.isOAuthConfigured as jest.Mock).mockReturnValue(true);

      const result = service.isGitHubConfigured();

      expect(oauthService.isOAuthConfigured).toHaveBeenCalledWith('github');
      expect(result).toBe(true);
    });
  });

  describe('validateGitHubConfig', () => {
    it('should delegate to OAuth service', () => {
      service.validateGitHubConfig();

      expect(oauthService.validateOAuthConfig).toHaveBeenCalledWith('github');
    });
  });

  describe('getGitHubAuthUrl', () => {
    it('should generate correct GitHub OAuth URL', () => {
      (oauthService.getOAuthConfig as jest.Mock).mockReturnValue({
        clientID: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
        scope: ['user:email'],
      });

      const authUrl = service.getGitHubAuthUrl();

      expect(authUrl).toContain('https://github.com/login/oauth/authorize');
      expect(authUrl).toContain('client_id=test-client-id');
      expect(authUrl).toContain(
        'redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fgithub%2Fcallback',
      );
      expect(authUrl).toContain('scope=user%3Aemail');
      expect(authUrl).toContain('response_type=code');
    });

    it('should use default scope when not provided', () => {
      (oauthService.getOAuthConfig as jest.Mock).mockReturnValue({
        clientID: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
      });

      const authUrl = service.getGitHubAuthUrl();

      expect(authUrl).toContain('scope=user%3Aemail');
    });

    it('should throw error when GitHub is not configured', () => {
      (oauthService.getOAuthConfig as jest.Mock).mockReturnValue(null);

      expect(() => service.getGitHubAuthUrl()).toThrow(
        'GitHub OAuth is not configured',
      );
    });
  });
});
