import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import type { Profile } from 'passport';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthService } from './oauth.service';

describe('QPMTXOAuthService', () => {
  let service: QPMTXOAuthService;
  let jwtService: JwtService;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(async () => {
    mockConfig = {
      defaultRoles: ['user'],
      oauth: {
        github: {
          clientID: 'test-client-id',
          clientSecret: 'test-client-secret',
          callbackURL: 'http://localhost:3000/auth/github/callback',
        },
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-jwt-token'),
          },
        },
        QPMTXOAuthService,
      ],
    }).compile();

    service = module.get<QPMTXOAuthService>(QPMTXOAuthService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('processOAuthUser', () => {
    const mockProfile: Profile = {
      id: '123456',
      displayName: 'Test User',
      username: 'testuser',
      provider: 'github',
      emails: [{ value: 'test@example.com' }],
    };

    it('should process OAuth user with default mapping', async () => {
      const result = await service.processOAuthUser(
        'access-token',
        'refresh-token',
        mockProfile,
      );

      expect(result.user).toEqual({
        id: '123456',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: [],
      });
      expect(result.token).toBe('mock-jwt-token');
    });

    it('should use custom user mapper when provided', async () => {
      const customUser = {
        id: 'custom-123',
        email: 'custom@example.com',
        username: 'customuser',
        roles: ['admin'],
        permissions: ['read', 'write'],
      };

      mockConfig.oauthUserMapper = jest
        .fn()
        .mockImplementation((accessToken, refreshToken, profile, done) => {
          done(null, customUser);
        });

      const result = await service.processOAuthUser(
        'access-token',
        'refresh-token',
        mockProfile,
      );

      expect(result.user).toEqual(customUser);
      expect(result.token).toBe('mock-jwt-token');
    });

    it('should handle custom mapper errors', async () => {
      const error = new Error('Custom mapper error');
      mockConfig.oauthUserMapper = jest
        .fn()
        .mockImplementation((accessToken, refreshToken, profile, done) => {
          done(error);
        });

      await expect(
        service.processOAuthUser('access-token', 'refresh-token', mockProfile),
      ).rejects.toThrow('Custom mapper error');
    });
  });

  describe('generateJwtFromUser', () => {
    it('should generate JWT from user data', () => {
      const user = {
        id: '123',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read'],
      };

      const token = service.generateJwtFromUser(user);

      expect(jwtService.sign).toHaveBeenCalledWith({
        sub: '123',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read'],
      });
      expect(token).toBe('mock-jwt-token');
    });
  });

  describe('generateJwtFromProfile', () => {
    it('should generate JWT from profile data', () => {
      const profile: Profile = {
        id: '123456',
        displayName: 'Test User',
        username: 'testuser',
        provider: 'github',
        emails: [{ value: 'test@example.com' }],
      };

      const token = service.generateJwtFromProfile(profile, 'github');

      expect(jwtService.sign).toHaveBeenCalledWith({
        sub: '123456',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: [],
        provider: 'github',
      });
      expect(token).toBe('mock-jwt-token');
    });
  });

  describe('getOAuthConfig', () => {
    it('should return OAuth config for existing provider', () => {
      const config = service.getOAuthConfig('github');
      expect(config).toEqual({
        clientID: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
      });
    });

    it('should return undefined for non-existing provider', () => {
      const config = service.getOAuthConfig('google');
      expect(config).toBeUndefined();
    });
  });

  describe('isOAuthConfigured', () => {
    it('should return true for configured provider', () => {
      expect(service.isOAuthConfigured('github')).toBe(true);
    });

    it('should return false for non-configured provider', () => {
      expect(service.isOAuthConfigured('google')).toBe(false);
    });
  });

  describe('validateOAuthConfig', () => {
    it('should not throw for valid configuration', () => {
      expect(() => service.validateOAuthConfig('github')).not.toThrow();
    });

    it('should throw for non-existing provider', () => {
      expect(() => service.validateOAuthConfig('google')).toThrow(
        'OAuth configuration for google is not found',
      );
    });

    it('should throw for invalid configuration', () => {
      mockConfig.oauth!.github = {
        clientID: '',
        clientSecret: 'secret',
        callbackURL: 'url',
      };

      expect(() => service.validateOAuthConfig('github')).toThrow(
        'Invalid OAuth configuration for github',
      );
    });
  });
});
