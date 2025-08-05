import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import type { Profile } from 'passport-github2';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXGitHubStrategy } from './github.strategy';

describe('QPMTXGitHubStrategy', () => {
  let strategy: QPMTXGitHubStrategy;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(async () => {
    mockConfig = {
      oauth: {
        github: {
          clientID: 'test-client-id',
          clientSecret: 'test-client-secret',
          callbackURL: 'http://localhost:3000/auth/github/callback',
          scope: ['user:email'],
        },
      },
      defaultRoles: ['user'],
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
        QPMTXGitHubStrategy,
      ],
    }).compile();

    strategy = module.get<QPMTXGitHubStrategy>(QPMTXGitHubStrategy);
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  it('should throw error if GitHub config is not provided', () => {
    const invalidConfig: QPMTXAuthModuleConfig = {
      oauth: {},
    };

    expect(() => new QPMTXGitHubStrategy(invalidConfig)).toThrow(
      'GitHub OAuth configuration is required',
    );
  });

  describe('validate', () => {
    const mockProfile = {
      id: '123456',
      displayName: 'Test User',
      username: 'testuser',
      provider: 'github',
      emails: [{ value: 'test@example.com' }],
      photos: [{ value: 'https://avatars.githubusercontent.com/u/123456' }],
      profileUrl: 'https://github.com/testuser',
      _raw: '',
      _json: {},
    } as Profile;

    it('should validate and return user with default mapping', async () => {
      const done = jest.fn();
      await strategy.validate(
        'access-token',
        'refresh-token',
        mockProfile,
        done,
      );

      expect(done).toHaveBeenCalledWith(null, {
        id: '123456',
        provider: 'github',
        username: 'testuser',
        displayName: 'Test User',
        email: 'test@example.com',
        photos: mockProfile.photos,
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        roles: ['user'],
      });
    });

    it('should use custom user mapper if provided', async () => {
      const customMapper = jest.fn();
      mockConfig.oauthUserMapper = customMapper;

      const done = jest.fn();
      await strategy.validate(
        'access-token',
        'refresh-token',
        mockProfile,
        done,
      );

      expect(customMapper).toHaveBeenCalledWith(
        'access-token',
        'refresh-token',
        mockProfile,
        done,
      );
    });

    it('should handle errors in validation', async () => {
      const error = new Error('Validation error');
      mockConfig.oauthUserMapper = jest.fn().mockRejectedValue(error);

      const done = jest.fn();
      await strategy.validate(
        'access-token',
        'refresh-token',
        mockProfile,
        done,
      );

      expect(done).toHaveBeenCalledWith(error);
    });
  });
});
