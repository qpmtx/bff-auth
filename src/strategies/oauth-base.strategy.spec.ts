import type { Profile } from 'passport';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthBaseStrategy } from './oauth-base.strategy';

describe('QPMTXOAuthBaseStrategy', () => {
  let strategy: QPMTXOAuthBaseStrategy;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(() => {
    mockConfig = {
      defaultRoles: ['user'],
    };
    strategy = new QPMTXOAuthBaseStrategy(mockConfig);
  });

  describe('handleOAuthValidation', () => {
    const mockProfile: Profile = {
      id: '123456',
      displayName: 'Test User',
      username: 'testuser',
      provider: 'github',
      emails: [{ value: 'test@example.com' }],
      photos: [{ value: 'https://example.com/photo.jpg' }],
    };

    it('should use default user mapping when no custom mapper is provided', async () => {
      const done = jest.fn();
      await strategy.handleOAuthValidation(
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

    it('should use displayName as username if username is not provided', async () => {
      const profileWithoutUsername: Profile = {
        ...mockProfile,
        username: undefined,
      };

      const done = jest.fn();
      await strategy.handleOAuthValidation(
        'access-token',
        'refresh-token',
        profileWithoutUsername,
        done,
      );

      expect(done).toHaveBeenCalledWith(
        null,
        expect.objectContaining({
          username: 'Test User',
        }),
      );
    });

    it('should use custom user mapper when provided', async () => {
      const customMapper = jest.fn();
      mockConfig.oauthUserMapper = customMapper;

      const done = jest.fn();
      await strategy.handleOAuthValidation(
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

    it('should handle errors in custom mapper', async () => {
      const error = new Error('Custom mapper error');
      mockConfig.oauthUserMapper = jest.fn().mockRejectedValue(error);

      const done = jest.fn();
      await strategy.handleOAuthValidation(
        'access-token',
        'refresh-token',
        mockProfile,
        done,
      );

      expect(done).toHaveBeenCalledWith(error);
    });

    it('should handle missing email gracefully', async () => {
      const profileWithoutEmail: Profile = {
        ...mockProfile,
        emails: undefined,
      };

      const done = jest.fn();
      await strategy.handleOAuthValidation(
        'access-token',
        'refresh-token',
        profileWithoutEmail,
        done,
      );

      expect(done).toHaveBeenCalledWith(
        null,
        expect.objectContaining({
          email: undefined,
        }),
      );
    });
  });
});
