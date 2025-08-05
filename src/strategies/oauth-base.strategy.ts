import type { Profile } from 'passport';
import type { QPMTXAuthModuleConfig } from '../interfaces';

/**
 * Base class for OAuth strategies
 */
export class QPMTXOAuthBaseStrategy {
  constructor(protected readonly config: QPMTXAuthModuleConfig) {}

  /**
   * Common OAuth validation handler
   */
  async handleOAuthValidation(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: unknown, user?: unknown) => void,
  ): Promise<void> {
    try {
      if (this.config.oauthUserMapper) {
        await this.config.oauthUserMapper(
          accessToken,
          refreshToken,
          profile,
          done,
        );
      } else {
        // Default user mapping
        const profileData = profile;
        const user = {
          id: String(profileData.id),
          provider: String(profileData.provider),
          username: profileData.username ?? profileData.displayName,
          displayName: profileData.displayName,
          email: profileData.emails?.[0]?.value,
          photos: profileData.photos,
          accessToken,
          refreshToken,
          roles: this.config.defaultRoles ?? ['user'],
        };
        done(null, user);
      }
    } catch (error) {
      done(error);
    }
  }
}
