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
        const user = {
          id: String(profile.id),
          provider: String(profile.provider),
          username: profile.username ?? profile.displayName,
          displayName: profile.displayName,
          email: profile.emails?.[0]?.value,
          photos: profile.photos,
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
