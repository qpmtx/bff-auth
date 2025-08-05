import { Inject, Injectable } from '@nestjs/common';
import type { Profile } from 'passport-github2';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthService } from './oauth.service';

/**
 * GitHub-specific OAuth service
 * Provides GitHub OAuth utility methods
 */
@Injectable()
export class QPMTXGitHubOAuthService {
  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
    private readonly oauthService: QPMTXOAuthService,
  ) {}

  /**
   * Process GitHub OAuth callback
   */
  async processGitHubCallback(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ) {
    return this.oauthService.processOAuthUser(
      accessToken,
      refreshToken,
      profile,
    );
  }

  /**
   * Get GitHub OAuth configuration
   */
  getGitHubConfig() {
    return this.oauthService.getOAuthConfig('github');
  }

  /**
   * Check if GitHub OAuth is configured
   */
  isGitHubConfigured(): boolean {
    return this.oauthService.isOAuthConfigured('github');
  }

  /**
   * Validate GitHub OAuth configuration
   */
  validateGitHubConfig(): void {
    this.oauthService.validateOAuthConfig('github');
  }

  /**
   * Get GitHub OAuth authorization URL
   */
  getGitHubAuthUrl(): string {
    const config = this.getGitHubConfig();
    if (!config) {
      throw new Error('GitHub OAuth is not configured');
    }

    const params = new URLSearchParams({
      client_id: config.clientID,
      redirect_uri: config.callbackURL,
      scope: (config.scope ?? ['user:email']).join(' '),
      response_type: 'code',
    });

    return `https://github.com/login/oauth/authorize?${params.toString()}`;
  }
}
