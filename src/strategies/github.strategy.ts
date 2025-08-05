import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-github2';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthBaseStrategy } from './oauth-base.strategy';

/**
 * GitHub OAuth Strategy for Passport authentication
 */
@Injectable()
export class QPMTXGitHubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly oauthBase: QPMTXOAuthBaseStrategy;

  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    const githubConfig = config.oauth?.github;
    if (!githubConfig) {
      throw new Error('GitHub OAuth configuration is required');
    }

    super({
      clientID: githubConfig.clientID,
      clientSecret: githubConfig.clientSecret,
      callbackURL: githubConfig.callbackURL,
      scope: githubConfig.scope ?? ['user:email'],
    });

    this.oauthBase = new QPMTXOAuthBaseStrategy(config);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: unknown, user?: unknown) => void,
  ): Promise<void> {
    return this.oauthBase.handleOAuthValidation(
      accessToken,
      refreshToken,
      profile,
      done,
    );
  }
}
