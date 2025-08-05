import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Profile } from 'passport';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import type { QPMTXAuthUser, QPMTXJwtPayload } from '../types';

/**
 * OAuth Service provides methods for handling OAuth authentication flows
 * Users can inject this service into their own controllers
 */
@Injectable()
export class QPMTXOAuthService {
  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Process OAuth user data and generate JWT token
   */
  async processOAuthUser(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): Promise<{
    user: QPMTXAuthUser;
    token: string;
  }> {
    // Use custom user mapper if provided
    if (this.config.oauthUserMapper) {
      return new Promise((resolve, reject) => {
        this.config.oauthUserMapper!(
          accessToken,
          refreshToken,
          profile,
          (error: unknown, user?: unknown) => {
            if (error) {
              reject(error);
              return;
            }

            const authUser = user as QPMTXAuthUser;
            const token = this.generateJwtFromUser(authUser);
            resolve({ user: authUser, token });
          },
        );
      });
    }

    // Default user mapping
    const user: QPMTXAuthUser = {
      id: profile.id,
      email: profile.emails?.[0]?.value,
      username: profile.username ?? profile.displayName,
      roles: this.config.defaultRoles ?? ['user'],
      permissions: [],
    };

    const token = this.generateJwtFromUser(user);
    return { user, token };
  }

  /**
   * Generate JWT token from authenticated user
   */
  generateJwtFromUser(user: QPMTXAuthUser): string {
    const payload: QPMTXJwtPayload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      roles: user.roles,
      permissions: user.permissions,
    };

    return this.jwtService.sign(payload);
  }

  /**
   * Generate JWT token from OAuth profile (simplified)
   */
  generateJwtFromProfile(profile: Profile, provider: string): string {
    const payload: QPMTXJwtPayload = {
      sub: profile.id,
      email: profile.emails?.[0]?.value,
      username: profile.username ?? profile.displayName,
      roles: this.config.defaultRoles ?? ['user'],
      permissions: [],
      provider,
    };

    return this.jwtService.sign(payload);
  }

  /**
   * Get OAuth configuration for a specific provider
   */
  getOAuthConfig(provider: string) {
    return this.config.oauth?.[provider];
  }

  /**
   * Check if OAuth is configured for a provider
   */
  isOAuthConfigured(provider: string): boolean {
    return !!this.config.oauth?.[provider];
  }

  /**
   * Validate OAuth configuration
   */
  validateOAuthConfig(provider: string): void {
    const config = this.getOAuthConfig(provider);
    if (!config) {
      throw new Error(`OAuth configuration for ${provider} is not found`);
    }

    if (!config.clientID || !config.clientSecret || !config.callbackURL) {
      throw new Error(
        `Invalid OAuth configuration for ${provider}. clientID, clientSecret, and callbackURL are required`,
      );
    }
  }
}
