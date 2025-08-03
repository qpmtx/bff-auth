import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthModuleConfig } from '../interfaces';
import { AUTH_MODULE_CONFIG } from '../modules/auth.module';
import { AuthUser, JwtPayload } from '../types';

/**
 * JWT Strategy for Passport authentication
 * Handles JWT token validation and user extraction
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  /**
   * Creates an instance of JwtStrategy
   * @param config - Authentication module configuration
   * @throws {Error} When JWT secret is not provided
   */
  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: AuthModuleConfig,
  ) {
    if (!config.jwt?.secret) {
      throw new Error('JWT secret is required');
    }

    super({
      jwtFromRequest:
        config.tokenExtractor || ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.jwt.secret,
      ...config.jwt.verifyOptions,
    });
  }

  /**
   * Validates JWT payload and returns user object
   * @param payload - JWT payload containing user information
   * @returns Promise<AuthUser> - Authenticated user object
   * @throws {UnauthorizedException} When user validation fails
   */
  async validate(payload: JwtPayload): Promise<AuthUser> {
    if (this.config.customUserValidator) {
      const isValid = await this.config.customUserValidator(payload);
      if (!isValid) {
        throw new UnauthorizedException('Invalid user');
      }
    }

    const user: AuthUser = {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      roles:
        payload.roles && payload.roles.length > 0
          ? payload.roles
          : this.config.defaultRoles || ['user'],
      permissions: payload.permissions,
    };

    return user;
  }
}
