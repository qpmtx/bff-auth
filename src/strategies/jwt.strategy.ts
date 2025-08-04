import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import type { QPMTXAuthUser, QPMTXJwtPayload } from '../types';

/**
 * JWT Strategy for Passport authentication
 * Handles JWT token validation and user extraction
 */
@Injectable()
export class QPMTXJwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    if (!config.jwt?.secret) throw new Error('JWT secret is required');

    super({
      jwtFromRequest:
        config.tokenExtractor ?? ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt.secret,
      ignoreExpiration: config.jwt?.verifyOptions?.ignoreExpiration ?? false,
      issuer: config.jwt?.verifyOptions?.issuer,
      audience: config.jwt?.verifyOptions?.audience,
      algorithms: config.jwt?.verifyOptions?.algorithms,
    });
  }

  async validate(payload: QPMTXJwtPayload): Promise<QPMTXAuthUser> {
    if (this.config.customUserValidator) {
      const ok = await this.config.customUserValidator(payload);
      if (!ok) throw new UnauthorizedException('Invalid user');
    }

    return {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      roles: payload.roles?.length
        ? payload.roles
        : (this.config.defaultRoles ?? ['user']),
      permissions: payload.permissions,
    };
  }
}

// Backward compatibility alias
/** @deprecated Use QPMTXJwtStrategy instead */
export const JwtStrategy = QPMTXJwtStrategy;
