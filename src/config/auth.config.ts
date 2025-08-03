import { registerAs } from '@nestjs/config';
import { AuthModuleConfig } from '../interfaces';

export const AUTH_CONFIG_TOKEN = 'auth';

export const authConfig = registerAs(
  AUTH_CONFIG_TOKEN,
  (): AuthModuleConfig => ({
    jwt: {
      secret: process.env.JWT_SECRET || 'default-secret',
      signOptions: {
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer: process.env.JWT_ISSUER || 'qpmtx-auth',
        audience: process.env.JWT_AUDIENCE || 'qpmtx-app',
      },
      verifyOptions: {
        issuer: process.env.JWT_ISSUER || 'qpmtx-auth',
        audience: process.env.JWT_AUDIENCE || 'qpmtx-app',
        clockTolerance: 60,
      },
    },
    globalGuard: process.env.AUTH_GLOBAL_GUARD === 'true',
    defaultRoles: process.env.AUTH_DEFAULT_ROLES?.split(',') || ['user'],
    unauthorizedMessage: 'Unauthorized access',
    forbiddenMessage: 'Insufficient permissions',
  }),
);
