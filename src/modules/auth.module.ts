import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { authConfig } from '../config/auth.config';
import { AuthGuard } from '../guards';
import {
  AuthConfigFactory,
  AuthModuleAsyncConfig,
  AuthModuleConfig,
} from '../interfaces';
import { JwtStrategy } from '../strategies';

/** Configuration token for the auth module */
export const AUTH_MODULE_CONFIG = 'AUTH_MODULE_CONFIG';

/**
 * Global authentication module for NestJS applications
 * Provides JWT-based authentication with role and permission support
 */
@Global()
@Module({})
export class AuthModule {
  /**
   * Configures the auth module with synchronous configuration
   * @param config - Authentication module configuration
   * @returns DynamicModule - Configured module
   */
  static forRoot(config: AuthModuleConfig): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useValue: config,
    };

    return {
      module: AuthModule,
      imports: [
        ConfigModule.forFeature(authConfig),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: config.jwt?.secret,
          signOptions: config.jwt?.signOptions || {},
        }),
      ],
      providers: [configProvider, JwtStrategy, AuthGuard],
      exports: [AUTH_MODULE_CONFIG, JwtModule, PassportModule, AuthGuard],
    };
  }

  /**
   * Configures the auth module with asynchronous configuration
   * @param options - Async configuration options
   * @returns DynamicModule - Configured module
   */
  static forRootAsync(options: AuthModuleAsyncConfig): DynamicModule {
    const asyncProviders = this.createAsyncProviders(options);

    return {
      module: AuthModule,
      imports: [
        ConfigModule.forFeature(authConfig),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: (config: AuthModuleConfig) => ({
            secret: config.jwt?.secret,
            signOptions: config.jwt?.signOptions || {},
          }),
          inject: [AUTH_MODULE_CONFIG],
        }),
        ...(options.imports || []),
      ],
      providers: [...asyncProviders, JwtStrategy, AuthGuard],
      exports: [AUTH_MODULE_CONFIG, JwtModule, PassportModule, AuthGuard],
    };
  }

  /**
   * Creates providers for async configuration
   * @param options - Async configuration options
   * @returns Provider[] - Array of providers
   * @throws {Error} When invalid configuration is provided
   */
  private static createAsyncProviders(
    options: AuthModuleAsyncConfig,
  ): Provider[] {
    if (options.useFactory) {
      return [
        {
          provide: AUTH_MODULE_CONFIG,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
      ];
    }

    if (options.useClass) {
      return [
        {
          provide: AUTH_MODULE_CONFIG,
          useFactory: async (factory: AuthConfigFactory) =>
            factory.createAuthConfig(),
          inject: [options.useClass],
        },
        {
          provide: options.useClass,
          useClass: options.useClass,
        },
      ];
    }

    if (options.useExisting) {
      return [
        {
          provide: AUTH_MODULE_CONFIG,
          useFactory: async (factory: AuthConfigFactory) =>
            factory.createAuthConfig(),
          inject: [options.useExisting],
        },
      ];
    }

    throw new Error('Invalid AuthModule async configuration');
  }
}
