import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { authConfig } from '../config/auth.config';
import { AUTH_MODULE_CONFIG } from '../constants';
import { AuthGuard } from '../guards';
import {
  AuthConfigFactory,
  AuthModuleAsyncConfig,
  AuthModuleConfig,
} from '../interfaces';
import { JwtStrategy } from '../strategies';

@Global()
@Module({})
export class QPMTXAuthModule {
  static forRoot(config: AuthModuleConfig): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useValue: config,
    };

    // Build JwtStrategy with the injected config (no unresolved deps)
    const jwtStrategyProvider: Provider = {
      provide: JwtStrategy,
      useFactory: (cfg: AuthModuleConfig) => new JwtStrategy(cfg),
      inject: [AUTH_MODULE_CONFIG],
    };

    return {
      module: QPMTXAuthModule,
      imports: [
        ConfigModule.forFeature(authConfig),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: config.jwt?.secret,
          signOptions: config.jwt?.signOptions ?? {},
        }),
      ],
      providers: [configProvider, jwtStrategyProvider, AuthGuard],
      exports: [
        AUTH_MODULE_CONFIG,
        JwtModule,
        PassportModule,
        AuthGuard,
        JwtStrategy,
      ],
    };
  }

  static forRootAsync(options: AuthModuleAsyncConfig): DynamicModule {
    const asyncProviders = this.createAsyncProviders(options);

    const jwtStrategyProvider: Provider = {
      provide: JwtStrategy,
      useFactory: (cfg: AuthModuleConfig) => new JwtStrategy(cfg),
      inject: [AUTH_MODULE_CONFIG],
    };

    return {
      module: QPMTXAuthModule,
      imports: [
        ConfigModule.forFeature(authConfig),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: (cfg: AuthModuleConfig) => ({
            secret: cfg.jwt?.secret,
            signOptions: cfg.jwt?.signOptions ?? {},
          }),
          inject: [AUTH_MODULE_CONFIG],
          ...(options.imports ? { imports: options.imports } : {}),
        }),
        ...(options.imports ?? []),
      ],
      providers: [...asyncProviders, jwtStrategyProvider, AuthGuard],
      exports: [
        AUTH_MODULE_CONFIG,
        JwtModule,
        PassportModule,
        AuthGuard,
        JwtStrategy,
      ],
    };
  }

  private static createAsyncProviders(
    options: AuthModuleAsyncConfig,
  ): Provider[] {
    if (options.useFactory) {
      return [
        {
          provide: AUTH_MODULE_CONFIG,
          useFactory: options.useFactory,
          inject: options.inject ?? [],
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
