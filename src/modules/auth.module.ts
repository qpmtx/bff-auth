import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { authConfig } from '../config/auth.config';
import { AUTH_MODULE_CONFIG } from '../constants';
import { QPMTXAuthGuard } from '../guards';
import {
  QPMTXAuthConfigFactory,
  QPMTXAuthModuleAsyncConfig,
  QPMTXAuthModuleConfig,
} from '../interfaces';
import { QPMTXJwtStrategy } from '../strategies';

@Global()
@Module({})
export class QPMTXAuthModule {
  static forRoot(config: QPMTXAuthModuleConfig): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useValue: config,
    };

    // Build QPMTXJwtStrategy with the injected config (no unresolved deps)
    const jwtStrategyProvider: Provider = {
      provide: QPMTXJwtStrategy,
      useFactory: (cfg: QPMTXAuthModuleConfig) => new QPMTXJwtStrategy(cfg),
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
      providers: [configProvider, jwtStrategyProvider, QPMTXAuthGuard],
      exports: [
        AUTH_MODULE_CONFIG,
        JwtModule,
        PassportModule,
        QPMTXAuthGuard,
        QPMTXJwtStrategy,
      ],
    };
  }

  static forRootAsync(options: QPMTXAuthModuleAsyncConfig): DynamicModule {
    const asyncProviders = this.createAsyncProviders(options);

    const jwtStrategyProvider: Provider = {
      provide: QPMTXJwtStrategy,
      useFactory: (cfg: QPMTXAuthModuleConfig) => new QPMTXJwtStrategy(cfg),
      inject: [AUTH_MODULE_CONFIG],
    };

    return {
      module: QPMTXAuthModule,
      imports: [
        ConfigModule.forFeature(authConfig),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: (cfg: QPMTXAuthModuleConfig) => ({
            secret: cfg.jwt?.secret,
            signOptions: cfg.jwt?.signOptions ?? {},
          }),
          inject: [AUTH_MODULE_CONFIG],
          ...(options.imports ? { imports: options.imports } : {}),
        }),
        ...(options.imports ?? []),
      ],
      providers: [...asyncProviders, jwtStrategyProvider, QPMTXAuthGuard],
      exports: [
        AUTH_MODULE_CONFIG,
        JwtModule,
        PassportModule,
        QPMTXAuthGuard,
        QPMTXJwtStrategy,
      ],
    };
  }

  private static createAsyncProviders(
    options: QPMTXAuthModuleAsyncConfig,
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
          useFactory: async (factory: QPMTXAuthConfigFactory) =>
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
          useFactory: async (factory: QPMTXAuthConfigFactory) =>
            factory.createAuthConfig(),
          inject: [options.useExisting],
        },
      ];
    }

    throw new Error('Invalid AuthModule async configuration');
  }
}
