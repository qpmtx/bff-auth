import {
  DynamicModule,
  Global,
  Inject,
  MiddlewareConsumer,
  Module,
  NestModule,
  Provider,
  Type,
} from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { authConfig } from '../config/auth.config';
import { AUTH_MODULE_CONFIG } from '../constants';
import { QPMTXGitHubOAuthService, QPMTXOAuthService } from '../services';
import { QPMTXAuthGuard } from '../guards';
import {
  QPMTXAuthConfigFactory,
  QPMTXAuthModuleAsyncConfig,
  QPMTXAuthModuleConfig,
} from '../interfaces';
import { QPMTXSessionMiddleware } from '../middleware';
import { QPMTXGitHubStrategy, QPMTXJwtStrategy } from '../strategies';

@Global()
@Module({})
export class QPMTXAuthModule implements NestModule {
  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {}

  configure(_consumer: MiddlewareConsumer) {
    // Session middleware is available but not auto-applied
    // Users should apply it to their own OAuth routes as needed
    // Example: _consumer.apply(QPMTXSessionMiddleware).forRoutes('auth/*');
  }
  static forRoot(config: QPMTXAuthModuleConfig): DynamicModule {
    const { providers, exports: moduleExports } =
      this.buildProvidersAndExports(config);

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
      controllers: [],
      providers,
      exports: moduleExports,
    };
  }

  static forRootAsync(options: QPMTXAuthModuleAsyncConfig): DynamicModule {
    const asyncProviders = this.createAsyncProviders(options);
    const { providers: baseProviders, exports: baseExports } =
      this.buildAsyncProvidersAndExports(asyncProviders);

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
      controllers: [],
      providers: baseProviders,
      exports: baseExports,
    };
  }

  private static buildProvidersAndExports(config: QPMTXAuthModuleConfig) {
    const configProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useValue: config,
    };

    const jwtStrategyProvider: Provider = {
      provide: QPMTXJwtStrategy,
      useFactory: (cfg: QPMTXAuthModuleConfig) => new QPMTXJwtStrategy(cfg),
      inject: [AUTH_MODULE_CONFIG],
    };

    const providers: Provider[] = [
      configProvider,
      jwtStrategyProvider,
      QPMTXAuthGuard,
    ];
    const exports: Array<Type | string> = [
      AUTH_MODULE_CONFIG,
      JwtModule,
      PassportModule,
      QPMTXAuthGuard,
      QPMTXJwtStrategy,
    ];

    this.addOAuthProviders(config, providers, exports);
    return { providers, exports };
  }

  private static addOAuthProviders(
    config: QPMTXAuthModuleConfig,
    providers: Provider[],
    exports: Array<Type | string>,
  ) {
    if (!config.oauth) return;

    providers.push(QPMTXOAuthService);
    exports.push(QPMTXOAuthService);

    if (config.session) {
      providers.push(QPMTXSessionMiddleware);
      exports.push(QPMTXSessionMiddleware);
    }

    if (config.oauth.github) {
      const githubStrategyProvider: Provider = {
        provide: QPMTXGitHubStrategy,
        useFactory: (cfg: QPMTXAuthModuleConfig) =>
          new QPMTXGitHubStrategy(cfg),
        inject: [AUTH_MODULE_CONFIG],
      };
      providers.push(githubStrategyProvider, QPMTXGitHubOAuthService);
      exports.push(QPMTXGitHubStrategy, QPMTXGitHubOAuthService);
    }
  }

  private static buildAsyncProvidersAndExports(asyncProviders: Provider[]) {
    const jwtStrategyProvider: Provider = {
      provide: QPMTXJwtStrategy,
      useFactory: (cfg: QPMTXAuthModuleConfig) => new QPMTXJwtStrategy(cfg),
      inject: [AUTH_MODULE_CONFIG],
    };

    const providers: Provider[] = [
      ...asyncProviders,
      jwtStrategyProvider,
      QPMTXAuthGuard,
    ];
    const exports: Array<Type | string> = [
      AUTH_MODULE_CONFIG,
      JwtModule,
      PassportModule,
      QPMTXAuthGuard,
      QPMTXJwtStrategy,
    ];

    // Add OAuth services for async configuration
    providers.push(QPMTXOAuthService);
    exports.push(QPMTXOAuthService);

    const githubStrategyProvider: Provider = {
      provide: QPMTXGitHubStrategy,
      useFactory: (cfg: QPMTXAuthModuleConfig) => {
        if (cfg.oauth?.github) {
          return new QPMTXGitHubStrategy(cfg);
        }
        return null;
      },
      inject: [AUTH_MODULE_CONFIG],
    };
    providers.push(githubStrategyProvider, QPMTXGitHubOAuthService);
    exports.push(QPMTXGitHubStrategy, QPMTXGitHubOAuthService);

    return { providers, exports };
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
