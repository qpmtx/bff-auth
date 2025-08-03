import { AuthConfigFactory, AuthModuleConfig } from '../interfaces';
import { AUTH_MODULE_CONFIG, AuthModule } from './auth.module';

class MockAuthConfigFactory implements AuthConfigFactory {
  createAuthConfig(): AuthModuleConfig {
    return {
      jwt: {
        secret: 'test-secret',
        signOptions: {
          expiresIn: '1h',
        },
      },
      defaultRoles: ['user'],
    };
  }
}

describe('AuthModule', () => {
  const mockConfig: AuthModuleConfig = {
    jwt: {
      secret: 'test-secret',
      signOptions: {
        expiresIn: '1h',
      },
    },
    defaultRoles: ['user'],
    globalGuard: true,
  };

  describe('forRoot', () => {
    it('should create dynamic module with correct configuration', () => {
      const dynamicModule = AuthModule.forRoot(mockConfig);

      expect(dynamicModule).toBeDefined();
      expect(dynamicModule.module).toBe(AuthModule);
      expect(dynamicModule.providers).toBeDefined();
      expect(dynamicModule.exports).toBeDefined();
      expect(dynamicModule.imports).toBeDefined();

      // Check that the config provider is present
      const configProvider = dynamicModule.providers?.find(
        (provider: unknown) =>
          (provider as { provide: unknown }).provide === AUTH_MODULE_CONFIG,
      );
      expect(configProvider).toBeDefined();
      expect((configProvider as { useValue: unknown }).useValue).toEqual(
        mockConfig,
      );
    });
  });

  describe('forRootAsync', () => {
    it('should create dynamic module with useFactory', () => {
      const dynamicModule = AuthModule.forRootAsync({
        useFactory: () => mockConfig,
      });

      expect(dynamicModule).toBeDefined();
      expect(dynamicModule.module).toBe(AuthModule);
      expect(dynamicModule.providers).toBeDefined();
      expect(dynamicModule.exports).toBeDefined();
      expect(dynamicModule.imports).toBeDefined();
    });

    it('should create dynamic module with useClass', () => {
      const dynamicModule = AuthModule.forRootAsync({
        useClass: MockAuthConfigFactory,
      });

      expect(dynamicModule).toBeDefined();
      expect(dynamicModule.module).toBe(AuthModule);
      expect(dynamicModule.providers).toBeDefined();
      expect(dynamicModule.exports).toBeDefined();
      expect(dynamicModule.imports).toBeDefined();
    });

    it('should create dynamic module with useExisting', () => {
      const dynamicModule = AuthModule.forRootAsync({
        useExisting: MockAuthConfigFactory,
      });

      expect(dynamicModule).toBeDefined();
      expect(dynamicModule.module).toBe(AuthModule);
      expect(dynamicModule.providers).toBeDefined();
      expect(dynamicModule.exports).toBeDefined();
      expect(dynamicModule.imports).toBeDefined();
    });

    it('should throw error with invalid configuration', () => {
      expect(() => {
        AuthModule.forRootAsync({});
      }).toThrow('Invalid AuthModule async configuration');
    });
  });

  describe('createAsyncProviders', () => {
    it('should create providers with useFactory', () => {
      const options = {
        useFactory: () => mockConfig,
        inject: ['SOME_TOKEN'],
      };

      const providers = (
        AuthModule as unknown as {
          createAsyncProviders: (options: unknown) => unknown[];
        }
      ).createAsyncProviders(options);

      expect(providers).toHaveLength(1);
      expect((providers[0] as { provide: unknown }).provide).toBe(
        AUTH_MODULE_CONFIG,
      );
      expect((providers[0] as { useFactory: unknown }).useFactory).toBe(
        options.useFactory,
      );
      expect((providers[0] as { inject: unknown[] }).inject).toEqual([
        'SOME_TOKEN',
      ]);
    });

    it('should create providers with useClass', () => {
      const options = {
        useClass: MockAuthConfigFactory,
      };

      const providers = (
        AuthModule as unknown as {
          createAsyncProviders: (options: unknown) => unknown[];
        }
      ).createAsyncProviders(options);

      expect(providers).toHaveLength(2);
      expect((providers[0] as { provide: unknown }).provide).toBe(
        AUTH_MODULE_CONFIG,
      );
      expect((providers[1] as { provide: unknown }).provide).toBe(
        MockAuthConfigFactory,
      );
    });

    it('should create providers with useExisting', () => {
      const options = {
        useExisting: MockAuthConfigFactory,
      };

      const providers = (
        AuthModule as unknown as {
          createAsyncProviders: (options: unknown) => unknown[];
        }
      ).createAsyncProviders(options);

      expect(providers).toHaveLength(1);
      expect((providers[0] as { provide: unknown }).provide).toBe(
        AUTH_MODULE_CONFIG,
      );
      expect((providers[0] as { inject: unknown[] }).inject).toEqual([
        MockAuthConfigFactory,
      ]);
    });
  });
});
