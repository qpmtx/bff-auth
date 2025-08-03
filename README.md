# @qpmtx/bff-auth

A comprehensive, type-safe authentication library for NestJS applications with configurable guards, role-based access control, and flexible configuration options.

## Features

- 🔒 **Type-safe authentication** with full TypeScript support
- 🛡️ **Configurable guards** that can be easily overridden
- 👥 **Role-based access control (RBAC)** with hierarchical roles
- 🔑 **Permission-based authorization**
- ⚙️ **External configuration support**
- 📦 **Peer dependencies** for optimal bundle size
- 🎯 **Decorator-based authorization**
- 🔄 **Async configuration support**

## Installation

```bash
npm install @qpmtx/bff-auth
# or
yarn add @qpmtx/bff-auth
```

## Peer Dependencies

Make sure to install the required peer dependencies:

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport passport passport-jwt reflect-metadata rxjs
```

## Quick Start

### 1. Basic Configuration

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from '@qpmtx/bff-auth';

@Module({
  imports: [
    AuthModule.forRoot({
      jwt: {
        secret: 'your-secret-key',
        signOptions: { expiresIn: '1h' },
      },
      globalGuard: true,
      defaultRoles: ['user'],
    }),
  ],
})
export class AppModule {}
```

### 2. Async Configuration

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from '@qpmtx/bff-auth';

@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        jwt: {
          secret: configService.get('JWT_SECRET'),
          signOptions: {
            expiresIn: configService.get('JWT_EXPIRES_IN', '1h'),
          },
        },
        globalGuard: configService.get('AUTH_GLOBAL_GUARD', false),
        defaultRoles: ['user'],
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

## Usage

### Using Decorators

```typescript
import { Controller, Get } from '@nestjs/common';
import { Roles, Permissions, User, Public } from '@qpmtx/bff-auth';

@Controller('users')
export class UsersController {
  @Get('profile')
  @Roles('user', 'admin')
  getProfile(@User() user: AuthUser) {
    return user;
  }

  @Get('admin')
  @Roles('admin')
  @Permissions('read:users')
  getAdminData() {
    return { message: 'Admin only data' };
  }

  @Get('public')
  @Public()
  getPublicData() {
    return { message: 'Public data' };
  }
}
```

### Advanced Authorization

```typescript
import { AuthOptions } from '@qpmtx/bff-auth';

@Controller('api')
export class ApiController {
  @Get('sensitive')
  @AuthOptions({
    roles: ['admin', 'moderator'],
    permissions: ['read:sensitive'],
    requireAll: true, // Requires ALL roles AND permissions
  })
  getSensitiveData() {
    return { data: 'sensitive' };
  }

  @Get('flexible')
  @AuthOptions({
    roles: ['user'],
    permissions: ['read:data'],
    requireAll: false, // Requires ANY role OR permission
  })
  getFlexibleData() {
    return { data: 'flexible' };
  }
}
```

### Role Hierarchy

Configure role inheritance:

```typescript
AuthModule.forRoot({
  jwt: { secret: 'secret' },
  roleHierarchy: {
    admin: ['moderator', 'user'],
    moderator: ['user'],
  },
  // admin inherits moderator and user permissions
  // moderator inherits user permissions
})
```

### Custom User Validation

```typescript
AuthModule.forRoot({
  jwt: { secret: 'secret' },
  customUserValidator: async (user) => {
    // Custom validation logic
    return user.isActive && !user.isBlocked;
  },
})
```

### Custom Token Extraction

```typescript
AuthModule.forRoot({
  jwt: { secret: 'secret' },
  tokenExtractor: (request) => {
    // Extract token from custom header
    return request.headers['x-api-token'] || null;
  },
})
```

## API Reference

### Types

```typescript
interface AuthUser {
  id: string;
  email?: string;
  username?: string;
  roles: string[];
  permissions?: string[];
  [key: string]: any;
}

interface AuthGuardOptions {
  roles?: string[];
  permissions?: string[];
  requireAll?: boolean;
  allowAnonymous?: boolean;
}
```

### Decorators

- `@Roles(...roles: string[])` - Require specific roles
- `@Permissions(...permissions: string[])` - Require specific permissions
- `@AuthOptions(options: AuthGuardOptions)` - Advanced authorization options
- `@Public()` - Mark endpoint as public (bypass authentication)
- `@User(field?: keyof AuthUser)` - Inject user data into route handler

### Utilities

```typescript
import { AuthUtils } from '@qpmtx/bff-auth';

// Check roles and permissions
AuthUtils.hasRole(user, 'admin');
AuthUtils.hasAnyRole(user, ['admin', 'moderator']);
AuthUtils.hasAllRoles(user, ['user', 'verified']);
AuthUtils.hasPermission(user, 'read:users');
AuthUtils.hasAnyPermission(user, ['read:users', 'write:users']);
AuthUtils.hasAllPermissions(user, ['read:users', 'write:users']);

// Role expansion with hierarchy
AuthUtils.expandRoles(userRoles, roleHierarchy);

// User utilities
AuthUtils.getUserDisplayName(user);
AuthUtils.sanitizeUser(user, ['password', 'secret']);
```

## Configuration Options

### AuthModuleConfig

```typescript
interface AuthModuleConfig {
  jwt?: JwtConfig;
  globalGuard?: boolean;
  defaultRoles?: string[];
  roleHierarchy?: Record<string, string[]>;
  customUserValidator?: (user: any) => Promise<boolean> | boolean;
  tokenExtractor?: (request: any) => string | null;
  unauthorizedMessage?: string;
  forbiddenMessage?: string;
}
```

### JWT Configuration

```typescript
interface JwtConfig {
  secret?: string;
  signOptions?: {
    expiresIn?: string | number;
    issuer?: string;
    audience?: string;
    algorithm?: string;
  };
  verifyOptions?: {
    issuer?: string;
    audience?: string;
    algorithms?: string[];
    clockTolerance?: number;
    ignoreExpiration?: boolean;
    ignoreNotBefore?: boolean;
  };
}
```

## Extending the Library

### Custom Guard

```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@qpmtx/bff-auth';

@Injectable()
export class CustomAuthGuard extends AuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Custom logic before authentication
    const result = await super.canActivate(context);
    
    if (result) {
      // Additional checks after successful authentication
      const request = context.switchToHttp().getRequest();
      return this.customValidation(request.user);
    }
    
    return false;
  }

  private customValidation(user: AuthUser): boolean {
    // Your custom validation logic
    return true;
  }
}
```

### Custom Configuration Factory

```typescript
import { Injectable } from '@nestjs/common';
import { AuthConfigFactory, AuthModuleConfig } from '@qpmtx/bff-auth';

@Injectable()
export class CustomAuthConfigService implements AuthConfigFactory {
  createAuthConfig(): AuthModuleConfig {
    return {
      jwt: {
        secret: process.env.JWT_SECRET,
        signOptions: { expiresIn: '24h' },
      },
      globalGuard: true,
      defaultRoles: ['user'],
      customUserValidator: async (user) => {
        // Custom validation logic
        return user.isActive;
      },
    };
  }
}

// Use in module
AuthModule.forRootAsync({
  useClass: CustomAuthConfigService,
})
```

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Support

For questions and support, please open an issue on our GitHub repository.
