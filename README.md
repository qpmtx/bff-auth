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

## The library includes these dependencies

- `@nestjs/jwt` - JWT token handling
- `@nestjs/passport` - Passport integration
- `passport` - Authentication middleware
- `passport-jwt` - JWT passport strategy

## Quick Start

### 1. Basic Configuration

```typescript
import { Module } from '@nestjs/common';
import { QPMTXAuthModule } from '@qpmtx/bff-auth';

@Module({
  imports: [
    QPMTXAuthModule.forRoot({
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
import { QPMTXAuthModule } from '@qpmtx/bff-auth';

@Module({
  imports: [
    ConfigModule.forRoot(),
    QPMTXAuthModule.forRootAsync({
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
QPMTXAuthModule.forRoot({
  jwt: { secret: 'secret' },
  roleHierarchy: {
    admin: ['moderator', 'user'],
    moderator: ['user'],
  },
  // admin inherits moderator and user permissions
  // moderator inherits user permissions
});
```

### Custom User Validation

```typescript
QPMTXAuthModule.forRoot({
  jwt: { secret: 'secret' },
  customUserValidator: async user => {
    // Custom validation logic
    return user.isActive && !user.isBlocked;
  },
});
```

### Custom Token Extraction

```typescript
QPMTXAuthModule.forRoot({
  jwt: { secret: 'secret' },
  tokenExtractor: request => {
    // Extract token from custom header
    return request.headers['x-api-token'] || null;
  },
});
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
  [key: string]: unknown;
}

interface AuthGuardOptions {
  roles?: string[];
  permissions?: string[];
  requireAll?: boolean;
  allowAnonymous?: boolean;
}

interface JwtPayload {
  sub: string;
  email?: string;
  username?: string;
  roles: string[];
  permissions?: string[];
  iat?: number;
  exp?: number;
  [key: string]: unknown;
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
import {
  hasRole,
  hasAnyRole,
  hasAllRoles,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  expandRoles,
  getUserDisplayName,
  sanitizeUser,
} from '@qpmtx/bff-auth';

// Check roles and permissions
hasRole(user, 'admin');
hasAnyRole(user, ['admin', 'moderator']);
hasAllRoles(user, ['user', 'verified']);
hasPermission(user, 'read:users');
hasAnyPermission(user, ['read:users', 'write:users']);
hasAllPermissions(user, ['read:users', 'write:users']);

// Role expansion with hierarchy
expandRoles(userRoles, roleHierarchy);

// User utilities
getUserDisplayName(user);
sanitizeUser(user, ['password', 'secret']);
```

## Configuration Options

### QPMTXAuthModuleConfig

```typescript
interface QPMTXAuthModuleConfig {
  jwt?: JwtConfig;
  globalGuard?: boolean;
  defaultRoles?: string[];
  roleHierarchy?: Record<string, string[]>;
  customUserValidator?: (user: unknown) => Promise<boolean> | boolean;
  tokenExtractor?: (request: unknown) => string | null;
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
    algorithm?: Algorithm;
  };
  verifyOptions?: {
    issuer?: string;
    audience?: string;
    algorithms?: Algorithm[];
    clockTolerance?: number;
    ignoreExpiration?: boolean;
    ignoreNotBefore?: boolean;
  };
}
```

## Extending the Library

### Custom Guard

```typescript
import { Injectable, ExecutionContext } from '@nestjs/common';
import { AbstractAuthGuard, AuthUser } from '@qpmtx/bff-auth';

@Injectable()
export class CustomAuthGuard extends AbstractAuthGuard {
  protected getRequest(context: ExecutionContext) {
    return context.switchToHttp().getRequest();
  }

  protected async extractToken(request: any): Promise<string | null> {
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return null;
  }

  protected async validateToken(token: string): Promise<AuthUser | null> {
    // Your token validation logic
    try {
      const payload = jwt.verify(token, 'your-secret');
      return {
        id: payload.sub,
        email: payload.email,
        roles: payload.roles || [],
        permissions: payload.permissions || [],
      };
    } catch {
      return null;
    }
  }

  protected async isPublicRoute(context: ExecutionContext): Promise<boolean> {
    // Check for @Public() decorator
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    return isPublic || false;
  }

  protected async getGuardOptions(context: ExecutionContext) {
    // Extract roles, permissions, and options from decorators
    return {
      roles: this.reflector.get<string[]>('roles', context.getHandler()),
      permissions: this.reflector.get<string[]>('permissions', context.getHandler()),
      requireAll: false,
      allowAnonymous: false,
    };
  }

  protected async customValidation(
    user: AuthUser,
    request: any,
    context: ExecutionContext,
  ): Promise<boolean> {
    // Your custom validation logic
    return user.id !== 'blocked-user';
  }
}
```

### Custom Configuration Factory

```typescript
import { Injectable } from '@nestjs/common';
import { AuthConfigFactory, QPMTXAuthModuleConfig } from '@qpmtx/bff-auth';

@Injectable()
export class CustomAuthConfigService implements AuthConfigFactory {
  createAuthConfig(): QPMTXAuthModuleConfig {
    return {
      jwt: {
        secret: process.env.JWT_SECRET,
        signOptions: { expiresIn: '24h' },
      },
      globalGuard: true,
      defaultRoles: ['user'],
      customUserValidator: async user => {
        // Custom validation logic
        return user.isActive;
      },
    };
  }
}

// Use in module
QPMTXAuthModule.forRootAsync({
  useClass: CustomAuthConfigService,
});
```

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Support

For questions and support, please open an issue on our GitHub repository.
