# @qpmtx/nestjs-auth

A comprehensive, type-safe authentication library for NestJS applications with configurable guards, role-based access control, and flexible configuration options.

## Features

- 🔒 **Type-safe authentication** with full TypeScript support
- 🛡️ **Configurable guards** that can be easily overridden
- 👥 **Role-based access control (RBAC)** with hierarchical roles
- 🔑 **Permission-based authorization**
- 🌐 **OAuth services** - Injectable services for complete control (GitHub, Google, etc.)
- 🚫 **No forced controllers** - You create your own routes and responses
- 🔐 **Session management** for OAuth flows
- ⚙️ **External configuration support**
- 📦 **Peer dependencies** for optimal bundle size
- 🎯 **Decorator-based authorization**
- 🔄 **Async configuration support**
- 📚 **Complete examples** - Ready-to-use implementation examples

## Installation

```bash
npm install @qpmtx/nestjs-auth
# or
yarn add @qpmtx/nestjs-auth
```

## The library includes these dependencies

- `@nestjs/jwt` - JWT token handling
- `@nestjs/passport` - Passport integration
- `passport` - Authentication middleware
- `passport-jwt` - JWT passport strategy
- `passport-github2` - GitHub OAuth strategy
- `express-session` - Session management for OAuth
- `@types/passport-github2` - TypeScript types for GitHub OAuth
- `@types/express-session` - TypeScript types for sessions

## Quick Start

### 1. Basic Configuration

```typescript
import { Module } from '@nestjs/common';
import { QPMTXAuthModule } from '@qpmtx/nestjs-auth';

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
import { QPMTXAuthModule } from '@qpmtx/nestjs-auth';

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
import {
  QPMTXRoles,
  QPMTXPermissions,
  QPMTXUser,
  QPMTXPublic,
  QPMTXAuthUser,
} from '@qpmtx/nestjs-auth';

@Controller('users')
export class UsersController {
  @Get('profile')
  @QPMTXRoles('user', 'admin')
  getProfile(@QPMTXUser() user: QPMTXAuthUser) {
    return user;
  }

  @Get('admin')
  @QPMTXRoles('admin')
  @QPMTXPermissions('read:users')
  getAdminData() {
    return { message: 'Admin only data' };
  }

  @Get('public')
  @QPMTXPublic()
  getPublicData() {
    return { message: 'Public data' };
  }
}
```

### Advanced Authorization

```typescript
import { QPMTXAuthOptions } from '@qpmtx/nestjs-auth';

@Controller('api')
export class ApiController {
  @Get('sensitive')
  @QPMTXAuthOptions({
    roles: ['admin', 'moderator'],
    permissions: ['read:sensitive'],
    requireAll: true, // Requires ALL roles AND permissions
  })
  getSensitiveData() {
    return { data: 'sensitive' };
  }

  @Get('flexible')
  @QPMTXAuthOptions({
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

## OAuth Integration

### Basic OAuth Configuration

```typescript
import { QPMTXAuthModule } from '@qpmtx/nestjs-auth';

@Module({
  imports: [
    QPMTXAuthModule.forRoot({
      jwt: {
        secret: 'your-secret-key',
        signOptions: { expiresIn: '1h' },
      },
      oauth: {
        github: {
          clientID: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
          callbackURL: 'http://localhost:3000/auth/github/callback',
          scope: ['user:email'],
        },
      },
      session: {
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
          secure: process.env.NODE_ENV === 'production',
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
        },
      },
    }),
  ],
})
export class AppModule {}
```

### OAuth Routes

The library provides **services** instead of predefined routes, giving you complete control:

- **No forced routes** - You decide your URL structure
- **Injectable services** - Use `QPMTXOAuthService` and `QPMTXGitHubOAuthService`
- **Complete examples** - See `examples/` folder for full implementations
- **Your controllers** - Create routes that match your application

### Custom OAuth User Mapping

```typescript
QPMTXAuthModule.forRoot({
  // ... other config
  oauthUserMapper: async (accessToken, refreshToken, profile, done) => {
    try {
      // Custom user creation/lookup logic
      const user = await userService.findOrCreateOAuthUser({
        provider: profile.provider,
        providerId: profile.id,
        email: profile.emails?.[0]?.value,
        username: profile.username,
        displayName: profile.displayName,
        avatar: profile.photos?.[0]?.value,
      });

      // Add custom roles based on your logic
      user.roles = await roleService.getUserRoles(user.id);

      done(null, user);
    } catch (error) {
      done(error);
    }
  },
});
```

### Using OAuth Services

The library provides OAuth services that you can inject into your own controllers and services for maximum flexibility:

```typescript
import { Controller, Get, UseGuards, Req, Res } from '@nestjs/common';
import {
  QPMTXGitHubAuthGuard,
  QPMTXOAuthService,
  QPMTXGitHubOAuthService,
  QPMTXOAuthRequest,
} from '@qpmtx/nestjs-auth';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly oauthService: QPMTXOAuthService,
    private readonly githubOAuthService: QPMTXGitHubOAuthService,
  ) {}

  @Get('github')
  @UseGuards(QPMTXGitHubAuthGuard)
  githubAuth() {
    // Guard redirects to GitHub
    // Or manually redirect: res.redirect(this.githubOAuthService.getGitHubAuthUrl());
  }

  @Get('github/callback')
  @UseGuards(QPMTXGitHubAuthGuard)
  async githubAuthCallback(@Req() req: QPMTXOAuthRequest, @Res() res) {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    try {
      // Process OAuth user and generate JWT
      const result = await this.githubOAuthService.processGitHubCallback(
        user.accessToken,
        user.refreshToken ?? '',
        user as any,
      );

      // Customize response based on your needs
      res.redirect(`/dashboard?token=${result.token}`);
      
      // Or return JSON:
      // res.json({ access_token: result.token, user: result.user });
    } catch (error) {
      res.status(500).json({ message: 'OAuth processing failed' });
    }
  }

  @Get('config/status')
  getOAuthStatus() {
    return {
      github: {
        configured: this.githubOAuthService.isGitHubConfigured(),
        authUrl: this.githubOAuthService.isGitHubConfigured()
          ? this.githubOAuthService.getGitHubAuthUrl()
          : null,
      },
    };
  }
}
```

### OAuth Service Methods

#### QPMTXOAuthService

```typescript
// Generate JWT from user data
generateJwtFromUser(user: QPMTXAuthUser): string

// Generate JWT from OAuth profile
generateJwtFromProfile(profile: Profile, provider: string): string

// Process OAuth user with custom mapping
processOAuthUser(accessToken: string, refreshToken: string, profile: Profile): Promise<{user: QPMTXAuthUser, token: string}>

// Get OAuth config for provider
getOAuthConfig(provider: string): QPMTXOAuthProviderConfig | undefined

// Check if OAuth is configured
isOAuthConfigured(provider: string): boolean

// Validate OAuth configuration
validateOAuthConfig(provider: string): void
```

#### QPMTXGitHubOAuthService

```typescript
// Process GitHub OAuth callback
processGitHubCallback(accessToken: string, refreshToken: string, profile: Profile): Promise<{user: QPMTXAuthUser, token: string}>

// Get GitHub config
getGitHubConfig(): QPMTXOAuthProviderConfig | undefined

// Check if GitHub is configured
isGitHubConfigured(): boolean

// Get GitHub authorization URL
getGitHubAuthUrl(): string

// Validate GitHub configuration
validateGitHubConfig(): void
```

### Multiple OAuth Providers

```typescript
QPMTXAuthModule.forRoot({
  // ... JWT config
  oauth: {
    github: {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/github/callback',
    },
    google: {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback',
      scope: ['email', 'profile'],
    },
    // Add more providers as needed
  },
  session: {
    secret: process.env.SESSION_SECRET,
  },
});
```

## API Reference

### Types

```typescript
interface QPMTXAuthUser {
  id: string;
  email?: string;
  username?: string;
  roles: string[];
  permissions?: string[];
  [key: string]: unknown;
}

interface QPMTXAuthGuardOptions {
  roles?: string[];
  permissions?: string[];
  requireAll?: boolean;
  allowAnonymous?: boolean;
}

interface QPMTXJwtPayload {
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

- `@QPMTXRoles(...roles: string[])` - Require specific roles
- `@QPMTXPermissions(...permissions: string[])` - Require specific permissions
- `@QPMTXAuthOptions(options: QPMTXAuthGuardOptions)` - Advanced authorization options
- `@QPMTXPublic()` - Mark endpoint as public (bypass authentication)
- `@QPMTXUser(field?: keyof QPMTXAuthUser)` - Inject user data into route handler

### Backward Compatibility

All decorators and types are also available with their original names for backward compatibility:

- `@Roles` (deprecated, use `@QPMTXRoles`)
- `@Permissions` (deprecated, use `@QPMTXPermissions`)
- `@AuthOptions` (deprecated, use `@QPMTXAuthOptions`)
- `@Public` (deprecated, use `@QPMTXPublic`)
- `@User` (deprecated, use `@QPMTXUser`)
- `AuthUser` (deprecated, use `QPMTXAuthUser`)
- `AuthGuardOptions` (deprecated, use `QPMTXAuthGuardOptions`)
- `JwtPayload` (deprecated, use `QPMTXJwtPayload`)

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
} from '@qpmtx/nestjs-auth';

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
  jwt?: QPMTXJwtConfig;
  oauth?: QPMTXOAuthConfig;
  oauthUserMapper?: QPMTXOAuthUserMapper;
  session?: {
    secret: string;
    resave?: boolean;
    saveUninitialized?: boolean;
    cookie?: {
      maxAge?: number;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: boolean | 'lax' | 'strict' | 'none';
    };
  };
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
interface QPMTXJwtConfig {
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

### OAuth Configuration

```typescript
interface QPMTXOAuthConfig {
  github?: QPMTXOAuthProviderConfig;
  google?: QPMTXOAuthProviderConfig;
  [provider: string]: QPMTXOAuthProviderConfig | undefined;
}

interface QPMTXOAuthProviderConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string[];
  [key: string]: unknown; // Additional provider-specific options
}

type QPMTXOAuthUserMapper = (
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: (error: any, user?: any) => void,
) => void | Promise<void>;
```

## Extending the Library

### Custom Guard

```typescript
import { Injectable, ExecutionContext } from '@nestjs/common';
import { QPMTXAbstractAuthGuard, QPMTXAuthUser } from '@qpmtx/nestjs-auth';

@Injectable()
export class CustomAuthGuard extends QPMTXAbstractAuthGuard {
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

  protected async validateToken(token: string): Promise<QPMTXAuthUser | null> {
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
    // Check for @QPMTXPublic() decorator
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
    user: QPMTXAuthUser,
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
import { QPMTXAuthConfigFactory, QPMTXAuthModuleConfig } from '@qpmtx/nestjs-auth';

@Injectable()
export class CustomAuthConfigService implements QPMTXAuthConfigFactory {
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
