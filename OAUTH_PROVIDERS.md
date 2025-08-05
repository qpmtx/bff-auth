# Adding OAuth Providers

This guide shows how to add additional OAuth providers to the @qpmtx/nestjs-auth library.

## Example: Adding Google OAuth

### 1. Install Dependencies

```bash
npm install passport-google-oauth20 @types/passport-google-oauth20
```

### 2. Create Google Strategy

```typescript
// src/strategies/google.strategy.ts
import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthBaseStrategy } from './oauth-base.strategy';

@Injectable()
export class QPMTXGoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly oauthBase: QPMTXOAuthBaseStrategy;

  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    const googleConfig = config.oauth?.google;
    if (!googleConfig) {
      throw new Error('Google OAuth configuration is required');
    }

    super({
      clientID: googleConfig.clientID,
      clientSecret: googleConfig.clientSecret,
      callbackURL: googleConfig.callbackURL,
      scope: googleConfig.scope ?? ['email', 'profile'],
    });

    this.oauthBase = new QPMTXOAuthBaseStrategy(config);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: unknown, user?: unknown) => void,
  ): Promise<void> {
    return this.oauthBase.handleOAuthValidation(
      accessToken,
      refreshToken,
      profile,
      done,
    );
  }
}
```

### 3. Create Google Guard

```typescript
// src/guards/google-oauth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class QPMTXGoogleAuthGuard extends AuthGuard('google') {}
```

### 4. Update Module Configuration

```typescript
// In auth.module.ts, add Google strategy support
if (config.oauth?.google) {
  const googleStrategyProvider: Provider = {
    provide: QPMTXGoogleStrategy,
    useFactory: (cfg: QPMTXAuthModuleConfig) =>
      new QPMTXGoogleStrategy(cfg),
    inject: [AUTH_MODULE_CONFIG],
  };
  providers.push(googleStrategyProvider);
  exports.push(QPMTXGoogleStrategy);
}
```

### 5. Usage in Application

```typescript
import { QPMTXAuthModule } from '@qpmtx/nestjs-auth';

@Module({
  imports: [
    QPMTXAuthModule.forRoot({
      jwt: {
        secret: 'your-secret',
        signOptions: { expiresIn: '1h' },
      },
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
      },
      session: {
        secret: process.env.SESSION_SECRET,
      },
    }),
  ],
})
export class AppModule {}
```

## Example: Adding Auth0 OAuth

### 1. Install Dependencies

```bash
npm install passport-auth0 @types/passport-auth0
```

### 2. Create Auth0 Strategy

```typescript
// src/strategies/auth0.strategy.ts
import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-auth0';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXOAuthBaseStrategy } from './oauth-base.strategy';

@Injectable()
export class QPMTXAuth0Strategy extends PassportStrategy(Strategy, 'auth0') {
  private readonly oauthBase: QPMTXOAuthBaseStrategy;

  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    const auth0Config = config.oauth?.auth0;
    if (!auth0Config) {
      throw new Error('Auth0 OAuth configuration is required');
    }

    super({
      domain: auth0Config.domain,
      clientID: auth0Config.clientID,
      clientSecret: auth0Config.clientSecret,
      callbackURL: auth0Config.callbackURL,
      scope: auth0Config.scope ?? 'openid email profile',
    });

    this.oauthBase = new QPMTXOAuthBaseStrategy(config);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    extraParams: any,
    profile: any,
    done: (error: unknown, user?: unknown) => void,
  ): Promise<void> {
    return this.oauthBase.handleOAuthValidation(
      accessToken,
      refreshToken,
      profile,
      done,
    );
  }
}
```

## Generic Pattern for Adding Providers

1. **Install the passport strategy package**
   ```bash
   npm install passport-[provider] @types/passport-[provider]
   ```

2. **Create a strategy class** extending PassportStrategy
   - Inject the auth module config
   - Configure the strategy with provider-specific options
   - Use QPMTXOAuthBaseStrategy for common validation logic

3. **Create a guard class** extending AuthGuard

4. **Update the auth module** to conditionally include the strategy

5. **Configure in your application** with provider credentials

## Best Practices

1. **Environment Variables**: Always store OAuth credentials in environment variables
2. **Secure Callbacks**: Use HTTPS callback URLs in production
3. **Scope Management**: Request only necessary scopes
4. **Error Handling**: Implement proper error handling in custom user mappers
5. **Testing**: Create unit tests for each OAuth strategy

## Common OAuth Providers

- **GitHub**: `passport-github2`
- **Google**: `passport-google-oauth20`
- **Facebook**: `passport-facebook`
- **Twitter**: `passport-twitter`
- **LinkedIn**: `passport-linkedin-oauth2`
- **Auth0**: `passport-auth0`
- **Okta**: `passport-okta-oauth`
- **Azure AD**: `passport-azure-ad`