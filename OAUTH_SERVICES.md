# OAuth Services Guide

The @qpmtx/nestjs-auth library provides **service-based OAuth functionality** that gives you complete control over your authentication flow. Instead of forcing you to use predefined controllers, the library provides services that you can inject into your own controllers and services.

## 🎯 Key Benefits

- **Complete Flexibility**: Create your own controllers and routes
- **Service-Based Architecture**: Injectable services for OAuth operations
- **Type Safety**: Full TypeScript support with proper interfaces
- **Easy Testing**: Services are easily mockable for unit tests
- **Clean Separation**: OAuth logic separated from HTTP handling

## 📦 Available Services

### QPMTXOAuthService
The main OAuth service providing core functionality:

```typescript
import { QPMTXOAuthService } from '@qpmtx/nestjs-auth';

@Injectable()
export class MyAuthService {
  constructor(private readonly oauthService: QPMTXOAuthService) {}

  // Generate JWT from user data
  generateToken(user: QPMTXAuthUser): string {
    return this.oauthService.generateJwtFromUser(user);
  }

  // Process OAuth user with custom logic
  async processOAuthUser(accessToken: string, refreshToken: string, profile: Profile) {
    return this.oauthService.processOAuthUser(accessToken, refreshToken, profile);
  }
}
```

### QPMTXGitHubOAuthService
GitHub-specific OAuth service:

```typescript
import { QPMTXGitHubOAuthService } from '@qpmtx/nestjs-auth';

@Injectable()
export class GitHubAuthService {
  constructor(private readonly githubOAuth: QPMTXGitHubOAuthService) {}

  // Check if GitHub OAuth is available
  isGitHubEnabled(): boolean {
    return this.githubOAuth.isGitHubConfigured();
  }

  // Get GitHub authorization URL
  getAuthUrl(): string {
    return this.githubOAuth.getGitHubAuthUrl();
  }

  // Process GitHub callback
  async processCallback(accessToken: string, profile: any) {
    return this.githubOAuth.processGitHubCallback(accessToken, '', profile);
  }
}
```

## 🚀 Implementation Examples

### Custom OAuth Controller

```typescript
import { Controller, Get, UseGuards, Req, Res } from '@nestjs/common';
import {
  QPMTXGitHubAuthGuard,
  QPMTXGitHubOAuthService,
  QPMTXOAuthRequest,
} from '@qpmtx/nestjs-auth';

@Controller('oauth')
export class MyOAuthController {
  constructor(
    private readonly githubOAuth: QPMTXGitHubOAuthService,
  ) {}

  @Get('github/login')
  @UseGuards(QPMTXGitHubAuthGuard)
  initiateGitHubLogin() {
    // Guard handles the redirect to GitHub
  }

  @Get('github/callback')
  @UseGuards(QPMTXGitHubAuthGuard)
  async handleGitHubCallback(@Req() req: QPMTXOAuthRequest, @Res() res) {
    const user = req.user;
    if (!user) {
      return res.redirect('/login?error=oauth_failed');
    }

    try {
      const result = await this.githubOAuth.processGitHubCallback(
        user.accessToken,
        user.refreshToken ?? '',
        user as any,
      );

      // Set JWT as httpOnly cookie
      res.cookie('auth_token', result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      });

      // Redirect to dashboard
      res.redirect('/dashboard');
    } catch (error) {
      res.redirect('/login?error=processing_failed');
    }
  }

  @Get('status')
  getOAuthStatus() {
    return {
      github: {
        enabled: this.githubOAuth.isGitHubConfigured(),
        authUrl: this.githubOAuth.isGitHubConfigured() 
          ? '/oauth/github/login' 
          : null,
      },
    };
  }
}
```

### Custom Authentication Service

```typescript
import { Injectable } from '@nestjs/common';
import { QPMTXOAuthService, QPMTXAuthUser } from '@qpmtx/nestjs-auth';

@Injectable()
export class AuthenticationService {
  constructor(
    private readonly oauthService: QPMTXOAuthService,
    private readonly userService: UserService, // Your user service
  ) {}

  async authenticateWithGitHub(profile: any): Promise<{
    user: QPMTXAuthUser;
    token: string;
    isNewUser: boolean;
  }> {
    // Check if user exists
    let user = await this.userService.findByGitHubId(profile.id);
    let isNewUser = false;

    if (!user) {
      // Create new user
      user = await this.userService.createFromGitHub(profile);
      isNewUser = true;
    } else {
      // Update existing user's GitHub data
      user = await this.userService.updateGitHubData(user.id, profile);
    }

    // Generate JWT token
    const token = this.oauthService.generateJwtFromUser(user);

    return { user, token, isNewUser };
  }

  async generateUserToken(userId: string): Promise<string> {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return this.oauthService.generateJwtFromUser(user);
  }
}
```

### REST API Approach

```typescript
@Controller('api/auth')
export class AuthApiController {
  constructor(
    private readonly githubOAuth: QPMTXGitHubOAuthService,
    private readonly authService: AuthenticationService,
  ) {}

  @Get('github/url')
  getGitHubAuthUrl() {
    if (!this.githubOAuth.isGitHubConfigured()) {
      throw new BadRequestException('GitHub OAuth not configured');
    }

    return {
      authUrl: this.githubOAuth.getGitHubAuthUrl(),
    };
  }

  @Post('github/callback')
  async handleGitHubCallback(@Body() body: { code: string }) {
    // Exchange code for access token (you would implement this)
    const { accessToken, profile } = await this.exchangeCodeForToken(body.code);
    
    // Process the authentication
    const result = await this.authService.authenticateWithGitHub(profile);

    return {
      access_token: result.token,
      user: {
        id: result.user.id,
        email: result.user.email,
        username: result.user.username,
      },
      is_new_user: result.isNewUser,
    };
  }

  private async exchangeCodeForToken(code: string) {
    // Implement GitHub token exchange
    // This would make HTTP requests to GitHub's token endpoint
    throw new Error('Implement token exchange logic');
  }
}
```

## 🔧 Configuration

The services are automatically available when you configure OAuth in your module:

```typescript
QPMTXAuthModule.forRoot({
  jwt: {
    secret: process.env.JWT_SECRET,
    signOptions: { expiresIn: '24h' },
  },
  oauth: {
    github: {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      scope: ['user:email'],
    },
  },
  session: {
    secret: process.env.SESSION_SECRET,
  },
})
```

## 🧪 Testing

Services are easily testable with mocks:

```typescript
describe('AuthenticationService', () => {
  let service: AuthenticationService;
  let oauthService: QPMTXOAuthService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        AuthenticationService,
        {
          provide: QPMTXOAuthService,
          useValue: {
            generateJwtFromUser: jest.fn().mockReturnValue('mock-token'),
            processOAuthUser: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthenticationService>(AuthenticationService);
    oauthService = module.get<QPMTXOAuthService>(QPMTXOAuthService);
  });

  it('should generate token for user', async () => {
    const token = await service.generateUserToken('user-123');
    
    expect(oauthService.generateJwtFromUser).toHaveBeenCalled();
    expect(token).toBe('mock-token');
  });
});
```

## 📝 Available Service Methods

### QPMTXOAuthService Methods

- `processOAuthUser(accessToken, refreshToken, profile)` - Process OAuth user data
- `generateJwtFromUser(user)` - Generate JWT from user object
- `generateJwtFromProfile(profile, provider)` - Generate JWT from OAuth profile
- `getOAuthConfig(provider)` - Get provider configuration
- `isOAuthConfigured(provider)` - Check if provider is configured
- `validateOAuthConfig(provider)` - Validate provider configuration

### QPMTXGitHubOAuthService Methods

- `processGitHubCallback(accessToken, refreshToken, profile)` - Process GitHub callback
- `getGitHubConfig()` - Get GitHub configuration
- `isGitHubConfigured()` - Check if GitHub is configured
- `getGitHubAuthUrl()` - Get GitHub authorization URL
- `validateGitHubConfig()` - Validate GitHub configuration

## 🎉 Benefits of This Approach

1. **No Forced Routes**: You control all your routes and responses
2. **Custom Logic**: Add your own user creation/lookup logic
3. **Flexible Responses**: Return JSON, redirect, set cookies - your choice
4. **Easy Testing**: Mock services instead of testing HTTP endpoints
5. **Type Safety**: Full TypeScript support throughout
6. **Separation of Concerns**: OAuth logic separate from HTTP handling

This approach gives you the OAuth functionality you need while maintaining complete control over your application's authentication flow!