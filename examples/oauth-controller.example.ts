import {
  Controller,
  Get,
  HttpStatus,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  QPMTXGitHubAuthGuard,
  QPMTXGitHubOAuthService,
  QPMTXOAuthService,
  type QPMTXOAuthRequest,
} from '@qpmtx/nestjs-auth';
import type { Response } from 'express';

/**
 * Example OAuth Controller showing how to use the OAuth services
 * Users can create their own controllers using the provided services
 */
@Controller('auth')
export class OAuthController {
  constructor(
    private readonly oauthService: QPMTXOAuthService,
    private readonly githubOAuthService: QPMTXGitHubOAuthService,
  ) {}

  /**
   * Initiates GitHub OAuth flow
   * Redirects to GitHub OAuth authorization URL
   */
  @Get('github')
  @UseGuards(QPMTXGitHubAuthGuard)
  githubAuth() {
    // Guard automatically redirects to GitHub
    // You can also manually redirect using:
    // const authUrl = this.githubOAuthService.getGitHubAuthUrl();
    // res.redirect(authUrl);
  }

  /**
   * GitHub OAuth callback handler
   * Processes the OAuth callback and generates JWT token
   */
  @Get('github/callback')
  @UseGuards(QPMTXGitHubAuthGuard)
  async githubAuthCallback(
    @Req() req: QPMTXOAuthRequest,
    @Res() res: Response,
  ) {
    const user = req.user;

    if (!user) {
      return res.status(HttpStatus.UNAUTHORIZED).json({
        message: 'Authentication failed',
      });
    }

    try {
      // Process the OAuth user and generate JWT token
      const result = await this.githubOAuthService.processGitHubCallback(
        user.accessToken,
        user.refreshToken ?? '',
        req.user as any, // Profile from GitHub
      );

      // Option 1: Redirect with token
      res.redirect(`/dashboard?token=${result.token}`);

      // Option 2: Set cookie and redirect
      // res.cookie('access_token', result.token, { httpOnly: true });
      // res.redirect('/dashboard');

      // Option 3: Return JSON response
      // res.status(HttpStatus.OK).json({
      //   access_token: result.token,
      //   user: result.user,
      // });
    } catch (error) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: 'Failed to process OAuth callback',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Generate JWT from user data
   * Useful for custom user processing
   */
  @Get('token/generate')
  async generateToken(@Req() req: QPMTXOAuthRequest, @Res() res: Response) {
    const user = req.user;

    if (!user) {
      return res.status(HttpStatus.UNAUTHORIZED).json({
        message: 'No user data available',
      });
    }

    try {
      const token = this.oauthService.generateJwtFromUser({
        id: user.id,
        email: user.email,
        username: user.username,
        roles: user.roles || ['user'],
        permissions: [],
      });

      res.status(HttpStatus.OK).json({
        access_token: token,
      });
    } catch (error) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: 'Failed to generate token',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Check OAuth configuration status
   */
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
