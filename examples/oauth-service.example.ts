import { Injectable } from '@nestjs/common';
import {
  QPMTXGitHubOAuthService,
  QPMTXOAuthService,
  type QPMTXAuthUser,
} from '@qpmtx/nestjs-auth';

/**
 * Example service showing how to use OAuth services
 * for custom authentication flows
 */
@Injectable()
export class AuthService {
  constructor(
    private readonly oauthService: QPMTXOAuthService,
    private readonly githubOAuthService: QPMTXGitHubOAuthService,
  ) {}

  /**
   * Process GitHub OAuth and create/update user
   */
  async handleGitHubOAuth(
    accessToken: string,
    profile: any,
  ): Promise<{
    user: QPMTXAuthUser;
    token: string;
    isNewUser: boolean;
  }> {
    // Custom user lookup/creation logic
    const existingUser = await this.findUserByGitHubId(profile.id);

    let user: QPMTXAuthUser;
    let isNewUser = false;

    if (existingUser) {
      // Update existing user
      user = await this.updateUserFromGitHub(existingUser, profile);
    } else {
      // Create new user
      user = await this.createUserFromGitHub(profile);
      isNewUser = true;
    }

    // Generate JWT token
    const token = this.oauthService.generateJwtFromUser(user);

    return { user, token, isNewUser };
  }

  /**
   * Generate token for authenticated user
   */
  async generateUserToken(userId: string): Promise<string> {
    const user = await this.findUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return this.oauthService.generateJwtFromUser(user);
  }

  /**
   * Check if GitHub OAuth is available
   */
  isGitHubOAuthEnabled(): boolean {
    return this.githubOAuthService.isGitHubConfigured();
  }

  /**
   * Get GitHub OAuth authorization URL
   */
  getGitHubAuthUrl(): string {
    if (!this.githubOAuthService.isGitHubConfigured()) {
      throw new Error('GitHub OAuth is not configured');
    }

    return this.githubOAuthService.getGitHubAuthUrl();
  }

  // Mock implementations - replace with your actual user service
  private async findUserByGitHubId(
    githubId: string,
  ): Promise<QPMTXAuthUser | null> {
    // Your user lookup logic here
    return null;
  }

  private async findUserById(userId: string): Promise<QPMTXAuthUser | null> {
    // Your user lookup logic here
    return null;
  }

  private async updateUserFromGitHub(
    user: QPMTXAuthUser,
    profile: any,
  ): Promise<QPMTXAuthUser> {
    // Your user update logic here
    return {
      ...user,
      email: profile.emails?.[0]?.value || user.email,
      username: profile.username || user.username,
    };
  }

  private async createUserFromGitHub(profile: any): Promise<QPMTXAuthUser> {
    // Your user creation logic here
    return {
      id: profile.id,
      email: profile.emails?.[0]?.value,
      username: profile.username || profile.displayName,
      roles: ['user'],
      permissions: [],
    };
  }
}
