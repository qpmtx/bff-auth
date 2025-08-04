import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import type {
  QPMTXGenericGuardOptions,
  QPMTXGenericJwtPayload,
  QPMTXGenericRequest,
  QPMTXGenericUser,
} from '../../src/types/generic.types';
import { QPMTXAbstractAuthService } from '../../src/services/abstract-auth.service';

export const TEST_JWT_SECRET = 'test-jwt-secret-for-concrete-service';

@Injectable()
export class ConcreteAuthService extends QPMTXAbstractAuthService<
  QPMTXGenericUser,
  QPMTXGenericJwtPayload,
  QPMTXGenericRequest
> {
  async validateToken(token: string): Promise<QPMTXGenericUser | null> {
    try {
      const payload = jwt.verify(
        token,
        TEST_JWT_SECRET,
      ) as QPMTXGenericJwtPayload;
      return this.validateUser(payload);
    } catch {
      return null;
    }
  }

  async validateUser(
    payload: QPMTXGenericJwtPayload,
  ): Promise<QPMTXGenericUser | null> {
    // Simulate user validation logic
    if (!payload.sub) {
      return null;
    }

    // Mock user database lookup
    let user: QPMTXGenericUser = {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      roles: payload.roles ?? ['user'],
      permissions: payload.permissions ?? [],
    };

    // Apply role hierarchy expansion
    const expandedRoles = this.expandRoles(user.roles, this.getRoleHierarchy());
    user.roles = expandedRoles;

    // Apply post-validation hook
    const processedUser = this.afterUserValidation(user);
    if (processedUser) {
      user = processedUser;
    }

    return user;
  }

  async generateToken(user: QPMTXGenericUser): Promise<string> {
    // Add small delay to ensure different timestamps
    await new Promise(resolve => setTimeout(resolve, 2));

    const payload: QPMTXGenericJwtPayload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      roles: user.roles,
      permissions: user.permissions,
      iat: Math.floor(Date.now() / 1000),
      // Add a random component to ensure uniqueness
      jti: Math.random().toString(36).substring(2, 15),
    };

    return jwt.sign(payload, TEST_JWT_SECRET, { expiresIn: '1h' });
  }

  async refreshToken(token: string): Promise<string> {
    const decoded = jwt.decode(token) as QPMTXGenericJwtPayload;
    if (!decoded) {
      throw new Error('Invalid token');
    }

    // Create a fresh user object with expanded roles
    let user: QPMTXGenericUser = {
      id: decoded.sub,
      email: decoded.email,
      username: decoded.username,
      roles: decoded.roles,
      permissions: decoded.permissions,
    };

    // Apply role hierarchy expansion for consistency
    const expandedRoles = this.expandRoles(user.roles, this.getRoleHierarchy());
    user.roles = expandedRoles;

    // Apply post-validation hook
    const processedUser = this.afterUserValidation(user);
    if (processedUser) {
      user = processedUser;
    }

    // Generate new token with fresh timestamp
    return this.generateToken(user);
  }

  extractTokenFromRequest(request: QPMTXGenericRequest): string | null {
    const authHeader = request.headers.authorization as string;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Also check for token in query params for testing
    if (typeof request.query?.token === 'string') {
      return request.query.token;
    }

    return null;
  }

  // Helper method for role hierarchy
  private getRoleHierarchy(): Record<string, string[]> {
    return {
      admin: ['moderator', 'user'],
      moderator: ['user'],
      editor: ['contributor'],
    };
  }

  // Override hook methods for testing
  protected beforeTokenValidation(token: string): string | void {
    // Log token validation attempt (for testing)
    // console.log(`Validating token: ${token.substring(0, 10)}...`);
    return token;
  }

  protected afterUserValidation(
    user: QPMTXGenericUser,
  ): QPMTXGenericUser | void {
    // Add custom fields or modifications after validation
    if (user.roles.includes('admin')) {
      user.permissions = user.permissions ?? [];
      if (!user.permissions.includes('admin:all')) {
        user.permissions.push('admin:all');
      }
    }
    return user;
  }

  protected onValidationFailure(error: Error, context?: string): void {
    console.error(
      `Validation failed in ${context ?? 'unknown context'}:`,
      error.message,
    );
  }

  // Additional utility methods for testing
  async validateUserAccess(
    user: QPMTXGenericUser,
    options: QPMTXGenericGuardOptions,
  ): Promise<boolean> {
    return this.validateGuardOptions(user, options);
  }

  async createTestUser(
    id: string,
    roles: string[] = ['user'],
    permissions: string[] = [],
  ): Promise<QPMTXGenericUser> {
    let user: QPMTXGenericUser = {
      id,
      email: `${id}@test.com`,
      username: id,
      roles,
      permissions,
    };

    // Apply role hierarchy expansion
    const expandedRoles = this.expandRoles(user.roles, this.getRoleHierarchy());
    user.roles = expandedRoles;

    // Apply post-validation hook
    const processedUser = this.afterUserValidation(user);
    if (processedUser) {
      user = processedUser;
    }

    return user;
  }

  async createTestToken(
    userId: string,
    roles: string[] = ['user'],
    permissions: string[] = [],
    expiresIn: string = '1h',
  ): Promise<string> {
    // Add small delay to ensure different timestamps
    await new Promise(resolve => setTimeout(resolve, 2));

    const payload: QPMTXGenericJwtPayload = {
      sub: userId,
      email: `${userId}@test.com`,
      username: userId,
      roles,
      permissions,
      iat: Math.floor(Date.now() / 1000),
      // Add a random component to ensure uniqueness
      jti: Math.random().toString(36).substring(2, 15),
    };

    return jwt.sign(payload, TEST_JWT_SECRET, { expiresIn } as jwt.SignOptions);
  }
}
