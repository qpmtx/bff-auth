import type { Request } from 'express';

/**
 * OAuth user data returned from provider
 */
export interface QPMTXOAuthUser {
  id: string;
  provider: string;
  username?: string;
  displayName?: string;
  email?: string;
  emails?: Array<{ value: string; type?: string }>;
  photos?: Array<{ value: string }>;
  accessToken: string;
  refreshToken?: string;
  roles?: string[];
  [key: string]: unknown;
}

/**
 * Express Request extended with OAuth user
 */
export interface QPMTXOAuthRequest extends Request {
  user?: QPMTXOAuthUser;
}
