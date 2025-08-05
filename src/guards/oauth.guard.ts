import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * GitHub OAuth Guard
 */
@Injectable()
export class QPMTXGitHubAuthGuard extends AuthGuard('github') {}

/**
 * Generic OAuth Guard that can work with any provider
 */
@Injectable()
export class QPMTXOAuthGuard extends AuthGuard('oauth') {
  constructor(private readonly provider: string) {
    super(provider);
  }

  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }
}
