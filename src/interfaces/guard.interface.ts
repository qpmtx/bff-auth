import { CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthGuardOptions } from '../types/auth.types';

export interface IAuthGuard extends CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean>;
}

export interface IGuardConfig {
  getGuardOptions(
    context: ExecutionContext,
  ): AuthGuardOptions | Promise<AuthGuardOptions>;
  handleUnauthorized(context: ExecutionContext, error?: unknown): boolean;
  handleForbidden(context: ExecutionContext, error?: unknown): boolean;
}
