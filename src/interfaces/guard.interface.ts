import type { CanActivate, ExecutionContext } from '@nestjs/common';
import type { QPMTXAuthGuardOptions } from '../types/auth.types';

export interface QPMTXIAuthGuard extends CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean>;
}

export interface QPMTXIGuardConfig {
  getGuardOptions(
    context: ExecutionContext,
  ): QPMTXAuthGuardOptions | Promise<QPMTXAuthGuardOptions>;
  handleUnauthorized(context: ExecutionContext, error?: unknown): boolean;
  handleForbidden(context: ExecutionContext, error?: unknown): boolean;
}

// Backward compatibility aliases
/** @deprecated Use QPMTXIAuthGuard instead */
export type IAuthGuard = QPMTXIAuthGuard;
/** @deprecated Use QPMTXIGuardConfig instead */
export type IGuardConfig = QPMTXIGuardConfig;
