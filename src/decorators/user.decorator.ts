import type { ExecutionContext } from '@nestjs/common';
import { createParamDecorator } from '@nestjs/common';
import type { QPMTXGenericUser } from '../types/generic.types';

/**
 * Parameter decorator to extract authenticated user from request
 * @param data - Optional property key to extract from user object
 * @param ctx - Execution context
 * @returns User object or specific user property
 */
export const QPMTXUser = createParamDecorator(
  <TUser extends QPMTXGenericUser = QPMTXGenericUser>(
    data: keyof TUser | undefined,
    ctx: ExecutionContext,
  ) => {
    const request: { user?: TUser } = ctx.switchToHttp().getRequest();
    const { user } = request;

    return data && user ? user[data] : user;
  },
);

// Backward compatibility alias
/** @deprecated Use QPMTXUser instead */
export const User = QPMTXUser;
