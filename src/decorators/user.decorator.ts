import type { ExecutionContext } from '@nestjs/common';
import { createParamDecorator } from '@nestjs/common';
import type { GenericUser } from '../types/generic.types';

/**
 * Parameter decorator to extract authenticated user from request
 * @param data - Optional property key to extract from user object
 * @param ctx - Execution context
 * @returns User object or specific user property
 */
export const User = createParamDecorator(
  <TUser extends GenericUser = GenericUser>(
    data: keyof TUser | undefined,
    ctx: ExecutionContext,
  ) => {
    const request: { user?: TUser } = ctx.switchToHttp().getRequest();
    const { user } = request;

    return data && user ? user[data] : user;
  },
);
