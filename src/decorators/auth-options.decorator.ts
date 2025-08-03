import { SetMetadata } from '@nestjs/common';
import { AuthGuardOptions } from '../types';
import { AUTH_OPTIONS_KEY } from './metadata.constants';

export const AuthOptions = (options: AuthGuardOptions) =>
  SetMetadata(AUTH_OPTIONS_KEY, options);
