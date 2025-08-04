import { SetMetadata } from '@nestjs/common';
import type { QPMTXAuthGuardOptions } from '../types';
import { AUTH_OPTIONS_KEY } from './metadata.constants';

export const QPMTXAuthOptions = (options: QPMTXAuthGuardOptions) =>
  SetMetadata(AUTH_OPTIONS_KEY, options);

// Backward compatibility alias
/** @deprecated Use QPMTXAuthOptions instead */
export const AuthOptions = QPMTXAuthOptions;
