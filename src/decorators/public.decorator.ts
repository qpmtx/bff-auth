import { SetMetadata } from '@nestjs/common';
import { PUBLIC_KEY } from './metadata.constants';

/**
 * Decorator to mark routes as publicly accessible (no authentication required)
 * @returns MethodDecorator - NestJS metadata decorator
 *
 * @example
 * ```typescript
 * @Public()
 * @Get('/health')
 * getHealth() {
 *   return { status: 'ok' };
 * }
 * ```
 */
export const Public = () => SetMetadata(PUBLIC_KEY, true);
