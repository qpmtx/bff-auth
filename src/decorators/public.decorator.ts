import { SetMetadata } from '@nestjs/common';
import { PUBLIC_KEY } from './metadata.constants';

/**
 * Decorator to mark routes as publicly accessible (no authentication required)
 * @returns MethodDecorator - NestJS metadata decorator
 *
 * @example
 * ```typescript
 * @QPMTXPublic()
 * @Get('/health')
 * getHealth() {
 *   return { status: 'ok' };
 * }
 * ```
 */
export const QPMTXPublic = () => SetMetadata(PUBLIC_KEY, true);

// Backward compatibility alias
/** @deprecated Use QPMTXPublic instead */
export const Public = QPMTXPublic;
