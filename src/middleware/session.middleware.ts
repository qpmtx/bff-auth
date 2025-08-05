import { Inject, Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import * as session from 'express-session';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';

/**
 * Session middleware for OAuth authentication
 */
@Injectable()
export class QPMTXSessionMiddleware implements NestMiddleware {
  private readonly sessionMiddleware: ReturnType<typeof session>;

  constructor(
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {
    if (!config.session) {
      throw new Error('Session configuration is required for OAuth');
    }

    this.sessionMiddleware = session({
      secret: config.session.secret,
      resave: config.session.resave ?? false,
      saveUninitialized: config.session.saveUninitialized ?? false,
      cookie: config.session.cookie ?? {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    });
  }

  use(req: Request, res: Response, next: NextFunction) {
    this.sessionMiddleware(req, res, next);
  }
}
