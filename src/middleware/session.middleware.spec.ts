import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import type { NextFunction, Request, Response } from 'express';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import { QPMTXSessionMiddleware } from './session.middleware';

// Mock express-session
jest.mock('express-session', () => {
  return jest.fn(() => jest.fn((req: any, res: any, next: any) => next()));
});

describe('QPMTXSessionMiddleware', () => {
  let middleware: QPMTXSessionMiddleware;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(async () => {
    mockConfig = {
      session: {
        secret: 'test-secret',
        resave: false,
        saveUninitialized: false,
        cookie: {
          secure: false,
          httpOnly: true,
          maxAge: 86400000,
        },
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
        QPMTXSessionMiddleware,
      ],
    }).compile();

    middleware = module.get<QPMTXSessionMiddleware>(QPMTXSessionMiddleware);
  });

  it('should be defined', () => {
    expect(middleware).toBeDefined();
  });

  it('should throw error if session config is not provided', () => {
    const invalidConfig: QPMTXAuthModuleConfig = {};

    expect(() => {
      new QPMTXSessionMiddleware(invalidConfig);
    }).toThrow('Session configuration is required for OAuth');
  });

  it('should apply session middleware', () => {
    const mockReq = {} as Request;
    const mockRes = {} as Response;
    const mockNext = jest.fn() as NextFunction;

    middleware.use(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
  });

  it('should use default cookie settings in production', () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    const configWithoutCookie: QPMTXAuthModuleConfig = {
      session: {
        secret: 'test-secret',
      },
    };

    const middlewareWithDefaults = new QPMTXSessionMiddleware(
      configWithoutCookie,
    );
    expect(middlewareWithDefaults).toBeDefined();

    process.env.NODE_ENV = originalEnv;
  });
});
