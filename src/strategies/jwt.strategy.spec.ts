import { UnauthorizedException } from '@nestjs/common';
import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import { AUTH_MODULE_CONFIG } from '../constants/tokens';
import type { QPMTXAuthModuleConfig } from '../interfaces';
import type { QPMTXJwtPayload } from '../types';
import { QPMTXJwtStrategy } from './jwt.strategy';

describe('QPMTXJwtStrategy', () => {
  let strategy: QPMTXJwtStrategy;
  let mockConfig: QPMTXAuthModuleConfig;

  beforeEach(async () => {
    mockConfig = {
      jwt: {
        secret: 'test-secret',
        signOptions: {
          expiresIn: '1h',
        },
        verifyOptions: {
          algorithms: ['HS256'],
        },
      },
      defaultRoles: ['user'],
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: QPMTXJwtStrategy,
          useFactory: (config: QPMTXAuthModuleConfig) => {
            return new QPMTXJwtStrategy(config);
          },
          inject: [AUTH_MODULE_CONFIG],
        },
        {
          provide: AUTH_MODULE_CONFIG,
          useValue: mockConfig,
        },
      ],
    }).compile();

    strategy = module.get<QPMTXJwtStrategy>(QPMTXJwtStrategy);
  });

  describe('constructor', () => {
    it('should be defined', () => {
      expect(strategy).toBeDefined();
    });

    it('should throw error when JWT secret is not provided', async () => {
      const configWithoutSecret = { ...mockConfig, jwt: {} };

      await expect(
        Test.createTestingModule({
          providers: [
            {
              provide: QPMTXJwtStrategy,
              useFactory: (config: QPMTXAuthModuleConfig) => {
                return new QPMTXJwtStrategy(config);
              },
              inject: [AUTH_MODULE_CONFIG],
            },
            {
              provide: AUTH_MODULE_CONFIG,
              useValue: configWithoutSecret,
            },
          ],
        }).compile(),
      ).rejects.toThrow('JWT secret is required');
    });
  });

  describe('validate', () => {
    const mockPayload: QPMTXJwtPayload = {
      sub: 'user-123',
      email: 'test@example.com',
      username: 'testuser',
      roles: ['admin'],
      permissions: ['read:users'],
      iat: 1234567890,
      exp: 1234567890 + 3600,
    };

    it('should return valid user object', async () => {
      const result = await strategy.validate(mockPayload);

      expect(result).toEqual({
        id: 'user-123',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['admin'],
        permissions: ['read:users'],
      });
    });

    it('should use default roles when payload roles are empty', async () => {
      const payloadWithoutRoles: QPMTXJwtPayload = {
        sub: 'user-123',
        roles: [],
      };
      const result = await strategy.validate(payloadWithoutRoles);

      expect(result.roles).toEqual(['user']);
    });

    it('should call custom user validator if provided', async () => {
      const customValidator = jest.fn().mockResolvedValue(true);
      mockConfig.customUserValidator = customValidator;

      await strategy.validate(mockPayload);

      expect(customValidator).toHaveBeenCalledWith(mockPayload);
    });

    it('should throw UnauthorizedException when custom validator returns false', async () => {
      const customValidator = jest.fn().mockResolvedValue(false);
      mockConfig.customUserValidator = customValidator;

      await expect(strategy.validate(mockPayload)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when custom validator throws', async () => {
      const customValidator = jest
        .fn()
        .mockRejectedValue(new Error('Validation failed'));
      mockConfig.customUserValidator = customValidator;

      await expect(strategy.validate(mockPayload)).rejects.toThrow();
    });

    it('should handle missing optional fields gracefully', async () => {
      const minimalPayload: QPMTXJwtPayload = {
        sub: 'user-123',
        roles: ['user'],
      };

      const result = await strategy.validate(minimalPayload);

      expect(result).toEqual({
        id: 'user-123',
        email: undefined,
        username: undefined,
        roles: ['user'],
        permissions: undefined,
      });
    });
  });
});
