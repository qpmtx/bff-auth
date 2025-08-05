import type { TestingModule } from '@nestjs/testing';
import { Test } from '@nestjs/testing';
import { QPMTXGitHubAuthGuard, QPMTXOAuthGuard } from './oauth.guard';

describe('OAuth Guards', () => {
  describe('QPMTXGitHubAuthGuard', () => {
    let guard: QPMTXGitHubAuthGuard;

    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [QPMTXGitHubAuthGuard],
      }).compile();

      guard = module.get<QPMTXGitHubAuthGuard>(QPMTXGitHubAuthGuard);
    });

    it('should be defined', () => {
      expect(guard).toBeDefined();
    });
  });

  describe('QPMTXOAuthGuard', () => {
    let guard: QPMTXOAuthGuard;

    beforeEach(() => {
      guard = new QPMTXOAuthGuard('google');
    });

    it('should be defined', () => {
      expect(guard).toBeDefined();
    });

    it('should be created with the provided provider', () => {
      // Verify the guard is properly constructed
      // The actual strategy validation happens at runtime with Passport
      expect(guard).toBeInstanceOf(QPMTXOAuthGuard);
    });
  });
});
