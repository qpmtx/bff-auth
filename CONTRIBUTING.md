# Contributing to QPMTX BFF Auth

Thank you for considering contributing to QPMTX BFF Auth! This document provides guidelines and information for contributors.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/qpmtx/bff-auth.git

   cd bff-auth
   ```

3. **Install dependencies**:

   ```bash

   pnpm install
   ```

4. **Create a feature branch**:

   ```bash

   git checkout -b feature/your-feature-name
   ```

## 📋 Development Setup

### Prerequisites

- **Node.js** 18+ (recommended: 20+)
- **pnpm** 10.13.1+
- **Git**

### Local Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run E2E tests
pnpm test:e2e

# Run tests with coverage
pnpm test:cov

# Lint code
pnpm lint

# Fix linting issues
pnpm lint:fix

# Format code
pnpm format

# Check formatting
pnpm format:check

# Build the project
pnpm build

# Build in watch mode
pnpm build:watch
```

## 🧪 Testing

We maintain high test coverage and require all contributions to include appropriate tests.

### Testing Structure

- **Unit Tests**: Located in `src/**/*.spec.ts`
- **E2E Tests**: Located in `test/**/*.e2e-spec.ts`
- **Test Utilities**: Located in `test/mocks/` and `test/utils/`

### Writing Tests

- **Unit tests** should test individual functions and classes in isolation
- **E2E tests** should test the integration between components
- Mock external dependencies appropriately
- Aim for descriptive test names that explain the expected behavior

### Running Specific Tests

```bash
# Run specific test file
pnpm test auth.guard.spec.ts

# Run tests matching a pattern
pnpm test --testNamePattern="should validate"

# Run E2E tests for a specific suite
pnpm test:e2e --testNamePattern="Auth Service"
```

## 📝 Code Style

We use ESLint and Prettier to maintain consistent code style.

### Key Guidelines

- **TypeScript**: Use strict typing, avoid `any`
- **Naming**: Use descriptive names with QPMTX prefix for exported types
- **Documentation**: Include JSDoc comments for public APIs
- **Error Handling**: Use proper error types and meaningful messages
- **Imports**: Use absolute imports from `src/` root

### Example Code Style

```typescript
/**
 * QPMTX Authentication Guard for role-based access control
 */
@Injectable()
export class QPMTXAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: QPMTXAuthModuleConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Implementation with proper error handling
    try {
      // Guard logic here
      return this.validateAccess(user, options);
    } catch (error) {
      this.logger.error('Authentication failed', error);
      throw new UnauthorizedException('Access denied');
    }
  }
}
```

## 🔄 Pull Request Process

### Before Submitting

1. **Ensure all tests pass**:

   ```bash
   pnpm test && pnpm test:e2e
   ```

2. **Run linting and formatting**:

   ```bash
   pnpm lint:fix && pnpm format
   ```

3. **Build successfully**:

   ```bash
   pnpm build
   ```

4. **Update documentation** if needed

### PR Guidelines

- **Descriptive title**: Use conventional commit format (e.g., `feat: add role hierarchy support`)
- **Clear description**: Explain what changes were made and why
- **Link issues**: Reference any related GitHub issues
- **Small focused changes**: Keep PRs focused on a single feature or fix
- **Tests included**: All new functionality must include tests

### PR Labels

Use appropriate labels to help with automated versioning:

- `major` / `breaking`: Breaking changes (major version bump)
- `minor` / `feature`: New features (minor version bump)
- `patch` / `fix`: Bug fixes (patch version bump)
- `docs`: Documentation changes
- `test`: Test-only changes
- `chore`: Maintenance tasks

### PR Template

When creating a PR, please fill out the template with:

- **Summary** of changes
- **Type of change** (bug fix, feature, breaking change, etc.)
- **Testing** information
- **Documentation** updates
- **Breaking changes** (if any)

## 🐛 Bug Reports

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml) when reporting bugs.

### Include:

- **Clear description** of the bug
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (Node.js version, OS, etc.)
- **Code samples** demonstrating the issue
- **Stack traces** if available

## 💡 Feature Requests

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.yml) for new features.

### Include:

- **Clear description** of the feature
- **Use case** and motivation
- **Proposed API** or interface
- **Alternative solutions** considered
- **Implementation ideas** (optional)

## 🏗️ Architecture Guidelines

### Project Structure

```
src/
├── decorators/     # Custom decorators (@QPMTXRoles, @QPMTXUser, etc.)
├── guards/         # Authentication guards
├── interfaces/     # Type definitions and interfaces
├── modules/        # NestJS modules
├── services/       # Business logic services
├── strategies/     # Passport strategies
├── types/          # Type definitions
└── index.ts        # Main exports

test/
├── mocks/          # Test utilities and mocks
└── *.e2e-spec.ts   # E2E test files
```

### Design Principles

- **Generic and Flexible**: Support multiple authentication strategies
- **Type Safe**: Leverage TypeScript for compile-time safety
- **Testable**: Design with testing in mind
- **Backward Compatible**: Maintain compatibility with existing APIs
- **Well Documented**: Clear documentation and examples

### Adding New Features

1. **Design the API** - Consider how it fits with existing patterns
2. **Create types** - Add appropriate TypeScript interfaces
3. **Implement core logic** - Write the main functionality
4. **Add tests** - Both unit and E2E tests
5. **Update documentation** - README, JSDoc comments, examples
6. **Consider backward compatibility** - Add deprecation warnings if needed

## 📚 Documentation

### API Documentation

- Use **JSDoc** comments for all public APIs
- Include **examples** in documentation
- Document **parameters**, **return types**, and **exceptions**
- Update **README.md** for user-facing changes

### Code Comments

- Explain **why**, not what
- Document **complex logic** and **edge cases**
- Use **TODO** comments for future improvements
- Remove **outdated comments**

## 🚀 Release Process

Releases are automated via GitHub Actions:

1. **Create PR** with your changes
2. **Add appropriate labels** for versioning
3. **Merge PR** to main branch
4. **Automated release** is triggered based on PR labels/title
5. **Package published** to npm automatically

### Release Types

- **Major** (1.0.0 → 2.0.0): Breaking changes
- **Minor** (1.0.0 → 1.1.0): New features
- **Patch** (1.0.0 → 1.0.1): Bug fixes

## 🤝 Community Guidelines

### Code of Conduct

- Be **respectful** and **inclusive**
- **Constructive feedback** only
- **Help others** learn and contribute
- **Follow project standards** and guidelines

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Pull Requests**: For code review and feedback

### Recognition

Contributors are recognized in:

- **Release notes** for significant contributions
- **README.md** contributor section
- **GitHub contributor graphs**

## 📄 License

By contributing to QPMTX BFF Auth, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## 🙏 Thank You

Your contributions make QPMTX BFF Auth better for everyone. Whether it's:

- 🐛 **Bug fixes**
- ✨ **New features**
- 📚 **Documentation improvements**
- 🧪 **Test enhancements**
- 💡 **Ideas and feedback**

Every contribution is valuable and appreciated!

---

**Happy Contributing!** 🎉

For any questions about contributing, feel free to open a GitHub Discussion or reach out to the maintainers.
