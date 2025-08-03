# Release Labels for Version Control

Use these labels on your Pull Requests to control automatic version bumping:

## Version Bump Labels

| Label                 | Version Bump  | When to Use                          |
| --------------------- | ------------- | ------------------------------------ |
| `major` or `breaking` | 1.0.0 → 2.0.0 | Breaking changes, major new features |
| `minor` or `feature`  | 1.0.0 → 1.1.0 | New features, backwards compatible   |
| `patch` or `fix`      | 1.0.0 → 1.0.1 | Bug fixes, small improvements        |

## Automatic Detection

If no labels are used, the workflow will try to detect version type from:

### PR Title Patterns

- `feature:` or `✨` → minor version
- `fix:` or `🐛` → patch version
- `BREAKING CHANGE` or `!` → major version

### Examples

- `feature: add new authentication module` → minor (1.0.0 → 1.1.0)
- `fix: resolve login issue` → patch (1.0.0 → 1.0.1)
- `feature!: redesign API structure` → major (1.0.0 → 2.0.0)

## Default Behavior

If no labels or patterns are detected, defaults to **patch** version bump.
