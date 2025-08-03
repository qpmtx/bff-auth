// @ts-check
import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Ignore things that shouldn’t be type-checked
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      // config files that often cause “file does not match your project config”
      'eslint.config.*',
      'jest.config.*',
      'vitest.config.*',
      'vite.config.*',
      'rollup.config.*',
      'tsup.config.*',
    ],
  },

  // Base + TS type-checked presets
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,

  // Language / parser options
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      sourceType: 'module',
      parserOptions: {
        // ✅ Use projectService; remove `project` and `tsconfigRootDir`
        projectService: true,
        ecmaVersion: 2022,
      },
    },
  },

  // Your rules
  {
    rules: {
      // TypeScript
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/prefer-nullish-coalescing': 'error',
      '@typescript-eslint/prefer-optional-chain': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/require-await': 'error',
      '@typescript-eslint/no-unnecessary-type-assertion': 'error',
      '@typescript-eslint/prefer-as-const': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports' },
      ],
      '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],
      '@typescript-eslint/array-type': ['error', { default: 'array-simple' }],
      '@typescript-eslint/consistent-generic-constructors': [
        'error',
        'constructor',
      ],

      // JS
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'prefer-const': 'error',
      'no-var': 'error',
      'object-shorthand': 'error',
      'prefer-arrow-callback': 'error',
      'prefer-template': 'error',
      'prefer-destructuring': [
        'error',
        { array: true, object: true },
        { enforceForRenamedProperties: false },
      ],

      // Imports (built-in sorter)
      'sort-imports': [
        'error',
        {
          ignoreCase: false,
          ignoreDeclarationSort: true,
          ignoreMemberSort: false,
          memberSyntaxSortOrder: ['none', 'all', 'multiple', 'single'],
          allowSeparatedGroups: true,
        },
      ],

      // Code quality
      complexity: ['warn', 10],
      'max-depth': ['warn', 4],
      'max-lines-per-function': ['warn', { max: 50, skipBlankLines: true }],
      'max-params': ['warn', 4],
    },
  },

  // Tests: relax noisy rules (supertest/Jest often trip these)
  {
    files: ['**/*.spec.ts', '**/*.e2e-spec.ts', '**/*.test.ts', 'test/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/require-await': 'off',
      // ➕ these two are the usual test offenders:
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/no-misused-promises': [
        'warn',
        { checksVoidReturn: false },
      ],
      'max-lines-per-function': 'off',
      complexity: 'off',
    },
  },
);
