module.exports = {
  // Basic formatting
  semi: true,
  trailingComma: 'es5',
  singleQuote: true,
  printWidth: 80,
  tabWidth: 2,
  useTabs: false,

  // TypeScript specific
  arrowParens: 'avoid',
  bracketSpacing: true,
  bracketSameLine: false,

  // JSX (if needed in future)
  jsxSingleQuote: true,
  jsxBracketSameLine: false,

  // Other
  quoteProps: 'as-needed',
  endOfLine: 'lf',
  embeddedLanguageFormatting: 'auto',

  // File type overrides
  overrides: [
    {
      files: '*.json',
      options: {
        printWidth: 120,
      },
    },
    {
      files: '*.md',
      options: {
        printWidth: 100,
        proseWrap: 'preserve',
      },
    },
    {
      files: ['*.yml', '*.yaml'],
      options: {
        tabWidth: 2,
        singleQuote: false,
      },
    },
  ],
};