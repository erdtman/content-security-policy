'use strict';

const js = require('@eslint/js');
const stylistic = require('@stylistic/eslint-plugin');

module.exports = [
  {
    ignores: ['coverage/']
  },
  js.configs.recommended,
  stylistic.configs.customize({
    indent: 2,
    quotes: 'single',
    semi: true,
    arrowParens: false,
    braceStyle: '1tbs',
    commaDangle: 'never',
    jsx: false
  }),
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        module: 'writable',
        require: 'readonly',
        __dirname: 'readonly',
        console: 'readonly'
      }
    },
    rules: {
      // Match the style this project has always used: a space before the
      // parameter list, and no parentheses around a single arrow parameter
      // even when the body is a block.
      '@stylistic/space-before-function-paren': ['error', 'always'],
      '@stylistic/arrow-parens': ['error', 'as-needed'],
      '@stylistic/quote-props': ['error', 'as-needed']
    }
  }
];
