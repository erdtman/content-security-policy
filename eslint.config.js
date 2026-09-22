'use strict';

const js = require('@eslint/js');

module.exports = [
  {
    ignores: ['coverage/', '.stryker-tmp/', 'reports/']
  },
  js.configs.recommended,
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
    }
  },
  {
    // The tests reach for runtime globals the library itself never touches.
    files: ['test/**/*.js'],
    languageOptions: {
      globals: {
        process: 'readonly',
        fetch: 'readonly',
        structuredClone: 'readonly'
      }
    }
  }
];
