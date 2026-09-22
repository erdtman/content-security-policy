'use strict';

const js = require('@eslint/js');

module.exports = [
  {
    ignores: ['coverage/']
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
  }
];
