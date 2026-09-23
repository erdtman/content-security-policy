'use strict';

const { readFileSync } = require('node:fs');
const path = require('node:path');
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');

const DECLARATIONS = readFileSync(path.join(__dirname, '..', 'lib', 'index.d.ts'), 'utf8');

describe('DIRECTIVES', () => {
  it('is a frozen array of valid, unique directive names', () => {
    assert.ok(Array.isArray(CSP.DIRECTIVES));
    assert.ok(Object.isFrozen(CSP.DIRECTIVES));
    assert.equal(new Set(CSP.DIRECTIVES).size, CSP.DIRECTIVES.length, 'no duplicates');

    for (const name of CSP.DIRECTIVES) {
      assert.match(name, /^[a-z][a-z0-9-]*$/, name);
    }
  });

  it('covers the CSP3 directives the README documents', () => {
    for (const name of ['default-src', 'base-uri', 'trusted-types', 'require-trusted-types-for', 'worker-src']) {
      assert.ok(CSP.DIRECTIVES.includes(name), name);
    }
  });

  it('is the same list the declarations describe', () => {
    const declared = [...DECLARATIONS.matchAll(/^ {2}\| '([a-z0-9-]+)';?$/gm)].map(m => m[1]);

    assert.deepEqual(declared, [...CSP.DIRECTIVES], 'KnownDirective union matches DIRECTIVES');
  });
});

describe('STARTER_OPTIONS', () => {
  it('is frozen, because it is shared by every consumer in the process', () => {
    assert.ok(Object.isFrozen(CSP.STARTER_OPTIONS));
    assert.throws(() => { CSP.STARTER_OPTIONS['script-src'] = CSP.SRC_UNSAFE_INLINE; }, TypeError);
    assert.equal(CSP.STARTER_OPTIONS['script-src'], CSP.SRC_SELF);
  });

  it('uses only known directives and compiles without warning', () => {
    for (const name of Object.keys(CSP.STARTER_OPTIONS)) {
      assert.ok(CSP.DIRECTIVES.includes(name), name);
    }
    assert.doesNotThrow(() => CSP.getCSP(CSP.STARTER_OPTIONS));
  });

  it('locks down the bypasses a strict policy depends on', () => {
    assert.equal(CSP.STARTER_OPTIONS['default-src'], CSP.SRC_NONE);
    assert.equal(CSP.STARTER_OPTIONS['object-src'], CSP.SRC_NONE);
    assert.equal(CSP.STARTER_OPTIONS['base-uri'], CSP.SRC_SELF);
    assert.ok(!Object.keys(CSP.STARTER_OPTIONS).includes('plugin-types'), 'no deprecated directives');

    for (const [name, value] of Object.entries(CSP.STARTER_OPTIONS)) {
      assert.ok(value !== CSP.SRC_ANY && value !== CSP.SRC_UNSAFE_INLINE && value !== CSP.SRC_UNSAFE_EVAL, name);
    }
  });

  it('can be spread into a derived policy', () => {
    const derived = { ...CSP.STARTER_OPTIONS, 'script-src': [CSP.SRC_SELF, 'https://cdn.example'] };

    assert.doesNotThrow(() => CSP.getCSP(derived));
    assert.equal(CSP.STARTER_OPTIONS['script-src'], CSP.SRC_SELF, 'the original is untouched');
  });
});

describe('constants', () => {
  it('keeps the misspelled alias in step with its replacement', () => {
    assert.equal(CSP.SRC_USAFE_INLINE, CSP.SRC_UNSAFE_INLINE);
  });

  it('quotes the source keywords that the CSP grammar requires quoting', () => {
    for (const name of ['SRC_SELF', 'SRC_NONE', 'SRC_UNSAFE_INLINE', 'SRC_UNSAFE_EVAL', 'SRC_UNSAFE_HASHES',
      'SRC_WASM_UNSAFE_EVAL', 'SRC_STRICT_DYNAMIC', 'SRC_REPORT_SAMPLE', 'TRUSTED_TYPES_FOR_SCRIPT']) {
      assert.match(CSP[name], /^'[a-z0-9-]+'$/, name);
    }
  });

  it('leaves schemes, wildcards and sandbox tokens unquoted', () => {
    for (const name of Object.keys(CSP).filter(key => key.startsWith('SANDBOX_'))) {
      assert.match(CSP[name], /^allow-[a-z-]+$/, name);
    }
    assert.equal(CSP.SRC_DATA, 'data:');
    assert.equal(CSP.SRC_BLOB, 'blob:');
    assert.equal(CSP.SRC_HTTPS, 'https:');
    assert.equal(CSP.SRC_ANY, '*');
  });

  it('are all usable as directive values', () => {
    for (const [name, value] of Object.entries(CSP)) {
      if (typeof value !== 'string') {
        continue;
      }
      assert.doesNotThrow(() => CSP.getCSP({ 'script-src': value }), name);
    }
  });
});

describe('declarations', () => {
  it('declares exactly the runtime exports', () => {
    const declared = new Set(
      [...DECLARATIONS.matchAll(/^export (?:declare )?(?:const|function) (\w+)/gm)].map(m => m[1])
    );

    assert.deepEqual([...declared].sort(), Object.keys(CSP).sort(), 'exported names');
  });

  it('declares the literal type of every string constant', () => {
    const declared = new Map(
      [...DECLARATIONS.matchAll(/^export const (\w+): "((?:[^"\\]|\\.)*)";/gm)]
        .map(([, name, value]) => [name, value.replace(/\\(.)/g, '$1')])
    );

    for (const [name, value] of Object.entries(CSP)) {
      if (typeof value !== 'string') {
        continue;
      }
      assert.ok(declared.has(name), `${name} has no literal type`);
      assert.equal(declared.get(name), value, name);
    }
  });

  it('marks the misspelled alias deprecated', () => {
    assert.match(DECLARATIONS, /@deprecated[^\n]*\n \*\/\nexport const SRC_USAFE_INLINE/);
  });
});
