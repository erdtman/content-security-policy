'use strict';

const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');
const { run, headerValue } = require('./helpers/response.js');

/**
 * The README and examples/ are the parts of this package most likely to drift,
 * because nothing executes them. These tests evaluate the documented policies
 * for real and compare them against what the library actually produces, so a
 * wrong example fails the build rather than misleading a reader.
 *
 * They deliberately assert that the expected shapes are still found: if the
 * documentation is restructured, these fail and have to be pointed at the new
 * shape rather than silently checking nothing.
 */

const ROOT = path.join(__dirname, '..');
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const EXAMPLE = readFileSync(path.join(ROOT, 'examples', 'express.js'), 'utf8');

// One shared context, so two evaluated snippets can be compared to each other
// rather than only to a string.
const CONTEXT = vm.createContext({ csp: CSP });

/**
 * Evaluate a snippet with `csp` bound to the library.
 *
 * @param source a JavaScript expression
 * @returns its value
 */
function evaluate (source) {
  return vm.runInContext('(' + source + ')', CONTEXT);
}

describe('README', () => {
  it('documents the directive value table correctly', () => {
    // | a string | `'script-src': "'self'"` → `script-src 'self'` |
    const rows = README.split('\n')
      .filter(line => line.startsWith('|') && line.includes('→'))
      .map(line => [...line.matchAll(/`([^`]+)`/g)].map(m => m[1]))
      .filter(spans => spans.length >= 2)
      // The mapping is always the last two code spans on the row; an earlier
      // one is the value kind, which is sometimes code too (`true`).
      .map(spans => spans.slice(-2));

    assert.ok(rows.length >= 3, 'found ' + rows.length + ' documented value mappings, expected at least 3');

    for (const [fragment, expected] of rows) {
      assert.equal(headerValue(CSP.getCSP(evaluate('{' + fragment + '}'))), expected, fragment);
    }
  });

  it('produces the header its annotated examples claim', () => {
    // csp.getCSP({ ... });
    // // Content-Security-Policy: default-src 'none'; ...
    const examples = [...README.matchAll(
      /^csp\.getCSP\(([\s\S]*?)\);\n\/\/ (Content-Security-Policy(?:-Report-Only)?): (.+)$/gm
    )];

    assert.ok(examples.length >= 1, 'found no annotated getCSP examples in the README');

    for (const [, args, expectedName, expectedValue] of examples) {
      const result = run(evaluate('csp.getCSP(' + args + ')'));

      assert.equal(result.name, expectedName, args);
      assert.equal(result.value, expectedValue, args);
    }
  });

  it('only claims constants that exist', () => {
    const section = README.slice(README.indexOf('### Constants'), README.indexOf('### STARTER_OPTIONS'));
    const named = [...section.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map(m => m[1]);

    assert.ok(named.length >= 20, 'found ' + named.length + ' documented constants');
    for (const name of named) {
      assert.ok(Object.hasOwn(CSP, name), name + ' is documented but not exported');
    }
  });

  it('documents every exported constant except the deprecated alias', () => {
    const exported = Object.keys(CSP).filter(name => /^(SRC|SANDBOX|TRUSTED)_/.test(name));

    for (const name of exported) {
      if (name === 'SRC_USAFE_INLINE') {
        continue;
      }
      assert.ok(README.includes('`' + name + '`'), name + ' is exported but not documented');
    }
  });
});

describe('examples/express.js', () => {
  /**
   * @param source a file containing `const cspPolicy = { ... };`
   * @returns the evaluated policy
   */
  function policyFrom (source) {
    const match = source.match(/const cspPolicy = (\{[\s\S]*?\n\});/);
    assert.ok(match, 'no cspPolicy literal found');
    return evaluate(match[1]);
  }

  it('uses a policy the library accepts', () => {
    const policy = policyFrom(EXAMPLE);

    assert.doesNotThrow(() => CSP.getCSP(policy));
    assert.equal(
      headerValue(CSP.getCSP(policy)),
      'default-src \'none\'; script-src \'self\' data:; report-uri /reporting'
    );
  });

  it('has not drifted from the README usage section', () => {
    assert.deepEqual(policyFrom(EXAMPLE), policyFrom(README));
  });

  it('requires the package by name the way a reader would', () => {
    assert.match(EXAMPLE, /require\('\.\.'\)/);
  });
});
