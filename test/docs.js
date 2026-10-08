'use strict';

const { readdirSync, readFileSync } = require('node:fs');
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

/** The factory each example is expected to demonstrate. */
const EXAMPLES = {
  'express.js': 'getCSP',
  'fastify.js': 'getFastifyCSP',
  'koa.js': 'getKoaCSP',
  'hono.js': 'getHonoCSP',
  'hapi.js': 'getHapiCSP'
};

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
  return vm.runInContext(`(${source})`, CONTEXT);
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

    assert.ok(rows.length >= 3, `found ${rows.length} documented value mappings, expected at least 3`);

    for (const [fragment, expected] of rows) {
      assert.equal(headerValue(CSP.getCSP(evaluate(`{${fragment}}`))), expected, fragment);
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
      const result = run(evaluate(`csp.getCSP(${args})`));

      assert.equal(result.name, expectedName, args);
      assert.equal(result.value, expectedValue, args);
    }
  });

  describe('each framework snippet stands on its own', () => {
    // A reader lands on one of these from the table above and copies it, so a
    // snippet that borrows `csp` or a policy from the usage section further up
    // is broken on arrival. These tests fail rather than let that come back.
    const section = README.slice(README.indexOf('## Frameworks'), README.indexOf('## Writing a policy'));
    const snippets = [...section.matchAll(/### (.+)\n[\s\S]*?```js\n([\s\S]*?)```/g)];

    /** The names the snippets make up for their own values, as opposed to the framework's. */
    const LOCALS = new Set(['csp', 'cspPolicy', 'localCSP', 'applyCSP', 'app', 'server', 'fastify']);

    it('attributes every snippet in the section to a heading', () => {
      // Not one per heading: the last section is prose with no snippet at all.
      assert.equal(snippets.length, [...section.matchAll(/```js\n/g)].length);
    });

    for (const [, label, source] of snippets) {
      // Strings and comments are prose, not uses: 'next/server' is not the
      // snippet referring to a `server` it never declared.
      const code = source.replace(/\/\/.*/g, '').replace(/'[^']*'/g, "''");

      it(`${label} brings in the package itself`, () => {
        assert.match(
          source,
          /require\('content-security-policy'\)|import csp from 'content-security-policy'/
        );
      });

      it(`${label} declares every name it uses`, () => {
        const declared = new Set([
          ...[...code.matchAll(/(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)/g)].map(m => m[1]),
          ...[...source.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from/g)].map(m => m[1]),
          ...[...code.matchAll(/(?:const|let|var|import)\s*\{([^}]*)\}/g)]
            .flatMap(m => m[1].split(',').map(name => name.trim().split(':').pop().trim()))
        ]);

        for (const [name] of code.matchAll(/[A-Za-z_$][\w$]*/g)) {
          if (LOCALS.has(name)) {
            assert.ok(declared.has(name), `${label} uses ${name} without declaring it`);
          }
        }
      });
    }
  });

  it('only claims constants that exist', () => {
    const section = README.slice(README.indexOf('### Constants'), README.indexOf('### STARTER_OPTIONS'));
    const named = [...section.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map(m => m[1]);

    assert.ok(named.length >= 20, `found ${named.length} documented constants`);
    for (const name of named) {
      assert.ok(Object.hasOwn(CSP, name), `${name} is documented but not exported`);
    }
  });

  it('documents every exported constant except the deprecated alias', () => {
    const exported = Object.keys(CSP).filter(name => /^(SRC|SANDBOX|TRUSTED)_/.test(name));

    for (const name of exported) {
      if (name === 'SRC_USAFE_INLINE') {
        continue;
      }
      assert.ok(README.includes(`\`${name}\``), `${name} is exported but not documented`);
    }
  });
});

/**
 * @param source a file containing `const cspPolicy = { ... };`
 * @returns the evaluated policy
 */
function policyFrom (source) {
  const match = source.match(/const cspPolicy = (\{[\s\S]*?\n\});/);
  assert.ok(match, 'no cspPolicy literal found');
  return evaluate(match[1]);
}

describe('examples/', () => {
  it('has one example per adapted framework, and no more', () => {
    // A framework gains an adapter and keeps no example, or an example
    // outlives the adapter it showed: either way this is the test that says so.
    const present = readdirSync(path.join(ROOT, 'examples')).filter(name => name.endsWith('.js'));

    assert.deepEqual(present.sort(), Object.keys(EXAMPLES).sort());
  });

  for (const [file, factory] of Object.entries(EXAMPLES)) {
    describe(`examples/${file}`, () => {
      const source = readFileSync(path.join(ROOT, 'examples', file), 'utf8');

      it('uses a policy the library accepts', () => {
        const policy = policyFrom(source);

        assert.doesNotThrow(() => CSP[factory](policy));
        assert.equal(
          headerValue(CSP.getCSP(policy)),
          'default-src \'none\'; script-src \'self\' data:; report-uri /reporting'
        );
      });

      it('has not drifted from the README usage section', () => {
        assert.deepEqual(policyFrom(source), policyFrom(README));
      });

      it('requires the package by name the way a reader would', () => {
        assert.match(source, /require\('\.\.'\)/);
      });

      it(`shows both policies through ${factory}`, () => {
        // Global and local: the precedence rule is the thing each example is
        // really documenting, and it takes two policies to show it.
        const calls = [...source.matchAll(/csp\.(\w+)\(/g)].map(match => match[1]);

        assert.deepEqual(calls, [factory, factory]);
      });

      it('only names exports the library actually has', () => {
        for (const [, name] of source.matchAll(/csp\.(\w+)/g)) {
          assert.ok(Object.hasOwn(CSP, name), `csp.${name} is used but not exported`);
        }
      });
    });
  }
});
