'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');
const { run } = require('./helpers/response.js');

/**
 * Properties that must hold for every policy, checked against a few thousand
 * generated ones. The example-based tests say what a given policy compiles to;
 * these say what no policy may ever compile to. The seed is fixed so a failure
 * is reproducible, and it is printed with the failing case.
 */

const SEED = Number(process.env.CSP_FUZZ_SEED || 0x5eed);
const RUNS = Number(process.env.CSP_FUZZ_RUNS || 2000);

/**
 * A small deterministic PRNG, so the suite needs no dependency and no entropy.
 *
 * @param seed any 32-bit integer
 * @returns a function returning the next float in [0, 1)
 */
function mulberry32 (seed) {
  let state = seed | 0;
  return () => {
    state = state + 0x6d2b79f5 | 0;
    let t = Math.imul(state ^ state >>> 15, 1 | state);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

const NAMES = [...CSP.DIRECTIVES, 'fenced-frame-src', 'x-custom-src', 'webrtc'];

const VALUES = [
  CSP.SRC_SELF, CSP.SRC_NONE, CSP.SRC_ANY, CSP.SRC_DATA, CSP.SRC_BLOB, CSP.SRC_HTTPS,
  CSP.SRC_UNSAFE_INLINE, CSP.SRC_STRICT_DYNAMIC, 'https://cdn.example', 'https://a.test:8443/p?q=1',
  '\'nonce-AbC+d/e==\'', true, false, null, undefined, '', '   ', [], ['', null],
  [CSP.SRC_SELF], [CSP.SRC_SELF, 'https://cdn.example'], [CSP.SRC_SELF, '', null, 'https://b.test'],
  0, 42, { nope: true }, ['  spaced  '], ['  ', CSP.SRC_SELF], ['\t']
];

const HOSTILE = [
  '\'self\'\r\nX: y', '\'self\'\nX: y', '\'self\'\rX: y', 'a;b', 'a,b', 'a\u0000b', 'a\tb',
  'exämple.test', 'a\u007fb', 'a b'
];

/**
 * Build a random policy from the pools above.
 *
 * @param random the PRNG
 * @returns a policy object
 */
function randomPolicy (random) {
  const policy = {};
  const size = Math.floor(random() * 8);

  for (let i = 0; i < size; i++) {
    policy[NAMES[Math.floor(random() * NAMES.length)]] = VALUES[Math.floor(random() * VALUES.length)];
  }
  if (random() < 0.3) {
    policy['report-only'] = random() < 0.5;
  }
  return policy;
}

describe('invariants over generated policies', () => {
  it('holds for every policy built from valid values', () => {
    const random = mulberry32(SEED);

    for (let i = 0; i < RUNS; i++) {
      const policy = randomPolicy(random);
      const context = () => 'seed ' + SEED + ', run ' + i + ', policy ' + JSON.stringify(policy);
      const result = run(CSP.getCSP(policy));
      const value = result.value;

      assert.equal(
        result.name,
        policy['report-only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy',
        context()
      );

      // Nothing that would split the response or start a second policy.
      assert.doesNotMatch(value, /[\r\n,]/, context());
      assert.ok(!value.includes('\u0000'), context());
      assert.doesNotMatch(value, /[^\x20-\x7e]/, context());

      if (value === '') {
        continue;
      }

      // No stray whitespace: no leading, trailing or doubled spaces, and no
      // empty segment between separators.
      assert.equal(value, value.trim(), context());
      assert.doesNotMatch(value, / {2}/, context());
      assert.doesNotMatch(value, /(^|;)\s*(;|$)/, context());

      const parts = value.split('; ');
      const names = parts.map(part => part.split(' ')[0]);

      // ";" is the directive separator, so it may appear between parts but
      // never inside one.
      for (const part of parts) {
        assert.doesNotMatch(part, /;/, context());
        assert.equal(part, part.trim(), context());
      }

      // Every part is a well-formed directive, emitted once, that the caller
      // actually asked for, and never the report-only control key.
      assert.equal(new Set(names).size, names.length, context());
      for (const name of names) {
        assert.match(name, /^[A-Za-z0-9-]+$/, context());
        assert.notEqual(name, 'report-only', context());
        assert.ok(Object.hasOwn(policy, name), context());
        assert.ok(policy[name], context());
      }

      // Known directives keep their relative spec order.
      const known = names.filter(name => CSP.DIRECTIVES.includes(name));
      const ordered = CSP.DIRECTIVES.filter(name => known.includes(name));
      assert.deepEqual(known, ordered, context());

      // Unknown directives all come after the known ones.
      const lastKnown = names.findLastIndex(name => CSP.DIRECTIVES.includes(name));
      const firstUnknown = names.findIndex(name => !CSP.DIRECTIVES.includes(name));
      if (lastKnown !== -1 && firstUnknown !== -1) {
        assert.ok(firstUnknown > lastKnown, context());
      }
    }
  });

  it('rejects every policy carrying a hostile value', () => {
    const random = mulberry32(SEED ^ 0xffff);

    for (let i = 0; i < RUNS; i++) {
      const policy = randomPolicy(random);
      const name = CSP.DIRECTIVES[Math.floor(random() * CSP.DIRECTIVES.length)];
      const hostile = HOSTILE[Math.floor(random() * HOSTILE.length)];

      policy[name] = random() < 0.5 ? hostile : [CSP.SRC_SELF, hostile];

      assert.throws(
        () => CSP.getCSP(policy),
        { name: 'TypeError' },
        'seed ' + SEED + ', run ' + i + ', policy ' + JSON.stringify(policy)
      );
    }
  });

  it('is deterministic: the same policy always compiles to the same header', () => {
    const random = mulberry32(SEED);

    for (let i = 0; i < 200; i++) {
      const policy = randomPolicy(random);
      const first = run(CSP.getCSP(policy)).value;
      const second = run(CSP.getCSP(structuredClone(policy))).value;

      assert.equal(first, second, JSON.stringify(policy));
    }
  });
});
