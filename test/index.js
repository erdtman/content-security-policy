'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');
const { recordingResponse, run, headerValue } = require('./helpers/response.js');

describe('header compilation', () => {
  it('compiles the starter policy exactly', () => {
    // Asserted as one exact string rather than with includes(): a substring
    // check still passes when a directive is widened, which is the bug that
    // matters most in a policy this library exists to keep narrow.
    assert.equal(headerValue(CSP.getCSP(CSP.STARTER_OPTIONS)), [
      'default-src \'none\'',
      'child-src \'self\'',
      'connect-src \'self\'',
      'font-src \'self\'',
      'img-src \'self\'',
      'object-src \'none\'',
      'script-src \'self\'',
      'style-src \'self\'',
      'base-uri \'self\'',
      'form-action \'self\'',
      'frame-ancestors \'self\''
    ].join('; '));
  });

  it('serialises a string value', () => {
    assert.equal(headerValue(CSP.getCSP({ 'script-src': CSP.SRC_SELF })), 'script-src \'self\'');
  });

  it('joins an array value with single spaces', () => {
    assert.equal(
      headerValue(CSP.getCSP({ 'script-src': [CSP.SRC_SELF, CSP.SRC_STRICT_DYNAMIC, 'https://cdn.example'] })),
      'script-src \'self\' \'strict-dynamic\' https://cdn.example'
    );
  });

  it('trims surrounding whitespace from strings and array members', () => {
    assert.equal(
      headerValue(CSP.getCSP({ 'script-src': '  \'self\'  ', 'style-src': ['  \'self\'', 'https://cdn.example  '] })),
      'script-src \'self\'; style-src \'self\' https://cdn.example'
    );
  });

  it('emits a valueless directive as its name alone', () => {
    assert.equal(
      headerValue(CSP.getCSP({ 'default-src': CSP.SRC_SELF, 'upgrade-insecure-requests': true })),
      'default-src \'self\'; upgrade-insecure-requests'
    );
  });

  it('keeps numeric array members, including zero', () => {
    assert.equal(headerValue(CSP.getCSP({ 'report-uri': ['/r', 0] })), 'report-uri /r 0');
  });

  it('skips falsy values so a directive can be toggled off', () => {
    assert.equal(headerValue(CSP.getCSP({
      'default-src': CSP.SRC_SELF,
      'script-src': false,
      'style-src': null,
      'img-src': '',
      'font-src': '   ',
      'media-src': [],
      'object-src': ['', null],
      'worker-src': undefined
    })), 'default-src \'self\'');
  });

  it('ignores values that are neither string, array nor true', () => {
    assert.equal(headerValue(CSP.getCSP({
      'default-src': CSP.SRC_SELF,
      'script-src': 42,
      'style-src': { nope: true },
      'img-src': () => {}
    })), 'default-src \'self\'');
  });

  it('produces an empty header for an empty or missing policy', () => {
    for (const policy of [undefined, null, {}]) {
      const result = run(CSP.getCSP(policy));
      assert.equal(result.name, 'Content-Security-Policy');
      assert.equal(result.value, '');
    }
  });

  it('switches header when report-only is truthy, without emitting it', () => {
    const result = run(CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true }));

    assert.equal(result.name, 'Content-Security-Policy-Report-Only');
    assert.equal(result.value, 'default-src \'none\'');
  });

  it('keeps the enforcing header when report-only is falsy', () => {
    const result = run(CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': false }));

    assert.equal(result.name, 'Content-Security-Policy');
    assert.equal(result.value, 'default-src \'none\'');
  });

  it('rejects options that are not a policy object', () => {
    for (const bad of ['default-src', 42, true, ['default-src'], Symbol('x')]) {
      assert.throws(() => CSP.getCSP(bad), { name: 'TypeError', message: /must be a policy object/ });
    }
  });

  it('shows the offending value in that error', () => {
    assert.throws(
      () => CSP.getCSP('default-src'),
      { message: 'Content-Security-Policy options must be a policy object, got "default-src"' }
    );
    assert.throws(
      () => CSP.getCSP(42),
      { message: 'Content-Security-Policy options must be a policy object, got 42' }
    );
    assert.throws(
      () => CSP.getCSP([{ 'default-src': CSP.SRC_NONE }]),
      { message: 'Content-Security-Policy options must be a policy object, got an array' }
    );
  });

  it('drops array members that are only whitespace, without leaving a gap', () => {
    assert.equal(
      headerValue(CSP.getCSP({ 'script-src': ['  ', CSP.SRC_SELF, '\t', 'https://cdn.example'] })),
      'script-src \'self\' https://cdn.example'
    );
    assert.equal(headerValue(CSP.getCSP({ 'script-src': ['  ', '\t'] })), '');
  });
});

describe('directive ordering', () => {
  it('emits every known directive in DIRECTIVES order', () => {
    // Generated from DIRECTIVES so the whole ordering table is pinned and a
    // directive added later is covered without touching this test.
    const policy = Object.fromEntries(CSP.DIRECTIVES.map((name, i) => [name, 'v' + i]));
    const expected = CSP.DIRECTIVES.map((name, i) => name + ' v' + i).join('; ');

    assert.equal(headerValue(CSP.getCSP(policy)), expected);
  });

  it('emits unknown directives after the known ones, in insertion order', () => {
    assert.equal(headerValue(CSP.getCSP({
      'z-custom-src': 'https://z.example',
      'frame-ancestors': CSP.SRC_NONE,
      'a-custom-src': 'https://a.example',
      'script-src': CSP.SRC_SELF,
      'default-src': CSP.SRC_NONE
    })), [
      'default-src \'none\'',
      'script-src \'self\'',
      'frame-ancestors \'none\'',
      'z-custom-src https://z.example',
      'a-custom-src https://a.example'
    ].join('; '));
  });

  it('is unaffected by the order keys appear in the policy', () => {
    const value = headerValue(CSP.getCSP({ 'frame-ancestors': CSP.SRC_NONE, 'default-src': CSP.SRC_NONE }));
    const reversed = headerValue(CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'frame-ancestors': CSP.SRC_NONE }));

    assert.equal(value, reversed);
    assert.equal(value, 'default-src \'none\'; frame-ancestors \'none\'');
  });

  it('never emits a directive twice', () => {
    const policy = Object.fromEntries(CSP.DIRECTIVES.map(name => [name, CSP.SRC_SELF]));
    const names = headerValue(CSP.getCSP(policy)).split('; ').map(part => part.split(' ')[0]);

    assert.equal(new Set(names).size, names.length);
  });
});

describe('response interaction', () => {
  it('removes both CSP headers before setting one, and sets exactly one', () => {
    const result = run(CSP.getCSP({ 'default-src': CSP.SRC_NONE }));

    assert.deepEqual(result.calls, [
      ['removeHeader', 'Content-Security-Policy-Report-Only'],
      ['removeHeader', 'Content-Security-Policy'],
      ['setHeader', 'Content-Security-Policy', 'default-src \'none\'']
    ]);
  });

  it('calls next exactly once, with no arguments', () => {
    // Nothing else in the suite would notice next() being dropped or being
    // handed an error: line coverage stays at 100% either way.
    const result = run(CSP.getCSP(CSP.STARTER_OPTIONS));

    assert.deepEqual(result.nextCalls, [[]]);
  });

  it('lets a later middleware replace an earlier policy', () => {
    const res = recordingResponse();
    run(CSP.getCSP(CSP.STARTER_OPTIONS), res);
    const result = run(CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true }), res);

    assert.deepEqual([...res.headers.keys()], ['Content-Security-Policy-Report-Only']);
    assert.equal(result.value, 'default-src \'none\'');
  });

  it('is reusable across responses and holds no per-request state', () => {
    const middleware = CSP.getCSP(CSP.STARTER_OPTIONS);

    assert.equal(headerValue(middleware), headerValue(middleware));
    assert.deepEqual(run(middleware).calls, run(middleware).calls);
  });

  it('snapshots the policy when the middleware is built', () => {
    // Documented behaviour: the policy is compiled once, which is why a
    // per-request nonce cannot be expressed as a policy value.
    const policy = { 'default-src': CSP.SRC_NONE };
    const middleware = CSP.getCSP(policy);
    policy['default-src'] = CSP.SRC_ANY;
    policy['script-src'] = CSP.SRC_UNSAFE_INLINE;

    assert.equal(headerValue(middleware), 'default-src \'none\'');
  });
});

describe('validation', () => {
  it('rejects CR and LF, which would split the response', () => {
    for (const value of ['\'self\'\r\nX-Injected: yes', '\'self\'\nX: y', '\'self\'\rX: y']) {
      assert.throws(() => CSP.getCSP({ 'script-src': value }), { name: 'TypeError', message: /Invalid character/ });
    }
  });

  it('rejects ";" and ",", which would inject a directive or a second policy', () => {
    assert.throws(() => CSP.getCSP({ 'script-src': '\'self\'; object-src *' }), /Invalid character ";"/);
    assert.throws(() => CSP.getCSP({ 'script-src': '\'self\', default-src *' }), /Invalid character ","/);
  });

  it('rejects control and non-ASCII characters', () => {
    assert.throws(() => CSP.getCSP({ 'script-src': '\'self\'\u0000' }), /Invalid character/);
    assert.throws(() => CSP.getCSP({ 'script-src': 'https://exämple.test' }), /Invalid character/);
    assert.throws(() => CSP.getCSP({ 'script-src': 'https://a.test\u007f' }), /Invalid character/);
  });

  it('validates every member of an array value', () => {
    assert.throws(
      () => CSP.getCSP({ 'script-src': [CSP.SRC_SELF, 'https://ok.example', 'bad;value'] }),
      /Invalid character ";"/
    );
  });

  it('names the offending directive in the error', () => {
    assert.throws(() => CSP.getCSP({ 'img-src': 'a,b' }), {
      message: 'Invalid character "," in Content-Security-Policy directive "img-src": a directive value may ' +
        'not contain control characters, ";", "," or non-ASCII characters.'
    });
  });

  it('explains what a directive name may contain', () => {
    assert.throws(() => CSP.getCSP({ bad_name: CSP.SRC_SELF }), {
      message: 'Invalid Content-Security-Policy directive name "bad_name": a directive name may contain ' +
        'only ASCII letters, digits and "-".'
    });
  });

  it('rejects directive names outside the CSP grammar', () => {
    for (const name of ['script src', 'script_src', 'scrïpt-src', 'script;src', '']) {
      assert.throws(
        () => CSP.getCSP({ [name]: CSP.SRC_SELF }),
        { name: 'TypeError', message: /Invalid Content-Security-Policy directive name/ }
      );
    }
  });

  it('validates the name of a valueless directive too', () => {
    assert.throws(() => CSP.getCSP({ bad_name: true }), /Invalid Content-Security-Policy directive name/);
  });

  it('does not validate a directive that is not emitted', () => {
    // Toggling a directive off must never throw, whatever is behind the key.
    assert.doesNotThrow(() => CSP.getCSP({ bad_name: false, 'other bad': '', worse: [] }));
    assert.equal(headerValue(CSP.getCSP({ bad_name: false })), '');
  });

  it('accepts the punctuation real policies use', () => {
    const value = headerValue(CSP.getCSP({
      'script-src': [
        CSP.SRC_SELF,
        '\'nonce-r4nd0m+Va1ue/w1thPad==\'',
        '\'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8=\'',
        'https://cdn.example:8443/path?a=b&c=d#frag',
        'wss://*.example.test'
      ]
    }));

    assert.equal(value, [
      'script-src \'self\'',
      '\'nonce-r4nd0m+Va1ue/w1thPad==\'',
      '\'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8=\'',
      'https://cdn.example:8443/path?a=b&c=d#frag',
      'wss://*.example.test'
    ].join(' '));
  });
});

describe('prototype safety', () => {
  it('ignores directives inherited from the prototype chain', () => {
    Object.prototype['script-src'] = CSP.SRC_UNSAFE_EVAL;
    try {
      assert.equal(headerValue(CSP.getCSP({ 'default-src': CSP.SRC_NONE })), 'default-src \'none\'');
    } finally {
      delete Object.prototype['script-src'];
    }
  });

  it('ignores report-only inherited from the prototype chain', () => {
    Object.prototype['report-only'] = true;
    try {
      assert.equal(run(CSP.getCSP({ 'default-src': CSP.SRC_NONE })).name, 'Content-Security-Policy');
    } finally {
      delete Object.prototype['report-only'];
    }
  });

  it('ignores a policy-shaped object used as a prototype', () => {
    const policy = Object.create({ 'script-src': CSP.SRC_ANY });
    policy['default-src'] = CSP.SRC_NONE;

    assert.equal(headerValue(CSP.getCSP(policy)), 'default-src \'none\'');
  });

  it('rejects a __proto__ key arriving from a JSON config', () => {
    const policy = JSON.parse('{"default-src":"\'none\'","__proto__":"evil"}');

    assert.throws(() => CSP.getCSP(policy), /Invalid Content-Security-Policy directive name "__proto__"/);
  });
});
