'use strict';

const http = require('node:http');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');

/**
 * The tests above this file all talk to a response double. These talk to a
 * real http.ServerResponse over a real socket, which is the only way to catch
 * a header Node itself refuses to send, and the only way to prove the
 * documented "a later middleware overrides an earlier one" behaviour.
 */

/** The middleware stack the current test wants to run. Set per test. */
let stack = [];

let server;
let origin;

before(async () => {
  server = http.createServer((req, res) => {
    // A minimal connect: run the stack, then answer.
    const run = i => {
      if (i === stack.length) {
        res.end('ok');
        return;
      }
      stack[i](req, res, () => run(i + 1));
    };

    try {
      run(0);
    } catch (error) {
      res.statusCode = 500;
      res.setHeader('X-Error', error.code || error.name);
      res.end(String(error.message));
    }
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = 'http://127.0.0.1:' + server.address().port;
});

after(() => new Promise(resolve => server.close(resolve)));

/**
 * Serve one request through the given middleware stack.
 *
 * @param middlewares the stack to run, in order
 * @returns the response
 */
async function request (...middlewares) {
  stack = middlewares;
  return fetch(origin + '/');
}

describe('over a real HTTP response', () => {
  it('sends the compiled policy verbatim', async () => {
    const response = await request(CSP.getCSP(CSP.STARTER_OPTIONS));

    assert.equal(response.status, 200);
    assert.equal(
      response.headers.get('content-security-policy'),
      'default-src \'none\'; child-src \'self\'; connect-src \'self\'; font-src \'self\'; img-src \'self\'; ' +
      'object-src \'none\'; script-src \'self\'; style-src \'self\'; base-uri \'self\'; form-action \'self\'; ' +
      'frame-ancestors \'self\''
    );
    assert.equal(response.headers.get('content-security-policy-report-only'), null);
  });

  it('sends the report-only header instead when asked', async () => {
    const response = await request(CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true }));

    assert.equal(response.headers.get('content-security-policy-report-only'), 'default-src \'none\'');
    assert.equal(response.headers.get('content-security-policy'), null);
  });

  it('runs the rest of the stack, so a dropped next() would hang the request', async () => {
    const response = await request(CSP.getCSP(CSP.STARTER_OPTIONS));

    assert.equal(await response.text(), 'ok');
  });

  it('lets a path-local policy override a global one, as the README promises', async () => {
    const response = await request(
      CSP.getCSP(CSP.STARTER_OPTIONS),
      CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'script-src': CSP.SRC_SELF })
    );

    assert.equal(response.headers.get('content-security-policy'), 'default-src \'none\'; script-src \'self\'');
  });

  it('leaves exactly one CSP header when a policy switches to report-only', async () => {
    const response = await request(
      CSP.getCSP(CSP.STARTER_OPTIONS),
      CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true })
    );

    assert.equal(response.headers.get('content-security-policy'), null);
    assert.equal(response.headers.get('content-security-policy-report-only'), 'default-src \'none\'');
  });

  it('never emits a duplicate header', async () => {
    const response = await request(CSP.getCSP(CSP.STARTER_OPTIONS), CSP.getCSP(CSP.STARTER_OPTIONS));
    const value = response.headers.get('content-security-policy');

    // fetch joins repeated headers with ", ", and a valid policy value can
    // never contain a comma, so this detects duplication.
    assert.ok(!value.includes(','), value);
  });

  it('sends an empty policy without breaking the response', async () => {
    const response = await request(CSP.getCSP());

    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-security-policy'), '');
  });

  it('survives a long policy intact', async () => {
    const sources = Array.from({ length: 200 }, (_, i) => 'https://cdn' + i + '.example');
    const response = await request(CSP.getCSP({ 'script-src': sources }));

    assert.equal(response.headers.get('content-security-policy'), 'script-src ' + sources.join(' '));
  });
});

describe('header injection', () => {
  it('is rejected when the policy is built, not when the response is sent', async () => {
    // Before validation existed this compiled happily and then threw
    // ERR_INVALID_CHAR inside res.setHeader, turning every request into a 500.
    assert.throws(
      () => CSP.getCSP({ 'script-src': '\'self\'\r\nX-Injected: yes' }),
      { name: 'TypeError', message: /Invalid character/ }
    );
  });

  it('cannot produce a header value Node refuses to send', async () => {
    const hostile = [
      '\'self\'\r\nX-Injected: yes',
      '\'self\'\nX-Injected: yes',
      '\'self\'; object-src *',
      '\'self\', default-src *',
      '\'self\'\u0000'
    ];

    for (const value of hostile) {
      let middleware;
      assert.throws(() => { middleware = CSP.getCSP({ 'script-src': value }); }, TypeError, value);
      assert.equal(middleware, undefined);
    }

    // And what does get through is always accepted by a real response.
    const response = await request(CSP.getCSP({ 'script-src': [CSP.SRC_SELF, '\'nonce-a+b/c==\''] }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-error'), null);
  });
});
