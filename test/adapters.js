'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');
const { ADAPTERS, CONTINUE, exercise, survivingHeader } = require('./helpers/frameworks.js');

/**
 * The framework adapters, against doubles shaped like each framework's response
 * object. test/frameworks.js runs the same adapters against the real
 * frameworks, but only when they are installed, so everything that has to hold
 * on every run is asserted here.
 *
 * Most of the file is one loop: an adapter is only correct if it agrees with
 * getCSPHeader, leaves exactly one header, and hands control on, so those are
 * stated once and checked against all of them. The per-adapter blocks below
 * cover what differs, which is how each framework spells those operations.
 */

const STARTER = CSP.getCSPHeader(CSP.STARTER_OPTIONS);
const REPORT_ONLY = { 'default-src': CSP.SRC_NONE, 'report-only': true };
const LOCAL = { 'default-src': CSP.SRC_NONE, 'script-src': CSP.SRC_SELF };

describe('getCSPHeader', () => {
  it('compiles a policy to the one header it is sent as', () => {
    assert.deepEqual(CSP.getCSPHeader({ 'default-src': CSP.SRC_NONE }), {
      name: 'Content-Security-Policy',
      value: 'default-src \'none\''
    });
  });

  it('names the report-only header when the policy asks for it', () => {
    assert.deepEqual(CSP.getCSPHeader(REPORT_ONLY), {
      name: 'Content-Security-Policy-Report-Only',
      value: 'default-src \'none\''
    });
  });

  it('compiles an empty or missing policy to an empty value', () => {
    for (const policy of [undefined, null, {}]) {
      assert.deepEqual(CSP.getCSPHeader(policy), { name: 'Content-Security-Policy', value: '' });
    }
  });

  it('is frozen, so a caller cannot rewrite a shared header', () => {
    const header = CSP.getCSPHeader(CSP.STARTER_OPTIONS);

    assert.ok(Object.isFrozen(header));
    assert.throws(() => { header.value = 'default-src *'; }, TypeError);
    assert.throws(() => { header.name = 'X-Content-Security-Policy'; }, TypeError);
  });

  it('validates the policy, like every factory built on it', () => {
    assert.throws(() => CSP.getCSPHeader({ 'script-src': '\'self\'\r\nX: y' }), /Invalid character/);
    assert.throws(() => CSP.getCSPHeader('default-src'), /must be a policy object/);
  });
});

describe('every adapter', () => {
  for (const adapter of ADAPTERS) {
    describe(adapter.label, () => {
      it('sets the header getCSPHeader compiled, and only that header', async () => {
        const { headers } = await exercise(adapter, [adapter.factory(CSP.STARTER_OPTIONS)]);

        assert.deepEqual([...headers], [[STARTER.name.toLowerCase(), STARTER.value]]);
      });

      it('switches to the report-only header', async () => {
        const { headers } = await exercise(adapter, [adapter.factory(REPORT_ONLY)]);

        assert.deepEqual([...headers], [['content-security-policy-report-only', 'default-src \'none\'']]);
      });

      it('hands control on exactly once, with no arguments', async () => {
        const { continuations } = await exercise(adapter, [adapter.factory(CSP.STARTER_OPTIONS)]);

        assert.deepEqual(continuations, [[]]);
      });

      it('lets the most specific policy win', async () => {
        // Outermost first: an app-wide policy, then a route-local one. The
        // route-local one is the answer whether the framework runs a list or
        // nests, which is the reason the Hono adapter sets before next().
        const header = await survivingHeader(adapter, [
          adapter.factory(CSP.STARTER_OPTIONS),
          adapter.factory(LOCAL)
        ]);

        assert.deepEqual(header, {
          name: 'content-security-policy',
          value: 'default-src \'none\'; script-src \'self\''
        });
      });

      it('leaves exactly one header when a policy switches to report-only', async () => {
        const { headers } = await exercise(adapter, [
          adapter.factory(CSP.STARTER_OPTIONS),
          adapter.factory(REPORT_ONLY)
        ]);

        assert.deepEqual([...headers], [['content-security-policy-report-only', 'default-src \'none\'']]);
      });

      it('compiles once, at build time', async () => {
        const policy = { 'default-src': CSP.SRC_NONE };
        const middleware = adapter.factory(policy);
        policy['default-src'] = CSP.SRC_ANY;
        policy['script-src'] = CSP.SRC_UNSAFE_INLINE;

        assert.equal((await survivingHeader(adapter, [middleware])).value, 'default-src \'none\'');
      });

      it('holds no per-request state, so it is reusable', async () => {
        const middleware = adapter.factory(CSP.STARTER_OPTIONS);
        const first = await exercise(adapter, [middleware]);
        const second = await exercise(adapter, [middleware]);

        assert.deepEqual(second.calls, first.calls);
        assert.deepEqual([...second.headers], [...first.headers]);
      });

      it('rejects a malformed policy at build time', () => {
        assert.throws(() => adapter.factory({ 'script-src': '\'self\'; object-src *' }), {
          name: 'TypeError',
          message: /Invalid character ";"/
        });
        assert.throws(() => adapter.factory('default-src'), { name: 'TypeError', message: /policy object/ });
      });

      it('tolerates being built with no policy at all', async () => {
        const header = await survivingHeader(adapter, [adapter.factory()]);

        assert.deepEqual(header, { name: 'content-security-policy', value: '' });
      });
    });
  }
});

describe('getCSP', () => {
  it('clears both headers through the response, then sets one', async () => {
    const adapter = ADAPTERS.find(entry => entry.label === 'connect/express');
    const { calls } = await exercise(adapter, [adapter.factory({ 'default-src': CSP.SRC_NONE })]);

    assert.deepEqual(calls, [
      ['remove', 'Content-Security-Policy-Report-Only'],
      ['remove', 'Content-Security-Policy'],
      ['set', 'Content-Security-Policy', 'default-src \'none\'']
    ]);
  });
});

describe('getFastifyCSP', () => {
  const adapter = ADAPTERS.find(entry => entry.label === 'fastify');

  it('uses reply.removeHeader and reply.header, in that order', async () => {
    const { calls } = await exercise(adapter, [adapter.factory({ 'default-src': CSP.SRC_NONE })]);

    assert.deepEqual(calls, [
      ['remove', 'Content-Security-Policy-Report-Only'],
      ['remove', 'Content-Security-Policy'],
      ['set', 'Content-Security-Policy', 'default-src \'none\'']
    ]);
  });

  it('calls done() rather than returning a promise, so it suits both hook styles', () => {
    const hook = CSP.getFastifyCSP(CSP.STARTER_OPTIONS);
    let done = 0;

    const returned = hook({}, { header: () => {}, removeHeader: () => {} }, () => { done++; });

    assert.equal(returned, undefined);
    assert.equal(done, 1);
  });
});

describe('getKoaCSP', () => {
  const adapter = ADAPTERS.find(entry => entry.label === 'koa');

  it('uses ctx.remove and ctx.set, in that order', async () => {
    const { calls } = await exercise(adapter, [adapter.factory({ 'default-src': CSP.SRC_NONE })]);

    assert.deepEqual(calls, [
      ['remove', 'Content-Security-Policy-Report-Only'],
      ['remove', 'Content-Security-Policy'],
      ['set', 'Content-Security-Policy', 'default-src \'none\'']
    ]);
  });

  it('returns the downstream promise, which Koa awaits', async () => {
    const middleware = CSP.getKoaCSP(CSP.STARTER_OPTIONS);
    const ctx = { set: () => {}, remove: () => {} };
    let finished = false;

    const returned = middleware(ctx, async () => { finished = true; });

    assert.ok(returned instanceof Promise, 'a dropped return would let Koa respond too early');
    await returned;
    assert.ok(finished);
  });
});

describe('getHonoCSP', () => {
  const adapter = ADAPTERS.find(entry => entry.label === 'hono');

  it('deletes with undefined, the way Hono spells removing a header', async () => {
    const seen = [];
    const middleware = CSP.getHonoCSP({ 'default-src': CSP.SRC_NONE });

    await middleware({ header: (name, value) => seen.push([name, value]) }, async () => {});

    assert.deepEqual(seen, [
      ['Content-Security-Policy-Report-Only', undefined],
      ['Content-Security-Policy', undefined],
      ['Content-Security-Policy', 'default-src \'none\'']
    ]);
  });

  it('sets the header before awaiting next(), not after', async () => {
    // Hono unwinds outermost-last, so a policy set after next() would be the
    // app-wide one overwriting the route-local one. Proven here by asserting
    // the header is already there when the handler runs.
    const middleware = CSP.getHonoCSP({ 'default-src': CSP.SRC_NONE });
    const headers = new Map();
    let duringHandler;

    await middleware(
      { header: (name, value) => (value === undefined ? headers.delete(name) : headers.set(name, value)) },
      async () => { duringHandler = headers.get('Content-Security-Policy'); }
    );

    assert.equal(duringHandler, 'default-src \'none\'');
  });

  it('returns the downstream promise', async () => {
    const returned = CSP.getHonoCSP()({ header: () => {} }, async () => {});

    assert.ok(returned instanceof Promise);
    await returned;
  });

  it('lets a route-local policy win over an app-wide one, via the adapter table', async () => {
    const header = await survivingHeader(adapter, [adapter.factory(CSP.STARTER_OPTIONS), adapter.factory(LOCAL)]);

    assert.equal(header.value, 'default-src \'none\'; script-src \'self\'');
  });
});

describe('getHapiCSP', () => {
  const adapter = ADAPTERS.find(entry => entry.label === 'hapi');

  it('sets the header on a normal response and returns h.continue', () => {
    const headers = {};
    const h = { continue: CONTINUE };

    const returned = CSP.getHapiCSP({ 'default-src': CSP.SRC_NONE })({ response: { headers } }, h);

    assert.deepEqual(headers, { 'Content-Security-Policy': 'default-src \'none\'' });
    assert.equal(returned, CONTINUE);
  });

  it('sets the header on an error response too, where Boom keeps its headers', async () => {
    // hapi serves 404s and 500s itself, so an extension that only handled
    // normal responses would let every error page out with no policy.
    const { headers, continuations } = await exercise(
      adapter,
      [adapter.factory(CSP.STARTER_OPTIONS)],
      { boom: true }
    );

    assert.deepEqual([...headers], [[STARTER.name.toLowerCase(), STARTER.value]]);
    assert.deepEqual(continuations, [[]]);
  });

  it('clears a policy another extension left, whatever case it used', async () => {
    // hapi lowercases the names it is given, so the stale header is rarely
    // spelled the way this library spells it.
    const { headers } = await exercise(adapter, [adapter.factory(REPORT_ONLY)], {
      existing: {
        'content-security-policy': 'default-src *',
        'Content-Security-Policy-Report-Only': 'default-src *',
        // Only the two headers this library sets are cleared. The legacy IE
        // header is someone else's, and it is not a policy this one replaces.
        'x-content-security-policy': 'default-src *',
        'x-frame-options': 'DENY'
      }
    });

    assert.deepEqual([...headers].sort(), [
      ['content-security-policy-report-only', 'default-src \'none\''],
      ['x-content-security-policy', 'default-src *'],
      ['x-frame-options', 'DENY']
    ]);
  });
});

describe('getHeadersCSP', () => {
  it('applies the policy to a real Headers object', () => {
    const headers = new Headers({ 'content-security-policy': 'default-src *', 'x-frame-options': 'DENY' });

    CSP.getHeadersCSP(REPORT_ONLY)(headers);

    assert.equal(headers.get('content-security-policy'), null);
    assert.equal(headers.get('content-security-policy-report-only'), 'default-src \'none\'');
    assert.equal(headers.get('x-frame-options'), 'DENY');
  });

  it('applies it to a Response, which is how a Fetch framework sends one', () => {
    const response = new Response('ok');

    CSP.getHeadersCSP(CSP.STARTER_OPTIONS)(response.headers);

    assert.equal(response.headers.get('Content-Security-Policy'), STARTER.value);
  });

  it('returns nothing: it mutates the headers it is handed', () => {
    assert.equal(CSP.getHeadersCSP()(new Headers()), undefined);
  });
});
