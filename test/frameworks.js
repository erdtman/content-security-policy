'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');

/**
 * The adapters against the real frameworks.
 *
 * test/adapters.js asserts the same behaviour against doubles, which is what
 * keeps the default suite dependency-free. Doubles can only be wrong in the
 * same way twice, though: they cannot tell us that reply.header is still the
 * way to set a header in Fastify, or that hapi puts an error response's headers
 * somewhere else. That is what this layer is for.
 *
 * Each framework is skipped unless it is installed, so `npm test` passes with
 * no dependencies at all. `npm run test:frameworks` installs them and runs
 * this file; CI does the same on every push.
 */

/** The app-wide policy, and the two that routes override it with. */
const GLOBAL = CSP.STARTER_OPTIONS;
const LOCAL = { 'default-src': CSP.SRC_NONE, 'script-src': CSP.SRC_SELF };
const REPORT = { 'default-src': CSP.SRC_NONE, 'report-only': true };

const GLOBAL_VALUE = CSP.getCSPHeader(GLOBAL).value;
const LOCAL_VALUE = CSP.getCSPHeader(LOCAL).value;
const REPORT_VALUE = CSP.getCSPHeader(REPORT).value;

/**
 * @param name a framework's package name
 * @returns the framework, or null when it is not installed
 */
function load (name) {
  try {
    return require(name);
  } catch {
    return null;
  }
}

/**
 * Wrap a listening Node server in the interface the tests use, so that a real
 * server and Hono's in-process dispatch look the same to them.
 *
 * @param server a listening http.Server
 * @param close how to shut the framework down
 * @returns an app with request() and close()
 */
function serving (server, close) {
  const origin = `http://127.0.0.1:${server.address().port}`;

  return {
    request: path => fetch(`${origin}${path}`),
    close
  };
}

const HARNESSES = [
  {
    label: 'express',
    module: 'express',
    factory: CSP.getCSP,
    // express serves a 404 through finalhandler, which sets a policy of its
    // own after every middleware has run, overwriting ours. It is stricter
    // than anything this library compiles, so the page is still locked down;
    // an app that wants its own policy there has to handle 404s itself. The
    // README says so, and this pins the claim.
    generatedPolicy: 'default-src \'none\'',
    async boot (express, { global, local, report }) {
      const app = express();

      app.use(global);
      app.get('/', (req, res) => res.send('ok'));
      app.get('/local', local, (req, res) => res.send('ok'));
      app.get('/report', report, (req, res) => res.send('ok'));

      const server = app.listen(0, '127.0.0.1');
      await new Promise(resolve => server.once('listening', resolve));

      return serving(server, () => new Promise(resolve => server.close(resolve)));
    }
  },
  {
    label: 'fastify',
    module: 'fastify',
    factory: CSP.getFastifyCSP,
    async boot (fastify, { global, local, report }) {
      const app = fastify();

      app.addHook('onRequest', global);
      app.get('/', async () => 'ok');
      // A route-level hook runs after the instance-wide one, so it wins.
      app.get('/local', { onRequest: local }, async () => 'ok');
      app.get('/report', { onRequest: report }, async () => 'ok');

      await app.listen({ port: 0, host: '127.0.0.1' });

      return serving(app.server, () => app.close());
    }
  },
  {
    label: 'koa',
    module: 'koa',
    factory: CSP.getKoaCSP,
    async boot (Koa, { global, local, report }) {
      const app = new Koa();
      // Koa has no router of its own, so the route-local policies are
      // dispatched by path. Nesting is the point either way: the inner
      // middleware is the more specific one.
      const routes = { '/local': local, '/report': report };

      app.use(global);
      app.use((ctx, next) => (routes[ctx.path] ? routes[ctx.path](ctx, next) : next()));
      app.use(ctx => {
        if (ctx.path !== '/missing') {
          ctx.body = 'ok';
        }
      });

      const server = app.listen(0, '127.0.0.1');
      await new Promise(resolve => server.once('listening', resolve));

      return serving(server, () => new Promise(resolve => server.close(resolve)));
    }
  },
  {
    label: 'hono',
    module: 'hono',
    factory: CSP.getHonoCSP,
    async boot ({ Hono }, { global, local, report }) {
      const app = new Hono();

      app.use('*', global);
      app.get('/', c => c.text('ok'));
      app.get('/local', local, c => c.text('ok'));
      app.get('/report', report, c => c.text('ok'));

      // Hono dispatches a Request to a Response in process, so it needs no
      // server adapter, and no port.
      return { request: path => app.request(path), close: () => {} };
    }
  },
  {
    label: 'hapi',
    module: '@hapi/hapi',
    factory: CSP.getHapiCSP,
    async boot (Hapi, { global, local, report }) {
      const server = Hapi.server({ port: 0, host: '127.0.0.1' });

      server.ext('onPreResponse', global);
      server.route([
        { method: 'GET', path: '/', handler: () => 'ok' },
        {
          method: 'GET',
          path: '/local',
          options: { ext: { onPreResponse: { method: local } } },
          handler: () => 'ok'
        },
        {
          method: 'GET',
          path: '/report',
          options: { ext: { onPreResponse: { method: report } } },
          handler: () => 'ok'
        }
      ]);

      await server.start();

      return {
        request: path => fetch(`${server.info.uri}${path}`),
        close: () => server.stop()
      };
    }
  }
];

for (const harness of HARNESSES) {
  const framework = load(harness.module);

  describe(harness.label, { skip: framework ? false : `${harness.module} is not installed` }, () => {
    let app;

    before(async () => {
      app = await harness.boot(framework, {
        global: harness.factory(GLOBAL),
        local: harness.factory(LOCAL),
        report: harness.factory(REPORT)
      });
    });

    after(() => app.close());

    it('sends the app-wide policy', async () => {
      const response = await app.request('/');

      assert.equal(response.status, 200);
      assert.equal(response.headers.get('content-security-policy'), GLOBAL_VALUE);
      assert.equal(response.headers.get('content-security-policy-report-only'), null);
    });

    it('lets a route-local policy override the app-wide one', async () => {
      const response = await app.request('/local');

      assert.equal(response.headers.get('content-security-policy'), LOCAL_VALUE);
    });

    it('leaves only the report-only header on a report-only route', async () => {
      const response = await app.request('/report');

      assert.equal(response.headers.get('content-security-policy-report-only'), REPORT_VALUE);
      assert.equal(response.headers.get('content-security-policy'), null);
    });

    it('never sends the header twice', async () => {
      // fetch joins repeated headers with ", ", and a valid policy value can
      // never contain a comma, so this detects duplication.
      const value = (await app.request('/local')).headers.get('content-security-policy');

      assert.ok(!value.includes(','), value);
    });

    it('covers a response the framework generated itself', async () => {
      // A 404 is served by the framework, not by a handler. That is the case
      // an adapter is most likely to miss, and the case where a missing policy
      // matters: an error page is as good a place to inject as any other.
      const response = await app.request('/missing');

      assert.equal(response.status, 404);
      assert.equal(response.headers.get('content-security-policy'), harness.generatedPolicy || GLOBAL_VALUE);
    });
  });
}
