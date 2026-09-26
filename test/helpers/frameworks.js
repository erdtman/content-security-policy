'use strict';

const CSP = require('../../lib/index.js');

/**
 * One entry per framework this library adapts, behind a single interface, so a
 * test can state a property once and have it checked against every adapter.
 *
 * Each entry builds a double shaped like that framework's response object and
 * records what the adapter did to it, because the contract is not only "the
 * right header survives": it is also that the stale header is cleared first,
 * that the header name keeps its canonical casing, and that the framework's
 * continuation is taken exactly once.
 *
 * `exercise` takes middlewares outermost-first and composes them the way the
 * framework would: in sequence where the framework runs a list, nested where
 * it wraps. Either way the last one listed is the most specific, so it is the
 * one whose policy must survive.
 */

/** Stands in for hapi's own continue symbol. */
const CONTINUE = Symbol('continue');

/**
 * A recording header store. Every framework here is a different spelling of
 * "set this header" and "remove that one", so the doubles differ only in the
 * method names they expose and in what they do with them.
 *
 * @returns a store with an ordered `calls` log and the surviving `headers`,
 *   keyed by lowercased name because that is how HTTP compares them
 */
function store () {
  const calls = [];
  const headers = new Map();

  return {
    calls,
    headers,
    set (name, value) {
      calls.push(['set', name, value]);
      headers.set(name.toLowerCase(), value);
    },
    remove (name) {
      calls.push(['remove', name]);
      headers.delete(name.toLowerCase());
    },
    /** A header that was already on the response, so not a call of ours. */
    seed (name, value) {
      headers.set(name.toLowerCase(), value);
    }
  };
}

const ADAPTERS = [
  {
    label: 'connect/express',
    factory: CSP.getCSP,
    async exercise (middlewares, s, continuations) {
      const res = {
        setHeader: (name, value) => s.set(name, value),
        removeHeader: name => s.remove(name)
      };

      for (const middleware of middlewares) {
        middleware(null, res, (...args) => continuations.push(args));
      }
    }
  },
  {
    label: 'fastify',
    factory: CSP.getFastifyCSP,
    async exercise (hooks, s, continuations) {
      const reply = {
        header: (name, value) => s.set(name, value),
        removeHeader: name => s.remove(name)
      };

      for (const hook of hooks) {
        hook({}, reply, (...args) => continuations.push(args));
      }
    }
  },
  {
    label: 'koa',
    factory: CSP.getKoaCSP,
    async exercise (middlewares, s, continuations) {
      const ctx = {
        set: (field, value) => s.set(field, value),
        remove: field => s.remove(field)
      };

      // Koa nests: the first middleware wraps the rest.
      await nest(middlewares, continuations, (middleware, next) => middleware(ctx, next));
    }
  },
  {
    label: 'hono',
    factory: CSP.getHonoCSP,
    async exercise (middlewares, s, continuations) {
      const c = {
        // Hono deletes a header when handed undefined as its value.
        header: (name, value) => (value === undefined ? s.remove(name) : s.set(name, value))
      };

      await nest(middlewares, continuations, (middleware, next) => middleware(c, next));
    }
  },
  {
    label: 'hapi',
    factory: CSP.getHapiCSP,
    async exercise (extensions, s, continuations, { boom = false, existing = {} } = {}) {
      // hapi's headers are a plain object, one level further in on a Boom error
      // response. A proxy keeps them a real object, with real Object.keys and
      // real deletes, while still recording what was done to them in order.
      // `existing` is seeded behind the proxy: it models what some other
      // extension left there, so it is not one of our calls.
      const target = { ...existing };

      for (const [name, value] of Object.entries(existing)) {
        s.seed(name, value);
      }

      const headers = new Proxy(target, {
        set (target, name, value) {
          s.set(name, value);
          target[name] = value;
          return true;
        },
        deleteProperty (target, name) {
          s.remove(name);
          delete target[name];
          return true;
        }
      });
      const response = boom ? { isBoom: true, output: { headers } } : { headers };
      const h = { continue: CONTINUE };

      for (const extension of extensions) {
        if (extension({ response }, h) === CONTINUE) {
          continuations.push([]);
        }
      }
    }
  },
  {
    label: 'headers',
    factory: CSP.getHeadersCSP,
    async exercise (appliers, s, continuations) {
      // A real Headers, so the adapter is checked against the platform rather
      // than against a guess at it: Headers rejects a value Node would refuse
      // to send, and lowercases the names it keeps.
      const headers = new Headers();
      const recording = {
        set: (name, value) => { s.set(name, value); headers.set(name, value); },
        delete: name => { s.remove(name); headers.delete(name); }
      };

      for (const applier of appliers) {
        applier(recording);
        // There is no next() to take in a bare Headers, so applying the policy
        // is the whole of it.
        continuations.push([]);
      }
    }
  }
];

/**
 * Compose middlewares the way a nesting framework does: the first wraps the
 * second, and the innermost is handed a next() that records being called.
 *
 * @param middlewares the stack, outermost first
 * @param continuations where each next() call is recorded
 * @param call invokes one middleware with the next() it should chain to
 * @returns a promise for the whole chain
 */
function nest (middlewares, continuations, call) {
  const step = i => {
    if (i === middlewares.length) {
      continuations.push([]);
      return Promise.resolve();
    }
    return Promise.resolve(call(middlewares[i], () => step(i + 1)));
  };

  return step(0);
}

/**
 * Run one adapter's middlewares against a fresh double.
 *
 * @param adapter an ADAPTERS entry
 * @param middlewares the stack, outermost first
 * @param options passed to the adapter, currently only hapi's `boom`
 * @returns the ordered call log, the surviving headers, and one entry per
 *   continuation taken
 */
async function exercise (adapter, middlewares, options) {
  const s = store();
  const continuations = [];

  await adapter.exercise(middlewares, s, continuations, options);

  return { calls: s.calls, headers: s.headers, continuations };
}

/**
 * The single header an adapter leaves behind.
 *
 * @param adapter an ADAPTERS entry
 * @param middlewares the stack, outermost first
 * @returns the surviving header as a `{ name, value }` pair, with a lowercased
 *   name, or undefined if there is none
 */
async function survivingHeader (adapter, middlewares) {
  const { headers } = await exercise(adapter, middlewares);
  const [name, value] = [...headers.entries()].at(-1) || [];

  return name === undefined ? undefined : { name, value };
}

module.exports = { ADAPTERS, CONTINUE, exercise, survivingHeader };
