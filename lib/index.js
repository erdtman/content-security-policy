'use strict';

/**
 * Middleware to add a Content-Security-Policy header.
 *
 * Policy reference: https://www.w3.org/TR/CSP3/
 *
 * A policy is a plain object keyed by directive name. Values may be:
 *   - a string, e.g. `'script-src': "'self'"`
 *   - an array of strings, e.g. `'script-src': ["'self'", 'https://cdn.example']`
 *   - `true`, for directives that take no value, e.g.
 *     `'upgrade-insecure-requests': true`
 *
 * Falsy values are skipped, so a directive can be toggled off by passing
 * `false`, `null` or `''`.
 *
 * The key `report-only` is not a directive: it switches the emitted header to
 * Content-Security-Policy-Report-Only.
 *
 * Directives listed in DIRECTIVES below are emitted in that order. Any other
 * key is passed through verbatim, after the known ones, in the order it
 * appears in the policy object. This means directives added to CSP after this
 * release can be used without waiting for a library update.
 *
 * Names and values are validated against the CSP3 grammar when the policy is
 * compiled, so a malformed policy throws at startup rather than producing a
 * broken or injected header on every request.
 *
 * A policy compiles to exactly one header, so supporting a framework is a
 * matter of knowing how it sets one. getCSPHeader compiles a policy to that
 * header and every factory below is a few lines on top of it: getCSP for
 * connect and express, getFastifyCSP, getKoaCSP, getHonoCSP and getHapiCSP for
 * those frameworks, and getHeadersCSP for anything carrying a Fetch Headers.
 */

/**
 * Known directives, in emission order. Grouped as in the CSP3 spec.
 */
const DIRECTIVES = [
  // Fetch directives
  'default-src',
  'child-src',
  'connect-src',
  'font-src',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'prefetch-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'style-src',
  'style-src-elem',
  'style-src-attr',
  'worker-src',
  // Document directives
  'base-uri',
  'sandbox',
  // Navigation directives
  'form-action',
  'frame-ancestors',
  // Reporting directives
  'report-to',
  'report-uri',
  // Other directives
  'require-trusted-types-for',
  'trusted-types',
  'upgrade-insecure-requests',
  // Deprecated, retained for backwards compatibility
  'block-all-mixed-content',
  'plugin-types'
];

const DIRECTIVE_SET = new Set(DIRECTIVES);

/** Policy keys that configure the middleware rather than the policy itself. */
const CONTROL_KEYS = new Set(['report-only']);

/**
 * Both header names a policy can be sent as, in the order the middleware
 * clears them. Only one is ever set: a policy that switches to report-only
 * must not leave the enforcing header behind, and vice versa.
 */
const HEADERS = ['Content-Security-Policy-Report-Only', 'Content-Security-Policy'];

/**
 * The same two names, lowercased, for where headers are a plain object and so
 * have to be cleared by key: whoever set one chose its casing.
 */
const LOWERCASED = HEADERS.map(header => header.toLowerCase());

/**
 * A directive name, per the CSP3 grammar:
 *   directive-name = 1*( ALPHA / DIGIT / "-" )
 */
const DIRECTIVE_NAME = /^[A-Za-z0-9-]+$/;

/**
 * A character that may not appear in a directive value. The CSP3 grammar for
 * directive-value allows SP and the printable ASCII range minus "," and ";",
 * which separate policies and directives respectively. Control characters are
 * excluded too: CR and LF in a header value are a response-splitting vector,
 * and Node rejects them with ERR_INVALID_CHAR at response time.
 */
const INVALID_VALUE_CHAR = /[^\x20-\x2B\x2D-\x3A\x3C-\x7E]/;

/** The known directive names, in emission order. */
// Stryker disable next-line all: dropping slice() is unobservable from outside, the export is frozen either way
module.exports.DIRECTIVES = Object.freeze(DIRECTIVES.slice());

/**
 * Compile a policy to the single header it is sent as.
 *
 * This is what every factory below is built from. Reach for it directly to
 * support a framework this module has no factory for: set the returned header
 * however that framework sets one.
 *
 * @param options the policy, see the module documentation above
 * @returns a frozen { name, value } pair, the header to send
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getCSPHeader = function (options) {
  // typeof null is 'object', so null falls through to the empty policy below.
  if (options !== undefined && (typeof options !== 'object' || Array.isArray(options))) {
    throw new TypeError(`Content-Security-Policy options must be a policy object, got ${describe(options)}`);
  }

  const policy = options || {};
  const name = Object.hasOwn(policy, 'report-only') && policy['report-only']
    ? 'Content-Security-Policy-Report-Only'
    : 'Content-Security-Policy';
  const parts = [];

  DIRECTIVES.forEach(directiveName => {
    if (!Object.hasOwn(policy, directiveName)) {
      return;
    }
    const directive = getDirective(directiveName, policy[directiveName]);
    if (directive) {
      parts.push(directive);
    }
  });

  Object.keys(policy).forEach(directiveName => {
    if (DIRECTIVE_SET.has(directiveName) || CONTROL_KEYS.has(directiveName)) {
      return;
    }
    const directive = getDirective(directiveName, policy[directiveName]);
    if (directive) {
      parts.push(directive);
    }
  });

  return Object.freeze({ name, value: parts.join('; ') });
};

/**
 * A local alias, so that replacing the export cannot change what the factories
 * below compile.
 */
const compile = module.exports.getCSPHeader;

/**
 * Build middleware that sets a Content-Security-Policy header.
 *
 * For connect, express, restify, polka, NestJS on express, and anything else
 * taking a (req, res, next) middleware.
 *
 * The policy is compiled once, here, so a malformed directive throws now
 * rather than on every request.
 *
 * @param options the policy, see the module documentation above
 * @returns a connect/express middleware function
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getCSP = function (options) {
  const { name, value } = compile(options);

  return function (req, res, next) {
    HEADERS.forEach(stale => res.removeHeader(stale));
    res.setHeader(name, value);
    next();
  };
};

/**
 * Build a Fastify onRequest hook that sets a Content-Security-Policy header.
 *
 * Add it to a whole instance with fastify.addHook('onRequest', hook), or to
 * one route with { onRequest: hook } in its options. A route-level hook runs
 * last, so it overrides an instance-wide policy.
 *
 * @param options the policy, see the module documentation above
 * @returns a Fastify onRequest hook
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getFastifyCSP = function (options) {
  const { name, value } = compile(options);

  return function (request, reply, done) {
    HEADERS.forEach(stale => reply.removeHeader(stale));
    reply.header(name, value);
    done();
  };
};

/**
 * Build Koa middleware that sets a Content-Security-Policy header.
 *
 * @param options the policy, see the module documentation above
 * @returns a Koa middleware function
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getKoaCSP = function (options) {
  const { name, value } = compile(options);

  return function (ctx, next) {
    HEADERS.forEach(stale => ctx.remove(stale));
    ctx.set(name, value);
    // Returned, not awaited: Koa needs the downstream promise.
    return next();
  };
};

/**
 * Build Hono middleware that sets a Content-Security-Policy header.
 *
 * @param options the policy, see the module documentation above
 * @returns a Hono middleware function
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getHonoCSP = function (options) {
  const { name, value } = compile(options);

  return function (c, next) {
    // Set before next(), not after. Hono unwinds middleware outermost-last,
    // so setting the header afterwards would let an app-wide policy overwrite
    // a route-local one, the opposite of how every other framework here
    // behaves. Set beforehand it lands in Hono's prepared headers, and it
    // survives a handler that returns a Response of its own.
    HEADERS.forEach(stale => c.header(stale, undefined));
    c.header(name, value);
    return next();
  };
};

/**
 * Build a hapi onPreResponse extension that sets a Content-Security-Policy
 * header.
 *
 * Register it with server.ext('onPreResponse', ext), or on one route with
 * { ext: { onPreResponse: { method: ext } } }.
 *
 * onPreResponse rather than an earlier extension point because it is the only
 * one that also sees error responses, which are served by hapi itself and
 * would otherwise go out with no policy at all.
 *
 * @param options the policy, see the module documentation above
 * @returns a hapi extension method
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getHapiCSP = function (options) {
  const { name, value } = compile(options);

  return function (request, h) {
    // An error response is a Boom object, which keeps its headers one level
    // further in. Both are plain objects, so a stale policy is deleted by key
    // rather than through a removeHeader() that hapi does not have.
    const response = request.response;
    const headers = response.isBoom ? response.output.headers : response.headers;

    Object.keys(headers).forEach(stale => {
      if (LOWERCASED.includes(stale.toLowerCase())) {
        delete headers[stale];
      }
    });
    headers[name] = value;

    return h.continue;
  };
};

/**
 * Build a function that sets a Content-Security-Policy header on a Fetch
 * Headers object.
 *
 * For the frameworks that have no Node response object at all: Next.js
 * middleware, h3 v2 and Nitro, Cloudflare Workers, Deno, Bun and Elysia.
 *
 * @param options the policy, see the module documentation above
 * @returns a function that applies the policy to a Headers object
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
module.exports.getHeadersCSP = function (options) {
  const { name, value } = compile(options);

  return function (headers) {
    HEADERS.forEach(stale => headers.delete(stale));
    headers.set(name, value);
  };
};

/**
 * Compile one directive. Handles strings, arrays and valueless directives.
 *
 * Nothing is validated for a directive that is not emitted, so toggling one
 * off with a falsy value never throws.
 *
 * @param name directive name
 * @param value the policy value for that directive
 * @returns the serialised directive, or null if there is nothing to emit
 */
function getDirective (name, value) {
  if (value === true) {
    assertName(name);
    return name;
  }

  // Stryker disable next-line all: a fast path only, every falsy value also returns null below
  if (!value) {
    return null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    assertName(name);
    assertValue(name, trimmed);
    return `${name} ${trimmed}`;
  }

  if (Array.isArray(value)) {
    const sources = value
      .filter(source => source || source === 0)
      .map(source => String(source).trim())
      .filter(source => source);
    if (!sources.length) {
      return null;
    }
    assertName(name);
    sources.forEach(source => assertValue(name, source));
    return `${name} ${sources.join(' ')}`;
  }

  return null;
}

/**
 * @param name a directive name about to be emitted
 * @throws TypeError if it is not a valid directive name
 */
function assertName (name) {
  if (!DIRECTIVE_NAME.test(name)) {
    throw new TypeError(
      `Invalid Content-Security-Policy directive name ${JSON.stringify(name)}` +
      ': a directive name may contain only ASCII letters, digits and "-".'
    );
  }
}

/**
 * @param name the directive the value belongs to, for the error message
 * @param value a source expression about to be emitted
 * @throws TypeError if it contains a character the CSP grammar forbids
 */
function assertValue (name, value) {
  const found = INVALID_VALUE_CHAR.exec(value);
  if (found) {
    throw new TypeError(
      `Invalid character ${JSON.stringify(found[0])} in Content-Security-Policy directive "${name}"` +
      ': a directive value may not contain control characters, ";", "," or non-ASCII characters.'
    );
  }
}

/**
 * A short, safe description of a value for an error message.
 *
 * @param value any value
 * @returns the value itself when it is a primitive, a type name otherwise
 */
function describe (value) {
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return 'an array';
  }
  return String(value);
}

/**  */
module.exports.SANDBOX_ALLOW_FORMS = 'allow-forms';
/**  */
module.exports.SANDBOX_ALLOW_SCRIPTS = 'allow-scripts';
/**  */
module.exports.SANDBOX_ALLOW_SAME = 'allow-same-origin';
/**  */
module.exports.SANDBOX_ALLOW_TOP_NAVIGATION = 'allow-top-navigation';
/**  */
module.exports.SANDBOX_ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION = 'allow-top-navigation-by-user-activation';
/**  */
module.exports.SANDBOX_ALLOW_DOWNLOADS = 'allow-downloads';
/**  */
module.exports.SANDBOX_ALLOW_MODALS = 'allow-modals';
/**  */
module.exports.SANDBOX_ALLOW_POPUPS = 'allow-popups';
/**  */
module.exports.SANDBOX_ALLOW_POPUPS_TO_ESCAPE_SANDBOX = 'allow-popups-to-escape-sandbox';
/**  */
module.exports.SANDBOX_ALLOW_PRESENTATION = 'allow-presentation';
/**  */
module.exports.SANDBOX_ALLOW_POINTER_LOCK = 'allow-pointer-lock';
/**  */
module.exports.SANDBOX_ALLOW_ORIENTATION_LOCK = 'allow-orientation-lock';
/** Allows loading resources from the same origin (same scheme, host and port). */
module.exports.SRC_SELF = '\'self\'';
/** Prevents loading resources from any source. */
module.exports.SRC_NONE = '\'none\'';
/** Allows use of inline source elements such as style attribute and onclick */
module.exports.SRC_USAFE_INLINE = '\'unsafe-inline\'';
module.exports.SRC_UNSAFE_INLINE = '\'unsafe-inline\'';
/** Allows unsafe dynamic code evaluation such as JavaScript eval() */
module.exports.SRC_UNSAFE_EVAL = '\'unsafe-eval\'';
/** Allows event handlers and javascript: URLs matched by a hash source. */
module.exports.SRC_UNSAFE_HASHES = '\'unsafe-hashes\'';
/** Allows WebAssembly compilation without allowing eval() for JavaScript. */
module.exports.SRC_WASM_UNSAFE_EVAL = '\'wasm-unsafe-eval\'';
/** Extends trust from a nonce- or hash-matched script to the scripts it loads. */
module.exports.SRC_STRICT_DYNAMIC = '\'strict-dynamic\'';
/** Includes a sample of the violating content in violation reports. */
module.exports.SRC_REPORT_SAMPLE = '\'report-sample\'';
/** Allows loading resources via the data scheme (e.g. Base64 encoded images). */
module.exports.SRC_DATA = 'data:';
/** Allows loading resources via a blob. */
module.exports.SRC_BLOB = 'blob:';
/** Wildcard, allows anything. */
module.exports.SRC_ANY = '*';
/** Allows loading resources only over HTTPS on any domain. */
module.exports.SRC_HTTPS = 'https:';
/** Value for require-trusted-types-for, enforcing Trusted Types at script sinks. */
module.exports.TRUSTED_TYPES_FOR_SCRIPT = '\'script\'';

/**
 * A reasonable modern baseline: denies everything by default and allows
 * scripts, styles, images, fonts, connections and form posts from the same
 * origin only. object-src and base-uri are locked down because they are the
 * usual bypasses for an otherwise strict policy.
 *
 * Frozen: it is shared by every consumer in the process, so mutating it would
 * change the baseline for all of them. Spread it to derive a policy.
 */
module.exports.STARTER_OPTIONS = Object.freeze({
  'default-src': module.exports.SRC_NONE,
  'script-src': module.exports.SRC_SELF,
  'connect-src': module.exports.SRC_SELF,
  'img-src': module.exports.SRC_SELF,
  'style-src': module.exports.SRC_SELF,
  'font-src': module.exports.SRC_SELF,
  'child-src': module.exports.SRC_SELF,
  'object-src': module.exports.SRC_NONE,
  'base-uri': module.exports.SRC_SELF,
  'form-action': module.exports.SRC_SELF,
  'frame-ancestors': module.exports.SRC_SELF
});
