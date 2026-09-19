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

/** The known directive names, in emission order. */
module.exports.DIRECTIVES = Object.freeze(DIRECTIVES.slice());

/**
 * Build middleware that sets a Content-Security-Policy header.
 *
 * @param options the policy, see the module documentation above
 * @returns a connect/express middleware function
 */
module.exports.getCSP = function (options) {
  const policy = options || {};
  const header = policy['report-only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const parts = [];

  DIRECTIVES.forEach(name => {
    const directive = getDirective(name, policy[name]);
    if (directive) {
      parts.push(directive);
    }
  });

  Object.keys(policy).forEach(name => {
    if (DIRECTIVE_SET.has(name) || CONTROL_KEYS.has(name)) {
      return;
    }
    const directive = getDirective(name, policy[name]);
    if (directive) {
      parts.push(directive);
    }
  });

  const compiled = parts.join('; ');

  return function (req, res, next) {
    res.removeHeader('Content-Security-Policy-Report-Only');
    res.removeHeader('Content-Security-Policy');
    res.setHeader(header, compiled);
    next();
  };
};

/**
 * Compile one directive. Handles strings, arrays and valueless directives.
 *
 * @param name directive name
 * @param value the policy value for that directive
 * @returns the serialised directive, or null if there is nothing to emit
 */
function getDirective (name, value) {
  if (value === true) {
    return name;
  }

  if (!value) {
    return null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? name + ' ' + trimmed : null;
  }

  if (Array.isArray(value)) {
    const sources = value
      .filter(source => source || source === 0)
      .map(source => String(source).trim())
      .filter(source => source);
    return sources.length ? name + ' ' + sources.join(' ') : null;
  }

  return null;
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
 */
module.exports.STARTER_OPTIONS = {
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
};
