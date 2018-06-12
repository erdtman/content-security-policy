/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

/**
 * Middleware to add Content-Security-Policy header http://www.w3.org/TR/CSP/
 *
 * @option report-only, The Content-Security-Policy-Report-Only header field
 *         lets servers experiment with policies by monitoring (rather than
 *         enforcing) a policy.
 * @option report-uri, Instructs the browser to POST a reports of policy
 *         failures to this URI. You can also append -Report-Only to the HTTP
 *         header name to instruct the browser to only send reports (does not
 *         block anything).
 * @option sandbox, Enables a sandbox for the requested resource similar to the
 *         iframe sandbox attribute.
 *
 * @option default-src, The default-src is the default policy for loading
 *         content such as JavaScript, Images, CSS, Font's, AJAX requests,
 *         Frames, HTML5 Media
 * @option script-src, Defines valid sources of JavaScript.
 * @option object-src, Defines valid sources of plugins, eg <object>, <embed>
 *         or <applet>.
 * @option style-src, Defines valid sources of stylesheets.
 * @option img-src, Defines valid sources of images.
 * @option media-src, Defines valid sources of audio and video, eg HTML5 <audio>, <video> elements.
 * @option frame-src, Defines valid sources for loading frames.
 * @option font-src, Defines valid sources of fonts.
 * @option connect-src, Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
 * @option child-src, Defines valid sources for web workers and nested browsing contexts loaded using elements such as <frame> and <iframe> (CSP2).
 * @option worker-src, Defines valid sources that can be loaded within a Worker, SharedWorker, or ServiceWorker (CSP3).
 * @option form-action, Defines valid sources that can be used as a HTML <form> action (CSP2).
 * @option frame-ancestors, Defines valid sources for embedding the resource using <frame> <iframe> <object> <embed> <applet>. Setting this directive to 'none' should be roughly equivalent to X-Frame-Options: DENY (CSP2).
 * @option plugin-types, Defines valid MIME types for plugins invoked via <object> and <embed>. To load an <applet> you must specify application/x-java-applet (CSP2).
 *
 */
module.exports.getCSP = function (options) {
  const header = options['report-only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const srcs = ['report-uri', 'sandbox', 'default-src', 'script-src', 'object-src', 'style-src', 'img-src', 'media-src', 'frame-src', 'font-src', 'connect-src', 'child-src', 'worker-src', 'form-action', 'frame-ancestors', 'plugin-types'];
  let compiled = '';
  srcs.forEach(src => {
    const directive = getDirective(options, src);
    if (directive) {
      compiled += directive + ';';
    }
  });

  return function (req, res, next) {
    res.removeHeader('Content-Security-Policy-Report-Only');
    res.removeHeader('Content-Security-Policy');
    res.setHeader(header, compiled);
    next();
  };
};

/**  */
module.exports.SANDBOX_ALLOW_FORMS = 'allow-forms';
/**  */
module.exports.SANDBOX_ALLOW_SCRIPTS = 'allow-scripts';
/**  */
module.exports.SANDBOX_ALLOW_SAME = 'allow-same-origin';
/**  */
module.exports.SANDBOX_ALLOW_TOP_NAVIGATION = 'allow-top-navigation';
/** Allows loading resources from the same origin (same scheme, host and port). */
module.exports.SRC_SELF = '\'self\'';
/** Prevents loading resources from any source. */
module.exports.SRC_NONE = '\'none\'';
/** Allows use of inline source elements such as style attribute and onclick */
module.exports.SRC_USAFE_INLINE = '\'unsafe-inline\'';
/** Allows unsafe dynamic code evaluation such as JavaScript eval() */
module.exports.SRC_UNSAFE_EVAL = '\'unsafe-eval\'';
/** Allows loading resources via the data scheme (e.g. Base64 encoded images). */
module.exports.SRC_DATA = 'data:';
/** Allows loading resources via a blob. */
module.exports.SRC_BLOB = 'blob:';
/** Wildcard, allows anything. */
module.exports.SRC_ANY = '*';
/** Allows loading resources only over HTTPS on any domain. */
module.exports.SRC_HTTPS = 'https:';
/**
 * This policy allows images, scripts, AJAX, and CSS from the same origin, and
 * does not allow any other resources to load (eg object, frame, media, etc). It
 * is a good starting point for many sites.
 */
module.exports.STARTER_OPTIONS = {
  'default-src': module.exports.SRC_NONE,
  'script-src': module.exports.SRC_SELF,
  'connect-src': module.exports.SRC_SELF,
  'img-src': module.exports.SRC_SELF,
  'style-src': module.exports.SRC_SELF,
  'font-src': module.exports.SRC_SELF,
  'child-src': module.exports.SRC_SELF,
  'form-action': module.exports.SRC_SELF,
  'frame-ancestors': module.exports.SRC_SELF,
  'plugin-types': module.exports.SRC_NONE
};

/**
 * Helper function to compile one directive. handles strings and arrays.
 *
 * @param options
 *          all options
 * @param name
 *          name of the one to compile
 * @returns compilation of named option
 */
function getDirective (options, name) {
  if (!options[name]) {
    return null;
  }

  if (typeof options[name] === 'string') {
    return name + ' ' + options[name];
  }

  if (Array.isArray(options[name])) {
    let result = name + ' ';
    options[name].forEach(value => {
      result += value + ' ';
    });
    return result;
  }

  return null;
}
