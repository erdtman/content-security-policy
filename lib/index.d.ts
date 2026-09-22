/**
 * Middleware to add a Content-Security-Policy header.
 *
 * Policy reference: https://www.w3.org/TR/CSP3/
 */

/**
 * The value of a single directive.
 *
 * A string or array of strings supplies the source list. `true` emits the
 * directive with no value (e.g. `upgrade-insecure-requests`). Falsy values
 * are skipped, so a directive can be toggled off.
 */
export type DirectiveValue = string | readonly string[] | boolean | null | undefined;

/** Directive names known to this release, used to order the emitted header. */
export type KnownDirective =
  | 'default-src'
  | 'child-src'
  | 'connect-src'
  | 'font-src'
  | 'frame-src'
  | 'img-src'
  | 'manifest-src'
  | 'media-src'
  | 'object-src'
  | 'prefetch-src'
  | 'script-src'
  | 'script-src-elem'
  | 'script-src-attr'
  | 'style-src'
  | 'style-src-elem'
  | 'style-src-attr'
  | 'worker-src'
  | 'base-uri'
  | 'sandbox'
  | 'form-action'
  | 'frame-ancestors'
  | 'report-to'
  | 'report-uri'
  | 'require-trusted-types-for'
  | 'trusted-types'
  | 'upgrade-insecure-requests'
  /** @deprecated removed from the CSP specification */
  | 'block-all-mixed-content'
  /** @deprecated removed from the CSP specification */
  | 'plugin-types';

/**
 * A policy. Known directives are emitted in specification order; any other
 * key is passed through verbatim after them.
 *
 * `report-only` is not a directive: it switches the emitted header to
 * Content-Security-Policy-Report-Only.
 */
export type Policy = {
  [directive in KnownDirective]?: DirectiveValue;
} & {
  'report-only'?: boolean;
  [directive: string]: DirectiveValue;
};

/** Minimal shape of the response object the middleware needs. */
export interface CSPResponse {
  setHeader (name: string, value: string): unknown;
  removeHeader (name: string): unknown;
}

/** A connect/express style middleware function. */
export type CSPMiddleware = (
  req: unknown,
  res: CSPResponse,
  next: () => void
) => void;

/**
 * Build middleware that sets a Content-Security-Policy header.
 *
 * The policy is compiled once, when the middleware is created. Directive names
 * and values are validated against the CSP grammar at that point, so a
 * malformed policy throws here rather than on every request.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getCSP (options?: Policy): CSPMiddleware;

/** The known directive names, in emission order. */
export const DIRECTIVES: readonly KnownDirective[];

export const SANDBOX_ALLOW_FORMS: "allow-forms";
export const SANDBOX_ALLOW_SCRIPTS: "allow-scripts";
export const SANDBOX_ALLOW_SAME: "allow-same-origin";
export const SANDBOX_ALLOW_TOP_NAVIGATION: "allow-top-navigation";
export const SANDBOX_ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION: "allow-top-navigation-by-user-activation";
export const SANDBOX_ALLOW_DOWNLOADS: "allow-downloads";
export const SANDBOX_ALLOW_MODALS: "allow-modals";
export const SANDBOX_ALLOW_POPUPS: "allow-popups";
export const SANDBOX_ALLOW_POPUPS_TO_ESCAPE_SANDBOX: "allow-popups-to-escape-sandbox";
export const SANDBOX_ALLOW_PRESENTATION: "allow-presentation";
export const SANDBOX_ALLOW_POINTER_LOCK: "allow-pointer-lock";
export const SANDBOX_ALLOW_ORIENTATION_LOCK: "allow-orientation-lock";

/** Allows loading resources from the same origin (same scheme, host and port). */
export const SRC_SELF: "'self'";
/** Prevents loading resources from any source. */
export const SRC_NONE: "'none'";
/**
 * Allows use of inline source elements such as style attribute and onclick.
 *
 * @deprecated misspelled; use {@link SRC_UNSAFE_INLINE}
 */
export const SRC_USAFE_INLINE: "'unsafe-inline'";
/** Allows use of inline source elements such as style attribute and onclick. */
export const SRC_UNSAFE_INLINE: "'unsafe-inline'";
/** Allows unsafe dynamic code evaluation such as JavaScript eval(). */
export const SRC_UNSAFE_EVAL: "'unsafe-eval'";
/** Allows event handlers and javascript: URLs matched by a hash source. */
export const SRC_UNSAFE_HASHES: "'unsafe-hashes'";
/** Allows WebAssembly compilation without allowing eval() for JavaScript. */
export const SRC_WASM_UNSAFE_EVAL: "'wasm-unsafe-eval'";
/** Extends trust from a nonce- or hash-matched script to the scripts it loads. */
export const SRC_STRICT_DYNAMIC: "'strict-dynamic'";
/** Includes a sample of the violating content in violation reports. */
export const SRC_REPORT_SAMPLE: "'report-sample'";
/** Allows loading resources via the data scheme (e.g. Base64 encoded images). */
export const SRC_DATA: "data:";
/** Allows loading resources via a blob. */
export const SRC_BLOB: "blob:";
/** Wildcard, allows anything. */
export const SRC_ANY: "*";
/** Allows loading resources only over HTTPS on any domain. */
export const SRC_HTTPS: "https:";
/** Value for require-trusted-types-for, enforcing Trusted Types at script sinks. */
export const TRUSTED_TYPES_FOR_SCRIPT: "'script'";

/**
 * A reasonable modern baseline: denies everything by default and allows
 * scripts, styles, images, fonts, connections and form posts from the same
 * origin only.
 *
 * Frozen at runtime: spread it to derive a policy rather than mutating it.
 */
export const STARTER_OPTIONS: Readonly<Policy>;
