/**
 * Middleware to add a Content-Security-Policy header.
 *
 * Policy reference: https://www.w3.org/TR/CSP3/
 *
 * The framework types here are structural: they describe the little this
 * library needs of a response object, so no framework type package has to be
 * installed for the declarations to resolve.
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

/** The single header a policy compiles to. */
export interface CSPHeader {
  /** `Content-Security-Policy`, or `Content-Security-Policy-Report-Only`. */
  readonly name: string;
  /** The serialised policy. Empty for an empty policy. */
  readonly value: string;
}

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

/** Minimal shape of the Fastify reply the hook needs. */
export interface FastifyReplyLike {
  header (name: string, value: string): unknown;
  removeHeader (name: string): unknown;
}

/** A Fastify onRequest hook. */
export type FastifyCSPHook = (
  request: unknown,
  reply: FastifyReplyLike,
  done: () => void
) => void;

/** Minimal shape of the Koa context the middleware needs. */
export interface KoaContextLike {
  set (field: string, value: string): unknown;
  remove (field: string): unknown;
}

/** A Koa middleware function. */
export type KoaCSPMiddleware = (
  ctx: KoaContextLike,
  next: () => Promise<void>
) => Promise<void>;

/** Minimal shape of the Hono context the middleware needs. */
export interface HonoContextLike {
  header (name: string, value: string | undefined): unknown;
}

/** A Hono middleware function. */
export type HonoCSPMiddleware = (
  c: HonoContextLike,
  next: () => Promise<void>
) => Promise<void>;

/**
 * A hapi headers object, keyed by header name. Values are `unknown` because
 * hapi's own are: a Boom response may carry numbers and arrays alongside
 * strings.
 */
export type HapiHeaders = Record<string, unknown>;

/**
 * Minimal shape of the hapi response the extension needs: a normal response,
 * or a Boom error, which keeps its headers one level further in.
 *
 * The two are told apart by `output`, not by `isBoom`: Boom declares that as a
 * plain boolean rather than the literal `true`, so it cannot discriminate.
 */
export type HapiResponseLike =
  | { isBoom?: false | undefined, headers: HapiHeaders, output?: undefined }
  | { isBoom: boolean, output: { headers: HapiHeaders } };

/** Minimal shape of the hapi request the extension needs. */
export interface HapiRequestLike {
  response: HapiResponseLike;
}

/** Minimal shape of the hapi response toolkit the extension needs. */
export interface HapiToolkitLike {
  continue: symbol;
}

/** A hapi extension method, which returns the toolkit's `continue` symbol. */
export type HapiCSPExtension = (
  request: HapiRequestLike,
  h: HapiToolkitLike
) => symbol;

/** Minimal shape of a Fetch Headers object. */
export interface HeadersLike {
  set (name: string, value: string): unknown;
  delete (name: string): unknown;
}

/** A function that applies a compiled policy to a Headers object. */
export type HeadersCSP = (headers: HeadersLike) => void;

/**
 * Compile a policy to the single header it is sent as.
 *
 * Every factory below is built from this. Use it directly to support a
 * framework that has no factory here.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getCSPHeader (options?: Policy): CSPHeader;

/**
 * Build middleware that sets a Content-Security-Policy header, for connect,
 * express and anything else taking a (req, res, next) middleware.
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

/**
 * Build a Fastify onRequest hook that sets a Content-Security-Policy header.
 *
 * Add it with `fastify.addHook('onRequest', hook)`, or to one route with
 * `{ onRequest: hook }`.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getFastifyCSP (options?: Policy): FastifyCSPHook;

/**
 * Build Koa middleware that sets a Content-Security-Policy header.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getKoaCSP (options?: Policy): KoaCSPMiddleware;

/**
 * Build Hono middleware that sets a Content-Security-Policy header.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getHonoCSP (options?: Policy): HonoCSPMiddleware;

/**
 * Build a hapi onPreResponse extension that sets a Content-Security-Policy
 * header, on error responses as well as normal ones.
 *
 * Register it with `server.ext('onPreResponse', ext)`.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getHapiCSP (options?: Policy): HapiCSPExtension;

/**
 * Build a function that sets a Content-Security-Policy header on a Fetch
 * Headers object: Next.js middleware, h3 and Nitro, Workers, Deno, Bun, Elysia.
 *
 * @param options the policy
 * @throws TypeError if options is not a policy object, or if a directive name
 *   or value is not valid per the CSP grammar
 */
export function getHeadersCSP (options?: Policy): HeadersCSP;

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
