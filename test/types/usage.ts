// Compile-only check that lib/index.d.ts matches the documented API.
//
// The @ts-expect-error lines are the point of this file: each one fails the
// build if the code below it stops being an error, which is how a declaration
// that has quietly widened to `any` gets caught. Plain tsc, no type-test
// dependency.
import * as CSP from '../../lib/index.js';
import {
  getCSP, Policy, CSPMiddleware, CSPResponse, DirectiveValue, KnownDirective,
  CSPHeader, FastifyCSPHook, FastifyReplyLike, KoaCSPMiddleware, KoaContextLike,
  HonoCSPMiddleware, HonoContextLike, HapiCSPExtension, HapiRequestLike, HapiToolkitLike,
  HeadersCSP, HeadersLike
} from '../../lib/index.js';

// --- accepted ---------------------------------------------------------------

const policy: Policy = {
  'report-only': true,
  'default-src': CSP.SRC_NONE,
  'script-src': [CSP.SRC_SELF, CSP.SRC_STRICT_DYNAMIC],
  'upgrade-insecure-requests': true,
  'require-trusted-types-for': CSP.TRUSTED_TYPES_FOR_SCRIPT,
  'style-src': false,
  'img-src': null,
  'font-src': undefined,
  // Unknown directives are allowed through.
  'fenced-frame-src': 'https://ads.example'
};

const middleware: CSPMiddleware = getCSP(policy);
const starter: CSPMiddleware = getCSP(CSP.STARTER_OPTIONS);
const empty: CSPMiddleware = CSP.getCSP();

// The starter policy is readonly, so it is derived from by spreading.
const derived: Policy = { ...CSP.STARTER_OPTIONS, 'script-src': [CSP.SRC_SELF, 'https://cdn.example'] };
const alsoDerived: CSPMiddleware = getCSP(derived);

const headers: Record<string, string> = {};
const response: CSPResponse = {
  setHeader: (name: string, value: string) => { headers[name] = value; },
  removeHeader: (name: string) => { delete headers[name]; }
};

for (const mw of [middleware, starter, empty, alsoDerived]) {
  mw(null, response, () => {});
}

// --- the framework adapters -------------------------------------------------

const header: CSPHeader = CSP.getCSPHeader(policy);
const headerName: string = header.name;
const headerValue: string = header.value;

const fastifyHook: FastifyCSPHook = CSP.getFastifyCSP(policy);
const reply: FastifyReplyLike = { header: () => reply, removeHeader: () => reply };
fastifyHook({}, reply, () => {});

const koaMiddleware: KoaCSPMiddleware = CSP.getKoaCSP(policy);
const ctx: KoaContextLike = { set: () => {}, remove: () => {} };
const koaDone: Promise<void> = koaMiddleware(ctx, async () => {});

const honoMiddleware: HonoCSPMiddleware = CSP.getHonoCSP(policy);
const honoContext: HonoContextLike = { header: () => {} };
const honoDone: Promise<void> = honoMiddleware(honoContext, async () => {});

const hapiExtension: HapiCSPExtension = CSP.getHapiCSP(policy);
const toolkit: HapiToolkitLike = { continue: Symbol('continue') };
const hapiRequest: HapiRequestLike = { response: { headers: {} } };
const boomRequest: HapiRequestLike = { response: { isBoom: true, output: { headers: {} } } };
const continued: symbol = hapiExtension(hapiRequest, toolkit);
hapiExtension(boomRequest, toolkit);

const applyCSP: HeadersCSP = CSP.getHeadersCSP(policy);
const fetchHeaders: HeadersLike = new Headers();
applyCSP(fetchHeaders);
applyCSP(new Response('ok').headers);

const names: readonly string[] = CSP.DIRECTIVES;
const known: KnownDirective = 'script-src';
const value: DirectiveValue = [CSP.SRC_SELF];

// A frozen array of frozen strings: readonly is the accurate type.
const first: KnownDirective = CSP.DIRECTIVES[0];

// --- rejected ---------------------------------------------------------------

// @ts-expect-error report-only is the one key that must be a boolean
const badControl: Policy = { 'report-only': 'yes' };

// @ts-expect-error a directive value is a string, string[] or boolean
const badValue: Policy = { 'script-src': 42 };

// @ts-expect-error array members are strings
const badMember: Policy = { 'script-src': [CSP.SRC_SELF, 42] };

// @ts-expect-error an object is not a source list
const badObject: Policy = { 'script-src': { self: true } };

// @ts-expect-error the policy itself must be an object
const badPolicy: CSPMiddleware = getCSP('default-src');

// @ts-expect-error the response must be able to remove headers as well as set them
getCSP()(null, { setHeader: () => {} }, () => {});

// @ts-expect-error next is required
getCSP()(null, response);

// @ts-expect-error DIRECTIVES is readonly
CSP.DIRECTIVES[0] = 'script-src';

// @ts-expect-error DIRECTIVES is readonly
CSP.DIRECTIVES.push('script-src');

// @ts-expect-error STARTER_OPTIONS is frozen at runtime, and readonly in types
CSP.STARTER_OPTIONS['script-src'] = CSP.SRC_UNSAFE_INLINE;

// @ts-expect-error an unknown directive name is fine, but its value is still typed
const badUnknown: Policy = { 'fenced-frame-src': 42 };

// @ts-expect-error a compiled header is readonly: it is shared by every request
CSP.getCSPHeader(policy).value = 'default-src *';

// @ts-expect-error the reply must be able to remove headers as well as set them
CSP.getFastifyCSP()({}, { header: () => {} }, () => {});

// @ts-expect-error the hook signals completion through done(), which is required
CSP.getFastifyCSP()({}, reply);

// @ts-expect-error a Koa context removes headers with remove(), not removeHeader()
CSP.getKoaCSP()({ set: () => {}, removeHeader: () => {} }, async () => {});

// @ts-expect-error a Hono context sets headers with header(), not set()
CSP.getHonoCSP()({ set: () => {} }, async () => {});

// @ts-expect-error a hapi extension needs a response to put the header on
CSP.getHapiCSP()({}, toolkit);

// @ts-expect-error a Headers object is not a policy
CSP.getHeadersCSP(new Headers());

// @ts-expect-error every factory validates its policy the same way
CSP.getKoaCSP('default-src');

export {
  policy, derived, names, known, value, first, header, headerName, headerValue, koaDone, honoDone,
  continued, badControl, badValue, badMember, badObject, badPolicy, badUnknown
};
