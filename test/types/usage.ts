// Compile-only check that lib/index.d.ts matches the documented API.
//
// The @ts-expect-error lines are the point of this file: each one fails the
// build if the code below it stops being an error, which is how a declaration
// that has quietly widened to `any` gets caught. Plain tsc, no type-test
// dependency.
import * as CSP from '../../lib/index.js';
import { getCSP, Policy, CSPMiddleware, CSPResponse, DirectiveValue, KnownDirective } from '../../lib/index.js';

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

export { policy, derived, names, known, value, first, badControl, badValue, badMember, badObject, badPolicy, badUnknown };
