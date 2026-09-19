// Compile-only check that lib/index.d.ts matches the documented API.
import * as CSP from '../../lib/index.js';
import { getCSP, Policy, CSPMiddleware } from '../../lib/index.js';

const policy: Policy = {
  'report-only': true,
  'default-src': CSP.SRC_NONE,
  'script-src': [CSP.SRC_SELF, CSP.SRC_STRICT_DYNAMIC],
  'upgrade-insecure-requests': true,
  'require-trusted-types-for': CSP.TRUSTED_TYPES_FOR_SCRIPT,
  'style-src': false,
  // Unknown directives are allowed through.
  'fenced-frame-src': 'https://ads.example'
};

const middleware: CSPMiddleware = getCSP(policy);
const starter: CSPMiddleware = getCSP(CSP.STARTER_OPTIONS);
const empty: CSPMiddleware = CSP.getCSP();

const headers: Record<string, string> = {};
for (const mw of [middleware, starter, empty]) {
  mw(null, {
    setHeader: (name: string, value: string) => { headers[name] = value; },
    removeHeader: (name: string) => { delete headers[name]; }
  }, () => {});
}

const names: readonly string[] = CSP.DIRECTIVES;
