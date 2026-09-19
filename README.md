[![CI](https://github.com/erdtman/content-security-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/erdtman/content-security-policy/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/content-security-policy.svg)](https://www.npmjs.com/package/content-security-policy)

# content-security-policy

Connect/Express middleware that adds a [Content-Security-Policy](https://www.w3.org/TR/CSP3/) header.

No runtime dependencies. Ships TypeScript declarations.

## Install

```sh
npm install content-security-policy
```

## Usage

```js
const csp = require('content-security-policy');
const express = require('express');
const app = express();

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [csp.SRC_SELF, csp.SRC_DATA]
};

const globalCSP = csp.getCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getCSP(cspPolicy);

// Applies to all requests that do not set a local policy.
app.use(globalCSP);

app.get('/', (req, res) => {
  res.send('Using global content security policy!');
});

// Applies only to this path, overriding the global policy.
app.get('/local', localCSP, (req, res) => {
  res.send('Using path local content security policy!');
});

app.listen(3000, () => {
  console.log('Example app listening on port 3000!');
});
```

## Writing a policy

A policy is a plain object keyed by directive name.

| Value | Result |
| --- | --- |
| a string | `'script-src': "'self'"` → `script-src 'self'` |
| an array of strings | `'script-src': ["'self'", 'https://cdn.example']` → `script-src 'self' https://cdn.example` |
| `true` | `'upgrade-insecure-requests': true` → `upgrade-insecure-requests` |
| falsy (`false`, `null`, `''`, `[]`) | the directive is omitted, which is handy for toggling one off |

The key `report-only` is not a directive. When truthy, the policy is sent as
`Content-Security-Policy-Report-Only`, which reports violations without
enforcing them:

```js
app.use(csp.getCSP({
  'default-src': csp.SRC_NONE,
  'report-uri': '/reporting',
  'report-only': true
}));
```

Directives listed in `csp.DIRECTIVES` are emitted in specification order. Any
other key is passed through verbatim after them, so a directive added to CSP
after this release can be used right away:

```js
csp.getCSP({ 'default-src': csp.SRC_NONE, 'fenced-frame-src': 'https://ads.example' });
// Content-Security-Policy: default-src 'none'; fenced-frame-src https://ads.example
```

### Constants

Source expressions: `SRC_SELF`, `SRC_NONE`, `SRC_UNSAFE_INLINE`,
`SRC_UNSAFE_EVAL`, `SRC_UNSAFE_HASHES`, `SRC_WASM_UNSAFE_EVAL`,
`SRC_STRICT_DYNAMIC`, `SRC_REPORT_SAMPLE`, `SRC_DATA`, `SRC_BLOB`, `SRC_ANY`,
`SRC_HTTPS`.

Sandbox tokens: `SANDBOX_ALLOW_FORMS`, `SANDBOX_ALLOW_SCRIPTS`,
`SANDBOX_ALLOW_SAME`, `SANDBOX_ALLOW_TOP_NAVIGATION`,
`SANDBOX_ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION`, `SANDBOX_ALLOW_DOWNLOADS`,
`SANDBOX_ALLOW_MODALS`, `SANDBOX_ALLOW_POPUPS`,
`SANDBOX_ALLOW_POPUPS_TO_ESCAPE_SANDBOX`, `SANDBOX_ALLOW_PRESENTATION`,
`SANDBOX_ALLOW_POINTER_LOCK`, `SANDBOX_ALLOW_ORIENTATION_LOCK`.

Also `TRUSTED_TYPES_FOR_SCRIPT` for `require-trusted-types-for`.

### STARTER_OPTIONS

`csp.STARTER_OPTIONS` is a strict same-origin baseline: everything is denied by
default, and scripts, styles, images, fonts, connections, frames and form posts
are allowed from the same origin only. `object-src` and `base-uri` are locked
down because they are the usual ways to bypass an otherwise strict policy.

Treat it as a starting point. Deploy it with `'report-only': true` first, watch
the reports, then widen it where your application genuinely needs it.

### Nonces

`getCSP` compiles the policy once, when the middleware is created, so it cannot
produce a fresh nonce per request. If you need nonces, build the policy per
request in your own middleware.

## TypeScript

Declarations are bundled; no `@types` package is needed.

```ts
import { getCSP, Policy, SRC_NONE, SRC_SELF } from 'content-security-policy';

const policy: Policy = {
  'default-src': SRC_NONE,
  'script-src': [SRC_SELF]
};

app.use(getCSP(policy));
```

## Requirements

Node.js 18 or newer. The package is CommonJS and has no runtime dependencies.

The test suite uses only `node:test`, so `node --test test/index.js` runs it with
nothing installed.

## Development

```sh
npm install
npm test          # lint, typecheck and run the tests
npm run coverage  # tests with a coverage report (100% thresholds)
npm run watch     # re-run tests on change
```

## License

MIT
