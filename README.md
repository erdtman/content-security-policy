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

### Validation

The policy is compiled once, when `getCSP` is called, and directive names and
values are checked against the [CSP grammar](https://www.w3.org/TR/CSP3/#framework-directives)
at that point. A malformed policy throws a `TypeError` at startup instead of
producing a broken header, or a 500, on every request:

```js
csp.getCSP({ 'script-src': "'self'\r\nX-Injected: yes" });
// TypeError: Invalid character "\r" in Content-Security-Policy directive "script-src": ...
```

A directive name may contain only ASCII letters, digits and `-`. A value may
not contain control characters, `;`, `,` or non-ASCII characters — `;` and `,`
separate directives and policies, so a value containing one would inject
another directive or a second policy. A directive that is toggled off with a
falsy value is never validated, so switching one off cannot throw.

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

It is frozen, because it is shared by every consumer in the process. Spread it
to derive a policy:

```js
app.use(csp.getCSP({
  ...csp.STARTER_OPTIONS,
  'script-src': [csp.SRC_SELF, 'https://cdn.example']
}));
```

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

Node.js 22 or newer. The package is CommonJS and has no runtime dependencies.

## Development

```sh
npm install
npm test           # lint, typecheck and run the tests
npm run coverage   # tests with a coverage report (100% thresholds)
npm run watch      # re-run tests on change
npm run mutation   # mutation testing (slow, fetches Stryker on demand)
```

### How this is tested

The suite runs on `node:test` alone, with no test dependencies, and is layered
so that each layer catches something the one above it cannot:

| File | What it pins |
| --- | --- |
| `test/index.js` | What a policy compiles to, asserted as exact header strings, plus ordering, validation and the calls the middleware makes |
| `test/http.js` | The same middleware against a real `http.ServerResponse` over a real socket — header serialisation, `next()`, and one policy overriding another |
| `test/invariants.js` | Properties that must hold for every policy, over a few thousand generated ones, from a fixed seed |
| `test/exports.js` | That the runtime exports and `lib/index.d.ts` describe the same API |
| `test/docs.js` | That the examples in this README and in `examples/` still do what they claim |
| `test/package.js` | The packed tarball: its contents, that `main` and `types` resolve, and that a TypeScript consumer can import it by name |
| `test/types/usage.ts` | That valid usage compiles and invalid usage does not, via `@ts-expect-error` |

Line coverage is held at 100%, but on a module this small that is easy and
proves little, so suite strength is measured with mutation testing instead:
`npm run mutation` changes the library and expects the tests to notice. It is
held at a 100% score, and runs weekly in CI rather than on every push. The few
mutants that cannot be killed because they are behaviourally equivalent are
marked in `lib/index.js` with a `Stryker disable` comment and a reason.

The fuzz seed and case count can be overridden to reproduce or widen a run:

```sh
CSP_FUZZ_SEED=12345 CSP_FUZZ_RUNS=100000 node --test test/invariants.js
```

## Releases

Staged from GitHub Actions on a `v*` tag push, with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements), so
each release can be traced back to the commit and workflow run that built it.
Verify with `npm audit signatures`. See [RELEASING.md](RELEASING.md).

## License

MIT
