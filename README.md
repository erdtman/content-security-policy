[![CI](https://github.com/erdtman/content-security-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/erdtman/content-security-policy/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/content-security-policy.svg)](https://www.npmjs.com/package/content-security-policy)

# content-security-policy

Adds a [Content-Security-Policy](https://www.w3.org/TR/CSP3/) header, on Express,
Connect, Fastify, Koa, Hono, Hapi, or anything that can set a header.

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

## Frameworks

A policy compiles to exactly one header, so fitting a framework is only a matter
of knowing how it sets one. Every factory below validates and compiles the
policy once, when it is called, and clears both CSP headers before setting its
own — switching a policy to `report-only` never leaves the enforcing header
behind.

| Framework | Factory | Mounted as |
| --- | --- | --- |
| Express, Connect, restify, NestJS on Express | `getCSP` | middleware, `(req, res, next)` |
| Fastify | `getFastifyCSP` | an `onRequest` hook |
| Koa | `getKoaCSP` | middleware, `(ctx, next)` |
| Hono | `getHonoCSP` | middleware, `(c, next)` |
| Hapi | `getHapiCSP` | an `onPreResponse` extension |
| Next.js middleware, h3/Nitro, Workers, Deno, Bun, Elysia | `getHeadersCSP` | applied to a Fetch `Headers` |
| anything else | `getCSPHeader` | a `{ name, value }` pair you set yourself |

Runnable versions of each of these are in [`examples/`](examples).

### Fastify

```js
const fastify = require('fastify')();

fastify.addHook('onRequest', csp.getFastifyCSP(csp.STARTER_OPTIONS));

// A route level hook runs after the instance wide one, so it wins.
fastify.get('/local', { onRequest: csp.getFastifyCSP(cspPolicy) }, async () => 'ok');
```

### Koa

```js
const app = new Koa();

app.use(csp.getKoaCSP(csp.STARTER_OPTIONS));
```

### Hono

```js
const app = new Hono();

app.use('*', csp.getHonoCSP(csp.STARTER_OPTIONS));
app.get('/local', csp.getHonoCSP(cspPolicy), c => c.text('ok'));
```

The header is set before `next()`, not after, because Hono's response phase
unwinds outermost-last: setting it afterwards would let the app-wide policy
overwrite the route-local one.

### Hapi

```js
server.ext('onPreResponse', csp.getHapiCSP(csp.STARTER_OPTIONS));

server.route({
  method: 'GET',
  path: '/local',
  options: { ext: { onPreResponse: { method: csp.getHapiCSP(cspPolicy) } } },
  handler: () => 'ok'
});
```

`onPreResponse` is used rather than an earlier extension point because it is the
one that also covers the responses hapi generates itself, including Boom errors.

### Fetch `Headers`

Anywhere responses carry a standard `Headers` — Next.js middleware, h3 and
Nitro, Cloudflare Workers, Deno, Bun, Elysia:

```js
const applyCSP = csp.getHeadersCSP(cspPolicy);

export function middleware () {
  const response = NextResponse.next();
  applyCSP(response.headers);
  return response;
}
```

### Anything else

`getCSPHeader` returns the frozen header the adapters above are built on, so a
framework with none of these shapes is still three lines:

```js
const { name, value } = csp.getCSPHeader(cspPolicy);
// { name: 'Content-Security-Policy', value: "default-src 'none'; ..." }
```

### Responses the framework generates

An error page is as good a place to inject as any other, so a policy should
cover the 404s and 500s the framework produces on its own. It does under
Fastify, Koa, Hono and Hapi above.

Express is the exception: it serves those through `finalhandler`, which sets
`Content-Security-Policy: default-src 'none'` itself, after all middleware has
run. That is stricter than anything this library compiles, so the page is still
locked down — but if you want your own policy there, handle 404s and errors in
your own handler.

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

Each adapter has a return type of its own — `CSPMiddleware`, `FastifyCSPHook`,
`KoaCSPMiddleware`, `HonoCSPMiddleware`, `HapiCSPExtension`, `HeadersCSP` and
`CSPHeader` — described structurally, so no framework type package is needed
and the real framework's own types still satisfy them.

## Requirements

Node.js 22 or newer. The package is CommonJS and has no runtime dependencies.

## Development

```sh
npm install
npm test                 # lint, typecheck and run the tests
npm run coverage         # tests with a coverage report (100% thresholds)
npm run watch            # re-run tests on change
npm run test:frameworks  # install the real frameworks and test against them
npm run mutation         # mutation testing (slow, fetches Stryker on demand)
```

### How this is tested

The suite runs on `node:test` alone, with no test dependencies, and is layered
so that each layer catches something the one above it cannot:

| File | What it pins |
| --- | --- |
| `test/index.js` | What a policy compiles to, asserted as exact header strings, plus ordering, validation and the calls the middleware makes |
| `test/http.js` | The same middleware against a real `http.ServerResponse` over a real socket — header serialisation, `next()`, and one policy overriding another |
| `test/adapters.js` | Every framework adapter against a double shaped like that framework's contract: the calls it makes, and the one header that survives |
| `test/frameworks.js` | The adapters against real Express, Fastify, Koa, Hono and Hapi apps over real requests, including a framework-generated 404. Skipped unless the frameworks are installed, so `npm test` stays dependency-free; `npm run test:frameworks` installs them, and CI runs it on every push |
| `test/invariants.js` | Properties that must hold for every policy, over a few thousand generated ones, from a fixed seed |
| `test/exports.js` | That the runtime exports and `lib/index.d.ts` describe the same API |
| `test/docs.js` | That the examples in this README and in `examples/` still do what they claim |
| `test/package.js` | The packed tarball: its contents, that `main` and `types` resolve, and that a TypeScript consumer can import it by name |
| `test/types/usage.ts` | That valid usage compiles and invalid usage does not, via `@ts-expect-error` |
| `test/types/frameworks.ts` | That the declarations accept the real frameworks' own types, by mounting each adapter where its framework expects one. Part of `npm run test:frameworks`, since it needs them installed |

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
