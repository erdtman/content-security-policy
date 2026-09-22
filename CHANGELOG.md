# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Directive names and values are validated against the CSP grammar when the
  policy is compiled. A name may contain only ASCII letters, digits and `-`; a
  value may not contain control characters, `;`, `,` or non-ASCII characters.
  A malformed policy now throws a `TypeError` from `getCSP`, at startup,
  instead of producing a broken header on every request. A directive toggled
  off with a falsy value is not validated, so switching one off cannot throw.
- `getCSP` rejects options that are not a policy object.

### Changed

- `STARTER_OPTIONS` is frozen. It is shared by every consumer in the process,
  so mutating it changed the baseline for all of them. Spread it to derive a
  policy. Its declared type is now `Readonly<Policy>`.

### Fixed

- Directive values were read through the prototype chain, so a polluted
  `Object.prototype` could add directives to, or loosen, every compiled policy,
  and could flip a policy to report-only. Only a policy's own properties are
  read now.
- A value containing CR or LF was accepted and then rejected by Node with
  `ERR_INVALID_CHAR` inside `res.setHeader`, turning every request into a 500.
  It is rejected when the policy is built instead.
- An error message described an array policy by its contents rather than as an
  array.

### Tests

- The suite is layered into compilation and validation tests, real
  `http.ServerResponse` integration tests, generated-policy invariant tests,
  export and declaration tests, documentation drift tests, and tests of the
  packed tarball. It still has no test dependencies.
- Header assertions compare the whole header string. They previously used
  substring matches, which still passed when a directive was widened.
- `next()` is asserted, the ordering table is generated from `DIRECTIVES`, and
  the type declarations are checked with `@ts-expect-error` so that invalid
  usage failing to fail is a build error.
- Suite strength is measured by mutation testing (`npm run mutation`), held at
  a 100% score and run weekly in CI. Stryker is fetched on demand rather than
  added as a dependency.

## [0.4.0] - 2026-09-22

### Added

- CSP3 directives: `manifest-src`, `prefetch-src`, `script-src-elem`,
  `script-src-attr`, `style-src-elem`, `style-src-attr`, `base-uri`,
  `report-to`, `require-trusted-types-for`, `trusted-types` and
  `upgrade-insecure-requests`.
- Unknown directives are passed through verbatim instead of being dropped, so
  directives added to CSP after a given release can be used without waiting for
  a library update.
- `true` as a directive value, for directives that take no value, e.g.
  `'upgrade-insecure-requests': true`.
- Source constants `SRC_STRICT_DYNAMIC`, `SRC_UNSAFE_HASHES`,
  `SRC_WASM_UNSAFE_EVAL`, `SRC_REPORT_SAMPLE` and `TRUSTED_TYPES_FOR_SCRIPT`,
  plus the remaining sandbox tokens.
- `DIRECTIVES`, the known directive names in emission order.
- Bundled TypeScript declarations (`lib/index.d.ts`).
- Releases are published from GitHub Actions with npm provenance attestations,
  so a published tarball can be traced to the commit and workflow run that
  built it. Verify with `npm audit signatures`.

### Changed

- `STARTER_OPTIONS` drops the deprecated `plugin-types` and adds
  `object-src 'none'` and `base-uri 'self'`.
- Directives are joined with `'; '`. Previously each was concatenated with a
  trailing `';'`, and array values left a stray space before it
  (`script-src 'self' data: ;`). The policy is semantically unchanged.
- `getCSP()` tolerates being called with no policy.
- `engines` now says Node.js >=22, the oldest release still supported upstream.
  It previously claimed >=0.4.0, which was never true for this code. Node.js 18
  and 20 reached end of life in April 2025 and April 2026 respectively; the
  library itself has no syntax requiring Node.js 22, so older runtimes will
  likely keep working, but they are no longer tested.
- Package metadata: `license` replaces the deprecated `licenses` array, and the
  repository and bugs URLs point at the correct account.

### Deprecated

- `plugin-types` and `block-all-mixed-content`, both removed from the CSP
  specification. They still work if passed explicitly.

### Fixed

- `examples/express.js` required `'./'` rather than the package root.

### Removed

- Travis CI configuration, replaced by GitHub Actions.
- The ava, c8 and neostandard development dependencies. Tests use the built-in
  `node:test` runner and its built-in coverage, and linting is eslint with its
  own recommended rules. Formatting is not linted: those rules are taste rather
  than correctness. The install tree went from 337 packages to 79.
- The Eclipse `.project` descriptor.
- `.npmignore`, replaced by an explicit `files` allowlist. The published
  tarball is now `lib/`, `README.md`, `LICENSE` and `package.json`.

## [0.3.4] and earlier

See the [commit history](https://github.com/erdtman/content-security-policy/commits/master).

[Unreleased]: https://github.com/erdtman/content-security-policy/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/erdtman/content-security-policy/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/erdtman/content-security-policy/releases/tag/v0.3.4
