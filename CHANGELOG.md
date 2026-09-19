# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- `STARTER_OPTIONS` drops the deprecated `plugin-types` and adds
  `object-src 'none'` and `base-uri 'self'`.
- Directives are joined with `'; '`. Previously each was concatenated with a
  trailing `';'`, and array values left a stray space before it
  (`script-src 'self' data: ;`). The policy is semantically unchanged.
- `getCSP()` tolerates being called with no policy.
- `engines` now says Node.js >=18. It previously claimed >=0.4.0, which was
  never true for this code.
- Package metadata: `license` replaces the deprecated `licenses` array, and the
  repository and bugs URLs point at the correct account.

### Deprecated

- `plugin-types` and `block-all-mixed-content`, both removed from the CSP
  specification. They still work if passed explicitly.

### Fixed

- `examples/express.js` required `'./'` rather than the package root.

### Removed

- Travis CI configuration, replaced by GitHub Actions.
- The ava and c8 development dependencies; tests now use the built-in
  `node:test` runner and its built-in coverage.
- The Eclipse `.project` descriptor.
- `.npmignore`, replaced by an explicit `files` allowlist. The published
  tarball is now `lib/`, `README.md`, `LICENSE` and `package.json`.

## [0.3.4] and earlier

See the [commit history](https://github.com/erdtman/content-security-policy/commits/master).

[Unreleased]: https://github.com/erdtman/content-security-policy/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/erdtman/content-security-policy/releases/tag/v0.3.4
