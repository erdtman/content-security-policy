'use strict';

const { execFileSync } = require('node:child_process');
const {
  mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');

/**
 * What a consumer gets is the published tarball, not the working tree. These
 * tests pack the package, install it the way npm would, and exercise it from
 * the outside: the shape most likely to break silently is `files` plus `main`
 * plus `types` disagreeing with each other.
 *
 * Nothing here touches the network.
 */

const ROOT = path.join(__dirname, '..');

const EXPECTED_FILES = ['LICENSE', 'README.md', 'lib/index.d.ts', 'lib/index.js', 'package.json'];

let workspace;
let installed;
let manifest;

before(() => {
  // realpath: on macOS the temp dir is a symlink, and require.resolve reports
  // the resolved path.
  workspace = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'csp-package-')));

  execFileSync('npm', ['pack', '--pack-destination', workspace], { cwd: ROOT, stdio: 'pipe' });
  const tarball = readdirSync(workspace).find(name => name.endsWith('.tgz'));
  assert.ok(tarball, 'npm pack produced no tarball');

  execFileSync('tar', ['-xf', path.join(workspace, tarball), '-C', workspace], { stdio: 'pipe' });

  // Lay it out as node_modules/<name> so module resolution is the real thing.
  installed = path.join(workspace, 'node_modules', 'content-security-policy');
  mkdirSync(path.dirname(installed), { recursive: true });
  renameSync(path.join(workspace, 'package'), installed);

  manifest = JSON.parse(readFileSync(path.join(installed, 'package.json'), 'utf8'));
});

after(() => rmSync(workspace, { recursive: true, force: true }));

/**
 * @param dir a directory in the extracted package
 * @returns every file under it, as slash-separated relative paths
 */
function filesUnder (dir, prefix = '') {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => (
    entry.isDirectory()
      ? filesUnder(path.join(dir, entry.name), prefix + entry.name + '/')
      : [prefix + entry.name]
  ));
}

describe('the published tarball', () => {
  it('contains exactly the files it should', () => {
    assert.deepEqual(filesUnder(installed).sort(), EXPECTED_FILES);
  });

  it('ships no tests, examples or tooling config', () => {
    for (const name of filesUnder(installed)) {
      assert.doesNotMatch(name, /^(test|examples|coverage|\.github)\//, name);
      assert.doesNotMatch(name, /^(tsconfig\.json|eslint\.config\.js|\.npmrc|package-lock\.json)$/, name);
    }
  });

  it('points main and types at files that are actually in it', () => {
    for (const field of ['main', 'types']) {
      assert.ok(manifest[field], 'package.json has no ' + field);
      assert.ok(
        filesUnder(installed).includes(manifest[field].replace(/^\.\//, '')),
        field + ' points at ' + manifest[field] + ', which is not published'
      );
    }
  });

  it('declares no runtime dependencies', () => {
    // devDependencies stay in the published manifest; npm just ignores them
    // for consumers. Only these two would be installed.
    assert.equal(manifest.dependencies, undefined);
    assert.equal(manifest.peerDependencies, undefined);
    assert.equal(manifest.engines.node, '>=22');
  });

  it('ships the declarations unchanged', () => {
    assert.equal(
      readFileSync(path.join(installed, 'lib', 'index.d.ts'), 'utf8'),
      readFileSync(path.join(ROOT, 'lib', 'index.d.ts'), 'utf8')
    );
  });
});

describe('the installed package', () => {
  it('resolves by name and exports the same API as the working tree', () => {
    const resolved = require.resolve('content-security-policy', { paths: [workspace] });
    assert.equal(resolved, path.join(installed, manifest.main));

    const packed = require(resolved);
    assert.deepEqual(Object.keys(packed).sort(), Object.keys(CSP).sort());

    for (const [name, value] of Object.entries(CSP)) {
      if (typeof value === 'string') {
        assert.equal(packed[name], value, name);
      }
    }
  });

  it('works when required from outside the repository', () => {
    const packed = require(require.resolve('content-security-policy', { paths: [workspace] }));
    const headers = {};
    packed.getCSP(packed.STARTER_OPTIONS)(null, {
      setHeader: (name, value) => { headers[name] = value; },
      removeHeader: name => { delete headers[name]; }
    }, () => {});

    assert.equal(headers['Content-Security-Policy'], 'default-src \'none\'; child-src \'self\'; ' +
      'connect-src \'self\'; font-src \'self\'; img-src \'self\'; object-src \'none\'; script-src \'self\'; ' +
      'style-src \'self\'; base-uri \'self\'; form-action \'self\'; frame-ancestors \'self\'');
  });

  it('type-checks against a TypeScript consumer resolving it by name', () => {
    writeFileSync(path.join(workspace, 'consumer.ts'), [
      'import { getCSP, Policy, CSPMiddleware, SRC_NONE, SRC_SELF, DIRECTIVES } from \'content-security-policy\';',
      'const policy: Policy = { \'default-src\': SRC_NONE, \'script-src\': [SRC_SELF] };',
      'const middleware: CSPMiddleware = getCSP(policy);',
      'const names: readonly string[] = DIRECTIVES;',
      'export { middleware, names };',
      ''
    ].join('\n'));

    writeFileSync(path.join(workspace, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        strict: true,
        noEmit: true,
        target: 'es2022',
        module: 'node16',
        moduleResolution: 'node16',
        skipLibCheck: false,
        types: []
      },
      include: ['consumer.ts']
    }));

    // typescript is a devDependency of this repo, not of the temp workspace.
    const tsc = require.resolve('typescript/bin/tsc');
    execFileSync(process.execPath, [tsc, '--project', workspace], { stdio: 'pipe' });
  });
});
