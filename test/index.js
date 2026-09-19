'use strict';

const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const CSP = require('../lib/index.js');

function getRes (result) {
  return {
    setHeader: (name, value) => {
      result.name = name;
      result.value = value;
    },
    removeHeader: () => {}
  };
}

function next () {}

test('Starter options', () => {
  const cspFunction = CSP.getCSP(CSP.STARTER_OPTIONS);
  const result = {};
  cspFunction(null, getRes(result), next);

  assert.equal(result.name, 'Content-Security-Policy');

  assert.ok(result.value.includes('default-src \'none\''), 'default-src');
  assert.ok(result.value.includes('script-src \'self\''), 'script-src');
  assert.ok(result.value.includes('connect-src \'self\''), 'connect-src');
  assert.ok(result.value.includes('img-src \'self\''), 'img-src');
  assert.ok(result.value.includes('style-src \'self\''), 'style-src');
  assert.ok(result.value.includes('child-src \'self\''), 'child-src');
  assert.ok(result.value.includes('form-action \'self\''), 'form-action');
  assert.ok(result.value.includes('frame-ancestors \'self\''), 'frame-ancestors');
  assert.ok(result.value.includes('object-src \'none\''), 'object-src');
  assert.ok(result.value.includes('base-uri \'self\''), 'base-uri');
  assert.ok(!result.value.includes('plugin-types'), 'plugin-types is deprecated and no longer in the starter policy');
});

test('Report only', () => {
  const policy = {
    'default-src': CSP.SRC_NONE,
    'report-only': true
  };
  const cspFunction = CSP.getCSP(policy);
  const result = {};
  cspFunction(null, getRes(result), next);

  assert.equal(result.name, 'Content-Security-Policy-Report-Only');

  assert.ok(result.value.includes('default-src \'none\''), 'default-src');
});

test('All policies', () => {
  const policy = {
    'report-uri': '/reporting',
    sandbox: [CSP.SANDBOX_ALLOW_FORMS],
    'default-src': CSP.SRC_NONE,
    'script-src': [CSP.SRC_SELF, CSP.SRC_USAFE_INLINE],
    'object-src': 'https://google.com',
    'style-src': 'http://tmp.com',
    'img-src': 'https://flikr.com',
    'media-src': '123',
    'frame-src': '456',
    'font-src': '789',
    'connect-src': 'abc',
    'child-src': 'def',
    'form-action': 'ghi',
    'worker-src': CSP.SRC_BLOB,
    'frame-ancestors': [CSP.SRC_SELF, CSP.SRC_DATA],
    'plugin-types': CSP.SRC_NONE
  };

  const result = {};
  const cspFunction = CSP.getCSP(policy);
  cspFunction(null, getRes(result), next);

  assert.equal(result.name, 'Content-Security-Policy');

  assert.ok(result.value.includes('report-uri /reporting'), 'report-uri');
  assert.ok(result.value.includes('sandbox allow-forms'), 'style-src');
  assert.ok(result.value.includes('default-src \'none\''), 'default-src');
  assert.ok(result.value.includes('script-src \'self\' \'unsafe-inline\''), 'script-src');
  assert.ok(result.value.includes('object-src https://google.com'), 'object-src');
  assert.ok(result.value.includes('style-src http://tmp.com'), 'style-src');
  assert.ok(result.value.includes('img-src https://flikr.com'), 'img-src');
  assert.ok(result.value.includes('media-src 123'), 'media-src');
  assert.ok(result.value.includes('frame-src 456'), 'frame-src');
  assert.ok(result.value.includes('font-src 789'), 'font-src');
  assert.ok(result.value.includes('connect-src abc'), 'connect-src');
  assert.ok(result.value.includes('child-src def'), 'child-src');
  assert.ok(result.value.includes('form-action ghi'), 'form-action');
  assert.ok(result.value.includes('worker-src blob:'), 'worker-src');
  assert.ok(result.value.includes('frame-ancestors \'self\' data:'), 'frame-ancestors');
  assert.ok(result.value.includes('plugin-types \'none\''), 'plugin-types');
});

test('Unknown directives are passed through', () => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_NONE,
    'fenced-frame-src': 'https://ads.example'
  })(null, getRes(result), next);

  assert.equal(result.value, 'default-src \'none\'; fenced-frame-src https://ads.example');
});

test('Valueless directives', () => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_SELF,
    'upgrade-insecure-requests': true
  })(null, getRes(result), next);

  assert.equal(result.value, 'default-src \'self\'; upgrade-insecure-requests');
});

test('Falsy values are skipped', () => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_SELF,
    'script-src': false,
    'style-src': null,
    'img-src': '',
    'font-src': '   ',
    'media-src': [],
    'object-src': ['', null]
  })(null, getRes(result), next);

  assert.equal(result.value, 'default-src \'self\'');
});

test('Directives are emitted in spec order, unknown ones last', () => {
  const result = {};
  CSP.getCSP({
    'x-custom-src': 'https://custom.example',
    'frame-ancestors': CSP.SRC_NONE,
    'script-src': CSP.SRC_SELF,
    'default-src': CSP.SRC_NONE
  })(null, getRes(result), next);

  assert.equal(result.value, [
    'default-src \'none\'',
    'script-src \'self\'',
    'frame-ancestors \'none\'',
    'x-custom-src https://custom.example'
  ].join('; '));
});

test('Array values are joined without stray whitespace', () => {
  const result = {};
  CSP.getCSP({
    'script-src': [CSP.SRC_SELF, CSP.SRC_STRICT_DYNAMIC, 'https://cdn.example']
  })(null, getRes(result), next);

  assert.equal(result.value, 'script-src \'self\' \'strict-dynamic\' https://cdn.example');
});

test('report-only is not emitted as a directive', () => {
  const result = {};
  CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true })(null, getRes(result), next);

  assert.equal(result.name, 'Content-Security-Policy-Report-Only');
  assert.equal(result.value, 'default-src \'none\'');
});

test('Empty and missing policies produce an empty header', () => {
  for (const policy of [undefined, null, {}]) {
    const result = {};
    CSP.getCSP(policy)(null, getRes(result), next);
    assert.equal(result.name, 'Content-Security-Policy');
    assert.equal(result.value, '');
  }
});

test('Previously set CSP headers are removed', () => {
  const removed = [];
  const res = {
    setHeader: () => {},
    removeHeader: name => removed.push(name)
  };
  CSP.getCSP(CSP.STARTER_OPTIONS)(null, res, next);

  assert.deepEqual(removed, ['Content-Security-Policy-Report-Only', 'Content-Security-Policy']);
});

test('DIRECTIVES is exported and frozen', () => {
  assert.ok(Array.isArray(CSP.DIRECTIVES));
  assert.ok(Object.isFrozen(CSP.DIRECTIVES));
  assert.ok(CSP.DIRECTIVES.includes('base-uri'));
  assert.ok(CSP.DIRECTIVES.includes('trusted-types'));
});

test('Values that are neither string, array nor true are ignored', () => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_SELF,
    'script-src': 42,
    'style-src': { nope: true }
  })(null, getRes(result), next);

  assert.equal(result.value, 'default-src \'self\'');
});

test('Type declarations match the runtime exports', () => {
  const declarations = readFileSync(path.join(__dirname, '..', 'lib', 'index.d.ts'), 'utf8');

  const declared = new Set(
    [...declarations.matchAll(/^export (?:declare )?(?:const|function) (\w+)/gm)].map(m => m[1])
  );
  assert.deepEqual([...declared].sort(), Object.keys(CSP).sort(), 'exported names');

  for (const [, name, value] of declarations.matchAll(/^export const (\w+): "((?:[^"\\]|\\.)*)";/gm)) {
    assert.equal(CSP[name], value.replace(/\\(.)/g, '$1'), name);
  }
});
