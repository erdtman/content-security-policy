import test from 'ava';
import CSP from '../lib/index.js';

function getRes (result) {
  return {
    setHeader: (name, value) => {
      result.name = name;
      result.value = value;
    },
    removeHeader: name => {}
  };
}

function next () {}

test('Starter options', t => {
  const cspFunction = CSP.getCSP(CSP.STARTER_OPTIONS);
  const result = {};
  cspFunction(null, getRes(result), next);

  t.is(result.name, 'Content-Security-Policy');

  t.true(result.value.indexOf('default-src \'none\'') > -1, 'default-src');
  t.true(result.value.indexOf('script-src \'self\'') > -1, 'script-src');
  t.true(result.value.indexOf('connect-src \'self\'') > -1, 'connect-src');
  t.true(result.value.indexOf('img-src \'self\'') > -1, 'img-src');
  t.true(result.value.indexOf('style-src \'self\'') > -1, 'style-src');
  t.true(result.value.indexOf('child-src \'self\'') > -1, 'child-src');
  t.true(result.value.indexOf('form-action \'self\'') > -1, 'form-action');
  t.true(result.value.indexOf('frame-ancestors \'self\'') > -1, 'frame-ancestors');
  t.true(result.value.indexOf('object-src \'none\'') > -1, 'object-src');
  t.true(result.value.indexOf('base-uri \'self\'') > -1, 'base-uri');
  t.false(result.value.indexOf('plugin-types') > -1, 'plugin-types is deprecated and no longer in the starter policy');
});

test('Report only', t => {
  const policy = {
    'default-src': CSP.SRC_NONE,
    'report-only': true
  };
  const cspFunction = CSP.getCSP(policy);
  const result = {};
  cspFunction(null, getRes(result), next);

  t.is(result.name, 'Content-Security-Policy-Report-Only');

  t.true(result.value.indexOf('default-src \'none\'') > -1, 'default-src');
});

test('All policies', t => {
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

  t.is(result.name, 'Content-Security-Policy');

  t.true(result.value.indexOf('report-uri /reporting') > -1, 'report-uri');
  t.true(result.value.indexOf('sandbox allow-forms') > -1, 'style-src');
  t.true(result.value.indexOf('default-src \'none\'') > -1, 'default-src');
  t.true(result.value.indexOf('script-src \'self\' \'unsafe-inline\'') > -1, 'script-src');
  t.true(result.value.indexOf('object-src https://google.com') > -1, 'object-src');
  t.true(result.value.indexOf('style-src http://tmp.com') > -1, 'style-src');
  t.true(result.value.indexOf('img-src https://flikr.com') > -1, 'img-src');
  t.true(result.value.indexOf('media-src 123') > -1, 'media-src');
  t.true(result.value.indexOf('frame-src 456') > -1, 'frame-src');
  t.true(result.value.indexOf('font-src 789') > -1, 'font-src');
  t.true(result.value.indexOf('connect-src abc') > -1, 'connect-src');
  t.true(result.value.indexOf('child-src def') > -1, 'child-src');
  t.true(result.value.indexOf('form-action ghi') > -1, 'form-action');
  t.true(result.value.indexOf('worker-src blob:') > -1, 'worker-src');
  t.true(result.value.indexOf('frame-ancestors \'self\' data:') > -1, 'frame-ancestors');
  t.true(result.value.indexOf('plugin-types \'none\'') > -1, 'plugin-types');
});

test('Unknown directives are passed through', t => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_NONE,
    'fenced-frame-src': 'https://ads.example'
  })(null, getRes(result), next);

  t.is(result.value, 'default-src \'none\'; fenced-frame-src https://ads.example');
});

test('Valueless directives', t => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_SELF,
    'upgrade-insecure-requests': true
  })(null, getRes(result), next);

  t.is(result.value, 'default-src \'self\'; upgrade-insecure-requests');
});

test('Falsy values are skipped', t => {
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

  t.is(result.value, 'default-src \'self\'');
});

test('Directives are emitted in spec order, unknown ones last', t => {
  const result = {};
  CSP.getCSP({
    'x-custom-src': 'https://custom.example',
    'frame-ancestors': CSP.SRC_NONE,
    'script-src': CSP.SRC_SELF,
    'default-src': CSP.SRC_NONE
  })(null, getRes(result), next);

  t.is(result.value, [
    'default-src \'none\'',
    'script-src \'self\'',
    'frame-ancestors \'none\'',
    'x-custom-src https://custom.example'
  ].join('; '));
});

test('Array values are joined without stray whitespace', t => {
  const result = {};
  CSP.getCSP({
    'script-src': [CSP.SRC_SELF, CSP.SRC_STRICT_DYNAMIC, 'https://cdn.example']
  })(null, getRes(result), next);

  t.is(result.value, 'script-src \'self\' \'strict-dynamic\' https://cdn.example');
});

test('report-only is not emitted as a directive', t => {
  const result = {};
  CSP.getCSP({ 'default-src': CSP.SRC_NONE, 'report-only': true })(null, getRes(result), next);

  t.is(result.name, 'Content-Security-Policy-Report-Only');
  t.is(result.value, 'default-src \'none\'');
});

test('Empty and missing policies produce an empty header', t => {
  for (const policy of [undefined, null, {}]) {
    const result = {};
    CSP.getCSP(policy)(null, getRes(result), next);
    t.is(result.name, 'Content-Security-Policy');
    t.is(result.value, '');
  }
});

test('Previously set CSP headers are removed', t => {
  const removed = [];
  const res = {
    setHeader: () => {},
    removeHeader: name => removed.push(name)
  };
  CSP.getCSP(CSP.STARTER_OPTIONS)(null, res, next);

  t.deepEqual(removed, ['Content-Security-Policy-Report-Only', 'Content-Security-Policy']);
});

test('DIRECTIVES is exported and frozen', t => {
  t.true(Array.isArray(CSP.DIRECTIVES));
  t.true(Object.isFrozen(CSP.DIRECTIVES));
  t.true(CSP.DIRECTIVES.includes('base-uri'));
  t.true(CSP.DIRECTIVES.includes('trusted-types'));
});

test('Values that are neither string, array nor true are ignored', t => {
  const result = {};
  CSP.getCSP({
    'default-src': CSP.SRC_SELF,
    'script-src': 42,
    'style-src': { nope: true }
  })(null, getRes(result), next);

  t.is(result.value, 'default-src \'self\'');
});
