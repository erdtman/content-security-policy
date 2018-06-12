/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const test = require('ava');
const CSP = require('../');

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
  t.true(result.value.indexOf('plugin-types \'none\'') > -1, 'plugin-types');
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
    'sandbox': [ CSP.SANDBOX_ALLOW_FORMS ],
    'default-src': CSP.SRC_NONE,
    'script-src': [ CSP.SRC_SELF, CSP.SRC_USAFE_INLINE ],
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
