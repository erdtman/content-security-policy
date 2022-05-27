[![Build Status](https://travis-ci.com/erdtman/content-security-policy.svg?branch=master)](https://travis-ci.com/erdtman/content-security-policy)
[![Coverage Status](https://coveralls.io/repos/github/erdtman/content-security-policy/badge.svg?branch=master)](https://coveralls.io/github/erdtman/content-security-policy?branch=master)
# content-security-policy
Middleware to add Content-Security-Policy header according to http://www.w3.org/TR/CSP/

hello

## Install
```
    $ npm install content-security-policy --save
```
## Tests
```
    $ npm install --dev
    $ npm test
```
## Usage
```js
const csp = require('content-security-policy');
const express = require('express');
const app = express();

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [ csp.SRC_SELF, csp.SRC_DATA ]
};

const globalCSP = csp.getCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getCSP(cspPolicy);

// This will apply this policy to all requests if no local policy is set
app.use(globalCSP);

app.get('/', (req, res) => {
  res.send('Using global content security policy!');
});

// This will apply the local policy just to this path, overriding the globla policy
app.get('/local', localCSP, (req, res) => {
  res.send('Using path local content security policy!');
});

app.listen(3000, () => {
  console.log('Example app listening on port 3000!');
});

```
