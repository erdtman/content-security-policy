# content-security-policy
Middleware to add Content-Security-Policy header according to http://www.w3.org/TR/CSP/

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

### Connect
```js
    const connect = require('connect');
    const csp = require('content-security-policy');
    // Using the example starter policy that will allow most common requests to 'self'
    const server = connect.createServer(csp.getCSP(CSP.STARTER_OPTIONS));
    server.listen(3030);
```
### Express
```js
    const csp = require('content-security-policy');
    const express = require('express');
    const app = express();
    
    const cspPolicy = {
      "report-uri" : "/reporting",
      "default-src" : CSP.SRC_NONE,
      "script-src" : [ CSP.SRC_SELF ]
    };
    
    const globalCSP = csp.getCSP(csp.STARTER_OPTIONS);
    const localCSP = csp.getCSP(cspPolicy);
    
    // Insert before 'app.router'
    app.use(globalCSP); // This will apply this policy to all requests
    app.use(app.router);
    
    app.get('/settings',
      localCSP, // This will apply the local policy just to this page
      function(req, res) {
        res.render('settings');
      });
```
