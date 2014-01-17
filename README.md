# content-security-policy
Middleware to add Content-Security-Policy header according to http://www.w3.org/TR/CSP/

## Install

    $ npm install content-security-policy

## Tests

    $ npm install --dev
    $ npm test

## Usage

### Connect

    var connect = require('connect');
    var csp = require('content-security-policy');
    // Using the example starter policy that will allow most common requests to 'self'
    var server = connect.createServer(csp.getCSP(CSP.STARTER_OPTIONS));
    server.listen(3030);
    
### Express

    var csp = require('content-security-policy');
    var express = require('express');
    var app = express();
    
    var cspPolicy = {
      "report-uri" : "/reporting",
      "default-src" : CSP.SRC_NONE,
      "script-src" : [ CSP.SRC_SELF ]
    };
    
    var globalCSP = csp.getCSP(csp.STARTER_OPTIONS);
    var localCSP = csp.getCSP(cspPolicy);
    
    // Insert before 'app.router'
    app.use(globalCSP); // This will apply this policy to all requests
    app.use(app.router);
    
    app.get('/settings',
      localCSP, // This will apply the local policy just to this page
      function(req, res) {
        res.render('settings');
      });
