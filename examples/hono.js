const csp = require('..');
const { Hono } = require('hono');
// Hono runs on any web standard runtime; on Node it is served through this.
const { serve } = require('@hono/node-server');
const app = new Hono();

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [csp.SRC_SELF, csp.SRC_DATA]
};

const globalCSP = csp.getHonoCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getHonoCSP(cspPolicy);

// This will apply this policy to all requests if no local policy is set
app.use('*', globalCSP);

app.get('/', c => c.text('Using global content security policy!'));

// This will apply the local policy just to this path, overriding the global one
app.get('/local', localCSP, c => c.text('Using path local content security policy!'));

serve({ fetch: app.fetch, port: 3000 }, () => {
  console.log('Example app listening on port 3000!');
});
