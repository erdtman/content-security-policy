const csp = require('..');
const Koa = require('koa');
const app = new Koa();

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [csp.SRC_SELF, csp.SRC_DATA]
};

const globalCSP = csp.getKoaCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getKoaCSP(cspPolicy);

// This will apply this policy to all requests if no local policy is set
app.use(globalCSP);

// Koa has no router of its own, so the local policy is dispatched by path.
// Whichever way it is reached, the more specific middleware is the inner one.
app.use((ctx, next) => (ctx.path === '/local' ? localCSP(ctx, next) : next()));

app.use(ctx => {
  ctx.body = ctx.path === '/local'
    ? 'Using path local content security policy!'
    : 'Using global content security policy!';
});

app.listen(3000, () => {
  console.log('Example app listening on port 3000!');
});
