const csp = require('..');
const fastify = require('fastify')();

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [csp.SRC_SELF, csp.SRC_DATA]
};

const globalCSP = csp.getFastifyCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getFastifyCSP(cspPolicy);

// This will apply this policy to all requests if no local policy is set
fastify.addHook('onRequest', globalCSP);

fastify.get('/', async () => 'Using global content security policy!');

// A route level hook runs after the instance wide one, so it wins
fastify.get('/local', { onRequest: localCSP }, async () => 'Using path local content security policy!');

fastify.listen({ port: 3000 }, () => {
  console.log('Example app listening on port 3000!');
});
