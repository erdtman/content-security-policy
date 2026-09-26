const csp = require('..');
const Hapi = require('@hapi/hapi');
const server = Hapi.server({ port: 3000 });

const cspPolicy = {
  'report-uri': '/reporting',
  'default-src': csp.SRC_NONE,
  'script-src': [csp.SRC_SELF, csp.SRC_DATA]
};

const globalCSP = csp.getHapiCSP(csp.STARTER_OPTIONS);
const localCSP = csp.getHapiCSP(cspPolicy);

// This will apply this policy to all requests if no local policy is set.
// onPreResponse is the extension point that also covers the responses hapi
// generates itself, such as a 404 or a 500.
server.ext('onPreResponse', globalCSP);

server.route([
  {
    method: 'GET',
    path: '/',
    handler: () => 'Using global content security policy!'
  },
  {
    method: 'GET',
    path: '/local',
    // A route level extension runs after the server wide one, so it wins
    options: { ext: { onPreResponse: { method: localCSP } } },
    handler: () => 'Using path local content security policy!'
  }
]);

server.start().then(() => {
  console.log(`Example app listening on ${server.info.uri}`);
});
