// Compile-only check that the structural types in lib/index.d.ts accept the
// real frameworks.
//
// test/types/usage.ts checks the declarations against hand-written doubles,
// which can only say that the declarations are self-consistent. This file
// mounts each adapter where its framework expects one, using that framework's
// own types, so a signature that drifts — a reply method renamed, a context
// narrowed — fails to compile here.
//
// It is excluded from the default tsconfig, because it needs the frameworks
// installed. `npm run test:frameworks` installs them and runs it.
import Fastify from 'fastify';
import Koa from 'koa';
import { Hono } from 'hono';
import Hapi from '@hapi/hapi';
import express from 'express';

import * as CSP from '../../lib/index.js';

const policy = { 'default-src': CSP.SRC_NONE, 'script-src': [CSP.SRC_SELF] };
const local = { 'default-src': CSP.SRC_NONE, 'report-only': true };

// --- express ----------------------------------------------------------------

const app = express();
app.use(CSP.getCSP(policy));
app.get('/local', CSP.getCSP(local), (req, res) => { res.send('ok'); });

// --- fastify ----------------------------------------------------------------

const fastify = Fastify();
fastify.addHook('onRequest', CSP.getFastifyCSP(policy));
fastify.get('/local', { onRequest: CSP.getFastifyCSP(local) }, async () => 'ok');

// --- koa --------------------------------------------------------------------

const koa = new Koa();
koa.use(CSP.getKoaCSP(policy));

// --- hono -------------------------------------------------------------------

const hono = new Hono();
hono.use('*', CSP.getHonoCSP(policy));
hono.get('/local', CSP.getHonoCSP(local), c => c.text('ok'));

// --- hapi -------------------------------------------------------------------

const server = Hapi.server({ port: 3000 });
server.ext('onPreResponse', CSP.getHapiCSP(policy));
server.route({
  method: 'GET',
  path: '/local',
  options: { ext: { onPreResponse: { method: CSP.getHapiCSP(local) } } },
  handler: () => 'ok'
});

// --- a Fetch Headers --------------------------------------------------------

const applyCSP = CSP.getHeadersCSP(policy);
applyCSP(new Response('ok').headers);

export { app, fastify, koa, hono, server, applyCSP };
