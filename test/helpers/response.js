'use strict';

/**
 * Test doubles for the response object the middleware talks to.
 *
 * The middleware's contract is not just "the header ends up right": it is the
 * ordered sequence of calls it makes, and the fact that it calls next() once
 * with no error. These helpers record all of that so a test can assert on the
 * whole interaction rather than on a single captured string.
 */

/**
 * A response that records every call, in order.
 *
 * @returns a response double with a `calls` log and a `headers` map
 */
function recordingResponse () {
  const calls = [];
  const headers = new Map();

  return {
    calls,
    headers,
    setHeader (name, value) {
      calls.push(['setHeader', name, value]);
      headers.set(name, value);
      return this;
    },
    removeHeader (name) {
      calls.push(['removeHeader', name]);
      headers.delete(name);
      return this;
    }
  };
}

/**
 * Run a middleware against a response and report everything it did.
 *
 * @param middleware the middleware under test
 * @param res an existing response double, to chain several middlewares
 * @returns the call log, the arguments of each next() call, and the surviving
 *   header, if any
 */
function run (middleware, res = recordingResponse()) {
  const nextCalls = [];
  middleware(null, res, (...args) => nextCalls.push(args));

  const entries = [...res.headers.entries()];
  const last = entries[entries.length - 1];

  return {
    res,
    calls: res.calls,
    nextCalls,
    headers: res.headers,
    name: last && last[0],
    value: last && last[1]
  };
}

/**
 * The header value a policy compiles to. For tests that care only about the
 * string.
 *
 * @param middleware the middleware under test
 * @returns the header value
 */
function headerValue (middleware) {
  return run(middleware).value;
}

module.exports = { recordingResponse, run, headerValue };
