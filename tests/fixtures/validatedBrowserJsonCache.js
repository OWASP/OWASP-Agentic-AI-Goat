'use strict';
const assert = require('node:assert/strict');
const MAX_REPRESENTATIONS_PER_URL = 64;
// Qualification evidence cache, not a browser/network cache override. Each
// instance belongs to one authenticated browser context and exact URL key.
function createValidatedBrowserJsonCache(context) {
  assert.ok(context && typeof context === 'object');
  const entries = new Map();
  const queues = new Map(), observations = new WeakMap();
  function validate(response, { context: actualContext, expectedUrl }) {
    assert.equal(actualContext, context, 'conditional representation context mismatch');
    assert.equal(response.url(), expectedUrl, 'conditional representation URL mismatch');
    assert.equal(response.request().method(), 'GET');
    assert.equal(typeof expectedUrl, 'string');assert.ok(expectedUrl.length > 0);
  }
  async function consume(response, expectedUrl) {
    const headers = response.headers(), etag = headers.etag;
    if (response.status() === 200) {
      const body = await response.json();
      if (typeof etag === 'string' && etag.length) {
        let representations = entries.get(expectedUrl);
        if (!representations) { representations = new Map();entries.set(expectedUrl, representations); }
        // Map insertion order supplies deterministic oldest-first eviction. A
        // repeated validator replaces and refreshes only its captured value.
        representations.delete(etag);representations.set(etag, structuredClone(body));
        while (representations.size > MAX_REPRESENTATIONS_PER_URL) representations.delete(representations.keys().next().value);
      }
      return body;
    }
    assert.equal(response.status(), 304, 'expected content or validated conditional response');
    const validator = response.request().headers()['if-none-match'];
    assert.equal(validator, etag, '304 request and response validators differ');
    assert.ok(typeof etag === 'string' && etag.length > 0, '304 requires a non-empty validator');
    const representations = entries.get(expectedUrl), prior = representations?.get(etag);
    assert.ok(prior !== undefined, '304 requires a captured 200 representation for this exact URL and ETag');
    return structuredClone(prior);
  }
  function schedule(response, options) {
    validate(response, options);
    const existing = observations.get(response);
    if (existing) return existing;
    const expectedUrl = options.expectedUrl;
    const previous = queues.get(expectedUrl) || Promise.resolve();
    const current = previous.then(() => consume(response, expectedUrl));
    queues.set(expectedUrl, current);observations.set(response, current);
    // A browser response listener cannot await its callback. Retain the exact
    // rejection in the per-URL queue for read()/settle(), while preventing an
    // unhandled-rejection report before the qualification reaches that fence.
    void current.catch(() => {});
    return current;
  }
  async function read(response, options) { return schedule(response, options); }
  read.observe = (response, options) => schedule(response, options);
  read.settle = async ({ context: actualContext, expectedUrl }) => {
    assert.equal(actualContext, context, 'conditional representation context mismatch');
    assert.equal(typeof expectedUrl, 'string');assert.ok(expectedUrl.length > 0);
    const pending = queues.get(expectedUrl);if (pending) await pending;
  };
  return read;
}
module.exports = { createValidatedBrowserJsonCache, MAX_REPRESENTATIONS_PER_URL };
