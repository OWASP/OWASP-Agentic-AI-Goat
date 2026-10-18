'use strict';
const assert = require('node:assert/strict');
const { createValidatedBrowserJsonCache } = require('./validatedBrowserJsonCache');

// Install before production login. This records actual responses; it never
// disables browser caching, changes requests, or supplies a synthetic response.
function createSecureShopCatalogEvidence({ page, origin }) {
  const parsed = new URL(origin);
  assert.equal(parsed.origin, origin);
  assert.equal(parsed.protocol, 'http:');
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.ok(parsed.port);
  const context = page.browserContext();
  const expectedUrl = origin + '/api/workshop/challenges';
  const cache = createValidatedBrowserJsonCache(context);
  let closed = false, failure;
  function matches(response) {
    return response.url() === expectedUrl && response.request().method() === 'GET';
  }
  function admit(response) {
    assert.equal(page.browserContext(), context, 'Catalog page context changed');
    assert.equal(response.frame()?.page(), page, 'Catalog response belongs to another page');
    assert.ok(matches(response), 'Exact catalog GET response required');
  }
  function retain(error) { if (!failure) failure = error; }
  function observe(response) {
    try {
      if (!matches(response)) return;
      admit(response);
      void cache.observe(response, { context, expectedUrl }).catch(retain);
    } catch (error) { retain(error); }
  }
  page.on('response', observe);
  async function settle() {
    try { await cache.settle({ context, expectedUrl }); } catch (error) { retain(error); }
    if (failure) throw failure;
  }
  async function read(response) {
    assert.equal(closed, false, 'Catalog observer is closed');
    try {
      admit(response);
      const body = await cache(response, { context, expectedUrl });
      await settle();
      return body;
    } catch (error) { retain(error); throw failure; }
  }
  async function close() {
    if (!closed) { closed = true; page.off('response', observe); }
    await settle();
  }
  return Object.freeze({ matches, read, settle, close });
}
module.exports = { createSecureShopCatalogEvidence };
