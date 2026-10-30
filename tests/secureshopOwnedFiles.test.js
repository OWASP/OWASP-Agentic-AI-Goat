'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ownedPath = require.resolve('../server/services/secureshopOwnedFiles');
const primitivePath = require.resolve('../sidecars/sandbox-runner/secureshopFiles');

function isolatedOwnedFiles() {
  const originalPrimitive = require.cache[primitivePath];
  const originalOwned = require.cache[ownedPath];
  const calls = [];
  const primitive = Object.freeze({
    provisionReservedTarget() {}, readFile() {}, writeFile() {}, retireReservedTarget() {},
  });
  try {
    require.cache[primitivePath] = { id: primitivePath, filename: primitivePath, loaded: true,
      exports: { createSecureShopFiles(options) { calls.push(options); return primitive; } } };
    delete require.cache[ownedPath];
    const api = require(ownedPath);
    return { api, calls, primitive };
  } finally {
    if (originalPrimitive) require.cache[primitivePath] = originalPrimitive;
    else delete require.cache[primitivePath];
    if (originalOwned) require.cache[ownedPath] = originalOwned;
    else delete require.cache[ownedPath];
  }
}

test('one retained primitive uses the private owned root and full public upload limits', () => {
  const { api, calls, primitive } = isolatedOwnedFiles();
  const appRoot = path.resolve('/private/owasp-ai-goat/app-data');
  const first = api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: appRoot });
  const second = api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: `${appRoot}/../app-data` });
  assert.equal(first, primitive);
  assert.equal(second, primitive);
  assert.deepEqual(calls, [{
    root: path.join(appRoot, 'secureshop-owned-files'),
    maxReadBytes: 20 * 1024 * 1024,
    maxWriteBytes: 20 * 1024 * 1024,
  }]);
});

test('invalid or changed roots fail without constructing a second primitive', () => {
  const invalid = isolatedOwnedFiles();
  assert.throws(() => invalid.api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: 'relative/data' }),
    /Private application data root required/);
  assert.equal(invalid.calls.length, 0);

  const configured = isolatedOwnedFiles();
  configured.api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: '/private/owasp-ai-goat/one' });
  assert.throws(() => configured.api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: '/private/owasp-ai-goat/two' }),
    /already configured/);
  assert.equal(configured.calls.length, 1);
});

test('missing configuration is optional only before the singleton is retained', () => {
  const absent = isolatedOwnedFiles();
  assert.equal(absent.api.getSecureShopOwnedFiles({}), undefined);
  assert.equal(absent.calls.length, 0);

  const configured = isolatedOwnedFiles();
  configured.api.getSecureShopOwnedFiles({ OWASP_AI_GOAT_APP_DATA_ROOT: '/private/owasp-ai-goat/retained' });
  assert.throws(() => configured.api.getSecureShopOwnedFiles({}), /already configured/);
  assert.equal(configured.calls.length, 1);
});
