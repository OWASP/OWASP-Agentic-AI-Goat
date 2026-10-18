'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  {
    EventEmitter
  } = require('node:events');
const {
  createSecureShopUploadAssetService,
  isCookieIsolatedHost
} = require('../server/services/secureshopUploadAssetService');
const {
  createSecureShopUploadAssetCapability
} = require('../server/services/secureshopUploadAssetCapability');
const ids = {
  effectId: '00000001-0000-4000-8000-000000000001',
  operationId: '00000002-0000-4000-8000-000000000002',
  targetId: '00000003-0000-4000-8000-000000000003',
  generation: 2,
  sceneId: '00000004-0000-4000-8000-000000000004',
  sceneGeneration: 3,
  mode: 'vuln',
  modeGeneration: 4,
  modeStamp: 'a'.repeat(64)
};
function response(outcome = 'finish') {
  const res = Object.assign(new EventEmitter(), {
    headers: {},
    headersSent: false,
    setHeader(k, v) {
      this.headers[k] = v;
    },
    end(v) {
      this.body = v;
      this.headersSent = true;
      queueMicrotask(() => this.emit(outcome));
    }
  });
  return res;
}
function setup({
  outcome = 'finish',
  now = () => 1700000000000
} = {}) {
  const capability = createSecureShopUploadAssetCapability({
      secret: 'x'.repeat(32),
      now,
      ttlMs: 1000
    }),
    claim = capability.mint(ids);
  let serves = 0,
    currents = 0;
  const admission = {
    scope: {}
  };
  const effect = {
    effectId: ids.effectId
  };
  const service = createSecureShopUploadAssetService({
    assetHost: '127.0.0.2',
    platformHost: '127.0.0.1',
    port: 9000,
    origin: 'http://127.0.0.2:9000',
    capability,
    lookup: async () => ({
      admission,
      effect,
      contentType: 'text/html',
      contentDisposition: 'inline; filename="x.html"',
      responseByteCount: 1,
      responseSha256: '2d711642b726b04401627ca9fbac32f5da7e5fbaedb0592e5fb3c9b9b5d1b9ef'
    }),
    read: async () => Buffer.from('x'),
    assertCurrent: async () => {
      currents++;
    },
    recordServe: async () => {
      serves++;
    },
    createServer() {}
  });
  return {
    service,
    claim,
    admission,
    effect,
    get serves() {
      return serves;
    },
    get currents() {
      return currents;
    },
    res: response(outcome)
  };
}
test('requires cookie-isolated host and rejects ambient authority', async () => {
  assert.equal(isCookieIsolatedHost('assets.example.test', 'app.example.test'), false);
  assert.equal(isCookieIsolatedHost('uploads.app.example.test', 'app.example.test'), false);
  assert.equal(isCookieIsolatedHost('::1', 'localhost'), true);
  assert.equal(isCookieIsolatedHost('::1', '127.0.0.1'), true);
  assert.equal(isCookieIsolatedHost('::1', '::1'), false);
  const x = setup(),
    res = response();
  await x.service.handler({
    method: 'GET',
    url: x.claim.path,
    headers: {
      host: '127.0.0.2:9000',
      cookie: 'platform=x'
    }
  }, res);
  assert.equal(res.statusCode, 403);
  assert.equal(x.serves, 0);
});
test('rejects a non-public Host before capability lookup', async () => {
  const x = setup(), res = response();
  await x.service.handler({method:'GET',url:x.claim.path,headers:{host:'127.0.0.1:9000'}},res);
  assert.equal(res.statusCode,403);
  assert.equal(x.currents,0);
  assert.equal(x.serves,0);
});
test('records serve only after exact finished response and two authority checks', async () => {
  const x = setup();
  await x.service.handler({
    method: 'GET',
    url: x.claim.path,
    headers: {host:'127.0.0.2:9000'}
  }, x.res);
  assert.equal(x.res.statusCode, 200);
  assert.equal(x.res.headers['Content-Security-Policy'], 'sandbox allow-scripts');
  assert.equal(x.res.headers['Access-Control-Allow-Credentials'], undefined);
  assert.equal(x.currents, 2);
  assert.equal(x.serves, 1);
});
test('aborted delivery creates no serve credit', async () => {
  const x = setup({
    outcome: 'close'
  });
  await x.service.handler({
    method: 'GET',
    url: x.claim.path,
    headers: {host:'127.0.0.2:9000'}
  }, x.res);
  assert.equal(x.res.statusCode, 200);
  assert.equal(x.serves, 0);
});
test('capability binds admission scene and mode and expires', () => {
  let now = 1700000000000;
  const capability = createSecureShopUploadAssetCapability({
      secret: 'x'.repeat(32),
      now: () => now,
      ttlMs: 1000
    }),
    claim = capability.mint(ids);
  assert.equal(capability.verify(claim), true);
  assert.equal(capability.verify({
    ...claim,
    sceneGeneration: 4
  }), false);
  assert.equal(capability.verify({
    ...claim,
    mode: 'fixed'
  }), false);
  assert.equal(capability.verify({
    ...claim,
    operationId: '00000005-0000-4000-8000-000000000005'
  }), false);
  now = 1700000001001;
  assert.equal(capability.verify(claim), false);
});
