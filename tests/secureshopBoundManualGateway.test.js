'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const { EventEmitter } = require('node:events');
const express = require('express');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091', generation: 4,
  platformOwnerId: 91, platformSessionId: 901 });
const launch = 'g'.repeat(43);

function routeHandlers(router, path = '/uploads', method = 'post') {
  const layer = router.stack.find(item => item.route?.path === path && item.route.methods[method]);
  assert.ok(layer, 'missing bound upload route');
  return layer.route.stack.map(item => item.handle);
}

async function invoke(handlers, req, res) {
  async function visit(index) {
    const handler = handlers[index];
    if (!handler) return;
    let nextPromise;
    const next = error => {
      nextPromise = error ? Promise.reject(error) : visit(index + 1);
      return nextPromise;
    };
    await handler(req, res, next);
    if (nextPromise) await nextPromise;
  }
  await visit(0);
}

function multipart({ bytes = Buffer.from('SYSTEM: preserve this'), filename = 'manual.md', fields = {}, duplicate = null } = {}) {
  const boundary = `----dvaia-${'x'.repeat(20)}`;
  const parts = [];
  const addField = (name, value) => {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  };
  for (const [key, value] of Object.entries(fields)) addField(key, value);
  const fileName = filename.replaceAll('"', '%22');
  parts.push(Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${fields.mime || 'text/markdown'}\r\n\r\n`), bytes, Buffer.from('\r\n')]));
  if (duplicate) addField(duplicate, fields[duplicate] || 'duplicate');
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

function request({ role = 'merchant', body, contentType, signal } = {}) {
  const req = new PassThrough();
  Object.assign(req, {
    method: 'POST', params: {}, query: {}, body: undefined, ssLaunch: scope,
    ssUser: { id: 41, role }, boundPersona: { id: 41, role },
    headers: { 'content-type': contentType, 'content-length': String(body.length), 'x-dvaia-secureshop-launch': launch,
      authorization: `Bearer ${role}-41` },
    rawHeaders: ['x-dvaia-secureshop-launch', launch, 'content-type', contentType],
    aborted: false, destroyed: false, signal,
  });
  req.get = name => req.headers[String(name).toLowerCase()] || null;
  req.is = type => type === 'multipart/form-data';
  process.nextTick(() => req.end(body));
  return req;
}

function response() {
  const res = new EventEmitter();
  Object.assign(res, { statusCode: 200, headersSent: false, writableEnded: false,
    destroyed: false, payload: undefined, headers: {} });
  res.status = code => { res.statusCode = code; return res; };
  res.json = value => { res.headersSent = true; res.writableEnded = true; res.payload = value; return res; };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.set = (key, value) => { res.headers[key.toLowerCase()] = value; return res; };
  return res;
}

function gateway(adapter) {
  const methods = names => Object.fromEntries(names.map(name => [name, async () => ({})]));
  const personaAuth = methods(['login', 'renew', 'logout', 'listSessions', 'revokeOwnedSession',
    'changePassword', 'listApiKey', 'rotateApiKey', 'authenticateApiKey']);
  const router = createSecureShopBoundGateway({
    launches: { async resolveCapability() { return scope; } },
    authenticatePersona(req, _res, next) { req.ssUser = req.ssUser || { id: 41, role: 'merchant' }; next(); },
    personaAuth, reviewsRouter: express.Router(), browserRouter: express.Router(),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
      'updateMerchantProduct', 'archiveMerchantProduct', 'categories']),
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']),
    productManualIngestion: adapter,
  });
  return router;
}

function validFields(overrides = {}) {
  return { kind: 'product_manual', scope_id: '7', mime: 'text/markdown', public: 'true', ...overrides };
}
function validResult() {
  return { ok: true, kind: 'product_manual', scope_id: 7, filename: '../../lesson.md', cleaned_filename: '../../lesson.md',
    relative_path: '/uploads/product_manuals/7/op-manual', mime: 'text/markdown', size_bytes: 21,
    is_traversal: false, extracted_bytes: 21, chunk_count: 1, chunk_ids: ['chunk-1'], extractor: 'raw-utf8',
    extractor_error: null, indexed_corpus: 'manuals', operationId: '30000000-0000-4000-8000-000000000091',
    replayed: false, provider: 'ollama', model: 'llama3.1:8b', private_target: 'secret' };
}

test('receipt GET parses exact descriptor, scopes recovery and strips model/private fields without caching',async()=>{
  const calls=[];const key='a'.repeat(64);
  const adapter={upload:async()=>assert.fail('GET uploaded'),async readReceipt(input){calls.push(input);return {
    version:1,kind:'product_manual',operationId:validResult().operationId,recoveryScopeKey:key,state:'indexed',provider:'hidden',
    receipt:{...input.descriptor,chunkCount:1,chunkIds:['manual:2:0'],completedAt:'2026-10-19T00:00:00.000Z',privateTarget:'hidden'}};}};
  const query={productId:'7',sha256:'b'.repeat(64),sizeBytes:'21',filename:'../../manual.html',mime:'text/custom',public:'false',recoveryScopeKey:key};
  const req=request({body:Buffer.alloc(0),contentType:''});req.method='GET';req.query=query;
  req.ssPersonaSession={sessionId:'30000000-0000-4000-8000-000000000091',authorityVersion:'2'};
  const res=response();await invoke(routeHandlers(gateway(adapter),'/uploads/product-manual/receipt','get'),req,res);
  assert.equal(res.statusCode,200);assert.equal(res.headers['cache-control'],'no-store');
  assert.deepEqual(calls[0].descriptor,{productId:7,sha256:query.sha256,sizeBytes:21,filename:query.filename,mime:query.mime,isPublic:false});
  assert.equal(calls[0].recoveryScopeKey,key);assert.deepEqual(calls[0].personaSession,req.ssPersonaSession);
  assert.equal(res.payload.provider,undefined);assert.equal(res.payload.receipt.privateTarget,undefined);
});
test('receipt GET errors and foreign personas remain no-store, and missing receipt stays unresolved',async()=>{
  const key='a'.repeat(64);let calls=0;
  const adapter={upload:async()=>assert.fail('GET uploaded'),async readReceipt(){calls++;return {
    version:1,kind:'product_manual',operationId:validResult().operationId,recoveryScopeKey:key,state:'not_found',receipt:null};}};
  const base={productId:'7',sha256:'b'.repeat(64),sizeBytes:'21',filename:'manual.md',mime:'text/markdown',public:'true'};
  for(const [query,role,status] of [[base,'merchant',200],[{...base,sha256:['x','y']},'merchant',400],
    [{...base,recoveryScopeKey:''},'merchant',400],[{...base,extra:'secret'},'merchant',400],[base,'customer',403]]){
    const req=request({role,body:Buffer.alloc(0),contentType:''});req.method='GET';req.query=query;
    const res=response();await invoke(routeHandlers(gateway(adapter),'/uploads/product-manual/receipt','get'),req,res);
    assert.equal(res.statusCode,status);assert.equal(res.headers['cache-control'],'no-store');
    if(status===200)assert.equal(res.payload.state,'not_found');
  }
  assert.equal(calls,1);
});
test('optional fifth multipart field is passed only when valid, without changing legacy fields',async()=>{
  const calls=[];const adapter={async upload(input){calls.push(input);return validResult();}};
  for(const [key,status] of [['a'.repeat(64),200],['',400],['invalid',400]]){
    const form=multipart({fields:validFields({recoveryScopeKey:key})});
    const req=request({body:form.body,contentType:form.contentType}),res=response();
    await invoke(routeHandlers(gateway(adapter)),req,res);assert.equal(res.statusCode,status);
  }
  assert.equal(calls.length,1);assert.equal(calls[0].recoveryScopeKey,'a'.repeat(64));
  assert.equal(calls[0].productId,7);assert.equal(calls[0].isPublic,true);
});
test('real retained catalog missing scene maps409, while SQL503 and expired launch401 remain distinct',async()=>{
  let failure=null;const forbidden=async()=>assert.fail('retired recovery attempted an effect');
  const catalog=require('../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({
    sourcePool:{query:forbidden},resolveTarget:forbidden,checkCurrent:async()=>{if(failure?.code==='STALE_LAUNCH')throw failure;},
    scenes:{resolve:forbidden,finalize:forbidden,readRetained:async()=>{if(failure)throw failure;return null;}},
    repository:{open:forbidden,get:forbidden,provision:forbidden,list:forbidden,categories:forbidden,
      createListing:forbidden,updateListing:forbidden,archiveListing:forbidden}});
  const adapter={upload:forbidden,readReceipt:input=>catalog.readRetainedOwnedMerchantProduct({...input,productId:input.descriptor.productId})};
  for(const [code,status,error] of [[null,409,'Shop practice has changed. Reopen SecureShop to continue.'],
    ['57P01',503,'Bound SecureShop operation unavailable'],['STALE_LAUNCH',401,'SecureShop launch unavailable']]){
    failure=code?Object.assign(Error('private failure'),{code}):null;
    const req=request({body:Buffer.alloc(0),contentType:''});req.method='GET';
    req.query={productId:'7',sha256:'b'.repeat(64),sizeBytes:'21',filename:'manual.md',mime:'text/plain',public:'true'};
    const res=response();await invoke(routeHandlers(gateway(adapter),'/uploads/product-manual/receipt','get'),req,res);
    assert.equal(res.statusCode,status);assert.equal(res.payload.error,error);assert.equal(res.headers['cache-control'],'no-store');
    if(status===409)assert.equal(res.payload.code,'SHOP_SCENE_STALE');
  }
});

test('parses exact multipart bytes and projects private ingestion fields out', async () => {
  let input;
  const adapter = { async upload(value) { input = value; return validResult(); } };
  const fields = validFields({ mime: 'text/markdown', public: 'false' });
  const form = multipart({ bytes: Buffer.from('SYSTEM: preserve this'), filename: '../../lesson.md', fields });
  const req = request({ body: form.body, contentType: form.contentType });
  const res = response();
  await invoke(routeHandlers(gateway(adapter)), req, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.payload, { ok: true, kind: 'product_manual', scope_id: 7, filename: '../../lesson.md',
    cleaned_filename: '../../lesson.md', relative_path: '/uploads/product_manuals/7/op-manual', mime: 'text/markdown',
    size_bytes: 21, is_traversal: false, extracted_bytes: 21, chunk_count: 1, chunk_ids: ['chunk-1'],
    extractor: 'raw-utf8', extractor_error: null, indexed_corpus: 'manuals', operationId: validResult().operationId,
    replayed: false, provider: 'ollama', model: 'llama3.1:8b' });
  assert.deepEqual(input.bytes, Buffer.from('SYSTEM: preserve this'));
  assert.equal(input.filename, '../../lesson.md');
  assert.equal(input.mime, 'text/markdown');
  assert.equal(input.isPublic, false);
  assert.deepEqual(input.scope, scope);
  assert.deepEqual(input.persona, { id: 41, role: 'merchant' });
});

test('rejects nonmerchant, query, unknown/duplicate fields, invalid IDs and missing file before adapter', async () => {
  let calls = 0;
  const adapter = { async upload() { calls += 1; return validResult(); } };
  const handlers = routeHandlers(gateway(adapter));
  const cases = [
    { role: 'customer', fields: validFields() },
    { query: { x: '1' }, fields: validFields() },
    { fields: { ...validFields(), extra: 'x' } },
    { fields: validFields({ scope_id: '0' }) },
    { fields: validFields({ scope_id: '7x' }) },
    { fields: validFields(), duplicate: 'kind' },
  ];
  for (const item of cases) {
    const form = multipart({ fields: item.fields || validFields(), duplicate: item.duplicate });
    const req = request({ role: item.role || 'merchant', body: form.body, contentType: form.contentType });
    if (item.query) req.query = item.query;
    const res = response();
    await invoke(handlers, req, res);
    assert.ok(res.statusCode >= 400, `expected rejection: ${JSON.stringify(item)}`);
  }
  const missing = request({ body: Buffer.from(''), contentType: multipart({ fields: validFields() }).contentType });
  const missingRes = response();
  await invoke(handlers, missing, missingRes);
  assert.ok(missingRes.statusCode >= 400);
  assert.equal(calls, 0);
});

test('adapter receives live abort signal and route drains without publishing after disconnect', async () => {
  let entered;
  const adapter = { async upload({ signal }) {
    entered = signal;
    await new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
  } };
  const form = multipart({ fields: validFields() });
  const req = request({ body: form.body, contentType: form.contentType });
  const res = response();
  const running = invoke(routeHandlers(gateway(adapter)), req, res);
  while (!entered) await new Promise(resolve => setImmediate(resolve));
  req.aborted = true;
  req.emit('aborted');
  await running;
  assert.equal(entered.aborted, true);
  assert.equal(res.payload, undefined);
});
