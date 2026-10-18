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

function routeHandlers(router) {
  const layer = router.stack.find(item => item.route?.path === '/uploads' && item.route.methods.post);
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
