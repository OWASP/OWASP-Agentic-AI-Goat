'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const express = require('express');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091', generation: 4,
  platformOwnerId: 91, platformSessionId: 901 });

function gateway(productAssist) {
  const methods = names => Object.fromEntries(names.map(name => [name, async () => ({})]));
  const personaAuth = methods(['login', 'renew', 'logout', 'listSessions', 'revokeOwnedSession',
    'changePassword', 'listApiKey', 'rotateApiKey', 'authenticateApiKey']);
  return createSecureShopBoundGateway({
    launches: { async resolveCapability() { return scope; } },
    authenticatePersona(req, res, next) {
      if (!req.authUser) return res.status(401).json({ error: 'Shop authentication required' });
      req.ssUser = req.authUser;
      return next();
    },
    personaAuth,
    reviewsRouter: express.Router(),
    browserRouter: express.Router(),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
      'updateMerchantProduct', 'archiveMerchantProduct', 'categories']),
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress',
      'deleteAddress']),
    productAssist,
  });
}

function routeHandlers(router, method, path) {
  const layer = router.stack.find(item => item.route?.path === path && item.route.methods[method]);
  assert.ok(layer, `missing ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map(item => item.handle);
}

async function invoke(handlers, req, res) {
  async function at(index) {
    const handler = handlers[index];
    if (!handler) return;
    let downstream;
    const next = error => {
      downstream = error ? Promise.reject(error) : at(index + 1);
      return downstream;
    };
    await handler(req, res, next);
    if (downstream) await downstream;
  }
  await at(0);
}

function request({ method = 'GET', id = '7', query = {}, body, role = 'customer', signal } = {}) {
  const req = new EventEmitter();
  Object.assign(req, { method, params: { id }, query, body, ssLaunch: scope,
    authUser: role ? { id: 41, role } : null, aborted: false, destroyed: false,
    rawHeaders: [], signal });
  req.get = () => null;
  req.is = type => type === 'application/json';
  return req;
}

function response() {
  const res = new EventEmitter();
  Object.assign(res, { statusCode: 200, headersSent: false, writableEnded: false,
    destroyed: false, payload: undefined });
  res.status = code => { res.statusCode = code; return res; };
  res.json = value => {
    assert.equal(res.destroyed, false, 'attempted to publish after client disconnect');
    res.headersSent = true;
    res.writableEnded = true;
    res.payload = structuredClone(value);
    return res;
  };
  res.set = () => res;
  return res;
}

const summary = Object.freeze({ product_id: 7, name: 'Trail mug', price: '12.50', category: 'Home',
  stock_quantity: 3, description: 'Raw product text',
  description_html: '<img src=x onerror=teachingSink()>', summary: 'Actual model summary.',
  provider: 'ollama', model: 'llama3.1:8b', private_binding: 'omit' });
const similar = Object.freeze({ results: [{ id: 8, name: 'Related', price: 9, category: 'Home',
  image_url: '/owned.png', private_binding: 'omit' }], count: 1, mode: 'manuals',
  seed: { id: 7, name: 'Trail mug', private_binding: 'omit' },
  retrieved_context: [{ text: 'raw target-owned teaching context', score: 0.9 }],
  recommendation: 'Exact model recommendation.',
  provider: 'ollama', model: 'llama3.1:8b', private_binding: 'omit' });

test('bound product question accepts only the selected product and exact owned conversation DTO',async()=>{
 const {randomUUID}=require('node:crypto'),sessionId=randomUUID(),requestId=randomUUID(),calls=[];
 const router=gateway({summary:async()=>summary,similar:async()=>similar,async question(input){calls.push(input);return {product_id:7,answer:'Catalog answer',sessionId,requestId,provider:'ollama',model:'configured',private_binding:'omit'};}});
 const handlers=routeHandlers(router,'post','/products/:id/question');
 const req=request({method:'POST',body:{message:'Does this mug have a lid?',sessionId,requestId}}),res=response();
 await invoke(handlers,req,res);assert.equal(res.statusCode,200);assert.equal(res.payload.requestId,requestId);assert.equal(res.payload.private_binding,undefined);assert.equal(calls[0].productId,7);assert.deepEqual(calls[0].scope,scope);
 for(const body of [{message:'question',mode:'fixed'},{message:'question',modeCapability:{}},{message:'question',sessionId:'foreign'}, {message:'',requestId}]){
  const denied=response();await invoke(handlers,request({method:'POST',body}),denied);assert.equal(denied.statusCode,400);
 }
 assert.equal(calls.length,1);
});

test('mounted product routes pass a live signal and publish only bounded Product UI fields', async () => {
  const calls = [];
  const router = gateway({
    async summary(input) { calls.push(['summary', input]); return summary; },
    async similar(input) { calls.push(['similar', input]); return similar; },
  });
  const summaryReq = request({ method: 'POST', body: undefined });
  const summaryRes = response();
  await invoke(routeHandlers(router, 'post', '/products/:id/summary'), summaryReq, summaryRes);
  assert.equal(summaryRes.statusCode, 200);
  assert.deepEqual(summaryRes.payload, { product_id: 7, name: 'Trail mug', price: '12.50',
    category: 'Home', stock_quantity: 3, description: 'Raw product text',
    description_html: '<img src=x onerror=teachingSink()>', summary: 'Actual model summary.',
    provider: 'ollama', model: 'llama3.1:8b' });
  assert.equal(calls[0][1].scope, scope);
  assert.deepEqual(calls[0][1].persona, { id: 41, role: 'customer' });
  assert.equal(calls[0][1].signal instanceof AbortSignal, true);
  assert.equal(summaryReq.listenerCount('aborted'), 0);
  assert.equal(summaryRes.listenerCount('close'), 0);

  const similarReq = request();
  const similarRes = response();
  await invoke(routeHandlers(router, 'get', '/products/:id/similar'), similarReq, similarRes);
  assert.deepEqual(similarRes.payload, { results: [{ id: 8, name: 'Related', price: 9,
    category: 'Home', image_url: '/owned.png' }], count: 1, mode: 'manuals',
  seed: { id: 7, name: 'Trail mug' },
  retrieved_context: [{ text: 'raw target-owned teaching context', score: 0.9 }],
  recommendation: 'Exact model recommendation.',
  provider: 'ollama', model: 'llama3.1:8b' });
  assert.equal(similarReq.listenerCount('aborted'), 0);
  assert.equal(similarRes.listenerCount('close'), 0);
});

test('request abort, premature response close and inherited abort cancel work without publishing', async () => {
  let entered;
  const waitForEntry = () => new Promise(resolve => { entered = resolve; });
  let enteredPromise = waitForEntry();
  const pending = ({ signal }) => new Promise((resolve, reject) => {
    entered(signal);
    signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
  const router = gateway({ summary: pending, similar: pending });
  for (const kind of ['request', 'response', 'inherited']) {
    const inherited = kind === 'inherited' ? new AbortController() : null;
    const req = request({ method: kind === 'request' ? 'POST' : 'GET',
      signal: inherited?.signal });
    const res = response();
    const handlers = routeHandlers(router, kind === 'request' ? 'post' : 'get',
      kind === 'request' ? '/products/:id/summary' : '/products/:id/similar');
    const running = invoke(handlers, req, res);
    const forwarded = await enteredPromise;
    assert.equal(forwarded.aborted, false);
    if (kind === 'request') { req.aborted = true; req.emit('aborted'); }
    if (kind === 'response') { res.destroyed = true; res.emit('close'); }
    if (kind === 'inherited') inherited.abort(new DOMException('upstream cancelled', 'AbortError'));
    await running;
    assert.equal(forwarded.aborted, true);
    assert.equal(res.payload, undefined);
    assert.equal(req.listenerCount('aborted'), 0);
    assert.equal(res.listenerCount('close'), 0);
    enteredPromise = waitForEntry();
  }
});

test('product routes enforce customer, IDs, query and summary body before model work', async () => {
  let calls = 0;
  const router = gateway({ async summary() { calls += 1; return summary; },
    async similar() { calls += 1; return similar; } });
  const cases = [
    ['post', '/products/:id/summary', request({ method: 'POST', role: null }), 401],
    ['post', '/products/:id/summary', request({ method: 'POST', role: 'merchant' }), 403],
    ['post', '/products/:id/summary', request({ method: 'POST', id: '0' }), 400],
    ['post', '/products/:id/summary', request({ method: 'POST', query: { extra: '1' } }), 400],
    ['post', '/products/:id/summary', request({ method: 'POST', body: { extra: true } }), 400],
    ['get', '/products/:id/similar', request({ id: '7x' }), 400],
    ['get', '/products/:id/similar', request({ query: { extra: '1' } }), 400],
  ];
  for (const [method, path, req, expected] of cases) {
    const res = response();
    await invoke(routeHandlers(router, method, path), req, res);
    assert.equal(res.statusCode, expected);
  }
  assert.equal(calls, 0);
});

test('product adapter not-found errors map to 404 without changing shared gateway errors', async () => {
  const notFound = async () => { throw Object.assign(new Error('absent'), { code: 'NOT_FOUND' }); };
  const router = gateway({ summary: notFound, similar: notFound });
  for (const [method, path] of [['post', '/products/:id/summary'], ['get', '/products/:id/similar']]) {
    const req = request({ method: method.toUpperCase() });
    const res = response();
    await invoke(routeHandlers(router, method, path), req, res);
    assert.equal(res.statusCode, 404);
    assert.deepEqual(res.payload, { error: 'not found' });
  }
});

test('related products retain truthful corpus modes and reject unsupported modes', async () => {
  for (const mode of ['products', 'manuals', 'mixed', 'invented']) {
    const router = gateway({ async summary() { return summary; },
      async similar() { return { ...similar, mode }; } });
    const res = response();
    await invoke(routeHandlers(router, 'get', '/products/:id/similar'), request(), res);
    if (mode === 'invented') assert.notEqual(res.statusCode, 200);
    else { assert.equal(res.statusCode, 200); assert.equal(res.payload.mode, mode); }
  }
});
