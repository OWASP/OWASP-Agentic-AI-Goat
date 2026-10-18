'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const origin = 'http://localhost:3000';
async function setup() {
  const { createBridgeFetch } = await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  const calls = [];
  const fetch = createBridgeFetch({origin, getToken:()=> 'stored-shop-token', bridge:{request(...args){calls.push(args);return Promise.resolve(new Response('{"ok":true}',{headers:{'content-type':'application/json'}}));}}});
  return { fetch, calls };
}

test('existing JSON fetch compiles named chat operation, preserves payload and explicit teaching JWT', async () => {
  const { fetch, calls } = await setup();
  const response = await fetch('/api/secureshop/agents/customer/chat', {method:'POST', headers:{'content-type':'application/json',authorization:'Bearer learner-crafted'},body:JSON.stringify({sessionId:'demo',message:'Read ../../synthetic/secret'})});
  assert.deepEqual(await response.json(), {ok:true});
  assert.equal(calls[0][0], 'agent.customer.chat');assert.equal(calls[0][1].body.message,'Read ../../synthetic/secret');assert.equal(calls[0][2].shopBearer,'learner-crafted');
});

test('Request init overrides retain body and propagate abort signal; static routes precede params', async () => {
  const { fetch, calls } = await setup();const controller=new AbortController();
  const request=new Request(origin+'/api/secureshop/orders/summary',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer old'},body:'{}',signal:controller.signal});
  await fetch(request,{headers:{'content-type':'application/json'}});
  assert.equal(calls[0][0],'orders.summary');assert.deepEqual(calls[0][1].body,{});assert.equal(calls[0][2].shopBearer,'stored-shop-token');
  controller.abort();assert.equal(calls[0][2].signal.aborted,true);
  await fetch('/api/secureshop/products/23/reviews?limit=5');assert.equal(calls[1][1].params.id,'23');assert.equal(calls[1][1].query.limit,'5');
});

test('checkout history paths compile to closed read-only operations before order ID lookup',async()=>{
 const {fetch,calls}=await setup();
 await fetch('/api/secureshop/orders/operations');
 await fetch('/api/secureshop/orders/operations/11111111-1111-4111-8111-111111111111');
 assert.equal(calls[0][0],'orders.operations');
 assert.equal(calls[1][0],'orders.operation');
 assert.equal(calls[1][1].params.operationId,'11111111-1111-4111-8111-111111111111');
 await assert.rejects(fetch('/api/secureshop/orders/operations?ownerId=2'));
});

test('policy readiness matches the static admin GET before policy-name routes',async()=>{
 const {fetch,calls}=await setup();
 await fetch('/api/secureshop/admin/policies/readiness');
 assert.equal(calls[0][0],'admin.policies.readiness');
 await assert.rejects(fetch('/api/secureshop/admin/policies/readiness?role=admin'));
});

test('relative URLs use the injected base URI and canonical percent-bearing params round trip', async () => {
  const { createBridgeFetch } = await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  const calls=[];
  const fetch=createBridgeFetch({origin,getRequestBaseUrl:()=>origin+'/secureshop/v2/account/',bridge:{request(...args){calls.push(args);return Promise.resolve(new Response('{}',{headers:{'content-type':'application/json'}}));}}});
  await fetch('../../../api/secureshop/admin/policies/50%25%20off/render',{method:'POST',headers:{'content-type':'application/json'},body:'{"markdown":"unchanged %2F bytes"}'});
  assert.equal(calls[0][0],'admin.policies.render');
  assert.equal(calls[0][1].params.name,'50% off');
  assert.equal(calls[0][1].body.markdown,'unchanged %2F bytes');
});

test('closed adapter rejects external/platform paths, expanded headers/keys and incomplete multipart before dispatch', async () => {
  const { fetch, calls } = await setup();
  for (const [url, init] of [
    ['https://evil.example/api/secureshop/products'],['/api/auth/me'],['/api/secureshop/unknown'],
    ['/api/secureshop/products?limit=1&limit=2'],['/api/secureshop/products?platformOwnerId=7'],
    ['/api/secureshop/products',{headers:{'x-dvaia-secureshop-launch':'private'}}],
    ['/api/secureshop/products',{headers:{authorization:'Basic unsupported'}}],
    ['/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body:'{"platformOwnerId":7}'}],
    ['/api/secureshop/uploads',{method:'POST',body:new FormData()}],
  ]) await assert.rejects(fetch(url,init));
  assert.equal(calls.length,0);
});

test('oversized, malformed, non-JSON and pre-aborted bodies cannot dispatch', async () => {
  const { fetch, calls } = await setup();
  for(const body of ['', '{', JSON.stringify({sessionId:'a',message:'x'.repeat(140000)})]) await assert.rejects(fetch('/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body}));
  await assert.rejects(fetch('/api/secureshop/agents/customer/chat',{method:'POST',body:'{"sessionId":"a","message":"x"}'}));
  await assert.rejects(fetch('/api/secureshop/products',{signal:AbortSignal.abort()}),{name:'AbortError'});
  assert.equal(calls.length,0);
});

test('snapshots and validates the shop token before awaiting a streamed body', async () => {
  const { createBridgeFetch } = await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  let token='first';let release;
  const stream=new ReadableStream({start(controller){release=()=>{controller.enqueue(new TextEncoder().encode('{"sessionId":"s","message":"m"}'));controller.close();};}});
  const calls=[];
  const fetch=createBridgeFetch({origin,getToken:()=>token,bridge:{request(...args){calls.push(args);return Promise.resolve(new Response('{}',{headers:{'content-type':'application/json'}}));}}});
  const pending=fetch(new Request(origin+'/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body:stream,duplex:'half'}));
  token='second';release();await pending;
  assert.equal(calls[0][2].shopBearer,'first');

  for (const bad of ['', 7, 'x'.repeat(8193), 'line\nbreak']) {
    const rejected=createBridgeFetch({origin,getToken:()=>bad,bridge:{request(){throw new Error('must not dispatch');}}});
    await assert.rejects(rejected('/api/secureshop/products'));
  }
});

test('abort while reading a stalled Request body cancels the stream and does not dispatch', async () => {
  const { fetch, calls } = await setup();const controller=new AbortController();let cancelled=false;
  const body=new ReadableStream({cancel(){cancelled=true;}});
  const pending=fetch(new Request(origin+'/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body,duplex:'half',signal:controller.signal}));
  controller.abort();await assert.rejects(pending,{name:'AbortError'});assert.equal(cancelled,true);assert.equal(calls.length,0);
});

test('abort after the final body chunk still fences bridge dispatch', async () => {
  const { createBridgeFetch } = await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  const controller=new AbortController();let calls=0;
  const body=new ReadableStream({start(stream){stream.enqueue(new TextEncoder().encode('{"sessionId":"s","message":"m"}'));stream.close();queueMicrotask(()=>controller.abort());}});
  const fetch=createBridgeFetch({origin,bridge:{request(){calls++;return Promise.resolve(new Response('{}'));}}});
  await assert.rejects(fetch(new Request(origin+'/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body,duplex:'half',signal:controller.signal})),{name:'AbortError'});
  assert.equal(calls,0);
});

test('bound learning panels compile through the real closed bridge with exact input', async () => {
  const { fetch, calls } = await setup();
  const cases = [
    ['controlled-ssrf/readiness', 'lab.ssrf.readiness'],
    ['controlled-ssrf/run', 'lab.ssrf.run', {resource:'public',request_id:'request-1'}],
    ['persona-inbox/readiness', 'lab.personaInbox.readiness'],
    ['persona-inbox/read', 'lab.personaInbox.read', {message_id:1,request_id:'request-2'}],
    ['persona-inbox/enforce', 'lab.personaInbox.enforce', {}],
    ['mcp-trust/readiness', 'lab.mcpTrust.readiness'],
    ['mcp-trust/discover', 'lab.mcpTrust.discover', {scenario:'rogue'}],
    ['mcp-trust/rotate', 'lab.mcpTrust.rotate', {}],
    ['mcp-trust/run', 'lab.mcpTrust.run', {scenario:'rug',request_id:'request-3'}],
  ];
  for (const [path, name, body] of cases) {
    await fetch(`/api/secureshop/v2/${path}`, body === undefined ? undefined : {
      method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),
    });
    const call = calls.at(-1);
    assert.equal(call[0], name);
    if (body !== undefined) assert.deepEqual(call[1].body, body);
    assert.equal(call[2].shopBearer, 'stored-shop-token');
    for (const field of ['url','platformOwnerId','generation']) {
      const before = calls.length;
      await assert.rejects(fetch(`/api/secureshop/v2/${path}${body === undefined ? `?${field}=override` : ''}`,
        body === undefined ? undefined : {method:'POST',headers:{'content-type':'application/json'},
          body:JSON.stringify({...body,[field]:'override'})}));
      assert.equal(calls.length, before);
    }
  }
});

test('controlled SSRF bridge operation reaches the authenticated mounted route without accepting client scope', async t => {
  const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000091',
    scenarioId: '20000000-0000-4000-8000-000000000091', generation: 4,
    platformOwnerId: 31, platformSessionId: 41 });
  const persona = Object.freeze({ id: 51, role: 'customer' });
  const seen = [];
  const feature = Object.freeze({ ready: true,
    availability: Object.freeze({ async read() { return { registered: true, visible: true, enabled: true }; } }),
    application: Object.freeze({ async run(input) {
      seen.push(input);
      return Object.freeze({ resourceKind: input.resourceKind, response: 'owned policy observation',
        stopReason: 'end_turn', replayed: false });
    } }),
  });
  const launches = Object.freeze({ async resolveCapability(value) {
    assert.equal(value, 'b'.repeat(43)); return scope;
  } });
  const authenticatePersona = (req, res, next) => {
    if (req.get('authorization') !== `Bearer ${'c'.repeat(43)}`) return res.sendStatus(401);
    req.ssUser = persona; next();
  };
  const router = require('../server/routes/secureshop/boundSsrf').createBoundSsrfRouter({
    launches, authenticatePersona, feature,
  });
  const app = express(); app.use(express.json()); app.use('/api/secureshop', router);
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => server.close(() => resolve())));
  const mountedOrigin = `http://127.0.0.1:${server.address().port}`;
  const { createBridgeFetch } = await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  const { compileBridgeOperation } = await import('../client/src/pages/secureshop/bridge/compiler.mjs');
  const networkFetch = globalThis.fetch.bind(globalThis);
  const bridge = Object.freeze({ async request(name, input, { shopBearer, signal }) {
    const operation = compileBridgeOperation(name, input);
    return networkFetch(`${mountedOrigin}${operation.path}`, { method: operation.method, signal,
      headers: { accept: 'application/json', 'x-dvaia-secureshop-launch': 'b'.repeat(43),
        ...(shopBearer ? { authorization: `Bearer ${shopBearer}` } : {}),
        ...(operation.body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(operation.body === undefined ? {} : { body: JSON.stringify(operation.body) }) });
  } });
  const bridgeFetch = createBridgeFetch({ bridge, origin: mountedOrigin, getToken: () => 'c'.repeat(43) });
  assert.deepEqual(await (await bridgeFetch('/api/secureshop/v2/controlled-ssrf/readiness')).json(), { ready: true });
  const requestId = '30000000-0000-4000-8000-000000000091';
  const response = await bridgeFetch('/api/secureshop/v2/controlled-ssrf/run', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ resource: 'private-policy', request_id: requestId }) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { resourceKind: 'private-policy', response: 'owned policy observation',
    stopReason: 'end_turn', replayed: false });
  assert.equal(seen.length, 1);
  assert.deepEqual({ scope: seen[0].scope, persona: seen[0].persona, requestId: seen[0].requestId,
    resourceKind: seen[0].resourceKind }, { scope, persona, requestId, resourceKind: 'private-policy' });
  assert.equal(Object.hasOwn(seen[0], 'platformOwnerId'), false);
});

test('owned user administration transports exact operation revision and receipt lookup without authority fields', async () => {
  const { fetch, calls } = await setup();
  const operationId='10000000-0000-4000-8000-000000000001';
  const body={role:'merchant',operationId,expectedVersion:'2'};
  await fetch('/api/secureshop/admin/users/4/role',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  assert.equal(calls[0][0],'admin.users.setRole');assert.deepEqual(calls[0][1].body,body);
  await fetch('/api/secureshop/admin/users/operations/'+operationId);
  assert.equal(calls[1][0],'admin.users.operation');assert.equal(calls[1][1].params.operationId,operationId);
  await assert.rejects(fetch('/api/secureshop/admin/users/4/role',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,platformOwnerId:2})}));
  assert.equal(calls.length,2);
});
