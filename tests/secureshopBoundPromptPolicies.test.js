'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { createBoundPromptPoliciesRouter } = require('../server/routes/secureshop/boundPromptPolicies');

const ID = '018f5b4e-5c8a-4b9c-8d0e-1f2a3b4c5d6e';
const SCOPE = { launchId: '018f5b4e-5c8a-4b9c-8d0e-1f2a3b4c5d6e', scenarioId: '118f5b4e-5c8a-4b9c-8d0e-1f2a3b4c5d6e', generation: '1', platformOwnerId: 7, platformSessionId: 9 };
const SESSION = { sessionId: ID, authorityVersion: '2' };

function appFor(service, state = {}, supportedTaskTargets = []) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.ssLaunch = SCOPE; req.ssUser = state.user || { id: 3, role: 'admin' }; req.ssPersonaSession = state.session === false ? null : SESSION; next(); });
  app.use('/api/secureshop', createBoundPromptPoliciesRouter({ service, authenticatePersona: (_req, _res, next) => next(), supportedTaskTargets }));
  return app;
}

function request(app, method, path, body) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const data = body === undefined ? null : JSON.stringify(body);
      const req = http.request({ host: address.address, port: address.port, path, method, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, res => {
        let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
        res.on('end', () => { server.close(); resolve({ status: res.statusCode, headers: res.headers, body: text ? JSON.parse(text) : null }); });
      });
      req.on('error', error => { server.close(); reject(error); });
      if (data) req.write(data); req.end();
    });
    server.on('error', reject);
  });
}

function serviceBase(overrides = {}) {
  return {
    async list() { return { version: '2', policies: [{ name: 'p', markdown: 'raw', targets: ['admin'], rendered: 'rendered' }] }; },
    async render(input) { return { receipt: { version: '2', operationId: input.request.operationId, renderResult: { rendered: 'ok' } } }; },
    async remove() { return { operationId: ID, deleted: true }; },
    async operation() { return { operationId: ID, done: true }; },
    ...overrides,
  };
}

test('list maps repository policies to the existing UI projection and disables caching', async () => {
  const result = await request(appFor(serviceBase()), 'GET', '/api/secureshop/admin/policies');
  assert.equal(result.status, 200);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(Object.hasOwn(result.body, 'supported_task_targets'), false);
  assert.deepEqual(result.body.policies[0], { name: 'p', markdown_source: 'raw', markdown_rendered: 'rendered', injected_into_json: '["admin"]', supported_targets: ['customer', 'merchant', 'admin'] });
});

test('opt-in task targets are advertised and sent as an exact v2 mutation while roles remain v1', async () => {
  const seen = [];
  const service = serviceBase({
    async list() { return { version: '2', policies: [{ name: 'p', markdown: 'raw', targets: ['summarizer', 'admin'], rendered: 'rendered' }] }; },
    async render(input) { seen.push(input.request); return { state: 'pending', operationId: input.request.operationId }; },
  });
  const app = appFor(service, {}, ['summarizer', 'review-moderator']);
  let result = await request(app, 'GET', '/api/secureshop/admin/policies');
  assert.deepEqual(result.body.supported_targets, ['customer', 'merchant', 'admin']);
  assert.deepEqual(result.body.supported_task_targets, ['review-moderator', 'summarizer']);
  assert.equal(result.body.policies[0].injected_into_json, '["admin","summarizer"]');
  assert.deepEqual(result.body.policies[0].supported_task_targets, ['review-moderator', 'summarizer']);
  result = await request(app, 'POST', '/api/secureshop/admin/policies', { name: 'p', markdown: 'raw', injected_into: ['summarizer', 'admin'], operationId: ID, expectedVersion: '1' });
  assert.equal(result.status, 202);
  assert.deepEqual(seen[0], { contractVersion: 2, operationId: ID, name: 'p', markdown: 'raw', targets: ['admin', 'summarizer'] });
  await request(app, 'POST', '/api/secureshop/admin/policies', { name: 'p', markdown: 'raw', injected_into: ['admin'], operationId: ID, expectedVersion: '1' });
  assert.deepEqual(seen[1], { operationId: ID, name: 'p', markdown: 'raw', targets: ['admin'] });
});

test('task target configuration is closed and unadvertised targets fail before effects', async () => {
  for (const supportedTaskTargets of [['summarizer', 'summarizer'], ['analytics'], ['price-advisor'], 'summarizer']) {
    assert.throws(() => appFor(serviceBase(), {}, supportedTaskTargets), /task targets invalid/);
  }
  let calls = 0;
  const service = serviceBase({ render: async () => { calls += 1; return {}; } });
  const result = await request(appFor(service, {}, ['summarizer']), 'POST', '/api/secureshop/admin/policies', {
    name: 'p', markdown: 'raw', injected_into: ['review-moderator'], operationId: ID, expectedVersion: '1',
  });
  assert.equal(result.status, 400);
  assert.equal(calls, 0);
  const retained = await request(appFor(serviceBase({ async list() {
    return { version: '2', policies: [{ name: 'p', markdown: 'raw', targets: ['summarizer'], rendered: 'rendered' }] };
  } })), 'GET', '/api/secureshop/admin/policies');
  assert.equal(retained.status, 200);
  assert.equal(retained.body.policies[0].injected_into_json, '["summarizer"]');
  assert.equal(Object.hasOwn(retained.body, 'supported_task_targets'), false);
});

test('historical known targets remain losslessly readable and deletable without expanding configured writes', async () => {
  const historical = ['analytics', 'inventory', 'listing', 'review-moderator', 'summarizer'];
  let renders = 0, deletes = 0;
  const service = serviceBase({ async list() { return { version: '2', policies: historical.map(name => ({
    name, markdown: '{{ retained source }}', targets: [name], rendered: 'retained rendered output',
  })) }; }, async render() { renders++; throw Error('not reachable'); },
  async remove(input) { deletes++; return { operationId: input.operationId, deleted: true }; } });
  const app = appFor(service);
  const read = await request(app, 'GET', '/api/secureshop/admin/policies');
  assert.equal(read.status, 200); assert.equal(read.headers['cache-control'], 'no-store');
  assert.equal(Object.hasOwn(read.body, 'supported_task_targets'), false);
  assert.deepEqual(read.body.policies.map(p => [p.name, p.markdown_source, JSON.parse(p.injected_into_json)]),
    historical.map(name => [name, '{{ retained source }}', [name]]));
  for (const target of historical) {
    const body = { markdown: '{{ retained source }}', injected_into: [target], operationId: ID, expectedVersion: '2' };
    for (const [path, input] of [['/api/secureshop/admin/policies', { ...body, name: target }],
      [`/api/secureshop/admin/policies/${target}`, body], [`/api/secureshop/admin/policies/${target}/render`, body]]) {
      assert.equal((await request(app, 'POST', path, input)).status, 400);
    }
  }
  assert.equal(renders, 0);
  assert.equal((await request(app, 'DELETE', '/api/secureshop/admin/policies/analytics',
    { operationId: ID, expectedVersion: '2' })).status, 200);
  assert.equal(deletes, 1);
});

test('read projection still rejects unknown, duplicate and malformed retained targets', async () => {
  for (const targets of [['unknown-agent'], ['admin', 'admin'], [1], [], 'admin']) {
    const result = await request(appFor(serviceBase({ async list() {
      return { version: '2', policies: [{ name: 'p', markdown: 'raw', targets, rendered: 'rendered' }] };
    } })), 'GET', '/api/secureshop/admin/policies');
    assert.equal(result.status, 503);
  }
});

test('upsert and preview validate closed bodies and return completed or pending contracts', async () => {
  let seen;
  const service = serviceBase({ render: async input => { seen = input; return { state: 'pending', operationId: input.request.operationId }; } });
  const body = { name: 'p', markdown: 'raw', injected_into: ['admin'], operationId: ID, expectedVersion: '1' };
  let result = await request(appFor(service), 'POST', '/api/secureshop/admin/policies', body);
  assert.equal(result.status, 202); assert.deepEqual(result.body, { ok: false, state: 'pending', operationId: ID });
  assert.equal(seen.action, 'upsert'); assert.deepEqual(seen.request.targets, ['admin']);
  result = await request(appFor(serviceBase()), 'POST', '/api/secureshop/admin/policies/p/render', { markdown: 'raw', injected_into: ['admin'], operationId: ID, expectedVersion: '1' });
  assert.equal(result.status, 200); assert.equal(result.body.rendered, 'ok'); assert.equal(result.body.rendered_length, 2);
  result = await request(appFor(serviceBase()), 'POST', '/api/secureshop/admin/policies', { ...body, extra: true });
  assert.equal(result.status, 400);
});

test('delete and operation read use exact IDs and no query fields', async () => {
  const service = serviceBase();
  let result = await request(appFor(service), 'DELETE', '/api/secureshop/admin/policies/p', { operationId: ID, expectedVersion: '2' });
  assert.equal(result.status, 200); assert.equal(result.body.ok, true);
  result = await request(appFor(service), 'GET', `/api/secureshop/admin/policies/operations/${ID}`);
  assert.equal(result.status, 200); assert.equal(result.body.receipt.operationId, ID);
  result = await request(appFor(service), 'GET', `/api/secureshop/admin/policies/operations/${ID}?x=1`);
  assert.equal(result.status, 400);
  result = await request(appFor(serviceBase({ operation: async () => ({ state: 'pending', operationId: ID }) })), 'GET', `/api/secureshop/admin/policies/operations/${ID}`);
  assert.equal(result.status, 202);
  assert.deepEqual(result.body, { ok: false, state: 'pending', operationId: ID });
});

test('authentication, role, conflict, quota, not-found and uncertainty statuses are explicit', async () => {
  let result = await request(appFor(serviceBase(), { session: false }), 'GET', '/api/secureshop/admin/policies');
  assert.equal(result.status, 401);
  result = await request(appFor(serviceBase(), { user: { id: 4, role: 'customer' } }), 'GET', '/api/secureshop/admin/policies');
  assert.equal(result.status, 403);
  for (const [code, status] of [['REVISION_CONFLICT', 409], ['POLICY_QUOTA_EXCEEDED', 429], ['POLICY_NOT_FOUND', 404], ['POLICY_OUTCOME_UNCERTAIN', 503], ['POLICY_RENDER_BUSY', 503]]) {
    const service = serviceBase({ render: async () => { throw Object.assign(new Error('secret details'), { code }); } });
    result = await request(appFor(service), 'POST', '/api/secureshop/admin/policies', { name: 'p', markdown: 'x', injected_into: ['admin'], operationId: ID, expectedVersion: '1' });
    assert.equal(result.status, status); assert.equal(result.body.error.includes('secret'), false);
    if ([409, 429, 503].includes(status)) assert.equal(result.body.code, code);
    if (code === 'POLICY_RENDER_BUSY') assert.equal(result.headers['retry-after'], '1');
  }
});

test('rejects unsupported targets, invalid versions and malformed operation IDs before service effects', async () => {
  let calls = 0;
  const service = serviceBase({ render: async () => { calls += 1; return {}; } });
  for (const body of [
    { name: 'p', markdown: 'x', injected_into: ['summarizer'], operationId: ID, expectedVersion: '1' },
    { name: 'p', markdown: 'x', injected_into: ['admin'], operationId: ID, expectedVersion: '0' },
    { name: 'p', markdown: 'x', injected_into: ['admin'], operationId: 'bad', expectedVersion: '1' },
  ]) {
    const result = await request(appFor(service), 'POST', '/api/secureshop/admin/policies', body);
    assert.equal(result.status, 400);
  }
  assert.equal(calls, 0);
});

test('lost browser connection does not cancel durable render; readback recovers one publication', async t => {
  const { createBoundPromptPolicyService } = require('../server/services/secureshopBoundPromptPolicyService');
  const { requestDigest } = require('../server/services/secureshopPromptPolicyContract');
  const { createHash } = require('node:crypto');
  let started, release, rendered = 0, published = 0, stored;
  const admitted = new Promise(resolve => { started = resolve; });
  const repository = {
    async list() { return { version: '1', policies: [] }; }, async remove() {},
    async operation() { return stored || { state: 'pending', operationId: ID }; },
    async beginRender(input) { return { state: 'admitted', operationId: ID, requestSha256: requestDigest(input.request) }; },
    async publish(input) { published++; stored = { operationId: ID, version: '2', requestSha256: requestDigest(input.request), renderResult: input.renderResult }; return stored; },
  };
  const service = createBoundPromptPolicyService({ repository, renderer: { async render(input, { signal }) {
    rendered++; assert.equal(signal, undefined); started(); await new Promise(resolve => { release = resolve; });
    return { version: 1, operationId: ID, requestSha256: requestDigest(input), isolation: 'bwrap-policy-template-v1', rendered: 'done', renderedSha256: createHash('sha256').update('done').digest('hex'), exitCode: 0, timedOut: false, truncated: false, drained: true };
  } } });
  const server = appFor(service).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { release?.(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const body = JSON.stringify({ name: 'p', markdown: 'source', injected_into: ['admin'], operationId: ID, expectedVersion: '1' });
  const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/api/secureshop/admin/policies', method: 'POST', headers: { 'content-type': 'application/json' } });
  req.on('error', () => {}); req.end(body); await admitted;
  req.destroy(); release();
  for (let i = 0; !stored && i < 20; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(published, 1); assert.equal(rendered, 1);
  const recovered = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/admin/policies/operations/${ID}`);
  assert.equal(recovered.status, 200); assert.deepEqual((await recovered.json()).receipt, stored);
});
