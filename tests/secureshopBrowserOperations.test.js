'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const MODULE_URL = new URL('../client/src/pages/secureshop/bridge/operations.mjs', `file://${__filename}`);

async function registry() {
  return import(MODULE_URL.href);
}

test('compiles fixed JSON operations while preserving learner-controlled shop values', async () => {
  const { compileOperation } = await registry();
  const payload = '<svg onload="shopToken()">& + %2F';
  const compiled = compileOperation('catalog.product.reviews.create', {
    params: { id: 17 },
    body: { author_id: 999, body: payload, rating: 1 },
  });

  assert.deepEqual(compiled, {
    path: '/api/secureshop/products/17/reviews',
    method: 'POST',
    responseKind: 'json',
    body: { author_id: 999, body: payload, rating: 1 },
  });
  assert.ok(Object.isFrozen(compiled));
  assert.ok(Object.isFrozen(compiled.body));
});

test('uses fixed query keys and URL encoding without normalizing learner values', async () => {
  const { compileOperation } = await registry();
  const url = 'http://127.0.0.1:8080/a?x=1&next=../secret';
  const compiled = compileOperation('merchant.pricing.compare', {
    query: { product_id: '2', url },
  });
  assert.equal(
    compiled.path,
    `/api/secureshop/merchant/pricing/compare?product_id=2&url=${encodeURIComponent(url)}`,
  );
  assert.equal(compiled.method, 'POST');
  assert.equal(compiled.body, undefined);
});

test('fixes role-specific agent paths and marks chat as SSE', async () => {
  const { compileOperation } = await registry();
  assert.deepEqual(compileOperation('agent.merchant.chat', {
    body: { sessionId: 'session-1', message: 'refund order 4' },
  }), {
    path: '/api/secureshop/agents/merchant/chat',
    method: 'POST',
    responseKind: 'sse',
    body: { sessionId: 'session-1', message: 'refund order 4' },
  });
  assert.throws(
    () => compileOperation('agent.chat', { params: { role: 'admin' } }),
    /unknown operation/,
  );
});

test('admin assistant admits only closed user review intents and source-bound confirmation', async () => {
  const { compileOperation } = await registry();
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  const proposalId = '33333333-3333-5333-8333-333333333333';
  const choiceId = '44444444-4444-4444-8444-444444444444';
  const chat = (selection, message = 'Documented account abuse') => compileOperation('agent.admin.assistant.chat', {
    body: { sessionId, requestId, message, selection },
  });
  assert.deepEqual(chat({ choiceId, intent: 'user_role', newRole: 'merchant' }).body.selection,
    { choiceId, intent: 'user_role', newRole: 'merchant' });
  assert.deepEqual(chat({ choiceId, intent: 'user_ban' }).body.selection,
    { choiceId, intent: 'user_ban' });
  assert.deepEqual(chat({ choiceId, intent: 'user_password_reset' }, 'Review a password reset for this user.')
    .body.selection, { choiceId, intent: 'user_password_reset' });
  for (const intent of ['policy_detail', 'policy_edit', 'policy_preview', 'policy_delete']) {
    assert.deepEqual(chat({ choiceId, intent }, 'Review this policy').body.selection, { choiceId, intent });
  }
  assert.throws(() => chat({ choiceId, intent: 'policy_edit', markdown: 'forged' }),
    /body.selection|role choice intent invalid/);
  assert.throws(() => compileOperation('agent.merchant.assistant.chat', {
    body: { sessionId, requestId, message: 'wrong role', selection: { choiceId, intent: 'policy_delete' } },
  }), /role choice intent invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_password_reset', targetId: 7 }),
    /body.selection|role choice intent invalid/);
  assert.throws(() => compileOperation('agent.merchant.assistant.chat', {
    body: { sessionId, requestId, message: 'wrong role',
      selection: { choiceId, intent: 'user_password_reset' } },
  }), /role choice intent invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_role' }), /role choice intent invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_role', newRole: 'banned' }), /role choice intent invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_ban', reason: 'forged' }), /role choice intent invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_ban' }, ' '), /admin ban reason invalid/);
  assert.throws(() => chat({ choiceId, intent: 'user_ban' }, 'x'.repeat(1025)), /admin ban reason invalid/);
  assert.throws(() => compileOperation('agent.merchant.assistant.chat', {
    body: { sessionId, requestId, message: 'wrong role', selection: { choiceId, intent: 'user_ban' } },
  }), /role choice intent invalid/);
  assert.deepEqual(compileOperation('agent.admin.assistant.userConfirm', {
    body: { sessionId, requestId, proposalId },
  }), { path: '/api/secureshop/agents/admin/assistant/user/confirm', method: 'POST',
    responseKind: 'json', body: { sessionId, requestId, proposalId } });
  assert.throws(() => compileOperation('agent.admin.assistant.userConfirm', {
    body: { sessionId, requestId, proposalId, targetId: 7 },
  }), /body contains unknown key/);
  assert.deepEqual(compileOperation('agent.admin.assistant.policyConfirm', {
    body: { sessionId, requestId, proposalId },
  }), { path: '/api/secureshop/agents/admin/assistant/policies/confirm', method: 'POST',
    responseKind: 'json', body: { sessionId, requestId, proposalId } });
  assert.throws(() => compileOperation('agent.admin.assistant.policyConfirm', {
    body: { sessionId, requestId, proposalId, markdown: 'not reviewed' },
  }), /body contains unknown key/);
});

test('refund request reference is compiled only into fixed customer chat and readback paths', async () => {
  const { compileOperation } = await registry();
  const sessionId = '91000000-0000-4000-8000-000000000011';
  const requestId = '92000000-0000-4000-8000-000000000011';
  assert.deepEqual(compileOperation('agent.customer.refund.chat', {
    body: { sessionId, requestId, message: 'Please refund order 1. Reason: duplicate charge' },
  }), { path: '/api/secureshop/agents/customer/refund/chat', method: 'POST', responseKind: 'sse',
    body: { sessionId, requestId, message: 'Please refund order 1. Reason: duplicate charge' } });
  assert.deepEqual(compileOperation('agent.customer.refund.operation', { params: { sessionId, requestId } }),
    { path: `/api/secureshop/agents/customer/refund/operations/${sessionId}/${requestId}`,
      method: 'GET', responseKind: 'json' });
});

test('rejects URL, header, unknown query, body, and nested patch expansion', async () => {
  const { compileOperation } = await registry();
  assert.throws(() => compileOperation('cart.get', { url: '/api/auth' }), /input envelope contains unknown key/);
  assert.throws(() => compileOperation('cart.get', { headers: { Authorization: 'platform-secret' } }), /input envelope contains unknown key/);
  assert.throws(() => compileOperation('cart.get', { query: { user_id: 9, next: '/api/auth' } }), /query contains unknown key/);
  assert.throws(() => compileOperation('cart.add', {
    body: { user_id: 9, product_id: 2, quantity: 1, platformOwnerId: 10 },
  }), /body contains unknown key/);
  assert.throws(() => compileOperation('merchant.products.update', {
    params: { id: 1 },
    body: { patch: { price: 2, platform_owner_id: 10 } },
  }), /body\.patch contains unknown key/);
});

test('rejects literal and encoded path escapes while allowing body traversal lessons', async () => {
  const { compileOperation } = await registry();
  for (const id of ['../whoami', '..', '%2e%2e', '%252e%252e', 'a%2fb', 'a\\b']) {
    assert.throws(() => compileOperation('orders.get', { params: { id } }), /path parameter id/);
  }
  const bodyPath = '../../../../etc/passwd';
  assert.equal(
    compileOperation('admin.system.readConfig', { body: { path: bodyPath } }).body.path,
    bodyPath,
  );
});

test('omits empty optional bodies and preserves the explicit auto-reply recovery identity', async () => {
  const { compileOperation } = await registry();
  assert.equal(compileOperation('auth.logout').body, undefined);
  assert.equal(compileOperation('auth.logout', { body: {} }).body, undefined);
  assert.deepEqual(compileOperation('email.autoReply', {
    params: { threadId: 5 }, body: {},
  }).body, undefined);
  const requestId = 'cc99f488-282b-4cb8-9034-10e4e0cb81c8';
  assert.deepEqual(compileOperation('email.autoReply', {
    params: { threadId: 5 }, body: { requestId },
  }).body, { requestId });
  assert.throws(() => compileOperation('email.autoReply', {
    params: { threadId: 5 }, body: { requestId, platformOwnerId: 99 },
  }));
});

test('rejects cyclic, accessor, sparse, non-finite, and oversized JSON before operation validation', async () => {
  const { compileOperation } = await registry();
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => compileOperation('auth.login', { body: cyclic }), /cyclic input/);

  const getter = {};
  Object.defineProperty(getter, 'body', { enumerable: true, get() { throw new Error('secret'); } });
  assert.throws(() => compileOperation('auth.login', getter), /accessors are not allowed/);

  const sparse = [];
  sparse.length = 100;
  assert.throws(() => compileOperation('auth.login', { body: { username: sparse } }), /dense and ordinary/);
  assert.throws(() => compileOperation('auth.login', { body: { username: 'u', password: Infinity } }), /finite/);
  assert.throws(() => compileOperation('auth.login', { body: { username: 'u', password: 'x'.repeat(128 * 1024 + 1) } }), /too large/);
});

test('description is frozen, covers all current JSON families, and records the separate typed multipart compiler', async () => {
  const { describeOperations } = await registry();
  const description = describeOperations();
  const names = new Set(description.operations.map((entry) => entry.name));
  for (const name of [
    'auth.login', 'account.profile.update', 'catalog.list', 'cart.add', 'orders.create',
    'email.send', 'agent.customer.chat', 'merchant.products.create', 'admin.users.list',
    'admin.audit.list', 'admin.policies.upsert', 'admin.mcp.register',
    'admin.system.diagnostic', 'admin.accessControl.setPermission',
  ]) assert.ok(names.has(name), `missing ${name}`);
  assert.ok(description.operations.every((entry) => entry.pathTemplate.startsWith('/api/secureshop/')));
  assert.ok(description.operations.every((entry) => ['json', 'sse'].includes(entry.responseKind)));
  assert.deepEqual(description.separate.map((entry) => entry.name), [
    'agent.customer.avatarTraversal.run', 'agent.customer.avatarUpload.run', 'agent.customer.fileSummary.run', 'uploads.create',
  ]);
  assert.ok(Object.isFrozen(description));
  assert.ok(Object.isFrozen(description.operations));
  assert.ok(Object.isFrozen(description.separate[0]));
});


test('audit continuation crosses the fixed bridge without admitting ownership query fields',async()=>{
 const {compileOperation}=await registry();
 const compiled=compileOperation('admin.audit.list',{query:{limit:'1',cursor:'owned_cursor'}});
 assert.match(compiled.path,/cursor=owned_cursor/);
 assert.throws(()=>compileOperation('admin.audit.list',{query:{platformOwnerId:'7'}}));
});
