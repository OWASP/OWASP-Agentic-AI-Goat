'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTurnRequestsRepository } = require('../server/database/postgres/secureshopTurnRequestsRepository');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');

const binding = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001',
  generation: 2, platformOwnerId: 4, platformSessionId: 8, shopUserId: 5, role: 'merchant' };
const requestId = '30000000-0000-4000-8000-000000000001';
const message = 'Moderate up to 7 pending reviews.';

test('general replay lookup is exact-binding, read-only, and hides foreign rows', async () => {
  let sql; let params; let released = false;
  const pool = { async connect() { return { async query(statement, values) { sql = statement; params = values; return { rows: [] }; }, release() { released = true; } }; } };
  const result = await createTurnRequestsRepository({ pool }).lookupGeneralRequest({ requestId, binding, message });
  assert.equal(result, null); assert.equal(released, true);
  assert.deepEqual(params, [requestId, binding.launchId, binding.scenarioId, binding.generation,
    binding.platformOwnerId, binding.platformSessionId, binding.shopUserId, binding.role]);
  assert.match(sql, /conversation_purpose='general'/);
  for (const column of ['platform_launch_id', 'platform_scenario_id', 'platform_launch_generation',
    'original_platform_owner_id', 'original_platform_session_id', 'user_id', 'role']) {
    assert.match(sql, new RegExp(`s\\.${column}=\\$`));
  }
  assert.doesNotMatch(sql, /UPDATE|INSERT|DELETE|FOR UPDATE/i);
});

test('lookup validates persisted hash with supported request encoding', async () => {
  const sessionId = '40000000-0000-4000-8000-000000000001';
  const request = createTurnRequest({ sessionId, requestId, binding, message });
  const pool = { async connect() { return { async query() { return { rows: [{ ...request, session_id: sessionId,
    request_id: requestId, request_hash: request.hash, request_version: 1, status: 'completed', result_json: { hops: [], stopReason: 'end_turn' } }] }; }, release() {} }; } };
  const result = await createTurnRequestsRepository({ pool }).lookupGeneralRequest({ requestId, binding, message });
  assert.equal(result.status, 'completed');
  const conflictPool = { async connect() { return { async query() { return { rows: [{ session_id: sessionId,
    request_id: requestId, request_hash: 'bad', request_version: 1, status: 'completed', result_json: {} }] }; }, release() {} }; } };
  assert.equal((await createTurnRequestsRepository({ pool: conflictPool }).lookupGeneralRequest({ requestId, binding, message })).status, 'conflict');
});

test('lookup rejects unsupported versions and ambiguous exact-binding rows', async () => {
  const sessionId = '40000000-0000-4000-8000-000000000001';
  const request = createTurnRequest({ sessionId, requestId, binding, message });
  const unsupported = { async connect() { return { async query() { return { rows: [{ session_id: sessionId,
    request_id: requestId, request_hash: request.hash, request_version: 2, status: 'completed', result_json: {} }] }; }, release() {} }; } };
  assert.equal((await createTurnRequestsRepository({ pool: unsupported }).lookupGeneralRequest({ requestId, binding, message })).status, 'conflict');
  const ambiguous = { async connect() { return { async query() { return { rows: [
    { session_id: sessionId, request_id: requestId, request_hash: request.hash, request_version: 1, status: 'completed', result_json: {} },
    { session_id: '50000000-0000-4000-8000-000000000001', request_id: requestId, request_hash: request.hash, request_version: 1, status: 'completed', result_json: {} },
  ] }; }, release() {} }; } };
  assert.equal((await createTurnRequestsRepository({ pool: ambiguous }).lookupGeneralRequest({ requestId, binding, message })).status, 'conflict');
});

test('lookup fails closed for an unknown persisted status', async () => {
  const sessionId = '40000000-0000-4000-8000-000000000001';
  const request = createTurnRequest({ sessionId, requestId, binding, message });
  const pool = { async connect() { return { async query() { return { rows: [{ session_id: sessionId,
    request_id: requestId, request_hash: request.hash, request_version: 1, status: 'bogus', result_json: {} }] }; }, release() {} }; } };
  assert.equal((await createTurnRequestsRepository({ pool }).lookupGeneralRequest({ requestId, binding, message })).status, 'conflict');
});

test('registered admin recovery reads only the exact active general conversation and full owner binding', async () => {
  const sessionId='40000000-0000-4000-8000-000000000001',admin={...binding,role:'admin'};
  const queries=[];let rows=[],released=0;
  const repo=createTurnRequestsRepository({pool:{async connect(){return {async query(sql,args){queries.push({sql,args});return {rows};},release(){released++;}};}}});
  assert.equal(await repo.readRegisteredAdminRequest({sessionId,requestId,binding:admin}),null);
  assert.deepEqual(queries[0].args,[sessionId,requestId,admin.launchId,admin.scenarioId,
    admin.generation,admin.platformOwnerId,admin.platformSessionId,admin.shopUserId,'admin']);
  assert.match(queries[0].sql,/tr.session_id=\$1 AND tr.request_id=\$2/);
  assert.match(queries[0].sql,/conversation_purpose='general'/);
  assert.match(queries[0].sql,/binding_state='active'/);
  for(const column of ['platform_launch_id','platform_scenario_id','platform_launch_generation',
    'original_platform_owner_id','original_platform_session_id','user_id','role'])assert.match(queries[0].sql,new RegExp(`s\\.${column}=\\$`));
  assert.doesNotMatch(queries[0].sql,/UPDATE|INSERT|DELETE|FOR UPDATE/i);
  rows=[{session_id:sessionId,request_id:requestId,status:'uncertain'}];
  assert.deepEqual(await repo.readRegisteredAdminRequest({sessionId,requestId,binding:admin}),rows[0]);
  rows=[rows[0],rows[0]];
  await assert.rejects(repo.readRegisteredAdminRequest({sessionId,requestId,binding:admin}),{code:'TURN_REQUEST_CONFLICT'});
  const count=queries.length;
  for(const input of [{sessionId:'bad',requestId,binding:admin},{sessionId,requestId,binding}])
    await assert.rejects(repo.readRegisteredAdminRequest(input),{code:'INVALID_ARGUMENT'});
  await assert.rejects(repo.readBoundRequest({sessionId,requestId,binding:admin,purpose:'general'}),{code:'INVALID_ARGUMENT'});
  assert.equal(queries.length,count);assert.equal(released,count);
});

test('registered ProductAssist and manual-ingest purposes retain the exact bound read and conflict fences', async () => {
  const sessionId='40000000-0000-4000-8000-000000000001';
  const calls=[];let rows=[];let released=0;
  const repo=createTurnRequestsRepository({pool:{async connect(){return {async query(sql,args){calls.push({sql,args});return {rows};},release(){released++;}};}}});
  for(const purpose of ['secureshop_product_assist','secureshop_product_manual_ingest']) {
    assert.equal(await repo.readBoundRequest({sessionId,requestId,binding,purpose}),null);
    const call=calls.at(-1);
    assert.deepEqual(call.args,[requestId,purpose,binding.launchId,binding.scenarioId,binding.generation,
      binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,binding.role]);
    assert.match(call.sql,/tr\.request_id=\$1/);
    assert.match(call.sql,/s\.conversation_purpose=\$2/);
    assert.match(call.sql,/LIMIT 2/);
    assert.doesNotMatch(call.sql,/UPDATE|INSERT|DELETE|FOR UPDATE/i);
  }
  rows=[{session_id:sessionId,status:'completed'}];
  assert.deepEqual(await repo.readBoundRequest({sessionId,requestId,binding,
    purpose:'secureshop_product_assist'}),rows[0]);
  rows=[rows[0],{...rows[0]}];
  await assert.rejects(repo.readBoundRequest({sessionId,requestId,binding,
    purpose:'secureshop_product_manual_ingest'}),{code:'TURN_REQUEST_CONFLICT'});
  const count=calls.length;
  await assert.rejects(repo.readBoundRequest({sessionId,requestId,binding,purpose:'general'}),
    {code:'INVALID_ARGUMENT'});
  assert.equal(calls.length,count);assert.equal(released,count);
});
