'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundConversationsRepository } = require('../server/database/postgres/secureshopBoundConversationsRepository');

const SESSION = '81000000-0000-4000-8000-000000000001';
const FIRST = '82000000-0000-4000-8000-000000000001';
const SECOND = '82000000-0000-4000-8000-000000000002';
const BINDING = Object.freeze({ launchId: '91000000-0000-4000-8000-000000000001',
  scenarioId: '91000000-0000-4000-8000-000000000002', generation: 3,
  platformOwnerId: 71, platformSessionId: 81, shopUserId: 91, role: 'admin' });

function fixture(rows) {
  const queries = [];
  const pool = { async query(sql, args) {
    queries.push({sql,args});
    if (sql.includes('information_schema.columns')) return { rows: [{ ready: true }] };
    return { rows };
  } };
  return { repository: createBoundConversationsRepository({pool,queue:async (_id,action)=>action()}), queries };
}

test('protected trace event read orders exact persisted IDs and binds active original conversation purpose', async () => {
  const {repository,queries} = fixture([
    {event_id:SECOND,session_id:SESSION,kind:'terminal'},
    {event_id:FIRST,session_id:SESSION,kind:'model_decision'},
  ]);
  const rows = await repository.getTraceEvents(SESSION,BINDING,[FIRST,SECOND],'secureshop_admin_assistant');
  assert.deepEqual(rows.map(row=>row.event_id),[FIRST,SECOND]);
  const {sql,args}=queries.at(-1);
  assert.match(sql,/t\.event_id = ANY\(\$10::text\[\]\)/);
  assert.match(sql,/s\.binding_state='active'/);
  assert.match(sql,/s\.conversation_purpose=\$9/);
  assert.match(sql,/s\.original_platform_owner_id=\$5/);
  assert.match(sql,/s\.original_platform_session_id=\$6/);
  assert.deepEqual(args,[SESSION,BINDING.launchId,BINDING.scenarioId,BINDING.generation,
    BINDING.platformOwnerId,BINDING.platformSessionId,BINDING.shopUserId,BINDING.role,
    'secureshop_admin_assistant',[FIRST,SECOND]]);
});

test('protected trace event read rejects incomplete, duplicate, malformed, and foreign evidence', async () => {
  for (const ids of [[],[FIRST,FIRST],['arbitrary'],Array(1),Array(4097).fill(FIRST)]) {
    const {repository,queries}=fixture([]);
    await assert.rejects(repository.getTraceEvents(SESSION,BINDING,ids,'secureshop_admin_assistant'),TypeError);
    assert.equal(queries.length,0);
  }
  for (const rows of [[{event_id:FIRST,session_id:SESSION}],
    [{event_id:FIRST,session_id:SESSION},{event_id:SECOND,session_id:'foreign'}],
    [{event_id:FIRST,session_id:SESSION},{event_id:FIRST,session_id:SESSION}]]) {
    const {repository}=fixture(rows);
    await assert.rejects(repository.getTraceEvents(SESSION,BINDING,[FIRST,SECOND],'secureshop_admin_assistant'),
      {code:'CONVERSATION_UNAVAILABLE'});
  }
});
