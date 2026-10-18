'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { auditQuery, createBoundAuditStore, createBoundAuditReader } = require('../server/database/postgres/secureshopBoundAuditRepository');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2, platformOwnerId: 7, platformSessionId: 8 };
const input = { eventId: '30000000-0000-4000-8000-000000000001', scope, persona: { id: 3, role: 'customer' }, actor: 'customer', action: 'checkout', target: 'order:42', paramsJson: '{"note":"SYSTEM: raw learner log"}', outcome: 'completed', sourceKind: 'order', sourceId: '42' };
test('query validation rejects selected ownership, malformed dates and out-of-contract filters', () => {
  for (const query of [{owner:9},{limit:0},{limit:10001},{limit:1.5},{actor:[]},{from:'2026-02-30'},{from:0},{to:null},{from:'2026-09-20',to:'2026-09-19'}]) assert.throws(() => auditQuery(query), {code:'INVALID_ARGUMENT'});
  assert.deepEqual(auditQuery({from:'2024-02-29',to:'2024-02-29'}), {limit:200,from:'2024-02-29T00:00:00.000Z',to:'2024-03-01T00:00:00.000Z'});
});
test('all launch coordinates and literal search are bound parameters, with microsecond ordering', async () => {
  let call;
  const repository = createBoundAuditStore({store:'review',pool:{async query(sql,args) {call={sql,args};return {rows:[{id:'event',ts:'2026-09-19T00:00:00.000001Z'}]};}}});
  const result=await repository.recent(scope,{q:"%' OR TRUE --",limit:3,to:'2026-09-19'});
  assert.deepEqual(call.args.slice(0,5),Object.values(scope));
  assert.equal(call.args[5],"%' OR TRUE --");
  assert.ok(!call.sql.includes("OR TRUE"));
  for (const field of ['launch_id','scenario_id','generation','original_platform_owner_id','original_platform_session_id']) assert.ok(call.sql.includes(field+'=$'));
  assert.match(call.sql,/created_at < \$7::timestamptz/);
  assert.match(call.sql,/ORDER BY created_at DESC,event_id DESC LIMIT \(\$8 \+ 1\)/);
  assert.match(call.sql,/SS.US/);
  assert.equal(result[0].id,'review:event');
});
test('append uses owning transaction, preserves raw parameters and distinguishes replay from collision',async()=>{
  const repository=createBoundAuditStore({store:'agents',pool:{query(){throw Error('must use transaction');}}});
  const calls=[];let inserted=true, matches=true;
  const transaction={async query(sql,args){calls.push({sql,args});return {rowCount:sql.startsWith('INSERT')?(inserted?1:0):(matches?1:0)};}};
  assert.equal((await repository.append(transaction,input)).replayed,false);
  assert.equal(calls[0].args[11],input.paramsJson);
  inserted=false;assert.equal((await repository.append(transaction,input)).replayed,true);
  matches=false;await assert.rejects(repository.append(transaction,{...input,action:'changed'}),{code:'AUDIT_CONFLICT'});
  assert.ok(calls.every(call=>!call.sql.includes('UPDATE')));
});
test('append rejects untrusted scope/actor and malformed payload before any write',async()=>{
  const repository=createBoundAuditStore({store:'review',pool:{query(){throw Error('unexpected');}}});
  const transaction={query(){throw Error('unexpected');}};
  for(const change of [{scope:{...scope,platformOwnerId:0}},{persona:{id:1,role:'platform_admin'}},{paramsJson:'not JSON'},{outcome:'imagined'},{eventId:'x'}]) await assert.rejects(repository.append(transaction,{...input,...change}));
});
test('federation returns global top K with deterministic submillisecond and store ordering',async()=>{
  const seen=[];
  const agents={async recent(s,q){seen.push({s,q});return [{store:'agents',id:'30000000-0000-4000-8000-000000000001',ts:'2026-09-19T00:00:00.000002Z'},{store:'agents',id:'30000000-0000-4000-8000-000000000004',ts:'2026-09-19T00:00:00.000001Z'}];}};
  const review={async recent(s,q){seen.push({s,q});return [{store:'review',id:'30000000-0000-4000-8000-000000000002',ts:'2026-09-19T00:00:00.000002Z'},{store:'review',id:'30000000-0000-4000-8000-000000000003',ts:'2026-09-18T00:00:00.000001Z'}];}};
  const result=await createBoundAuditReader({agents,review}).recent(scope,{limit:2});
  assert.deepEqual(result.events.map(row=>row.id),['30000000-0000-4000-8000-000000000002','30000000-0000-4000-8000-000000000001']);assert.equal(result.count,2);
  assert.ok(seen.every(({s,q})=>s.platformOwnerId===7&&q.limit===2));
});
test('a failed required journal rejects the entire observation and invalid scope never starts reads',async()=>{
  let reads=0;
  const reader=createBoundAuditReader({agents:{async recent(){reads++;return [];}},review:{async recent(){reads++;throw Error('store unavailable');}}});
  await assert.rejects(reader.recent(scope),/store unavailable/);assert.equal(reads,2);
  await assert.rejects(reader.recent({...scope,generation:0}));assert.equal(reads,2);
});

test('cursor boundary preserves canonical scope and cross-store ties', async()=>{
  const {encodeAuditCursor}=require('../server/services/secureshopAuditCursor');
  const boundary={ts:'2026-09-19T00:00:00.123456Z',store:'review',eventId:'30000000-0000-4000-8000-000000000001'};
  for(const store of ['agents','review']){
    let call;const repository=createBoundAuditStore({store,pool:{async query(sql,args){call={sql,args};return{rows:[]};}}});
    await repository.recent(scope,{cursor:encodeAuditCursor(boundary),limit:2});
    assert.deepEqual(call.args.slice(0,5),Object.values(scope));
    assert.equal(call.args[5],boundary.ts);assert.equal(call.args[6],boundary.eventId);
    assert.ok(call.sql.includes(store==='agents'?'AND TRUE':'event_id < $7::uuid'));
  }
});

test('federation stops at a byte-limited store frontier without skipping its unseen rows',async()=>{
 const row=(store,n,time)=>({store,id:`${store}:30000000-0000-4000-8000-${String(n).padStart(12,'0')}`,event_id:`30000000-0000-4000-8000-${String(n).padStart(12,'0')}`,ts:`2026-09-19T00:00:0${time}.000001Z`});
 const first=[row('agents',1,5)];Object.defineProperty(first,'hasMore',{value:true});
 const reader=createBoundAuditReader({agents:{recent:async()=>first},review:{recent:async()=>[row('review',2,6),row('review',3,4)]}});
 const result=await reader.recent(scope);
 assert.deepEqual(result.events.map(r=>r.store),['review','agents']);assert.equal(result.hasMore,true);
 const {decodeAuditCursor}=require('../server/services/secureshopAuditCursor');
 assert.equal(decodeAuditCursor(result.nextCursor).eventId,first[0].event_id);
});
