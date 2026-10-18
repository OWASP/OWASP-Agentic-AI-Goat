'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfDb,createCtfMutationAdapter}=require('../server/database/postgres/ctfDb');
function harness(responses=[]){
 const queries=[];let releases=0,connects=0;
 const client={release(){releases++;},async query(sql,args){queries.push({sql,args});
  if(/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[],rowCount:0};
  return responses.shift()||{rows:[{id:9,attempts_count:2}],rowCount:1};}};
 const pool={async connect(){connects++;return client;},query:client.query.bind(client)};
 return{client,pool,queries,counts:()=>({releases,connects})};
}
async function parity(method,args,responses){
 const a=harness(structuredClone(responses||[])),b=harness(structuredClone(responses||[]));
 const expected=await createCtfDb(a.pool)[method](...args),actual=await createCtfMutationAdapter(b.client)[method](...args);
 assert.deepEqual(actual,expected,method);assert.deepEqual(b.queries,a.queries.filter(q=>!(/^(BEGIN|COMMIT|ROLLBACK)$/.test(q.sql)||q.sql.startsWith('SELECT pg_advisory_xact_lock'))),method);
 assert.deepEqual(b.counts(),{releases:0,connects:0});assert.deepEqual(a.counts(),{releases:1,connects:1});
}
test('transaction adapter reuses facade SQL and return values without BEGIN/pool/lease',async()=>{
 for(const [method,args] of [['updateConfig',['ctf_enabled','true']],['createSession',[1,'token',null,null]],['recordRegistration',[1,'{}']],['startStage',[1,2]],['recordStageStart',[1,2,'{}']],['incrementAttempts',[1,2,false,3]],['purchaseHint',[3,0,0]],['incrementPayloadHitCount',[2,'hash']],['banUser',[1,'reason',4]],['unbanUser',[1]],['deleteStage',[2]],['createStage',[{stage_number:1,stage_name:'A',stage_order:1}]],['logAttempt',[1,2,1,'payload','denied',false,0,null,'other',0,true,'blocked',null]]])await parity(method,args);
});
test('registration active recovery preserves capacity behavior',async()=>{
 const config={rows:[{key:'ctf_registration_open',value:'true'},{key:'ctf_max_participants',value:'0'}],rowCount:2};
 await parity('admitParticipant',[1,'Name',null,null],[config,{rows:[{id:9,is_active:1}],rowCount:1},{rows:[{id:9}],rowCount:1}]);
 await parity('admitParticipant',[1,'Name',null,null],[config,{rows:[],rowCount:0},{rows:[{count:0}],rowCount:1}]);
});
test('reset/remove/full and scoped/all clears preserve teaching history boundaries',async()=>{
 for(const options of [{participantId:1},{participantId:1,userId:2,remove:true},{all:true}]){
  await parity('reset',[options]);const h=harness();await createCtfMutationAdapter(h.client).reset(options);
  assert(!h.queries.some(q=>q.sql.includes('DELETE FROM ctf.ctf_judgments')));
  assert.equal(h.queries.some(q=>q.sql==='DELETE FROM ctf.ctf_payload_blocklist'),!!options.all);
 }
 for(const method of ['clearTechniqueBlocklist','clearPayloadBlocklist'])for(const scope of [null,3])await parity(method,[scope]);
});
test('decision/deletion authority unavailable and stale hint/attempt errors preserved',async()=>{
 const h=harness(),adapter=createCtfMutationAdapter(h.client);
 await assert.rejects(adapter.commitAttempt({}),/NOT_ENABLED/);await assert.rejects(adapter.destroyOwner(1),/POLICY_REQUIRED/);assert.equal(h.queries.length,0);
 await assert.rejects(adapter.logAttempt(1,2,1,'','',true),/JUDGED_ATTEMPT_REQUIRED/);
 for(const method of ['purchaseHint','incrementAttempts']){
  const state=harness([{rows:[],rowCount:0}]);await assert.rejects(createCtfMutationAdapter(state.client)[method](1,2),{name:'AbortError'});
 }
});
test('stage edit still marks instructor-owned provenance even for equal default bytes',async()=>{
 const fields={system_prompt:require('../server/data/ctfDefaults').stages[0].system_prompt};
 const answers=[{rows:[{stage_number:1}],rowCount:1},{rows:[],rowCount:1},{rows:[],rowCount:1}];
 await parity('updateStage',[1,fields],answers);
 const h=harness(structuredClone(answers));await createCtfMutationAdapter(h.client).updateStage(1,fields);
 assert(h.queries.some(q=>q.sql==='SELECT ctf.mark_stage_default_fields_custom($1,$2::text[])'));
 assert.deepEqual(h.queries[1].args,[1,['system_prompt']]);
});

test('nullable managed stage patch keeps SQL null and instructor provenance',async()=>{
 const fields={stage_description:null,ai_guardian_personality:null,system_prompt:null,hints:null};
 const answers=[{rows:[{stage_number:1}],rowCount:1},{rows:[],rowCount:1},{rows:[],rowCount:1}];
 await parity('updateStage',[1,fields],answers);
 const h=harness(structuredClone(answers));await createCtfMutationAdapter(h.client).updateStage(1,fields);
 assert.deepEqual(h.queries[2].args,[null,null,null,null,1]);
});

test('ordered adapter timestamps use captured event time without changing facade default',async()=>{
 const occurredAt='2026-09-26T01:02:03.456Z';
 for(const [method,args] of [['recordRegistration',[1,'{}']],['recordStageStart',[1,2,'{}']],['startStage',[1,2]],['incrementAttempts',[1,2,false,3]],['purchaseHint',[3,0,0]],['logAttempt',[1,2,1,'payload',null,false,0,null,null,null,true,'blocked',null]]]){
  const h=harness();await createCtfMutationAdapter(h.client,{occurredAt})[method](...args);
  assert.equal(h.queries.at(-1).args.at(-1),occurredAt,method);
  assert.deepEqual(h.counts(),{releases:0,connects:0});
  const old=harness();await createCtfDb(old.pool)[method](...args);
  assert.equal(old.queries.filter(q=>q.args?.length).at(-1).args.at(-1),null,method);
 }
});
test('new registration takes event time while both recovery paths preserve original clock',async()=>{
 const occurredAt='2026-09-26T01:02:03.456Z';
 const config={rows:[{key:'ctf_registration_open',value:'true'},{key:'ctf_max_participants',value:'-1'}],rowCount:2};
 for(const existing of [null,{id:9,is_active:0},{id:9,is_active:1}]){
  const h=harness([structuredClone(config),{rows:existing?[existing]:[],rowCount:existing?1:0},{rows:[{id:9}],rowCount:1}]);
  const value=await createCtfMutationAdapter(h.client,{occurredAt}).admitParticipant(1,'Name',null,null);
  assert.equal(value.recovered,!!existing);
  const q=h.queries.at(-1);
  if(existing?.is_active)assert(!q.sql.includes('started_at'));
  else {assert.equal(q.args.at(-1),occurredAt);assert(!q.sql.split('ON CONFLICT')[1].includes('started_at'));}
 }
});
test('invalid event timestamps fail before any query',()=>{
 const h=harness();for(const occurredAt of ['2026-09-26','2026-02-30T00:00:00.000Z',42,'invalid'])assert.throws(()=>createCtfMutationAdapter(h.client,{occurredAt}),/timestamp/);
 assert.equal(h.queries.length,0);
});
