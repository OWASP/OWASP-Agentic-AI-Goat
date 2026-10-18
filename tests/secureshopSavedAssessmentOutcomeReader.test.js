'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {createSavedAssessmentOutcomeReader}=require('../server/services/secureshopSavedAssessmentOutcomeReader');
const id=n=>`a0000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 const binding={launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:3,platformSessionId:4,shopUserId:5,role:'customer'};
 const {shopUserId,role,...scope}=binding,personaSession={sessionId:id(6),authorityVersion:'1'};
 const rubric={family:'SecureShop',scenario:'bound_search_echo_browser',version:'controlled-v1',objectiveId:'ss_search_echo_browser'};
 const publication={generation:1,mode:'vuln',modeStamp:'stamp'},result={verdict:'fail',explanation:'Controlled no-credit result'};
 const packet='{"controlled":true}',serialized=JSON.stringify(result),owner=JSON.stringify(['SecureShopBoundConversation',id(7)]);
 const row={tenant_id:id(8),principal_id:id(9),evaluation_id:id(10),shop_user_id:5,
  workshop_key:'secureshop_agent_security',objective_id:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,
  rubric_version:rubric.version,mode:'vuln',generation:1,mode_stamp:'stamp',owner_key:owner,owner_generation:'1',live_owner_generation:'1',
  current_tenant_id:id(8),current_principal_id:id(9),current_membership_version:'2',run_id:id(11),
  execution_json:{tenantId:id(8),principalId:id(9),membershipVersion:'2',scope,
   personaSessionId:personaSession.sessionId,personaAuthorityVersion:'1',role:'customer',runId:id(11)},
  packet,evidence_digest:hash(packet),result_json:result,result_serialized:serialized,result_digest:hash(serialized),
  verdict:'fail',disposition:'not_pass',child_id:null};
 const calls={query:0,prepare:0,check:0};let active=true;
 const reader=createSavedAssessmentOutcomeReader({identityPool:{query:async sql=>{
  assert.match(sql,/^SELECT /);calls.query++;return{rows:[row]};}},objectiveId:rubric.objectiveId,rubric,role:'customer'});
 const input={binding,personaSession,publication,assessmentOwnerKey:owner,
  turnResult:{completed:false,judgment:{...result,evaluationId:id(10),canRetry:false}},
  prepareRetainedPacket:async (saved,execution)=>{calls.prepare++;assert.equal(saved,packet);assert.deepEqual(execution,{runId:row.run_id,ownerKey:owner,generation:'1'});return{packet,evidenceDigest:hash(packet)};},
  check:async()=>{calls.check++;if(!active)throw Error('revoked');}};
 return{reader,input,row,calls,revoke:()=>{active=false;}};
}
test('saved outcome uses scoped SELECT and mandatory reconstructed packet before closed replay',async()=>{
 const f=fixture();assert.deepEqual(await f.reader.read(f.input),{...f.input.turnResult,replayed:true});
 assert.equal(f.calls.query,1);assert.equal(f.calls.prepare,1);assert.ok(f.calls.check>=3);
});
test('saved outcome rejects foreign identity, stale epoch and result or packet substitution',async()=>{
 for(const mutate of [r=>{r.objective_id='other';},r=>{r.owner_key='other';},r=>{r.live_owner_generation='2';},
  r=>{r.current_tenant_id=id(99);},r=>{r.execution_json.personaSessionId=id(99);},
  r=>{r.execution_json.personaAuthorityVersion='99';},r=>{r.execution_json.role='admin';},
  r=>{r.execution_json.scope.generation++;},r=>{r.mode='fixed';},r=>{r.mode_stamp='new';},
  r=>{r.packet+=' ';},r=>{r.evidence_digest='0'.repeat(64);},r=>{r.result_serialized+=' ';},
  r=>{r.result_json.verdict='pass';},r=>{r.disposition='awarded';}]){
  const f=fixture();mutate(f.row);await assert.rejects(f.reader.read(f.input));
 }
 const f=fixture();f.input.turnResult.completed=true;await assert.rejects(f.reader.read(f.input));
 const g=fixture();g.revoke();await assert.rejects(g.reader.read(g.input));assert.equal(g.calls.query,0);
 const h=fixture();h.row.current_tenant_id=id(99);await assert.rejects(h.reader.read(h.input));assert.equal(h.calls.prepare,0);
});
test('saved outcome requires immutable parent-child continuity and does not invent pending child credit',async()=>{
 const f=fixture();f.row.child_id=id(12);f.row.child_row={...structuredClone(f.row),evaluation_id:id(12),run_id:f.row.run_id,
  execution_json:{...structuredClone(f.row.execution_json),runId:id(13)},verdict:null};
 f.row.child_invocation={tenant_id:f.row.tenant_id,principal_id:f.row.principal_id,parent_id:f.row.evaluation_id,
  attempt:1,run_id:id(13),execution_json:structuredClone(f.row.child_row.execution_json)};
 assert.deepEqual(await f.reader.read(f.input),{...f.input.turnResult,replayed:true});
 f.row.child_row.verdict='fail';
 assert.equal((await f.reader.read(f.input)).judgment.evaluationId,id(12));
 for(const mutate of [c=>{c.packet='forged';},c=>{c.principal_id=id(99);},c=>{c.execution_json.personaSessionId=id(99);},
  c=>{c.evidence_digest='0'.repeat(64);},c=>{c.owner_generation='2';},c=>{c.execution_json.runId=id(99);}]){
  const before=structuredClone(f.row.child_row);mutate(f.row.child_row);
  await assert.rejects(f.reader.read(f.input));f.row.child_row=before;
 }
 for(const mutate of [i=>{i.parent_id=id(99);},i=>{i.execution_json.role='admin';},i=>{i.attempt=4;},i=>{i.run_id=id(99);}]){
  const before=structuredClone(f.row.child_invocation);mutate(f.row.child_invocation);
  await assert.rejects(f.reader.read(f.input));f.row.child_invocation=before;
 }
 delete f.row.child_invocation;await assert.rejects(f.reader.read(f.input));
});
