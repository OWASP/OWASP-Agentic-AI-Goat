'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {assertRegisteredPersonaJudgment,createStandalonePersonaEvidence,physicalPersonaControl,verifyPersonaReadPreservesMessages,observeConfiguredPersonaJudge,IDS,MODEL}=require('./fixtures/secureshopStandalonePersonaInboxQualification');
const {createRenderedPersonaEvidence}=require('./fixtures/renderedSecureShopPersona');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const hash=value=>createHash('sha256').update(value).digest('hex');
test('each accepted original read preserves the complete baseline message rows',async()=>{
  const baseline={messages:[{message_id:7,body:'synthetic private body',body_sha256:Buffer.from('abcd','hex')}]};
  for(const mode of ['advisory','enforced']){
    const input={mode},verified={controlled:true},order=[];
    const snapshot={messages:baseline.messages.map(row=>({...row,body_sha256:Buffer.from(row.body_sha256)})),acls:[{mode}]};
    const result=await verifyPersonaReadPreservesMessages({async verify(value){assert.equal(value,input);order.push('verify');return verified;},
      async snapshotFull(){order.push('snapshot');return snapshot;}},baseline,input);
    assert.deepEqual(order,['verify','snapshot']);assert.equal(result.verified,verified);assert.equal(result.snapshot,snapshot);
  }
});
test('accepted read cannot conceal a changed body, digest, missing row or missing baseline',async()=>{
  const baseline={messages:[{message_id:7,body:'synthetic private body',body_sha256:Buffer.from('abcd','hex')}]};
  for(const mode of ['advisory','enforced'])for(const mutate of [
    rows=>{rows[0].body='changed after original action';},rows=>{rows[0].body_sha256=Buffer.from('ffff','hex');},rows=>{rows.pop();},
  ]){
    const snapshot={messages:baseline.messages.map(row=>({...row,body_sha256:Buffer.from(row.body_sha256)}))};mutate(snapshot.messages);
    let accepted=0;await assert.rejects(verifyPersonaReadPreservesMessages({async verify(){accepted++;return {controlled:true};},
      async snapshotFull(){return snapshot;}},baseline,{mode}),/read must preserve persisted messages/);assert.equal(accepted,1);
  }
  await assert.rejects(verifyPersonaReadPreservesMessages({async verify(){return {};},async snapshotFull(){return {};}},{},{mode:'enforced'}),/Baseline messages required/);
});
const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:4,platformSessionId:5,shopUserId:6,role:'merchant'};
const subject={tenantId:randomUUID(),principalId:randomUUID(),targetId:randomUUID(),binding,
  personaSessionId:randomUUID(),personaAuthorityVersion:'1'};
function row(){const packet=JSON.stringify({fixture:'controlled only'}),result={provider:'ollama',model:'llama3.1:8b',verdict:'pass'};
  const raw=JSON.stringify(result),run=randomUUID(),evaluation=randomUUID(),owner='owned-test';
  return {tenant_id:subject.tenantId,principal_id:subject.principalId,shop_user_id:binding.shopUserId,
    objective_id:IDS[0],evaluation_id:evaluation,credited:evaluation,run_id:run,owner_key:owner,owner_generation:'3',
    execution_json:{tenantId:subject.tenantId,principalId:subject.principalId,shopUserId:binding.shopUserId,role:binding.role,
      scope:createLaunchScope(binding),personaSessionId:subject.personaSessionId,personaAuthorityVersion:'1',runId:run,ownerKey:owner,ownerGeneration:'3'},
    packet,evidence_digest:hash(packet),result_serialized:raw,result_digest:hash(raw),result_json:result,
    judge_result_json:raw,judge_observations:{version:1,runId:run,evidenceDigest:hash(packet),resultSha256:hash(raw),calls:[{provider:'ollama',model:'llama3.1:8b'}]},
    verdict:'pass',disposition:'awarded'};
}
test('registered adapter validates exact received ownership and hashes without claiming an actual run',async t=>{
  assert.equal(assertRegisteredPersonaJudgment(row(),subject).verdict,'pass');
  for(const [name,mutate]of Object.entries({
    tenant:r=>{r.tenant_id=randomUUID();},principal:r=>{r.execution_json.principalId=randomUUID();},
    scope:r=>{r.execution_json.scope={...r.execution_json.scope,generation:r.execution_json.scope.generation+1};},session:r=>{r.execution_json.personaSessionId=randomUUID();},
    packet:r=>{r.packet+=' ';},result:r=>{r.result_serialized+=' ';},proof:r=>{r.judge_observations.resultSha256='0'.repeat(64);},
    credit:r=>{r.credited=null;},mock:r=>{r.result_json.provider='mock';},
  }))await t.test(name,()=>{const value=row();mutate(value);assert.throws(()=>assertRegisteredPersonaJudgment(value,subject));});
});

test('registered evidence translates only the exact judgment SELECT and retains registered rows',async()=>{
  const original=row(),queries=[],captured=[];
  const identity={async query(sql,args){queries.push({sql,args});assert(!sql.includes('workshop_platform.'));
    assert(sql.includes('secureshop_auth.assessment_judgments'));assert.deepEqual(args,[subject.tenantId,subject.principalId,binding.launchId,'2',IDS]);return{rows:[original]};}};
  const agents={async connect(){throw Error('No mutable query');},async query(sql){assert(sql.includes('COALESCE(MAX(t.id),0)'));return{rows:[{id:'0'}]};}};
  const evidence=createStandalonePersonaEvidence({identity,agents,subject,mailScenes:{async readRetained(){throw Error('Not a snapshot operation');}},
    inboxRepository:{async readAccessEvent(){throw Error('Not a snapshot operation');}},record:value=>captured.push(value)});
  const snapshot=await evidence.snapshot();assert.deepEqual(snapshot.rows,[original]);assert.equal(queries.length,1);
  assert.equal(snapshot.rows[0],original);assert.deepEqual(captured,[]);
});

test('paired trusted scene readers keep current execution checks before accepting access evidence',async()=>{
  const identityRuntime={async query(){return{rows:[{launch_id:binding.launchId}]};}},agentsRuntime={async connect(){throw Error('No mutable query');},async query(){throw Error('No legacy target lookup');}};
  const base={identityRuntime,agentsRuntime,binding};
  assert.throws(()=>createRenderedPersonaEvidence({...base,readTarget:async()=>({})}),/paired/);
  const birth={...createLaunchScope(binding),launchId:randomUUID(),platformSessionId:8,generation:1};
  const scene=require('../server/services/secureshopSceneBinding').createSceneBinding({...birth,targetId:randomUUID()},
    {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:createLaunchScope(binding),withLease:work=>work()});
  const target=require('../server/services/secureshopMailSceneBinding').attach({...birth,targetId:subject.targetId},scene);
  const stop=Error('Real reader reached');let observed;
  const trusted=createRenderedPersonaEvidence({...base,readTarget:async()=>target,async readAccessEvent(value){observed=value;throw stop;}});
  const input={before:{rows:[],head:'0'},requestId:randomUUID(),messageId:7,mode:'advisory',
    response:{stopReason:'end_turn',replayed:false,accesses:[{message_id:7,event_id:randomUUID()}]}};
  await assert.rejects(trusted.verify(input),error=>error===stop);assert.equal(observed,target);
  const wrong=createRenderedPersonaEvidence({...base,readTarget:async()=>({...binding,targetId:subject.targetId,platformSessionId:99}),
    async readAccessEvent(){assert.fail('Foreign current scene must fail before evidence lookup');}});
  await assert.rejects(wrong.verify(input),{code:'ERR_ASSERTION'});
});

test('physical helper uses the browser pointer and removes its temporary selector',async()=>{
  const calls=[];const frame={async waitForFunction(_fn,options,input){calls.push(['wait',options,input]);},
    async click(selector){calls.push(['click',selector]);},async evaluate(){calls.push(['remove']);}};
  await physicalPersonaControl(frame,'Owned message');assert.equal(calls[0][2].control,'read');
  assert.deepEqual(calls.slice(1),[['click','[data-c31-control="active"]'],['remove']]);
  calls.length=0;await physicalPersonaControl(frame,undefined,'refresh');assert.equal(calls[0][2].control,'refresh');
});

test('configured Judge observation forwards exact HTTP bytes without injecting a model or result',async()=>{
  const original=global.fetch,oldEnv={...process.env},forwarded=[],expected=[];
  let actor=false,phase=true;
  const sentinel={controlledTransportOnly:true};
  global.fetch=async(...args)=>{forwarded.push(args);return sentinel;};
  const before=global.fetch;
  const close=observeConfiguredPersonaJudge({transport:{url:'http://127.0.0.1:32123',expect:(...args)=>expected.push(args)},
    assertPhase:()=>assert(phase),isActor:()=>actor});
  try{
    const request={method:'POST',body:JSON.stringify({model:MODEL,stream:true,messages:[{role:'system',content:'fixture'},{role:'user',content:'fixture'}],
      options:{temperature:0,num_predict:900,num_ctx:32768},format:{type:'object'}})};
    assert.equal(await global.fetch('http://127.0.0.1:32123/api/chat',request),sentinel);
    assert.equal(expected.length,1);assert.equal(expected[0][0],'judge');
    assert.equal(forwarded[0][1],request);assert.equal(process.env.JUDGE_MODEL,MODEL);
    actor=true;await global.fetch('http://127.0.0.1:32123/api/chat',request);assert.equal(expected.length,1);
    actor=false;phase=false;
    await assert.rejects(global.fetch('http://127.0.0.1:32123/api/chat',request));assert.equal(forwarded.length,2);
    await global.fetch('http://127.0.0.1:32124/api/chat',request);assert.equal(forwarded.length,3);
  }finally{close();assert.equal(global.fetch,before);global.fetch=original;}
  for(const key of ['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL'])assert.equal(process.env[key],oldEnv[key]);
});
