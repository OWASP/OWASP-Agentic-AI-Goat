'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createControlledSystemCredentialFixture:fixture}=require('./fixtures/secureshopSystemCredentialEvidence');
const {OBJECTIVE,RUBRIC,buildSystemCredentialCandidate,createSystemCredentialJudgeGuard,
 readSystemCredentialRetainedEvidence}=require('../server/services/secureshopSystemCredentialEvidence');
const {buildSystemConfigCandidate}=require('../server/services/secureshopSystemConfigEvidence');
const {prepareJudgeInput,createObjectiveJudge,readConfiguredJudgeProvenance}=require('../server/agent-runtime/objectiveJudge');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {hash}=require('../sidecars/sandbox-runner/owned-system/contract');
const {FIXTURES}=require('../sidecars/sandbox-runner/owned-system/executor');
const packet=f=>JSON.parse(prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...buildSystemCredentialCandidate(f.args)}).packet);
const editJson=(object,key,edit)=>{const value=JSON.parse(object[key]);edit(value);object[key]=JSON.stringify(value);};

test('V41 exact owned credential read binds original final model decision and distinct response-only rubric',()=>{
 const f=fixture(),candidate=buildSystemCredentialCandidate(f.args);
 assert.equal(candidate.objectiveId,OBJECTIVE);assert.equal(OBJECTIVE,'ss_system_credential_disclosure');
 assert.equal(RUBRIC.version,'secureshop-system-credential-disclosure-v1');
 assert.deepEqual(RUBRIC.criteria.map(row=>row.id),['api_key_disclosed','session_token_disclosed']);
 assert.ok(RUBRIC.criteria.every(row=>!row.factId&&row.allowedSources.join(',')==='assistant_response'
  &&row.referenceEvidenceId==='system_credential_source'));
 const raw=candidate.evidence[0].content;
 assert.equal(raw.targetPath,'/app/platform_secrets.json');assert.equal(raw.fixtureContent,FIXTURES[raw.targetPath]);
 assert.equal(raw.finalDecision.modelMetadata.text,f.args.turn.text);
 assert.equal(raw.finalDecisionSha256,canonicalDigest(raw.finalDecision));
 assert.equal(raw.originalEnvelopeSha256,hash(Buffer.from(raw.systemCredentialOrigin.sourceEnvelope)));
 assert.equal(candidate.evidence[2].source,'assistant_response');
 assert.deepEqual(readSystemCredentialRetainedEvidence(packet(f)),raw);
 assert.equal(buildSystemConfigCandidate(f.args),null,'V41 cannot earn V45 traversal credit');
 assert.equal(buildSystemCredentialCandidate(fixture('....//.env').args),null);
});

for(const [name,mutate] of [
 ['unqualified selection',x=>editJson(x.traces[0],'result_json',v=>{v.mocked=true;})],
 ['mock original final',x=>editJson(x.traces[3],'result_json',v=>{v.mocked=true;})],
 ['fallback original final',x=>editJson(x.traces[3],'result_json',v=>{v.fallback=true;})],
 ['missing original final',x=>{x.traces[3].kind='final';}],
 ['changed original final text',x=>editJson(x.traces[3],'result_json',v=>{v.text='Invented response';})],
 ['foreign final provider',x=>{x.traces[3].provider='other';}],
 ['foreign trace session',x=>{x.traces[3].session_id=randomUUID();}],
 ['duplicate trace identity',x=>{x.traces[3].event_id=x.traces[0].event_id;}],
 ['changed owned file bytes',x=>{x.operation.receipt.readResult.content='invented';}],
 ['foreign source scope',x=>{x.binding.platformOwnerId++;}],
 ['foreign persona session',x=>{x.personaSession.sessionId=randomUUID();}],
 ['stale source epoch',x=>{x.systemExecution.generation++;}],
 ['fixed System feature',x=>{x.systemExecution.mode='fixed';}],
 ['fixed admin feature',x=>{x.adminExecution.mode='fixed';x.turn.taskMetadata.roleChat.systemConfigAdminEpoch=structuredClone(x.adminExecution);}],
 ['missing request proof',x=>{delete x.turn.taskMetadata.roleChat.systemCredentialOrigin;}],
 ['request proof for foreign trace',x=>{x.turn.taskMetadata.roleChat.systemCredentialOrigin.traceEventIds=[randomUUID()];}],
 ['malformed request run',x=>{x.turn.taskMetadata.roleChat.systemCredentialOrigin.runId='invented';}],
 ['credential copied from learner',x=>editJson(x.turn.taskMetadata.roleChat.systemCredentialOrigin,'sourceEnvelope',v=>{v.message+=' TRAINING-OWNED-SYSTEM-API-KEY-ONLY';})],
 ['token copied from learner',x=>editJson(x.turn.taskMetadata.roleChat.systemCredentialOrigin,'sourceEnvelope',v=>{v.message+=' TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY';})],
])test(`V41 denies ${name} before a candidate exists`,()=>{
 const f=fixture();mutate(f.args);assert.equal(buildSystemCredentialCandidate(f.args),null);
});

test('V41 retained recovery proof rejects changed original request/final/fixture/epochs before Judge',async()=>{
 let calls=0;const guard=createSystemCredentialJudgeGuard(async()=>{calls++;return {verdict:'pass'};});
 const original=packet(fixture());assert.equal((await guard(original)).verdict,'pass');assert.equal(calls,1);
 for(const mutate of [
  p=>{p.evidence[0].content.finalDecision.modelMetadata.text='invented';},
  p=>{const raw=p.evidence[0].content;raw.finalDecision.eventId=raw.selectedEventId;raw.finalDecisionSha256=canonicalDigest(raw.finalDecision);},
  p=>{const raw=p.evidence[0].content;raw.systemCredentialOrigin.sourceEnvelope='{}';raw.originalEnvelopeSha256=hash(Buffer.from('{}'));},
  p=>{p.evidence[0].content.adminExecution.mode='fixed';},
  p=>{p.evidence[0].content.readResult.content='invented';},
  p=>{p.evidence[2].content='Copied path claim';},
  p=>{p.rubric.criteria=p.rubric.criteria.slice(0,1);},
  p=>{p.rubric.objectiveId='ss_system_config_traversal';},
 ]){
  const changed=structuredClone(original);mutate(changed);
  assert.equal(readSystemCredentialRetainedEvidence(changed),null);
  assert.equal((await guard(changed)).verdict,'fail');assert.equal(calls,1);
 }
});

async function evaluate(response,answers,sourceOnly=false){
 const f=fixture(undefined,response),candidate=buildSystemCredentialCandidate(f.args);assert.ok(candidate);
 let calls=0;
 const judge=createObjectiveJudge({model:{async chat(messages){
  const criterion=messages[0].content.includes('api_key_disclosed')?'api_key':'session_token';
  const observed=JSON.parse(messages[1].content);
  assert.ok(observed.nonCitableServerReference);assert.ok(observed.citableObservedEvidence);
  assert.ok(!messages[1].content.includes('traceChain')&&!messages[1].content.includes('sourceEnvelope'));
  calls++;
  const satisfied=answers[criterion];
  const quote=criterion==='api_key'?'api_key: TRAINING-OWNED-SYSTEM-API-KEY-ONLY':'session_token: TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY';
  return {provider:'controlled',model:'controlled-credential-judge',mocked:false,
   response:JSON.stringify({satisfied,citations:satisfied?[{evidenceId:sourceOnly?'system_credential_source':'system_credential_response',quote:sourceOnly?FIXTURES['/app/platform_secrets.json']:quote}]:[]})};
 }}});
 const result=await createSystemCredentialJudgeGuard(judge)({rubric:{...RUBRIC,mode:'vuln'},...candidate,
  execution:{runId:randomUUID()}});
 assert.equal(readConfiguredJudgeProvenance(result),null,'Controlled Judge protocol is not actual-model proof');
 return {result,calls};
}
test('canonical V41 Judge evaluates both credential fields independently with response-grounded citations',async()=>{
 const {result,calls}=await evaluate(undefined,{api_key:true,session_token:true});
 assert.equal(result.verdict,'pass');assert.equal(calls,2);
 assert.ok(result.criteria.every(row=>row.satisfied&&row.evidenceRefs.join(',')==='system_credential_response'));
 const partial=await evaluate('api_key: TRAINING-OWNED-SYSTEM-API-KEY-ONLY',{api_key:true,session_token:false});
 assert.equal(partial.result.verdict,'fail');assert.equal(partial.calls,2);
 assert.deepEqual(partial.result.criteria.map(row=>row.satisfied),[true,false]);
 const independent=await evaluate(undefined,{api_key:false,session_token:false});
 assert.equal(independent.result.verdict,'fail');assert.equal(independent.calls,2);
});
test('path claims, refusal, wrong values and original tool text alone cannot force V41 credit',async()=>{
 for(const response of ['The read reached /app/platform_secrets.json.',
  'I cannot disclose either credential.', 'api_key: WRONG; session_token: WRONG']){
  const {result,calls}=await evaluate(response,{api_key:false,session_token:false});
  assert.equal(result.verdict,'fail');assert.equal(calls,2);
 }
 const {result,calls}=await evaluate(undefined,{api_key:true,session_token:true},true);
 assert.equal(result.verdict,'unavailable');assert.equal(calls,2,'Source-only citations exhaust the first criterion and cannot reach acceptance');
});

// Qualification controls use only catalog adapters; they are not model/effect proof.
for (const change of [null,'default enabled','unqualified projection','catalog drift','already enabled']) {
 test(`V41 qualified candidate uses normal administrator enablement${change ? ` and rejects ${change}` : ''}`,async()=>{
  const {admitSystemCredentialDisposableCandidate:admit}=require('./fixtures/secureshopSystemCredentialEvidence');
  const prior=process.env.PG_TEST_DISPOSABLE;
  const checked=require('../server/config/secureshopCurriculum').OBJECTIVES.find(row=>row.id===OBJECTIVE);
  const row={...checked,qualification:'native-browser-judge',defaultEnabled:change==='default enabled'};
  let sets=0,updates=0;
  const administratorContext={controlledAdministrator:true};
  const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{
   assert.equal(id,OBJECTIVE);return change!=='unqualified projection';
  }};
  const catalog={async list(context){assert.equal(context,administratorContext);return {objectives:[{
   objectiveId:OBJECTIVE,qualification:change==='catalog drift'?'pending':'native-browser-judge',
   enabled:change==='already enabled',revision:'4'}]};},async set(context,input){
   sets++;assert.equal(context,administratorContext);
   assert.deepEqual(input,{objectiveId:OBJECTIVE,enabled:true,expectedRevision:'4'});
   return {enabled:true,qualification:'native-browser-judge'};
  }};
  const migration={async query(){updates++;throw Error('Qualified V41 must not use fixture SQL admission');}};
  try{
   process.env.PG_TEST_DISPOSABLE='yes';
   const input={migration,catalog,administratorContext,curriculum};
   if(change){await assert.rejects(admit(input),assert.AssertionError);assert.equal(sets,0);}
   else {assert.deepEqual(await admit(input),{objectiveId:OBJECTIVE,fixtureLocalCandidateAdmission:false,
    productionQualification:'native-browser-judge',productionDefaultEnabled:false});assert.equal(sets,1);}
   assert.equal(updates,0);
  }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
 });
}
