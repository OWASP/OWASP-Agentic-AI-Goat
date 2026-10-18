'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const C=require('../server/services/secureshopRoleAuditJobProposal');
const {createBoundAuditJobs}=require('../server/services/secureshopBoundAuditJobs');
const {createFeatureModeAuthority}=require('../server/services/secureshopFeatureModeAuthority');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createOwnedAuditSearchApplication}=require('../server/services/secureshopOwnedAuditSearchApplication');
function fixture(){
 const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},persona:{id:9,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 let revoked=false,mode='vuln',modelCalls=0,timingAssessments=0,lost=false,row,runInput;const calls=[],sessions=new Map();
 const check=async()=>{if(revoked)throw Error('revoked');};
 const personaAuthority={capture:async x=>({binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:check,withPersonaEffect:async f=>f({})})};
 const modeAuthority=createFeatureModeAuthority({launches:{assertCurrent:check},progress:{getEvaluationScope:async()=>({mode,generation:0,modeStamp:mode})}});
 const conversations={async create(binding,persona,purpose){calls.push('session');const id=randomUUID();sessions.set(id,purpose);return{id};},async assertOwned(id,b,p,purpose){await check();if(sessions.get(id)!==purpose)throw Error('purpose');}};
 const journal={async claim(input){calls.push('claim');const r=createTurnRequest(input);if(row){if(row.request_hash!==r.hash)throw Error('conflict');return{status:'completed',result:row.result_json};}return{status:'claimed',claimId:randomUUID()};},async complete(input){const r=createTurnRequest(input);row={session_id:input.sessionId,request_id:input.requestId,request_version:r.version,request_hash:r.hash,status:'completed',result_json:structuredClone(input.result)};calls.push('complete');if(lost)throw Error('lost ACK');},async markUncertain(){calls.push('uncertain');},async readAuditRequest(input){calls.push('read');await conversations.assertOwned(input.sessionId,input.binding,context.persona,input.purpose);return structuredClone(row||null);}};
 const turns={async run(id,b,p,options,work){runInput=options;await conversations.assertOwned(id,b,p,options.conversationPurpose);const admitted=await options.admit();if(admitted.skip)return admitted.value;return work({identity:{runId:randomUUID(),ownerKey:'owned',durableGeneration:'1'},check,signal:options.signal,trace:async()=>{calls.push('trace');}});}};
 const app=createOwnedAuditSearchApplication({launches:{assertCurrent:check},personaAuthority,modeAuthority,conversations,journal,turns,
  decisionGraph:{async run({message,boundary}){await boundary.check();modelCalls++;assert.equal(message,'Inspect the current audit');return{text:'Controlled audit answer',query:null,provider:'controlled',model:'fixture',};}},beginAssessment:async()=>({mode,consume:async()=>({passed:false,reason:'No source witness'})}),
  beginTimingAssessment:async()=>({mode,consume:async()=>{timingAssessments++;return{passed:false,reason:'No timing witness'};}})});
 let summaryCalls=0;
 const {guardFeatureFence,captureFeatureMode}=require('../server/services/secureshopFeatureModeAuthority');
 const summary=require('../server/services/secureshopAuditRunner').createSecureShopAuditRunner({turns,conversations,journal,
  capturePersonaAuthority:async({binding,personaSession})=>guardFeatureFence(await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,...personaSession}),await captureFeatureMode(modeAuthority,binding,'audit_summary')),
  beginAssessment:async()=>({consume:async()=>{},outcome:()=>({completed:false,judgment:{verdict:'fail'}})}),
  executeJob:async({boundary,requestedCount})=>{await boundary.check();summaryCalls++;const summary='Controlled source-backed summary',sha=createHash('sha256').update(summary).digest('hex'),artifacts=Object.fromEntries(['log','sources','messages','traces','effects'].map(k=>[k,{bytes:10,sha256:'a'.repeat(64)}]));return{runId:boundary.identity.runId,summary,provider:'ollama',model:'controlled',requestedCount,rowCount:1,objectiveCredit:false,evidence:{version:1,modelProvenance:true,logSha256:artifacts.log.sha256,sourcesSha256:artifacts.sources.sha256,summarySha256:sha,observationSha256:'b'.repeat(64),trace:[{step:1,phase:'decision',provider:'ollama',model:'controlled',tool:'audit.summarize_anomalies'},{step:2,phase:'final',provider:'ollama',model:'controlled',tool:null}],artifacts}};}});
 const summaryService={...summary,createSession:async()=>({sessionId:(await conversations.create(null,null,'secureshop_audit_summary')).id})};
 const adapter=createBoundAuditJobs({getAuditSearch:()=>app,getAuditSummary:()=>summaryService,personaAuthority,modeAuthority,conversations,journal});
 const input={context,source:{sessionId:randomUUID(),requestId:randomUUID()},origin:{step:1,callId:'prepare-1'},action:'agent',input:{message:'Inspect the current audit'}};
 return{adapter,app,input,calls,context,journal,conversations,sessions,get row(){return row;},set row(v){row=v;},get summaryCalls(){return summaryCalls;},get modelCalls(){return modelCalls;},get timingAssessments(){return timingAssessments;},setMode(v){mode=v;},revoke(){revoked=true;},loseAck(){lost=true;}};
}
test('server-selected timing agent uses its own durable session purpose and assessment',async()=>{
 const f=fixture(),created=await f.app.createTimingSession(f.context);
 assert.equal(f.sessions.get(created.sessionId),'secureshop_audit_sql_timing');
 const input={...f.context,sessionId:created.sessionId,requestId:randomUUID(),message:'Inspect the current audit'};
 const original=await f.app.runTimingAgent(input);
 assert.equal(original.assessment?.reason||original.result?.assessment?.reason,'No timing witness');
 assert.equal(f.timingAssessments,1);assert.equal(f.modelCalls,1);
 await f.app.runTimingAgent(input);assert.equal(f.timingAssessments,1);assert.equal(f.modelCalls,1);
 const extraction=await f.app.createAgentSession(f.context);
 assert.equal(f.sessions.get(extraction.sessionId),'secureshop_audit_sql');
 await assert.rejects(f.app.runTimingAgent({...input,sessionId:extraction.sessionId}),/purpose/);
});
test('prepare is no-model; physical run uses existing agent journal and exact GET never runs again',async()=>{const f=fixture(),p=await f.adapter.prepare(f.input);assert.deepEqual(f.calls,['session']);assert.equal(f.modelCalls,0);assert.equal((await f.adapter.read({context:f.context,proposal:p})).status,'not_found');const result=await f.adapter.run({context:f.context,proposal:p});assert.equal(result.status,'completed');assert.equal(result.result.evidence,null);assert.equal(result.result.provider,'controlled');assert.equal(result.result.assessment.passed,false);assert.equal(Object.hasOwn(result.result,'_auditJob'),false);assert.deepEqual(await f.adapter.read({context:f.context,proposal:p}),result);assert.deepEqual(await f.adapter.run({context:f.context,proposal:p}),result);assert.equal(f.modelCalls,1);assert.equal(f.calls.filter(x=>x==='session').length,1);});
test('lost publication ACK recovers exact completed journal; no second model call',async()=>{const f=fixture(),p=await f.adapter.prepare(f.input);f.loseAck();await assert.rejects(f.adapter.run({context:f.context,proposal:p}),/lost ACK/);const before=f.modelCalls;assert.equal((await f.adapter.read({context:f.context,proposal:p})).status,'completed');assert.equal(f.modelCalls,before);});
test('original scope/session/mode and scene guard reject before job admission',async()=>{for(const change of ['session','mode','scene','abort']){const f=fixture(),p=await f.adapter.prepare(f.input);let args={context:f.context,proposal:p};if(change==='session')args.context={...f.context,personaSession:{...f.context.personaSession,sessionId:randomUUID()}};if(change==='mode')f.setMode('fixed');if(change==='scene')args.beforeEffect=async()=>{throw Error('scene');};if(change==='abort'){const c=new AbortController();c.abort();args.signal=c.signal;}await assert.rejects(f.adapter.run(args));assert.equal(f.modelCalls,0);assert.equal(f.calls.includes('claim'),false);}});
test('saved request hash and private request context defeat altered proposal and result metadata',async()=>{for(const mutate of [f=>{f.row.request_hash='0'.repeat(64);},f=>{f.row.result_json._auditJob.requestContext='0'.repeat(64);},f=>{f.row.result_json._auditJob.modeCapability.effectiveMode='fixed';},f=>{f.row.result_json.runId=randomUUID();f.row.result_json.extra=true;},f=>{f.row.result_json.modeCapability.effectiveMode='fixed';},f=>{f.row.request_id=randomUUID();}]){const f=fixture(),p=await f.adapter.prepare(f.input);await f.adapter.run({context:f.context,proposal:p});mutate(f);await assert.rejects(f.adapter.read({context:f.context,proposal:p}));assert.equal(f.modelCalls,1);}});
test('pending journal stays unconfirmed and historical result without chat metadata is not invented evidence',async()=>{const f=fixture(),p=await f.adapter.prepare(f.input);await f.adapter.run({context:f.context,proposal:p});f.row.status='uncertain';assert.equal((await f.adapter.read({context:f.context,proposal:p})).status,'unconfirmed');f.row.status='completed';delete f.row.result_json._auditJob;await assert.rejects(f.adapter.read({context:f.context,proposal:p}));assert.equal(f.modelCalls,1);});
test('proposal canonical digest is JSONB order independent and legacy request bytes remain exact',async()=>{const f=fixture(),p=await f.adapter.prepare(f.input);const reverse=v=>Array.isArray(v)?v.map(reverse):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).reverse().map(([k,x])=>[k,reverse(x)])):v;assert.deepEqual(C.validate(reverse(p)),reverse(p));assert.equal(C.requestMessage('agent',{message:' raw text '}),' raw text ');assert.equal(C.requestMessage('summary',{requestedCount:10000}),JSON.stringify(['secureshop-audit-summary',1,10000]));assert.notEqual(C.requestMessage('agent',p.input,p.requestSha256),p.input.message);assert.throws(()=>C.validate({...p,input:{message:'different'}}));assert.throws(()=>C.input('summary',{requestedCount:1.5}));});
test('purpose-specific repository read binds exact two IDs and complete owner context',async()=>{const {createTurnRequestsRepository}=require('../server/database/postgres/secureshopTurnRequestsRepository');let sql,args;const repo=createTurnRequestsRepository({pool:{connect:async()=>({release(){},query:async(s,a)=>{sql=s;args=a;return{rows:[]};}})}});const f=fixture(),binding=C.context(f.context).binding,sessionId=randomUUID(),requestId=randomUUID();assert.equal(await repo.readAuditRequest({sessionId,requestId,binding,purpose:'secureshop_audit_sql'}),null);assert.ok(sql.includes('tr.session_id=$1 AND tr.request_id=$2'));assert.ok(sql.includes("s.binding_state='active'"));assert.deepEqual(args,[sessionId,requestId,'secureshop_audit_sql',binding.launchId,binding.scenarioId,binding.generation,7,8,9,'admin']);await assert.rejects(repo.readAuditRequest({sessionId,requestId,binding,purpose:'general'}));});

test('summary uses original separate runner and preserves saved verified artifact proof and assessment',async()=>{const f=fixture(),p=await f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:10000}});assert.equal(f.summaryCalls,0);const value=await f.adapter.run({context:f.context,proposal:p});assert.equal(f.summaryCalls,1);assert.equal(value.result.requestedCount,10000);assert.equal(value.result.evidence.modelProvenance,true);assert.equal(value.result.objectiveCredit,false);assert.equal(value.result.assessment.judgment.verdict,'fail');assert.equal(value.result.evidence.artifacts.traces.sha256,'a'.repeat(64));assert.deepEqual(await f.adapter.read({context:f.context,proposal:p}),value);assert.deepEqual(await f.adapter.run({context:f.context,proposal:p}),value);assert.equal(f.summaryCalls,1);});
test('fixed summary count retains existing100 limit while vulnerable preparation does not clamp',async()=>{const f=fixture();f.setMode('fixed');await assert.rejects(f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:101}}),{code:'AUDIT_FIXED_COUNT_LIMIT'});assert.deepEqual(f.calls,[]);const p=await f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:100}});assert.equal(p.input.requestedCount,100);});
test('preparation snapshots input before awaits and rejects bad source before session creation',async()=>{const f=fixture();let release;const gate=new Promise(r=>{release=r;});let calls=0;const input={...f.input,input:{message:'Inspect the current audit'},beforeEffect:async()=>{if(++calls===1)await gate;}};const pending=f.adapter.prepare(input);await Promise.resolve();input.input.message='substituted';release();assert.equal((await pending).input.message,'Inspect the current audit');const g=fixture();await assert.rejects(g.adapter.prepare({...g.input,source:{sessionId:'invalid',requestId:randomUUID()}}));assert.equal(g.calls.includes('session'),false);});
test('late source change after journal admission prevents agent model dispatch',async()=>{const f=fixture(),p=await f.adapter.prepare(f.input);await assert.rejects(f.adapter.run({context:f.context,proposal:p,beforeEffect:async()=>{if(f.calls.includes('claim'))throw Error('source changed');}}),/source changed/);assert.equal(f.modelCalls,0);assert.equal(f.calls.includes('complete'),false);});
test('public summary proof rejects missing provenance and modified summary rather than displaying saved success',async()=>{for(const change of ['provenance','summary','source']){const f=fixture(),p=await f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:2}});await f.adapter.run({context:f.context,proposal:p});if(change==='provenance')f.row.result_json.evidence.modelProvenance=false;if(change==='summary')f.row.result_json.summary='substitute';if(change==='source')f.row.result_json.evidence.sourcesSha256='c'.repeat(64);await assert.rejects(f.adapter.read({context:f.context,proposal:p}));assert.equal(f.summaryCalls,1);}});

test('saved phase trace rejects invented tool, nonsequential steps, extra raw prompt and final identity substitution',async()=>{for(const change of ['tool','step','prompt','model']){const f=fixture(),p=await f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:2}});await f.adapter.run({context:f.context,proposal:p});const trace=f.row.result_json.evidence.trace;if(change==='tool')trace[0].tool='other.read';if(change==='step')trace[1].step=9;if(change==='prompt')trace[0].prompt='raw';if(change==='model')trace[1].model='substitute';await assert.rejects(f.adapter.read({context:f.context,proposal:p}));assert.equal(f.summaryCalls,1);}});

for(const phase of ['before admission','after claim'])for(const change of ['revoked session','mode change'])
test(`pending summary rejects ${change} ${phase} without dispatch or completed publication`,async()=>{
 const f=fixture(),p=await f.adapter.prepare({...f.input,action:'summary',input:{requestedCount:5}});
 const before=structuredClone(p),changeAuthority=()=>change==='revoked session'?f.revoke():f.setMode('fixed');
 let pending;
 if(phase==='after claim'){
  let entered,release;
  const claimed=new Promise(resolve=>{entered=resolve}),gate=new Promise(resolve=>{release=resolve});
  const claim=f.journal.claim;
  f.journal.claim=async input=>{const result=await claim(input);entered();await gate;return result;};
  pending=f.adapter.run({context:f.context,proposal:p});
  // Observe the rejection before releasing admission, avoiding an unhandled rejection.
  const rejected=assert.rejects(pending,change==='revoked session'?/revoked/:{code:'ANALYTICS_MODE_STALE'});
  await claimed;changeAuthority();release();await rejected;
  assert.equal(f.calls.filter(value=>value==='claim').length,1);
 }else{
  changeAuthority();await assert.rejects(f.adapter.run({context:f.context,proposal:p}),change==='revoked session'?/revoked/:{code:'AUDIT_JOB_INVALID'});
  assert.equal(f.calls.includes('claim'),false);
 }
 assert.equal(f.summaryCalls,0);assert.equal(f.modelCalls,0);assert.equal(f.row,undefined);
 assert.equal(f.calls.includes('complete'),false);assert.equal(f.calls.includes('trace'),false);
 assert.deepEqual(p,before);
 await assert.rejects(f.adapter.read({context:f.context,proposal:p}),change==='revoked session'?/revoked/:{code:'AUDIT_JOB_INVALID'});
 assert.equal(f.summaryCalls,0);assert.equal(f.calls.includes('complete'),false);
});
