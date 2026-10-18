'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),{createRequire}=require('node:module'),{randomUUID}=require('node:crypto');
const file=path.resolve('server/services/secureshopMailBrowserAssessment.js'),realRequire=createRequire(file);
const {buildMailBrowserCandidate}=require('../server/services/secureshopMailBrowserEvidence');
function fixture(publicationModes){
 const b={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};
 const payload={from:'merchant@lab',to:'customer@lab',subject:'Hello\r\nX-Lab: injected'};payload.headers_raw=`From: ${payload.from}\r\nTo: ${payload.to}\r\nSubject: ${payload.subject}`;
 const observed={binding:b,receipt:{email_id:10,contentSha256:'b'.repeat(64)},payload:{body_html:'<b>controlled</b>'},requestSha256:'a'.repeat(64)};
 const state={enabled:true,revoked:false,evaluations:0,retries:0,reads:0,observed};const sessions=new Map(),claims=new Map();
 const check=async()=>{if(state.revoked)throw Error('revoked');};
 const conversations={async acquireBoundSession({id,binding,purpose}){const prior=[...sessions.values()][0];if(prior)return prior;const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},async activateBoundSession(id){sessions.get(id).state='active';return true;},async getBoundSession(id){return sessions.get(id);}};
 const journal={async claim({requestId,message}){if(claims.has(requestId)){const prior=claims.get(requestId);return prior.message===message?prior:{status:'conflict'};}return {status:'claimed',claimId:requestId};},async complete({requestId,result,message}){claims.set(requestId,{status:'completed',result,message});},async markUncertain({requestId}){claims.set(requestId,{status:'uncertain'});}};
 const personaAuthority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:check,async withCrossStoreEffect(work){await check();return work();},async withPersonaEffect(work){await check();return work({});}};}};
 const coordinator={async run(owner,options,run){state.owner=owner;const admitted=await options.admit();if(admitted.skip)return admitted.value;return run({runId:randomUUID(),ownerKey:owner,generation:1,durableGeneration:1,signal:options.signal,check,async trace(event){(state.traces||=[]).push(structuredClone(event));},async effect(k,fn){return fn();},async effectWithReceipt(k,fn){state.effects=(state.effects||0)+1;const value=await fn();return {value,receipt:{version:1,status:'completed',runId:this.runId,ownerKey:owner,generation:1,effectKey:`${options.idempotencyKey}:${k}`}};}});}};
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,require(name){if(name==='./secureshopAssessmentEligibility')return {readSecureShopAssessmentEligibility:async(_pool,scope)=>{assert.deepEqual(scope,b.scope);return state.enabled?['ss_mail_stored_browser_execution']:[];}};if(name==='../config/secureshopCurriculum')return {isQualifiedObjective:()=>true};if(name==='./secureshopObjectiveCompletionService')return {createObjectiveCompletionService:()=>({async beginAttempt(){return {mode:b.mode};},async evaluate(input){state.evaluations++;state.packet=input;return {completed:state.pass===true,judgment:{verdict:state.pass?'pass':'fail'}};},async retry({execution:e}){state.retries++;await e.check();return {completed:false,judgment:{verdict:'unavailable'}};}})};return realRequire(name);},Buffer,console,JSON,structuredClone});
 const assessment=module.exports.createMailBrowserAssessment({identityPool:{async query(sql){return {rows:sql.includes("graph_runtime.effects")?(state.effectRows||[]):state.enabled?[{}]:[]};}},launches:{assertCurrent:check},conversationRepository:conversations,journal,coordinator,personaAuthority,personaBindings:{async capture(){}},receipts:{async getRecovery(){return state.recovery;}},progress:{async getEvaluationScope(){return {generation:1,mode:'vuln',modeStamp:state.stamp||'initial'};}},publicationModes,judge:async()=>{},browserQualification:{readComponent(){return state.component||{id:"SecureShop.MailMessageBody",sourceSha256:"a".repeat(64),artifactSha256:"b".repeat(64)};},async qualifyMail(){if(state.browserWait)await state.browserWait();state.browsers=(state.browsers||0)+1;if(state.revokeDuring)state.revoked=true;if(state.changeDuring)state.observed={...state.observed,payload:{body_html:"changed"}};return {component:{id:"SecureShop.MailMessageBody",sourceSha256:"a".repeat(64),artifactSha256:"b".repeat(64)},executed:true,targetEventExecuted:true,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,markers:["controlled"]};}},evidenceRepository:{async readBrowser(){state.reads++;return structuredClone(state.observed);}}});
 return {b,state,assessment};
}

test('controlled canonical Judge fail is preserved; same request replays without browser or Judge',async()=>{const f=fixture(),input={binding:f.b,requestId:randomUUID(),messageId:10};const r=await f.assessment.runAttempt(input);assert.equal(r.completed,false);assert.equal(r.judgment.verdict,'fail');assert.equal(f.state.evaluations,1);assert.equal(f.state.browsers,1);assert.equal((await f.assessment.runAttempt(input)).replayed,true);assert.equal(f.state.browsers,1);assert.equal(f.state.evaluations,1);});
test('source change and persona retirement after browser prevent canonical evaluation',async()=>{for(const key of ['changeDuring','revokeDuring']){const f=fixture();f.state[key]=true;await assert.rejects(f.assessment.runAttempt({binding:f.b,requestId:randomUUID(),messageId:10}));assert.equal(f.state.evaluations,0);}});
test('disabled catalog and fixed mode do not execute browser',async()=>{for(const key of ['enabled','fixed']){const f=fixture();if(key==='enabled')f.state.enabled=false;else f.b.mode='fixed';const r=await f.assessment.runAttempt({binding:f.b,requestId:randomUUID(),messageId:10});assert.equal(r.completed,false);assert.equal(f.state.browsers,undefined);assert.equal(f.state.evaluations,0);}});

test('controlled retry delegation validates retained effect/source/component without rerunning browser; eligibility is repository-owned',async()=>{
 const f=fixture();await f.assessment.runAttempt({binding:f.b,requestId:randomUUID(),messageId:10});
 const packet=JSON.parse(require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(f.state.packet).packet);const receipt=packet.evidence[0].content.effectReceipt;
 f.state.recovery={workshop_key:'secureshop_agent_security',objective_id:'ss_mail_stored_browser_execution',owner_key:receipt.ownerKey,owner_generation:receipt.generation,run_id:receipt.runId,packet:JSON.stringify(packet)};
 const {version,...row}=receipt;f.state.effectRows=[{...row,generation:String(row.generation)}];
 const input={binding:f.b,requestId:randomUUID(),messageId:10,evaluationId:randomUUID()};
 const result=await f.assessment.runAttempt(input);assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'unavailable');assert.equal(f.state.retries,1);assert.equal(f.state.browsers,1);
 const originalPacket=f.state.recovery.packet;
 for(const mutate of [p=>{p.rubric.criteria[0].description+=' changed';},p=>{p.rubric.authoritativeVerdictFacts=['owned_saved_mail'];}]){const changed=JSON.parse(originalPacket);mutate(changed);f.state.recovery={...f.state.recovery,packet:JSON.stringify(changed)};await assert.rejects(f.assessment.runAttempt({...input,requestId:randomUUID()}));assert.equal(f.state.retries,1);}
 f.state.recovery={...f.state.recovery,packet:originalPacket};
 f.state.effectRows=[];await assert.rejects(f.assessment.runAttempt({...input,requestId:randomUUID()}));assert.equal(f.state.retries,1);
 f.state.effectRows=[{...row,generation:String(row.generation)}];const original=f.state.observed;f.state.observed={...original,payload:{body_html:'changed'}};await assert.rejects(f.assessment.runAttempt({...input,requestId:randomUUID()}));f.state.observed=original;const prior=f.state.recovery;f.state.recovery={...prior,owner_key:'foreign'};await assert.rejects(f.assessment.runAttempt({...input,requestId:randomUUID()}));f.state.recovery=prior;f.state.component={id:'wrong'};await assert.rejects(f.assessment.runAttempt({...input,requestId:randomUUID()}));assert.equal(f.state.browsers,1);
});

test('manual browser run emits its own trace once and replay does not fabricate model activity',async()=>{
 const f=fixture(),input={binding:f.b,requestId:randomUUID(),messageId:10};
 await f.assessment.runAttempt(input);await f.assessment.runAttempt(input);
 assert.equal(JSON.stringify(f.state.traces),JSON.stringify([{node:'mail_browser_assessment',type:'node_start',data:{}}]));
});


test('deferred browser positive after abort or authority reset cannot reach grading',async()=>{
 for(const kind of ['abort','reset']){
  const f=fixture(),stop=new AbortController();let entered,release;const started=new Promise(r=>entered=r);
  f.state.browserWait=async()=>{entered();await new Promise(r=>release=r);};f.state.pass=true;
  const pending=f.assessment.runAttempt({binding:f.b,requestId:randomUUID(),messageId:10,signal:stop.signal});
  const rejected=assert.rejects(pending);await started;if(kind==='abort')stop.abort();else f.state.revoked=true;
  release();await rejected;assert.equal(f.state.evaluations,0);assert.equal(f.state.retries,0);
 }
});
test('browser publication reads the scoped shop mode before rendering',async()=>{const seen=[];const f=fixture({async getEvaluationScope(owner,key,scope){seen.push({owner,key,scope});return{generation:1,mode:'fixed',modeStamp:'shop-fixed'};}});const result=await f.assessment.runAttempt({binding:f.b,requestId:randomUUID(),messageId:10});assert.equal(result.status,'ineligible');assert.deepEqual(seen,[{owner:f.b.scope.platformOwnerId,key:'secureshop_agent_security',scope:f.b.scope}]);assert.equal(f.state.browsers,undefined);});
