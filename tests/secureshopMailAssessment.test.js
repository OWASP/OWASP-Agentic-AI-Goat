'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),{createRequire}=require('node:module'),{randomUUID}=require('node:crypto');
const file=path.resolve('server/services/secureshopMailReplyAssessment.js'),realRequire=createRequire(file);
function fixture({pass=false,publicationModes}={}){
 const b={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};
 let enabled=true,revoked=false,retries=0,reads=0,stamp='initial';const sessions=new Map(),claims=new Map();
 const check=async()=>{if(revoked)throw Error('revoked');};
 const conversations={async acquireBoundSession({id,binding,purpose}){const prior=[...sessions.values()][0];if(prior)return prior;const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},async activateBoundSession(id){sessions.get(id).state='active';return true;},async getBoundSession(id){return sessions.get(id);}};
 const journal={async claim({requestId,message}){if(claims.has(requestId)){const prior=claims.get(requestId);return prior.message===message?prior:{status:'conflict'};}return {status:'claimed',claimId:requestId};},async complete({requestId,result,message}){claims.set(requestId,{status:'completed',result,message});},async markUncertain({requestId}){claims.set(requestId,{status:'uncertain'});}};
 const personaAuthority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:check,async withCrossStoreEffect(work){await check();return work();},async withPersonaEffect(work){await check();return work({});}};}};
 const coordinator={async run(owner,options,run){const admitted=await options.admit();if(admitted.skip)return admitted.value;return run({runId:randomUUID(),ownerKey:owner,generation:1,durableGeneration:1,signal:options.signal,check,async effect(k,fn){return fn();}});}};
 const recovery={workshop_key:'secureshop_agent_security',objective_id:'ss_mail_reply_redirect',owner_generation:'1',packet:JSON.stringify({rubric:{objectiveId:'ss_mail_reply_redirect'},evidence:[{id:'mail_reply',source:'server_observation',content:{raw:{binding:b,threadId:5}}}]})};
 let execution;
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,require(name){if(name==='./secureshopAssessmentEligibility')return {readSecureShopAssessmentEligibility:async(_pool,scope)=>{assert.deepEqual(scope,b.scope);return enabled?['ss_mail_reply_redirect']:[];}};if(name==='./secureshopObjectiveCompletionService')return {createObjectiveCompletionService:()=>({async retry({execution:e}){retries++;await e.check();return {completed:pass,judgment:{verdict:pass?'pass':'unavailable',canRetry:false}};}})};return realRequire(name);},Buffer,console,JSON});
 const assessment=module.exports.createMailReplyAssessment({identityPool:{async query(){throw Error('Assessment must use scoped eligibility');}},launches:{assertCurrent:check},conversationRepository:conversations,journal,coordinator,personaAuthority,personaBindings:{async capture(){}},receipts:{async getRecovery(){return {...recovery,owner_key:execution};}},progress:{async getEvaluationScope(){return {generation:1,mode:'vuln',modeStamp:stamp};}},publicationModes,judge:async()=>{},qualifyModel:()=>true,evidenceRepository:{async readReply(){reads++;throw Error('must not reread on retry');}},listPersonas:async()=>[]});
 const original=coordinator.run;coordinator.run=async(owner,...args)=>{execution=owner;return original(owner,...args);};
 return {b,assessment,recovery,rotateStamp(){stamp='rotated';},get retries(){return retries;},get reads(){return reads;},disable(){enabled=false;},revoke(){revoked=true;}};
}
test('retained Judge retry uses exact immutable packet and canonical request replay without source/model rerun',async()=>{
 const f=fixture(),input={binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()};const r=await f.assessment.runAttempt(input);assert.equal(r.judgment.verdict,'unavailable');assert.equal(f.retries,1);assert.equal(f.reads,0);assert.equal((await f.assessment.runAttempt(input)).replayed,true);assert.equal(f.retries,1);
});
test('retry refuses foreign target, operation, persona session, thread and owner generation packets',async()=>{
 for(const mutate of [r=>r.binding.targetId=randomUUID(),r=>r.binding.operationId=randomUUID(),r=>r.binding.personaSession.sessionId=randomUUID(),r=>r.threadId=9]){const f=fixture(),packet=JSON.parse(f.recovery.packet);mutate(packet.evidence[0].content.raw);f.recovery.packet=JSON.stringify(packet);await assert.rejects(f.assessment.runAttempt({binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()}));assert.equal(f.retries,0);}
 const f=fixture();f.recovery.owner_generation='2';await assert.rejects(f.assessment.runAttempt({binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()}));assert.equal(f.retries,0);
});
test('disabled objective and revoked authority admit no Judge retry',async()=>{const f=fixture(),input={binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()};f.disable();assert.equal((await f.assessment.runAttempt(input)).status,'disabled');f.revoke();await assert.rejects(f.assessment.runAttempt(input),/revoked/);assert.equal(f.retries,0);});
test('v4 categorical retained retry preserves the packet protocol and audit without rebuilding source evidence',async()=>{
 const f=fixture(),packet=JSON.parse(f.recovery.packet);packet.rubric.version='secureshop-mail-reply-v4';packet.rubric.mailReplyComparison={primary:true,protocolVersion:'mail-owned-recipient-comparison-v1'};packet.evidence[0].id='mail_reply_audit';f.recovery.packet=JSON.stringify(packet);const before=f.recovery.packet;
 const input={binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()};await f.assessment.runAttempt(input);await f.assessment.runAttempt(input);
 assert.equal(f.recovery.packet,before);assert.equal(f.reads,0);assert.equal(f.retries,1);
});

test('historical v6/v12 and current v13 retries preserve stored protocol bytes, never rebuild with the current default',async()=>{
 for(const [version,protocol] of [['secureshop-mail-reply-v6','mail-grounded-action-comparison-v3'],['secureshop-mail-reply-v12','mail-whole-source-comparison-v9'],['secureshop-mail-reply-v13','mail-recipient-authority-comparison-v10']]){
 const f=fixture(),packet=JSON.parse(f.recovery.packet);packet.rubric.version=version;packet.rubric.mailReplyComparison={primary:true,protocolVersion:protocol};packet.evidence[0].id='mail_reply_audit';f.recovery.packet=JSON.stringify(packet);const before=f.recovery.packet;
 await f.assessment.runAttempt({binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()});assert.equal(f.recovery.packet,before);assert.equal(f.reads,0);assert.equal(f.retries,1);
 }
});

test('fixed mode cannot replay a cached vulnerable Judge retry pass',async()=>{const f=fixture({pass:true}),input={binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()};assert.equal((await f.assessment.runAttempt(input)).completed,true);assert.equal((await f.assessment.runAttempt(input)).replayed,true);f.b.mode='fixed';const result=await f.assessment.runAttempt(input);assert.equal(result.completed,false);assert.equal(result.status,'ineligible');assert.equal(f.retries,1);});

test('canonical stamp roundtrip invalidates cached reply',async()=>{const f=fixture(),input={binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()};await f.assessment.runAttempt(input);f.rotateStamp();await assert.rejects(f.assessment.runAttempt(input));assert.equal(f.retries,1);});
test('reply publication reads the scoped shop mode before any Judge retry',async()=>{const seen=[];const f=fixture({publicationModes:{async getEvaluationScope(owner,key,scope){seen.push({owner,key,scope});return{generation:1,mode:'fixed',modeStamp:'shop-fixed'};}}});const result=await f.assessment.runAttempt({binding:f.b,threadId:5,requestId:randomUUID(),evaluationId:randomUUID()});assert.equal(result.status,'ineligible');assert.deepEqual(seen,[{owner:f.b.scope.platformOwnerId,key:'secureshop_agent_security',scope:f.b.scope}]);assert.equal(f.retries,0);});
