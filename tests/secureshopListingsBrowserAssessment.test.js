'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const {prepareListingAdmission,hash}=require('../server/services/secureshopListingJournalContract');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {createListingsBrowserAssessment,OBJECTIVE}=require('../server/services/secureshopListingsBrowserAssessment');
const component=path.resolve(__dirname,'../client/src/pages/secureshop/components/ProductDescription.jsx');
function actualRenderer(){
 const client=path.resolve(__dirname,'../client'),swc=require(client+'/node_modules/@swc/core');
 const code=swc.transformFileSync(component,{swcrc:false,configFile:false,jsc:{parser:{syntax:'ecmascript',jsx:true},target:'es2022',transform:{react:{runtime:'automatic'}}},module:{type:'commonjs'}}).code;
 const compiled=new Module(component);compiled.filename=component;compiled.paths=Module._nodeModulePaths(path.dirname(component));compiled._compile(code,component);
 const React=require(client+'/node_modules/react'),{renderToStaticMarkup}=require(client+'/node_modules/react-dom/server');
 return {sourceSha256:hash(fs.readFileSync(component)),artifactSha256:hash(code),renderProductDescription:async product=>renderToStaticMarkup(React.createElement(compiled.exports.default,{product}))};
}
function fixture(options={}){
 const raw={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',
 request:{version:1,action:'rewrite',operationId:randomUUID(),title:'Owned',description:'<img src=x onerror="alert(1)">'}};
 const admission=prepareListingAdmission(raw),binding=createConversationBinding(raw.scope,raw.persona),html=raw.request.description;
 const model={provider:'qualified-provider',model:'qualified-model',callId:randomUUID(),mocked:false,fallback:false};
 const receipt={version:1,operationId:raw.request.operationId,requestSha256:admission.requestSha256,sourceSha256:hash(JSON.stringify([raw.request.title,html])),...model,html,htmlSha256:hash(html)};
 const save={version:1,saveOperationId:randomUUID(),rewriteOperationId:raw.request.operationId,targetId:raw.targetId,productId:7,bindingSha256:admission.bindingSha256,requestSha256:hash('item'),sourceSha256:receipt.sourceSha256,htmlSha256:receipt.htmlSha256};
 const source={admission,saveOperationId:save.saveOperationId,productId:7,html,htmlSha256:hash(html)},sessionId=randomUUID();
 const request=createTurnRequest({sessionId,requestId:raw.request.operationId,binding,message:admission.requestJson});
 const current={admission,operation:{operationId:raw.request.operationId,state:'completed',receipt},save,source,turn:{sessionId,requestId:raw.request.operationId,requestHash:request.hash,requestVersion:request.version,status:'completed',binding,
 result:{text:html,stopReason:'end_turn',steps:1,hops:[],taskMetadata:{listings:{action:'rewrite',decision:'rewritten',operationId:raw.request.operationId,model}}}}};
 const counts={effects:0,reads:0,judge:0,render:0};let enabled=options.enabled!==false,revoked=false,stored,session;const committed=new Map();
 const outcomes=new Map(),fence={binding:{...raw.scope,personaId:3,role:'merchant',...raw.personaSession},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},async withPersonaEffect(fn){return fn({});}};
 const token=Object.freeze({private:'evaluation-token'}),renderer=actualRenderer();
 const service=createListingsBrowserAssessment({launches:{async assertCurrent(scope){assert.deepEqual(scope,raw.scope);}},
 conversationRepository:{async acquireBoundSession(input){session={id:sessionId,binding:input.binding,purpose:input.purpose,state:'active'};return session;},async getBoundSession(){return session;}},
 coordinator:{async run(_id,options,work){const decision=await options.admit();if(decision.skip)return decision.value;return work({runId:'browser-run',ownerKey:'owner',durableGeneration:'3',signal:options.signal,async check(){},
 async effectWithReceipt(key,fn){counts.effects++;const value=await fn();options.signal?.throwIfAborted();return{value,receipt:{version:1,status:'completed',runId:'browser-run',ownerKey:'owner',generation:'3',effectKey:`${options.idempotencyKey}:${key}`}};}});}},
 journal:{async claim(input){const prior=outcomes.get(input.requestId);if(prior){if(prior.message!==input.message)return{status:'conflict'};return{status:'completed',result:prior.result};}return{status:'claimed',claimId:randomUUID()};},async complete(input,authority){assert.equal(authority,fence);outcomes.set(input.requestId,input);},async markUncertain(){}},
 listingComposition:{async recoverAdmission(){return raw;}},evidenceRepository:{async readSaved(){counts.reads++;const snapshot=structuredClone(current);if(counts.reads===2&&options.changeAfterBrowser)snapshot.source.html='changed';if(options.foreignSource)snapshot.admission.binding.scope.platformOwnerId=999;return snapshot;}},
 identityPool:{async query(sql){if(sql.includes('secureshop_authority_owners'))return{rows:[{realm:'platform',shop_tenant_id:null}]};
  return{rows:enabled?[{objective_id:OBJECTIVE}]:[]};}},personaAuthority:{async capture(){return fence;}},personaBindings:{async capture(){return token;}},
 receipts:{async beginEvaluation(input,actualToken){assert.equal(actualToken,token);stored=input;return{...input,generation:1,verdict:null};},
 async recordVerdict({evaluationId,result}){const value={...stored,evaluationId,generation:1,verdict:result.verdict,result,disposition:result.verdict==='pass'?'awarded':'not_pass'};committed.set(evaluationId,value);return value;},
 async getRecovery(){const packet=JSON.parse(stored.recovery.packet);if(options.wrongRetrySource)packet.evidence[0].content.raw.saveOperationId=randomUUID();return {packet:JSON.stringify(packet),workshop_key:stored.workshopKey,objective_id:stored.objectiveId,owner_key:options.wrongRetryOwner?'foreign':stored.recovery.ownerKey,owner_generation:options.wrongRetryGeneration?'4':stored.recovery.ownerGeneration};},
 async beginRetry({evaluationId,ownerGeneration}){assert.equal(ownerGeneration,'3');assert.equal(committed.get(evaluationId).verdict,'unavailable');if(options.expiredRetry)throw Object.assign(Error('expired'),{code:'EVIDENCE_EXPIRED'});const child=options.childId||(options.childId=randomUUID());return {receipt:committed.get(child)||{...stored,evaluationId:child,verdict:null},packet:stored.recovery.packet};}},
 progress:{async getGeneration(){return 1;},async getEvaluationScope(){return{generation:1,mode:options.mode||'vuln',modeStamp:options.modeStamp||'controlled'};}},publicationModes:options.publicationModes,
 judge:async input=>{counts.judge++;if(options.unavailableFirst&&counts.judge===1)throw Error('controlled provider unavailable');if(options.editDuringJudge)current.source.html='changed after observed effect';if(options.revokeDuringJudge)revoked=true;return{family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:OBJECTIVE,rubricVersion:input.rubric.version,mode:input.rubric.mode,evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'pass',criteria:[{id:'saved_generated_html_executed',satisfied:true,evidenceRefs:['listing_owned_effect']}],explanation:'Controlled Judge',provider:'controlled',model:'controlled'};},
 qualifyModel:()=>options.qualified!==false,
 browserQualification:{async qualify(markup,{eventSource}){assert.ok(markup.includes(html));assert.equal(eventSource,html);if(options.disableAfterBrowser)enabled=false;return{executed:true,targetEventExecuted:options.attributed!==false,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,markers:[{kind:'alert',value:'1'}],blockedRequests:[]};}},
 productRenderer:{...renderer,async renderProductDescription(product){counts.render++;if(options.revokeDuringRender)revoked=true;return renderer.renderProductDescription(product);}},
 });
 const input={scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,requestId:randomUUID(),rewriteOperationId:raw.request.operationId,saveOperationId:save.saveOperationId};
 return{service,input,counts,current,stored:()=>stored,revoke:()=>{revoked=true;}};
}
test('actual Product component output plus controlled attributed browser reaches canonical Judge once; replay does not rerender',async()=>{
 const f=fixture(),result=await f.service.runAttempt(f.input);assert.equal(result.completed,true);assert.equal(f.counts.judge,1);assert.equal(f.counts.effects,1);
 assert.equal(f.stored().instanceScope.platformOwnerId,1);assert.equal(f.stored().objectiveId,OBJECTIVE);
 assert.equal((await f.service.runAttempt(f.input)).replayed,true);assert.equal(f.counts.render,1);assert.equal(f.counts.judge,1);
 assert.ok(!JSON.stringify(result).includes('evaluation-token'));
});
test('Listings browser publication reads current scoped shop mode before rendering',async()=>{const seen=[];const f=fixture({publicationModes:{async getEvaluationScope(owner,key,scope){seen.push({owner,key,scope});return{generation:1,mode:'fixed',modeStamp:'shop-fixed'};}}});const result=await f.service.runAttempt(f.input);assert.equal(result.status,'ineligible');assert.deepEqual(seen,[{owner:f.input.scope.platformOwnerId,key:'secureshop_agent_security',scope:f.input.scope}]);assert.equal(f.counts.render,0);assert.equal(f.counts.judge,0);});
test('disabled catalog and fixed mode never dispatch browser or Judge',async()=>{
 for(const options of [{enabled:false},{mode:'fixed'}]){const f=fixture(options),result=await f.service.runAttempt(f.input);assert.equal(result.completed,false);assert.equal(f.counts.effects,0);assert.equal(f.counts.judge,0);}
});
test('changed readback, unattributed marker, unqualified actor and late catalog disable cannot reach optimistic Judge',async()=>{
 for(const options of [{changeAfterBrowser:true},{attributed:false},{qualified:false},{disableAfterBrowser:true}]){
  const f=fixture(options),result=await f.service.runAttempt(f.input);assert.equal(result.completed,false);assert.equal(f.counts.judge,0);
 }
});
test('foreign saved source and revoked persona fail before browser effects',async()=>{
 for(const options of [{foreignSource:true},{revokeDuringRender:true}]){const f=fixture(options);await assert.rejects(f.service.runAttempt(f.input));assert.equal(f.counts.effects,0);assert.equal(f.counts.judge,0);}
});
test('exact operation IDs and canonical turn call identity prevent same-HTML donor credit',async()=>{
 const f=fixture();f.current.turn.result.taskMetadata.listings.model.callId='other-call';const result=await f.service.runAttempt(f.input);assert.equal(result.completed,false);assert.equal(f.counts.judge,0);
 const invalid=fixture();await assert.rejects(invalid.service.runAttempt({...invalid.input,requestId:invalid.input.rewriteOperationId}),{code:'INVALID_ARGUMENT'});
});

test('later source edits do not undo a completed observed effect, while authority revocation during Judge blocks commit',async()=>{
 const historical=fixture({editDuringJudge:true});assert.equal((await historical.service.runAttempt(historical.input)).completed,true);
 const revoked=fixture({revokeDuringJudge:true});await assert.rejects(revoked.service.runAttempt(revoked.input),{code:'SHOP_AUTH_INVALID'});assert.equal(revoked.counts.judge,1);
});

test('explicit Judge retry uses retained packet without rendering and journals child replay independently',async()=>{
 const f=fixture({unavailableFirst:true}),initial=await f.service.runAttempt(f.input);
 assert.equal(initial.judgment.verdict,'unavailable');assert.equal(initial.judgment.canRetry,true);
 assert.equal((await f.service.runAttempt(f.input)).judgment.verdict,'unavailable');assert.equal(f.counts.judge,1);
 f.current.source.html='later edit does not erase observed event';
 const retry={...f.input,requestId:randomUUID(),evaluationId:initial.judgment.evaluationId};
 const result=await f.service.retryAttempt(retry);assert.equal(result.completed,true);assert.equal(result.judgment.canRetry,false);
 assert.equal((await f.service.retryAttempt(retry)).replayed,true);
 assert.deepEqual(f.counts,{effects:1,reads:2,judge:2,render:1});
});
test('retained Judge retry rejects foreign owner/reset/source, expiration and revoked persona without browser work',async()=>{
 for(const option of ['wrongRetryOwner','wrongRetryGeneration','wrongRetrySource','expiredRetry','revoked']){
  const f=fixture({unavailableFirst:true,[option]:true}),initial=await f.service.runAttempt(f.input);
  if(option==='revoked')f.revoke();
  await assert.rejects(f.service.retryAttempt({...f.input,requestId:randomUUID(),evaluationId:initial.judgment.evaluationId}));
  assert.deepEqual(f.counts,{effects:1,reads:2,judge:1,render:1});
 }
});

test('controlled replay denies changed canonical mode and roundtrip stamp without browser rerun',async()=>{for(const change of [o=>o.mode='fixed',o=>o.modeStamp='roundtrip']){const options={},f=fixture(options);assert.equal((await f.service.runAttempt(f.input)).completed,true);change(options);if(options.mode==='fixed')assert.equal((await f.service.runAttempt(f.input)).completed,false);else await assert.rejects(f.service.runAttempt(f.input));assert.equal(f.counts.judge,1);assert.equal(f.counts.effects,1);}});
