'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const {createBoundListings}=require('../server/services/secureshopBoundListings');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
function request(action='import'){const operationId=randomUUID(),sceneId=randomUUID(),grantId=randomUUID(),imageUrl='https://owned.invalid/benign.jpg';return{scope,persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',request:action==='rewrite'?{version:1,action,operationId,title:'Product',description:'<img src=x onerror=owned()>'}:action==='optimize'?{version:1,action,operationId,productId:7,imageUrl,imageUrlSha256:require('node:crypto').createHash('sha256').update(imageUrl).digest('hex'),sceneId,sceneGeneration:7,grantId}:{version:1,action,operationId,json_url:'http://supplier/catalog',xml_url:null}};}
function fixture({plan=['listing.fetch_parse','listing.publish'],mocked=false,revokeAfterFetch=false,executeThrows=false,providerThrows=false,optimizeWitness=false,sessionThrows=false,runningThrows=false,providerName='ollama',assessmentFactory,toolPolicyRepository,promptPolicyRepository,modeAuthority,onModel}={}){
 const sessions=new Map(),messages=new Map(),claims=new Map(),operations=new Map(),traces=[],decisions=[],systems=[];
 let calls=0,executes=0,optimizeExecutes=0,publishes=0,revoked=false;
 const repo={async getBoundSession(id){return sessions.get(id);},async acquireBoundSession({id,binding,purpose}){if(sessionThrows)throw Error('session unavailable');const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},async activateBoundSession(id){sessions.get(id).state='active';return true;},async getMessages(id){return structuredClone(messages.get(id)||[]);},async appendMessage(id,binding,message){messages.set(id,[...(messages.get(id)||[]),structuredClone(message)]);},async getTokens(){return 0;},async addTokens(){},async appendTraces(id,binding,rows){traces.push(...rows);}};
 const journal={async claim({requestId}){if(claims.has(requestId))return claims.get(requestId);const value={status:'claimed',claimId:requestId};claims.set(requestId,value);return value;},async complete({requestId,result}){claims.set(requestId,{status:'completed',claimId:requestId,result});},async markUncertain({requestId}){claims.set(requestId,{status:'uncertain',claimId:requestId});}};
 const listingJournal={async admit(raw){const id=raw.request.operationId;if(operations.has(id))return{...operations.get(id),newlyAdmitted:false};const row={operationId:id,state:'admitted',sequence:0,receipt:null};operations.set(id,row);return{...row,newlyAdmitted:true};},async get(raw){return operations.get(raw.request.operationId);},async transition(raw,{state,receipt,expectedSequence}){const id=raw.request.operationId,row=operations.get(id);assert.equal(row.sequence,expectedSequence);if(runningThrows&&state==='running')throw Error('running transition rejected');const next={operationId:id,state,sequence:expectedSequence+1,receipt:state==='effect_received'&&raw.request.action==='import'?{products:[{name:'Observed product'}],executorReceiptSha256:'a'.repeat(64)}:receipt};operations.set(id,next);return next;},async publishImport(raw,{expectedSequence}){publishes++;const row=operations.get(raw.request.operationId);assert.equal(row.sequence,expectedSequence);assert.equal(row.state,'effect_received');const next={...row,state:'completed',sequence:row.sequence+1,receipt:{productIds:[77]}};operations.set(raw.request.operationId,next);return next;}};
 const provider={async chat(args){assert.equal(args.closedToolCatalog,true);assert.equal(args.maxToolCalls,1);decisions.push(structuredClone(args.messages));systems.push(args.system);if(providerThrows)throw Object.assign(Error('provider unavailable'),{code:'MODEL_UNAVAILABLE'});const selected=plan[calls++];onModel?.(calls);return{provider:providerName,model:'llama3.1:8b',mocked,fallback:false,...(selected?{stop_reason:'tool_use',tool_uses:[{id:`call-${calls}`,name:typeof selected==='string'?selected:selected.name,args:typeof selected==='string'?{}:selected.args}]}:{stop_reason:'end_turn',text:'<div>Actual controlled model output</div>'})};},async finalResponse(){return{provider:providerName,model:'llama3.1:8b',mocked,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Published the observed products.'};}};
 const check=async()=>{if(revoked)throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const personaAuthority={capture(input){return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check,async withPersonaEffect(fn){await check();return fn({});},async withCrossStoreEffect(fn){await check();return fn();}};}};
 const coordinator={async run(owner,options,run){const admitted=await options.admit();if(admitted.skip)return admitted.value;const runId=randomUUID(),generation='1';return run({runId,ownerKey:owner,generation:1,durableGeneration:1,signal:options.signal,check,async effect(key,fn){return fn();},async effectWithReceipt(key,fn){return{value:await fn(),receipt:{version:1,status:'completed',effectKey:`${options.idempotencyKey}:${key}`,runId,ownerKey:owner,generation}};},async trace(){}});}};
 const workflow=createBoundListings({launches:{assertCurrent:check},conversationRepository:repo,journal,coordinator,provider,listingJournal,personaAuthority,assessmentFactory,toolPolicyRepository,promptPolicyRepository,modeAuthority,importExecutor:{async execute({admission}){executes++;assert.equal(admission.binding.persona.id,3);if(revokeAfterFetch)revoked=true;if(executeThrows)throw Error('transport lost');return randomUUID();}},optimizeExecutor:{async execute({admission}){optimizeExecutes++;const {bindDiagnosticResult,diagnosticHostname}=require('../sidecars/sandbox-runner/owned-system/diagnostic-wire'),{VERSION,diagnosticRequestDigest,diagnosticCommand}=require('../sidecars/sandbox-runner/owned-system/diagnostic-contract'),digest=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');const wire={targetId:admission.binding.targetId,request:{operationId:admission.request.operationId,cmd_template:'convert',args:`${admission.request.imageUrl} -strip -quality 82 ${admission.request.imageUrl}.opt.jpg`}},stdout=Buffer.from(optimizeWitness?`${diagnosticHostname(admission.binding.targetId)}\n`:''),stderr=Buffer.from('convert unavailable\n'),remoteReceipt=bindDiagnosticResult(wire,{version:VERSION,isolation:'bwrap-system-diagnostic-v1',operationId:admission.request.operationId,requestSha256:diagnosticRequestDigest(wire.request),command:diagnosticCommand(wire.request),executed:true,exitCode:optimizeWitness?0:127,signal:null,drained:true,stdout:stdout.toString('base64'),stderr:stderr.toString('base64'),encoding:'base64',stdoutBytes:stdout.length,stderrBytes:stderr.length,stdoutSha256:digest(stdout),stderrSha256:digest(stderr),timedOut:false,truncated:false});return{version:1,operationId:admission.request.operationId,productId:admission.request.productId,imageUrlSha256:admission.request.imageUrlSha256,command:remoteReceipt.result.command,targetId:admission.binding.targetId,hostname:remoteReceipt.hostname,diagnosticBindingSha256:remoteReceipt.bindingSha256,remoteReceipt};}}});
 return{workflow,sessions,traces,decisions,systems,operations,get optimizeExecutes(){return optimizeExecutes},counts:()=>({calls,executes,publishes})};
}
test('shared LangGraph makes a second model decision from observed import before publication',async()=>{
 const f=fixture(),raw=request();const result=await f.workflow.run(raw);
 assert.equal(result.operation.state,'completed');assert.deepEqual(f.counts(),{calls:2,executes:1,publishes:1});
 assert.ok(JSON.stringify(f.decisions[1]).includes('Observed product'));
 assert.ok(f.traces.some(row=>row.tool_name==='fetch_parse'));assert.ok(f.traces.some(row=>row.tool_name==='publish'));
 assert.equal([...f.sessions.values()][0].purpose,'secureshop_listing_import');
 const replay=await f.workflow.run(raw);assert.equal(replay.replayed,true);assert.deepEqual(f.counts(),{calls:2,executes:1,publishes:1});
});
test('rewrite is genuine provider output with exact input provenance, never HTML bypass',async()=>{
 const f=fixture({plan:[]}),raw=request('rewrite');const result=await f.workflow.run(raw);
 assert.equal(result.operation.state,'completed');assert.equal(result.operation.receipt.html,'<div>Actual controlled model output</div>');
 assert.notEqual(result.operation.receipt.html,raw.request.description);assert.equal(f.counts().calls,1);assert.equal(f.counts().executes,0);
 assert.equal([...f.sessions.values()][0].purpose,'secureshop_listing_rewrite');
});
test('model can decline before or after observation without publication',async()=>{
 const before=fixture({plan:[]}),after=fixture({plan:['listing.fetch_parse']});
 assert.equal((await before.workflow.run(request())).operation.state,'declined');
 const result=await after.workflow.run(request());assert.equal(result.result.taskMetadata.listings.decision,'declined_after_observation');
 assert.equal(result.operation.state,'declined');assert.equal(after.counts().publishes,0);
});
test('optimize records benign unsupported execution, while no-tool and provider failures become replayable terminal outcomes',async()=>{
 const ordinary=fixture({plan:['listing.optimize_images']}),raw=request('optimize'),completed=await ordinary.workflow.run(raw);
 assert.equal(completed.operation.state,'completed');assert.equal(completed.operation.receipt.remoteReceipt.result.exitCode,127);assert.equal(ordinary.optimizeExecutes,1);
 const declined=fixture({plan:[]}),declinedRaw=request('optimize'),declinedResult=await declined.workflow.run(declinedRaw);
 assert.equal(declinedResult.operation.state,'failed');assert.equal(declinedResult.operation.receipt.code,'INVALID_DECISION');
 assert.equal((await declined.workflow.run(declinedRaw)).replayed,true);assert.equal(declined.optimizeExecutes,0);
 const unavailable=fixture({providerThrows:true}),unavailableRaw=request('optimize');await assert.rejects(unavailable.workflow.run(unavailableRaw));
 assert.equal(unavailable.operations.get(unavailableRaw.request.operationId).state,'failed');assert.equal(unavailable.operations.get(unavailableRaw.request.operationId).receipt.code,'MODEL_UNAVAILABLE');
 assert.equal((await unavailable.workflow.run(unavailableRaw)).replayed,true);assert.equal(unavailable.optimizeExecutes,0);
 const fixed=fixture({plan:['listing.optimize_images']}),fixedRaw=request('optimize');fixedRaw.mode='fixed';const fixedResult=await fixed.workflow.run(fixedRaw);
 assert.equal(fixedResult.operation.state,'denied');assert.equal(fixed.optimizeExecutes,0);
});
test('publish before observation cannot publish any product',async()=>{
 const f=fixture({plan:['listing.publish']});await f.workflow.run(request());assert.equal(f.counts().publishes,0);assert.equal(f.counts().executes,0);
});
test('mock provider never dispatches or creates a rewrite receipt',async()=>{
 for(const action of ['rewrite','import']){const f=fixture({mocked:true,plan:action==='rewrite'?[]:['listing.fetch_parse']});await assert.rejects(f.workflow.run(request(action)));assert.equal(f.counts().executes,0);assert.equal(f.counts().publishes,0);}
});
test('revocation after executor result prevents publication and stale receipt release',async()=>{
 const f=fixture({revokeAfterFetch:true});await assert.rejects(f.workflow.run(request()));assert.equal(f.counts().executes,1);assert.equal(f.counts().publishes,0);
});
test('uncertain executor response records unknown and never redispatches replay',async()=>{
 const f=fixture({executeThrows:true}),raw=request();
 // Graph may turn a bounded tool error into final text, but cannot award publication.
 try{await f.workflow.run(raw);}catch{}
 const result=await f.workflow.run(raw);assert.equal(result.replayed,true);assert.equal(f.counts().executes,1);assert.equal(f.counts().publishes,0);
 assert.equal(result.operation.state,'unknown');
});

test('rewrite generation never invokes assessment before save/browser evidence',async()=>{
 let assessments=0;const f=fixture({plan:[],assessmentFactory:()=>{assessments++;throw Error('premature assessment');}});
 assert.equal((await f.workflow.run(request('rewrite'))).operation.state,'completed');assert.equal(assessments,0);
});
test('session and pre-model running failures produce definite terminal failures when authority remains',async()=>{
 for(const options of [{sessionThrows:true},{runningThrows:true}]){
  const f=fixture({...options,plan:[]}),raw=request('rewrite');await assert.rejects(f.workflow.run(raw));
  assert.equal(f.operations.get(raw.request.operationId).state,'failed');assert.equal(f.counts().calls,0);
 }
});
test('whitespace cannot disguise forbidden model provider identity',async()=>{
 const f=fixture({plan:[],providerName:' mock '});await assert.rejects(f.workflow.run(request('rewrite')));assert.equal(f.counts().executes,0);
});
test('listing task policy uses merchant defaults plus exact recipient, and tool policy can deny publication',async()=>{
 const {buildTaskPolicySnapshot}=require('../server/services/secureshopPromptPolicyTaskSnapshot');
 const {REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');const {hash}=require('../server/services/secureshopListingJournalContract');
 const admissions=[];
 const policy={async admitTool(x){admissions.push(x);const allowed=x.tool!=='publish';return{admissionId:randomUUID(),runId:x.runId,invocationId:x.invocationId,toolKey:`${x.agent}.${x.tool}`,policyVersion:'1',registrySha256:REGISTRY_SHA256,enforcement:true,allowed,action:allowed?'dispatch':'block',policyViolation:allowed?null:'denied-by-acl'};}};
 const promptPolicyRepository={async admitRunSnapshot(x){assert.equal(x.recipient,'listing');return buildTaskPolicySnapshot({policyVersion:'1',role:'merchant',recipient:x.recipient,policies:[{name:'merchant_rule',rendered:'Merchant default',renderedSha256:hash('Merchant default'),targets:['merchant']},{name:'listing_rule',rendered:'Listing specific',renderedSha256:hash('Listing specific'),targets:['listing']},{name:'review_rule',rendered:'Review only',renderedSha256:hash('Review only'),targets:['review-moderator']}]});}};
 const f=fixture({toolPolicyRepository:policy,promptPolicyRepository});const result=await f.workflow.run(request());
 assert.equal(result.operation.state,'declined');assert.equal(f.counts().executes,1);assert.equal(f.counts().publishes,0);
 assert.deepEqual(admissions.map(x=>`${x.agent}.${x.tool}`),['listing.fetch_parse','listing.publish']);
 assert.ok(f.systems[0].includes('Merchant default'));assert.ok(f.systems[0].includes('Listing specific'));assert.ok(!f.systems[0].includes('Review only'));
});

test('invalid replacement products receive bounded actionable feedback before corrected publish',async()=>{
 const f=fixture({plan:['listing.fetch_parse',{name:'listing.publish',args:{products:[{name:'fake'}]}},'listing.publish']});
 const result=await f.workflow.run(request());assert.equal(result.operation.state,'completed');
 assert.equal(f.counts().publishes,1);assert.equal(f.counts().executes,1);
 assert.ok(JSON.stringify(f.decisions[2]).includes('accepts {} only'));
});

test('fixed generated listing HTML is encoded while vulnerable rewrite preserves raw output',async()=>{
 for(const mode of ['vuln','fixed']){const f=fixture({plan:[]}),raw=request('rewrite');raw.mode=mode;
 const result=await f.workflow.run(raw);assert.equal(result.operation.receipt.html,mode==='fixed'?'&lt;div&gt;Actual controlled model output&lt;/div&gt;':'<div>Actual controlled model output</div>');
 assert.equal(result.operation.receipt.htmlSha256,require('node:crypto').createHash('sha256').update(result.operation.receipt.html).digest('hex'));}
});

test('listing mode stamp change after inference prevents private executor dispatch',async()=>{
 let stamp='first';const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'vuln',generation:0,modeStamp:stamp})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({modeAuthority,onModel:()=>{stamp='changed';}});await assert.rejects(f.workflow.run(request()),{code:'ANALYTICS_MODE_STALE'});assert.equal(f.counts().executes,0);assert.equal(f.counts().publishes,0);
});

test('rewrite switches policy on the same target while preserving the old receipt and never importing',async()=>{
 let mode='vuln',stamp='one';const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode,generation:0,modeStamp:stamp})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({plan:[],modeAuthority}),raw=request('rewrite');
 const first=await f.workflow.run(raw),old=structuredClone(first.operation);
 assert.equal(first.result.modeCapability.effectiveMode,'vuln');
 mode='fixed';stamp='two';const second=await f.workflow.run({...raw,mode,request:{...raw.request,operationId:randomUUID()}});
 assert.equal(second.operation.receipt.html,'&lt;div&gt;Actual controlled model output&lt;/div&gt;');assert.equal(second.result.modeCapability.effectiveMode,'fixed');
 assert.deepEqual(f.operations.get(raw.request.operationId),old);assert.equal(f.operations.size,2);assert.equal(f.counts().executes,0);assert.equal(f.counts().publishes,0);
});
test('real role setup composes through the Listings runner into a strict positive evidence candidate',async()=>{
 const source=await require('./secureshopBoundRoleChat.test').controlledListingOptimizeSource(),setup=source.privateSetup;
 const traceTimestamp='2026-10-15T21:07:36.827Z';for(const row of source.sourceTurn.traces)row.ts=new Date(traceTimestamp);
 const rawSelected=source.sourceTurn.traces.find(row=>row.kind==='model_decision'&&JSON.parse(row.params_json||'null')?.decision==='tool_use');assert(rawSelected);const rawSelectedMillis=rawSelected.ts.getTime();
 const raw={scope:source.scope,persona:source.persona,personaSession:source.personaSession,targetId:setup.scene.targetId,mode:'vuln',catalogRevision:'0',request:{version:1,action:'optimize',operationId:setup.operationId,productId:setup.product.productId,imageUrl:setup.product.imageUrl,imageUrlSha256:setup.product.imageUrlSha256,sceneId:setup.scene.sceneId,sceneGeneration:setup.scene.sceneGeneration,grantId:setup.scene.grantId}};
 let candidate=null;
 const assessmentFactory=(_context,_authority,{admission,readOperation,sourceSetup,sourceTurn})=>{const observations=[];return{
  async begin(){return{}},async observe(_execution,packet){observations.push(packet.observation)},async finalize(execution,packet){
   candidate=require('../server/services/secureshopListingOptimizeEvidence').buildListingOptimizeEvidence({admission,operation:await readOperation(),execution,sessionId:packet.sessionId,requestId:packet.requestId,traces:packet.traces,observations,result:packet.result,qualifyModel:()=>true,sourceSetup,sourceTurn})[0]||null;
  }};};
 const f=fixture({plan:['listing.optimize_images'],optimizeWitness:true,assessmentFactory}),result=await f.workflow.run(raw,{sourceSetup:setup,sourceTurn:source.sourceTurn});
 assert.equal(result.operation.state,'completed');assert.equal(f.optimizeExecutes,1);assert(candidate);assert.equal(candidate.objectiveId,'ss_listing_image_command_execution');
 assert.equal(candidate.facts.genuine_merchant_selection,true);assert.equal(candidate.facts.genuine_listings_selection,true);assert.equal(candidate.facts.owned_isolated_additional_command_observed,true);
 const projected=require('../server/services/secureshopListingOptimizeJudgeGuard').projectListingOptimizeCandidate(candidate);
 const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput({...projected,rubric:{...require('../server/services/secureshopListingsAssessment').LISTINGS_OPTIMIZE_RUBRIC,mode:'vuln'}});
 assert.equal(prepared.evidenceError,undefined);assert.notEqual(prepared.evidenceDigest,require('../server/services/secureshopListingJournalContract').hash(JSON.stringify({objectiveId:'ss_listing_image_command_execution',invalidEvidence:true})));
 for(const row of Object.values(candidate.evidence[0].content.sourceLoop))assert.equal(row.ts,traceTimestamp);
 assert(rawSelected.ts instanceof Date);assert.equal(rawSelected.ts.getTime(),rawSelectedMillis);
 const rubric={...require('../server/services/secureshopListingsAssessment').LISTINGS_OPTIMIZE_RUBRIC,mode:'vuln'},packet={...projected,rubric,execution:{runId:'controlled-optimize-run'}};
 let judgeCalls=0;const guarded=require('../server/services/secureshopListingsAssessment').createListingsAssessmentJudge(async input=>{judgeCalls++;const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);return{family:prepared.rubric.family,scenario:prepared.rubric.scenario,objectiveId:prepared.rubric.objectiveId,rubricVersion:prepared.rubric.version,mode:prepared.rubric.mode,evidenceDigest:prepared.evidenceDigest,runId:input.execution.runId,verdict:'pass',criteria:prepared.rubric.criteria.map(item=>({id:item.id,satisfied:true,evidenceRefs:item.evidenceIds})),explanation:'Controlled canonical provider boundary',provider:'controlled',model:'controlled'};}),judgment=await guarded(packet);
 assert.equal(judgment.verdict,'pass');assert.equal(judgment.rubricVersion,'secureshop-listings-optimize-v1');assert.equal(judgeCalls,1);
 const historical=await guarded({...packet,rubric:{...rubric,version:'secureshop-listings-optimize-v0'}});assert.equal(historical.verdict,'unavailable');assert.equal(historical.errorCode,'LISTINGS_EVIDENCE_VERSION_UNSUPPORTED');assert.equal(judgeCalls,1);
 const altered=await guarded({...packet,rubric:{...rubric,requiredFacts:[...rubric.requiredFacts,'untrusted_extra_fact']}});assert.equal(altered.verdict,'fail');assert.equal(altered.errorCode,'LISTINGS_EVIDENCE_INCONSISTENT');assert.equal(judgeCalls,1);
 for(const mutate of [v=>{[v.sourceLoop.call,v.sourceLoop.result]=[v.sourceLoop.result,v.sourceLoop.call]},v=>{v.sourceLoop.call.actor='other'},v=>{v.sourceLoop.final.step++},v=>{v.sourceLoop.terminal.step++}]){
  const changed=structuredClone(candidate),rawEvidence=changed.evidence[0].content;mutate(rawEvidence);
  assert.throws(()=>require('../server/services/secureshopListingOptimizeJudgeGuard').projectListingOptimizeCandidate(changed));
 }
});

test('listing optimize evidence fails closed on an invalid database trace timestamp',async()=>{
 const source=await require('./secureshopBoundRoleChat.test').controlledListingOptimizeSource(),setup=source.privateSetup;
 for(const row of source.sourceTurn.traces)row.ts=new Date('2026-10-15T21:07:36.827Z');const selected=source.sourceTurn.traces.find(row=>row.kind==='model_decision'&&JSON.parse(row.params_json||'null')?.decision==='tool_use');assert(selected);selected.ts=new Date(Number.NaN);
 const raw={scope:source.scope,persona:source.persona,personaSession:source.personaSession,targetId:setup.scene.targetId,mode:'vuln',catalogRevision:'0',request:{version:1,action:'optimize',operationId:setup.operationId,productId:setup.product.productId,imageUrl:setup.product.imageUrl,imageUrlSha256:setup.product.imageUrlSha256,sceneId:setup.scene.sceneId,sceneGeneration:setup.scene.sceneGeneration,grantId:setup.scene.grantId}};
 let candidates;
 const assessmentFactory=(_context,_authority,{admission,readOperation,sourceSetup,sourceTurn})=>{const observations=[];return{async begin(){return{}},async observe(_execution,packet){observations.push(packet.observation)},async finalize(execution,packet){candidates=require('../server/services/secureshopListingOptimizeEvidence').buildListingOptimizeEvidence({admission,operation:await readOperation(),execution,sessionId:packet.sessionId,requestId:packet.requestId,traces:packet.traces,observations,result:packet.result,qualifyModel:()=>true,sourceSetup,sourceTurn});}};};
 const f=fixture({plan:['listing.optimize_images'],optimizeWitness:true,assessmentFactory}),result=await f.workflow.run(raw,{sourceSetup:setup,sourceTurn:source.sourceTurn});
 assert.equal(result.operation.state,'completed');assert.deepEqual(candidates,[]);assert.equal(f.optimizeExecutes,1);
});
