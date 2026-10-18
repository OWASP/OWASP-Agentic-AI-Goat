'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createPersonaProductEffect}=require('../server/services/secureshopPersonaProductEffect');
const {createSystemRebuildTargetResolver}=require('../server/services/secureshopSystemRebuildTarget');
const {normalizeRebuildRequest,rebuildRequestDigest,rebuildBindingDigest,createSecureShopSystemRebuildService}=require('../server/services/secureshopSystemRebuildService');
const id='11111111-1111-4111-8111-111111111111',op='22222222-2222-4222-8222-222222222222',hash='a'.repeat(64),vector=()=>Array.from({length:384},(_,i)=>i===0?1:0);
const scope={launchId:id,scenarioId:id,generation:1,platformOwnerId:7,platformSessionId:8};
const binding={...scope,targetId:'33333333-3333-4333-8333-333333333333'};
const actor={id:9,role:'admin',sessionId:'44444444-4444-4444-8444-444444444444',authorityVersion:'2'};
test('retained scene rebuild administration and recovery validate current execution separately from birth target',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const birth={...binding,launchId:'55555555-5555-4555-8555-555555555555',platformSessionId:18};
 const scene=createSceneBinding(birth,{sceneId:'66666666-6666-4666-8666-666666666666',sceneGeneration:1,grantId:'77777777-7777-4777-8777-777777777777',execution:scope,withLease:work=>work()});
 const fence={binding:{...scope,personaId:actor.id,role:actor.role,sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}};
 const resolver=createSystemRebuildTargetResolver({launches:{async assertCurrent(){},readExistingProductsTarget(){assert.fail('No legacy target fallback');}},products:{async open(value){assert.equal(value,scene);return value;}},scenes:{async readExisting(){return scene;}},personaAuthority:{async capture(){return fence;}}});
 let reads=0,admissions=0,override;
 const service=createSecureShopSystemRebuildService({resolveTarget:async input=>override||resolver(input),journal:{async begin(value){admissions++;assert.equal(value.binding,scene);return{kind:'replay',result:{state:'completed'}};},async read(value){reads++;assert.equal(value.binding,scene);return{state:'completed'};},async complete(){assert.fail('No new publication');},async markFailed(){},async abandon(){}},revisionRepository:{publishInTransaction(){}},embedder:{getRuntimeFingerprint:()=>({fingerprint:hash}),async embed(){assert.fail('No embedding during read/replay');}},checkCurrent:async()=>{}});
 const input={scope,persona:{id:actor.id,role:actor.role},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion}};
 assert.equal((await service.administration(input)).rebuildCapability,'secureshop-owned-system-rebuild.v1');
 assert.equal((await service.read({...input,operationId:op})).state,'completed');
 assert.equal((await service.execute({...input,request:{version:1,operationId:op,corpus:'products'}})).state,'completed');
 assert.equal(reads,1);assert.equal(admissions,1);
 const valid=await resolver(input);
 for(const key of ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']){
  const foreign={...scope,[key]:typeof scope[key]==='number'?scope[key]+1:op};
  await assert.rejects(service.administration({...input,scope:foreign}));
 }
 for(const change of [{id:actor.id+1},{sessionId:op},{authorityVersion:'3'},{role:'merchant'}]){
  override={...valid,actor:{...valid.actor,...change}};
  await assert.rejects(service.administration(input),{code:'SHOP_AUTH_INVALID'});
 }
 override={...valid,binding:structuredClone(scene)};
 await assert.rejects(service.administration(input),{code:'SHOP_AUTH_INVALID'});
 assert.equal(reads,1);assert.equal(admissions,1);
});
function fixture({completeMode='ok',embedError=null}={}){
 let state=null,embeds=0,beginCalls=0,completeCalls=0,failed=0,abandoned=0,publication;
 const fence={binding:{...scope,personaId:actor.id,role:'admin',sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){try{return await work(this.binding);}catch(cause){throw Object.assign(Error('Persona effect outcome is uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',cause});}}};
 const personaEffect=createPersonaProductEffect(fence);
 const snapshot={operationMode:'selective',sourceSetDigest:hash,expectedHead:id,baseRevisionId:id,currentRuntimeFingerprint:hash,documents:[{sourceKind:'product',sourceId:'1',chunkIndex:0,text:'selected product',sourceSha256:hash,embedding:null},{sourceKind:'manual',sourceId:'2',chunkIndex:0,text:'retained manual',sourceSha256:hash,embedding:vector()}]};
 const completed=()=>Object.freeze({ok:true,operationId:op,corpus:'products',targetId:binding.targetId,generation:1,state:'completed',replayed:true,revisionId:op,sourceSetDigest:hash,vectorDigest:hash,documentCount:2});
 const journal={
  async begin(){beginCalls++;if(state)return{kind:'replay',result:state};state={ok:false,operationId:op,corpus:'products',targetId:binding.targetId,generation:1,state:'running',replayed:false};return{kind:'worker',handle:Object.freeze({}),snapshot};},
  async complete(_handle,_binding,value){completeCalls++;publication=value;if(completeMode==='committed-loss'){state=completed();throw Error('lost response');}if(completeMode==='unknown')throw Error('connection lost');state=completed();return state;},
  async markFailed(){failed++;state={ok:false,operationId:op,corpus:'products',targetId:binding.targetId,generation:1,state:'failed',failureCode:'EXECUTION_FAILED',replayed:true};return state;},
  async abandon(){abandoned++;},async read(){return state;},
 };
 const service=createSecureShopSystemRebuildService({resolveTarget:async()=>({binding,actor,personaEffect}),journal,revisionRepository:{publishInTransaction(){}},checkCurrent:async()=>{},embedder:{getRuntimeFingerprint:()=>({fingerprint:hash}),async embed(){embeds++;if(embedError)throw embedError;return{embeddingDimension:384,embedding:vector()};}}});
 const input={scope,persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'products'}};
 return{service,input,journal,get:()=>({state,embeds,beginCalls,completeCalls,failed,abandoned,publication})};
}

test('request digest is public while target and original admin bind separately',()=>{
 const request=normalizeRebuildRequest({version:1,operationId:op.toUpperCase(),corpus:'products'}),requestSha256=rebuildRequestDigest(request);
 assert.match(requestSha256,/^[a-f0-9]{64}$/);assert.equal(request.operationId,op);
 const first=rebuildBindingDigest(requestSha256,binding,actor),second=rebuildBindingDigest(requestSha256,{...binding,generation:2},actor);
 assert.notEqual(first,second);assert.equal(rebuildRequestDigest(request),requestSha256);
 assert.equal(normalizeRebuildRequest({version:1,operationId:op,corpus:'policies'}).corpus,'policies');
});

test('first request embeds selected rows once, atomically completes, and replay never computes',async()=>{
 const f=fixture(),result=await f.service.execute(f.input);assert.equal(result.state,'completed');let s=f.get();assert.equal(s.embeds,1);assert.equal(s.completeCalls,1);assert.equal(s.publication.documents.length,2);assert.deepEqual(s.publication.documents[1].embedding,vector());
 const replay=await f.service.execute(f.input);assert.equal(replay.state,'completed');s=f.get();assert.equal(s.embeds,1);assert.equal(s.beginCalls,2);assert.equal(s.completeCalls,1);
 assert.deepEqual(await f.service.read({scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession,operationId:op}),replay);assert.equal(f.get().embeds,1);
});

test('first-index mode embeds the entire admitted snapshot and returns the categorical mode',async()=>{
 let publication,calls=0;const fence={binding:{...scope,personaId:actor.id,role:'admin',sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}},personaEffect=createPersonaProductEffect(fence);
 const snapshot={operationMode:'initialize',sourceSetDigest:hash,expectedHead:null,baseRevisionId:null,currentRuntimeFingerprint:hash,documents:[{sourceKind:'product',sourceId:'7',chunkIndex:0,text:'Fresh product\nowned',sourceSha256:hash,embedding:null}]};
 const journal={async begin(){return{kind:'worker',handle:Object.freeze({}),snapshot};},async complete(_handle,_binding,value){publication=value;return{ok:true,state:'completed',operationMode:'initialize',operationId:op,corpus:'products'};},async markFailed(){assert.fail('initialization must not fail');},async abandon(){},async read(){}};
 const service=createSecureShopSystemRebuildService({resolveTarget:async()=>({binding,actor,personaEffect}),journal,revisionRepository:{publishInTransaction(){}},checkCurrent:async()=>{},embedder:{getRuntimeFingerprint:()=>({fingerprint:hash}),async embed(){calls++;return{embeddingDimension:384,embedding:vector()};}}});
 const result=await service.execute({scope,persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'products'}});
 assert.equal(result.operationMode,'initialize');assert.equal(calls,1);assert.equal(publication.expectedHead,null);assert.equal(publication.documents.length,1);
});

test('administration is original-session scoped and performs no embedding or admission',async()=>{
 const f=fixture();const administration=await f.service.administration({scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession});
 assert.deepEqual(administration,{rebuildCapability:'secureshop-owned-system-rebuild.v1',scopeKey:administration.scopeKey,corpora:['products','reviews','manuals']});
 assert.match(administration.scopeKey,/^[a-f0-9]{64}$/);assert.deepEqual(f.get(),{state:null,embeds:0,beginCalls:0,completeCalls:0,failed:0,abandoned:0,publication:undefined});
 const changed=structuredClone({scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession});changed.personaSession.authorityVersion='3';
 await assert.rejects(f.service.administration(changed),{code:'SHOP_AUTH_INVALID'});
});

test('policy corpus is explicit, captures the current task snapshot, and embeds only policy rows',async()=>{
 const rendered='Owned task policy',renderedSha=require('node:crypto').createHash('sha256').update(rendered).digest('hex');let journalInput,publication,embeds=0;
 const fence={binding:{...scope,personaId:actor.id,role:'admin',sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work(this.binding);}};
 const personaEffect=createPersonaProductEffect(fence),policySource=require('../server/services/secureshopPolicyCorpusSource').createSecureShopPolicyCorpusSource({policyRepository:{async list(){return{version:'3',policies:[{name:'Owned policy',targets:['summarizer'],rendered,renderedSha256:renderedSha}]};}}});
 const captured=await policySource.capture({scope,persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion}});
 const sibling={sourceKind:'product',sourceId:'1',chunkIndex:0,text:'retained product',sourceSha256:hash,embedding:vector()};
 const snapshot={operationMode:'selective',sourceSetDigest:hash,expectedHead:id,baseRevisionId:id,currentRuntimeFingerprint:hash,policySnapshot:captured,documents:[sibling,...captured.documents.map(d=>({...d,sourceId:String(d.sourceId),embedding:null}))]};
 const journal={async begin(value){journalInput=value;return{kind:'worker',handle:Object.freeze({}),snapshot};},async complete(_handle,_binding,value){publication=value;return{ok:true,state:'completed',operationMode:'selective',operationId:op,corpus:'policies'};},async markFailed(){assert.fail('policy rebuild must not fail');},async abandon(){},async read(){}};
 const service=createSecureShopSystemRebuildService({resolveTarget:async()=>({binding,actor,personaEffect}),journal,revisionRepository:{publishInTransaction(){}},policySource,checkCurrent:async()=>{},embedder:{getRuntimeFingerprint:()=>({fingerprint:hash}),async embed(text){embeds++;assert.equal(text,rendered);return{embeddingDimension:384,embedding:vector()};}}});
 const input={scope,persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'policies'}};
 assert.deepEqual((await service.administration({scope,persona:input.persona,personaSession:input.personaSession})).corpora,['products','reviews','manuals','policies']);
 const result=await service.execute(input);assert.equal(result.corpus,'policies');assert.deepEqual(journalInput.policySnapshot,captured);assert.equal(embeds,1);assert.deepEqual(publication.documents[0].embedding,vector());assert.deepEqual(publication.documents[1].embedding,vector());
});

test('lost committed reply reconciles through immutable replay without redispatch',async()=>{
 const f=fixture({completeMode:'committed-loss'});await assert.rejects(f.service.execute(f.input),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});assert.equal(f.get().embeds,1);
 const recovered=await f.service.execute(f.input);assert.equal(recovered.state,'completed');assert.equal(f.get().embeds,1);assert.equal(f.get().completeCalls,1);
});

test('unknown publication remains running and replay never infers no effect',async()=>{
 const f=fixture({completeMode:'unknown'});await assert.rejects(f.service.execute(f.input),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});assert.equal(f.get().state.state,'running');assert.equal(f.get().abandoned,1);
 const replay=await f.service.execute(f.input);assert.equal(replay.state,'running');assert.equal(f.get().embeds,1);assert.equal(f.get().completeCalls,1);
});

test('definitive prepublication failure records terminal failure once',async()=>{
 const error=Object.assign(Error('encoder unavailable'),{code:'ENCODER_FAILED'}),f=fixture({embedError:error});await assert.rejects(f.service.execute(f.input),error);assert.equal(f.get().failed,1);assert.equal(f.get().state.state,'failed');
 const replay=await f.service.execute(f.input);assert.equal(replay.state,'failed');assert.equal(f.get().embeds,1);assert.equal(f.get().failed,1);
});

test('service composes the real target resolver with copied admin authority and operation-only recovery',async()=>{
 let captured,reads=0;
 const launches={async assertCurrent(){},async readExistingProductsTarget(){return{...scope,kind:'products',targetId:binding.targetId};}};
 const products={async open(value){return{...value};}};
 const personaAuthority={async capture(value){captured=structuredClone(value);return{binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}};}};
 const resolveTarget=createSystemRebuildTargetResolver({launches,products,personaAuthority});
 const journal={async begin(){return{kind:'replay',result:{state:'running'}};},async complete(){},async markFailed(){},async abandon(){},async read(value){reads++;assert.deepEqual(Object.keys(value).sort(),['actor','binding','operationId']);return{state:'running',operationId:value.operationId};}};
 const service=createSecureShopSystemRebuildService({resolveTarget,journal,revisionRepository:{publishInTransaction(){}},checkCurrent:async()=>{},embedder:{getRuntimeFingerprint:()=>({fingerprint:hash}),async embed(){assert.fail('replay must not embed');}}});
 const mutable={scope:{...scope},persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'products'}};
 assert.equal((await service.execute(mutable)).state,'running');assert.equal(captured.personaId,actor.id);assert.equal(captured.role,'admin');
 const result=await service.read({scope:mutable.scope,persona:mutable.persona,personaSession:mutable.personaSession,operationId:op});assert.equal(result.operationId,op);assert.equal(reads,1);
});
test('service rejects a resolver that substitutes the captured actor',async()=>{
 const personaEffect=createPersonaProductEffect({binding:{...scope,personaId:actor.id,role:'admin',sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}});
 const service=createSecureShopSystemRebuildService({resolveTarget:async()=>({binding,actor:{...actor,id:10},personaEffect}),journal:{begin(){},read(){},complete(){},markFailed(){},abandon(){}},revisionRepository:{publishInTransaction(){}},checkCurrent:async()=>{},embedder:{embed(){},getRuntimeFingerprint(){}}});
 await assert.rejects(service.execute({scope,persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'products'}}),{code:'SHOP_AUTH_INVALID'});
});
test('service snapshots caller authority and request before the resolver yields',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;}),seen=[];
 const personaEffect=createPersonaProductEffect({binding:{...scope,personaId:actor.id,role:'admin',sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}});
 const service=createSecureShopSystemRebuildService({resolveTarget:async value=>{seen.push(value);await gate;return{binding,actor,personaEffect};},journal:{async begin(value){seen.push(value);return{kind:'replay',result:{state:'running'}};},read(){},complete(){},markFailed(){},abandon(){}},revisionRepository:{publishInTransaction(){}},checkCurrent:async()=>{},embedder:{embed(){},getRuntimeFingerprint(){}}});
 const raw={scope:{...scope},persona:{id:actor.id,role:'admin'},personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},request:{version:1,operationId:op,corpus:'products'}},pending=service.execute(raw);raw.scope.generation=2;raw.persona.id=10;raw.personaSession.authorityVersion='3';raw.request.corpus='reviews';release();assert.equal((await pending).state,'running');assert.equal(seen[0].scope.generation,1);assert.equal(seen[0].persona.id,actor.id);assert.equal(seen[1].request.corpus,'products');
});
