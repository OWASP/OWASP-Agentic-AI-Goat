'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {createSceneBinding} = require('../server/services/secureshopSceneBinding');
const reviewScene = require('../server/services/secureshopReviewSceneBinding');
const {createReviewModerationRecovery,reviewRecoveryMetadata,assertReviewRecoveryResult}
  = require('../server/services/secureshopReviewModerationRecovery');
const {createBoundReviewModeration} = require('../server/services/secureshopBoundReviewModeration');
const {createTurnRequestsRepository} = require('../server/database/postgres/secureshopTurnRequestsRepository');
const {createTurnRequest} = require('../server/services/secureshopTurnRequest');
const {createSecureShopBoundReviewRepository} = require('../server/database/postgres/secureshopBoundReviewRepository');
const {createBoundReviewsRouter} = require('../server/routes/secureshop/boundReviews');
const id = n => `${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
const scope = Object.freeze({launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:4,platformSessionId:8});
const persona = Object.freeze({id:5,role:'merchant'});
const personaSession = Object.freeze({sessionId:id(3),authorityVersion:'1'});
const requestId = id(4), binding = {...scope,shopUserId:persona.id,role:persona.role};
function target(generation=1) {
  return reviewScene.attach({...scope,targetId:id(6)},createSceneBinding({...scope,targetId:id(7)},
    {execution:scope,sceneId:id(8),sceneGeneration:generation,grantId:id(9),withLease:work=>work()}));
}
function fixture() {
  const state = {target:target(),mode:{mode:'vuln',generation:1,modeStamp:'mode-1'},row:null,
    revoked:false,launchStale:false,calls:[],runCalls:0};
  const personaAuthority = {capture(input) {
    return {binding:{...scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},
      async assertRemoteAdmission() {state.calls.push('persona');if(state.revoked)throw Object.assign(Error(),{code:'SHOP_AUTH_INVALID'});}};
  }};
  const recovery = createReviewModerationRecovery({personaAuthority,
    async checkCurrent(){state.calls.push('launch');if(state.launchStale)throw Object.assign(Error(),{code:'STALE_LAUNCH'});},
    async readTarget(){state.calls.push('target');return state.target;},
    async readMode(){state.calls.push('mode');return state.mode;}});
  const batches = new WeakMap();
  const journal = {async lookupReviewModerationRequest(input){state.calls.push('lookup');state.lookup=input;await state.onLookup?.();return state.row;}};
  const service = createBoundReviewModeration({recovery,journal,bindRecovery:(batch,value)=>batches.set(batch,value),
    conversations:{async assertOwned(session,_scope,_persona,purpose){assert.equal(session,id(10));assert.equal(purpose,'review_moderation');
      await state.onOwned?.();if(state.conversationRevoked)throw Object.assign(Error(),{code:'CONVERSATION_UNAVAILABLE'});},
      async create(){state.calls.push('create');return {id:id(10)};}},
    runner:{async run(input){state.runCalls++;state.calls.push('run');state.input=input;
      const captured=batches.get(input.localToolAuthority);await captured?.authority.check();
      const result={hops:[],stopReason:'end_turn',taskMetadata:{reviewBatch:{contract:'bound-review-batch-v1',
        runId:id(11),requested:input.localToolAuthority.requested,considered:0,complete:true,continuationRequired:false},
        ...(captured?{reviewRecovery:captured.metadata}:{})}};
      state.row={sessionId:id(10),status:'completed',result};return result;}}});
  const input={scope,persona,personaSession,requestId,limit:7};
  return {state,service,input,recovery};
}

test('read-only preflight, later completed read and exact replay use the original journal, never run on GET',async()=>{
  const f=fixture();const absent=await f.service.readModeration(f.input);
  assert.deepEqual(Object.keys(absent),['version','requestId','requestedLimit','recoveryScopeKey','state','result']);
  assert.equal(absent.state,'not_found');assert.equal(absent.result,null);assert.match(absent.recoveryScopeKey,/^[a-f0-9]{64}$/);
  assert.equal(f.state.calls.includes('create'),false);assert.equal(f.state.runCalls,0);
  const scoped={...f.input,recoveryScopeKey:absent.recoveryScopeKey};
  const posted=await f.service.moderateReviews(scoped);
  const original=structuredClone(f.state.row);const before=f.state.runCalls;
  const saved=await f.service.readModeration(scoped);
  assert.equal(saved.state,'completed');assert.deepEqual(saved.result,posted);
  assert.equal(f.state.runCalls,before);assert.deepEqual(f.state.row,original);
  const replay=await f.service.moderateReviews(scoped);
  assert.equal(replay.replayed,true);assert.equal(f.state.runCalls,before);
  assert.equal(f.state.input.message,f.state.lookup.message);
  assert.deepEqual(f.state.row.result.taskMetadata.reviewRecovery,
    reviewRecoveryMetadata({requestId,requestedLimit:7,recoveryScopeKey:absent.recoveryScopeKey}));
});
test('started and uncertain observations remain unresolved and cannot rerun',async()=>{
  for(const status of ['started','uncertain']){
    const f=fixture();f.state.row={sessionId:id(10),status};const observed=await f.service.readModeration(f.input);
    assert.equal(observed.state,status);assert.equal(observed.result,null);
    await assert.rejects(f.service.moderateReviews({...f.input,recoveryScopeKey:observed.recoveryScopeKey}),{code:'TURN_RECOVERY_REQUIRED'});
    assert.equal(f.state.runCalls,0);assert.equal(f.state.calls.includes('create'),false);
  }
});
test('scope key changes with scene, mode, session, authority version, and current null reads are fenced',async()=>{
  for(const mutation of [f=>{f.state.target=target(2);},f=>{f.state.mode={...f.state.mode,mode:'fixed'};},
    f=>{f.input.personaSession={...personaSession,sessionId:id(12)};},
    f=>{f.input.personaSession={...personaSession,authorityVersion:'2'};}]){
    const f=fixture();const original=await f.service.readModeration(f.input);mutation(f);
    await assert.rejects(f.service.readModeration({...f.input,recoveryScopeKey:original.recoveryScopeKey}),{code:'REVIEW_RECOVERY_SCOPE_CHANGED'});
    assert.equal(f.state.runCalls,0);
  }
  for(const [mutation,code] of [[f=>{f.state.target=target(2);},'REVIEW_RECOVERY_SCOPE_CHANGED'],
    [f=>{f.state.target=null;},'SHOP_SCENE_STALE'],[f=>{f.state.revoked=true;},'SHOP_AUTH_INVALID'],
    [f=>{f.state.launchStale=true;},'STALE_LAUNCH']]){
    const f=fixture();f.state.onLookup=()=>mutation(f);
    await assert.rejects(f.service.readModeration(f.input),{code});assert.equal(f.state.runCalls,0);
  }
});
test('foreign execution, nonmerchant, missing credentials, and copied scene cannot authorize recovery',async()=>{
  const f=fixture();
  await assert.rejects(f.service.readModeration({...f.input,persona:{id:5,role:'customer'}}),{code:'OWNER_MISMATCH'});
  await assert.rejects(f.service.readModeration({...f.input,personaSession:undefined}),{code:'SHOP_AUTH_INVALID'});
  await assert.rejects(f.service.readModeration({...f.input,scope:{...scope,platformOwnerId:44}}),{code:'SHOP_AUTH_INVALID'});
  f.state.target={...f.state.target};
  await assert.rejects(f.service.readModeration(f.input),{code:'SHOP_SCENE_STALE'});
});
test('saved GET rechecks active workflow session and persona after projection without new work',async()=>{
  for(const [mutation,code] of [[f=>{f.state.conversationRevoked=true;},'CONVERSATION_UNAVAILABLE'],
    [f=>{f.state.revoked=true;},'SHOP_AUTH_INVALID']]){
    const f=fixture();const ready=await f.service.readModeration(f.input);
    await f.service.moderateReviews({...f.input,recoveryScopeKey:ready.recoveryScopeKey});
    let checks=0;f.state.onOwned=()=>{if(++checks===2)mutation(f);};
    await assert.rejects(f.service.readModeration({...f.input,recoveryScopeKey:ready.recoveryScopeKey}),{code});
    assert.equal(f.state.runCalls,1);
  }
});
test('scoped recovery rejects historical result, wrong request/limit/key, extra saved metadata',async()=>{
  const f=fixture();const prepared=await f.service.readModeration(f.input);
  await f.service.moderateReviews({...f.input,recoveryScopeKey:prepared.recoveryScopeKey});
  const original=structuredClone(f.state.row.result),expected=original.taskMetadata.reviewRecovery;
  for(const change of [r=>{delete r.taskMetadata.reviewRecovery;},r=>{r.taskMetadata.reviewRecovery.requestId=id(13);},
    r=>{r.taskMetadata.reviewRecovery.requestedLimit=8;},r=>{r.taskMetadata.reviewRecovery.recoveryScopeKey='a'.repeat(64);},
    r=>{r.taskMetadata.reviewRecovery.extra=true;},r=>{r.taskMetadata.reviewBatch.requested=8;}]){
    const invalid=structuredClone(original);change(invalid);
    assert.throws(()=>assertReviewRecoveryResult(invalid,expected),{code:'REVIEW_RECOVERY_UNAVAILABLE'});
    f.state.row={sessionId:id(10),status:'completed',result:invalid};
    await assert.rejects(f.service.readModeration(f.input),{code:'REVIEW_RECOVERY_UNAVAILABLE'});
  }
  assert.equal(f.state.runCalls,1);
});

test('dedicated SQL lookup uses only review_moderation, validates persisted hash/limit and keeps general closed',async()=>{
  let rows=[],calls=[];
  const repo=createTurnRequestsRepository({pool:{async connect(){return {async query(sql,args){calls.push({sql,args});return {rows};},release(){}};}}});
  const message='exact original message',req=createTurnRequest({sessionId:id(10),requestId,binding,message});
  rows=[{session_id:id(10),request_id:requestId,request_version:1,request_hash:req.hash,status:'completed',result_json:{original:true}}];
  assert.deepEqual(await repo.lookupReviewModerationRequest({requestId,binding,message}),{sessionId:id(10),status:'completed',result:{original:true}});
  assert.match(calls[0].sql,/conversation_purpose='review_moderation'/);assert.match(calls[0].sql,/LIMIT 2/);
  assert.doesNotMatch(calls[0].sql,/INSERT|UPDATE|DELETE|FOR UPDATE/);
  assert.deepEqual(calls[0].args,[requestId,scope.launchId,scope.scenarioId,1,4,8,5,'merchant']);
  assert.equal((await repo.lookupReviewModerationRequest({requestId,binding,message:'changed limit'})).status,'conflict');
  rows[0].request_version=2;assert.equal((await repo.lookupReviewModerationRequest({requestId,binding,message})).status,'conflict');
  rows=[rows[0],rows[0]];assert.equal((await repo.lookupReviewModerationRequest({requestId,binding,message})).status,'conflict');
  rows=[];assert.equal(await repo.lookupReviewModerationRequest({requestId,binding,message}),null);
  await repo.lookupGeneralRequest({requestId,binding,message});assert.match(calls.at(-1).sql,/conversation_purpose='general'/);
});

test('retained review target reader never adopts missing mapping and preserves scene capability',async()=>{
  const queries=[];let row=null;
  const pool={async query(){throw Error('Unexpected unleased query');},async connect(){return {async query(sql){queries.push(sql);
    if(sql.includes('assert_scene_execution_grant'))return {rows:[{allowed:true}]};
    if(sql.includes('JOIN secureshop_review.review_targets'))return {rows:row?[row]:[]};
    return {rows:[]};},release(){}};}};
  const repo=createSecureShopBoundReviewRepository(pool,{checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{}});
  const scene=reviewScene.productScene(target());
  assert.equal(await repo.readRetainedSceneTarget(scene),null);
  row={target_id:id(6),launch_id:scope.launchId,scenario_id:scope.scenarioId,generation:1,
    original_platform_owner_id:4,original_platform_session_id:8};
  const retained=await repo.readRetainedSceneTarget(scene);
  assert.equal(retained.targetId,id(6));assert.equal(reviewScene.productScene(retained),scene);
  assert.equal(queries.some(sql=>/INSERT|UPDATE|DELETE|bind_scene_review_target|adopt_seller/.test(sql)),false);
});

async function routeRequest({query={limit:'7'},role='merchant',error,body,method='get'}={}) {
  const service=Object.fromEntries(['listProductReviews','submitReview','listMerchantReviews','approveReview','rejectReview'].map(n=>[n,()=>{throw Error('unexpected mutation');}]));
  let input;
  const router=createBoundReviewsRouter({launches:{async resolveCapability(){return scope;}},
    authenticatePersona(req,_res,next){req.ssUser={id:5,role};req.ssPersonaSession=personaSession;next();},service,
    moderation:{async moderateReviews(value){input=value;if(error)throw error;return {ok:true};},
      async readModeration(value){input=value;if(error)throw error;return {version:1,requestId,requestedLimit:7,recoveryScopeKey:'a'.repeat(64),state:'not_found',result:null};}}});
  const path=method==='get'?'/merchant/reviews/moderation/:requestId':'/merchant/reviews/moderate-all';
  const handlers=router.stack.find(x=>x.route?.path===path&&x.route.methods[method]).route.stack.map(x=>x.handle);
  const req=Object.assign(new EventEmitter(),{query,params:{requestId},body,
    headers:{'x-owasp-ai-goat-secureshop-launch':'l'.repeat(43)},
    rawHeaders:['x-owasp-ai-goat-secureshop-launch','l'.repeat(43)],get:()=> 'l'.repeat(43),is:()=>true});
  const res=Object.assign(new EventEmitter(),{headers:{},statusCode:200,headersSent:false,writableEnded:false,
    set(name,value){this.headers[name.toLowerCase()]=value;return this;},setHeader(name,value){this.headers[name.toLowerCase()]=value;},
    status(code){this.statusCode=code;return this;},json(value){this.value=value;this.headersSent=true;this.writableEnded=true;return this;}});
  async function step(i){if(!handlers[i])return;let tail;await handlers[i](req,res,arg=>{if(arg)throw Error(String(arg));tail=step(i+1);return tail;});await tail;}
  await step(0);return {res,input};
}
test('GET route is exact, no-store on success/error, and carries authenticated inputs only',async()=>{
  const good=await routeRequest();assert.equal(good.res.statusCode,200);assert.equal(good.res.headers['cache-control'],'no-store');
  assert.deepEqual(good.input,{scope,persona,personaSession,requestId,limit:7,recoveryScopeKey:undefined});
  for(const query of [{},{limit:['7']},{limit:'07'},{limit:'101'},{limit:'7',extra:'x'},{limit:'7',recoveryScopeKey:['a'.repeat(64)]}]){
    const {res,input}=await routeRequest({query});assert.equal(res.statusCode,400);assert.equal(input,undefined);assert.equal(res.headers['cache-control'],'no-store');
  }
  assert.equal((await routeRequest({role:'customer'})).res.statusCode,403);
  for(const [code,status] of [['SHOP_SCENE_STALE',409],['REVIEW_RECOVERY_UNAVAILABLE',409],['TURN_REQUEST_CONFLICT',409],['SHOP_AUTH_INVALID',401],['SQL_FAILURE',503]]){
    const {res}=await routeRequest({error:Object.assign(Error(),{code})});assert.equal(res.statusCode,status);assert.equal(res.headers['cache-control'],'no-store');
  }
});
test('POST accepts optional key only with exact explicit limit; legacy POST is unchanged',async()=>{
  const legacy=await routeRequest({method:'post',query:{},body:{request_id:requestId}});
  assert.equal(legacy.input.limit,100);assert.equal(Object.hasOwn(legacy.input,'recoveryScopeKey'),false);
  const scoped=await routeRequest({method:'post',query:{},body:{request_id:requestId,limit:7,recoveryScopeKey:'a'.repeat(64)}});
  assert.equal(scoped.input.recoveryScopeKey,'a'.repeat(64));assert.equal(scoped.input.limit,7);
  assert.equal((await routeRequest({method:'post',query:{},body:{request_id:requestId,recoveryScopeKey:'a'.repeat(64)}})).res.statusCode,400);
});

test('real runtime persists scoped metadata, replays without work, and fences changed scene before a tool',async()=>{
  const {createBoundReviewRuntime}=require('../server/services/secureshopBoundReviewRuntime');
  async function run(changeScene,failFinal=false) {
    let current=target(),session,stored,modelCalls=0,reads=0,creates=0;const messages=[];
    const personaAuthority={capture(input){return {binding:{...scope,personaId:input.personaId,role:input.role,
      sessionId:input.sessionId,authorityVersion:input.authorityVersion},async assertRemoteAdmission(){},
      async withPersonaEffect(work){return work({});},async withCrossStoreEffect(work){return work();}};}};
    const pending=[17,18].map(value=>({id:value,productId:2,authorId:9,body:'The product works well.',rating:4,status:'pending'}));
    const repository={async provision(){throw Error('Unexpected provisioning');},async listReviews(){throw Error('Unexpected list');},
      async readDecisionReceipt(){return null;},async submitReview(){throw Error('Unexpected submission');},
      async decide(_target,input){assert.equal(failFinal,true);assert.equal(input.reviewId,17);
        return {applied:true,review:{...pending[0],status:'approved',moderatorKind:'auto',moderatorNotes:null}};},
      async listPending(actual){assert.equal(actual.targetId,id(6));assert.equal(reviewScene.productScene(actual).scene.sceneGeneration,1);reads++;return failFinal?pending:[];}};
    const runtime=createBoundReviewRuntime({personaAuthority,
      readRetainedReviewTarget:async()=>current,readRecoveryMode:async()=>({mode:'vuln',generation:1,modeStamp:'mode-1'}),
      launches:{async assertCurrent(){},async resolveCapability(){return scope;},async reserveReviewsTarget(){throw Error('Unexpected reservation');}},
      reviewRepository:repository,conversationRepository:{
        async acquireBoundSession({id:sessionId,binding:owned,purpose}){creates++;session||={id:sessionId,binding:owned,purpose,state:'active'};return session;},
        async getBoundSession(){return session;},async getMessages(){return structuredClone(messages);},
        async appendMessage(_id,_binding,row){messages.push(structuredClone(row));},async getTokens(){return 0;},async addTokens(){},async appendTraces(){}},
      journal:{async lookupReviewModerationRequest(){return stored||null;},async claim(){return {status:'claimed',claimId:id(14)};},
        async complete({result}){stored={sessionId:session.id,status:'completed',result:structuredClone(result)};},async markUncertain(){stored||={sessionId:session.id,status:'uncertain'};}},
      coordinator:{async reset(_id,work){return work();},async run(_id,options,work){
        const admitted=await options.admit();if(admitted.skip)return admitted.value;
        return work({runId:id(15),ownerKey:'controlled-moderation-owner',durableGeneration:'1',async check(){},async effect(_key,fn){return fn();}});}},
      authenticatePersona(_req,_res,next){next();},buildBasePrompt:()=> 'Original controlled merchant base',buildPolicyBlock:async()=>'',
      checkToolAcl:async()=>({action:'dispatch',policyViolation:null}),assessmentFactory:()=>({async begin(){return {};},async observe(){},async finalize(){}}),
      limits:{maxSteps:3,maxParallelTools:1},
      provider:{async chat(){modelCalls++;if(changeScene)current=target(2);
        if(modelCalls===2)return {stop_reason:'tool_use',tool_uses:[{id:'approve',name:'review-moderator.approve',args:{review_id:17}}]};
        return {stop_reason:'tool_use',tool_uses:[{id:'read',name:'review-moderator.moderate_pending',args:{}}]};},
        async finalResponse(){modelCalls++;if(failFinal)throw Error('Controlled provider final failure');
          return {stop_reason:'end_turn',text:'No pending reviews.',responseMode:'structured_final'};}},
      manifest:{getForRole:()=>[{agent:'review-moderator',tool:'moderate_pending',description:'Original tool'},
        {agent:'review-moderator',tool:'approve',description:'Original decision tool'}]}});
    const input={scope,persona,personaSession,requestId,limit:7};
    const preflight=await runtime.moderation.readModeration(input);
    assert.equal(creates,0);assert.equal(reads,0);assert.equal(modelCalls,0);
    if(changeScene){await assert.rejects(runtime.moderation.moderateReviews({...input,recoveryScopeKey:preflight.recoveryScopeKey}));
      assert.equal(reads,0);assert.equal(stored.status,'uncertain');assert.equal(modelCalls,1);return;}
    const posted=await runtime.moderation.moderateReviews({...input,recoveryScopeKey:preflight.recoveryScopeKey});
    assert.equal(posted.ok,!failFinal);assert.equal(posted.stopReason,failFinal?'error':'end_turn');
    assert.equal(reads,1);assert.equal(modelCalls,failFinal?3:2);
    const original=JSON.stringify({stored,messages,modelCalls,reads,creates});
    const recovered=await runtime.moderation.readModeration({...input,recoveryScopeKey:preflight.recoveryScopeKey});
    assert.deepEqual(recovered.result,posted);assert.equal(recovered.state,'completed');
    assert.equal(JSON.stringify({stored,messages,modelCalls,reads,creates}),original);
    assert.equal((await runtime.moderation.moderateReviews({...input,recoveryScopeKey:preflight.recoveryScopeKey})).replayed,true);
    assert.equal(modelCalls,failFinal?3:2);assert.equal(creates,1);
    if(failFinal){assert.equal(recovered.result.ok,false);assert.equal(recovered.result.batch.complete,true);
      assert.equal(recovered.result.batch.continuationRequired,true);assert.equal(recovered.result.processed,1);}
  }
  await run(false);await run(false,true);await run(true);
});
