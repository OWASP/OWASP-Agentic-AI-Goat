'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopAuditRuntime}=require('../server/services/secureshopAuditRuntime');
function fixture(){return {agentsPool:{query(){},connect(){}},reviewPool:{connect(){}},ledger:{readCompletedEffect(){}},
  turns:{run(){}},conversations:{assertOwned(){},create(){}},journal:{claim(){},complete(){},markUncertain(){}},receipts:{beginEvaluation(){},recordVerdict(){}},
  progress:{getGeneration(){}},root:'/private/tmp/owned-audit',baseUrl:'http://127.0.0.1:11434',model:'llama3.1:8b'};}
test('audit runtime rejects missing owned storage, authority and server model configuration',()=>{
  for(const changed of [{root:'relative'},{ledger:{}},{agentsPool:{}},{model:''},{baseUrl:'file:///tmp/model'},{baseUrl:'http://user:secret@localhost'}])
    assert.throws(()=>createSecureShopAuditRuntime({...fixture(),...changed}));
});
test('construction exposes retained session admission and run operations',()=>{
  const runtime=createSecureShopAuditRuntime(fixture());assert.deepEqual(Object.keys(runtime),['createSession','run']);assert.equal(Object.isFrozen(runtime),true);
});

test('audit session admission binds the dedicated purpose and rejects another persona',async()=>{
  const options=fixture(),calls=[];
  options.conversations.create=async(...args)=>{calls.push(args);return{id:'owned-session'};};
  const runtime=createSecureShopAuditRuntime(options);
  const scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
  assert.deepEqual(await runtime.createSession({scope,persona:{id:3,role:'admin'}}),{sessionId:'owned-session'});
  assert.equal(calls[0][2],'secureshop_audit_summary');assert.equal(calls[0][0].platformOwnerId,7);
  await assert.rejects(runtime.createSession({scope,persona:{id:3,role:'customer'}}),/Administrator/);
  assert.equal(calls.length,1);
});

test('candidate runtime requires authority and rejects missing captured fence before session creation',async()=>{
  assert.throws(()=>createSecureShopAuditRuntime({...fixture(),personaBindings:{capture(){}}}),/persona authority required/i);
  const options=fixture();let created=0;options.conversations.create=async()=>{created++;return{id:'owned-session'};};
  const runtime=createSecureShopAuditRuntime({...options,personaAuthority:{capture(){}}});
  await assert.rejects(runtime.createSession({scope:{launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8},persona:{id:3,role:'admin'}}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(created,0);
});
test('candidate session creation captures exact private credential and rechecks before returning',async()=>{
  const options=fixture(),scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
  const personaSession={sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'};let capture,checks=0,revoked=false;
  options.conversations.create=async()=>{revoked=true;return{id:'owned-session'};};
  const runtime=createSecureShopAuditRuntime({...options,personaAuthority:{capture(input){capture=input;return{binding:{...scope,personaId:3,role:'admin',...personaSession},withPersonaEffect(){},async assertRemoteAdmission(){checks++;if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};}}});
  await assert.rejects(runtime.createSession({scope,persona:{id:3,role:'admin'},personaSession}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(capture.sessionId,personaSession.sessionId);assert.equal(capture.authorityVersion,'2');assert.equal(checks,2);
});

test('candidate session admission rejects a substituted credential generation before create',async()=>{
 const scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
 const personaSession={sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'};
 for(const patch of [{sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'},{authorityVersion:'3'}]){
  const options=fixture();let created=0;options.conversations.create=async()=>{created++;return{id:'unexpected'};};
  const runtime=createSecureShopAuditRuntime({...options,personaAuthority:{capture(){return{binding:{...scope,personaId:3,role:'admin',...personaSession,...patch},assertRemoteAdmission:async()=>{},withPersonaEffect(){}};}}});
  await assert.rejects(runtime.createSession({scope,persona:{id:3,role:'admin'},personaSession}),{code:'SHOP_AUTH_INVALID'});assert.equal(created,0);
 }
});


test('policy repository requires original authority and rejects ambiguous callback configuration',()=>{
  const toolPolicyRepository={admitTool(){throw Error('Construction must not admit a tool');}};
  assert.throws(()=>createSecureShopAuditRuntime({...fixture(),toolPolicyRepository}),/persona authority/);
  assert.throws(()=>createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},toolPolicyRepository:{}}),/Policy repository/);
  assert.throws(()=>createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},toolPolicyRepository,toolPolicyAdmission(){}}),/one audit policy source/);
  assert.equal(typeof createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},toolPolicyRepository}).run,'function');
});

test('audit capture retains the original credential while authority capture is pending',async()=>{
 const options=fixture(),scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
 const personaSession={sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'};
 options.conversations.create=async()=>({id:'owned-session'});
 const runtime=createSecureShopAuditRuntime({...options,personaAuthority:{async capture(input){
   personaSession.sessionId='dddddddd-dddd-4ddd-8ddd-dddddddddddd';personaSession.authorityVersion='3';
   return {binding:{...scope,personaId:3,role:'admin',sessionId:input.sessionId,authorityVersion:input.authorityVersion},withPersonaEffect(){},async assertRemoteAdmission(){}};
 }}});
 assert.deepEqual(await runtime.createSession({scope,persona:{id:3,role:'admin'},personaSession}),{sessionId:'owned-session'});
});

test('prompt policy repository requires current persona authority before runtime construction',()=>{
 assert.throws(()=>createSecureShopAuditRuntime({...fixture(),promptPolicyRepository:{admitRunSnapshot(){}}}),/prompt policy authority/);
 assert.throws(()=>createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},promptPolicyRepository:{}}),/prompt policy authority/);
 assert.doesNotThrow(()=>createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},promptPolicyRepository:{admitRunSnapshot(){throw Error('no construction admission');}}}));
});
test('runtime private policy closure binds parent run and all original persona coordinates',async()=>{
 const jobPath=require.resolve('../server/services/secureshopAuditJob'),runnerPath=require.resolve('../server/services/secureshopAuditRunner'),runtimePath=require.resolve('../server/services/secureshopAuditRuntime');
 const originals=[jobPath,runnerPath,runtimePath].map(key=>[key,require.cache[key]]);let executeJob,jobOptions;
 try{
  require.cache[jobPath]={id:jobPath,filename:jobPath,loaded:true,exports:{createSecureShopAuditJob:options=>{jobOptions=options;return async()=>({});}}};
  require.cache[runnerPath]={id:runnerPath,filename:runnerPath,loaded:true,exports:{createSecureShopAuditRunner:options=>{executeJob=options.executeJob;return{run(){}};}}};
  delete require.cache[runtimePath];
  const scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
  const b=Object.freeze({...scope,personaId:3,role:'admin',sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'}),events=[],snapshot=require('../server/services/secureshopPromptPolicySnapshot').buildPolicySnapshot({policyVersion:'1',role:'admin',policies:[]});let actual;
  require(runtimePath).createSecureShopAuditRuntime({...fixture(),personaAuthority:{capture(){}},promptPolicyRepository:{async admitRunSnapshot(input){events.push('admit');actual=input;return snapshot;}}});
  await executeJob({boundary:{check:async()=>events.push('boundary')},promptPolicySnapshot:{forged:true}},{binding:b,assertRemoteAdmission:async()=>events.push('persona')});
  assert.equal(jobOptions.taskRequestVersion,1);
  const runId='dddddddd-dddd-4ddd-8ddd-dddddddddddd';assert.deepEqual(await jobOptions.capturePromptPolicy({runId}),snapshot);
  assert.deepEqual(actual,{scope,persona:{id:3,role:'admin'},personaSession:{sessionId:b.sessionId,authorityVersion:'2'},runId});
  assert.deepEqual(events,['boundary','persona','admit','persona','boundary']);
 }finally{for(const[key,value]of originals){if(value)require.cache[key]=value;else delete require.cache[key];}}
});

test('scene runtime binds the real retained capability and fences changed practice before job or grading',async()=>{
  const paths=['secureshopAuditJob','secureshopAuditRunner','secureshopAuditAssessment','secureshopAuditRuntime'].map(name=>require.resolve('../server/services/'+name));
  const originals=paths.map(key=>[key,require.cache[key]]);
  let options,jobOptions,assessments=0,leased=false,allowed=true,selected,grants=0;
  const scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
  const personaSession={sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'};
  const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
  const retained=createSceneBinding({...scope,platformSessionId:6,targetId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'},
    {sceneId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',sceneGeneration:1,grantId:'ffffffff-ffff-4fff-8fff-ffffffffffff',execution:scope,
      withLease:async work=>{assert.equal(leased,false);leased=true;try{return await work();}finally{leased=false;}}});
  selected=retained;
  try{
    require.cache[paths[0]]={id:paths[0],filename:paths[0],loaded:true,exports:{createSecureShopAuditJob:value=>{jobOptions=value;return async()=>({});}}};
    require.cache[paths[1]]={id:paths[1],filename:paths[1],loaded:true,exports:{createSecureShopAuditRunner:value=>{options=value;return{run(){}};}}};
    require.cache[paths[2]]={id:paths[2],filename:paths[2],loaded:true,exports:{createSecureShopAuditAssessment:()=>async context=>{assessments++;return context;}}};
    delete require.cache[paths[3]];
    const dependencies={...fixture(),scenes:{readRetained:async()=>selected},personaAuthority:{capture:async()=>({
      binding:{...scope,personaId:3,role:'admin',...personaSession},assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work()})},
      reviewPool:{connect:async()=>({query:async(sql,args)=>{grants++;assert.equal(leased,true);assert.equal(args[0],retained.scene.grantId);return{rows:[{allowed}]};},release(){}})}};
    require(paths[3]).createSecureShopAuditRuntime(dependencies);
    const input={binding:{...scope,shopUserId:3,role:'admin'},personaSession};
    const fence=await options.capturePersonaAuthority(input);assert.ok(grants>0);
    await options.executeJob({boundary:{check:async()=>{}}},fence);
    assert.equal(jobOptions.sceneBinding,retained);assert.equal(typeof jobOptions.sceneSource.rows,'function');
    const context={binding:input.binding,execution:{runId:'parent',check:async()=>{}}};
    const admitted=await options.beginAssessment(context,fence);assert.equal(assessments,1);
    selected=null;
    await assert.rejects(jobOptions.checkScene(),{code:'SHOP_SCENE_STALE'});
    await assert.rejects(options.beginAssessment(context,fence),{code:'SHOP_SCENE_STALE'});
    assert.equal(assessments,1);
    selected=retained;allowed=false;
    await assert.rejects(admitted.execution.check(),{code:'SHOP_SCENE_STALE'});
    await assert.rejects(options.capturePersonaAuthority(input),{code:'SHOP_SCENE_STALE'});
    selected={...retained};allowed=true;
    await assert.rejects(options.capturePersonaAuthority(input),{code:'SHOP_SCENE_STALE'});
    assert.equal(leased,false);
  }finally{for(const[key,value]of originals){if(value)require.cache[key]=value;else delete require.cache[key];}}
});

test('installed audit lifecycle receives actual scenes instead of model-supplied scene input',()=>{
  const source=require('node:fs').readFileSync(require.resolve('../server/services/secureshopBoundReviewComposition'),'utf8');
  assert.match(source,/const auditOptions=\{modeAuthority:featureModeAuthority,scenes:value\.scenes,/);
  assert.throws(()=>createSecureShopAuditRuntime({...fixture(),scenes:{readRetained(){}}}),/retained scene authority/);
});


test('unbounded variant is constructor-selected and requires protected scene authority',()=>{
 assert.throws(()=>createSecureShopAuditRuntime({...fixture(),assessmentVariant:'other'}),/assessment configuration/);
 assert.throws(()=>createSecureShopAuditRuntime({...fixture(),assessmentVariant:'unbounded'}),/retained persona and scene/);
 const runtime=createSecureShopAuditRuntime({...fixture(),assessmentVariant:'unbounded',personaAuthority:{capture(){}},scenes:{readRetained(){}}});
 assert.deepEqual(Object.keys(runtime),['createSession','run']);
});

test('unbounded runtime persists its own request witness inside current scene and persona transaction before original job',async()=>{
 const names=['secureshopAuditJob','secureshopAuditRunner','secureshopAuditRuntime'];
 const paths=names.map(name=>require.resolve('../server/services/'+name)),originals=paths.map(key=>[key,require.cache[key]]);
 const scope={launchId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scenarioId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',generation:1,platformOwnerId:7,platformSessionId:8};
 const credential={sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',authorityVersion:'2'},persona={id:3,role:'admin'};
 let leased=false,inEffect=false,allowed=true,options,insert,jobCalls=0,jobOptions;
 const retained=require('../server/services/secureshopSceneBinding').createSceneBinding({...scope,targetId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'},
  {sceneId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',sceneGeneration:1,grantId:'ffffffff-ffff-4fff-8fff-ffffffffffff',execution:scope,
   withLease:async work=>{assert.equal(leased,false);leased=true;try{return await work();}finally{leased=false;}}});
 try{
  require.cache[paths[0]]={id:paths[0],filename:paths[0],loaded:true,exports:{createSecureShopAuditJob:value=>{jobOptions=value;return async()=>{assert.ok(insert);assert.equal(inEffect,false);jobCalls++;return{original:true};};}}};
  require.cache[paths[1]]={id:paths[1],filename:paths[1],loaded:true,exports:{createSecureShopAuditRunner:value=>{options=value;return{run(){}};}}};
  delete require.cache[paths[2]];
  const authority={...scope,personaId:3,role:'admin',...credential};
  require(paths[2]).createSecureShopAuditRuntime({...fixture(),assessmentVariant:'unbounded',scenes:{readRetained:async()=>retained},
   reviewPool:{connect:async()=>({query:async()=>({rows:[{allowed}]}),release(){}})},
   personaAuthority:{capture:async()=>({binding:authority,assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>{
    assert.equal(leased,true);inEffect=true;try{return await work({query:async(sql,values)=>{assert.equal(inEffect,true);assert.match(sql,/INSERT INTO secureshop_agents.bound_audit_events/);insert=values;return{rowCount:1};}},authority);}finally{inEffect=false;}
   }})}});
  assert.equal(options.conversationPurpose,'secureshop_audit_unbounded');
  const binding={...scope,shopUserId:3,role:'admin'},fence=await options.capturePersonaAuthority({binding,personaSession:credential});
  const input={scope:binding,persona,requestId:'11111111-1111-4111-8111-111111111111',requestedCount:201,boundary:{identity:{runId:'22222222-2222-4222-8222-222222222222'},check:async()=>{}}};
  assert.deepEqual(await options.executeJob(input,fence),{original:true});
  assert.equal(jobOptions.taskRequestVersion,2);
  assert.deepEqual(insert.slice(1,8),[scope.launchId,scope.scenarioId,1,7,8,3,'admin']);
  assert.deepEqual(insert.slice(8,11),['admin','audit_unbounded_requested',input.boundary.identity.runId]);
  const params=JSON.parse(insert[11]);assert.equal(params.requestId,input.requestId);assert.equal(params.requestedCount,201);assert.match(params.nonce,/^[a-f0-9-]{36}$/);
  assert.deepEqual(insert.slice(12),['completed','audit_request',input.requestId]);
  allowed=false;insert=null;
  await assert.rejects(options.executeJob(input,fence),{code:'SHOP_SCENE_STALE'});assert.equal(insert,null);assert.equal(jobCalls,1);
 }finally{for(const[key,value]of originals){if(value)require.cache[key]=value;else delete require.cache[key];}}
});
