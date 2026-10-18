'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const mail=require('../server/services/secureshopMailSceneBinding');
const {createMailScenes}=require('../server/services/secureshopMailScenes');
function fixture({prior=false,ambiguous=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:16,platformSessionId:25};
 const old={...scope,launchId:randomUUID(),platformSessionId:10,targetId:randomUUID()};
 const context={scope,persona:{id:1000000001,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 let current=true,selected=null,mapped=null,target=prior?old:null,provisionLeaseHeld=false;
 const calls={catalog:0,provision:0,reserve:0,adopt:0,mirror:0,lease:0};
 const check=async()=>{if(!current)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});};
 const scene=createSceneBinding({...old,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,
  withLease:async work=>{calls.lease++;await check();const result=await work();await check();return result;}});
 const agentsPool={async query(sql,args){
  if(sql.includes('FROM secureshop_agents.persona_inbox_targets')){
   if(!target||target.targetId!==args[0])return {rows:[]};
   return {rows:[{target_id:target.targetId,launch_id:target.launchId,scenario_id:target.scenarioId,generation:target.generation,
    original_platform_owner_id:target.platformOwnerId,original_platform_session_id:target.platformSessionId}]};
  }
  if(sql.includes('assert_mail_scene_execution_grant')){assert.equal(args[3],target.targetId);assert.equal(args[4],scope.launchId);return {rows:[{allowed:true}]};}
  if(sql.includes('INSERT')){calls.mirror++;return {rows:[],rowCount:1};}
  throw Error('Unexpected query');
 }};
 const repository={read:async()=>mapped,candidates:async()=>prior?[{...old,associated:false},...(ambiguous?[{...old,targetId:randomUUID(),associated:false}]:[])]:[],
  adopt:async(_scene,value)=>{calls.adopt++;mapped=value;return value;}};
 if(ambiguous){const original=agentsPool.query;agentsPool.query=async(sql,args)=>{
  if(sql.includes('FROM secureshop_agents.persona_inbox_targets'))return {rows:[{target_id:args[0],launch_id:old.launchId,scenario_id:old.scenarioId,generation:old.generation,original_platform_owner_id:old.platformOwnerId,original_platform_session_id:old.platformSessionId}]};
  return original(sql,args);
 };}
 const service=createMailScenes({repository,scenes:{readExisting:async()=>selected,withProvisionLease:async(_scope,work)=>{
  assert.equal(provisionLeaseHeld,false);provisionLeaseHeld=true;try{return await work();}finally{provisionLeaseHeld=false;}}},
  catalog:{prepareTarget:async input=>{assert.equal(provisionLeaseHeld,false,'catalog must acquire its own provisioning lease before mail');assert.equal(input.scope,context.scope);assert.ok(require('../server/services/secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect));calls.catalog++;selected=scene;}},agentsPool,
  launches:{assertCurrent:check,reservePersonaInboxTarget:async()=>{calls.reserve++;return {targetId:randomUUID()};}},
  inboxRepository:{provision:async(value,options)=>{calls.provision++;assert.deepEqual(options.fixtures,['three-template-fixture']);target=value;}},
  resolveFixtures:async()=>['three-template-fixture'],personaAuthority:{capture:async()=>({binding:{...scope,personaId:context.persona.id,role:context.persona.role,...context.personaSession},assertRemoteAdmission:check,withCrossStoreEffect:async work=>{await check();const result=await work();await check();return result;}})}});
 return {service,context,scope,old,scene,calls,setCurrent:value=>{current=value;}};
}
test('mail-first creates the shared shop scene and provisions once; later access retains inbox birth',async()=>{
 const f=fixture(),first=await f.service.resolve(f.context),second=await f.service.resolve(f.context);
 assert.equal(first.targetId,second.targetId);assert.equal(f.calls.provision,1);assert.equal(f.calls.reserve,1);assert.equal(f.calls.adopt,1);
 assert.deepEqual(mail.current(first),f.scope);assert.equal(mail.productScene(first),f.scene);
 assert.equal((await f.service.readExisting(f.scope)).targetId,first.targetId);assert.equal(f.calls.catalog,2);
});
test('verified historical inbox is adopted without reprovision, reseed, copy or birth rewrite',async()=>{
 const f=fixture({prior:true}),result=await f.service.resolve(f.context);
 assert.deepEqual(mail.birth(result),f.old);assert.deepEqual(mail.current(result),f.scope);
 assert.equal(f.calls.provision,0);assert.equal(f.calls.reserve,0);assert.equal(f.calls.adopt,1);
});
test('fresh mail grant refuses a switched outer scene before inbox adoption or provision',async()=>{
 const f=fixture();
 await assert.rejects(f.service.resolve({...f.context,
  target:{...f.scene,targetId:randomUUID()}}),{code:'MAIL_SCENE_STALE'});
 assert.equal(f.calls.reserve,0);assert.equal(f.calls.provision,0);
 assert.equal(f.calls.adopt,0);assert.equal(f.calls.mirror,0);
 const result=await f.service.resolve({...f.context,target:f.scene});
 assert.equal(mail.productScene(result),f.scene);
 assert.equal(f.calls.reserve,1);assert.equal(f.calls.provision,1);
});
test('ambiguous historical inboxes and stale sessions cannot create an adoption',async()=>{
 const ambiguous=fixture({prior:true,ambiguous:true});await assert.rejects(ambiguous.service.resolve(ambiguous.context),{code:'MAIL_SCENE_SELECTION_REQUIRED'});
 assert.equal(ambiguous.calls.adopt,0);assert.equal(ambiguous.calls.reserve,0);
 const stale=fixture();stale.setCurrent(false);await assert.rejects(stale.service.resolve(stale.context),{code:'STALE_LAUNCH'});assert.equal(stale.calls.catalog,0);
 const absent=fixture();await assert.rejects(absent.service.readExisting(absent.scope),{code:'MAIL_SCENE_STALE'});assert.equal(absent.calls.provision,0);
});
test('mail normalization retains private birth/current capability and rejects changed authority',async()=>{
 const f=fixture({prior:true}),target=await f.service.resolve(f.context);
 const normalized=mail.copy(target,{scope:f.scope,targetId:target.targetId,operationId:randomUUID()});
 assert.equal(mail.productScene(normalized),f.scene);assert.deepEqual(mail.birth(normalized),f.old);
 assert.throws(()=>mail.copy(target,{scope:{...f.scope,platformSessionId:999},targetId:target.targetId}),{code:'MAIL_SCENE_STALE'});
 assert.throws(()=>mail.copy(target,{scope:f.scope,targetId:randomUUID()}),{code:'MAIL_SCENE_STALE'});
 assert.equal(mail.productScene(JSON.parse(JSON.stringify(normalized))),null);
 f.setCurrent(false);await assert.rejects(mail.withLease(normalized,async()=>assert.fail('stale effect executed')),{code:'STALE_LAUNCH'});
});
