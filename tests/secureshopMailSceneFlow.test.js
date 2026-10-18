'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const mailScene=require('../server/services/secureshopMailSceneBinding');
const {createBoundMailRepository,normalize}=require('../server/database/postgres/secureshopBoundMailRepository');
const {requestDigest}=require('../server/database/postgres/secureshopPersonaInboxRepository');
const {createSecureShopPersonaInboxRepository}=require('../server/database/postgres/secureshopPersonaInboxRepository');
const {createSecureShopPersonaInboxTools}=require('../server/services/secureshopPersonaInboxTools');

function fixture(){
 const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:19,platformSessionId:23};
 const current={...birth,launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformSessionId:29};
 let leases=0;
 const scene=createSceneBinding({...birth,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,
   withLease:async work=>{leases++;return work();}});
 const target=mailScene.attach({...birth,targetId:randomUUID()},scene);
 return {birth,current,scene,target,get leases(){return leases;}};
}

test('only a trusted mail scene target carries its current grant through normalization and the mail effect',async()=>{
 const f=fixture(),operationId=randomUUID(),sessionId=randomUUID(),queries=[];
 const raw={scope:f.current,targetId:f.target.targetId,target:f.target,persona:{id:1000000000,role:'customer'},
  personaSession:{sessionId,authorityVersion:'1'},mode:'vuln',operationId};
 const b=normalize(raw);assert.equal(mailScene.productScene(b),f.scene);
 assert.deepEqual(mailScene.current(b),f.current);
 const {threadId,...graphInput}={...b,threadId:7};
 assert.equal(mailScene.productScene(normalize(graphInput)),f.scene,
  'the graph task spread retains the private target pointer');
 const client={async query(sql,args){queries.push({sql,args});
  if(sql.includes('assert_mail_scene_execution_grant'))return {rows:[{allowed:true}]};
  if(sql.includes('bound_lab_mail'))return {rows:[{result:{ok:true,operationId,replayed:false,
   receipt:{userId:1000000000},emails:[]}}]};
  return {rows:[]};}};
 const repo=createBoundMailRepository({pool:{query:async()=>({rows:[]})},checkCleanup:async()=>{},
  personaAuthority:{capture:()=>({binding:{...f.current,personaId:1000000000,role:'customer',sessionId,authorityVersion:'1'},
   withPersonaEffect:work=>work(client),assertRemoteAdmission:async()=>{}})}});
 const result=await repo.browse(raw,1000000000);
 assert.equal(result.ok,true);assert.equal(f.leases,1);
 const effect=queries.find(q=>q.sql.includes('bound_lab_mail'));
 assert.match(effect.sql,/\$15::uuid/);assert.equal(effect.args[14],f.scene.scene.grantId);
 assert.equal(queries.filter(q=>q.sql.includes('assert_mail_scene_execution_grant')).length,2);
 assert.throws(()=>normalize({...raw,scope:{...f.current,platformSessionId:30}}),{code:'MAIL_SCENE_STALE'});
 const untrusted=normalize({...raw,target:{...f.target}});
 assert.equal(mailScene.productScene(untrusted),null);
});

test('exact saved-send projection carries the current scene grant and returns only persisted DTO fields',async()=>{
 const f=fixture(),operationId=randomUUID(),sessionId=randomUUID(),queries=[];
 const raw={scope:f.current,targetId:f.target.targetId,target:f.target,persona:{id:1000000000,role:'merchant'},
  personaSession:{sessionId,authorityVersion:'1'},mode:'vuln',operationId};
 const saved={recipientId:1000000001,to:'owned@example.invalid',subject:'Owned',body_markdown:'Saved body'};
 const client={async query(sql,args){queries.push({sql,args});
  if(sql.includes('assert_mail_scene_execution_grant'))return {rows:[{allowed:true}]};
  if(sql.includes('project_bound_lab_mail_send'))return {rows:[{saved}]};
  return {rows:[]};}};
 const repo=createBoundMailRepository({pool:{query:async()=>({rows:[]})},checkCleanup:async()=>{},
  personaAuthority:{capture:()=>({binding:{...f.current,personaId:1000000000,role:'merchant',sessionId,authorityVersion:'1'},
   withPersonaEffect:work=>work(client),assertRemoteAdmission:async()=>{}})}});
 assert.deepEqual(await repo.readSavedSend(raw),saved);
 const projection=queries.find(query=>query.sql.includes('project_bound_lab_mail_send'));
 assert.equal(projection.args[11],operationId);
 assert.equal(projection.args[12],f.scene.scene.grantId);
 assert.equal(queries.filter(query=>query.sql.includes('assert_mail_scene_execution_grant')).length,2);
 assert.equal(f.leases,1);
});
test('full saved-send request hash uses a read-only SQL projection under retained mail authority',async()=>{
 const f=fixture(),operationId=randomUUID(),sessionId=randomUUID(),queries=[];
 const raw={scope:f.current,targetId:f.target.targetId,target:f.target,persona:{id:1000000000,role:'merchant'},
  personaSession:{sessionId,authorityVersion:'1'},mode:'fixed',operationId};
 const client={async query(sql,args){queries.push({sql,args});
  if(sql.includes('assert_mail_scene_execution_grant'))return {rows:[{allowed:true}]};
  if(sql.includes('request_sha256'))return {rows:[{request_sha256:'a'.repeat(64)}]};
  return {rows:[]};}};
 const repo=createBoundMailRepository({pool:{query:async()=>({rows:[]})},checkCleanup:async()=>{},
  personaAuthority:{capture:()=>({binding:{...f.current,personaId:1000000000,role:'merchant',sessionId,authorityVersion:'1'},
   withPersonaEffect:work=>work(client),assertRemoteAdmission:async()=>{}})}});
 const digest=await repo.hashSendRequest(raw,{from:'merchant@lab',to:'customer@lab',
  subject:'Hello',body_markdown:'<b>literal</b>'});
 assert.equal(digest,'a'.repeat(64));
 const query=queries.find(row=>row.sql.includes('request_sha256'));
 assert.match(query.sql,/jsonb_build_array\('send'/);
 assert.match(query.sql,/CASE WHEN \$2='fixed'/);
 assert.equal(query.args[1],'fixed');
 assert.equal(queries.some(row=>row.sql.includes('bound_lab_mail(')),false);
 assert.equal(queries.filter(row=>row.sql.includes('assert_mail_scene_execution_grant')).length,2);
});

test('persona inbox tool and digest retain immutable birth with current scene provenance',async()=>{
 const f=fixture(),requestId=randomUUID(),caller={id:1000000000,role:'customer'};
 const first=requestDigest(f.target,caller,7,requestId).toString('hex');
 const legacy=requestDigest({...f.target},caller,7,requestId).toString('hex');
 assert.notEqual(first,legacy);
 let selected;
 const tools=createSecureShopPersonaInboxTools({trustedScope:f.current,trustedPersona:caller,
  authorizedTargetId:f.target.targetId,allowedMessageId:7,resolveTarget:async()=>f.target,
  checkCurrent:async()=>{},repository:{async list(target){selected=target;return [
   {messageId:7,ownerShopUserId:11,ownerShopRole:'customer',subject:'A'},
   {messageId:8,ownerShopUserId:12,ownerShopRole:'merchant',subject:'B'},
   {messageId:9,ownerShopUserId:13,ownerShopRole:'admin',subject:'C'}];},async read(){}},
  makeOperationId:()=>randomUUID()});
 const output=await tools['persona-inbox.list_messages']({});
 assert.equal(output.isError,undefined);
 assert.equal(mailScene.productScene(selected),f.scene);
 assert.deepEqual(mailScene.current(selected),f.current);
 assert.deepEqual(mailScene.birth(selected),{...f.birth,targetId:f.target.targetId});
});

test('persona inbox scene read uses the grant overload and current actor session in one transaction',async()=>{
 const f=fixture(),operationId=randomUUID(),personaSessionId=randomUUID(),queries=[];
 const body='Synthetic advisory note',bodyHash=require('node:crypto').createHash('sha256').update(body).digest();
 const client={async query(sql,args){queries.push({sql,args});
   if(sql.includes('assert_mail_scene_execution_grant'))return {rows:[{allowed:true}]};
   if(sql.includes('read_persona_inbox_message'))return {rows:[{event_id:operationId,message_id:7,
    owner_shop_user_id:12,owner_shop_role:'merchant',subject:'Note',body,body_sha256:bodyHash,
    acl_version:1,acl_mode:'advisory',acl_decision:'deny',cross_persona:true,disclosed:true}]};
   return {rows:[]};},release(){}};
 const repo=createSecureShopPersonaInboxRepository({connect:async()=>client,query:async()=>{throw Error('outside effect transaction');}},
  {checkCurrent:async()=>{},checkAclTransition:async()=>{},checkCleanup:async()=>{}});
 const result=await repo.read(f.target,{id:11,role:'customer'},
  {messageId:7,operationId,personaSession:{sessionId:personaSessionId,authorityVersion:'1'}});
 assert.equal(result.disclosed,true);assert.equal(f.leases,1);
 const effect=queries.find(q=>q.sql.includes('read_persona_inbox_message'));
 assert.match(effect.sql,/\$14::bigint/);
 assert.deepEqual(effect.args.slice(1,6),[f.current.launchId,f.current.scenarioId,f.current.generation,
  f.current.platformOwnerId,f.current.platformSessionId]);
 assert.deepEqual(effect.args.slice(11),[f.scene.scene.grantId,personaSessionId,'1']);
 assert.equal(queries.filter(q=>q.sql.includes('assert_mail_scene_execution_grant')).length,2);
});
