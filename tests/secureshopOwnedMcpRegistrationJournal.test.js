'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createOwnedMcpRegistrationJournal}=require('../server/database/postgres/secureshopOwnedMcpRegistrationJournal');
const {createOwnedMcpRegistrationLifecycle}=require('../server/services/secureshopOwnedMcpRegistrationLifecycle');
const {withEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {registryRequestDigest}=require('../server/services/secureshopMcpRegistryContract');
const id=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
const scope={launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:11,platformSessionId:12};
const execution={runId:id(3),ownerKey:'bound-conversation',durableGeneration:'1'};
const args={name:'owned-package',transport:'stdio',stdio_cmd:'printf exact > /owned-mcp-files/stdio-effect'};
const request={version:1,action:'register',operationId:id(4),expectedVersion:'0',...args,url:''};
const raw={version:1,scope,persona:{id:15,role:'admin'},personaSession:{sessionId:id(5),authorityVersion:'2'},
 runId:execution.runId,callId:'model-call-1',step:1,tool:'mcp-registry.register',args,argsSha256:canonicalDigest(args),
 request,requestSha256:registryRequestDigest(request),instanceId:id(6),runtimeDigest:'a'.repeat(64),mode:'vuln'};
function fixture(){
 const rows=new Map();let queries=0;
 const pool={async query(sql,values){queries++;
  if(sql.includes('admit_owned_mcp_registration')){const v=JSON.parse(values[0]);if(rows.has(v.request.operationId))throw Error('already admitted');
   const row={operation_id:v.request.operationId,state:'admitted',drained:false,request_sha256:Buffer.from(v.requestSha256,'hex'),request_json:v};rows.set(row.operation_id,row);return{rows:[row]};}
  if(sql.includes('settle_owned_mcp_registration')){const row=rows.get(values[0]),r=JSON.parse(values[2]);Object.assign(row,{state:r.state,drained:r.drained,receipt_json:r});return{rows:[row]};}
  throw Error('Unexpected journal query');}};
 const personaAuthority={capture(input){return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},withPersonaEffect:work=>work(pool)}}};
 return{journal:createOwnedMcpRegistrationJournal({pool,personaAuthority,makeId:()=>id(7)}),rows,queries:()=>queries};
}
test('registration admission requires the current durable effect and private handle; preserves original command',async()=>{
 const f=fixture();assert.throws(()=>f.journal.prepare(raw,execution),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});
 await assert.rejects(f.journal.admitPrepared({}),{code:'MCP_REGISTRATION_ADMISSION_REQUIRED'});assert.equal(f.queries(),0);
 let handle;
 await withEffectAdmission(execution,'request:1:model-call-1',async()=>{
  handle=f.journal.prepare(raw,execution);assert.deepEqual(f.journal.scopeOf(handle),scope);
  await f.journal.admitPrepared(handle);
  assert.equal(f.rows.get(request.operationId).request_json.args.stdio_cmd,args.stdio_cmd);
  assert.equal(f.rows.get(request.operationId).request_json.effectKey,'request:1:model-call-1');
  await assert.rejects(f.journal.admitPrepared(handle),/already admitted/);
 });
 await assert.rejects(f.journal.admitPrepared(handle),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});
});
test('registration envelope rejects changed command or forged run before admission',async()=>{
 const f=fixture();await withEffectAdmission(execution,'effect',async()=>{
  assert.throws(()=>f.journal.prepare({...raw,args:{...args,stdio_cmd:'different'}},execution));
  assert.throws(()=>f.journal.prepare({...raw,runId:id(8)},execution));
 });assert.equal(f.queries(),0);
});
test('unknown registration status cannot claim cleanup; exact completed receipt can settle after request expires',async()=>{
 const f=fixture();let handle;await withEffectAdmission(execution,'effect',async()=>{handle=f.journal.prepare(raw,execution);await f.journal.admitPrepared(handle)});
 const identity=f.journal.identity(handle);
 await assert.rejects(f.journal.settlePrepared(handle,{status:{version:1,...identity,state:'unknown',drained:true}}));
 const result=await f.journal.settlePrepared(handle,{status:{version:1,...identity,state:'unknown',drained:false}});
 assert.equal(result.state,'uncertain');assert.equal(result.drained,false);
 await assert.rejects(f.journal.settlePrepared(handle,{receipt:{version:1,...identity,operationId:id(9),state:'completed',drained:true,changes:[]}}));
 const completed=await f.journal.settlePrepared(handle,{receipt:{version:1,...identity,state:'completed',drained:true,changes:[]}});
 assert.equal(completed.state,'completed');assert.equal(completed.drained,true);
});
test('reset waits exact owned registration drain and never fences unknown executor state',async()=>{
 let state='unknown',fences=0;const called=[];
 const journal={async existing(s){assert.deepEqual(s,scope);return[{operation_id:id(4),instance_id:id(6),runtime_digest:raw.runtimeDigest,request_sha256:raw.requestSha256,drained:false}]},async recordFence(v){fences++;assert.deepEqual(v.operationIds,[id(4)]);assert.equal(v.platformOwnerId,11)}};
 const client={async registrationHealth(){return{instanceId:id(6),runtimeDigest:raw.runtimeDigest}},async registrationState(q,options){called.push(q);assert.equal(options.drain,true);return{version:1,...q,state,drained:state==='retired'}}};
 const cleanupAuthority={async getOperation(resetId){return{resetId,status:'fenced',binding:scope}}};
 const lifecycle=createOwnedMcpRegistrationLifecycle({journal,client,cleanupAuthority});
 await assert.rejects(lifecycle.beforeRetirement(id(10)),{code:'MCP_REGISTRATION_DRAIN_REQUIRED'});assert.equal(fences,0);
 state='retired';await lifecycle.beforeRetirement(id(10));assert.equal(fences,1);assert.equal(called.length,2);
});
test('real launch repository exposes registration admission and commits identity authority after journal admission',async()=>{
 const {createSecureShopLaunchRepository}=require('../server/database/postgres/secureshopLaunchRepository');
 const events=[];let stale=false;const now=new Date('2026-10-20T00:00:00Z'),expires=new Date('2026-10-21T00:00:00Z');
 const client={async query(sql){events.push(sql);
  if(sql.includes('FROM identity.secureshop_authority_owners'))return{rows:[{id:11,is_active:true}]};
  if(sql.includes('FROM identity.secureshop_authority_sessions'))return{rows:[{id:12,user_id:11,is_active:true,expires_at:expires}]};
  if(sql.includes('clock_timestamp() AS now'))return{rows:[{now}]};
  if(sql.includes('FROM identity.secureshop_launches'))return{rows:[{platform_session_id:12,status:'active',expires_at:expires,generation:stale?2:1,scenario_id:scope.scenarioId}]};
  return{rows:[]};},release(){events.push('release')}};
 const pool={query:client.query,async connect(){return client}},handle=Object.freeze({});
 const journal={scopeOf(value){assert.equal(value,handle);return scope},async admitPrepared(value){assert.equal(value,handle);events.push('journal-admitted');return{state:'admitted'}}};
 const repository=createSecureShopLaunchRepository(pool,{ownedMcpRegistrationJournal:journal});
 assert.equal(typeof repository.admitOwnedMcpRegistration,'function');
 assert.deepEqual(await repository.admitOwnedMcpRegistration(handle),{state:'admitted'});
 assert.ok(events.indexOf('journal-admitted')<events.indexOf('COMMIT'));
 events.length=0;stale=true;await assert.rejects(repository.admitOwnedMcpRegistration(handle),{code:'STALE_GENERATION'});
 assert.ok(!events.includes('journal-admitted'));assert.ok(events.includes('ROLLBACK'));
});
test('shutdown scans durable unresolved registrations after live promises disappear and rejects unknown drain',async()=>{
 const row={operation_id:id(4),instance_id:id(6),runtime_digest:raw.runtimeDigest,request_sha256:raw.requestSha256,drained:false};
 let state='unknown',drained=false,recorded=0;
 const journal={async existing(){return[]},async recordFence(){throw Error('shutdown is not retirement')},async unsettled(){return drained?[]:[row]},async recordDrain(proof){assert.equal(proof.operationId,id(4));assert.equal(proof.drained,true);recorded++;drained=true}};
 const client={async registrationHealth(){return{instanceId:id(6),runtimeDigest:raw.runtimeDigest}},async registrationState(identity){return{version:1,...identity,state,drained:state==='retired'}}};
 const lifecycle=createOwnedMcpRegistrationLifecycle({journal,client});
 await assert.rejects(lifecycle.shutdown(),{code:'MCP_REGISTRATION_DRAIN_REQUIRED'});assert.equal(recorded,0);
 state='retired';await lifecycle.shutdown();assert.equal(recorded,1);assert.equal(drained,true);
});
test('tracked registry service proves only pretransport failures not dispatched',async()=>{
 const {createOwnedMcpRegistry}=require('../server/services/secureshopOwnedMcpRegistry');
 let failBefore=true,entered=0,noDispatch=0;
 const admission={newlyAdmitted:true,prepared:{request},fence:{async assertRemoteAdmission(){if(failBefore)throw Error('authority changed')}}};
 const repository={prepare:()=>({scope,request}),async beginPrepared(){return admission},async activeEntries(){return[]},async publish(){throw Error('unexpected')},async finish(){},async read(){}};
 const executor={async execute(){throw Error('legacy route forbidden')},async registerOwned(){entered++;throw Error('response lost')}};
 const service=createOwnedMcpRegistry({repository,executor,readMode:async()=>'vuln'});
 const options={registrationIdentity:{instanceId:id(6),operationId:request.operationId,requestSha256:raw.requestSha256},expectedRegistrationMode:'vuln',async assertRunCurrent(){},async onRegistrationReceipt(){},async onRegistrationNotDispatched(){noDispatch++}};
 await assert.rejects(service.mutate({},options),/authority changed/);assert.equal(entered,0);assert.equal(noDispatch,1);
 failBefore=false;await assert.rejects(service.mutate({},options),{code:'MCP_REGISTRY_OUTCOME_UNCERTAIN'});
 assert.equal(entered,1);assert.equal(noDispatch,1);
});
