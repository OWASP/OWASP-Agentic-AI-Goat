'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createSyntheticUserDirectoryRepository:create}=require('../server/database/postgres/secureshopSyntheticUserDirectoryRepository');
test('synthetic records are independent, persisted once, JSONB-order stable and scope parameterized',async()=>{
 const repository=create({pool:{query:async()=>{throw Error('No authentication source');}},audit:{append:async(_client,event)=>{assert.deepEqual(JSON.parse(event.paramsJson),{found:true});assert.equal(event.sourceKind,'synthetic_user_lookup');}}});
 const prepared=await repository.prepare();assert.equal(prepared.length,3);
 assert.ok(prepared.every(row=>row.api_key.startsWith('TRAINING_API_')&&row.session_token.startsWith('TRAINING_SESSION_')&&/^\$2[ab]\$10\$/.test(row.password)));
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};let stored;const calls=[];
 const client={query:async(sql,args)=>{calls.push([sql,args]);if(sql.startsWith('INSERT'))stored??={rows_json:JSON.parse(args[5]).map(row=>Object.fromEntries(Object.entries(row).reverse())),content_sha256:args[6]};return{rows:sql.startsWith('SELECT')?[stored]:[]};}};
 const first=await repository.lookup(client,{scope,username:'student_admin',prepared});
 const fresh=await repository.prepare();assert.notEqual(fresh[2].api_key,prepared[2].api_key);
 assert.deepEqual(await repository.lookup(client,{scope,username:'student_admin',prepared:fresh}),first);
 assert.deepEqual(calls.find(([sql])=>sql.startsWith('SELECT'))[1],[scope.launchId,scope.scenarioId,1,1,2]);
 await assert.rejects(repository.lookup(client,{scope,username:'student_admin',prepared:JSON.parse(JSON.stringify(prepared))}),/Trusted synthetic/);
 stored.content_sha256=Buffer.alloc(32);await assert.rejects(repository.lookup(client,{scope,username:'student_admin',prepared}),/integrity/);
});
test('readiness rejects cleanup privilege and exact bounds drift',async()=>{
 const base={permitted:true,mutable:false,columns:false,lifecycle:true};
 const safe={private_cleanup:true,runtime_execute:false,public_execute:false};
 const bounds=[{conname:'synthetic_directory_rows_type',expression:"(jsonb_typeof(rows_json) = 'array'::text)",convalidated:true},{conname:'synthetic_directory_rows_count',expression:'(jsonb_array_length(rows_json) = 3)',convalidated:true},{conname:'synthetic_directory_rows_bytes',expression:'(octet_length((rows_json)::text) < 32768)',convalidated:true}];
 for(const mode of ['valid','runtime','public','bounds','unvalidated']){
  let call=0;const repo=create({audit:{append(){}},pool:{query:async()=>{call++;return{rows:call===1?[base]:call===2?[{...safe,...(mode==='runtime'?{runtime_execute:true}:mode==='public'?{public_execute:true}:{})}]:bounds.map((b,i)=>i===2&&mode==='bounds'?{...b,expression:'(octet_length((rows_json)::text) < 65536)'}:i===2&&mode==='unvalidated'?{...b,convalidated:false}:b)};}}});
  if(mode==='valid')await repo.checkReadiness();else await assert.rejects(repo.checkReadiness(),/unavailable/);
 }
});

async function agentFixture(mode='vuln'){
 const {createHash}=require('node:crypto'),events=[],queries=[],auditRows=new Map();let stored;
 const auditStore=require('../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:{query:async()=>{throw Error('Use captured same-client effect');}}});
 const repository=create({pool:{query:async()=>{throw Error('No authentication source');}},audit:{append:async(client,event)=>{const receipt=await auditStore.append(client,event);events.push(structuredClone(event));return receipt;}}});
 const prepared=await repository.prepare(),scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:11};
 const context={scope,persona:{id:13,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'3'},username:'student_admin',prepared,
  modeExecution:{version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',mode,generation:0,modeStamp:'mode-0',scope},
  sceneExecution:{targetId:randomUUID(),sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID()}};
 const client={async query(sql,args){queries.push({sql,args});
  if(sql.startsWith('INSERT INTO secureshop_agents.bound_audit_events')){
   assert.equal(typeof args[11],'string');assert.equal(typeof args[14],'string');assert.equal(args[14],args[0]);
   assert.deepEqual(args.slice(1,8),[scope.launchId,scope.scenarioId,1,7,11,13,'admin']);
   auditRows.set(args[0],{params_json:require('pg').types.getTypeParser(25,'text')(args[11])});return{rowCount:1,rows:[{event_id:args[0]}]};
  }
  if(sql.startsWith('INSERT')){
   const jsonb=require('pg').types.getTypeParser(3802,'text'),bytea=require('pg').types.getTypeParser(17,'text');
   stored??={rows_json:jsonb(args[5]).map(row=>Object.fromEntries(Object.entries(row).reverse())),content_sha256:bytea('\\x'+args[6].toString('hex'))};return{rows:[]};
  }
  if(sql.includes('SELECT params_json')){
   assert.match(sql,/source_id=\$1::text/);assert.deepEqual(args.slice(1),[scope.launchId,scope.scenarioId,1,7,11,13]);
   return{rows:auditRows.has(args[0])?[auditRows.get(args[0])]:[]};
  }
  if(sql.startsWith('SELECT')){
   if(!stored)return{rows:[]};
   if(sql.includes('AS safe_user')){
    const user=stored.rows_json.find(row=>row.username===args[5]);
    return{rows:[{content_sha256:stored.content_sha256,safe_user:user?{id:user.id,username:user.username,role:user.role}:null}]};
   }
   return{rows:[stored]};
  }
  return{rows:[]};
 }};
 return{repository,context,client,events,queries,prepared,hash:value=>createHash('sha256').update(value).digest('hex'),
  corruptAudit:(id,value)=>auditRows.set(id,{params_json:value}),forget:()=>{stored=undefined;},mutateRow:()=>{stored.rows_json[2].api_key='CHANGED_SYNTHETIC';},stored:()=>stored};
}

test('agent lookup retains complete original synthetic fields and immutable exact audit reference; recovery performs only reads',async()=>{
 const f=await agentFixture(),result=await f.repository.lookupForAgent(f.client,f.context);
 assert.equal(result.version,1);assert.equal(result.status,'complete');assert.deepEqual(Object.keys(result.user).sort(),['id','username','role','email','full_name','phone','password','api_key','session_token'].sort());
 assert.match(result.user.password,/^\$2[ab]\$10\$/);assert.match(result.user.api_key,/^TRAINING_API_/);assert.match(result.user.session_token,/^TRAINING_SESSION_/);
 assert.equal(result.user.email,'admin@training.example.invalid');assert.equal(result.user.full_name,'Synthetic admin');assert.equal(result.user.phone,'+1-202-555-0100');
 assert.deepEqual(result.receipt.scope,f.context.scope);assert.deepEqual(result.receipt.personaSession,f.context.personaSession);assert.deepEqual(result.receipt.sceneExecution,f.context.sceneExecution);assert.deepEqual(result.receipt.modeExecution,f.context.modeExecution);
 assert.equal(result.receipt.username,'student_admin');assert.equal(f.events.length,1);assert.equal(f.events[0].sourceKind,'synthetic_user_agent_lookup');
 assert.deepEqual(JSON.parse(f.events[0].paramsJson),{version:1,status:'complete',receipt:result.receipt});
 const before=f.queries.length;assert.deepEqual(await f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt}),result);
 assert(f.queries.slice(before).every(query=>query.sql.startsWith('SELECT')));assert.equal(f.events.length,1);
});

test('fixed model and manual lookup use SQL identity projection before protected observation',async()=>{
 const f=await agentFixture('fixed'),result=await f.repository.lookupForAgent(f.client,f.context);
 assert.equal(result.status,'redacted');assert.deepEqual(result.user,{id:3,username:'student_admin',role:'admin'});
 const selects=f.queries.filter(q=>q.sql.startsWith('SELECT'));assert.equal(selects.length,1);assert.match(selects[0].sql,/jsonb_build_object\('id',u->'id','username',u->'username','role',u->'role'\)/);
 assert.doesNotMatch(selects[0].sql,/SELECT rows_json|u->'(password|api_key|session_token|email|full_name|phone)'/);
 const recovered=await f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt});assert.deepEqual(recovered,result);assert.equal(f.events.length,1);
 const manual=await f.repository.lookup(f.client,{scope:f.context.scope,username:f.context.username,prepared:f.prepared,persona:f.context.persona,mode:'fixed'});
 assert.deepEqual(manual,result.user);assert(f.queries.filter(q=>q.sql.startsWith('SELECT')&&!q.sql.includes('bound_audit_events')).every(q=>q.sql.includes('AS safe_user')));
 assert.deepEqual(JSON.parse(f.events[1].paramsJson),{found:true});assert.equal(f.events[1].sourceKind,'synthetic_user_lookup');
});

test('foreign epoch, owner, session, scene or receipt and missing audit cannot be substituted for original agent source',async()=>{
 const f=await agentFixture(),result=await f.repository.lookupForAgent(f.client,f.context);
 for(const mutate of [x=>x.scope.generation++,x=>x.persona.id++,x=>x.personaSession.authorityVersion='4',x=>x.sceneExecution.grantId=randomUUID(),
  x=>x.modeExecution.generation++,x=>x.reference.username='student_customer',x=>x.reference.rowSha256='a'.repeat(64),x=>x.reference.eventId=randomUUID()]){
  const input=structuredClone({...f.context,reference:result.receipt});mutate(input);await assert.rejects(f.repository.readAgentLookup(f.client,input),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 }
 assert.equal(f.events.length,1);
 // A manual lookup event cannot become an original agent source.
 const original=f.events[0].paramsJson;f.corruptAudit(result.receipt.eventId,JSON.stringify({found:true}));await assert.rejects(f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});f.corruptAudit(result.receipt.eventId,original);
 f.mutateRow();await assert.rejects(f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 f.forget();await assert.rejects(f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});assert.equal(f.events.length,1);
});

test('unknown synthetic username is a retained not-found observation without invented protected fields',async()=>{
 const f=await agentFixture();f.context.username='unmatched-owned-user';const result=await f.repository.lookupForAgent(f.client,f.context);
 assert.equal(result.status,'not_found');assert.equal(result.user,null);assert.equal(result.receipt.rowSha256,f.hash('null'));
 assert.deepEqual(await f.repository.readAgentLookup(f.client,{...f.context,reference:result.receipt}),result);
});
