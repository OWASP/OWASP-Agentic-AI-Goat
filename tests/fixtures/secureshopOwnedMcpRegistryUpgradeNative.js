'use strict';
const assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
async function qualifyUpgrade({runtime,workM,a,b,admit,publish,register,change,seedAdmin,migrate,evidence}){
 const tables=['heads','entries','revisions','operations','cleanup_receipts'];
 const snapshot=async()=>{
  const result={};for(const name of tables)result[name]=(await runtime.query(`SELECT to_jsonb(t) row FROM secureshop_agents.bound_mcp_registry_${name} t ORDER BY to_jsonb(t)::text`)).rows;
  result.audits=(await runtime.query("SELECT to_jsonb(t) row FROM secureshop_agents.bound_audit_events t WHERE source_kind='bound_mcp_registry_operation' ORDER BY to_jsonb(t)::text")).rows;return result;
 };
 const preUpgrade=await snapshot();
 assert.ok(preUpgrade.revisions.length>=3);assert.ok(preUpgrade.operations.length>=3);
 const prior0035=fs.readFileSync(path.join(process.env.OWNED_MCP_REGISTRY_PRIOR_MIGRATIONS,'0035_owned_mcp_registry.sql'));
 const checksum=createHash('sha256').update(prior0035).digest('hex');
 assert.equal(checksum,'2986e860e4523f6596f695d97032985fdff48b63a42e076eb392180041a5a13e');
 assert.deepEqual(await migrate(workM,process.env.OWNED_MCP_REGISTRY_CANDIDATE_MIGRATIONS),['0036_owned_mcp_registry_publication.sql']);
 assert.deepEqual(await migrate(workM,process.env.OWNED_MCP_REGISTRY_CANDIDATE_MIGRATIONS),[]);
 assert.deepEqual(await snapshot(),preUpgrade);
 assert.equal((await workM.query("SELECT checksum FROM dvaia_migrations.ledger WHERE name='0035_owned_mcp_registry.sql'")).rows[0].checksum,checksum);
 const {assertOwnedMcpRegistryReady,createOwnedMcpRegistryRepository}=require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository');
 await assertOwnedMcpRegistryReady({pool:runtime,expectedDatabase:(await runtime.query('SELECT current_database() db')).rows[0].db});
 evidence.cases.push('unchanged0035 populated completed register/retire upgraded0036; exact all registry/audit evidence preserved; secondrun noop; grants unchanged');
 const entry=(await runtime.query('SELECT entry_id::text FROM secureshop_agents.bound_mcp_registry_entries WHERE platform_launch_id=$1',[a.launch])).rows[0].entry_id;
 const req=register(randomUUID(),'2'),admission=await admit(runtime,a,req);
 const valid=change(req.name,entry);
 const negatives={name:[{...valid,name:'wrong'}],endpoint:[{...valid,endpoint:'http://127.0.0.1:8099/other'}],transport:[{...valid,transport:'streamable-http'}],cardinality:[valid,change('extra',randomUUID())],action:[{...valid,action:'import'}]};
 for(const key of ['name','entryId','action','transport','endpoint','schemaSha256','tools','effect'])negatives['null_'+key]=[{...valid,[key]:null}];
 for(const [label,changes] of Object.entries(negatives)){
  const before=await snapshot();await assert.rejects(publish(runtime,a,req,admission,changes),e=>e.code==='55000',label);assert.deepEqual(await snapshot(),before,label);
 }
 for(const scope of [b,{...a,platformSession:b.platformSession},{...a,personaSession:b.personaSession}]){
  const before=await snapshot();
  if(scope.personaSession!==a.personaSession&&scope.launch===a.launch&&scope.platformSession===a.platformSession)await assert.rejects(admit(runtime,scope,register(randomUUID(),'2')),e=>e.code==='55000');
  else await assert.rejects(publish(runtime,scope,req,admission,[valid]),e=>e.code==='55000');
  assert.deepEqual(await snapshot(),before);
 }
 evidence.cases.push('direct runtime SQL rejects name endpoint transport extra changes action eight null fields and sibling/session authorities without any registry/audit mutation');
 await publish(runtime,a,req,admission,[{...valid,schemaSha256:'5'.repeat(64)}]);
 const replayBefore=await snapshot();await publish(runtime,a,req,admission,[{...valid,schemaSha256:'5'.repeat(64)}]);assert.deepEqual(await snapshot(),replayBefore);
 let version=3;
 const scope=s=>({launchId:s.launch,scenarioId:s.scenario,generation:1,platformOwnerId:s.owner,platformSessionId:s.platformSession});
 // Native agents authority is real; the separate identity-store launch check is
 // deliberately out of scope in this two-store migration qualification.
 const baseAuthority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:runtime,checkCurrent:async value=>{
  const retired=(await runtime.query('SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=$1 AND from_generation=$2',[value.launchId,value.generation])).rowCount;
  if(retired)throw Object.assign(Error('Retired native fixture launch'),{code:'STALE_LAUNCH'});
 }});
 let afterLookup;
 const authority={capture(input){const fence=baseAuthority.capture(input);return{...fence,async withPersonaEffect(work){let lookup=false;const result=await fence.withPersonaEffect(client=>work({query(...args){if(String(args[0]).includes("lifecycle='retired' AND name=ANY"))lookup=true;return client.query(...args);}}));if(lookup&&afterLookup)await afterLookup();return result;}};}};
 const repo=createOwnedMcpRegistryRepository({pool:runtime,personaAuthority:authority});
 const prepare=(s,request)=>repo.prepare({scope:scope(s),persona:{id:s.persona,role:'admin'},personaSession:{sessionId:s.personaSession,authorityVersion:'1'},request});
 async function retire(){const r={version:1,action:'retire',operationId:randomUUID(),expectedVersion:String(version),name:req.name};const ad=await admit(runtime,a,r);await publish(runtime,a,r,ad,[change(req.name,entry,'retire')]);version++;}
 async function reactivate(action,mode,schema){
  const request=action==='import'?{version:1,action:'import',operationId:randomUUID(),expectedVersion:String(version),xml_url:'http://127.0.0.1:8099/manifest.xml'}:register(randomUUID(),String(version));
  const ad=await repo.beginPrepared(prepare(a,request),{mode});const out=await repo.publish(ad,[{...change(req.name,randomUUID(),action),schemaSha256:schema}]);assert.equal(out.changes[0].entryId,entry);version++;return out;
 }
 await retire();await reactivate('register','vuln','6'.repeat(64));await retire();await reactivate('import','vuln','7'.repeat(64));await retire();
 // Both SQL and repository deny changed fixed pins even for retired names.
 for(const mutation of ['schema','endpoint']){
  const request=register(randomUUID(),String(version));if(mutation==='endpoint')request.url='http://127.0.0.1:8099/rotated';
  const ad=await admit(runtime,a,request,{mode:'fixed'}),changes=[{...change(req.name,entry),schemaSha256:mutation==='schema'?'8'.repeat(64):'7'.repeat(64),endpoint:request.url}];
  const before=await snapshot();await assert.rejects(publish(runtime,a,request,ad,changes),e=>e.code==='55000');assert.deepEqual(await snapshot(),before);
  const rr={...request,operationId:randomUUID()},ra=await repo.beginPrepared(prepare(a,rr),{mode:'fixed'}),prior=await snapshot();
  await assert.rejects(repo.publish(ra,[{...changes[0],entryId:randomUUID()}]),e=>e.code==='MCP_REGISTRY_FIXED_IDENTITY_DENIED');assert.deepEqual(await snapshot(),prior);
 }
 await reactivate('register','fixed','7'.repeat(64));await retire();await reactivate('import','fixed','7'.repeat(64));
 evidence.cases.push('register-retire-register and import restore stableUUID; vulnerable changed schema allowed; fixed exact register/import pins accepted; SQL+repository changed endpoint/schema rejected; exact completed replay');
 const c={launch:randomUUID(),scenario:randomUUID(),owner:9001,platformSession:9101,persona:9201,personaSession:randomUUID()};await seedAdmin(workM,c);
 const cr=register(randomUUID(),'0','race'),ca=await admit(runtime,c,cr),cid=randomUUID();await publish(runtime,c,cr,ca,[change('race',cid)]);
 const ct={version:1,action:'retire',operationId:randomUUID(),expectedVersion:'1',name:'race'},cta=await admit(runtime,c,ct);await publish(runtime,c,ct,cta,[change('race',cid,'retire')]);
 const rr=register(randomUUID(),'2','race'),ra=await repo.beginPrepared(prepare(c,rr),{mode:'vuln'});
 const unrelatedBefore=(await runtime.query('SELECT to_jsonb(t) row FROM secureshop_agents.bound_mcp_registry_entries t WHERE platform_launch_id<>$1 ORDER BY to_jsonb(t)::text',[c.launch])).rows;
 let retiredDuringLookup=false;
 afterLookup=async()=>{afterLookup=null;await runtime.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,1,$4,$5)',[randomUUID(),c.launch,c.scenario,c.owner,c.platformSession]);retiredDuringLookup=true;};
 await assert.rejects(repo.publish(ra,[change('race',randomUUID())]),e=>['STALE_LAUNCH','SHOP_AUTH_INVALID'].includes(e.code));assert.equal(retiredDuringLookup,true);
 assert.equal((await runtime.query('SELECT count(*)::int n FROM secureshop_agents.bound_mcp_registry_revisions WHERE operation_id=$1',[rr.operationId])).rows[0].n,0);
 assert.deepEqual((await runtime.query('SELECT to_jsonb(t) row FROM secureshop_agents.bound_mcp_registry_entries t WHERE platform_launch_id<>$1 ORDER BY to_jsonb(t)::text',[c.launch])).rows,unrelatedBefore);
 evidence.cases.push('actual agents retirement committed after retiredlookup fence release before publication; stale publish denied and siblings preserved');
 evidence.upgrade={immutable0035Sha256:checksum,negativeCases:Object.keys(negatives),stableEntryId:entry,finalRegistryVersion:String(version),limitations:['Seeded native agents authority; canonical identity reset admission/commit not exercised','No executor discovery, model, browser or Judge qualification']};
}
module.exports={qualifyUpgrade};

// Test-only bootstrap for an EMPTY owned agents database. The production loader
// performs the actual upgrade/no-op; canonical migration bytes never leave main.
async function installPreInvocationMapping(migration){
 const {readMigrations,executionSql}=require('../../db/postgres/migrate');
 const {withTransaction,verifyServer}=require('../../server/database/postgres');
 const directory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
 const all=await readMigrations(directory),selected=all.filter(row=>row.name<'0044_');
 assert.equal(selected.at(-1).name,'0043_mail_snapshot_integrity.sql');
 assert.equal(all[selected.length].name,'0044_owned_mcp_registry_executor_mapping.sql');
 await withTransaction(migration,async client=>{
  await verifyServer(client);await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
  assert.equal((await client.query("SELECT to_regclass('dvaia_migrations.ledger') AS ledger")).rows[0].ledger,null,'Upgrade database must be empty');
  await client.query('CREATE SCHEMA dvaia_migrations');
  await client.query('CREATE TABLE dvaia_migrations.ledger(name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())');
  for(const row of selected){await client.query(executionSql(row));await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',[row.name,row.checksum]);}
 });
 return {directory,selected:selected.map(({name,checksum})=>({name,checksum}))};
}
async function qualifyInvocationUpgrade({runtime,migration,evidence={}}){
 const C=require('../../server/services/secureshopOwnedMcpInvocationContract');
 const P=require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
 const {canonicalDigest}=require('../../server/services/mcp/protocolContext');
 const {registryRequestDigest}=require('../../server/services/secureshopMcpRegistryContract');
 const {mcpSchemaDigest}=require('../../server/services/secureshopMcpSchemaDigest');
 const {migrate}=require('../../db/postgres/migrate');
 const baseline=await installPreInvocationMapping(migration);
 const tools=[{name:'lookup',description:'Controlled migration fixture, no remote execution',inputSchema:{type:'object'}}];
 const templates=require('../../db/postgres/seeds/secureshop.json').shop_users.filter(x=>['student_admin','student_merchant','student_customer'].includes(x.username)).sort((a,b)=>a.username.localeCompare(b.username));
 assert.equal(templates.length,3);const aggregate=createHash('sha256');
 for(const t of templates){
  const digest=createHash('sha256').update(JSON.stringify([t.id,t.username,t.email,t.password,t.role,t.full_name??null,t.phone??null])).digest();aggregate.update(digest);
  await migration.query('INSERT INTO secureshop_agents.bound_persona_templates(username,shop_user_id,email,password_hash,role,full_name,phone,source_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[t.username,t.id,t.email,t.password,t.role,t.full_name??null,t.phone??null,digest]);
 }
 await migration.query('INSERT INTO secureshop_agents.bound_persona_template_catalog(singleton,version,template_count,template_sha256) VALUES(true,1,3,$1)',[aggregate.digest()]);
 const admin=templates.find(t=>t.role==='admin');assert(admin);
 const owners=[0,1].map(i=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:70001+i,platformSessionId:71001+i,shopUserId:admin.id,role:'admin',sessionId:randomUUID()}));
 const entries=[];
 for(const b of owners){
  await migration.query(`INSERT INTO secureshop_agents.bound_persona_sessions(session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
   original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,expires_at,credential_version)
   VALUES($1::uuid,sha256(convert_to($1::text,'UTF8')),$2,$3,1,$4,$5,$6,$7,'admin',$8,clock_timestamp()+interval '1 hour',1)`,
   [b.sessionId,b.launchId,b.scenarioId,b.platformOwnerId,b.platformSessionId,b.shopUserId,admin.username,admin.email]);
  const q={version:1,action:'register',operationId:randomUUID(),expectedVersion:'0',name:'upgrade-catalog',transport:'sse',url:'http://127.0.0.1:8099/mcp',stdio_cmd:''};
  const worker=randomUUID(),digest=registryRequestDigest(q),binding='3'.repeat(64);
  await runtime.query('SELECT * FROM secureshop_agents.admit_owned_mcp_registry_operation($1,$2,1,$3,$4,$5,$6,$7,1,\'vuln\',\'register\',0,decode($8,\'hex\'),decode($9,\'hex\'),$10,$11::jsonb)',[b.launchId,b.scenarioId,b.platformOwnerId,b.platformSessionId,q.operationId,b.shopUserId,b.sessionId,digest,binding,worker,JSON.stringify(q)]);
  const change={name:q.name,entryId:randomUUID(),action:'register',transport:'sse',endpoint:q.url,schemaSha256:mcpSchemaDigest(tools),tools,effect:{isolation:'controlled-migration-fixture',drained:true}};
  const receipt={version:'secureshop-owned-mcp-registry.v1',operationId:q.operationId,state:'completed',action:'register',requestSha256:digest,registryVersion:'1',changes:[Object.fromEntries(['name','entryId','action','schemaSha256','effect'].map(k=>[k,change[k]]))]};
  await runtime.query('SELECT * FROM secureshop_agents.publish_owned_mcp_registry_operation($1,$2,1,$3,$4,$5,$6,decode($7,\'hex\'),decode($8,\'hex\'),$9::jsonb,decode($10,\'hex\'),$11::jsonb,$12)',[b.launchId,b.scenarioId,b.platformOwnerId,b.platformSessionId,q.operationId,worker,digest,binding,JSON.stringify(receipt),canonicalDigest(receipt),JSON.stringify([change]),randomUUID()]);
  entries.push(change);
 }
 const old=[];
 function envelope(index){
  const {sessionId,...binding}=owners[index],entry=entries[index];
  const snapshot=C.snapshot({binding,entryId:entry.entryId,registryVersion:'1',schemaSha256:entry.schemaSha256,tools});
  const request=C.request({snapshot,runId:randomUUID(),requestId:randomUUID(),callId:'upgrade',toolIndex:0,args:{},mode:'vuln'});
  return {invocationId:randomUUID(),snapshot,request,requestSha256:C.digest(request),personaSession:{sessionId,authorityVersion:'1'},managerInstanceId:randomUUID(),runtimeSha256:'a'.repeat(64),policySha256:C.digest({fixture:'migration-only'}),effectKey:randomUUID()};
 }
 const admit=async(v,worker)=>runtime.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify(v),worker]);
 const settle=async(v,worker,receipt)=>runtime.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[v.invocationId,worker,receipt.state,JSON.stringify(receipt)]);
 for(const [ownerIndex,state,drained] of [[0,'admitted',false],[0,'completed',true],[0,'uncertain',true],[1,'completed',true]]){
  const v=envelope(ownerIndex),worker=randomUUID();await admit(v,worker);
  const receipt={invocationId:v.invocationId,requestSha256:v.requestSha256,managerInstanceId:v.managerInstanceId,runtimeSha256:v.runtimeSha256,state,drained};
  if(state!=='admitted')await settle(v,worker,receipt);old.push({v,worker,receipt});
 }
 const snapshot=async()=>{
  const result={};for(const name of ['owned_mcp_invocation_journal','owned_mcp_invocation_fences','bound_mcp_registry_entries','bound_mcp_registry_revisions','bound_mcp_registry_operations','bound_persona_sessions'])result[name]=(await migration.query(`SELECT to_jsonb(t) AS row FROM secureshop_agents.${name} t ORDER BY to_jsonb(t)::text`)).rows;
  return result;
 };
 const before=await snapshot();assert.equal(before.owned_mcp_invocation_journal.length,4);
 assert.deepEqual(await migrate(migration,baseline.directory),['0044_owned_mcp_registry_executor_mapping.sql']);
 assert.deepEqual(await snapshot(),before);
 for(const {v,worker,receipt} of old){await admit(v,worker);if(receipt.state==='completed')await settle(v,worker,receipt);}
 assert.deepEqual(await snapshot(),before,'Legacy wrapper replay must be byte preserving');
 await require('../../server/services/secureshopRegisteredInvocationProduction').assertRegisteredInvocationReadiness({runtimePool:runtime,migrationPool:migration});
 await assert.rejects(runtime.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation_legacy($1::jsonb,$2)',[JSON.stringify(old[0].v),old[0].worker]),{code:'42501'});
 const mapped=envelope(0),entry=entries[0];
 const q=P.request({version:1,instanceId:mapped.managerInstanceId,operationId:mapped.invocationId,entry:{entryId:entry.entryId,registryVersion:'1',transport:entry.transport,endpoint:entry.endpoint,schemaSha256:entry.schemaSha256,tools},toolName:'lookup',args:{}});
 mapped.executorMapping={version:1,request:q,requestSha256:P.digest(q),instanceId:mapped.managerInstanceId,runtimeSha256:mapped.runtimeSha256};
 const wrong=structuredClone(mapped);wrong.executorMapping.request.entry.endpoint='http://127.0.0.1:8099/foreign';wrong.executorMapping.requestSha256=P.digest(wrong.executorMapping.request);
 await assert.rejects(admit(wrong,randomUUID()),{code:'55000'});assert.deepEqual(await snapshot(),before);
 await admit(mapped,randomUUID());
 const after=await snapshot();assert.equal(after.owned_mcp_invocation_journal.length,5);
 const oldRows=after.owned_mcp_invocation_journal.filter(x=>x.row.invocation_id!==mapped.invocationId);assert.deepEqual(oldRows,before.owned_mcp_invocation_journal);
 assert.deepEqual(await migrate(migration,baseline.directory),[]);assert.deepEqual(await snapshot(),after);
 const proof={version:1,status:'passed',legacyRows:4,newMappedRows:1,legacyStates:['admitted','completed','uncertain-drained'],exactRowsPreserved:true,wrapperReplayPreserved:true,grantsVerified:true,mappedEndpointDenied:true,secondRunNoop:true,modelCalls:0,remoteCalls:0,genuineCredit:0,
  beforeSha256:canonicalDigest(before),afterSha256:canonicalDigest(after),limitations:['Controlled agents-native authority and SQL receipts only; no actual executor/identity/Judge proof']};
 evidence.invocationUpgrade=proof;return proof;
}
module.exports.installPreInvocationMapping=installPreInvocationMapping;
module.exports.qualifyInvocationUpgrade=qualifyInvocationUpgrade;
