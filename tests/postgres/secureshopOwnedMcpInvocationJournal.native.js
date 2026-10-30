'use strict';
// Native SQL/lifecycle qualification with a controlled invocation manager. The
// existing registry discovery executor is real; no remote invocation is made.
const fs=require('node:fs'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createAssembly,bounded,publicationBarrier,identityCommitPool}=require('./secureshopOwnedMcpAssemblySupport');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {createAgentsMigrationView}=require('../helpers/secureshopAgentsMigrationView');
const C=require('../../server/services/secureshopOwnedMcpInvocationContract');
const MIGRATIONS='db/postgres/workshop-migrations/secureshop_agents';
(async()=>{
 const evidence={status:'running',modelCalls:0,browserCalls:0,remoteInvocationCalls:0,cases:[],manager:'controlled fixture; no remote drain/authentication proof'};
 const save=()=>fs.writeFileSync(process.env.MCP_ASSEMBLY_RESULT,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});save();
 let h,fresh,primary,gate,pending;const managerState={receipts:new Map(),calls:[],hold:null,unavailable:false};
 const manager={async retire(request){managerState.calls.push(request);if(managerState.unavailable)throw Error('controlled manager unavailable');
  if(managerState.hold){const selected=managerState.hold;managerState.hold=null;await selected.hold(null);}
  const key=request.fenceId+':'+request.managerInstanceId,receipt={...request,retired:true,drained:true};
  if(managerState.receipts.has(key))assert.deepEqual(managerState.receipts.get(key),receipt);else managerState.receipts.set(key,receipt);return structuredClone(receipt);
 }};
 const rows=async owner=>(await h.am.query(`SELECT invocation_id::text,request_sha256,receipt_sha256,state,drained,request_json,receipt_json,redacted_at
 FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=$1 ORDER BY invocation_id`,[owner.user.id])).rows;
 try{
  h=await createAssembly({invocationJournal:true,invocationManager:manager});
  const owner=await h.owner(),sibling=await h.owner();
  async function register(o,name){const result=await h.shop(o,'/admin/mcp/register',{version:1,action:'register',operationId:randomUUID(),expectedVersion:'0',name,transport:'sse',url:'http://attacker.training:8080/mcp',stdio_cmd:''});assert.equal(result.status,200);return(await h.snapshot(o)).entries[0];}
  const entry=await register(owner,'journal-owner'),siblingEntry=await register(sibling,'journal-sibling'),priorOwner=await h.snapshot(owner),priorSibling=await h.snapshot(sibling);
  // Representative pre-existing0011 trust data uses its unchanged repository.
  // Synthetic receipt hashes are lifecycle fixtures, never genuine model credit.
  const trustOwner=await h.owner(),trustScope={...trustOwner.scope,targetId:randomUUID(),serverIdentity:'historical-owned-trust',trustScenario:'rogue_registration'};
  const trustRepo=require('../../server/database/postgres/secureshopBoundMcpRepository').createSecureShopBoundMcpRepository(h.agents,{checkCurrent:value=>h.launches.assertCurrent(value),checkRotation:async()=>{throw Error('unused controlled rotation');},checkCleanup:async()=>{throw Error('unused controlled cleanup');}});
  await trustRepo.provision(trustScope);const trustTools=[{name:'forecast.lookup',description:'Historical controlled trust descriptor\r\n😀',inputSchema:{type:'object'}}],trustHash=require('../../server/services/secureshopMcpSchemaDigest').mcpSchemaDigest(trustTools);
  await trustRepo.recordDiscovery(trustScope,{expectedVersion:0,schemaSha256:trustHash,discoveryReceiptSha256:'d'.repeat(64),tools:trustTools});
  const trustOperation=randomUUID();await trustRepo.recordInvocation(trustScope,{operationId:trustOperation,schemaVersion:1,schemaSha256:trustHash,runId:randomUUID(),requestId:randomUUID(),callId:'historical-controlled',toolName:'forecast.lookup',argumentsSha256:'a'.repeat(64),remoteReceiptSha256:'b'.repeat(64),trustPolicySha256:'c'.repeat(64),approved:true,serverApproved:true,schemaApproved:true,trustScenario:'rogue_registration',behaviorClass:'public_forecast_lookup',resultSha256:'e'.repeat(64)});
  const trustSnapshot=async()=>{const value={};for(const name of ['bound_mcp_targets','bound_mcp_schema_versions','bound_mcp_tool_payloads','bound_mcp_invocations'])value[name]=(await h.agents.query(`SELECT * FROM secureshop_agents.${name} WHERE target_id=$1 ORDER BY 1`,[trustScope.targetId])).rows;
   value.columns=(await h.am.query("SELECT attname,format_type(atttypid,atttypmod) AS type,attnotnull FROM pg_attribute WHERE attrelid='secureshop_agents.bound_mcp_invocations'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum")).rows;return value;};
  const legacyBefore=await trustSnapshot();for(const name of ['bound_mcp_targets','bound_mcp_schema_versions','bound_mcp_tool_payloads','bound_mcp_invocations'])assert.equal(legacyBefore[name].length,1);
  const oldJournalProbe=require('../../server/database/postgres/secureshopOwnedMcpInvocationJournal').createOwnedMcpInvocationJournal({pool:h.agents});assert.deepEqual(await oldJournalProbe.existing(trustOwner.scope),[]);
  const beforeLedger=(await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.equal(beforeLedger.at(-1).name.slice(0,4),'0040');
  const view41=createAgentsMigrationView(41),view42=createAgentsMigrationView(42);
  const canonical=await readMigrations(MIGRATIONS);
  assert.deepEqual(await view41.migrate(h.am,MIGRATIONS),['0041_owned_mcp_invocation_journal.sql']);assert.deepEqual(await h.snapshot(owner),priorOwner);assert.deepEqual(await h.snapshot(sibling),priorSibling);assert.deepEqual(await trustSnapshot(),legacyBefore);
  let ledger=(await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(await view41.migrate(h.am,MIGRATIONS),[]);assert.deepEqual((await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
  assert.deepEqual(await trustSnapshot(),legacyBefore);
  const privilege=(await h.agents.query(`SELECT current_user AS role,
   has_column_privilege(current_user,'secureshop_agents.owned_mcp_invocation_journal','worker_token','SELECT') AS token_read,
   has_column_privilege(current_user,'secureshop_agents.owned_mcp_invocation_journal','request_json','SELECT') AS request_read,
   has_function_privilege(current_user,'secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb)','EXECUTE') AS settle`)).rows[0];
  assert.deepEqual(privilege,{role:'dvaia_secureshop_agents_runtime',token_read:false,request_read:true,settle:true});evidence.runtimePrivileges=privilege;
  for(const sql of ["INSERT INTO secureshop_agents.owned_mcp_invocation_journal DEFAULT VALUES","UPDATE secureshop_agents.owned_mcp_invocation_journal SET state='uncertain'","INSERT INTO secureshop_agents.owned_mcp_invocation_fences DEFAULT VALUES","UPDATE secureshop_agents.owned_mcp_invocation_fences SET kind='retirement'",'SELECT worker_token FROM secureshop_agents.owned_mcp_invocation_journal','DELETE FROM secureshop_agents.owned_mcp_invocation_journal','DELETE FROM secureshop_agents.owned_mcp_invocation_fences'])await assert.rejects(h.agents.query(sql),e=>e.code==='42501');
  const functions=['secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid)','secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb)','secureshop_agents.record_owned_mcp_invocation_fence(jsonb)'];
  for(const signature of functions){const acl=(await h.agents.query(`SELECT has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime_execute,
   EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
   FROM pg_proc p WHERE p.oid=$1::regprocedure`,[signature])).rows[0];assert.deepEqual(acl,{runtime_execute:true,public_execute:false});}
  const journal=require('../../server/database/postgres/secureshopOwnedMcpInvocationJournal').createOwnedMcpInvocationJournal({pool:h.agents,personaAuthority:h.authority});
  const launchAdmission=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(h.identity,{ownedMcpInvocationJournal:journal});
  const managerId=randomUUID(),runtimeSha='a'.repeat(64),policySha='b'.repeat(64);
  async function prepare(o,e,execution){
   const actor=await h.personaAuth.authenticateBoundToken({token:o.shopToken,scope:o.scope});
   const reader=require('../../server/database/postgres/secureshopOwnedMcpInvocationRepository').createOwnedMcpInvocationRepository({personaAuthority:h.authority}).capture({scope:o.scope,persona:actor.user,personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},entryId:e.entry_id});
   const raw={snapshot:await reader.readSnapshot(),runId:execution.runId,requestId:randomUUID(),callId:'owned-call',toolIndex:0,args:{query:'owned fixture'},mode:'vuln',invocationId:randomUUID(),personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},managerInstanceId:managerId,runtimeSha256:runtimeSha,policySha256:policySha};
   return{raw,handle:journal.prepare(raw,execution)};
  }
  async function admit(o,e,repository=launchAdmission){return h.lifecycle.runCoordinator.run(o.user.id,{timeoutMs:30000},execution=>execution.effect('journal-admit',async()=>{const prepared=await prepare(o,e,execution);const result=await repository.admitOwnedMcpInvocation(prepared.handle);assert.deepEqual(await repository.admitOwnedMcpInvocation(prepared.handle),result);return{...prepared,result};}));}
  gate=publicationBarrier();const heldAdmission=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identityCommitPool(h.identity,{hold:gate}),{ownedMcpInvocationJournal:journal});
  let returned=false;pending=admit(owner,entry,heldAdmission).then(value=>{returned=true;return value;});await bounded(Promise.race([gate.entered,pending.then(()=>{throw Error('admission returned before commit barrier');})]),10000,'identity commit barrier');
  assert.equal(returned,false);assert.equal((await rows(owner)).length,1);assert.equal(managerState.calls.length,0);gate.release();const first=await pending;pending=null;
  const other=await admit(sibling,siblingEntry);assert.equal((await rows(sibling)).length,1);
  const failedAdmission=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identityCommitPool(h.identity,{fail:true}),{ownedMcpInvocationJournal:journal});
  await assert.rejects(admit(owner,entry,failedAdmission),/fixture identity commit failure/);assert.equal((await rows(owner)).length,2);assert.equal(managerState.calls.length,0);
  evidence.cases.push('agents obligation persists before identity commit; failed commit returns no grant and never dispatches');

  // Qualify0042 over actual nonempty0041 obligations, including failed-COMMIT orphan.
  const beforeRecoveryOwner=await rows(owner),beforeRecoverySibling=await rows(sibling);
  assert.equal(beforeRecoveryOwner.length,2);assert.equal(beforeRecoverySibling.length,1);
  const ledger41=ledger;
  assert.deepEqual(await view42.migrate(h.am,MIGRATIONS),['0042_owned_mcp_invocation_recovery.sql']);
  assert.deepEqual(await rows(owner),beforeRecoveryOwner);assert.deepEqual(await rows(sibling),beforeRecoverySibling);assert.deepEqual(await trustSnapshot(),legacyBefore);
  ledger=(await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(ledger.slice(0,ledger41.length),ledger41);assert.deepEqual(ledger.map(({name,checksum})=>({name,checksum})),canonical.filter(m=>m.name<'0043_').map(({name,checksum})=>({name,checksum})));assert.deepEqual(await view42.migrate(h.am,MIGRATIONS),[]);assert.deepEqual((await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
  const recoverySignature='secureshop_agents.read_owned_mcp_invocation_recovery(uuid,integer,uuid,uuid,bigint,integer)';
  const recoveryAcl=(await h.agents.query(`SELECT has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime_execute,
   EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute FROM pg_proc p WHERE p.oid=$1::regprocedure`,[recoverySignature])).rows[0];assert.deepEqual(recoveryAcl,{runtime_execute:true,public_execute:false});await assert.rejects(h.agents.query('SELECT worker_token FROM secureshop_agents.owned_mcp_invocation_journal'),e=>e.code==='42501');await assert.rejects(h.agents.query("UPDATE secureshop_agents.owned_mcp_invocation_journal SET state='uncertain'"),e=>e.code==='42501');
  const recoverySql='SELECT * FROM secureshop_agents.read_owned_mcp_invocation_recovery($1,$2,$3,$4,$5,$6)',recoveryArgs=[first.raw.invocationId,owner.scope.platformOwnerId,owner.scope.launchId,owner.scope.scenarioId,owner.scope.generation,owner.scope.platformSessionId];
  const recoveredRow=(await h.agents.query(recoverySql,recoveryArgs)).rows[0];assert.equal(recoveredRow.invocation_id,first.raw.invocationId);assert.deepEqual(recoveredRow.request_json,beforeRecoveryOwner.find(r=>r.invocation_id===first.raw.invocationId).request_json);assert.match(recoveredRow.worker_token,/^[0-9a-f-]{36}$/);
  for(let i=0;i<recoveryArgs.length;i++)for(const value of [null,typeof recoveryArgs[i]==='number'?recoveryArgs[i]+1000:randomUUID()]){const changed=[...recoveryArgs];changed[i]=value;await assert.rejects(h.agents.query(recoverySql,changed),e=>e.code==='55000');assert.deepEqual(await rows(owner),beforeRecoveryOwner);assert.deepEqual(await rows(sibling),beforeRecoverySibling);}
  const recoveryRepo=require('../../server/database/postgres/secureshopOwnedMcpInvocationRecovery').createInvocationRecoveryRepository({pool:h.agents,recoveryAuthority:{assertCurrent:query=>h.launches.assertCurrent(query.scope)}});
  const recoveryQuery={invocationId:first.raw.invocationId,scope:owner.scope};const recoveryHandle=await recoveryRepo.prepare(recoveryQuery);assert.equal(recoveryRepo.identity(recoveryHandle).invocationId,first.raw.invocationId);
  evidence.recoveryReader={upgradeFrom0041:true,nonemptyOwnerRows:2,nonemptySiblingRows:1,runtimeExecute:true,publicExecute:false,nullAndWrongScopeDenied:true};evidence.cases.push('0041 populated obligations survive0042 upgrade; exact runtime reader denies null and foreign scope');save();
  // Separate current-tail transition after the bounded0042 recovery assertions.
  const ledger42=ledger;
  assert.deepEqual(await migrate(h.am,MIGRATIONS),canonical.filter(m=>m.name>'0042_owned_mcp_invocation_recovery.sql').map(m=>m.name));
  assert.deepEqual(await rows(owner),beforeRecoveryOwner);assert.deepEqual(await rows(sibling),beforeRecoverySibling);assert.deepEqual(await trustSnapshot(),legacyBefore);
  assert.deepEqual(await h.snapshot(owner),priorOwner);assert.deepEqual(await h.snapshot(sibling),priorSibling);
  ledger=(await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(ledger.slice(0,ledger42.length),ledger42);assert.deepEqual(ledger.map(({name,checksum})=>({name,checksum})),canonical.map(({name,checksum})=>({name,checksum})));
  assert.deepEqual(await migrate(h.am,MIGRATIONS),[]);assert.deepEqual((await h.am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
  const url=new URL(process.env.MCP_ASSEMBLY_AGENTS_FRESH_MIGRATION_URL);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/owasp_ai_goat_test_mcp_assembly_[a-f0-9]{12}_agents_fresh$/);
  fresh=new(require('pg').Pool)({connectionString:url.href,max:1,statement_timeout:10000});assert.equal((await migrate(fresh,MIGRATIONS)).length,(await readMigrations(MIGRATIONS)).length);assert.deepEqual(await migrate(fresh,MIGRATIONS),[]);assert.deepEqual((await fresh.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger.map(({name,checksum})=>({name,checksum})));
  evidence.historicalTrust={scope:'synthetic existing0011 repository rows, no model/effect credit',operationId:trustOperation,preservedTables:4,preservedSchema:true};
  evidence.migrations={fresh:true,populatedUpgrade:true,noOp:true,ledger:ledger.map(({name,checksum})=>({name,checksum})),duplicateAgentsRolePair:'canonical agents runtime/migration roles shared only by the two owned same-family fixture databases'};evidence.cases.push('fresh and populated upgrade and no-op preserve real registry rows');save();
  const stored=(await rows(owner)).find(row=>row.invocation_id===first.raw.invocationId);assert.deepEqual(stored.request_json.snapshot.tools,priorOwner.revisions[0].tools_json);assert.equal(stored.request_json.request.runId,first.raw.runId);
  const effects=(await h.identity.query('SELECT status,effect_key FROM graph_runtime.effects WHERE run_id=$1',[first.raw.runId])).rows;assert.equal(effects.length,1);assert.equal(effects[0].status,'completed');assert.equal(effects[0].effect_key,stored.request_json.effectKey);
  const replayRow=(await h.agents.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify(stored.request_json),randomUUID()])).rows[0];
  assert.equal(replayRow.invocation_id,first.raw.invocationId);assert.match(replayRow.worker_token,/^[0-9a-f-]{36}$/);evidence.functionTokenVisibility='SETOF exposes correlation token to trusted runtime role; no secrecy/authenticity claim';
  await assert.rejects(h.agents.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify({...stored.request_json,requestSha256:'c'.repeat(64)}),randomUUID()]),e=>e.code==='55000');
  for(const mutate of [v=>{v.request.binding.platformOwnerId=sibling.user.id;},v=>{v.request.binding.generation++;},v=>{v.request.registryVersion='999';},v=>{v.snapshot.tools[0].description='forged descriptor';},v=>{v.personaSession.sessionId=randomUUID();},v=>{v.personaSession.authorityVersion='999';}]){
   const ownerBefore=await rows(owner),siblingBefore=await rows(sibling);const changed=structuredClone(stored.request_json);changed.invocationId=randomUUID();mutate(changed);
   await assert.rejects(h.agents.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify(changed),randomUUID()]),e=>e.code==='55000');assert.deepEqual(await rows(owner),ownerBefore);assert.deepEqual(await rows(sibling),siblingBefore);
  }
  assert.equal((await rows(owner)).length,2);
  await assert.rejects(h.am.query("UPDATE secureshop_agents.owned_mcp_invocation_journal SET request_json='{}'::jsonb WHERE invocation_id=$1",[first.raw.invocationId]),e=>e.code==='55000');
  await assert.rejects(h.am.query('UPDATE secureshop_agents.bound_mcp_registry_entries SET current_version=current_version WHERE entry_id=$1',[entry.entry_id]),e=>e.code==='55000');
  const receipt={invocationId:first.raw.invocationId,requestSha256:first.result.requestSha256,managerInstanceId:managerId,runtimeSha256:runtimeSha,state:'completed',drained:true,result:{owned:true}};
  await assert.rejects(h.agents.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[first.raw.invocationId,randomUUID(),'completed',JSON.stringify(receipt)]),e=>e.code==='55000');
  for(const changed of [{...receipt,managerInstanceId:randomUUID()},{...receipt,requestSha256:'c'.repeat(64)},{...receipt,drained:false}])await assert.rejects(h.agents.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[first.raw.invocationId,replayRow.worker_token,'completed',JSON.stringify(changed)]),e=>e.code==='55000');
  await assert.rejects(journal.settlePrepared(first.handle,{...receipt,managerInstanceId:randomUUID()}));await recoveryRepo.settle(recoveryHandle,receipt);const terminal=await rows(owner);await journal.settlePrepared(first.handle,receipt);assert.deepEqual(await rows(owner),terminal);
  await assert.rejects(journal.settlePrepared(first.handle,{...receipt,result:{changed:true}}),e=>e.code==='55000');await assert.rejects(h.am.query('UPDATE secureshop_agents.bound_mcp_registry_entries SET current_version=current_version WHERE entry_id=$1',[entry.entry_id]),e=>e.code==='55000');
  evidence.cases.push('canonical identity and real persisted effect admit exact original descriptor once','runtime DML/token read denied; trusted function correlation and exact terminal settlement','unresolved commit-failure obligation still prevents registry replacement; terminal replay immutable');save();
  // Prepare under the real durable effect, then change canonical authority
  // before the identity admission transaction. No incidental missing-ALS denial.
  for(const kind of ['platform-session','persona-session','reset-before-grant']){
   const deniedOwner=await h.owner(),deniedEntry=await register(deniedOwner,'denied-'+kind);let prepared,resetRequest;
   gate=publicationBarrier();pending=h.lifecycle.runCoordinator.run(deniedOwner.user.id,{timeoutMs:30000},execution=>execution.effect('denied-admission',async()=>{
    prepared=await prepare(deniedOwner,deniedEntry,execution);await gate.hold(null);return launchAdmission.admitOwnedMcpInvocation(prepared.handle);
   }));
   // Keep the rejection observed while the independent authority mutation runs.
   pending.catch(()=>{});await bounded(Promise.race([gate.entered,pending.then(()=>{throw Error('denied admission ended before barrier');})]),10000,'revocation barrier');
   const callsBefore=managerState.calls.length;
   if(kind==='platform-session'){
    const replacement=await h.request('/auth/login',{body:{username:deniedOwner.user.username,password:'Owned-only-Password!42'}});assert.equal(replacement.status,200);
    assert.equal(await h.users.revokeSession(deniedOwner.token,deniedOwner.user.id),1);
    const sessions=(await h.identity.query('SELECT id,is_active FROM identity.user_sessions WHERE user_id=$1',[deniedOwner.user.id])).rows;
    assert.equal(sessions.find(r=>Number(r.id)===deniedOwner.scope.platformSessionId).is_active,0);assert(sessions.some(r=>Number(r.id)!==deniedOwner.scope.platformSessionId&&r.is_active===1));
   }else if(kind==='persona-session'){
    const replacement=await h.request('/shop/v2/auth/login',{launch:deniedOwner.launch,body:{username:'student_admin',password:'student123'}});assert.equal(replacement.status,200);
    const active=await h.personaAuth.authenticateBoundToken({token:replacement.body.token,scope:deniedOwner.scope});assert.notEqual(active.sessionId,prepared.raw.personaSession.sessionId);
    await h.personaAuth.logout({scope:deniedOwner.scope,token:deniedOwner.shopToken});assert.equal((await h.personaAuth.authenticateBoundToken({token:replacement.body.token,scope:deniedOwner.scope})).sessionId,active.sessionId);
   }else{
    resetRequest={launchId:deniedOwner.scope.launchId,expectedGeneration:deniedOwner.scope.generation,idempotencyKey:randomUUID()};
    const fenced=await h.launches.beginReset({...resetRequest,platformOwnerId:deniedOwner.scope.platformOwnerId,platformSessionId:deniedOwner.scope.platformSessionId});assert.equal(fenced.toGeneration,deniedOwner.scope.generation+1);
   }
   gate.release();await assert.rejects(pending,{code:kind==='platform-session'?'SESSION_UNAVAILABLE':kind==='persona-session'?'SHOP_AUTH_INVALID':'STALE_GENERATION'});pending=null;
   assert.equal((await rows(deniedOwner)).length,0);assert.equal(managerState.calls.length,callsBefore);
   if(resetRequest){const recovered=await h.request('/launch/reset',{token:deniedOwner.token,body:resetRequest});assert.equal(recovered.status,200);assert.equal(recovered.body.cleanupComplete,true);}
   evidence.cases.push(kind+' denies prepared grant with replacement or reset authority retained');save();
  }
  // Real canonical recovery composition, with an independently owned pool of
  // exactly one identity client. Status HTTP is represented by a controlled
  // manager barrier, never by a signed/remote invocation proof.
  const recoveryIdentityPool=h.createRecoveryIdentityPool();assert.equal(recoveryIdentityPool.options.max,1);
  const createRecovery=require('../../server/services/secureshopOwnedMcpRecoveryComposition').createOwnedMcpRecoveryComposition;
  const terminalReceipt=q=>({...q,state:'completed',drained:true,result:{owned:'recovery fixture'},resultSha256:C.digest({owned:'recovery fixture'})});
  const recoverySiblingBefore=await rows(sibling);
  const concurrentOwner=await h.owner(),concurrentEntry=await register(concurrentOwner,'recovery-concurrent'),concurrentGrant=await admit(concurrentOwner,concurrentEntry);
  let statusCount=0;
  const concurrentRecovery=createRecovery({identityPool:recoveryIdentityPool,agentsPool:h.agents,manager:{async status(q){statusCount++;return terminalReceipt(q);}}});
  const concurrentQuery={invocationId:concurrentGrant.raw.invocationId,scope:concurrentOwner.scope};
  pending=Promise.allSettled([concurrentRecovery.reconcile(concurrentQuery),concurrentRecovery.reconcile(concurrentQuery)]);pending.catch(()=>{});
  const concurrentResults=await bounded(pending,15000,'max1 concurrent recovery');pending=null;
  assert(concurrentResults.every(r=>r.status==='fulfilled'&&r.value.settled&&r.value.state==='completed')); assert.equal(statusCount,2);assert.equal(recoveryIdentityPool.totalCount,1);assert.equal(recoveryIdentityPool.waitingCount,0);
  const concurrentRows=await rows(concurrentOwner);assert.equal(concurrentRows.length,1);assert.equal(concurrentRows[0].state,'completed');assert.equal(concurrentRows[0].receipt_json.invocationId,concurrentGrant.raw.invocationId);
  evidence.cases.push('real canonical recovery settles concurrent status results with identity pool max1');save();
  for(const kind of ['platform-session','persona-session','reset']){
   const recoveryOwner=await h.owner(),recoveryEntry=await register(recoveryOwner,'recovery-'+kind),grant=await admit(recoveryOwner,recoveryEntry);
   const before=await rows(recoveryOwner);assert.equal(before.length,1);assert.equal(before[0].receipt_json,null);
   gate=publicationBarrier();let calls=0;
   const service=createRecovery({identityPool:recoveryIdentityPool,agentsPool:h.agents,manager:{async status(q){calls++;return gate.hold(terminalReceipt(q));}}});
   pending=service.reconcile({invocationId:grant.raw.invocationId,scope:recoveryOwner.scope});pending.catch(()=>{});
   await bounded(Promise.race([gate.entered,pending.then(()=>{throw Error('recovery ended before status barrier');})]),10000,'recovery status barrier');
   let expected=before;
   if(kind==='platform-session'){
    const replacement=await h.request('/auth/login',{body:{username:recoveryOwner.user.username,password:'Owned-only-Password!42'}});assert.equal(replacement.status,200);
    assert.equal(await h.users.revokeSession(recoveryOwner.token,recoveryOwner.user.id),1);
    const sessions=(await h.identity.query('SELECT id,is_active FROM identity.user_sessions WHERE user_id=$1',[recoveryOwner.user.id])).rows;
    assert.equal(sessions.find(r=>Number(r.id)===recoveryOwner.scope.platformSessionId).is_active,0);assert(sessions.some(r=>Number(r.id)!==recoveryOwner.scope.platformSessionId&&r.is_active===1));
   }else if(kind==='persona-session'){
    const replacement=await h.request('/shop/v2/auth/login',{launch:recoveryOwner.launch,body:{username:'student_admin',password:'student123'}});assert.equal(replacement.status,200);
    const active=await h.personaAuth.authenticateBoundToken({token:replacement.body.token,scope:recoveryOwner.scope});assert.notEqual(active.sessionId,grant.raw.personaSession.sessionId);
    await h.personaAuth.logout({scope:recoveryOwner.scope,token:recoveryOwner.shopToken});assert.equal((await h.personaAuth.authenticateBoundToken({token:replacement.body.token,scope:recoveryOwner.scope})).sessionId,active.sessionId);
   }else{
    const reset=await bounded(h.request('/launch/reset',{token:recoveryOwner.token,body:{launchId:recoveryOwner.scope.launchId,expectedGeneration:recoveryOwner.scope.generation,idempotencyKey:randomUUID()}}),30000,'reset during recovery status');
    assert.equal(reset.status,200);assert.equal(reset.body.cleanupComplete,true);expected=await rows(recoveryOwner);assert.equal(expected.length,1);assert(expected[0].redacted_at);assert.equal(expected[0].request_json,null);
   }
   gate.release();await assert.rejects(bounded(pending,15000,'denied recovery settlement'),e=>kind==='persona-session'?e.code==='MCP_RECOVERY_SETTLEMENT_UNCERTAIN'&&e.cause?.code==='SHOP_AUTH_INVALID':e.code===(kind==='platform-session'?'SESSION_UNAVAILABLE':'STALE_GENERATION'));pending=null;
   assert.equal(calls,1);assert.deepEqual(await rows(recoveryOwner),expected);assert.deepEqual(await rows(sibling),recoverySiblingBefore);
   evidence.cases.push('canonical recovery '+kind+' between status and settlement denies publication and preserves sibling');save();
  }
  evidence.canonicalRecovery={identityPoolMax:1,concurrentStatusCalls:statusCount,controlledManager:true,remoteInvocationCalls:0,originalSessionsOnly:true};
  // Completed invocations still require the manager generation tombstone.
  const siblingBefore=await h.snapshot(sibling),siblingJournal=await rows(sibling);gate=publicationBarrier();managerState.hold=gate;
  const resetInput={launchId:owner.scope.launchId,expectedGeneration:owner.scope.generation,idempotencyKey:randomUUID()};
  pending=h.request('/launch/reset',{token:owner.token,body:resetInput});await bounded(Promise.race([gate.entered,pending.then(value=>{throw Error('reset ended before manager drain '+value.status);})]),15000,'manager entry');
  assert.equal((await h.agents.query('SELECT count(*)::int AS n FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=$1',[owner.scope.launchId])).rows[0].n,0);assert.equal((await h.snapshot(owner)).entries.length,1);gate.release();const reset=await bounded(pending,30000,'reset drain');pending=null;assert.equal(reset.status,200);assert.equal(reset.body.cleanupComplete,true);
  const after=await rows(owner);assert.equal(after.length,terminal.length);for(let i=0;i<after.length;i++){assert.equal(after[i].invocation_id,terminal[i].invocation_id);assert.deepEqual(after[i].request_sha256,terminal[i].request_sha256);assert.deepEqual(after[i].receipt_sha256,terminal[i].receipt_sha256);assert.equal(after[i].request_json,null);assert.equal(after[i].receipt_json,null);assert(after[i].redacted_at);assert.equal(after[i].drained,true);}
  assert.deepEqual(await h.snapshot(sibling),siblingBefore);assert.deepEqual(await rows(sibling),siblingJournal);await assert.rejects(launchAdmission.admitOwnedMcpInvocation(first.handle),{code:'STALE_GENERATION'});
  await assert.rejects(h.agents.query(recoverySql,recoveryArgs),e=>e.code==='55000');await assert.rejects(recoveryRepo.prepare(recoveryQuery),{code:'STALE_LAUNCH'});await assert.rejects(recoveryRepo.settle(recoveryHandle,receipt),{code:'STALE_LAUNCH'});await assert.rejects(h.agents.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[first.raw.invocationId,recoveredRow.worker_token,'completed',JSON.stringify(receipt)]),e=>e.code==='55000');assert.deepEqual(await rows(owner),after);
  await h.disableServing();managerState.unavailable=true;const siblingReset={launchId:sibling.scope.launchId,expectedGeneration:sibling.scope.generation,idempotencyKey:randomUUID()};const failed=await h.request('/launch/reset',{token:sibling.token,body:siblingReset});assert.notEqual(failed.status,200);assert.equal((await rows(sibling))[0].redacted_at,null);
  managerState.unavailable=false;const recovered=await h.request('/launch/reset',{token:sibling.token,body:siblingReset});assert.equal(recovered.status,200);assert.equal(recovered.body.cleanupComplete,true);
  evidence.cases.push('held manager prevents SQL retirement; canonical reset preserves hashes and redacts raw values','disabled serving retains manager obligation and canonical reset retry recovers');save();
  const admin=await h.users.createUser({username:'delete-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash('owned-only',4)});await h.im.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]);
  const jobs=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(h.identity,{steps:['revoke_runs','secureshop','identity']}),admitted=await jobs.admit({requesterId:admin.id,subjectId:owner.user.id}),lease=await jobs.claim(admitted.jobId,120000);assert(lease);
  const deletion={jobId:admitted.jobId,subjectId:owner.user.id,leaseToken:lease.leaseToken,check:()=>jobs.listSecureShopResetIds({jobId:admitted.jobId,subjectId:owner.user.id,leaseToken:lease.leaseToken})};const siblingFinal=await rows(sibling);const deleted=await h.lifecycle.createStudentDeletionCleanup(jobs)(deletion);assert.equal(deleted.completed,true);assert.equal((await rows(owner)).length,0);assert.deepEqual(await rows(sibling),siblingFinal);
  evidence.cases.push('canonical deletion stage drains owner and removes authorized rows only');assert.deepEqual(await trustSnapshot(),legacyBefore);evidence.managerCalls=managerState.calls;evidence.status='passed';save();
 }catch(error){primary=error;evidence.status='failed';evidence.error={name:error.name,code:error.code,message:error.message};save();}
 finally{gate?.release();for(const close of [()=>pending?bounded(pending,30000,'pending reset'):Promise.resolve(),()=>h?.close(),()=>fresh?.end()])try{await close();}catch(error){primary=primary?new AggregateError([primary,error],'Native and cleanup errors'):error;}if(primary&&evidence.status==='passed')evidence.status='failed';save();}
 if(primary)throw primary;
})().catch(error=>{console.error(error);process.exitCode=1;});
