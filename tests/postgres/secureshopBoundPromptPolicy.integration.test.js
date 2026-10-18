'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
const agentsDirectory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
function migrationView(){
 const fsp=require('node:fs/promises'),{Module,createRequire}=require('node:module');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(directory,...args){assert.equal(path.resolve(directory),agentsDirectory);return(await fsp.readdir(directory,...args)).filter(name=>name<'0027_');},
  readFile:(...args)=>fsp.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}
test('prompt policy migration view preserves canonical prefix checksums without filesystem mutation',async()=>{
 const fsp=require('node:fs/promises'),original=fsp.readdir,loader=require('../../db/postgres/migrate');
 const full=await loader.readMigrations(agentsDirectory),prefix=await migrationView().readMigrations(agentsDirectory);
 assert.ok(prefix.length>0);assert.deepEqual(prefix,full.filter(row=>row.name<'0027_'));
 const policy=full.find(row=>row.name==='0027_bound_prompt_policies.sql');assert.ok(policy);
 assert.equal(policy.checksum,createHash('sha256').update(fs.readFileSync(path.join(agentsDirectory,policy.name))).digest('hex'));
 assert.deepEqual(fs.readFileSync(path.resolve(__dirname,'../../docs/modernization/drafts/secureshop-bound-prompt-policies/0027_bound_prompt_policies.candidate.sql')),Buffer.from(policy.sql));
 assert.equal(fsp.readdir,original);assert.equal(require('../../db/postgres/migrate'),loader);assert.deepEqual(await loader.readMigrations(agentsDirectory),full);
});
function admitOutputRoot(env=process.env){
 const root=env.PROMPT_POLICY_EVIDENCE_ROOT,source=fs.realpathSync(path.resolve(__dirname,'../..'));
 assert.ok(root&&path.isAbsolute(root),'PROMPT_POLICY_EVIDENCE_ROOT must be an explicit private directory');
 assert.equal(fs.realpathSync(root),root,'output root must be canonical');
 const stat=fs.lstatSync(root);assert.ok(stat.isDirectory()&&!stat.isSymbolicLink());
 assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o777,0o700);
 assert.ok(root!==source&&!root.startsWith(source+path.sep)&&!source.startsWith(root+path.sep),'output root must be disjoint from source');
 assert.deepEqual(fs.readdirSync(root),[],'output root must start empty');
 if(env.PROMPT_POLICY_STORAGE_ONLY==='1'){
  assert.notEqual(env.PROMPT_POLICY_COMPOSED_BROWSER,'1','storage-only selector rejects browser mode');
  assert.notEqual(env.PROMPT_POLICY_ACTUAL_CONTRAST,'1','storage-only selector rejects actual-model mode');
 }
 return root;
}
test('prompt policy output admission requires private canonical data outside source and fences storage-only optional modes',()=>{
 const os=require('node:os'),root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'prompt-policy-output-control-')));
 try{
  fs.chmodSync(root,0o700);assert.equal(admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:root}),root);
  assert.throws(()=>admitOutputRoot({}));assert.throws(()=>admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:'.'}));
  for(const mode of ['PROMPT_POLICY_COMPOSED_BROWSER','PROMPT_POLICY_ACTUAL_CONTRAST']){assert.equal(admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:root,[mode]:'1'}),root);assert.throws(()=>admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:root,PROMPT_POLICY_STORAGE_ONLY:'1',[mode]:'1'}));}
  fs.chmodSync(root,0o755);assert.throws(()=>admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:root}));fs.chmodSync(root,0o700);
  const alias=root+'-alias';fs.symlinkSync(root,alias);try{assert.throws(()=>admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:alias}));}finally{fs.unlinkSync(alias);}
  fs.writeFileSync(path.join(root,'occupied'),'synthetic');assert.throws(()=>admitOutputRoot({PROMPT_POLICY_EVIDENCE_ROOT:root}));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('owned prompt policy canonical migration and authority',{skip:process.env.PERSONA_PROMPT_POLICY_NATIVE!=='1',timeout:process.env.PROMPT_POLICY_COMPOSED_BROWSER==='1'?660000:process.env.PROMPT_POLICY_ACTUAL_CONTRAST==='1'?480000:180000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 const outputRoot=admitOutputRoot(),outputFile=name=>path.join(outputRoot,name);
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 const {migrate}=require('../../db/postgres/migrate');const base=agentsDirectory;
 const migrationName='0027_bound_prompt_policies.sql',canonical=path.join(base,migrationName),candidate='docs/modernization/drafts/secureshop-bound-prompt-policies/0027_bound_prompt_policies.candidate.sql';
 assert.ok(fs.existsSync(canonical));assert.deepEqual(fs.readFileSync(canonical),fs.readFileSync(candidate));
 const names=fs.readdirSync(base).filter(name=>name.endsWith('.sql')).sort();assert.ok(names.includes(migrationName));
 assert.equal(names.filter(name=>name.startsWith('0027_')).length,1);
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await migrationView().migrate(am,base);
 const freshApplied=await migrate(fm,base);assert.ok(freshApplied.includes('0023_secureshop_persona_authority_state.sql'));assert.deepEqual(freshApplied,names);assert.deepEqual(await migrate(fm,base),[]);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const owner=async()=>{const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),login=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});return{scope,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};};
 const a=await owner(),b=await owner(),old=await owner();const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(ledgerBefore.map(row=>row.name),names.filter(name=>name<migrationName));assert.deepEqual(await migrate(am,base),names.filter(name=>name>=migrationName));assert.deepEqual(await migrate(am,base),[]);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(after.slice(0,ledgerBefore.length),ledgerBefore);assert.equal(after.find(row=>row.name===migrationName).checksum,createHash('sha256').update(fs.readFileSync(canonical)).digest('hex'));const expectedLedger=(await require('../../db/postgres/migrate').readMigrations(base)).map(({name,checksum})=>({name,checksum}));assert.deepEqual(after.map(({name,checksum})=>({name,checksum})),expectedLedger);assert.deepEqual((await fm.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,expectedLedger);
 const {createBoundPromptPolicyRepository:createRepo}=require('../../server/database/postgres/secureshopBoundPromptPolicyRepository');
 const contract=require('../../server/services/secureshopPromptPolicyContract');
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const checkRunBinding=require('../../server/services/secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding({identityPool:identity});
 const repository=createRepo({pool:agents,personaAuthority:authority,audit,checkRunBinding});
 const freshRepo=createRepo({pool:fresh,personaAuthority:authority,audit,checkRunBinding});
 try{await repository.checkReadiness();await freshRepo.checkReadiness();}catch(error){if(error.schemaDiagnostic)fs.writeFileSync(outputFile('prompt-policy-schema-diagnostic.json'),JSON.stringify(error.schemaDiagnostic,null,2));throw error;}
 await assert.rejects(createRepo({pool:am,personaAuthority:authority,audit,checkRunBinding}).checkReadiness(),{code:'POLICY_NOT_READY'});
 let drifts=0;async function drift(change,restore){await fm.query(change);try{await assert.rejects(freshRepo.checkReadiness(),{code:'POLICY_NOT_READY'});drifts++;}finally{await fm.query(restore);}await freshRepo.checkReadiness();}
 const tables=['heads','current','revisions','operations','snapshots'];
 for(const table of tables){
  for(const privilege of ['SELECT','INSERT'])await drift(`REVOKE ${privilege} ON secureshop_agents.bound_prompt_policy_${table} FROM dvaia_secureshop_agents_runtime`,`GRANT ${privilege} ON secureshop_agents.bound_prompt_policy_${table} TO dvaia_secureshop_agents_runtime`);
  await drift(`GRANT TRUNCATE ON secureshop_agents.bound_prompt_policy_${table} TO dvaia_secureshop_agents_runtime`,`REVOKE TRUNCATE ON secureshop_agents.bound_prompt_policy_${table} FROM dvaia_secureshop_agents_runtime`);
 }
 const columns={heads:['policy_version'],current:['policy_version','payload_json','payload_sha256'],operations:['result_json','result_sha256']};
 for(const [table,names]of Object.entries(columns))for(const column of names)await drift(`REVOKE UPDATE(${column}) ON secureshop_agents.bound_prompt_policy_${table} FROM dvaia_secureshop_agents_runtime`,`GRANT UPDATE(${column}) ON secureshop_agents.bound_prompt_policy_${table} TO dvaia_secureshop_agents_runtime`);
 await drift('REVOKE DELETE ON secureshop_agents.bound_prompt_policy_current FROM dvaia_secureshop_agents_runtime','GRANT DELETE ON secureshop_agents.bound_prompt_policy_current TO dvaia_secureshop_agents_runtime');
 await drift('GRANT UPDATE(name) ON secureshop_agents.bound_prompt_policy_current TO dvaia_secureshop_agents_runtime','REVOKE UPDATE(name) ON secureshop_agents.bound_prompt_policy_current FROM dvaia_secureshop_agents_runtime');
 for(const fn of ['guard_prompt_policy_record','guard_prompt_policy_actor','cleanup_prompt_policy_records'])for(const role of ['PUBLIC','dvaia_secureshop_agents_runtime'])await drift(`GRANT EXECUTE ON FUNCTION secureshop_agents.${fn}() TO ${role}`,`REVOKE EXECUTE ON FUNCTION secureshop_agents.${fn}() FROM ${role}`);
 const triggerRows=(await fm.query("SELECT tgrelid::regclass::text AS rel,tgname FROM pg_trigger WHERE NOT tgisinternal AND (tgname LIKE 'prompt_policy_%' OR tgname LIKE 'z_prompt_policy_%')")).rows;
 assert.equal(triggerRows.length,15);
 for(const row of triggerRows)await drift(`ALTER TABLE ${row.rel} DISABLE TRIGGER ${row.tgname}`,`ALTER TABLE ${row.rel} ENABLE TRIGGER ${row.tgname}`);
 const checks=(await fm.query("SELECT conrelid::regclass::text AS rel,conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid::regclass::text LIKE 'secureshop_agents.bound_prompt_policy_%' AND contype='c'")).rows;
 for(const row of checks){const drop=`ALTER TABLE ${row.rel} DROP CONSTRAINT ${row.conname}`,restore=`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} ${row.def}`;await drift(drop,restore);await fm.query(drop);try{await fm.query(`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} CHECK(true)`);await assert.rejects(freshRepo.checkReadiness(),{code:'POLICY_NOT_READY'});drifts++;}finally{await fm.query(drop);await fm.query(restore);}await freshRepo.checkReadiness();}
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 const input=(o,extra={})=>({...context(o),action:'upsert',expectedVersion:'1',request:{operationId:randomUUID(),name:'owned-policy',markdown:'Controlled native policy text',targets:['admin']},...extra});
 // A completed renderer receipt is supplied by the fixture. No renderer/model claim.
 const render=request=>({version:1,operationId:request.operationId,requestSha256:contract.requestDigest(request),isolation:contract.ISOLATION,rendered:request.markdown,renderedSha256:createHash('sha256').update(request.markdown).digest('hex'),exitCode:0,timedOut:false,truncated:false,drained:true});
 const first=input(a);assert.equal((await repository.beginRender(first)).state,'admitted');assert.equal((await repository.beginRender(first)).state,'pending');
 await assert.rejects(repository.beginRender({...first,request:{...first.request,markdown:'changed'}}),{code:'OPERATION_CONFLICT'});
 const published=await repository.publish({...first,renderResult:render(first.request)});assert.equal(published.version,'2');assert.equal(published.renderResult.version,1);assert.equal((await repository.beginRender(first)).state,'completed');
 assert.equal((await repository.publish({...first,renderResult:render(first.request)})).replayed,true);
 const preview=input(a,{action:'preview',expectedVersion:'2'});await repository.beginRender(preview);assert.equal((await repository.publish({...preview,renderResult:render(preview.request)})).version,'2');assert.equal((await repository.list(context(a))).version,'2');
 const sibling=input(b);await repository.beginRender(sibling);await repository.publish({...sibling,renderResult:render(sibling.request)});
 assert.equal(await repository.operation({...context(b),operationId:first.request.operationId}),null);
 const otherLogin=await auth.login({scope:a.scope,username:'student_admin',password:'student123'}),otherSession=await auth.authenticateBoundToken({scope:a.scope,token:otherLogin.token});
 await assert.rejects(repository.operation({...context(a),personaSession:{sessionId:otherSession.sessionId,authorityVersion:otherSession.authorityVersion},operationId:first.request.operationId}),{code:'OPERATION_CONFLICT'});
 const conversations=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
 const conversation=async o=>{const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(o.scope,o.persona),id=randomUUID();await conversations.acquireBoundSession({id,binding});assert.equal(await conversations.activateBoundSession(id,binding),true);return id;};
 const aid=await conversation(a),bid=await conversation(b);
 const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:identity});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',ledger});
 let completedRun;
 await coordinator.run(aid,{},async execution=>{
  completedRun=execution.runId;await execution.check();
  const snap=await repository.admitRunSnapshot({...context(a),runId:execution.runId});assert.equal(snap.policyVersion,'2');assert.match(snap.text,/Controlled native policy text/);
  await assert.rejects(repository.admitRunSnapshot({...context(b),runId:execution.runId}),{code:'POLICY_RUN_AUTHORITY_UNAVAILABLE'});
  const edit=input(a,{expectedVersion:'2'});edit.request.markdown='Changed after snapshot';await repository.beginRender(edit);await repository.publish({...edit,renderResult:render(edit.request)});
  assert.deepEqual(await repository.admitRunSnapshot({...context(a),runId:execution.runId}),snap);await execution.check();return{};
 });
 await assert.rejects(repository.admitRunSnapshot({...context(a),runId:completedRun}),{code:'POLICY_RUN_AUTHORITY_UNAVAILABLE'});
 await assert.rejects(repository.admitRunSnapshot({...context(a),runId:randomUUID()}),{code:'POLICY_RUN_AUTHORITY_UNAVAILABLE'});
 // A persisted stale-generation row is a negative fixture, never model evidence.
 const staleRun=randomUUID(),ownerKey=JSON.stringify(['SecureShopBoundConversation',aid]);
 await im.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) SELECT $1,owner_key,generation+1,'running' FROM graph_runtime.owners WHERE owner_key=$2",[staleRun,ownerKey]);
 await assert.rejects(repository.admitRunSnapshot({...context(a),runId:staleRun}),{code:'POLICY_RUN_AUTHORITY_UNAVAILABLE'});
 await coordinator.run(bid,{},async execution=>{assert.equal((await repository.admitRunSnapshot({...context(b),runId:execution.runId})).policyVersion,'2');return{};});
 const race1=input(a,{expectedVersion:'3'}),race2=input(a,{expectedVersion:'3'});await repository.beginRender(race1);await repository.beginRender(race2);
 const results=await Promise.allSettled([repository.publish({...race1,renderResult:render(race1.request)}),repository.publish({...race2,renderResult:render(race2.request)})]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.find(r=>r.status==='rejected').reason.code,'REVISION_CONFLICT');
 const deletion={...context(a),operationId:randomUUID(),name:'owned-policy',expectedVersion:'4'};assert.equal((await repository.remove(deletion)).version,'5');assert.equal((await repository.remove(deletion)).replayed,true);assert.equal((await repository.list(context(a))).policies.length,0);
 const lostOwner=await owner(),lost=input(lostOwner);let dropped=false;
 const droppedAuthority={capture:async request=>{const fence=await authority.capture(request);return{...fence,withPersonaEffect:async callback=>{const result=await fence.withPersonaEffect(callback);if(!dropped){dropped=true;throw Error('Controlled post-commit response loss');}return result;}};}};
 const uncertain=createRepo({pool:agents,personaAuthority:droppedAuthority,audit,checkRunBinding});await assert.rejects(uncertain.beginRender(lost),{code:'POLICY_OUTCOME_UNCERTAIN'});assert.equal(dropped,true);
 assert.equal((await repository.beginRender(lost)).state,'pending');assert.equal((await repository.operation({...context(lostOwner),operationId:lost.request.operationId})).state,'pending');
 const revokedOwner=await owner(),revoked=input(revokedOwner);await repository.beginRender(revoked);await personas.revokeOwnedSession({scope:revokedOwner.scope,shopUserId:revokedOwner.persona.id,sessionId:revokedOwner.sessionId});await assert.rejects(repository.publish({...revoked,renderResult:render(revoked.request)}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(agents.query("UPDATE secureshop_agents.bound_prompt_policy_operations SET result_json='{}',result_sha256=decode(repeat('00',32),'hex') WHERE operation_id=$1",[revoked.request.operationId]),{code:'55000'});
 await assert.rejects(agents.query('UPDATE secureshop_agents.bound_prompt_policy_operations SET mutation_sha256=mutation_sha256'),{code:'42501'});
 await assert.rejects(agents.query('DELETE FROM secureshop_agents.bound_prompt_policy_snapshots'),{code:'42501'});
 const rows=async(table,o)=>(await agents.query(`SELECT * FROM secureshop_agents.bound_prompt_policy_${table} WHERE platform_launch_id=$1 ORDER BY 1`,[o.scope.launchId])).rows;
 const siblingRows={};for(const table of tables)siblingRows[table]=await rows(table,b);
 const retained=(await rows('operations',a)).map(r=>[r.operation_id,r.mutation_sha256.toString('hex'),r.result_sha256?.toString('hex')]).sort();
 await retire(a);for(const table of ['heads','current'])assert.equal((await rows(table,a)).length,0);
 for(const table of ['revisions','operations','snapshots'])for(const row of await rows(table,a)){assert.equal(row.payload_json,null);if(table==='operations')assert.equal(row.result_json,null);}
 assert.deepEqual((await rows('operations',a)).map(r=>[r.operation_id,r.mutation_sha256.toString('hex'),r.result_sha256?.toString('hex')]).sort(),retained);
 await assert.rejects(repository.beginRender(input(a,{expectedVersion:'1'})));
 await assert.rejects(agents.query('INSERT INTO secureshop_agents.bound_prompt_policy_heads(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5)',coords(a)),{code:'55000'});
 await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[lostOwner.scope.platformOwnerId,randomUUID()]);for(const table of tables)assert.equal((await rows(table,lostOwner)).length,0);
 for(const table of tables)assert.deepEqual(await rows(table,b),siblingRows[table]);
 const audits=JSON.stringify((await agents.query("SELECT params_json FROM secureshop_agents.bound_audit_events WHERE action LIKE 'prompt_policy_%'")).rows);assert.ok(!audits.includes(first.request.markdown));
 // Actual compositions consume policy snapshots under the existing native
 // coordinator and original persona sessions. Provider decisions are controlled
 // and explicitly mock; this gate cannot establish actual-model completion.
 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
 await im.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'");
 await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id=ANY($1::text[])",[['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block','ss_controlled_ssrf']]);
 const conversationService=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations,launches});
 const turns=require('../../server/services/secureshopBoundTurns').createBoundTurns({conversations:conversationService,coordinator});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const inboxRepository=require('../../server/database/postgres/secureshopPersonaInboxRepository').createSecureShopPersonaInboxRepository(agents,{
  checkCurrent:scope=>launches.assertCurrent(scope),checkAclTransition:async()=>{throw Error('ACL mutation outside policy gate');},checkCleanup:async()=>{throw Error('Inbox cleanup outside gate');},auditStore:audit});
 const targetRoot=fs.mkdtempSync(path.join(outputRoot,'policy-ssrf-targets-'));
 const targetPool=require('../../server/services/secureshopSsrfTargetPool').createSecureShopSsrfTargetPool({root:targetRoot});
 t.after(async()=>{await targetPool.close();fs.rmSync(targetRoot,{recursive:true,force:true});});
 process.env.SECURESHOP_DATABASE_URL=process.env.PERSONA_COMMERCE_RUNTIME_URL;
 process.env.PG_POOL_MAX_WORKSHOP='2';
 const secureShopPools=require('../../server/database/postgres/secureshopPools');t.after(()=>secureShopPools.closeSecureShopPools());
 const [{Client},{InMemoryTransport}]=await Promise.all([import('@modelcontextprotocol/sdk/client/index.js'),import('@modelcontextprotocol/sdk/inMemory.js')]);
 const sdkServer=require('../../agent-host/agents/summarizer/server').createServer();
 const sdkClient=new Client({name:'prompt-policy-native-controlled',version:'1'}),[clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
 t.after(async()=>{await sdkClient.close();await clientTransport.close();await serverTransport.close();await sdkServer.close();});
 await sdkServer.connect(serverTransport);await sdkClient.connect(clientTransport);
 let sdkCalls=0,controlledJudgeCalls=0;
 const upstreamPool={async callTool(agent,tool,args,options){assert.equal(agent,'summarizer');sdkCalls++;return sdkClient.callTool({name:tool,arguments:args},undefined,{signal:options?.signal});}};
 const controlledJudge=async packet=>{controlledJudgeCalls++;return{family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,runId:packet.execution.runId,mode:packet.rubric.mode,evidenceDigest:require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet).evidenceDigest,verdict:'fail',criteria:packet.rubric.criteria.map(row=>({id:row.id,satisfied:false,evidenceRefs:[]})),explanation:'Controlled mock provider gate; no genuine model credit.',provider:'controlled-native',model:'controlled-native',usage:null};};
 const graphProof=[];
 for(const workflow of ['inbox','ssrf']){
  let messageId,chatCalls=0,finalCalls=0;const seenPrompts=[];
  const provider={name:'mock',model:'controlled-policy-fixture',async chat(modelInput){
   const {messages}=modelInput;chatCalls++;seenPrompts.push(JSON.stringify(modelInput));
   let tool;
   if(workflow==='inbox')tool={id:'controlled-owned-read',name:'persona-inbox.read_message',args:{message_id:messageId}};
   else{const task=[...messages].reverse().find(row=>row.role==='user')?.content;const url=String(task).match(/http:\/\/127\.0\.0\.1:\d+\/[^\s]+/)?.[0];assert.ok(url,'Owned target URL must come from actual application task');tool={id:'controlled-owned-fetch',name:'summarizer.explain_return_policy',args:{policy_url:url}};}
   return{stop_reason:'tool_use',tool_uses:[tool],provider:'mock',model:'controlled-policy-fixture',mocked:true,fallback:false};
  },async finalResponse(){finalCalls++;return{stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled owned read finished; no model credit.',provider:'mock',model:'controlled-policy-fixture',mocked:true,fallback:false};}};
  const resetComposition={launches,conversationService,turns,journal,conversations,cleanupAuthority:{checkTarget:async()=>{throw Error('Target cleanup outside gate');}},personaInbox:{repository:inboxRepository,authorizeAclTransition:async()=>{throw Error('ACL change outside gate');}}};
  const feature=workflow==='inbox'
   ?require('../../server/services/secureshopPersonaInboxComposition').createSecureShopPersonaInboxComposition({enabled:true,identityPool:identity,provider,judge:controlledJudge,authenticatePersona:auth.authenticatePersona,personaRepository:personas,resetComposition,personaAuthority:authority,promptPolicyRepository:repository})
   :require('../../server/services/secureshopSsrfComposition').createSecureShopSsrfComposition({enabled:true,identityPool:identity,agentsPool:agents,provider,judge:controlledJudge,resetComposition,targetPool,upstreamPool,personaAuthority:authority,promptPolicyRepository:repository});
  const owned=await owner(),siblingOwner=await owner();
  for(const [index,adminOwner]of [owned,siblingOwner].entries()){
   const policyText=`OWNED_${workflow.toUpperCase()}_${index}_PROMPT_POLICY`,policyInput=input(adminOwner);
   policyInput.request.markdown=policyText;policyInput.request.targets=['customer'];await repository.beginRender(policyInput);await repository.publish({...policyInput,renderResult:render(policyInput.request)});
   const login=await auth.login({scope:adminOwner.scope,username:'student_customer',password:'student123'}),verified=await auth.authenticateBoundToken({scope:adminOwner.scope,token:login.token});
   const actor={scope:adminOwner.scope,persona:{id:login.user.id,role:login.user.role},personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};
   if(workflow==='inbox'){const status=await feature.application.status(actor);assert.equal(status.ready,true);messageId=status.messages.find(row=>row.ownerShopRole==='merchant').messageId;}
   const requestId=randomUUID(),callsBefore=chatCalls;
   const args={...actor,requestId,...(workflow==='inbox'?{messageId}:{resourceKind:'private-policy'}),promptPolicySnapshot:{text:'FORGED_CALLER_POLICY'}};
   const result=await feature.application.run(args);fs.writeFileSync(outputFile(`prompt-policy-${workflow}-${index}-result.json`),JSON.stringify(result,null,2));assert.equal(result.stopReason,'end_turn',`${workflow} graph must finish; retained owned result includes diagnostics`);assert.equal(chatCalls,callsBefore+1);assert.ok(seenPrompts.at(-1).includes(policyText));assert.ok(!seenPrompts.at(-1).includes('FORGED_CALLER_POLICY'));
   if(workflow==='inbox'){assert.equal(result.accesses.length,1);assert.equal(result.accesses[0].acl.disclosed,true);}else assert.equal(result.resourceKind,'private-policy');
   const snapshots=(await agents.query('SELECT * FROM secureshop_agents.bound_prompt_policy_snapshots WHERE platform_launch_id=$1',[adminOwner.scope.launchId])).rows;
   assert.equal(snapshots.length,1);const persisted=snapshots[0];assert.equal(persisted.persona_session_id,actor.personaSession.sessionId);assert.equal(String(persisted.authority_version),actor.personaSession.authorityVersion);assert.equal(persisted.persona_id,actor.persona.id);assert.equal(persisted.persona_role,'customer');assert.equal(persisted.payload_json.policyVersion,'2');assert.equal(persisted.payload_json.policies[0].rendered,policyText);assert.ok(seenPrompts.at(-1).includes(JSON.stringify(persisted.payload_json.text).slice(1,-1)));
   const traces=(await agents.query("SELECT tr.* FROM secureshop_agents.agent_trace tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id WHERE s.platform_launch_id=$1 AND tr.kind='prompt_policy_snapshot'",[adminOwner.scope.launchId])).rows;
   assert.equal(traces.length,1);assert.deepEqual(JSON.parse(traces[0].result_json),{runId:persisted.run_id,policyVersion:'2',sha256:persisted.payload_json.sha256,role:'customer',policyCount:1});
   const run=(await identity.query('SELECT owner_key,status FROM graph_runtime.runs WHERE run_id=$1',[persisted.run_id])).rows[0];assert.equal(run.status,'completed');assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',traces[0].session_id]));
   const priorCalls=chatCalls;await assert.rejects(feature.application.run({...args,requestId:randomUUID(),personaSession:{sessionId:randomUUID(),authorityVersion:'1'}}));assert.equal(chatCalls,priorCalls);
   await personas.revokeOwnedSession({scope:actor.scope,shopUserId:actor.persona.id,sessionId:actor.personaSession.sessionId});await assert.rejects(feature.application.run({...args,requestId:randomUUID()}));assert.equal(chatCalls,priorCalls);
   const judgments=(await identity.query('SELECT verdict,disposition,result_json FROM workshop_platform.objective_judgments WHERE user_id=$1',[adminOwner.scope.platformOwnerId])).rows;assert.ok(judgments.every(row=>row.verdict!=='pass'&&!['awarded','already_complete'].includes(row.disposition)));
   graphProof.push({workflow,sibling:index===1,runId:persisted.run_id,originalSessionBound:true,policySha256:persisted.payload_json.sha256,policyTextReachedProvider:true,actualOwnedEffect:true,foreignAndRevokedSessionDeniedBeforeProvider:true,judgmentCount:judgments.length,awarded:0,provider:'mock',model:'controlled-policy-fixture'});
  }
  assert.equal(chatCalls,2);assert.equal(finalCalls,2);
 }
 assert.equal(sdkCalls,2);
 let composed;
 if(process.env.PROMPT_POLICY_COMPOSED_BROWSER==='1')composed=await require('../fixtures/secureshopPromptPoliciesComposed').qualifyComposedPolicies({identity,users,launches,auth,repository,personas,authority,root:outputRoot});
 if(process.env.PROMPT_POLICY_ACTUAL_CONTRAST==='1')await require('./secureshopPromptPolicyActualContrast')({outputRoot,t,owner,auth,repository,input,render,identity,agents,personas,authority,renderer:composed?.renderer,resetComposition:{launches,conversationService,turns,journal,conversations,personaInbox:{repository:inboxRepository,authorizeAclTransition:async()=>{throw Error('ACL changes outside contrast');}}}});
 fs.writeFileSync(outputFile('prompt-policy-graphs-result.json'),JSON.stringify({status:'passed',actualModelCalls:0,controlledActorCalls:8,controlledJudgeCalls,actualSsrfSdkCalls:sdkCalls,graphs:graphProof,scope:'Actual inbox/SSRF compositions and tools, native authority/conversation/run/policy stores; controlled mock provider decisions and fail-only Judge. No genuine model/Judge qualification, mounted HTTP/UI or installed activation.'},null,2));
 fs.writeFileSync(outputFile('prompt-policy-result.json'),JSON.stringify({status:'passed',actualModelCalls:0,actualRendererCalls:0,fresh:true,populated:true,noop:true,readinessDrifts:drifts,realPersonaAuthority:true,originalSessionReplay:true,cas:true,pendingLostAck:true,previewNoVersionAdvance:true,immutableSnapshot:true,realCoordinatorRunBinding:true,terminalForeignMissingGenerationDenied:true,revokedFinalizeDenied:true,lifecycleRedactionDigestRetention:true,ownerStoreCleanup:true,siblingPreserved:true,scope:'Canonical registered storage migration in owned disposable stores; controlled completed renderer receipts. Actual agents and identity repositories/coordinator; cross-store reads require retained coordinator boundary and are not a distributed transaction. No installed activation, HTTP/UI, renderer or model proof.'},null,2));
});
