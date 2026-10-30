'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
test('owned synthetic user lookup candidate migration and authority',{skip:process.env.PERSONA_OWNED_USER_LOOKUP_NATIVE!=='1',timeout:120000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(path.resolve(__dirname,'../..')));
 const databases=new Set();let ownedPort;
 for(const store of ['IDENTITY','FRESH','COMMERCE','ACLFRESH']){
  const runtime=new URL(process.env[`PERSONA_${store}_RUNTIME_URL`]),migration=new URL(process.env[`PERSONA_${store}_MIGRATION_URL`]);
  assert.equal(runtime.pathname,migration.pathname);assert.equal(runtime.port,migration.port);assert.equal(runtime.hostname,migration.hostname);
  assert.ok(runtime.pathname.endsWith('_'+store.toLowerCase()));assert.ok(!databases.has(runtime.pathname));databases.add(runtime.pathname);
  if(ownedPort===undefined)ownedPort=runtime.port;else assert.equal(runtime.port,ownedPort);
 }
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);assert.equal(u.protocol,'postgresql:');assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');assert.ok(Number(u.port)>0&&Number(u.port)<=65535);const family=store==='IDENTITY'?'identity':store==='COMMERCE'?'secureshop':'secureshop_agents';assert.equal(decodeURIComponent(u.username),'dvaia_'+family+'_'+role.toLowerCase());const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 const {migrate}=require('../../db/postgres/migrate');const {createAgentsMigrationView}=require('../helpers/secureshopAgentsMigrationView');const baseline=createAgentsMigrationView(24),candidateView=createAgentsMigrationView(25);const base=candidateView.directory;
 const candidateName='0025_owned_user_lookup.sql',candidate=path.join(base,candidateName),dir=base;
 assert.equal(createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'),createHash('sha256').update(fs.readFileSync('docs/modernization/drafts/secureshop-owned-user-lookup/0025_owned_user_lookup.candidate.sql')).digest('hex'));
 await migrate(im,'db/postgres/identity-migrations');await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await baseline.migrate(am,base);assert.deepEqual(await baseline.migrate(am,base),[]);
 const freshApplied=await candidateView.migrate(fm,dir);assert.ok(freshApplied.includes('0023_secureshop_persona_authority_state.sql'));assert.equal(freshApplied.at(-1),candidateName);assert.deepEqual(await candidateView.migrate(fm,dir),[]);
 const assessmentSeed=require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults;
 await assessmentSeed(im);
 const objective='ss_user_lookup_sensitive_disclosure';
 const objectiveRow=async()=>(await identity.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',[objective])).rows;
 const platformRow=async()=>(await identity.query("SELECT * FROM workshop_platform.objectives WHERE workshop_key='secureshop_agent_security' AND objective_id=$1",[objective])).rows;
 const freshObjective=await objectiveRow(),freshPlatform=await platformRow();
 assert.equal(freshObjective.length,1);assert.equal(freshPlatform.length,1);
 assert.equal(freshObjective[0].qualification,'pending');assert.equal(freshObjective[0].is_enabled,false);assert.equal(freshPlatform[0].is_enabled,false);
 assert.equal(freshPlatform[0].catalog_active,true);assert.equal(freshObjective[0].configuration_source,'checked_in_default');
 const expectedSource=JSON.stringify({version:1,id:objective,label:freshObjective[0].label,defaultEnabled:false,qualification:'pending'});
 assert.deepEqual(freshObjective[0].source_document,JSON.parse(expectedSource));
 assert.equal(freshObjective[0].source_sha256,createHash('sha256').update(expectedSource).digest('hex'));
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const ownerScope=async()=>{const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt});return{scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding)};};
 const owner=async()=>{const {scope}=await ownerScope(),login=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});return{scope,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};};
 const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 // Historical 0024 session rows are migration data, not current authentication
 // authority. Their real platform scopes and canonical teaching template satisfy
 // the exact old guarded schema; no current auth method runs before 0045.
 const historicalOwners=[];
 for(let index=0;index<3;index++){
  const historical=await ownerScope();historicalOwners.push(historical);
  await agents.query(`INSERT INTO secureshop_agents.bound_persona_sessions
   (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
    original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,full_name,phone,expires_at)
   SELECT $1,$2,$3,$4,$5,$6,$7,shop_user_id,username,role,email,full_name,phone,clock_timestamp()+interval '10 minutes'
    FROM secureshop_agents.bound_persona_templates WHERE username='student_admin'`,
   [randomUUID(),createHash('sha256').update(randomUUID()).digest(),...coords(historical)]);
 }
 const old=historicalOwners[2];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;assert.equal(before.length,3);const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await candidateView.migrate(am,dir),[candidateName]);assert.deepEqual(await candidateView.migrate(am,dir),[]);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(after.slice(0,-1),ledgerBefore);assert.equal(after.at(-1).checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
 const priorCurrent=createAgentsMigrationView(110);await priorCurrent.migrate(am,base);
 const a=await owner(),b=await owner();
 const {createSyntheticUserDirectoryRepository:createRepo}=require('../../server/database/postgres/secureshopSyntheticUserDirectoryRepository');
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const repository=createRepo({pool:agents,audit}),freshRepo=createRepo({pool:fresh,audit});
 await repository.checkReadiness();await freshRepo.checkReadiness();
 // Only lookup is exercised; directory and role mutation dependencies never execute.
 const modeRepository=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
 const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:modeRepository,launches});
 const service=require('../../server/services/secureshopBoundUserAdministration').createSecureShopBoundUserAdministration({
  repository:{mutate(){throw Error('unused');},readEffectivePersona(){throw Error('unused');}},directory:{users(){throw Error('unused');}},personaAuthority:authority,lookupRepository:repository,modeAuthority});
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version},username:'student_customer'});
 const first=await service.lookup(context(a)),sibling=await service.lookup(context(b));
 assert.equal(first.synthetic,true);assert.equal(first.user.username,'student_customer');assert.match(first.user.password,/^\$2[ab]\$10\$/);assert.match(first.user.api_key,/^TRAINING_API_/);
 assert.notEqual(first.user.api_key,sibling.user.api_key);assert.deepEqual(await service.lookup(context(a)),first);
 const real=(await agents.query('SELECT password_hash FROM secureshop_agents.bound_persona_templates WHERE username=$1',['student_customer'])).rows[0];assert.notEqual(first.user.password,real.password_hash);
 await assert.rejects(service.lookup({...context(a),personaSession:{...context(a).personaSession,sessionId:randomUUID()}}),{code:'SHOP_AUTH_INVALID'});
 let drifts=0;async function drift(change,restore){try{await fm.query(change);await assert.rejects(freshRepo.checkReadiness(),/unavailable/);drifts++;}finally{await fm.query(restore);}await freshRepo.checkReadiness();}
 await drift('GRANT EXECUTE ON FUNCTION secureshop_agents.cleanup_synthetic_user_directory() TO PUBLIC','REVOKE EXECUTE ON FUNCTION secureshop_agents.cleanup_synthetic_user_directory() FROM PUBLIC');
 await drift('GRANT EXECUTE ON FUNCTION secureshop_agents.cleanup_synthetic_user_directory() TO dvaia_secureshop_agents_runtime','REVOKE EXECUTE ON FUNCTION secureshop_agents.cleanup_synthetic_user_directory() FROM dvaia_secureshop_agents_runtime');
 await drift('ALTER TABLE secureshop_agents.bound_synthetic_user_directories DROP CONSTRAINT synthetic_directory_rows_count','ALTER TABLE secureshop_agents.bound_synthetic_user_directories ADD CONSTRAINT synthetic_directory_rows_count CHECK(jsonb_array_length(rows_json)=3)');
 await drift('ALTER TABLE secureshop_agents.bound_synthetic_user_directories DISABLE TRIGGER synthetic_user_directory_admission','ALTER TABLE secureshop_agents.bound_synthetic_user_directories ENABLE TRIGGER synthetic_user_directory_admission');
 // Preserve the historical 0025 migration proof above, then qualify the same
 // stores at the complete current migration head before testing agent receipts.
 const registry=require('../../server/services/secureshopBoundAclRegistry');
 const historicalRows=registry.REGISTRY.filter(row=>row.toolKey!=='admin.user_lookup');
 const priorHash='435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc';
 assert.equal(createHash('sha256').update(JSON.stringify({version:33,rows:historicalRows})).digest('hex'),priorHash);
 // Execute the checked-in repository with its exact historical published
 // registry dependency. This creates real guarded policy/override rows, not a
 // hand-shaped SQL substitute, before applying the forward guard migration.
 const {Module,createRequire}=require('node:module'),aclFile=require.resolve('../../server/database/postgres/secureshopBoundAclRepository');
 const historicalModule=new Module(aclFile,module),localRequire=createRequire(aclFile);
 historicalModule.filename=aclFile;historicalModule.require=name=>name==='../../services/secureshopBoundAclRegistry'
  ?{...registry,REGISTRY:historicalRows,REGISTRY_SHA256:priorHash,REGISTRY_UPGRADES:{}}:localRequire(name);
 historicalModule._compile(fs.readFileSync(aclFile,'utf8'),aclFile);
 const historicalAcl=historicalModule.exports.createSecureShopBoundAclRepository({personaAuthority:authority,audit});
 for(const subject of [a,b]){
  const input={scope:subject.scope,persona:subject.persona,personaSession:context(subject).personaSession};
  const policy=await historicalAcl.readPolicy(input);assert.equal(policy.registrySha256,priorHash);
  await historicalAcl.mutate({...input,operationId:randomUUID(),expectedVersion:policy.version,
   change:{kind:'permission',toolKey:'admin.users_search',role:'admin',allowed:false}});
 }
 const policySnapshot=async subject=>{
  const result={};for(const table of ['bound_tool_policy_heads','bound_tool_policy_overrides','bound_tool_policy_operations','bound_tool_registry_upgrades'])
   result[table]=(await agents.query(`SELECT to_jsonb(t) AS row FROM secureshop_agents.${table} t WHERE platform_launch_id=$1 ORDER BY to_jsonb(t)::text`,[subject.scope.launchId])).rows;
  return result;
 };
 const priorPolicies=await policySnapshot(a),priorPeerPolicies=await policySnapshot(b);
 const directoriesBefore=(await agents.query('SELECT * FROM secureshop_agents.bound_synthetic_user_directories ORDER BY platform_launch_id')).rows;
 const successor='0111_admin_user_lookup_registry_successor.sql';
 assert.deepEqual(await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),[successor]);
 assert.deepEqual(await policySnapshot(a),priorPolicies);assert.deepEqual(await policySnapshot(b),priorPeerPolicies);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_synthetic_user_directories ORDER BY platform_launch_id')).rows,directoriesBefore);
 assert.deepEqual(await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),[]);
 const freshTail=await migrate(fm,'db/postgres/workshop-migrations/secureshop_agents');assert.equal(freshTail.at(-1),successor);
 assert.deepEqual(await migrate(fm,'db/postgres/workshop-migrations/secureshop_agents'),[]);
 for(const migrationPool of [am,fm])assert.equal((await migrationPool.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[successor])).rows[0].checksum,
  createHash('sha256').update(fs.readFileSync(path.join(base,successor))).digest('hex'));
 const currentAcl=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({personaAuthority:authority,audit});
 const currentInput={scope:a.scope,persona:a.persona,personaSession:context(a).personaSession};
 const upgraded=await currentAcl.readPolicy(currentInput);assert.equal(upgraded.registrySha256,registry.REGISTRY_SHA256);
 assert.equal(upgraded.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,false);
 const lookupPermission=upgraded.rows.find(row=>row.toolKey==='admin.user_lookup');
 assert.deepEqual(lookupPermission.roleApplicability,{customer:false,merchant:false,admin:true});assert.equal(lookupPermission.allowed.admin,false);
 assert.deepEqual(await policySnapshot(b),priorPeerPolicies,'owner upgrade cannot rewrite sibling policy');
 const upgradeRows=(await agents.query("SELECT encode(predecessor_sha256,'hex') AS predecessor,encode(successor_sha256,'hex') AS successor,overrides_before,added_denials FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1",[a.scope.launchId])).rows;
 assert.deepEqual(upgradeRows,[{predecessor:priorHash,successor:registry.REGISTRY_SHA256,
  overrides_before:[{toolKey:'admin.users_search',role:'admin',allowed:false}],added_denials:[{toolKey:'admin.user_lookup',role:'admin'}]}]);
 await currentAcl.mutate({...currentInput,operationId:randomUUID(),expectedVersion:upgraded.version,
  change:{kind:'permission',toolKey:'admin.user_lookup',role:'admin',allowed:true}});

 await repository.checkReadiness();await freshRepo.checkReadiness();
 const sceneRepository=require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches});
 const sceneFor=async o=>{
  const reserved=await launches.reserveProductsTarget({...o.scope,expectedGeneration:o.scope.generation});
  const scenes=await sceneRepository.adopt(o.scope,[{...o.scope,targetId:reserved.targetId}]);
  const grant=await sceneRepository.grant(o.scope,scenes.find(row=>row.storage.targetId===reserved.targetId).sceneId);
  return require('../../server/services/secureshopSceneBinding').createSceneBinding(grant.storage,{...grant,
   withLease:work=>sceneRepository.withLease(grant,work)});
 };
 const aScene=await sceneFor(a),bScene=await sceneFor(b);
 const agentContext=(o,target)=>({...context(o),target,check:()=>launches.assertCurrent(o.scope)});
 const auditRows=async o=>(await agents.query(`SELECT event_id,params_json,source_kind,source_id
  FROM secureshop_agents.bound_audit_events WHERE launch_id=$1 AND source_kind='synthetic_user_agent_lookup' ORDER BY event_id`,[o.scope.launchId])).rows;
 const agentOriginal=await service.lookupForAgent(agentContext(a,aScene));
 assert.equal(agentOriginal.status,'complete');assert.deepEqual(agentOriginal.user,first.user);
 assert.deepEqual(Object.keys(agentOriginal.receipt).sort(),['version','eventId','scope','persona','personaSession','username','modeExecution','sceneExecution','directorySha256','rowSha256'].sort());
 assert.equal(agentOriginal.receipt.rowSha256,require('../../server/services/secureshopUserLookupEvidence').rowDigest(agentOriginal.user));
 const aSourceRows=await auditRows(a);assert.equal(aSourceRows.length,1);
 assert.deepEqual(JSON.parse(aSourceRows[0].params_json),{version:1,status:'complete',receipt:agentOriginal.receipt});
 assert.deepEqual(await service.readAgentLookup({...agentContext(a,aScene),reference:agentOriginal.receipt}),agentOriginal);
 assert.deepEqual(await auditRows(a),aSourceRows,'protected source read must not append another event');
 const siblingAgent=await service.lookupForAgent(agentContext(b,bScene));
 const siblingSourceRows=await auditRows(b);assert.equal(siblingSourceRows.length,1);
 assert.notEqual(siblingAgent.user.api_key,agentOriginal.user.api_key);
 for(const patch of [{rowSha256:'0'.repeat(64)},{eventId:randomUUID()},{username:'student_admin'}])
  await assert.rejects(service.readAgentLookup({...agentContext(a,aScene),reference:{...agentOriginal.receipt,...patch}}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 await assert.rejects(service.readAgentLookup({...agentContext(b,bScene),reference:agentOriginal.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 await assert.rejects(service.lookupForAgent({...agentContext(a,aScene),target:{...aScene}}),{code:'SHOP_SCENE_STALE'});
 await assert.rejects(service.readAgentLookup({...agentContext(a,aScene),personaSession:{...context(a).personaSession,sessionId:randomUUID()},reference:agentOriginal.receipt}),{code:'SHOP_AUTH_INVALID'});
 // Actual PostgreSQL producer -> production RoleChat -> production evidence.
 // Only the provider is controlled; these traces never claim a real model run.
 const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository')
  .createBoundConversationsRepository({pool:agents,queue:(_key,work)=>work()});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const bindings=require('../../server/database/postgres/secureshopRoleChatBindingRepository').createRoleChatBindingRepository({pool:agents});
 const leasePool=pool('IDENTITY','RUNTIME');
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',
  ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool})});
 const acl=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({personaAuthority:authority,audit});
 const RoleChat=require('../../server/services/secureshopBoundRoleChat');
 const admission=require('../../server/services/secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({repository:acl,
  workflow:'admin-assistant',declaredTools:RoleChat.TOOLS.admin});
 let providerCalls=0,lastLookup;
 const administration={...service,async lookupForAgent(input){lastLookup=await service.lookupForAgent(input);return lastLookup;}};
 const unexpected=async()=>{throw Error('Unexpected native lookup dependency');};
 const graph=RoleChat.createSecureShopBoundRoleChat({role:'admin',launches,personaAuthority:authority,modeAuthority,
  conversations:conversationRepository,journal,coordinator,bindingRepository:bindings,toolPolicyAdmission:admission,
  userAdministration:administration,userLookupAssessmentReady:async()=>false,
  catalog:{async prepareTarget(){return aScene;}},
  scenes:{withProvisionLease:(scope,work)=>sceneRepository.withProvisionLease(scope,work),
   async readExisting(scope){assert.deepEqual(require('../../server/services/secureshopConversationBinding').createLaunchScope(scope),a.scope);
    await sceneRepository.readRetainedGrant(a.scope,aScene.scene.sceneId);return aScene;},
   async readRetained(scope){return this.readExisting(scope);}},
  admin:{users:unexpected,audit:unexpected},auditChat:{search:unexpected,read:unexpected},
  systemReads:{health:unexpected,configRead:unexpected,operation:unexpected},
  provider:{async chat(input){providerCalls++;assert.ok(input.tools.some(tool=>tool.agent==='admin'&&tool.tool==='user_lookup'));
    return{provider:'native-controlled',model:'native-controlled-lookup',mocked:false,fallback:false,stop_reason:'tool_use',
     tool_uses:[{id:'native-lookup',name:'admin.user_lookup',args:{username:'student_customer'}}]};},
   async finalResponse(input){providerCalls++;assert.equal(Object.hasOwn(input,'tools'),false);
    assert.ok(lastLookup);return{provider:'native-controlled',model:'native-controlled-lookup',mocked:false,fallback:false,
     responseMode:'structured_final',stop_reason:'end_turn',text:lastLookup.status==='complete'
      ?require('../../server/services/secureshopUserLookupEvidence').FIELDS.map(key=>`${key}: ${lastLookup.user[key]}`).join('\n')
      :'Only the safe teaching identity is available.'};}}});
 const graphSession=await graph.createSession(a.scope,a.persona,context(a).personaSession);
 const graphInput={scope:a.scope,persona:a.persona,personaSession:context(a).personaSession,
  sessionId:graphSession.id,requestId:randomUUID(),message:'Look up the student_customer synthetic teaching record.',signal:AbortSignal.timeout(20000)};
 const graphOriginal=await graph.run(graphInput);
 assert.equal(graphOriginal.stopReason,'end_turn');assert.equal(providerCalls,2);assert.equal(lastLookup.status,'complete');
 const graphSaved=await graph.readRequest(a.scope,a.persona,context(a).personaSession,graphInput.sessionId,graphInput.requestId);
 assert.deepEqual(graphSaved.userLookup,{version:1,username:'student_customer',status:'complete',assessmentReady:false});
 const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(a.scope,a.persona);
 const boundTurn=await bindings.read({...graphInput});
 const turn=await journal.readBoundRequest({sessionId:graphInput.sessionId,requestId:graphInput.requestId,binding,
  purpose:require('../../server/database/postgres/secureshopRoleChatBindingRepository').PURPOSES.admin});
 const origin=turn.result_json.taskMetadata.roleChat.userLookupOrigin;
 const traces=await conversationRepository.getTraceEvents(graphInput.sessionId,binding,origin.traceEventIds,
  require('../../server/database/postgres/secureshopRoleChatBindingRepository').PURPOSES.admin);
 const run=(await identity.query('SELECT run_id,owner_key,generation::text AS generation,status FROM graph_runtime.runs WHERE run_id=$1',[origin.runId])).rows[0];
 const effects=(await identity.query('SELECT run_id,owner_key,generation::text AS generation,effect_key,status FROM graph_runtime.effects WHERE run_id=$1',[origin.runId])).rows;
 const E=require('../../server/services/secureshopUserLookupEvidence');
 const value=E.validateUserLookupEvidence({binding,personaSession:context(a).personaSession,target:aScene,boundTurn,
  turn:{...turn,request_id:graphInput.requestId},traces,run,effects,lookup:lastLookup,modeExecution:origin.execution,
  qualifyModel:entry=>entry.provider==='native-controlled'&&entry.model==='native-controlled-lookup'});
 assert.equal(value.proof.receipt.eventId,lastLookup.receipt.eventId);
 assert.equal(value.proof.receipt.rowSha256,E.rowDigest(lastLookup.user));
 const packet=E.projectUserLookupCandidate(value);assert.equal(packet.evidence[2].content,graphOriginal.text);
 assert.ok(!require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput({rubric:{...E.RUBRIC,mode:'vuln'},...packet}).evidenceError);
 const graphBefore=providerCalls,graphSources=await auditRows(a);
 assert.deepEqual(await graph.readRequest(a.scope,a.persona,context(a).personaSession,graphInput.sessionId,graphInput.requestId),graphSaved);
 assert.equal(providerCalls,graphBefore);assert.deepEqual(await auditRows(a),graphSources);
 // Reseed this genuinely populated store; instructor content/configuration and
 // the original native graph/source records must remain byte-for-byte intact.
 await im.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor lookup assessment',configuration_source='instructor' WHERE objective_id=$1",[objective]);
 await im.query("UPDATE workshop_platform.objectives SET label='Instructor lookup lesson',hint_enabled=false,solution_enabled=true,hint_content=$2::jsonb,solution_content=$3::jsonb WHERE workshop_key='secureshop_agent_security' AND objective_id=$1",
  [objective,JSON.stringify(['Instructor lookup hint']),JSON.stringify({description:'Instructor lookup guidance',example:'Preserved example',tips:['Preserved tips']})]);
 const configuredObjective=await objectiveRow(),configuredPlatform=await platformRow();
 const retainedGraph=await journal.readBoundRequest({sessionId:graphInput.sessionId,requestId:graphInput.requestId,binding,
  purpose:require('../../server/database/postgres/secureshopRoleChatBindingRepository').PURPOSES.admin});
 for(let seedAttempt=0;seedAttempt<2;seedAttempt++){
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);await assessmentSeed(im);
  assert.deepEqual(await objectiveRow(),configuredObjective);assert.deepEqual(await platformRow(),configuredPlatform);
  assert.deepEqual(await auditRows(a),graphSources);assert.deepEqual(await auditRows(b),siblingSourceRows);
  assert.deepEqual(await journal.readBoundRequest({sessionId:graphInput.sessionId,requestId:graphInput.requestId,binding,
   purpose:require('../../server/database/postgres/secureshopRoleChatBindingRepository').PURPOSES.admin}),retainedGraph);
 }
 const modes=require('../../server/database/postgres/workshopRevisionRepository').createWorkshopModeRepository(identity);
 await modes.setMode({userId:a.scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:'fixed'});
 const fixedManual=await service.lookup(context(a));
 assert.deepEqual(fixedManual,{ok:true,synthetic:true,user:{id:first.user.id,username:first.user.username,role:first.user.role}});
 await assert.rejects(service.readAgentLookup({...agentContext(a,aScene),reference:agentOriginal.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 const fixedAgent=await service.lookupForAgent(agentContext(a,aScene));assert.equal(fixedAgent.status,'redacted');
 assert.deepEqual(fixedAgent.user,fixedManual.user);assert.equal(fixedAgent.receipt.modeExecution.mode,'fixed');
 assert.deepEqual(await service.readAgentLookup({...agentContext(a,aScene),reference:fixedAgent.receipt}),fixedAgent);
 const fixedGraph=await graph.run({...graphInput,requestId:randomUUID(),signal:AbortSignal.timeout(20000)});
 assert.equal(fixedGraph.stopReason,'end_turn');assert.equal(lastLookup.status,'redacted');assert.deepEqual(lastLookup.user,fixedManual.user);
 assert.equal(providerCalls,4);for(const field of E.FIELDS)assert.equal(fixedGraph.text.includes(first.user[field]),false);
 const fixedHistory=await auditRows(a);assert.equal(fixedHistory.length,4);
 assert.deepEqual(await auditRows(b),siblingSourceRows);
 await modes.setMode({userId:a.scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:'vuln'});
 await assert.rejects(service.readAgentLookup({...agentContext(a,aScene),reference:agentOriginal.receipt}),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
 assert.deepEqual(await auditRows(a),fixedHistory,'mode changes and denied readbacks preserve immutable sources');
 const stored=async o=>(await agents.query('SELECT * FROM secureshop_agents.bound_synthetic_user_directories WHERE platform_launch_id=$1',[o.scope.launchId])).rows;
 const siblingBefore=await stored(b);await retire(a);assert.deepEqual(await stored(a),[]);await assert.rejects(service.lookup(context(a)));await assert.rejects(service.readAgentLookup({...agentContext(a,aScene),reference:agentOriginal.receipt}));assert.deepEqual(await auditRows(a),fixedHistory);assert.deepEqual(await auditRows(b),siblingSourceRows);
 const prepared=await repository.prepare(),client=await agents.connect();try{await client.query('BEGIN');await assert.rejects(repository.lookup(client,{scope:a.scope,persona:a.persona,username:'student_customer',prepared}),{code:'55000'});await client.query('ROLLBACK');}finally{client.release();}
 const c=await owner();await service.lookup(context(c));await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[c.scope.platformOwnerId,randomUUID()]);assert.deepEqual(await stored(c),[]);await assert.rejects(service.lookup(context(c)));
 assert.deepEqual(await stored(b),siblingBefore);assert.deepEqual(await service.lookup(context(b)),sibling);
 await assert.rejects(agents.query('DELETE FROM secureshop_agents.bound_synthetic_user_directories'),{code:'42501'});
 fs.writeFileSync(process.env.PERSONA_OWNED_USER_LOOKUP_EVIDENCE_PATH||'owned-user-lookup-result.json',JSON.stringify({status:'passed',actualModelCalls:0,fresh:true,populated:true,noop:true,originalCredential:true,sibling:true,retirement:true,ownerCleanup:true,readinessDrifts:drifts,currentTail:true,registryFreshPopulatedNoop:true,registryOverridePreserved:true,pendingFreshPopulatedNoop:true,instructorContentPreserved:true,controlledGraphEvidence:true,controlledActorCalls:providerCalls,genuineCredit:false,agentSourceReadback:true,manualFixedSafe:true,agentFixedSafe:true,modeFence:true,sceneFence:true,sessionFence:true,immutableAgentSources:true,scope:'Real agents authority/service and canonical store retirement/owner cleanup; not full identity deletion finalizer'},null,2));
});
