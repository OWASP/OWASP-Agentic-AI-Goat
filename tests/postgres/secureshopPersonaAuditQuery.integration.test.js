'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
test('owned audit query persona authority with real isolated SQL',{skip:process.env.PERSONA_AUDIT_QUERY_NATIVE!=='1',timeout:process.env.PERSONA_AUDIT_QUERY_ACTUAL_MODEL==='1'?600000:240000},async t=>{
 const evidencePath=process.env.PERSONA_AUDIT_QUERY_EVIDENCE;
 if(evidencePath!==undefined)assert.ok(path.isAbsolute(evidencePath),'PERSONA_AUDIT_QUERY_EVIDENCE must be absolute');
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');const {migrate}=require('../../db/postgres/migrate');await require('./secureshopPolicyTraceMigrationGate')({t,identity,migration:im});await require('./secureshopAuditSnapshotMigrationGate')({t,identity,migration:im});await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 await migrate(am,'db/postgres/workshop-migrations/secureshop_agents');
 // Retain the promoted candidate's existence guards without an artificial9999 ledger entry.
 const promoted=(await am.query(`SELECT to_regclass('secureshop_agents.bound_persona_state') IS NOT NULL AS state,
  to_regclass('secureshop_agents.bound_persona_admin_operations') IS NOT NULL AS operations,
  to_regclass('secureshop_agents.bound_persona_admin_cleanup_receipts') IS NOT NULL AS cleanup,
  to_regprocedure('secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer)') IS NOT NULL AS revoke,
  to_regprocedure('secureshop_agents.cleanup_bound_persona_admin()') IS NOT NULL AS retire`)).rows[0];
 assert.deepEqual(promoted,{state:true,operations:true,cleanup:true,revoke:true,retire:true});
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
 await im.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'");
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_audit_sql_extraction'")).rowCount,1);
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),resetComposition=Object.freeze({launches});
 const gradingBootstrap=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,resetComposition,expectedIdentityDatabase:new URL(process.env.PERSONA_IDENTITY_RUNTIME_URL).pathname.slice(1),expectedAgentsDatabase:new URL(process.env.PERSONA_FRESH_RUNTIME_URL).pathname.slice(1)});
 const authority=gradingBootstrap.personaAuthority;const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-canonical-review-native-only-secret'});
 const createOwner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+1200000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,bearer:issued.bearer,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};
 const evidence={status:'running',actualModelCalls:0,cases:[],cleanup:[]};const save=()=>fs.writeFileSync(evidencePath??'persona-audit-query-result.json',JSON.stringify(evidence,null,2)+'\n',{mode:0o600});t.after(save);
 const controlURL=new URL(process.env.PERSONA_AUDIT_CONTROL_URL);assert.equal(controlURL.hostname,'127.0.0.1');assert.notEqual(controlURL.port,new URL(process.env.PERSONA_IDENTITY_RUNTIME_URL).port);assert.match(controlURL.pathname,/^\/owasp_ai_goat_test_audit_search_[a-f0-9]+$/);
 const config={host:controlURL.hostname,port:Number(controlURL.port),user:controlURL.username,database:controlURL.pathname.slice(1)},control=new Pool({...config,max:2});
 for(const file of ['schema.sql','migrations/0002_query_receipts.sql','migrations/0003_query_destruction_tombstones.sql'])await control.query(fs.readFileSync('sidecars/audit-sql-target/'+file,'utf8'));
 const service=require('../../sidecars/audit-sql-target/service').createService({controlPool:control,clusterConfig:config});
 const backend=require('../../server/services/secureshopOwnedAuditSearchBackend').createOwnedAuditBackend({journal:require('../../sidecars/audit-sql-target/journal').createJournal({pool:control}),service,checkReadiness:()=>require('../../sidecars/audit-sql-target/readiness').assertReadiness({pool:control,controlDatabase:config.database,administrator:config.user})});
 const token=require('node:crypto').randomBytes(32).toString('base64url'),http=require('../../sidecars/audit-sql-target/http').createPrivateAuditServer({token,backend});const address=await http.listen();const client=require('../../server/services/secureshopOwnedAuditHttpClient').createOwnedAuditHttpClient({url:`http://127.0.0.1:${address.port}`,token});
 const owned=[];t.after(async()=>{try{for(const owner of owned){await backend.retire({binding:owner.scope});evidence.cleanup.push({launchId:owner.scope.launchId,retired:true});}}finally{await http.close();await service.close();await control.end();save();}});
 const rows=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:require('../../server/services/secureshop/sessionStore').runSessionExclusive});const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:rows,launches});
 const repository=require('../../server/database/postgres/secureshopAuditQueryRepository').createAuditQueryRepository({pool:identity,checkExecutionBinding:require('../../server/services/secureshopAuditQueryExecutionBinding').createAuditQueryExecutionBinding({repository:rows,conversations})});
 const admissions=require('../../server/database/postgres/secureshopAuditTargetAdmissionRepository').createAuditTargetAdmissionRepository({pool:identity});
 const review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION');await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');
 const auditBundle=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review});
 const leases=pool('IDENTITY','RUNTIME'),ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',ledger});
 const actualTurns=require('../../server/services/secureshopBoundTurns').createBoundTurns({conversations,coordinator});
 const actualJournal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const snapshotBuilder=require('../../server/services/secureshopOwnedAuditSearchSnapshot').createOwnedAuditSearchSnapshotBuilder({reader:auditBundle.reader,assertCurrent:checkCurrent});
 const snapshotModule=require('../../server/services/secureshopOwnedAuditSearchSnapshot');
 async function create(label,provision=true,canonical=false,purpose='secureshop_audit_sql',admitSnapshot=true){const owner=await createOwner(label);owned.push(owner);const conversation=await conversations.create(owner.scope,owner.persona,purpose),runId=randomUUID(),ownerKey=JSON.stringify(['SecureShopBoundConversation',conversation.id]);if(!canonical){await im.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);await im.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[runId,ownerKey]);}await require('../../server/database/postgres').withTransaction(agents,c=>auditBundle.agents.append(c,{eventId:randomUUID(),scope:owner.scope,persona:owner.persona,actor:'admin',action:'qualification',target:null,paramsJson:'{}',outcome:'completed',sourceKind:'profile',sourceId:'1'}));const execution={runId,ownerKey,durableGeneration:'0',check:()=>launches.assertCurrent(owner.scope)};const snapshot=await snapshotBuilder.capture(owner.scope),source=snapshotModule.receiptFor(snapshot);if(admitSnapshot)await admissions.admit({binding:owner.scope,sourceSha256:source.sourcesSha256,payloadSha256:source.payloadSha256,snapshot});if(provision)await client.provision(snapshotModule.privateRequestFor(snapshot));const selected=await client.target({binding:owner.scope});const fence=await authority.capture({scope:owner.scope,personaId:owner.persona.id,role:'admin',...owner.personaSession});return{owner,admittedSource:source,conversationId:conversation.id,fence,execution,request:{binding:owner.scope,runId,operationId:randomUUID(),username:'owned',...selected}};}
 try{
 if(process.env.PERSONA_AUDIT_QUERY_ACTUAL_MODEL==='1'){
  await require('./secureshopPersonaAuditQueryActualGate')({t,identity,agents,gradingBootstrap,resetComposition,launches,auth,auditBundle,actualTurns,actualJournal,conversations,rows,client,ledger,personas,create,evidence,save});evidence.status='passed';save();return;
 }
 for(const phase of ['snapshot','provision']){
  const f=await create('audit-target-'+phase,false,true,'secureshop_audit_sql',phase!=='snapshot');let queryCalls=0,revokeCalls=0;
  const revoke=()=>{revokeCalls++;return personas.revokeOwnedSession({scope:f.owner.scope,shopUserId:f.owner.persona.id,sessionId:f.owner.personaSession.sessionId});};
  const transport={...client,provision:async input=>{const result=await client.provision(input);if(phase==='provision')await revoke();return result;}};
  const snapshots={capture:async scope=>{const result=await snapshotBuilder.capture(scope);if(phase==='snapshot')await revoke();return result;}};
  const app=require('../../server/services/secureshopOwnedAuditSearchApplication').createOwnedAuditSearchApplication({launches,personaAuthority:authority,snapshots,client:transport,targetAdmissions:admissions,
   journal:actualJournal,turns:actualTurns,
   graphAdapter:{execute:async()=>{queryCalls++;throw Error('No query after revoked provisioning');}},decisionGraph:{run:async({query})=>{await query('owned');return{text:'controlled'};}},beginAssessment:async()=>({mode:'vuln',consume:async()=>{throw Error('No grading after revoked target');}})});
  await assert.rejects(app.runAgent({scope:f.owner.scope,persona:f.owner.persona,personaSession:f.owner.personaSession,sessionId:f.conversationId,requestId:randomUUID(),message:'controlled'}),error=>phase==='snapshot'?error.code==='SHOP_AUTH_INVALID':error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.cause.code==='SHOP_AUTH_INVALID');
  assert.equal(revokeCalls,1,'The requested authority race must actually be injected');assert.equal(queryCalls,0);const turnsAfter=(await agents.query('SELECT status FROM secureshop_agents.turn_requests WHERE session_id=$1',[f.conversationId])).rows;assert.ok(turnsAfter.length>0);assert.ok(turnsAfter.every(row=>row.status==='uncertain')); const target=await client.target({binding:f.owner.scope});assert.equal(target.missing===true,phase==='snapshot');
  evidence.cases.push({case:'actual_target_revoke_'+phase,targetRetained:phase==='provision',canonicalTurnJournal:true});save();
 }
 const canonical=await create('audit-canonical-live',false,true);let canonicalQueries=0;
 const realAdapter=require('../../server/services/secureshopOwnedAuditQueryAdapter').createOwnedAuditQueryAdapter({repository,client});
 const canonicalApp=require('../../server/services/secureshopOwnedAuditSearchApplication').createOwnedAuditSearchApplication({launches,personaAuthority:authority,snapshots:snapshotBuilder,client,targetAdmissions:admissions,journal:actualJournal,turns:actualTurns,
  graphAdapter:{execute:async(...args)=>{canonicalQueries++;return realAdapter.execute(...args);}},decisionGraph:{run:async({query})=>{await query('owned');return{text:'Controlled actor after real SQL'};}},beginAssessment:async()=>({mode:'vuln',consume:async()=>({completed:false,controlled:true})})});
 const canonicalInput={scope:canonical.owner.scope,persona:canonical.owner.persona,personaSession:canonical.owner.personaSession,sessionId:canonical.conversationId,requestId:randomUUID(),message:'Controlled canonical query'};
 await canonicalApp.runAgent(canonicalInput);assert.equal(canonicalQueries,1);assert.equal((await agents.query('SELECT status FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[canonical.conversationId,canonicalInput.requestId])).rows[0].status,'completed');
 assert.equal((await canonicalApp.runAgent(canonicalInput)).replayed,true);assert.equal(canonicalQueries,1);evidence.cases.push({case:'canonical_controlled_actor_real_query_completed_replay',queryCalls:canonicalQueries,judgeCalls:0});save();
 // Actual public factory and actual private assessment, with deliberately controlled
 // actor output. No qualification override: this cannot create a grade packet.
 const assembled=await create('audit-factory-live',false,true);let actorCalls=0,judgeCalls=0;
 const provider={chat:async()=>{actorCalls++;return{provider:'fixture',model:'controlled',tool_uses:[{id:'owned-query',name:'audit.search_by_user',args:{username:'owned'}}]};},finalResponse:async()=>{actorCalls++;return{provider:'fixture',model:'controlled',text:'Controlled observation of the real owned SQL result'};}};
 const factoryInput={identityPool:identity,agentsPool:agents,resetComposition,gradingBootstrap,launches,personaAuth:auth,auditReader:auditBundle.reader,cleanupAuthority:require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity),turns:actualTurns,journal:actualJournal,conversations,conversationRepository:rows,client,provider,judge:async()=>{judgeCalls++;throw Error('Controlled actor must not reach Judge');}};
 const assembledFactory=require('../../server/services/secureshopOwnedAuditComposition').createOwnedAuditComposition({...factoryInput,agentEnabled:true});await assembledFactory.checkReadiness();
 const assembledInput={scope:assembled.owner.scope,persona:assembled.owner.persona,personaSession:assembled.owner.personaSession,sessionId:assembled.conversationId,requestId:randomUUID(),message:'Search owned audit events'};
 const assembledResult=await assembledFactory.application.runAgent(assembledInput);assert.equal(assembledResult.result.assessment.passed,false);assert.equal(actorCalls,2);assert.equal(judgeCalls,0);
 assert.equal((await identity.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1',[assembled.owner.user.id])).rows[0].n,0);
 assert.equal((await identity.query('SELECT count(*)::int AS n FROM workshop_platform.persona_evaluation_bindings WHERE user_id=$1',[assembled.owner.user.id])).rows[0].n,0);
 assert.equal((await assembledFactory.application.runAgent(assembledInput)).replayed,true);assert.equal(actorCalls,2);
 const manualFactory=require('../../server/services/secureshopOwnedAuditComposition').createOwnedAuditComposition({...factoryInput,agentEnabled:false});await manualFactory.checkReadiness();
 assert.equal((await manualFactory.application.search({scope:assembled.owner.scope,persona:assembled.owner.persona,token:assembled.owner.personaToken,operationId:randomUUID(),username:'owned'})).ok,true);
 await personas.revokeOwnedSession({scope:assembled.owner.scope,shopUserId:assembled.owner.persona.id,sessionId:assembled.owner.personaSession.sessionId});
 await assert.rejects(assembledFactory.application.runAgent(assembledInput),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(manualFactory.application.search({scope:assembled.owner.scope,persona:assembled.owner.persona,token:assembled.owner.personaToken,operationId:randomUUID(),username:'owned'}),{code:'SHOP_AUTH_INVALID'});
 evidence.cases.push({case:'actual_branded_factory_controlled_graph_and_assessment',actorCalls,judgeCalls,judgments:0,bindings:0,manualOnlyGuarded:true,actualModel:false});save();
 const live=await create('audit-query-live');let searches=0,reads=0;
 const wrapped={search:async input=>{searches++;const result=await client.search(input);throw Object.assign(Error('Controlled lost acknowledgement after real receipt'),{code:'ECONNRESET'});},receipt:async input=>{reads++;return client.receipt(input);}};
 const factory=transport=>require('../../server/services/secureshopOwnedAuditQueryAdapter').createOwnedAuditQueryAdapter({repository,client:transport});
 await assert.rejects(factory(wrapped).execute(live,live.fence),e=>e.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&e.cause.code==='ECONNRESET');assert.equal(searches,1);
 const pending=(await identity.query('SELECT receipt_json FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[live.request.operationId])).rows[0];assert.equal(pending.receipt_json,null);
 const recovered=await factory(wrapped).execute(live,live.fence);assert.equal(recovered.ok,true);assert.equal(searches,1);assert.equal(reads,1);await factory(wrapped).execute(live,live.fence);assert.equal(reads,1);evidence.cases.push({case:'real_query_lost_ack_receipt_only',searches,reads});save();
 const revoked=await create('audit-query-revoked');let dispatched=0;
 const revokeTransport={...client,search:async input=>{dispatched++;const receipt=await client.search(input);await personas.revokeOwnedSession({scope:revoked.owner.scope,shopUserId:revoked.owner.persona.id,sessionId:revoked.owner.personaSession.sessionId});return receipt;}};
 await assert.rejects(factory(revokeTransport).execute(revoked,revoked.fence),e=>e.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&e.cause.code==='SHOP_AUTH_INVALID');assert.equal(dispatched,1);assert.equal((await identity.query('SELECT receipt_json FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[revoked.request.operationId])).rows[0].receipt_json,null);
 await assert.rejects(factory(revokeTransport).execute(revoked,revoked.fence),{code:'SHOP_AUTH_INVALID'});assert.equal(dispatched,1);assert.ok(await client.receipt({binding:revoked.owner.scope,operationId:revoked.request.operationId,username:revoked.request.username}));evidence.cases.push({case:'revoked_after_actual_query',targetReceiptRetained:true,centralReceipt:null});
 const manualRepository=require('../../server/database/postgres/secureshopAuditManualRepository').createAuditManualRepository({pool:identity,personaAuth:auth});
 const appFactory=({transport=client,graph=realAdapter}={})=>require('../../server/services/secureshopOwnedAuditSearchApplication').createOwnedAuditSearchApplication({launches,personaAuth:auth,personaAuthority:authority,snapshots:snapshotBuilder,client,targetAdmissions:admissions,journal:actualJournal,turns:actualTurns,graphAdapter:graph,manualAdapter:require('../../server/services/secureshopOwnedAuditManualAdapter').createOwnedAuditManualAdapter({repository:manualRepository,client:transport})});
 const manual=await create('audit-manual-live');let manualSearches=0,manualReads=0;
 const manualTransport={...client,search:async input=>{manualSearches++;await client.search(input);throw Object.assign(Error('Controlled manual lost acknowledgement'),{code:'ECONNRESET'});},receipt:async input=>{manualReads++;return client.receipt(input);}};
 const manualInput={scope:manual.owner.scope,persona:manual.owner.persona,token:manual.owner.personaToken,operationId:randomUUID(),username:'owned'};
 await assert.rejects(appFactory({transport:manualTransport}).search(manualInput),error=>error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.cause.code==='ECONNRESET');
 assert.equal((await identity.query('SELECT receipt_json FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1',[manualInput.operationId])).rows[0].receipt_json,null);
 assert.equal((await appFactory({transport:manualTransport}).search(manualInput)).ok,true);assert.equal(manualSearches,1);assert.equal(manualReads,1);assert.equal((await appFactory({transport:manualTransport}).search(manualInput)).ok,true);assert.equal(manualSearches,1);assert.equal(manualReads,1);
 evidence.cases.push({case:'manual_real_auth_lost_ack_receipt_only',searches:manualSearches,reads:manualReads});save();
 const manualRevoked=await create('audit-manual-revoked');let manualRevokedSearches=0;
 const manualRevokeTransport={...client,search:async input=>{manualRevokedSearches++;const receipt=await client.search(input);await personas.revokeOwnedSession({scope:manualRevoked.owner.scope,shopUserId:manualRevoked.owner.persona.id,sessionId:manualRevoked.owner.personaSession.sessionId});return receipt;}};
 const manualRevokedInput={scope:manualRevoked.owner.scope,persona:manualRevoked.owner.persona,token:manualRevoked.owner.personaToken,operationId:randomUUID(),username:'owned'};
 await assert.rejects(appFactory({transport:manualRevokeTransport}).search(manualRevokedInput),error=>error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.cause.code==='SHOP_AUTH_INVALID');
 await assert.rejects(appFactory({transport:manualRevokeTransport}).search(manualRevokedInput),{code:'SHOP_AUTH_INVALID'});assert.equal(manualRevokedSearches,1);
 assert.equal((await identity.query('SELECT receipt_json FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1',[manualRevokedInput.operationId])).rows[0].receipt_json,null);evidence.cases.push({case:'manual_revoked_after_real_query',centralReceipt:null});save();
 const retained=await create('audit-retained-graph',true,true,'general');let retainedQueries=0;
 const retainedAdapter={execute:async(...args)=>{retainedQueries++;const result=await realAdapter.execute(...args);await personas.revokeOwnedSession({scope:retained.owner.scope,shopUserId:retained.owner.persona.id,sessionId:retained.owner.personaSession.sessionId});return result;}};
 const retainedInput={scope:retained.owner.scope,persona:retained.owner.persona,personaSession:retained.owner.personaSession,sessionId:retained.conversationId,requestId:randomUUID(),username:'owned'};
 await assert.rejects(appFactory({graph:retainedAdapter}).runGraph(retainedInput),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await agents.query('SELECT status FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[retained.conversationId,retainedInput.requestId])).rows[0].status,'uncertain');
 assert.ok((await identity.query('SELECT receipt_json FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[retainedInput.requestId])).rows[0].receipt_json);
 await assert.rejects(appFactory({graph:retainedAdapter}).runGraph(retainedInput),{code:'SHOP_AUTH_INVALID'});assert.equal(retainedQueries,1);evidence.cases.push({case:'retained_graph_postreceipt_revoke_denies_completed_turn',centralReceiptRetained:true,turn:'uncertain'});save();
 const admins=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,checkCurrent,auditStore:auditFactory({store:'agents',pool:agents})});
 for(const kind of ['role','platform','reset']){
  const f=await create('audit-query-'+kind);await factory(client).execute(f,f.fence);
  const original=(await identity.query('SELECT receipt_json FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[f.request.operationId])).rows[0];
  if(kind==='role'){const login=await auth.login({scope:f.owner.scope,username:'student_admin',password:'student123'}),actor=await auth.authenticateBoundToken({scope:f.owner.scope,token:login.token});await admins.mutate({scope:f.owner.scope,actorId:actor.user.id,actorSessionId:actor.sessionId,targetId:f.owner.persona.id,operationId:randomUUID(),expectedVersion:'1',action:'set_role',role:'merchant'});}
  if(kind==='platform')await users.revokeSession(f.owner.token,f.owner.user.id,'Owned query qualification');
  if(kind==='reset')await launches.beginReset({...f.owner.scope,expectedGeneration:f.owner.scope.generation,idempotencyKey:randomUUID()});
  let network=0;const forbidden={search:async()=>{network++;throw Error('No dispatch');},receipt:async()=>{network++;throw Error('No readback');}};
  await assert.rejects(factory(forbidden).execute(f,f.fence),error=>kind==='role'?error.code==='SHOP_AUTH_INVALID':['STALE_LAUNCH','SESSION_UNAVAILABLE'].includes(error.code));assert.equal(network,0);
  assert.deepEqual((await identity.query('SELECT receipt_json FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[f.request.operationId])).rows[0],original);evidence.cases.push({case:kind+'_denies_completed_projection',originalReceiptPreserved:true});save();
 }
 assert.equal((await factory(wrapped).execute(live,live.fence)).ok,true);evidence.cases.push({case:'live_sibling_replay_preserved'});evidence.status='passed';save();
 }catch(error){evidence.status='failed';evidence.failure={code:error.code||null,message:error.message};save();throw error;}
});

test('Persona audit migration views retain canonical bytes and staged boundaries without global mutation',async()=>{
 const fsp=require('node:fs/promises'),original=fsp.readdir;
 const directory=path.resolve(__dirname,'../../db/postgres/identity-migrations');
 const {readMigrations}=require('../../db/postgres/migrate'),full=await readMigrations(directory);
 const {canonicalIdentityView}=require('./secureshopPolicyTraceMigrationGate');
 for(const [stage,bound] of [['before0099','0099_'],['through0099','0100_'],['through0100','0101_']]){
  const view=canonicalIdentityView(stage);
  assert.deepEqual(await view.readMigrations(directory),full.filter(row=>row.name<bound));
  await assert.rejects(view.readMigrations(path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents')));
 }
 assert.throws(()=>canonicalIdentityView('all'));
 assert.equal(fsp.readdir,original);assert.deepEqual(await readMigrations(directory),full);
 assert.ok(full.some(row=>row.name>'0100_secureshop_audit_target_snapshot.sql'));
});
