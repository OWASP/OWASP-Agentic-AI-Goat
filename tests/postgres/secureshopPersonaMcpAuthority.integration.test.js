'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
test('optional production MCP persona assembly uses real SDK effects and controlled provider',{skip:process.env.PERSONA_REVIEW_CANONICAL_NATIVE!=='1',timeout:90000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);const p=new Pool({connectionString:u.href,max:3,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');const {migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const dir=fs.mkdtempSync(path.join(process.cwd(),'canonical-candidate-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));for(const name of fs.readdirSync('db/postgres/workshop-migrations/secureshop_agents'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/workshop-migrations/secureshop_agents',name),path.join(dir,name));fs.copyFileSync('docs/modernization/drafts/secureshop-user-administration/persona-state.candidate.sql',path.join(dir,'9999_persona_admin.sql'));await migrate(am,dir);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-canonical-review-native-only-secret'});
 const createOwner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+600000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,bearer:issued.bearer,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};





 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
 // Explicit owned fixture configuration; supported curriculum defaults stay disabled.
 const objective='ss_loop_observation';
 assert.equal((await im.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'")).rowCount,1);
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id=$1",[objective])).rowCount,1);
 const visibility=(await identity.query("SELECT w.is_visible,w.catalog_active AS exercise_active,o.is_enabled,o.catalog_active AS objective_active FROM workshop_platform.exercises w JOIN workshop_platform.objectives o USING(workshop_key) WHERE w.workshop_key='secureshop_agent_security' AND o.objective_id=$1",[objective])).rows[0];
 assert.deepEqual(visibility,{is_visible:true,exercise_active:true,is_enabled:true,objective_active:true});
 const o=await createOwner('judgment-owner');
 const write=async(c,evalId,runId,required)=>{await c.query(`INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,canonical_mode,mode_stamp,platform_launch_id,platform_scenario_id,platform_launch_generation${required===undefined?'':',persona_authority_required'}) VALUES($1,$2,'secureshop_agent_security',$3,'SecureShop','candidate','candidate-v1',$4,$5,0,'vuln','vuln','default',$6,$7,$8${required===undefined?'':',$9'})`,[o.user.id,evalId,objective,'a'.repeat(64),runId,o.scope.launchId,o.scope.scenarioId,o.scope.generation,...(required===undefined?[]:[required])]);await c.query("INSERT INTO workshop_platform.grade_packets(user_id,evaluation_id,packet,judge_version,mode_stamp) VALUES($1,$2,'{}','controlled-test','default')",[o.user.id,evalId]);};
 const oldId=randomUUID();await write(identity,oldId,randomUUID());
 const identityDir=fs.mkdtempSync(path.join(process.cwd(),'judgment-candidate-'));t.after(()=>fs.rmSync(identityDir,{recursive:true,force:true}));for(const name of fs.readdirSync('db/postgres/identity-migrations'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/identity-migrations',name),path.join(identityDir,name));fs.copyFileSync('docs/modernization/drafts/secureshop-persona-judgments/persona-judgments.candidate.sql',path.join(identityDir,'9999_persona_judgments.sql'));assert.deepEqual(await migrate(im,identityDir),['9999_persona_judgments.sql']);assert.deepEqual(await migrate(im,identityDir),[]);const freshIdentity=pool('IDENTITYFRESH','MIGRATION');assert.ok((await migrate(freshIdentity,identityDir)).includes('9999_persona_judgments.sql'));assert.deepEqual(await migrate(freshIdentity,identityDir),[]);assert.equal((await freshIdentity.query('SELECT count(*)::int n FROM workshop_platform.persona_evaluation_bindings')).rows[0].n,0);
 assert.equal((await identity.query('SELECT persona_authority_required FROM workshop_platform.objective_judgments WHERE evaluation_id=$1',[oldId])).rows[0].persona_authority_required,false);
 const candidate=require('../../docs/modernization/drafts/secureshop-persona-judgments/repository.candidate').createPersonaJudgmentCandidate({pool:identity,personaAuthority:authority});

 const objectiveIds=['ss_rogue_tool_selected','ss_rug_pull_invoked'];
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id=ANY($1::text[])",[objectiveIds])).rowCount,2);
 const {createSecureShopMcpTrustProduction,createSecureShopMcpTrustRepositoryBundle,assertSecureShopMcpTrustReadiness}=require('../../server/services/secureshopMcpTrustProduction');
 const {createSecureShopMcpTrustAvailability}=require('../../server/services/secureshopMcpTrustAvailability');
 await assertSecureShopMcpTrustReadiness({identityPool:identity,agentsPool:agents});
 await candidate.ready();
 const cleanupAuthority=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
 const fixtureRoot=fs.mkdtempSync(path.join(process.cwd(),'mcp-persona-files-'));
 const evidence={modelCalls:0,judgeCalls:0,controlledProviderCalls:0,remoteReceipts:[],cases:[],remote:{discover:0,ensure:0,rotate:0,callTool:0},cleanup:[]};
 const save=()=>fs.writeFileSync(path.join(process.cwd(),'persona-mcp-result.json'),JSON.stringify(evidence,null,2)+'\n',{mode:0o600});t.after(save);
 const realTargets=require('../../server/services/secureshopMcpControlledTargetPool').createSecureShopMcpControlledTargetPool({root:fixtureRoot});
 const tracked=new Set();let remoteHold=null,providerHold=null;
 const targetPool={...realTargets};
 for(const method of ['discover','ensure','rotate','callTool'])targetPool[method]=async(...args)=>{evidence.remote[method]++;const targetId=typeof args[0]==='string'?args[0]:args[0].targetId;if(targetId)tracked.add(targetId);const result=await realTargets[method](...args);if(method==='callTool'){assert.match(result.receiptSha256,/^[a-f0-9]{64}$/);evidence.remoteReceipts.push({behaviorClass:result.behaviorClass,receiptSha256:result.receiptSha256});}if(method==='callTool'&&remoteHold){const hold=remoteHold;remoteHold=null;hold.entered.resolve();await hold.release.promise;}save();return result;};
 t.after(async()=>{const results=await Promise.allSettled([...tracked].map(id=>realTargets.retire(id)));await realTargets.close();const failed=results.filter(r=>r.status==='rejected');evidence.finalCleanup={failed:failed.length,filesAbsent:fs.readdirSync(fixtureRoot).length===0};save();assert.equal(failed.length,0);assert.equal(evidence.finalCleanup.filesAbsent,true);fs.rmdirSync(fixtureRoot);});
 const bundle=createSecureShopMcpTrustRepositoryBundle({agentsPool:agents,launches,cleanupAuthority,availability:createSecureShopMcpTrustAvailability(identity),fixtureRoot,targetPool,auditStore:auditFactory({store:'agents',pool:agents})});
 const conversationRows=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:require('../../server/services/secureshop/sessionStore').runSessionExclusive});
 const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRows,launches});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const leases=pool('IDENTITY','RUNTIME'),ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopMcpPersona:'+randomUUID(),ledger});
 const turns=require('../../server/services/secureshopBoundTurns').createBoundTurns({conversations,coordinator});
 let decisionId=0;
 const provider={config:{provider:'mock',model:'controlled-persona-native'},async chat(input){evidence.controlledProviderCalls++;if(providerHold){const hold=providerHold;providerHold=null;hold.entered.resolve();await hold.release.promise;}
  if(input.messages.at(-1)?.role==='tool')return{provider:'mock',model:'controlled-persona-native',mocked:true,stop_reason:'end_turn',text:'Controlled response to observed SDK effect'};
  const tool=input.tools[0];assert.ok(tool);return{provider:'mock',model:'controlled-persona-native',mocked:true,stop_reason:'tool_use',tool_uses:[{id:'controlled-'+(++decisionId),name:`${tool.agent}.${tool.tool}`,args:{city:'Seattle'}}]};}};
 const production=createSecureShopMcpTrustProduction({enabled:true,identityPool:identity,provider,judge:async()=>{evidence.judgeCalls++;throw Error('Controlled provider must never qualify Judge evidence');},personaAuthority:authority,personaBindings:candidate,resetComposition:{mcpTrust:bundle,launches,conversationService:conversations,turns,conversations:conversationRows,journal}});
 assert.equal(production.ready,true);const app=production.application;
 const request=(owner,trustScenario='rogue_registration')=>({scope:owner.scope,persona:owner.persona,personaSession:owner.personaSession,trustScenario,requestId:randomUUID()});
 const owners=[];const owner=async label=>{const value=await createOwner(label);owners.push(value);return value;};
 const countInvocations=async value=>Number((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_mcp_invocations i JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE t.original_platform_owner_id=$1',[value.user.id])).rows[0].n);
 const sibling=await owner('mcp-live-sibling'),rug=await owner('mcp-live-rug');
 for(const personaSession of [undefined,rug.personaSession])for(const method of ['status','discover','rotate','run'])await assert.rejects(app[method]({...request(sibling),personaSession}),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await app.status(request(sibling))).ready,true);await app.discover(request(sibling));const live=await app.run(request(sibling));assert.equal(live.ok,true);assert.equal(await countInvocations(sibling),1);evidence.cases.push({case:'live_rogue',invocations:1});save();
 await app.discover(request(rug,'rug_pull'));assert.equal((await app.run(request(rug,'rug_pull'))).ok,true);assert.equal((await app.rotate(request(rug))).schemaVersion,2);assert.equal((await app.run(request(rug,'rug_pull'))).ok,true);assert.equal(await countInvocations(rug),2);evidence.cases.push({case:'rug_baseline_rotated',invocations:2});save();
 for(const stage of ['provider','remote']){
  const value=await owner('mcp-revoke-'+stage),hold={entered:Promise.withResolvers(),release:Promise.withResolvers()};if(stage==='provider')providerHold=hold;else remoteHold=hold;
  const before=evidence.remote.callTool,pending=app.run(request(value));pending.catch(()=>{});await Promise.race([hold.entered.promise,pending.then(()=>{throw Error('Expected hold not reached');})]);
  assert.equal(await personas.revokeOwnedSession({scope:value.scope,shopUserId:value.persona.id,sessionId:value.personaSession.sessionId}),true);hold.release.resolve();
  await assert.rejects(pending,error=>stage==='provider'?error.code==='SHOP_AUTH_INVALID':error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.executionBoundary===true&&error.cause?.code==='SHOP_AUTH_INVALID');
  assert.equal(await countInvocations(value),0);assert.equal(evidence.remote.callTool-before,stage==='provider'?0:1);
  const turnStates=(await agents.query('SELECT tr.status FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id WHERE s.original_platform_owner_id=$1',[value.user.id])).rows;assert.deepEqual(turnStates,[{status:'uncertain'}]);
  for(const method of ['status','discover','rotate','run'])await assert.rejects(app[method](request(value)),{code:'SHOP_AUTH_INVALID'});
  evidence.cases.push({case:'revoke_'+stage,remoteCalls:evidence.remote.callTool-before,invocations:0,turnStatus:'uncertain'});save();
 }
 assert.equal(await countInvocations(sibling),1);assert.equal((await app.status(request(sibling))).ready,true);
 assert.equal(evidence.judgeCalls,0);assert.equal((await identity.query("SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE objective_id=ANY($1::text[])",[objectiveIds])).rows[0].n,0);
 assert.equal((await identity.query("SELECT count(*)::int n FROM workshop_platform.completions WHERE objective_id=ANY($1::text[])",[objectiveIds])).rows[0].n,0);
 const audits=(await agents.query("SELECT action,count(*)::int n FROM secureshop_agents.bound_audit_events WHERE action IN ('mcp_schema_discovered','mcp_schema_rotated','mcp_invocation_recorded') GROUP BY action ORDER BY action")).rows;evidence.audits=audits;assert.equal(audits.find(r=>r.action==='mcp_invocation_recorded')?.n,3);assert.equal(audits.find(r=>r.action==='mcp_schema_rotated')?.n,1);
 for(const value of owners){const reset=await launches.beginReset({...value.scope,expectedGeneration:value.scope.generation,idempotencyKey:randomUUID()});const targets=await cleanupAuthority.listTargets(reset.resetId);
  for(const target of targets.targets){const receipt=await bundle.cleanup(target,{operationId:reset.resetId});assert.deepEqual(await bundle.readCleanupReceipt({...target,operationId:reset.resetId}),receipt);assert.equal(fs.existsSync(path.join(fixtureRoot,target.targetId)),false);evidence.cleanup.push({targetId:target.targetId,kind:target.targetKind,retired:true});}
  await assert.rejects(app.status(request(value)),{code:'STALE_LAUNCH'});save();
 }
 assert.equal(fs.readdirSync(fixtureRoot).length,0);
 t.diagnostic('Real optional production factory, actual SDK files and PostgreSQL persona/launch/turn/audit. Controlled provider only; zero actual model/Judge/credit. Target reset cleanup only, no full reset completion or student finalizer claim.');
});
