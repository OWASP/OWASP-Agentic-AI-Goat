'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
test('optional MCP persona actual actor Judge initial and regrade authority',{skip:process.env.PERSONA_MCP_ACTUAL_MODEL!=='1',timeout:900000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);const p=new Pool({connectionString:u.href,max:3,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');const {migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const dir=fs.mkdtempSync(path.join(process.cwd(),'canonical-candidate-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));for(const name of fs.readdirSync('db/postgres/workshop-migrations/secureshop_agents'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/workshop-migrations/secureshop_agents',name),path.join(dir,name));fs.copyFileSync('docs/modernization/drafts/secureshop-user-administration/persona-state.candidate.sql',path.join(dir,'9999_persona_admin.sql'));await migrate(am,dir);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-canonical-review-native-only-secret'});
 const createOwner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+1200000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,bearer:issued.bearer,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};





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
 const evidence={status:'running',scope:'Actual local8B actor and Judge; optional candidate persona binding; controlled initial transport faults for retry; no mounted route or installed activation',actorAttempts:0,judgeAttempts:0,injectedTransportFaults:0,actorCalls:[],judgeCalls:[],budget:{actor:64,judge:16},remoteReceipts:[],cases:[],remote:{discover:0,ensure:0,rotate:0,callTool:0},cleanup:[]};
 const save=()=>fs.writeFileSync(path.join(process.cwd(),'persona-mcp-actual-result.json'),JSON.stringify(evidence,null,2)+'\n',{mode:0o600});t.after(save);
 const realTargets=require('../../server/services/secureshopMcpControlledTargetPool').createSecureShopMcpControlledTargetPool({root:fixtureRoot});
 const tracked=new Set();
 const targetPool={...realTargets};
 for(const method of ['discover','ensure','rotate','callTool'])targetPool[method]=async(...args)=>{evidence.remote[method]++;const targetId=typeof args[0]==='string'?args[0]:args[0].targetId;if(targetId)tracked.add(targetId);const result=await realTargets[method](...args);if(method==='callTool'){assert.match(result.receiptSha256,/^[a-f0-9]{64}$/);evidence.remoteReceipts.push({behaviorClass:result.behaviorClass,receiptSha256:result.receiptSha256});}save();return result;};
 t.after(async()=>{const results=await Promise.allSettled([...tracked].map(id=>realTargets.retire(id)));await realTargets.close();const failed=results.filter(r=>r.status==='rejected');evidence.finalCleanup={failed:failed.length,filesAbsent:fs.readdirSync(fixtureRoot).length===0};save();assert.equal(failed.length,0);assert.equal(evidence.finalCleanup.filesAbsent,true);fs.rmdirSync(fixtureRoot);});
 const bundle=createSecureShopMcpTrustRepositoryBundle({agentsPool:agents,launches,cleanupAuthority,availability:createSecureShopMcpTrustAvailability(identity),fixtureRoot,targetPool,auditStore:auditFactory({store:'agents',pool:agents})});
 const conversationRows=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:require('../../server/services/secureshop/sessionStore').runSessionExclusive});
 const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRows,launches});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const leases=pool('IDENTITY','RUNTIME'),ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopMcpPersona:'+randomUUID(),ledger});
 const turns=require('../../server/services/secureshopBoundTurns').createBoundTurns({conversations,coordinator});
 assert.equal(process.env.LIVE_OLLAMA_TEST,'1');assert.equal(process.env.JUDGE_PROVIDER,'ollama');assert.equal(process.env.OLLAMA_MODEL,'llama3.1:8b');
 const baseURL=process.env.OLLAMA_BASE_URL;assert.equal(baseURL,'http://127.0.0.1:11434');
 const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
 const {createLangChainProvider}=require('../../server/agent-runtime/providers/langchainProvider');
 const {createObjectiveJudge,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');
 const provider=new OllamaProvider({baseUrl:baseURL,model:'llama3.1:8b'});
 const lifetime=new AbortController();t.after(()=>lifetime.abort());
 const instrument=(transport,kind)=>{const original=transport.chat.bind(transport);return async(messages,tools,options={})=>{
  const counter=kind==='actor'?'actorAttempts':'judgeAttempts',calls=kind==='actor'?evidence.actorCalls:evidence.judgeCalls;
  if(evidence[counter]>=evidence.budget[kind])throw Object.assign(Error('Owned provider budget exhausted'),{code:'QUALIFICATION_BUDGET_EXHAUSTED'});
  evidence[counter]++;const row={attempt:evidence[counter],request:structuredClone({messages,tools}),status:'pending'};calls.push(row);save();
  try{const result=await original(messages,tools,{...options,signal:AbortSignal.any([...(options.signal?[options.signal]:[]),lifetime.signal,AbortSignal.timeout(60000)])});row.result=result;row.status='returned';assert.equal(result.provider,'ollama');assert.equal(result.model,'llama3.1:8b');assert.notEqual(result.mocked,true);assert.notEqual(result.fallback,true);return result;}
  catch(error){row.status='failed';row.error={code:error.code||null,name:error.name};throw error;}finally{save();}
 };};
 provider.transport.chat=instrument(provider.transport,'actor');
 const judgeTransport=createLangChainProvider({provider:'ollama',baseURL,model:'llama3.1:8b'});
 const actualJudge=createObjectiveJudge({model:{chat:instrument(judgeTransport,'judge')}});
 let injectInitialTransportFault=false;
 const initialJudge=async packet=>{if(injectInitialTransportFault){evidence.injectedTransportFaults++;save();throw Object.assign(Error('Controlled initial Judge transport failure before dispatch'),{code:'ECONNRESET'});}return actualJudge(packet);};
 const production=createSecureShopMcpTrustProduction({enabled:true,identityPool:identity,provider,judge:initialJudge,personaAuthority:authority,personaBindings:candidate,resetComposition:{mcpTrust:bundle,launches,conversationService:conversations,turns,conversations:conversationRows,journal}});
 const app=production.application,owners=[];
 const owner=async label=>{const value=await createOwner(label);owners.push(value);return value;};
 const objectiveId='ss_rogue_tool_selected';
 const request=value=>({scope:value.scope,persona:value.persona,personaSession:value.personaSession,trustScenario:'rogue_registration',requestId:randomUUID(),signal:lifetime.signal});
 const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity,{personaBindings:candidate});
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const makeRetry=judge=>require('../../server/services/objectiveRegradeService').createObjectiveRegradeService({receipts,
  completion:require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge}),
  coordinatorFactory:family=>require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family,ledger})});
 const rows=async value=>(await identity.query(`SELECT j.*,b.original_run_id,b.platform_session_id,b.persona_id,b.persona_session_id,b.persona_role,b.authority_version
 FROM workshop_platform.objective_judgments j JOIN workshop_platform.persona_evaluation_bindings b USING(user_id,evaluation_id)
 WHERE j.user_id=$1 AND j.objective_id=$2 ORDER BY j.created_at,j.evaluation_id`,[value.user.id,objectiveId])).rows;
 const completed=async value=>(await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND objective_id=$2',[value.user.id,objectiveId])).rows[0].n;
 const verifyBinding=(row,value)=>{assert.equal(row.persona_authority_required,true);assert.equal(row.platform_launch_id,value.scope.launchId);assert.equal(row.platform_scenario_id,value.scope.scenarioId);assert.equal(Number(row.platform_launch_generation),value.scope.generation);assert.equal(Number(row.platform_session_id),value.scope.platformSessionId);assert.equal(Number(row.persona_id),value.persona.id);assert.equal(row.persona_session_id,value.personaSession.sessionId);assert.equal(String(row.authority_version),value.personaSession.authorityVersion);assert.equal(row.persona_role,'admin');assert.equal(row.original_run_id,row.run_id);};
 const start=async(value,fault=false)=>{injectInitialTransportFault=fault;let result;try{result=await app.run(request(value));}finally{injectInitialTransportFault=false;}assert.equal(result.ok,true);const stored=await rows(value);assert.equal(stored.length,1,'Exactly one initial evaluation expected; no outcome search');const invocations=(await agents.query('SELECT i.* FROM secureshop_agents.bound_mcp_invocations i JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE t.original_platform_owner_id=$1 AND i.run_id=$2',[value.user.id,stored[0].run_id])).rows;assert.ok(invocations.length>0,'Actual owned SDK invocation must match initial evaluation run');evidence.cases.push({case:value.user.username,invocations});verifyBinding(stored[0],value);evidence.cases.push({case:value.user.username,initial:stored[0]});save();return stored[0];};
 try{
  const live=await owner('mcp-actual-initial'),initial=await start(live);assert.equal(initial.verdict,'pass');assert.equal(initial.result_json.provider,'ollama');assert.equal(initial.result_json.model,'llama3.1:8b');assert.equal(initial.result_json.judgeVersion,JUDGE_VERSION);assert.equal(await completed(live),1);
  const retryOwner=await owner('mcp-actual-retry'),original=await start(retryOwner,true);assert.equal(original.verdict,'unavailable');assert.equal(original.result_json.errorCode,'JUDGE_TRANSPORT');assert.equal(await completed(retryOwner),0);
  const retry=makeRetry(actualJudge),retried=await retry({userId:retryOwner.user.id,evaluationId:original.evaluation_id});assert.equal(retried.completed,true);assert.equal(retried.judgment.verdict,'pass');
  const pair=await rows(retryOwner);assert.equal(pair.length,2);pair.forEach(row=>verifyBinding(row,retryOwner));const child=pair.find(row=>row.evaluation_id!==original.evaluation_id);assert.equal(child.run_id,original.run_id);assert.notEqual(retried.retryRunId,original.run_id);assert.equal(pair.find(row=>row.evaluation_id===original.evaluation_id).verdict,'unavailable');assert.equal(child.result_json.provider,'ollama');assert.equal(await completed(retryOwner),1);
  const beforeReplay=[evidence.actorAttempts,evidence.judgeAttempts,evidence.remote.callTool];assert.equal((await retry({userId:retryOwner.user.id,evaluationId:original.evaluation_id})).replayed,true);assert.deepEqual([evidence.actorAttempts,evidence.judgeAttempts,evidence.remote.callTool],beforeReplay);evidence.cases.push({case:'original_scope_retry',child,retryRunId:retried.retryRunId});save();
  const revoked=await owner('mcp-actual-revoked'),revokedOriginal=await start(revoked,true);assert.equal(revokedOriginal.verdict,'unavailable');await personas.revokeOwnedSession({scope:revoked.scope,shopUserId:revoked.persona.id,sessionId:revoked.personaSession.sessionId});
  const before=[evidence.actorAttempts,evidence.judgeAttempts,evidence.remote.callTool];await assert.rejects(retry({userId:revoked.user.id,evaluationId:revokedOriginal.evaluation_id}),{code:'SHOP_AUTH_INVALID'});assert.deepEqual([evidence.actorAttempts,evidence.judgeAttempts,evidence.remote.callTool],before);assert.equal((await rows(revoked)).length,1);assert.equal(await completed(revoked),0);evidence.cases.push({case:'revoked_before_retry',newProviderCalls:0});save();
  const heldOwner=await owner('mcp-actual-held'),heldOriginal=await start(heldOwner,true);assert.equal(heldOriginal.verdict,'unavailable');
  const entered=Promise.withResolvers(),release=Promise.withResolvers();let heldResult,pending;
  const heldRetry=makeRetry(async packet=>{heldResult=await actualJudge(packet);evidence.heldJudgeResult=heldResult;save();entered.resolve();await release.promise;return heldResult;});
  let timer;
  try{pending=heldRetry({userId:heldOwner.user.id,evaluationId:heldOriginal.evaluation_id});pending.catch(()=>{});await Promise.race([entered.promise,pending.then(()=>{throw Error('Expected held Judge was not reached');}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Held Judge deadline')),180000);})]);
   assert.equal(await personas.revokeOwnedSession({scope:heldOwner.scope,shopUserId:heldOwner.persona.id,sessionId:heldOwner.personaSession.sessionId}),true);release.resolve();await assert.rejects(pending,{code:'SHOP_AUTH_INVALID'});
  }finally{clearTimeout(timer);release.resolve();if(pending)await pending.catch(()=>{});}
  const heldRows=await rows(heldOwner);assert.equal(heldRows.length,2);heldRows.forEach(row=>verifyBinding(row,heldOwner));assert.equal(heldRows.find(row=>row.evaluation_id!==heldOriginal.evaluation_id).verdict,null);assert.equal(await completed(heldOwner),0);assert.equal(heldResult.verdict,'pass','A passing actual result is required to qualify blocked-positive credit');evidence.cases.push({case:'held_actual_pass_revoked',credit:false});save();
  assert.equal((await app.status(request(live))).ready,true);assert.equal(await completed(live),1);
  for(const value of owners){const reset=await launches.beginReset({...value.scope,expectedGeneration:value.scope.generation,idempotencyKey:randomUUID()});const targets=await cleanupAuthority.listTargets(reset.resetId);for(const target of targets.targets){const receipt=await bundle.cleanup(target,{operationId:reset.resetId});assert.deepEqual(await bundle.readCleanupReceipt({...target,operationId:reset.resetId}),receipt);evidence.cleanup.push({targetId:target.targetId,retired:true});}}
  assert.equal(fs.readdirSync(fixtureRoot).length,0);evidence.status='passed';save();
 }catch(error){evidence.status='failed';evidence.failure={code:error.code||null,message:error.message};save();throw error;}
});
