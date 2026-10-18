'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const path=require('node:path');
const fs=require('node:fs/promises');const os=require('node:os');const crypto=require('node:crypto');const bcrypt=require('bcryptjs');
const express=require('express');const {Pool}=require('pg');const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {seedSecureShop}=require('../../server/database/postgres/secureshopSeed');
const {createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
const {createLangChainProvider}=require('../../server/agent-runtime/providers/langchainProvider');
const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
const {createSecureShopCleanupComposition}=require('../../server/services/secureshopCleanupComposition');
const {createSecureShopBoundReviewComposition}=require('../../server/services/secureshopBoundReviewComposition');
const {createSecureShopMcpTrustAvailability}=require('../../server/services/secureshopMcpTrustAvailability');
const {assertSecureShopMcpTrustReadiness,createSecureShopMcpTrustRepositoryBundle}=require('../../server/services/secureshopMcpTrustProduction');
const {createSecureShopBoundGateway}=require('../../server/routes/secureshop/boundGateway');
const {PRIMARY_TRACE_SQL,EFFECT_STATUS_SQL,findPacketInvocation}=require('./secureshopMcpTrustQualifierSchema');
const {createMcpJudgeInputCapture}=require('./mcpJudgeInputCapture');

const PREFIX='PG_SECURESHOP_MCP_TRUST_AUTH_',STORES=['IDENTITY','AGENTS','REVIEW','COMMERCE'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.LIVE_OLLAMA_TEST==='1'
  &&STORES.every(store=>['MIGRATION','RUNTIME'].every(role=>process.env[`${PREFIX}${store}_${role}_URL`]));
const WORKSHOP='secureshop_agent_security',OBJECTIVES=['ss_rogue_tool_selected','ss_rug_pull_invoked'];
function checked(name){const value=new URL(process.env[`${PREFIX}${name}_URL`]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));
  assert.match(value.pathname,/^\/dvaia_test_[a-z0-9_]+$/);return value.href;}
async function json(response,status=200){assert.equal(response.status,status);return response.json();}
const parse=value=>{if(value&&typeof value==='object')return value;try{return JSON.parse(value);}catch{return null;}};
async function assertLedger(pool,directory){const expected=await readMigrations(directory),actual=(await pool.query(
  'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(actual,
  expected.map(row=>({name:row.name,checksum:row.checksum})));}

test('mounted MCP trust binds real launch and admin JWT to SDK actor/Judge, replay, restart and reset',
  {skip:!enabled,timeout:360000},async t=>{
  const workspace=path.resolve(process.env.DVAIA_ISOLATED_TEST_WORKSPACE||'');
  assert.match(path.basename(path.dirname(workspace)),/^dvaia-secureshop-mcp-trust-auth-/);
  const pools=Object.fromEntries(STORES.flatMap(store=>['MIGRATION','RUNTIME'].map(role=>[`${store}_${role}`,
    new Pool({connectionString:checked(`${store}_${role}`),max:store==='IDENTITY'&&role==='RUNTIME'?14:6})])));
  const leases=new Pool({connectionString:checked('IDENTITY_RUNTIME'),max:4,application_name:'mcp-trust-auth-lease'});
  const fixtureRoot=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-mcp-trust-auth-fixture-'));
  const semantic=[],requests=[],scopes=[],judgeInputs=[];let server,composition,resetComposition,judgeCalls=0,primaryError;
  const verify=(label,callback)=>{try{callback();}catch(error){semantic.push({label,message:error.message});}};
  const stop=async()=>{const failures=[];if(server){const current=server;server=null;try{await new Promise((resolve,reject)=>current.close(error=>error?reject(error):resolve()));}catch(error){failures.push(error);}}
    if(composition)try{await composition.closeBrowserAssessment();}catch(error){failures.push(error);}
    if(resetComposition)try{await resetComposition.closeFeatureTransports();}catch(error){failures.push(error);}
    composition=null;resetComposition=null;if(failures.length)throw new AggregateError(failures,'Mounted MCP trust transport shutdown failed');};
  try{
    await migrate(pools.IDENTITY_MIGRATION,path.join(workspace,'db/postgres/identity-migrations'));
    await migrate(pools.AGENTS_MIGRATION,path.join(workspace,'db/postgres/workshop-migrations/secureshop_agents'));
    await migrate(pools.REVIEW_MIGRATION,path.join(workspace,'db/postgres/workshop-migrations/secureshop_review'));
    await migrate(pools.COMMERCE_MIGRATION,path.join(workspace,'db/postgres/workshop-migrations/secureshop'));
    const migrationDirectories={
      IDENTITY:path.join(workspace,'db/postgres/identity-migrations'),
      AGENTS:path.join(workspace,'db/postgres/workshop-migrations/secureshop_agents'),
      REVIEW:path.join(workspace,'db/postgres/workshop-migrations/secureshop_review'),
      COMMERCE:path.join(workspace,'db/postgres/workshop-migrations/secureshop')};
    await Promise.all([
      assertLedger(pools.IDENTITY_MIGRATION,migrationDirectories.IDENTITY),
      assertLedger(pools.AGENTS_MIGRATION,migrationDirectories.AGENTS),
      assertLedger(pools.REVIEW_MIGRATION,migrationDirectories.REVIEW),
      assertLedger(pools.COMMERCE_MIGRATION,migrationDirectories.COMMERCE)]);
    await Promise.all([
      assert.deepEqual(await migrate(pools.IDENTITY_MIGRATION,migrationDirectories.IDENTITY),[]),
      assert.deepEqual(await migrate(pools.AGENTS_MIGRATION,migrationDirectories.AGENTS),[]),
      assert.deepEqual(await migrate(pools.REVIEW_MIGRATION,migrationDirectories.REVIEW),[]),
      assert.deepEqual(await migrate(pools.COMMERCE_MIGRATION,migrationDirectories.COMMERCE),[])]);
    await seedWorkshopPlatform(pools.IDENTITY_MIGRATION);await pools.COMMERCE_MIGRATION.query('BEGIN');
    try{await seedSecureShop(pools.COMMERCE_MIGRATION);await pools.COMMERCE_MIGRATION.query('COMMIT');}
    catch(error){await pools.COMMERCE_MIGRATION.query('ROLLBACK');throw error;}
    assert.deepEqual((await pools.IDENTITY_MIGRATION.query(
      'SELECT name FROM dvaia_migrations.ledger WHERE name=ANY($1::text[]) ORDER BY name',
      [['0046_graph_judge_validation_code.sql','0051_secureshop_mcp_trust.sql','0061_mcp_supply_chain_curriculum_defaults.sql']])).rows.map(row=>row.name),
      ['0046_graph_judge_validation_code.sql','0051_secureshop_mcp_trust.sql','0061_mcp_supply_chain_curriculum_defaults.sql']);
    assert.deepEqual((await pools.AGENTS_MIGRATION.query(
      'SELECT name FROM dvaia_migrations.ledger WHERE name=ANY($1::text[]) ORDER BY name',
      [['0010_secureshop_persona_inbox.sql','0013_secureshop_conversation_purpose.sql']])).rows.map(row=>row.name),
      ['0010_secureshop_persona_inbox.sql','0013_secureshop_conversation_purpose.sql']);
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key=$1`,[WORKSHOP]);
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true
      WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,[WORKSHOP,OBJECTIVES]);
    assert.equal(await assertSecureShopMcpTrustReadiness({identityPool:pools.IDENTITY_RUNTIME,agentsPool:pools.AGENTS_RUNTIME}),true);
    const model='llama3.1:8b',baseURL=process.env.OLLAMA_BASE_URL||'http://127.0.0.1:11434';
    const actor=new OllamaProvider({baseUrl:baseURL,model});const actualJudge=createObjectiveJudge({model:createLangChainProvider({provider:'ollama',baseURL,model})});
    const capturedJudge=createMcpJudgeInputCapture({judge:actualJudge,entries:judgeInputs});
    const judge=async packet=>{judgeCalls++;return capturedJudge.judge(packet);};
    const browserQualification=Object.freeze({async qualify(){throw new Error('unexpected browser call');},async close(){}});
    const renderer=Object.freeze({sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),async renderReviewCard(review){return`<article>${review.body}</article>`;}});
    async function build(){const availability=createSecureShopMcpTrustAvailability(pools.IDENTITY_RUNTIME);
      resetComposition=createSecureShopCleanupComposition({identityPool:pools.IDENTITY_RUNTIME,agentsPool:pools.AGENTS_RUNTIME,
        reviewPool:pools.REVIEW_RUNTIME,leasePool:leases,mcpTrustFixtureRoot:fixtureRoot,
        mcpTrustFactory:input=>createSecureShopMcpTrustRepositoryBundle({...input,availability})});
      composition=createSecureShopBoundReviewComposition({identityPool:pools.IDENTITY_RUNTIME,agentsPool:pools.AGENTS_RUNTIME,
        reviewPool:pools.REVIEW_RUNTIME,commercePool:pools.COMMERCE_RUNTIME,resetComposition,
        agentRuntime:Object.freeze({provider:actor}),jwtSecret:'owned-mcp-trust-auth-secret-at-least-32-bytes',
        mcpTrustFeature:true,judge,reviewCardRenderer:renderer,browserQualification});
      assert.equal(composition.mcpTrust.ready,true);const app=express();app.use(express.json());
      app.use('/api/secureshop',createSecureShopBoundGateway({launches:composition.launches,
        authenticatePersona:composition.personaAuth.authenticatePersona,personaAuth:composition.personaAuth,
        reviewsRouter:composition.router,browserRouter:composition.browserRouter,mcpTrustRouter:composition.mcpTrust.router,
        catalog:composition.catalog,commerce:composition.commerce,account:composition.account}));
      server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
      return`http://127.0.0.1:${server.address().port}/api/secureshop`;}
    const identities=createIdentityRepository(pools.IDENTITY_RUNTIME),passwordHash=await bcrypt.hash('mcp-auth-platform',4),expiresAt=new Date(Date.now()+3600000).toISOString();
    async function owner(label){const user=await identities.createUser({username:`${label}-${crypto.randomUUID().slice(0,8)}`,
      email:`${crypto.randomUUID()}@mcp-auth.invalid`,passwordHash});const session=await identities.createSession({userId:user.id,token:crypto.randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
      const launch=await (composition||resetComposition).launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});
      await pools.IDENTITY_RUNTIME.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,$2,'vuln') ON CONFLICT DO NOTHING`,[user.id,WORKSHOP]);
      return{user,session,launch};}
    let base=await build();const primary=await owner('mcp-auth-primary'),sibling=await owner('mcp-auth-sibling');scopes.push(primary,sibling);
    async function login(owner){const launch={'x-dvaia-secureshop-launch':owner.launch.bearer};const value=await json(await fetch(`${base}/v2/auth/login`,{method:'POST',headers:{...launch,'content-type':'application/json'},
        body:JSON.stringify({username:'student_admin',password:'student123'})}));assert.equal(value.user.role,'admin');return{...launch,authorization:`Bearer ${value.token}`,'content-type':'application/json'};}
    let headers=await login(primary),siblingHeaders=await login(sibling);
    const readiness=await json(await fetch(`${base}/v2/mcp-trust/readiness`,{headers}));assert.deepEqual(readiness,{ready:true,scenarios:{rogue_registration:true,rug_pull:true}});
    const discover=async(h,scenario)=>json(await fetch(`${base}/v2/mcp-trust/discover`,{method:'POST',headers:h,body:JSON.stringify({scenario})}));
    const run=async(h,scenario,requestId)=>json(await fetch(`${base}/v2/mcp-trust/run`,{method:'POST',headers:h,body:JSON.stringify({scenario,request_id:requestId})}));
    const rugV1=await discover(headers,'rug_pull'),rogueV1=await discover(headers,'rogue_registration');assert.equal(rugV1.schemaVersion,1);assert.equal(rogueV1.schemaVersion,1);
    const siblingSchema=await discover(siblingHeaders,'rogue_registration');assert.equal(siblingSchema.schemaVersion,1);
    const baselineRequest=crypto.randomUUID();requests.push(baselineRequest);const baseline=await run(headers,'rug_pull',baselineRequest);
    verify('approved baseline terminal',()=>assert.equal(baseline.stopReason,'end_turn'));
    verify('approved baseline no credit',()=>assert.equal(baseline.ok,true));
    const beforeReplayCredit=(await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int n FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2`,[primary.user.id,primary.launch.binding.launchId])).rows[0].n;
    verify('approved baseline does not award attack credit',()=>assert.equal(beforeReplayCredit,0));
    const rogueRequest=crypto.randomUUID();requests.push(rogueRequest);const rogue=await run(headers,'rogue_registration',rogueRequest);
    verify('rogue terminal',()=>assert.equal(rogue.stopReason,'end_turn'));
    const rotated=await json(await fetch(`${base}/v2/mcp-trust/rotate`,{method:'POST',headers,body:'{}'}));
    assert.equal(rotated.schemaVersion,2);assert.notEqual(rotated.schemaSha256,rugV1.schemaSha256);
    await stop();base=await build();headers=await login(primary);siblingHeaders=await login(sibling);
    const rehydrated=await discover(headers,'rug_pull');assert.equal(rehydrated.schemaVersion,2);assert.equal(rehydrated.schemaSha256,rotated.schemaSha256);
    const rugRequest=crypto.randomUUID();requests.push(rugRequest);const changed=await run(headers,'rug_pull',rugRequest);
    verify('changed-schema terminal',()=>assert.equal(changed.stopReason,'end_turn'));
    const counts=async()=>{const [identity,agents]=await Promise.all([
      pools.IDENTITY_RUNTIME.query(`SELECT (SELECT count(*)::int FROM graph_runtime.runs) runs,
        (SELECT count(*)::int FROM graph_runtime.effects) effects,(SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$1) judgments,
        (SELECT count(*)::int FROM workshop_platform.objective_contributions WHERE user_id=$1) contributions`,[primary.user.id]),
      pools.AGENTS_RUNTIME.query(`SELECT (SELECT count(*)::int FROM secureshop_agents.bound_mcp_invocations) invocations,
        (SELECT count(*)::int FROM secureshop_agents.agent_trace) traces`) ]);return{...identity.rows[0],...agents.rows[0],judgeCalls};};
    const beforeReplay=await counts(),replay=await run(headers,'rug_pull',rugRequest);assert.equal(replay.replayed,true);assert.deepEqual(await counts(),beforeReplay);
    const targets=(await pools.AGENTS_RUNTIME.query(`SELECT target_id,launch_id,scenario_id,generation,original_platform_owner_id,
      original_platform_session_id,server_identity,trust_scenario,lifecycle,current_schema_version FROM secureshop_agents.bound_mcp_targets
      WHERE launch_id=$1 ORDER BY trust_scenario`,[primary.launch.binding.launchId])).rows;assert.deepEqual(targets.map(row=>row.trust_scenario),['rogue_registration','rug_pull']);
    assert.equal(Number(targets.find(row=>row.trust_scenario==='rug_pull').current_schema_version),2);
    const invocations=(await pools.AGENTS_RUNTIME.query(`SELECT i.invocation_id,i.operation_id,i.target_id,i.run_id,i.request_id,i.call_id,i.trust_scenario,i.schema_version,
        i.behavior_class,i.server_approved,i.schema_approved,encode(i.remote_receipt_sha256,'hex') remote_receipt_sha256,
        encode(i.result_sha256,'hex') result_sha256,t.server_identity
      FROM secureshop_agents.bound_mcp_invocations i JOIN secureshop_agents.bound_mcp_targets t USING(target_id)
      WHERE t.launch_id=$1 ORDER BY i.completed_at,i.invocation_id`,[primary.launch.binding.launchId])).rows;
    verify('approved baseline behavior',()=>assert.ok(invocations.some(row=>row.request_id===baselineRequest&&row.schema_version===1&&row.behavior_class==='public_forecast_lookup')));
    verify('rogue protected behavior',()=>assert.ok(invocations.some(row=>row.request_id===rogueRequest&&row.trust_scenario==='rogue_registration'&&row.server_approved===false&&row.behavior_class==='protected_record_export')));
    verify('rug protected behavior',()=>assert.ok(invocations.some(row=>row.request_id===rugRequest&&row.trust_scenario==='rug_pull'&&row.schema_version===2&&row.schema_approved===false&&row.behavior_class==='protected_record_export')));
    for(const row of invocations){verify(`invocation ${row.invocation_id} exact receipts`,()=>{assert.match(row.run_id,/^[0-9a-f-]{36}$/i);assert.ok(requests.includes(row.request_id));
      assert.match(row.call_id,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);assert.match(row.remote_receipt_sha256,/^[0-9a-f]{64}$/);assert.match(row.result_sha256,/^[0-9a-f]{64}$/);});}
    const primaryConversationRows=(await pools.AGENTS_RUNTIME.query(`SELECT id,conversation_purpose,messages_json
      FROM secureshop_agents.agent_sessions WHERE authority_mode='launch_bound' AND platform_launch_id=$1
      ORDER BY conversation_purpose`,[primary.launch.binding.launchId])).rows;
    verify('rogue and rug use distinct durable histories',()=>{
      assert.deepEqual(primaryConversationRows.map(row=>row.conversation_purpose),['mcp_rogue_registration','mcp_rug_pull']);
      const rogueHistory=primaryConversationRows.find(row=>row.conversation_purpose==='mcp_rogue_registration').messages_json;
      const rugHistory=primaryConversationRows.find(row=>row.conversation_purpose==='mcp_rug_pull').messages_json;
      assert.match(rogueHistory,new RegExp(rogueRequest));assert.doesNotMatch(rogueHistory,new RegExp(rugRequest));
      assert.match(rugHistory,new RegExp(baselineRequest));assert.match(rugHistory,new RegExp(rugRequest));
      assert.doesNotMatch(rugHistory,new RegExp(rogueRequest));});
    const primarySessions=primaryConversationRows.map(row=>row.id);
    const traces=(await pools.AGENTS_RUNTIME.query(PRIMARY_TRACE_SQL,[primarySessions])).rows;
    const effects=new Map((await pools.IDENTITY_RUNTIME.query(EFFECT_STATUS_SQL,
      [requests.map(requestId=>`${requestId}:%`)])).rows.map(row=>[row.effect_key,row.status]));
    for(const row of invocations){const selected=traces.find(trace=>trace.kind==='model_decision'&&trace.provider==='ollama'
        &&parse(trace.params_json)?.toolCalls?.some(call=>call.id===row.call_id&&call.name===`${row.server_identity}.forecast_lookup`));
      verify(`invocation ${row.invocation_id} selected by actual actor`,()=>assert.ok(selected));if(!selected)continue;
      verify(`invocation ${row.invocation_id} observed by actual actor`,()=>assert.ok(traces.some(trace=>trace.kind==='mcp_result'
        &&trace.step===selected.step&&trace.agent_ns===row.server_identity&&trace.tool_name==='forecast_lookup')));
      const effectKey=`${row.request_id}:${JSON.stringify([selected.step,row.call_id,`${row.server_identity}.forecast_lookup`])}`;
      verify(`invocation ${row.invocation_id} has completed canonical effect`,()=>assert.equal(effects.get(effectKey),'completed'));}
    const schemaHistory=(await pools.AGENTS_RUNTIME.query(`SELECT v.target_id,v.version,encode(v.schema_sha256,'hex') schema_sha256
      FROM secureshop_agents.bound_mcp_schema_versions v JOIN secureshop_agents.bound_mcp_targets t USING(target_id)
      WHERE t.launch_id=$1 ORDER BY t.trust_scenario,v.version`,[primary.launch.binding.launchId])).rows;
    verify('restart retained exact schema history without duplicate discovery',()=>assert.deepEqual(schemaHistory.map(row=>({scenario:
      targets.find(target=>target.target_id===row.target_id)?.trust_scenario,version:Number(row.version)})),[
      {scenario:'rogue_registration',version:1},{scenario:'rug_pull',version:1},{scenario:'rug_pull',version:2}]));
    const judgments=(await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,run_id,verdict,result_json FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND objective_id=ANY($2::text[]) ORDER BY created_at`,[primary.user.id,OBJECTIVES])).rows;
    const contributions=(await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,platform_launch_generation FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 ORDER BY objective_id`,[primary.user.id,primary.launch.binding.launchId])).rows;
    verify('two independent Judge passes',()=>{for(const objective of OBJECTIVES){const accepted=judgments.find(row=>row.objective_id===objective&&row.verdict==='pass');
      assert.ok(accepted,objective);assert.equal(accepted.result_json.provider,'ollama');assert.equal(accepted.result_json.model,model);}assert.ok(judgeCalls>=2);});
    verify('persisted Judge results retain observable explanations',()=>{assert.ok(judgments.length>=2);
      for(const row of judgments)assert.ok(typeof row.result_json.explanation==='string'&&row.result_json.explanation.trim().length>0,row.objective_id);});
    verify('two exact canonical contributions',()=>assert.deepEqual(contributions.map(row=>row.objective_id),[...OBJECTIVES].sort()));
    for(const row of contributions){const packet=JSON.parse((await pools.IDENTITY_RUNTIME.query(`SELECT packet FROM workshop_platform.grade_packets
        WHERE user_id=$1 AND evaluation_id=$2`,[primary.user.id,row.evaluation_id])).rows[0].packet);
      const evidence=packet.evidence.find(value=>value.id==='bound_mcp_invocation_chain')?.content;verify(`${row.objective_id} packet linkage`,()=>{
        assert.ok(evidence);assert.ok(findPacketInvocation(evidence,invocations));
        assert.match(evidence.remoteReceiptSha256,/^[0-9a-f]{64}$/);assert.match(evidence.resultSha256,/^[0-9a-f]{64}$/);});}
    const primaryFixturePaths=targets.map(row=>path.join(fixtureRoot,row.target_id,'private-forecast.json'));
    for(const file of primaryFixturePaths)assert.equal((await fs.stat(file)).isFile(),true);
    const beforeHidden=await counts();await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET is_enabled=false
      WHERE workshop_key=$1 AND objective_id=$2`,[WORKSHOP,OBJECTIVES[0]]);
    assert.equal((await fetch(`${base}/v2/mcp-trust/run`,{method:'POST',headers,body:JSON.stringify({scenario:'rogue_registration',request_id:crypto.randomUUID()})})).status,503);
    assert.deepEqual(await counts(),beforeHidden);await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,[WORKSHOP,OBJECTIVES[0]]);
    await pools.IDENTITY_MIGRATION.query('UPDATE workshop_platform.exercises SET is_visible=false WHERE workshop_key=$1',[WORKSHOP]);
    const hiddenReadiness=await json(await fetch(`${base}/v2/mcp-trust/readiness`,{headers}));
    assert.equal(hiddenReadiness.ready,false);assert.deepEqual(hiddenReadiness.scenarios,{rogue_registration:true,rug_pull:true});
    assert.equal((await fetch(`${base}/v2/mcp-trust/run`,{method:'POST',headers,
      body:JSON.stringify({scenario:'rug_pull',request_id:crypto.randomUUID()})})).status,503);
    assert.deepEqual(await counts(),beforeHidden);
    await pools.IDENTITY_MIGRATION.query('UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key=$1',[WORKSHOP]);
    const resetKey=`mcp-auth-${crypto.randomUUID()}`;const reset=await composition.launchResetCoordinator.reset({launchId:primary.launch.binding.launchId,platformOwnerId:primary.user.id,
      platformSessionId:primary.session.id,expectedGeneration:primary.launch.binding.generation,idempotencyKey:resetKey});
    assert.equal(reset.status,'committed');assert.equal(reset.targets,2);
    const replayReset=await composition.launchResetCoordinator.reset({launchId:primary.launch.binding.launchId,platformOwnerId:primary.user.id,
      platformSessionId:primary.session.id,expectedGeneration:primary.launch.binding.generation,idempotencyKey:resetKey});
    assert.equal(replayReset.status,'committed');assert.equal(replayReset.resetId,reset.resetId);
    assert.deepEqual((await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,platform_launch_generation FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=1 ORDER BY objective_id`,[primary.user.id,primary.launch.binding.launchId])).rows,contributions);
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int n FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=2`,[primary.user.id,primary.launch.binding.launchId])).rows[0].n,0);
    const cleanup=(await pools.IDENTITY_RUNTIME.query(`SELECT target_kind,count(*)::int n FROM identity.secureshop_target_cleanup_history
      WHERE launch_id=$1 GROUP BY target_kind ORDER BY target_kind`,[primary.launch.binding.launchId])).rows;
    assert.deepEqual(cleanup,[{target_kind:'mcp_rogue',n:1},{target_kind:'mcp_rug_pull',n:1}]);
    const cleanupReceipts=(await pools.AGENTS_RUNTIME.query(`SELECT c.target_id,c.deleted_payload_count,c.retained_invocation_count,
      encode(c.receipt_sha256,'hex') receipt_sha256 FROM secureshop_agents.bound_mcp_cleanup_receipts c
      JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE t.launch_id=$1 ORDER BY c.target_id`,
    [primary.launch.binding.launchId])).rows;
    assert.equal(cleanupReceipts.length,2);assert.equal(cleanupReceipts.reduce((sum,row)=>sum+Number(row.retained_invocation_count),0),invocations.length);
    assert.ok(cleanupReceipts.every(row=>Number(row.deleted_payload_count)>0&&/^[0-9a-f]{64}$/.test(row.receipt_sha256)));
    for(const file of primaryFixturePaths)await assert.rejects(fs.stat(file),{code:'ENOENT'});
    assert.equal((await fetch(`${base}/v2/mcp-trust/readiness`,{headers})).status,401);
    assert.equal((await json(await fetch(`${base}/v2/mcp-trust/readiness`,{headers:siblingHeaders}))).ready,true);
    assert.equal((await discover(siblingHeaders,'rogue_registration')).schemaSha256,siblingSchema.schemaSha256);
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int n FROM workshop_platform.objective_contributions WHERE user_id=$1`,[sibling.user.id])).rows[0].n,0);
    t.diagnostic(JSON.stringify({checkpoint:'mcp-trust-auth-mounted',requests,invocations:invocations.map(row=>({invocationId:row.invocation_id,
      requestId:row.request_id,scenario:row.trust_scenario,version:row.schema_version,behavior:row.behavior_class,receipt:row.remote_receipt_sha256})),
      judgments:judgments.map(row=>({objectiveId:row.objective_id,runId:row.run_id,verdict:row.verdict,provider:row.result_json.provider,model:row.result_json.model,
        explanation:String(row.result_json.explanation||'').slice(0,600),criteria:row.result_json.criteria})),
      traces:traces.length,effects:effects.size,schemaHistory:schemaHistory.length,cleanupReceipts:cleanupReceipts.length,
      resetId:reset.resetId,siblingLaunch:sibling.launch.binding.launchId,semantic}));
    if(semantic.length)throw new AggregateError(semantic.map(row=>new Error(`${row.label}: ${row.message}`)),'Mounted MCP trust semantic gate failed');
  }catch(error){const diagnostic={checkpoint:'mcp-trust-auth-failure',error:{name:error.name,code:error.code||null,message:String(error.message).slice(0,320)},requests,semantic};
    try{diagnostic.judgments=(await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,run_id,verdict,disposition,result_json FROM workshop_platform.objective_judgments
      WHERE objective_id=ANY($1::text[]) ORDER BY created_at LIMIT 16`,[OBJECTIVES])).rows;}catch{}
    try{diagnostic.invocations=(await pools.AGENTS_RUNTIME.query(`SELECT invocation_id,target_id,run_id,request_id,call_id,trust_scenario,schema_version,behavior_class
      FROM secureshop_agents.bound_mcp_invocations ORDER BY completed_at,invocation_id LIMIT 32`)).rows;}catch{}
    try{diagnostic.traces=(await pools.AGENTS_RUNTIME.query(`SELECT id,session_id,kind,step,agent_ns,tool_name,provider FROM secureshop_agents.agent_trace ORDER BY id LIMIT 128`)).rows;}catch{}
    t.diagnostic(JSON.stringify(diagnostic));primaryError=error;
  }finally{const teardown=[];
    try{await fs.writeFile(path.join(path.dirname(workspace),'judge-inputs.json'),JSON.stringify(judgeInputs,null,2),{mode:0o600});}catch(error){teardown.push(error);}
    try{await stop();}catch(error){teardown.push(error);}
    const poolResults=await Promise.allSettled([leases.end(),...Object.values(pools).map(pool=>pool.end())]);
    teardown.push(...poolResults.filter(row=>row.status==='rejected').map(row=>row.reason));
    let fixtureAbsent=false;try{await fs.rm(fixtureRoot,{recursive:true,force:true});
      try{await fs.stat(fixtureRoot);throw new Error('Owned MCP trust fixture root remains after cleanup');}catch(error){if(error.code==='ENOENT')fixtureAbsent=true;else throw error;}}
    catch(error){teardown.push(error);}
    t.diagnostic(JSON.stringify({checkpoint:'mcp-trust-auth-owned-cleanup',fixtureRoot,fixtureAbsent,errors:teardown.map(error=>error.code||error.name)}));
    if(primaryError&&teardown.length)throw new AggregateError([primaryError,...teardown],'Mounted MCP trust gate and teardown failed');
    if(primaryError)throw primaryError;if(teardown.length)throw new AggregateError(teardown,'Mounted MCP trust teardown failed');}
});
