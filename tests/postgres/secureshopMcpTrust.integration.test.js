'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs/promises');const path=require('node:path');
const os=require('node:os');const crypto=require('node:crypto');const bcrypt=require('bcryptjs');const {Pool}=require('pg');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {readMigrations,migrate}=require('../../db/postgres/migrate');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {initializeSecureShopAgentsDb}=require('../../server/database/postgres/secureshopAgentsDb');
const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');
const {createSecureShopResetCleanupAuthorityRepository}=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const {createSecureShopTargetReconciliationRepository}=require('../../server/database/postgres/secureshopTargetReconciliationRepository');
const {createSecureShopBoundMcpRepository}=require('../../server/database/postgres/secureshopBoundMcpRepository');
const {createSecureShopMcpTrustApplication}=require('../../server/services/secureshopMcpTrustApplication');
const {createSecureShopMcpTrustTools}=require('../../server/services/secureshopMcpTrustTools');
const {createSecureShopMcpControlledTargetPool}=require('../../server/services/secureshopMcpControlledTargetPool');
const {createSecureShopMcpTrustResetAdapter}=require('../../server/services/secureshopMcpTrustResetAdapter');
const {createSecureShopReviewResetCoordinator}=require('../../server/services/secureshopReviewResetCoordinator');
const {validateSecureShopMcpTrustQualifierSchema}=require('./secureshopMcpTrustQualifierSchema');
const PREFIX='PG_SECURESHOP_MCP_TRUST_';const KEYS=['IDENTITY_MIGRATION_URL','IDENTITY_RUNTIME_URL','AGENTS_MIGRATION_URL','AGENTS_RUNTIME_URL'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&KEYS.every(key=>process.env[PREFIX+key]);const uuid=crypto.randomUUID;
async function assertLedger(pool,directory){const expected=await readMigrations(directory),actual=(await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(actual,expected.map(row=>({name:row.name,checksum:row.checksum})));}
function checked(key){const value=new URL(process.env[PREFIX+key]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));assert.match(value.pathname,/^\/dvaia_test_[a-z0-9_]+$/);return value.href;}
test('launch-owned MCP targets preserve distinct trust lessons, runtime effects, reset replay and sibling isolation',{skip:!enabled,timeout:120000},async t=>{
  const workspaceInput=process.env.DVAIA_ISOLATED_TEST_WORKSPACE;assert.ok(workspaceInput,'DVAIA_ISOLATED_TEST_WORKSPACE is required');
  const workspace=await fs.realpath(workspaceInput);assert.equal(workspace,await fs.realpath(process.cwd()));assert.equal((await fs.stat(workspace)).isDirectory(),true);
  const identityMigration=new Pool({connectionString:checked('IDENTITY_MIGRATION_URL'),max:2});const identity=new Pool({connectionString:checked('IDENTITY_RUNTIME_URL'),max:8});
  const agentsMigration=new Pool({connectionString:checked('AGENTS_MIGRATION_URL'),max:2});const agents=new Pool({connectionString:checked('AGENTS_RUNTIME_URL'),max:8});
  const fixtureRoot=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-mcp-native-fixture-'));t.after(()=>fs.rm(fixtureRoot,{recursive:true,force:true}));
  try{await initializeIdentityRepository(identity,identityMigration);await seedWorkshopPlatform(identityMigration);
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
    const ledger={identity:Number((await identityMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
      agents:Number((await agentsMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n)};
    const migrationDirectories={identity:path.resolve(__dirname,'../../db/postgres/identity-migrations'),agents:path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents')};
    await Promise.all([assertLedger(identityMigration,migrationDirectories.identity),assertLedger(agentsMigration,migrationDirectories.agents)]);
    await Promise.all([assert.deepEqual(await migrate(identityMigration,migrationDirectories.identity),[]),assert.deepEqual(await migrate(agentsMigration,migrationDirectories.agents),[])]);
    assert.deepEqual((await identityMigration.query('SELECT name FROM dvaia_migrations.ledger WHERE name=ANY($1::text[]) ORDER BY name',
      [['0046_graph_judge_validation_code.sql','0051_secureshop_mcp_trust.sql','0061_mcp_supply_chain_curriculum_defaults.sql']])).rows.map(row=>row.name),
      ['0046_graph_judge_validation_code.sql','0051_secureshop_mcp_trust.sql','0061_mcp_supply_chain_curriculum_defaults.sql']);
    assert.deepEqual((await agentsMigration.query('SELECT name FROM dvaia_migrations.ledger WHERE name=ANY($1::text[]) ORDER BY name',
      [['0010_secureshop_persona_inbox.sql','0011_secureshop_mcp_trust.sql','0013_secureshop_conversation_purpose.sql']])).rows.map(row=>row.name),
      ['0010_secureshop_persona_inbox.sql','0011_secureshop_mcp_trust.sql','0013_secureshop_conversation_purpose.sql']);
    assert.deepEqual(await fs.readFile(path.join(workspace,'docs/modernization/drafts/secureshop-mcp-trust-identity.sql')),
      await fs.readFile(path.join(migrationDirectories.identity,'0051_secureshop_mcp_trust.sql')));
    assert.deepEqual(await fs.readFile(path.join(workspace,'docs/modernization/drafts/secureshop-mcp-trust-agents.sql')),
      await fs.readFile(path.join(migrationDirectories.agents,'0011_secureshop_mcp_trust.sql')));
    await validateSecureShopMcpTrustQualifierSchema({identityMigration,identity,agentsMigration,agents});
    assert.deepEqual({identity:Number((await identityMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
      agents:Number((await agentsMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n)},ledger);
    const identities=createIdentityRepository(identity);const launches=createSecureShopLaunchRepository(identity);const passwordHash=await bcrypt.hash('mcp-owned-test',4);
    async function owner(label){const user=await identities.createUser({username:`${label}-${uuid().slice(0,8)}`,email:`${uuid()}@mcp.invalid`,passwordHash});
      const session=await identities.createSession({userId:user.id,token:uuid(),expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});
      const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
      return{user,session,scope:Object.freeze({...issued.binding,platformOwnerId:user.id,platformSessionId:session.id})};}
    const primary=await owner('mcp-primary');const sibling=await owner('mcp-sibling');const cleanupAuthority=createSecureShopResetCleanupAuthorityRepository(identity);
    const rotations=new Set();const repository=createSecureShopBoundMcpRepository(agents,{checkCurrent:value=>launches.assertCurrent(value),
      checkRotation:async value=>{if(!rotations.has(value.targetId))throw new Error('rotation unavailable');},
      checkCleanup:input=>cleanupAuthority.checkTarget(input)});const targetPool=createSecureShopMcpControlledTargetPool({root:fixtureRoot});
    const configurations={rogue_registration:'secureshop-rogue-weather-lab',rug_pull:'secureshop-weather-lab'};const apps={};const tools={};
    for(const [trustScenario,serverIdentity] of Object.entries(configurations)){apps[trustScenario]=createSecureShopMcpTrustApplication({launches,repository,transport:targetPool,
      serverIdentity,trustScenario,endpoint:'owned-sdk://secureshop',authorizeRotation:async value=>{rotations.add(value.targetId);return()=>rotations.delete(value.targetId);}});
      tools[trustScenario]=createSecureShopMcpTrustTools({repository,transport:targetPool,serverIdentity,resolveTarget:apps[trustScenario].target,checkCurrent:value=>launches.assertCurrent(value)});}
    const schemas={},targets={};for(const scenario of Object.keys(configurations)){schemas[scenario]=await apps[scenario].initialize(primary.scope);
      targets[scenario]=await apps[scenario].target(primary.scope);assert.equal(targets[scenario].trustScenario,scenario);}
    const siblingSchema=await apps.rug_pull.initialize(sibling.scope),siblingTarget=await apps.rug_pull.target(sibling.scope);
    assert.equal(siblingSchema.serverIdentity,configurations.rug_pull);assert.equal(siblingTarget.trustScenario,'rug_pull');
    assert.notEqual(siblingTarget.targetId,targets.rug_pull.targetId);
    const execution=()=>Object.freeze({runId:uuid(),signal:new AbortController().signal,check(){}});
    const rogue=await tools.rogue_registration.call(primary.scope,{execution:execution(),requestId:uuid(),callId:'rogue-call',toolName:'forecast_lookup',args:{city:'Seattle'}});
    assert.equal(rogue.serverApproved,false);assert.equal(rogue.behaviorClass,'protected_record_export');
    const safe=await tools.rug_pull.call(primary.scope,{execution:execution(),requestId:uuid(),callId:'safe-call',toolName:'forecast_lookup',args:{city:'Seattle'}});
    assert.equal(safe.approved,true);assert.equal(safe.behaviorClass,'public_forecast_lookup');
    await apps.rug_pull.rotate(primary.scope);const pulled=await tools.rug_pull.call(primary.scope,{execution:execution(),requestId:uuid(),callId:'rug-call',toolName:'forecast_lookup',args:{city:'Seattle'}});
    assert.equal(pulled.serverApproved,true);assert.equal(pulled.schemaApproved,false);
    const preciseBaselineId=uuid(),preciseCurrentId=uuid(),lateInvocationId=uuid();
    await agents.query(`WITH source AS (
        SELECT * FROM secureshop_agents.bound_mcp_invocations WHERE invocation_id IN ($4,$5)
      ), anchor AS (
        SELECT date_trunc('second',max(completed_at))+interval '2 seconds 100 milliseconds' AS at FROM source
      ), copies(invocation_id,run_id,request_id,call_id,source_id,offset_value) AS (
        VALUES ($1::uuid,$6::uuid,$7::uuid,'precise-baseline',$4::uuid,interval '0.0001 second'),
          ($2::uuid,$8::uuid,$9::uuid,'precise-current',$5::uuid,interval '0.0008 second'),
          ($3::uuid,$10::uuid,$11::uuid,'late-prior',$4::uuid,interval '0.0009 second')
      ) INSERT INTO secureshop_agents.bound_mcp_invocations
      (invocation_id,operation_id,target_id,schema_version,schema_sha256,run_id,request_id,call_id,tool_name,arguments_sha256,
       remote_receipt_sha256,trust_policy_sha256,approved,server_approved,schema_approved,trust_scenario,behavior_class,result_sha256,completed_at)
      SELECT copies.invocation_id,copies.invocation_id,source.target_id,source.schema_version,source.schema_sha256,copies.run_id,
       copies.request_id,copies.call_id,source.tool_name,source.arguments_sha256,source.remote_receipt_sha256,
       source.trust_policy_sha256,source.approved,source.server_approved,source.schema_approved,source.trust_scenario,
       source.behavior_class,source.result_sha256,anchor.at+copies.offset_value
      FROM copies JOIN source ON source.invocation_id=copies.source_id CROSS JOIN anchor`,
    [preciseBaselineId,preciseCurrentId,lateInvocationId,safe.invocationId,pulled.invocationId,uuid(),uuid(),uuid(),uuid(),uuid(),uuid()]);
    const precisePrior=await repository.readPriorSchema(targets.rug_pull,{...pulled,invocationId:preciseCurrentId});
    assert.equal(precisePrior.behaviorClass,'public_forecast_lookup');
    assert.equal(precisePrior.invocationId,preciseBaselineId,
      'PostgreSQL microsecond ordering excludes a later old-schema invocation in the same JavaScript millisecond');
    const resetAdapter=createSecureShopMcpTrustResetAdapter({repository,targetPool,cleanupAuthority});
    const reconciler=createSecureShopTargetReconciliationRepository(identity,{checkAuthority:input=>cleanupAuthority.checkTarget(input),
      readCleanupReceipt:input=>resetAdapter.readCleanupReceipt(input)});
    const idempotencyKey=uuid();const reset=await launches.beginReset({launchId:primary.scope.launchId,
      platformSessionId:primary.scope.platformSessionId,platformOwnerId:primary.scope.platformOwnerId,
      expectedGeneration:1,idempotencyKey});const operation=await cleanupAuthority.listTargets(reset.resetId);
    assert.equal(operation.targets.length,2);const reconciled=[];
    for(const item of operation.targets){await resetAdapter.cleanup(item,{operationId:reset.resetId});
      reconciled.push(await reconciler.reconcile(item,{operationId:reset.resetId}));}
    await cleanupAuthority.assertResolved(reset.resetId);
    await cleanupAuthority.finalizeReconciliation(reset.resetId,reconciled.map(item=>item.history));
    const replay=await launches.beginReset({launchId:primary.scope.launchId,platformSessionId:primary.scope.platformSessionId,
      platformOwnerId:primary.scope.platformOwnerId,expectedGeneration:1,idempotencyKey});assert.equal(replay.resetId,reset.resetId);
    for(const item of operation.targets){const receipt=await resetAdapter.cleanup(item,{operationId:reset.resetId});
      assert.equal(receipt.operationId,reset.resetId);}
    const cleanupReceipts=(await agents.query(`SELECT operation_id,target_id FROM secureshop_agents.bound_mcp_cleanup_receipts
      WHERE operation_id=$1 ORDER BY target_id`,[reset.resetId])).rows;
    assert.deepEqual(cleanupReceipts.map(row=>row.target_id).sort(),[targets.rogue_registration.targetId,targets.rug_pull.targetId].sort());
    const retireSql='SELECT * FROM secureshop_agents.retire_bound_mcp_target($1,$2,$3,$4,$5,$6,$7,$8)';
    const retire=(operation,target,scope,receipt=Buffer.alloc(32,7))=>agents.query(retireSql,[operation,target.targetId,scope.launchId,
      scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,receipt]);
    await assert.rejects(retire(reset.resetId,targets.rogue_registration,primary.scope,Buffer.alloc(32,8)),error=>error.code==='55000');
    await assert.rejects(retire(uuid(),targets.rogue_registration,primary.scope),error=>error.code==='55000');
    await assert.rejects(retire(reset.resetId,targets.rogue_registration,sibling.scope),error=>error.code==='55000');
    await assert.rejects(retire(reset.resetId,siblingTarget,sibling.scope),error=>error.code==='55000');
    assert.equal((await identity.query('SELECT count(*)::int AS n FROM identity.secureshop_target_reservations WHERE launch_id=$1',[primary.scope.launchId])).rows[0].n,0);
    assert.equal((await identity.query('SELECT count(*)::int AS n FROM identity.secureshop_target_reservations WHERE launch_id=$1',[sibling.scope.launchId])).rows[0].n,1);
    assert.equal((await agents.query("SELECT count(*)::int AS n FROM secureshop_agents.bound_mcp_targets WHERE lifecycle='retired'")).rows[0].n,2);
    assert.equal((await agents.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_mcp_invocations')).rows[0].n,6);
    assert.equal((await agents.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_mcp_cleanup_receipts')).rows[0].n,2);
  }finally{await Promise.allSettled([identity.end(),identityMigration.end(),agents.end(),agentsMigration.end()]);}
});
