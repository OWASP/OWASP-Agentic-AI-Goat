'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const crypto=require('node:crypto');
const {Module,createRequire}=require('node:module');const {migrate}=require('../../db/postgres/migrate');
const fs=require('node:fs/promises');const os=require('node:os');const path=require('node:path');const bcrypt=require('bcryptjs');const {Pool}=require('pg');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {initializeSecureShopAgentsDb}=require('../../server/database/postgres/secureshopAgentsDb');
const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');
const {createSecureShopResetCleanupAuthorityRepository}=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const {createSecureShopTargetReconciliationRepository}=require('../../server/database/postgres/secureshopTargetReconciliationRepository');
const {createSecureShopBoundSsrfRepository}=require('../../server/database/postgres/secureshopBoundSsrfRepository');
const {createSecureShopSsrfTargetPool}=require('../../server/services/secureshopSsrfTargetPool');
const {createSecureShopSsrfExternalAdapter,SSRF_EGRESS_POLICY_SHA256}=require('../../server/services/secureshopSsrfExternalAdapter');
const {createSecureShopSsrfResetAdapter}=require('../../server/services/secureshopSsrfResetAdapter');
const {POLICY_SHA256:HTML_POLICY_SHA256}=require('../../server/services/secureshopPolicyFinalHtmlContract');
const POLICY_HTML='<section data-native-policy="owned"><p>Returns accepted within 30 days.</p></section>\n';
function migratorThrough(directory,ceiling){
 const filename=require.resolve('../../db/postgres/migrate'),local=createRequire(filename),original=require('node:fs/promises');
 const virtual={...original,async readdir(target,...args){const names=await original.readdir(target,...args);
  return path.resolve(target)===directory?names.filter(name=>!/^\d{4}_[a-z0-9_]+\.sql$/.test(name)||Number(name.slice(0,4))<=ceiling):names;}};
 const loaded=new Module(filename,module);loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?virtual:local(name);
 loaded._compile(require('node:fs').readFileSync(filename,'utf8'),filename);return loaded.exports.migrate;
}
const PREFIX='PG_SECURESHOP_SSRF_';const KEYS=['IDENTITY_MIGRATION_URL','IDENTITY_RUNTIME_URL','AGENTS_MIGRATION_URL','AGENTS_RUNTIME_URL'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&KEYS.every(key=>process.env[PREFIX+key]);const uuid=crypto.randomUUID;
function checked(key){const value=new URL(process.env[PREFIX+key]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));
  assert.match(value.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);return value.href;}
async function protocol(t){const [{Client},{InMemoryTransport}]=await Promise.all([import('@modelcontextprotocol/sdk/client/index.js'),
  import('@modelcontextprotocol/sdk/inMemory.js')]);
  // Register the original policy tool through the production MCP/LangGraph seam.
  // Loading the entire summarizer also eagerly opens unrelated commerce pools.
  const {Server}=require('../../agent-host/shared/graphServer');
  const {ListToolsRequestSchema,CallToolRequestSchema}=require('@modelcontextprotocol/sdk/types.js');
  const {extractCaller}=require('../../agent-host/shared/callerContext');
  const {explainReturnPolicy}=require('../../agent-host/agents/summarizer/tools/explain_return_policy');
  const server=new Server({name:'secureshop-summarizer-policy-native',version:'0.2.0'},{capabilities:{tools:{}}});
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[{name:'explain_return_policy',
    description:'Fetch a return-policy URL and return its body summarized.',
    inputSchema:{type:'object',properties:{policy_url:{type:'string'}},required:['policy_url']}}]}));
  server.setRequestHandler(CallToolRequestSchema,async req=>{
    assert.equal(req.params.name,'explain_return_policy');
    const {args}=extractCaller(req.params.arguments);
    return{content:[{type:'text',text:JSON.stringify(await explainReturnPolicy(args||{}))}]};
  });
  const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
  const client=new Client({name:'secureshop-ssrf-pg-contract',version:'1.0.0'});await server.connect(serverTransport);await client.connect(clientTransport);
  t.after(()=>Promise.allSettled([client.close(),clientTransport.close(),serverTransport.close(),server.close()]));
  return{callTool(agent,tool,args,options){assert.equal(agent,'summarizer');return client.callTool({name:tool,arguments:args},undefined,{signal:options?.signal});}};}
// Allows a resource-free preflight of the exact native MCP registration seam.
module.exports={protocol};

test('controlled SSRF repository binds real MCP effects, active scope and restart-safe reset',{skip:!enabled,timeout:120000},async t=>{
  assert.ok(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE,'Explicit source workspace is required');
  const workspace=await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);assert.equal(await fs.realpath(process.cwd()),workspace);
  const evidencePath=process.env.PG_SECURESHOP_SSRF_EVIDENCE_PATH;
  if(evidencePath){assert(path.isAbsolute(evidencePath));assert(!path.resolve(evidencePath).startsWith(workspace+path.sep));}
  const status={scope:'controlled V27 policy HTML native storage and C32 persistence; no model, browser or credit',
    passed:false,controlled:true,actualModel:false,genuineCredit:false,migrationFresh:false,migrationPopulated:false,
    migrationNoop:false,htmlRequestImmutable:false,htmlReplayConflict:false,c32Preserved:false,siblingPreserved:false,
    resetFenced:false,historyPreserved:false,recordedHtmlInvocations:0,controlledMcpInvocations:0,historicalMigrationInvocations:2};
  const identityMigration=new Pool({connectionString:checked('IDENTITY_MIGRATION_URL'),max:2}),identity=new Pool({connectionString:checked('IDENTITY_RUNTIME_URL'),max:8});
  const agentsMigration=new Pool({connectionString:checked('AGENTS_MIGRATION_URL'),max:2}),agents=new Pool({connectionString:checked('AGENTS_RUNTIME_URL'),max:8});
  const fixtureRoot=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-ssrf-pg-fixture-'));t.after(()=>fs.rm(fixtureRoot,{recursive:true,force:true}));
  try{await initializeIdentityRepository(identity,identityMigration);
    const agentsDirectoryBefore=path.join(workspace,'db/postgres/workshop-migrations/secureshop_agents');
    await migratorThrough(agentsDirectoryBefore,109)(agentsMigration,agentsDirectoryBefore);
    const constraints=(await agentsMigration.query(`SELECT conname FROM pg_constraint
      WHERE conrelid='secureshop_agents.bound_ssrf_invocations'::regclass
        AND conname IN ('bound_ssrf_invocations_resource_kind_check','bound_ssrf_invocations_check') ORDER BY conname`)).rows;
    assert.deepEqual(constraints,[{conname:'bound_ssrf_invocations_check'},{conname:'bound_ssrf_invocations_resource_kind_check'}]);
    assert.equal((await agentsMigration.query(`SELECT count(*)::int n FROM information_schema.columns
      WHERE table_schema='secureshop_agents' AND table_name='bound_ssrf_requests' AND column_name='policy_html'`)).rows[0].n,0);
    // Fresh DDL preview uses the original migration bytes inside one rollback.
    // The later committed path runs against nonempty immutable C32 history.
    const migration110=await fs.readFile(path.join(agentsDirectoryBefore,'0110_policy_final_html.sql'),'utf8');
    const preview=await agentsMigration.connect();
    try{await preview.query('BEGIN');await preview.query(migration110);
      const target=uuid();await preview.query(`INSERT INTO secureshop_agents.bound_ssrf_targets
        (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,1,1,1)`,[target,uuid(),uuid()]);
      await preview.query(`INSERT INTO secureshop_agents.bound_ssrf_requests
        (operation_id,target_id,request_id,resource_kind,policy_html) VALUES($1,$2,$3,'html-policy',$4)`,[uuid(),target,uuid(),POLICY_HTML]);
      assert.deepEqual((await preview.query('SELECT resource_kind,policy_html FROM secureshop_agents.bound_ssrf_requests')).rows,
        [{resource_kind:'html-policy',policy_html:POLICY_HTML}]);
      await preview.query('ROLLBACK');status.migrationFresh=true;
    }catch(error){await preview.query('ROLLBACK').catch(()=>{});throw error;}finally{preview.release();}
    assert.equal((await agentsMigration.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_requests')).rows[0].n,0);
    // Migration-only fixtures prove history preservation, not actual MCP/model effects.
    const historical={targetId:uuid(),launchId:uuid(),scenarioId:uuid(),generation:1,platformOwnerId:1,platformSessionId:1};
    await agentsMigration.query(`INSERT INTO secureshop_agents.bound_ssrf_targets
      (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
      VALUES($1,$2,$3,1,1,1)`,[historical.targetId,historical.launchId,historical.scenarioId]);
    for(const resourceKind of ['public-policy','private-policy']){
      const operation=uuid(),request=uuid(),nonce=uuid();
      await agentsMigration.query(`INSERT INTO secureshop_agents.bound_ssrf_requests
        (operation_id,target_id,request_id,resource_kind,nonce,issued_url) VALUES($1,$2,$3,$4,$5,$6)`,
        [operation,historical.targetId,request,resourceKind,nonce,`http://127.0.0.1:1/policy/${resourceKind}/${nonce}`]);
      await agentsMigration.query(`INSERT INTO secureshop_agents.bound_ssrf_invocations
        (operation_id,target_id,run_id,request_id,session_id,call_id,arguments_sha256,result_sha256,response_sha256,
          egress_receipt_sha256,egress_policy_sha256,request_method,request_path,response_status,resource_kind,policy_decision)
        VALUES($1,$2,$3,$4,'migration-history','migration-history',decode($5,'hex'),decode($5,'hex'),decode($5,'hex'),
          decode($5,'hex'),decode($6,'hex'),'GET',$7,200,$8,$9)`,
        [operation,historical.targetId,uuid(),request,'a'.repeat(64),SSRF_EGRESS_POLICY_SHA256,
          `/policy/${resourceKind}/${nonce}`,resourceKind,resourceKind==='public-policy'?'allowed':'denied']);
    }
    await agentsMigration.query(`SELECT * FROM secureshop_agents.retire_bound_ssrf_target($1,$2,$3,$4,1,1,1,decode($5,'hex'))`,
      [uuid(),historical.targetId,historical.launchId,historical.scenarioId,'b'.repeat(64)]);
    async function historicalRows(){const value={};for(const table of ['bound_ssrf_targets','bound_ssrf_requests','bound_ssrf_invocations','bound_ssrf_cleanup_receipts'])
      value[table]=(await agentsMigration.query(`SELECT to_jsonb(t)-'policy_html' AS row FROM secureshop_agents.${table} t
        WHERE target_id=$1 ORDER BY to_jsonb(t)::text`,[historical.targetId])).rows;return value;}
    const preservedHistory=await historicalRows();
    assert.equal(preservedHistory.bound_ssrf_requests.length,2);
    assert.equal(preservedHistory.bound_ssrf_invocations.length,2);
    assert.equal(preservedHistory.bound_ssrf_cleanup_receipts.length,1);
    assert.deepEqual(preservedHistory.bound_ssrf_requests.map(value=>value.row.resource_kind).sort(),['private-policy','public-policy']);
    assert.deepEqual(await migrate(agentsMigration,agentsDirectoryBefore),['0110_policy_final_html.sql']);
    assert.deepEqual(await historicalRows(),preservedHistory);
    assert.equal((await agentsMigration.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_requests WHERE policy_html IS NOT NULL')).rows[0].n,0);
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
    assert.deepEqual(await historicalRows(),preservedHistory);status.migrationPopulated=true;
    assert.deepEqual(await migrate(agentsMigration,agentsDirectoryBefore),[]);assert.deepEqual(await historicalRows(),preservedHistory);
    status.migrationNoop=true;
    async function assertLedger(pool,directory){const names=(await fs.readdir(directory)).filter(name=>name.endsWith('.sql')).sort();
      const expected=[];for(const name of names){const bytes=await fs.readFile(path.join(directory,name));expected.push({name,
        checksum:crypto.createHash('sha256').update(bytes).digest('hex')});}
      assert.deepEqual((await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,expected);return expected;}
    const identityDirectory=path.join(workspace,'db/postgres/identity-migrations'),agentsDirectory=path.join(workspace,'db/postgres/workshop-migrations/secureshop_agents');
    const identityLedger=await assertLedger(identityMigration,identityDirectory),agentsLedger=await assertLedger(agentsMigration,agentsDirectory);
    assert.ok(identityLedger.some(row=>row.name==='0052_secureshop_controlled_ssrf.sql'));
    assert.ok(agentsLedger.some(row=>row.name==='0012_secureshop_controlled_ssrf.sql'));
    assert.ok(agentsLedger.some(row=>row.name==='0110_policy_final_html.sql'));
    assert.deepEqual(await initializeIdentityRepository(identity,identityMigration),[],'identity canonical loader replay is empty');
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
    assert.deepEqual(await assertLedger(identityMigration,identityDirectory),identityLedger);
    assert.deepEqual(await assertLedger(agentsMigration,agentsDirectory),agentsLedger);
    const privileges=(await agentsMigration.query(`SELECT table_name,privilege_type FROM information_schema.role_table_grants
      WHERE grantee='dvaia_secureshop_agents_runtime' AND table_schema='secureshop_agents' AND table_name LIKE 'bound_ssrf_%'`)).rows;
    assert.ok(['SELECT','INSERT'].every(privilege=>privileges.some(row=>row.table_name==='bound_ssrf_requests'&&row.privilege_type===privilege)));
    const updateColumns=(await agentsMigration.query(`SELECT table_name,column_name FROM information_schema.role_column_grants
      WHERE grantee='dvaia_secureshop_agents_runtime' AND table_schema='secureshop_agents' AND privilege_type='UPDATE'
      AND table_name LIKE 'bound_ssrf_%' ORDER BY table_name,column_name`)).rows;
    assert.deepEqual(updateColumns,[{table_name:'bound_ssrf_requests',column_name:'issued_url'},
      {table_name:'bound_ssrf_requests',column_name:'nonce'}]);
    const publicPrivileges=(await agentsMigration.query(`SELECT table_name,privilege_type FROM information_schema.table_privileges
      WHERE grantee='PUBLIC' AND table_schema='secureshop_agents' AND table_name LIKE 'bound_ssrf_%'`)).rows;
    assert.deepEqual(publicPrivileges,[],'PUBLIC has no effective controlled SSRF table privileges');
    const identities=createIdentityRepository(identity),launches=createSecureShopLaunchRepository(identity),passwordHash=await bcrypt.hash('ssrf-pg-contract',4);
    async function owner(label){const user=await identities.createUser({username:`${label}-${uuid().slice(0,8)}`,email:`${uuid()}@ssrf.invalid`,passwordHash});
      const session=await identities.createSession({userId:user.id,token:uuid(),expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});
      const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
      const reserved=await launches.reserveSsrfTarget({platformOwnerId:user.id,platformSessionId:session.id,launchId:issued.binding.launchId,expectedGeneration:1});
      return{user,session,scope:Object.freeze({...issued.binding,platformOwnerId:user.id,platformSessionId:session.id}),
        target:Object.freeze({...issued.binding,platformOwnerId:user.id,platformSessionId:session.id,targetId:reserved.targetId})};}
    const primary=await owner('ssrf-primary'),sibling=await owner('ssrf-sibling'),recovery=await owner('ssrf-recovery');
    const cleanupAuthority=createSecureShopResetCleanupAuthorityRepository(identity);
    const repository=createSecureShopBoundSsrfRepository(agents,{checkCurrent:value=>launches.assertCurrent(value),
      checkCleanup:value=>cleanupAuthority.checkTarget({...value,targetKind:'controlled_ssrf',fromGeneration:value.generation})});
    const rawRepository=createSecureShopBoundSsrfRepository(agents,{checkCurrent:async()=>{},checkCleanup:async()=>{}});
    await Promise.all([repository.provision(primary.target),repository.provision(sibling.target),repository.provision(recovery.target)]);
    const targetPool=createSecureShopSsrfTargetPool({root:fixtureRoot});t.after(()=>Promise.allSettled([targetPool.retire(primary.target),targetPool.retire(sibling.target)]));
    const upstreamPool=await protocol(t),records=[];
    async function execute(resourceKind){const requestId=uuid(),html=resourceKind==='html-policy'?{policyHtml:POLICY_HTML}:{},
      claimed=await repository.claimRequest(primary.target,{requestId,resourceKind,...html});
      if(resourceKind==='html-policy'){
        const replay=await repository.claimRequest(primary.target,{requestId,resourceKind,...html});
        assert.equal(replay.operationId,claimed.operationId);assert.equal(replay.policyHtml,POLICY_HTML);assert.equal(replay.replayed,true);
        // A simultaneous otherwise-valid nonce attachment must not rewrite source bytes.
        await assert.rejects(agentsMigration.query(`UPDATE secureshop_agents.bound_ssrf_requests
          SET nonce=$2,issued_url=$3,policy_html=$4 WHERE operation_id=$1`,
          [claimed.operationId,uuid(),'http://127.0.0.1:1/changed',POLICY_HTML+'changed']),{code:'55000'});
        await assert.rejects(repository.claimRequest(primary.target,{requestId,resourceKind,policyHtml:POLICY_HTML+'changed'}),/conflict/);
      }
      const attached=await repository.attachRequest(primary.target,await targetPool.issue(primary.target,{requestId,resourceKind,...html,operationId:claimed.operationId}));
      const request={...primary.target,...attached,egressPolicySha256:resourceKind==='html-policy'?HTML_POLICY_SHA256:SSRF_EGRESS_POLICY_SHA256,
        policyDecision:resourceKind==='private-policy'?'denied':'allowed'};
      const execution={runId:uuid(),ownerKey:'owner:ssrf-pg',durableGeneration:'1',signal:new AbortController().signal,async check(){}};
      const adapter=createSecureShopSsrfExternalAdapter({resolveRequest:async()=>request,targetPool,upstreamPool,checkCurrent:value=>launches.assertCurrent(value),
        recordInvocation:async(binding,input)=>repository.recordInvocation(binding,input)});
      const launchBinding={...primary.scope,shopUserId:11,role:'customer'},callId=`call-${resourceKind}`,args={policy_url:request.url};
      const tools=await adapter.createToolPool(launchBinding,{execution,requestId,sessionId:`session:${uuid()}`});
      const result=await tools.callTool('summarizer','explain_return_policy',args,{callId});
      const effectReceipt={version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'1',
        effectKey:`${requestId}:${JSON.stringify([1,callId,'summarizer.explain_return_policy'])}`};
      const recorded=await adapter.observeExternalTool({run:execution,binding:launchBinding,sessionId:result._meta.sessionId,requestId,
        observation:{step:1,callId,tool:'summarizer.explain_return_policy',args,result,effectReceipt}});
      if(resourceKind==='html-policy'){assert.equal(JSON.parse(result.content[0].text).body,POLICY_HTML);
        assert.equal(recorded.invocation.responseSha256,crypto.createHash('sha256').update(POLICY_HTML).digest('hex'));}
      records.push(recorded.invocation);return{requestId,request,recorded};}
    const publicEffect=await execute('public-policy'),privateEffect=await execute('private-policy');
    const c32Requests=async()=>(await agents.query(`SELECT * FROM secureshop_agents.bound_ssrf_requests
      WHERE operation_id=ANY($1::uuid[]) ORDER BY operation_id`,[[publicEffect.request.operationId,privateEffect.request.operationId]])).rows;
    const c32BeforeHtml=await c32Requests();
    const htmlEffect=await execute('html-policy');
    assert.deepEqual(await c32Requests(),c32BeforeHtml);
    assert.equal(htmlEffect.recorded.invocation.policyDecision,'allowed');assert.equal(htmlEffect.recorded.invocation.egressPolicySha256,HTML_POLICY_SHA256);
    assert.notEqual(HTML_POLICY_SHA256,SSRF_EGRESS_POLICY_SHA256);
    assert.equal(publicEffect.recorded.invocation.egressPolicySha256,SSRF_EGRESS_POLICY_SHA256);
    assert.equal(privateEffect.recorded.invocation.egressPolicySha256,SSRF_EGRESS_POLICY_SHA256);
    status.recordedHtmlInvocations=1;status.controlledMcpInvocations=records.length;
    assert.equal(publicEffect.recorded.invocation.policyDecision,'allowed');assert.equal(privateEffect.recorded.invocation.policyDecision,'denied');
    assert.deepEqual(await repository.recordInvocation(primary.target,privateEffect.recorded.invocation),privateEffect.recorded.invocation,'exact invocation replay is stable');
    await assert.rejects(repository.recordInvocation(primary.target,{...privateEffect.recorded.invocation,callId:'changed'}),/conflict/);
    await assert.rejects(repository.claimRequest(primary.target,{requestId:publicEffect.requestId,resourceKind:'private-policy'}),/conflict/);
    const htmlRequest=await repository.readRequest(primary.target,{requestId:htmlEffect.requestId});
    assert.equal(htmlRequest.policyHtml,POLICY_HTML);assert.equal(htmlRequest.completed,true);
    assert.deepEqual(await repository.recordInvocation(primary.target,htmlEffect.recorded.invocation),htmlEffect.recorded.invocation);
    const htmlReplay=await repository.claimRequest(primary.target,{requestId:htmlEffect.requestId,resourceKind:'html-policy',policyHtml:POLICY_HTML});
    assert.equal(htmlReplay.replayed,true);assert.equal(htmlReplay.completed,true);assert.equal(htmlReplay.operationId,htmlRequest.operationId);
    await assert.rejects(repository.claimRequest(primary.target,{requestId:htmlEffect.requestId,resourceKind:'html-policy',policyHtml:POLICY_HTML+'changed'}),/conflict/);
    await assert.rejects(repository.claimRequest(primary.target,{requestId:uuid(),resourceKind:'public-policy',policyHtml:POLICY_HTML}),/unavailable/);
    await assert.rejects(rawRepository.readRequest({...primary.target,platformOwnerId:sibling.user.id},{requestId:htmlEffect.requestId}),/unavailable/);
    const immutableHtml=(await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_requests WHERE operation_id=$1',[htmlRequest.operationId])).rows[0];
    await assert.rejects(agentsMigration.query('UPDATE secureshop_agents.bound_ssrf_requests SET policy_html=$2 WHERE operation_id=$1',
      [htmlRequest.operationId,POLICY_HTML+'changed']),{code:'55000'});
    await assert.rejects(agentsMigration.query('DELETE FROM secureshop_agents.bound_ssrf_requests WHERE operation_id=$1',[htmlRequest.operationId]),{code:'55000'});
    for(const [kind,body] of [['html-policy',null],['html-policy',''],['html-policy','a'.repeat(8193)],['public-policy',POLICY_HTML]])
      await assert.rejects(agentsMigration.query(`INSERT INTO secureshop_agents.bound_ssrf_requests
        (operation_id,target_id,request_id,resource_kind,policy_html) VALUES($1,$2,$3,$4,$5)`,
        [uuid(),primary.target.targetId,uuid(),kind,body]),{code:'23514'});
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_requests WHERE operation_id=$1',[htmlRequest.operationId])).rows[0],immutableHtml);
    status.htmlRequestImmutable=true;status.htmlReplayConflict=true;
    await assert.rejects(rawRepository.readRequest({...primary.target,platformOwnerId:sibling.user.id},{requestId:privateEffect.requestId}),/unavailable/);
    await assert.rejects(rawRepository.readRequest({...primary.target,launchId:sibling.scope.launchId},{requestId:privateEffect.requestId}),/unavailable/);
    const siblingRequestId=uuid(),siblingClaim=await repository.claimRequest(sibling.target,{requestId:siblingRequestId,resourceKind:'public-policy'});
    const siblingIssued=await targetPool.issue(sibling.target,{requestId:siblingRequestId,resourceKind:'public-policy',operationId:siblingClaim.operationId});
    await repository.attachRequest(sibling.target,siblingIssued);

    const siblingHtmlRequestId=uuid(),siblingHtmlBody='<p>Independent sibling policy bytes.</p>\n';
    const siblingHtmlClaim=await repository.claimRequest(sibling.target,{requestId:siblingHtmlRequestId,resourceKind:'html-policy',policyHtml:siblingHtmlBody});
    const siblingHtmlIssued=await targetPool.issue(sibling.target,{requestId:siblingHtmlRequestId,resourceKind:'html-policy',policyHtml:siblingHtmlBody,operationId:siblingHtmlClaim.operationId});
    await repository.attachRequest(sibling.target,siblingHtmlIssued);
    const retainedRequests=(await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_requests ORDER BY operation_id')).rows;
    const retainedInvocations=(await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_invocations ORDER BY operation_id')).rows;
    const siblingTargetBefore=(await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_targets WHERE target_id=$1',[sibling.target.targetId])).rows[0];

    const resetAdapter=createSecureShopSsrfResetAdapter({repository,targetPool,cleanupAuthority});
    const reconciler=createSecureShopTargetReconciliationRepository(identity,{checkAuthority:input=>cleanupAuthority.checkTarget(input),
      readCleanupReceipt:input=>resetAdapter.readCleanupReceipt(input)});
    const idempotencyKey=uuid(),reset=await launches.beginReset({launchId:primary.scope.launchId,platformSessionId:primary.scope.platformSessionId,
      platformOwnerId:primary.scope.platformOwnerId,expectedGeneration:1,idempotencyKey});const targets=await cleanupAuthority.listTargets(reset.resetId);
    assert.equal(targets.targets.length,1);const item=targets.targets[0],receipt=await resetAdapter.cleanup(item,{operationId:reset.resetId});
    const reconciled=await reconciler.reconcile(item,{operationId:reset.resetId});await cleanupAuthority.assertResolved(reset.resetId);
    const retainedCleanup=await repository.readCleanupReceipt(primary.target,{operationId:reset.resetId});
    assert.equal(retainedCleanup.retainedRequestCount,3);assert.equal(retainedCleanup.retainedInvocationCount,3);
    await cleanupAuthority.finalizeReconciliation(reset.resetId,[reconciled.history]);
    assert.equal((await resetAdapter.cleanup(item,{operationId:reset.resetId})).receiptSha256,receipt.receiptSha256);
    await assert.rejects(rawRepository.readRequest(primary.target,{requestId:privateEffect.requestId}),/unavailable/);
    assert.equal(targetPool.state(sibling.target).active,true);
    const siblingResult=await upstreamPool.callTool('summarizer','explain_return_policy',{policy_url:siblingIssued.url},{});
    assert.equal(JSON.parse(siblingResult.content[0].text).status,200);assert.equal(targetPool.consume(sibling.target,{nonce:siblingIssued.nonce,
      requestId:siblingRequestId}).targetId,sibling.target.targetId,'the sibling remains actually reachable after primary reset');

    await assert.rejects(repository.claimRequest(primary.target,{requestId:uuid(),resourceKind:'html-policy',policyHtml:POLICY_HTML}));
    await assert.rejects(rawRepository.readRequest(primary.target,{requestId:htmlEffect.requestId}),/unavailable/);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_requests ORDER BY operation_id')).rows,retainedRequests);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_invocations ORDER BY operation_id')).rows,retainedInvocations);
    assert.deepEqual(await c32Requests(),c32BeforeHtml);assert.deepEqual(await historicalRows(),preservedHistory);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_targets WHERE target_id=$1',[sibling.target.targetId])).rows[0],siblingTargetBefore);
    const siblingHtmlResult=await upstreamPool.callTool('summarizer','explain_return_policy',{policy_url:siblingHtmlIssued.url},{});
    assert.equal(JSON.parse(siblingHtmlResult.content[0].text).body,siblingHtmlBody);
    assert.equal(targetPool.consume(sibling.target,{nonce:siblingHtmlIssued.nonce,requestId:siblingHtmlRequestId}).responseSha256,
      crypto.createHash('sha256').update(siblingHtmlBody).digest('hex'));
    assert.equal((await repository.readRequest(sibling.target,{requestId:siblingHtmlRequestId})).policyHtml,siblingHtmlBody);
    status.c32Preserved=true;status.siblingPreserved=true;status.resetFenced=true;status.historyPreserved=true;

    const recoveryDirectory=path.join(fixtureRoot,recovery.target.targetId);await fs.mkdir(recoveryDirectory,{mode:0o700});
    await fs.writeFile(path.join(recoveryDirectory,'private-policy.json'),'restart-owned',{mode:0o600});
    const restartedPool=createSecureShopSsrfTargetPool({root:fixtureRoot,async createTarget(){throw new Error('reset must not recreate');}});
    const recoveryResetAdapter=createSecureShopSsrfResetAdapter({repository,targetPool:restartedPool,cleanupAuthority});
    const recoveryIdempotencyKey=uuid(),recoveryReset=await launches.beginReset({launchId:recovery.scope.launchId,
      platformSessionId:recovery.scope.platformSessionId,platformOwnerId:recovery.scope.platformOwnerId,
      expectedGeneration:1,idempotencyKey:recoveryIdempotencyKey});
    const recoveryTargets=await cleanupAuthority.listTargets(recoveryReset.resetId);assert.equal(recoveryTargets.targets.length,1);
    const recoveryItem=recoveryTargets.targets[0],recoveryReceipt=await recoveryResetAdapter.cleanup(recoveryItem,{operationId:recoveryReset.resetId});
    const recoveryReconciled=await reconciler.reconcile(recoveryItem,{operationId:recoveryReset.resetId});
    await cleanupAuthority.assertResolved(recoveryReset.resetId);
    await cleanupAuthority.finalizeReconciliation(recoveryReset.resetId,[recoveryReconciled.history]);
    const recoveryReplay=await launches.beginReset({launchId:recovery.scope.launchId,platformSessionId:recovery.scope.platformSessionId,
      platformOwnerId:recovery.scope.platformOwnerId,expectedGeneration:1,idempotencyKey:recoveryIdempotencyKey});
    assert.equal(recoveryReplay.resetId,recoveryReset.resetId,'restart recovery reset admission replays exactly');
    assert.equal((await recoveryResetAdapter.cleanup(recoveryItem,{operationId:recoveryReset.resetId})).receiptSha256,
      recoveryReceipt.receiptSha256,'restart recovery cleanup receipt replays exactly');
    await assert.rejects(fs.stat(recoveryDirectory),{code:'ENOENT'});await assert.rejects(restartedPool.issue(recovery.target,{requestId:uuid(),resourceKind:'public-policy'}),/retired/);
    assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_invocations')).rows[0].n,5);
    assert.deepEqual(await historicalRows(),preservedHistory);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_requests ORDER BY operation_id')).rows,retainedRequests);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_invocations ORDER BY operation_id')).rows,retainedInvocations);
    assert.equal((await agents.query("SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_targets WHERE lifecycle='active'")).rows[0].n,1,'sibling remains active');
    assert.equal(status.controlledMcpInvocations,3);assert.equal(status.recordedHtmlInvocations,1);
    status.passed=true;
    if(evidencePath){await fs.writeFile(evidencePath,JSON.stringify(status,null,2)+'\n',{flag:'wx',mode:0o600});
      assert.equal((await fs.stat(evidencePath)).mode&0o777,0o600);}
  }finally{await Promise.allSettled([identity.end(),identityMigration.end(),agents.end(),agentsMigration.end()]);}
});
