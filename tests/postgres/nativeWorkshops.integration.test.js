'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const {createPool,closePostgresPools}=require('../../server/database/postgres');
const {createMcpWorkshopDb}=require('../../server/database/postgres/mcpWorkshopDb');
const {createCsrfWorkshopDb}=require('../../server/database/postgres/csrfWorkshopDb');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_NATIVE_TEST_RUNTIME_URL;
test('native MCP/CSRF PG storage and selected HTTP routes preserve owner isolation, activity, victim hydration and scoped resets',{skip:!enabled},async()=>{
 const pools=[];const pool=key=>{assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);const p=createPool(process.env,key);pools.push(p);return p;};
 const mcp=createMcpWorkshopDb(pool('PG_MCP_TEST_RUNTIME_URL')),csrf=createCsrfWorkshopDb(pool('PG_CSRF_TEST_RUNTIME_URL'));
 const nativePool=pool('PG_NATIVE_TEST_RUNTIME_URL'),nativeMigration=pool('PG_NATIVE_TEST_MIGRATION_URL');
 let server;
 let restoreCodeBotReset,restoreCodeBotProduction;
 try{
  const supply=require('../../server/database/postgres/supplyChainWorkshopDb').createSupplyChainWorkshopDb(pool('PG_SUPPLY_CHAIN_TEST_RUNTIME_URL'));
  await supply.initialize(pool('PG_SUPPLY_CHAIN_TEST_MIGRATION_URL'));
  await supply.ensureObjectives('alice');assert.equal((await supply.getProgress('alice')).length,6);
  assert.equal((await supply.completeObjective('alice','tool_list')).changed,true);
  assert.deepEqual(await supply.completeObjective('alice','tool_list'),{changed:false,completed:true},'Retry must still request canonical reconciliation');
  await supply.ensureObjectives('bob');await supply.resetUser('alice');assert.equal((await supply.getProgress('bob')).length,6);assert.equal((await supply.getProgress('alice')).length,0);
  await mcp.initialize(pool('PG_MCP_TEST_MIGRATION_URL'));await csrf.initialize(pool('PG_CSRF_TEST_MIGRATION_URL'));
  await initializeIdentityRepository(nativePool,nativeMigration);await seedWorkshopPlatform(nativeMigration);
  await mcp.markProgress('alice','mcp_recon');await mcp.markProgress('bob','mcp_recon');
  await mcp.logToolCall({userKey:'alice',toolName:'read_file',args:'{"path":"x"}',resultSummary:'literal <script>lesson</script>',outcome:'mcp_recon'});
  assert.equal((await mcp.listActivity('alice'))[0].result_summary,'literal <script>lesson</script>');assert.equal((await mcp.listActivity('bob')).length,0);
  await mcp.resetUser('alice');assert.equal((await mcp.getProgress('alice')).length,0);assert.equal((await mcp.getProgress('bob')).length,1);
  // Direct storage characterization uses a non-browser objective; browser
  // objectives require the private v8 receipt path before canonical credit.
  await csrf.markProgress('alice','csrf_g1');await csrf.markProgress('alice','csrf_x1');await csrf.markProgress('bob','csrf_g1');
  await csrf.logToolCall({userKey:'alice',tabId:'get',toolName:'recon',args:'{}',resultSummary:'surface',flag:'safe'});
  await csrf.saveVictimState('csrf_alice',{get:{xssInbox:'fixture@example.test'}});
  assert.equal((await csrf.getVictimState('csrf_alice')).get.xssInbox,'fixture@example.test');assert.equal(await csrf.getVictimState('csrf_bob'),null);
  await csrf.resetTab('alice','get',['csrf_g1','csrf_g2','csrf_g3']);assert.deepEqual((await csrf.getProgress('alice')).map(r=>r.objective_id),['csrf_x1']);assert.equal((await csrf.listActivity('alice','get')).length,0);
  await csrf.resetUser('alice');assert.equal(await csrf.getVictimState('csrf_alice'),null);assert.equal((await csrf.getProgress('bob')).length,1);
  const repository=createIdentityRepository(nativePool);const hash=await require('bcryptjs').hash('FixtureUser@123',4);
  const user=await repository.createUser({username:'native-student',email:'native@example.test',passwordHash:hash});
  Object.assign(process.env,{JWT_SECRET:require('node:crypto').randomBytes(48).toString('hex'),PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:process.env.PG_NATIVE_TEST_RUNTIME_URL,MCP_WORKSHOP_DATABASE_URL:process.env.PG_MCP_TEST_RUNTIME_URL,CSRF_WORKSHOP_DATABASE_URL:process.env.PG_CSRF_TEST_RUNTIME_URL,SUPPLY_CHAIN_WORKSHOP_DATABASE_URL:process.env.PG_SUPPLY_CHAIN_TEST_RUNTIME_URL,EXPORT_INTERNALS:'1'});
  // This storage/HTTP suite never invokes a real provider if a route starts grading.
  const graderModule=require('../../server/services/csrfObjectiveGrader');
  const createGrader=graderModule.createCsrfObjectiveGrader;
  const fixtureJudge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{generate:async()=>({response:JSON.stringify({verdict:'fail',explanation:'Storage fixture does not attest exploit success.',criteria:[{id:'observed_outcome',satisfied:false,evidenceRefs:[]}]}),provider:'fixture',model:'storage-only',metadata:{eval_count:0}})}});
  const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(nativePool),progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(nativePool),judge:fixtureJudge});
  graderModule.createCsrfObjectiveGrader=()=>createGrader({completionService:completion,judge:fixtureJudge});
  // Exercise the real reset-before-progress adapter without contacting a host runner.
  // This suite proves native persistence ordering, not sandbox execution/cleanup.
  const codeBotRuntime=require('../../server/services/supplyChain/codeBotSandboxRuntime');
  const originalReset=codeBotRuntime.resetOwnerBeforeProgress;
  let runnerReady=false;const runnerCalls=[];
  restoreCodeBotReset=()=>{codeBotRuntime.resetOwnerBeforeProgress=originalReset;};
  codeBotRuntime.resetOwnerBeforeProgress=(owner,resetProgress)=>originalReset(owner,resetProgress,async(path,body)=>{
    assert.equal(path,'/codebot/reset');
    assert.equal(body.sessionId,codeBotRuntime.sessionIdForOwner(user.id));
    runnerCalls.push(body.sessionId);
    return runnerReady?{ok:true}:{ok:false,error:'synthetic runner unavailable'};
  });
  // Controlled runner health isolates this storage fixture; the real activation gate
  // still checks the native request journal, and reset failure preserves progress.
  const production=require('../../server/services/supplyChain/codeBotProduction');
  const originalActivation=production.getCodeBotProductionActivation;
  restoreCodeBotProduction=()=>{production.getCodeBotProductionActivation=originalActivation;};
  const activation=production.createCodeBotProductionActivation({
    env:{...process.env,CODEBOT_OWNED_EXECUTION_ENABLED:'true',CODEBOT_SANDBOX_RUNNER_URL:'http://127.0.0.1:1'},
    journal:require('../../server/agent-runtime/codeBotRequestJournal').getConfiguredCodeBotRequestJournal(),
    runnerReadiness:async()=>({ready:true,runnerReady:true}),
  });
  production.getCodeBotProductionActivation=()=>activation;
  const mcpRoutes=require('../../server/routes/mcpWorkshop'),csrfRoutes=require('../../server/routes/csrfWorkshop'),supplyRoutes=require('../../server/routes/supplyChainWorkshop');
  graderModule.createCsrfObjectiveGrader=createGrader;
  assert.equal(Object.keys(require.cache).some(p=>/node_modules\/(sqlite3|better-sqlite3)\//.test(p)),false,'Selected native routes must not load SQLite');
  const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={id:user.id};req.session={userId:user.id};next();});app.use('/mcp',mcpRoutes);app.use('/csrf',csrfRoutes);app.use('/supply',supplyRoutes);
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  const base=`http://127.0.0.1:${server.address().port}`;
  const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
  const login=await adapter.createSession(await repository.findCredentialById(user.id),{});
  async function request(path,body){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',Authorization:`Bearer ${login.token}`},body:body?JSON.stringify(body):undefined});return{status:r.status,body:await r.json()};}
  assert.equal((await request('/supply/progress/999')).status,200);
  assert.equal((await supply.getProgress(String(user.id))).length,6);assert.equal((await supply.getProgress('999')).length,0,'Path user ID cannot change authenticated progress owner');
  await supply.completeObjective(String(user.id),'tool_list');
  const beforeFailedReset=await supply.getProgress(String(user.id));
  assert.equal((await request('/supply/progress/reset',{})).status,503);
  assert.deepEqual(await supply.getProgress(String(user.id)),beforeFailedReset,'Unavailable target reset must preserve native progress');
  runnerReady=true;
  assert.equal((await request('/supply/progress/reset',{})).status,200);
  assert.equal(runnerCalls.length,2);
  assert.ok((await supply.getProgress(String(user.id))).every(row=>row.status!=='completed'));
  assert.equal((await request('/mcp/progress')).status,200);
  assert.equal((await request('/mcp/progress/complete',{objectiveId:'mcp_recon'})).status,409);
  assert.ok(!(await request('/mcp/progress')).body.completed.includes('mcp_recon'));
  assert.equal((await request('/mcp/progress/reset',{})).status,200);assert.equal((await mcp.getProgress(String(user.id))).length,0);
  assert.equal((await request('/csrf/victim-state?tab=get')).status,200);
  const toggle=await request('/csrf/defense-toggle',{tab:'get',enabled:true});assert.equal(toggle.status,200);
  assert.equal((await csrf.getVictimState(`csrf_${user.id}`)).get.defenses.csrfToken,true);
  assert.equal((await request('/csrf/progress/reset',{})).status,200);
  assert.equal(await csrf.getVictimState(`csrf_${user.id}`),null);
 }finally{if(restoreCodeBotProduction)restoreCodeBotProduction();if(restoreCodeBotReset)restoreCodeBotReset();if(server)await new Promise(resolve=>server.close(resolve));await Promise.all(pools.map(p=>p.end()));await closePostgresPools();}
});
