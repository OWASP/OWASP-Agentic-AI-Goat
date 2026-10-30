'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{Pool}=require('pg');
const enabled=process.env.RUN_LIVE_ARIA_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
test('ARIA live8B selection, native syntax error, real judge and durable receipt',{skip:!enabled,timeout:180000},async t=>{
 const adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.ok(['postgres:','postgresql:'].includes(adminUrl.protocol));assert.equal(adminUrl.pathname,'/postgres');const admin=new Pool({connectionString:adminUrl.href});const databases=[],pools=[];
 try{
  const make=async(schema)=>{const db=`owasp_ai_goat_test_arialive_${process.pid}_${schema}`;await admin.query(`CREATE DATABASE ${db} OWNER dvaia_${schema}_migration`);databases.push(db);await admin.query(`REVOKE CONNECT ON DATABASE ${db} FROM PUBLIC; GRANT CONNECT ON DATABASE ${db} TO dvaia_${schema}_runtime,dvaia_${schema}_migration`);const url=role=>{const value=new URL(adminUrl);value.pathname='/'+db;value.username=role;value.password=process.env.PG_LIVE_ROLE_PASSWORD||'';return value.href;};const runtime=new Pool({connectionString:url(`dvaia_${schema}_runtime`),max:4}),migration=new Pool({connectionString:url(`dvaia_${schema}_migration`),max:2});pools.push(runtime,migration);return{runtime,migration};};
  const identity=await make('identity'),aria=await make('aria');await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity.runtime,identity.migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identity.migration);
  const user=await require('../../server/database/postgres/identityRepository').createIdentityRepository(identity.runtime).createUser({username:'live-fixture',email:'live@example.invalid',passwordHash:await require('bcryptjs').hash('fixture',4)});
  await identity.runtime.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'sql_injection_workshop','vuln')",[user.id]);
  const store=require('../../server/database/postgres/sqlWorkshopDb').createSqlWorkshopDb(aria.runtime);await store.initializeSqlWorkshopDb(aria.migration);
  const provider=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
  const model={provider:'ollama',generateResponse:(prompt,options)=>provider.generate(prompt,{...options,num_ctx:8192,timeout:60000})};
  const lease=new Pool({connectionString:identity.runtime.options.connectionString,max:2});pools.push(lease);
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity.runtime,{leasePool:lease});
  let simulateJudgeOutage=true;
  const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity.runtime),progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity.runtime),judge:async packet=>{if(simulateJudgeOutage)throw Error('Synthetic judge transport outage');try{return await require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:provider,timeoutMs:60000})(packet);}catch(error){console.error('JUDGE_EXECUTION_FAILURE',error.stack);throw error;}}});
  const grader=require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:true,completionService:completion});
  const agent=require('../../server/services/ariaAgentService').createAgent({store,model,runLedger:ledger,defaultTimeoutMs:150000});
  let execution,attempt,outcome,observed;const message="Search products using this exact searchTerm: %'";
  const result=await agent.invoke(String(user.id),message,'vuln',{onStart:async e=>{execution={...e,emit:e.trace};attempt=await grader.begin(user.id,execution);},onResult:async(dto,check,e,toolInvocation)=>{observed={...dto,toolInvocation};outcome=await grader.evaluate({userId:user.id,objectiveId:'sqli_1',message,result:observed,mode:'vuln',execution,attempt});}});
  assert.equal(observed.toolUsed,'search_products');assert.ok(observed.toolResult.error);assert.equal(outcome.judgment.verdict,'unavailable');assert.equal(outcome.completed,false);
  assert.equal((await identity.runtime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,0);
  const historyBefore=await store.getHistory(String(user.id));const originalRun=await ledger.getRun(execution.runId,execution.ownerKey);assert.ok(originalRun.events.some(e=>e.type==='decision'&&e.data.decisionSource==='model'));
  simulateJudgeOutage=false;
  const recoveryCoordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'ARIA',ledger,defaultTimeoutMs:150000});
  const recovered=await recoveryCoordinator.run(String(user.id),{},async current=>completion.retry({userId:user.id,evaluationId:outcome.judgment.evaluationId,execution:{...current,emit:current.trace}}));
  assert.equal(recovered.judgment.verdict,'pass');assert.equal(recovered.completed,true);assert.deepEqual(await store.getHistory(String(user.id)),historyBefore);
  const run=await ledger.getRun(recovered.retryRunId,execution.ownerKey);assert.ok(run.events.some(e=>e.node==='judge_validate'&&e.data.verdict==='pass'));assert.equal(run.events.some(e=>e.type==='tool'),false);
  outcome=recovered;
  assert.equal((await identity.runtime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,1);
  t.diagnostic(JSON.stringify({provider:'ollama',model:'llama3.1:8b',objective:'sqli_1',tool:observed.toolUsed,invocation:observed.toolInvocation,verdict:outcome.judgment.verdict,completed:outcome.completed,runStatus:run.status,eventCount:run.events.length}));
 }catch(error){console.error('WORKFLOW_FAILURE',error.stack);throw error;}finally{await Promise.all(pools.map(p=>p.end()));for(const db of databases)await admin.query(`DROP DATABASE ${db} WITH(FORCE)`);await admin.end();}
});
