'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {randomUUID}=require('node:crypto');
test('native conversation history follows completed runs and reset generations',{
 skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_CONVERSATIONS_RUNTIME_URL,
},async()=>{
 for(const key of ['PG_CONVERSATIONS_RUNTIME_URL','PG_CONVERSATIONS_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const {createPool}=require('../../server/database/postgres');
 const runtime=createPool(process.env,'PG_CONVERSATIONS_RUNTIME_URL'),migration=createPool(process.env,'PG_CONVERSATIONS_MIGRATION_URL');
 try{
  const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
  await initializeIdentityRepository(runtime,migration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  await migration.query(await fs.readFile(path.resolve(__dirname,'../../docs/modernization/drafts/mcp-conversation-history.sql'),'utf8'));
  const users=createIdentityRepository(runtime),passwordHash=await require('bcryptjs').hash('owned fixture',4);
  const a=await users.createUser({username:'conversation-a',email:'a@conversation.test',passwordHash});
  const b=await users.createUser({username:'conversation-b',email:'b@conversation.test',passwordHash});
  const ownerKey=JSON.stringify(['MCP',String(a.id)]),runId=randomUUID();
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[ownerKey]);
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[runId,ownerKey]);
  const execution={ownerKey,runId,durableGeneration:'0',check:async()=>{}};
  const {createMcpConversationRepository}=require('../../server/database/postgres/mcpConversationRepository');
  const repository=createMcpConversationRepository(runtime);
  const args={userId:a.id,execution,userText:'Read the training index',assistantText:'The index returned training data'};
  assert.equal((await repository.append(args)).replayed,false);
  assert.deepEqual(await repository.list(a.id),[],'In-flight run is not restored as a completed answer');
  assert.equal((await repository.append(args)).replayed,true);
  await assert.rejects(repository.append({...args,assistantText:'changed'}),{code:'IDEMPOTENCY_CONFLICT'});
  await assert.rejects(repository.append({...args,userId:b.id}),{code:'BAD_REQUEST'});
  await runtime.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[runId]);
  assert.equal((await createMcpConversationRepository(runtime).list(a.id))[0].assistantText,args.assistantText);
  assert.deepEqual(await repository.list(b.id),[]);
  await runtime.query('UPDATE graph_runtime.owners SET generation=1 WHERE owner_key=$1',[ownerKey]);
  assert.deepEqual(await repository.list(a.id),[],'Reset hides old turns without replay');
  await assert.rejects(repository.append(args),{code:'STALE_GENERATION'});
  const nextRun=randomUUID();
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,1,'running')",[nextRun,ownerKey]);
  await repository.append({...args,execution:{...execution,runId:nextRun,durableGeneration:'1'}});
  await runtime.query("UPDATE graph_runtime.runs SET status='failed' WHERE run_id=$1",[nextRun]);
  assert.deepEqual(await repository.list(a.id),[],'Failed response never becomes restored conversation');
  const racingRun=randomUUID();
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,1,'running')",[racingRun,ownerKey]);
  const resetClient=await migration.connect();
  let append;
  try{
   await resetClient.query('BEGIN');
   await resetClient.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[ownerKey]);
   append=repository.append({...args,execution:{...execution,runId:racingRun,durableGeneration:'1'}}).then(value=>({value}),error=>({error}));
   let waiting=false;
   for(let attempt=0;attempt<100;attempt++){
    waiting=(await runtime.query("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND locktype='transactionid') AS waiting")).rows[0].waiting;
    if(waiting)break;
    await new Promise(resolve=>setTimeout(resolve,10));
   }
   assert.equal(waiting,true,'Append reaches the real PostgreSQL row-lock boundary');
   await resetClient.query('UPDATE graph_runtime.owners SET generation=2 WHERE owner_key=$1',[ownerKey]);
   await resetClient.query('COMMIT');
   assert.equal((await append).error?.code,'STALE_GENERATION');
   assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_conversations.turns WHERE run_id=$1',[racingRun])).rows[0].n,0);
  }finally{
   await resetClient.query('ROLLBACK');resetClient.release();if(append)await append;
  }
  const requests=require('../../server/database/postgres/mcpRequestRepository').createMcpRequestRepository(runtime);
  const requestId=randomUUID(),requestRun=randomUUID();
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,2,'running')",[requestRun,ownerKey]);
  const request={userId:a.id,requestId,userText:'read training config',execution:{...execution,runId:requestRun,durableGeneration:'2'}};
  assert.equal((await requests.admit(request)).state,'admitted');
  await assert.rejects(requests.admit(request),{code:'REQUEST_UNCERTAIN'});
  const response={response:'Observed training config',completedObjectives:['mcp_secret_exposure'],judgments:[{verdict:'pass',evaluationId:randomUUID()}]};
  assert.equal((await requests.complete({...request,response})).replayed,false);
  assert.equal((await requests.complete({...request,response})).replayed,true);
  await assert.rejects(requests.complete({...request,response:{response:'changed'}}),{code:'IDEMPOTENCY_CONFLICT'});
  await assert.rejects(requests.admit(request),{code:'REQUEST_UNCERTAIN'},'Response is not replayable before coordinator completion');
  await runtime.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[requestRun]);
  const replayRun=randomUUID();
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,2,'running')",[replayRun,ownerKey]);
  const retry={...request,execution:{...request.execution,runId:replayRun}};
  const replay=await requests.admit(retry);assert.equal(replay.state,'replay');assert.deepEqual(replay.response,response);
  await assert.rejects(requests.admit({...retry,userText:'changed'}),{code:'IDEMPOTENCY_CONFLICT'});
  await runtime.query('UPDATE graph_runtime.owners SET generation=3 WHERE owner_key=$1',[ownerKey]);
  const resetRun=randomUUID();
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,3,'running')",[resetRun,ownerKey]);
  await assert.rejects(requests.admit({...request,execution:{...request.execution,runId:resetRun,durableGeneration:'3'}}),{code:'STALE_REQUEST'},'Old request IDs cannot rerun effects after reset');
  const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime)});
  const service=require('../../server/services/mcp/conversationService').createMcpConversationService({requests,conversations:repository,coordinator});
  const logicalId=randomUUID();let effects=0;
  const invoke=()=>coordinator.run(String(a.id),{},execution=>service.execute({userId:a.id,requestId:logicalId,message:'one owned action',execution},async({history})=>{
   assert.deepEqual(require('../../server/services/mcp/conversationHistory').readConversationHistory(history,execution).messages,[]);effects++;return {response:'Completed one owned action',completedObjectives:[]};
  }));
  assert.deepEqual(await invoke(),await invoke());assert.equal(effects,1,'Completed response replay skips the callback under actual coordinator leases');
  assert.equal((await repository.list(a.id)).length,1);
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'mcp_workshop','mcp_recon')",[a.id]);
  const otherOwner=JSON.stringify(['MCP',String(b.id)]),otherRun=randomUUID();
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[otherOwner]);
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')",[otherRun,otherOwner]);
  await runtime.query("INSERT INTO workshop_conversations.turns(run_id,user_id,owner_key,generation,user_text,assistant_text) VALUES($1,$2,$3,0,'other request','other answer')",[otherRun,b.id,otherOwner]);
  const cleared=await service.clear(a.id);assert.ok(cleared.removedTurns>0);assert.deepEqual(await repository.list(a.id),[]);
  assert.equal((await repository.list(b.id)).length,1,'Conversation clear does not affect another learner');
  assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1',[a.id])).rows[0].n,1,'Conversation clear preserves workshop credit');
  const tombstone=(await runtime.query('SELECT user_text,response_json FROM workshop_conversations.requests WHERE user_id=$1 AND request_id=$2',[a.id,logicalId])).rows[0];
  assert.deepEqual(tombstone,{user_text:null,response_json:null},'Old request identity remains without retained chat payloads');
  await assert.rejects(invoke(),{code:'STALE_REQUEST'});assert.equal(effects,1);
  const uncertainId=randomUUID();let uncertainEffects=0;
  const uncertain=()=>coordinator.run(String(a.id),{},execution=>service.execute({userId:a.id,requestId:uncertainId,message:'uncertain owned action',execution},async()=>{
   uncertainEffects++;throw Error('fixture crash after action');
  }));
  await assert.rejects(uncertain(),/fixture crash after action/);
  await assert.rejects(uncertain(),{code:'REQUEST_UNCERTAIN'});
  assert.equal(uncertainEffects,1,'A failed run with an admitted request cannot repeat uncertain work');
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:users,
   progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),jwtSecret:'owned-conversation-http-fixture-secret'});
  const session=await adapter.createSession(await users.findCredentialById(a.id),{get:()=>null,ip:'127.0.0.1'});
  const otherSession=await adapter.createSession(await users.findCredentialById(b.id),{get:()=>null,ip:'127.0.0.1'});
  const app=require('express')();let httpEffects=0;
  app.use(require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter).authenticateToken);
  app.use(require('../../server/routes/mcpConversationRoutes').createMcpConversationRouter({coordinator,service,conversations:repository,admit:async()=>({}),
   perform:async({message})=>{httpEffects++;return {response:`Observed ${message}`,completedObjectives:[]};}}));
  const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  try{
   const base=`http://127.0.0.1:${server.address().port}`,headers={authorization:`Bearer ${session.token}`,'content-type':'application/json'};
   const body={requestId:randomUUID(),message:'owned HTTP action'};
   const post=()=>fetch(base+'/chat',{method:'POST',headers,body:JSON.stringify(body)});
   assert.equal((await fetch(base+'/history')).status,401);
   const first=await post();assert.equal(first.status,200);const saved=await first.json();
   assert.deepEqual(await (await post()).json(),saved);assert.equal(httpEffects,1);
   const restored=await (await fetch(base+'/history',{headers})).json();assert.equal(restored.turns.length,1);assert.equal(restored.turns[0].assistantText,saved.response);
   const other=await (await fetch(base+'/history',{headers:{authorization:`Bearer ${otherSession.token}`}})).json();
   assert.equal(other.turns[0].assistantText,'other answer');
   const clear=await fetch(base+'/clear',{method:'POST',headers,body:'{}'});assert.equal(clear.status,200);
   assert.deepEqual((await (await fetch(base+'/history',{headers})).json()).turns,[]);
   const stale=await post();assert.equal(stale.status,409);assert.equal((await stale.json()).code,'STALE_REQUEST');assert.equal(httpEffects,1);
  }finally{await new Promise(resolve=>server.close(resolve));}
  await coordinator.run(String(a.id),{},execution=>service.execute({userId:a.id,requestId:randomUUID(),message:'before account deletion',execution},async()=>({response:'owned persisted answer'})));
  assert.equal((await repository.list(a.id)).length,1);
  await require('../../server/database/postgres/adminRepository').createPostgresAdminRepository(runtime).deleteUser(a.id);
  for(const table of ['turns','requests'])assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_conversations.${table} WHERE user_id=$1`,[a.id])).rows[0].n,0);
  assert.equal((await repository.list(b.id)).length,1,'Admin user deletion preserves other learners’ conversations');
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
