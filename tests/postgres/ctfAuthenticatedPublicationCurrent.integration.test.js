'use strict';
// Current-source, disposable four-store proof. The provider is controlled and
// synthetic; this does not claim a genuine model or Objective Judge result.
const test=require('node:test'),assert=require('node:assert/strict');
const http=require('node:http'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const jwt=require('jsonwebtoken');
const {createPool,withTransaction,verifyServer}=require('../../server/database/postgres');
const {migrate,readMigrations,executionSql}=require('../../db/postgres/migrate');
const express=require('express');
const ROOT=path.resolve(__dirname,'../..'),IDENTITY_DIR=path.join(ROOT,'db/postgres/identity-migrations');
const CTF_DIR=path.join(ROOT,'db/postgres/workshop-migrations/ctf');
const ENABLED=process.env.CTF_PUBLICATION_CURRENT_NATIVE==='1';
const sha=value=>createHash('sha256').update(value).digest('hex');
const one=async(pool,sql,args=[])=>(await pool.query(sql,args)).rows[0];

test('current publication fixture defers provider import and denies ambient Ollama',()=>{
 const providerModule=require.resolve('../../server/services/multiProviderAIService');
 assert.equal(require.cache[providerModule],undefined);
 const restore=require('./ctfStage9MainQualification').installSocketFence(new Set([54321]));
 try{assert.throws(()=>require('node:net').createConnection({host:'127.0.0.1',port:11434}),/Unowned socket port/);}
 finally{restore();}
 assert.equal(require.cache[providerModule],undefined);
});

async function migrateIdentityThrough0154(pool){
 const items=(await readMigrations(IDENTITY_DIR)).filter(item=>item.name<='0154_ctf_global_reset_adaptive_memory.sql');
 assert.equal(items.at(-1)?.name,'0154_ctf_global_reset_adaptive_memory.sql');
 await withTransaction(pool,async client=>{
  await verifyServer(client);
  await client.query('SELECT pg_advisory_xact_lock(1886610804,1)');
  await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
  await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger(
   name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`);
  assert.equal((await one(client,'SELECT count(*)::integer AS n FROM dvaia_migrations.ledger')).n,0);
  for(const item of items){
   await client.query(executionSql(item));
   await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',[item.name,item.checksum]);
  }
 });
}

function pair(state,kind){
 const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_PUBLICATION_CURRENT_${state}_${kind}_${role}_URL`);
 assert(keys.every(key=>typeof process.env[key]==='string'&&process.env[key].length));
 const urls=keys.map(key=>new URL(process.env[key]));
 for(const url of urls){
  assert.equal(url.hostname,'127.0.0.1');
  assert.match(url.pathname,new RegExp(`^/dvaia_test_ctf_publication_current_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_[a-f0-9]{12}$`));
  assert.equal(url.search,'');assert.equal(url.hash,'');
 }
 assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);
 const family=kind==='IDENTITY'?'identity':'ctf';
 assert.equal(decodeURIComponent(urls[0].username),`dvaia_${family}_runtime`);
 assert.equal(decodeURIComponent(urls[1].username),`dvaia_${family}_migration`);
 return keys;
}

test('current 0155 publication is valid before canonical reset and stale only for its owner generation',
 {skip:!ENABLED,timeout:240000},async t=>{
  assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
  assert.equal(process.env.DVAIA_CURRENT_MAIN_WORKSPACE,ROOT);
  const providerModule=require.resolve('../../server/services/multiProviderAIService');
  assert.equal(require.cache[providerModule],undefined,'Provider singleton was loaded before owned endpoint admission');
  const pools=[],runtimes=[],stopped=new Set(),listeners=[],paths=new Set(),provider=[];
  let restoreFence=null;
  t.after(async()=>{
   const retirement=await Promise.allSettled(runtimes.filter(runtime=>!stopped.has(runtime)).map(async runtime=>{
    await runtime.stop();stopped.add(runtime);
   }));
   const failedRetirement=retirement.filter(result=>result.status==='rejected');
   if(failedRetirement.length)throw new AggregateError(failedRetirement.map(result=>result.reason),'Runtime not quiescent; preserve owned pools');
   const closed=await Promise.allSettled(listeners.map(server=>new Promise((resolve,reject)=>{
    server.closeAllConnections();server.close(error=>error?reject(error):resolve());
   })));
   const failedClose=closed.filter(result=>result.status==='rejected');
   if(failedClose.length)throw new AggregateError(failedClose.map(result=>result.reason),'Listener not retired; preserve owned pools');
   const ended=await Promise.allSettled(pools.map(pool=>pool.end()));
   const failedEnd=ended.filter(result=>result.status==='rejected');
   if(failedEnd.length)throw new AggregateError(failedEnd.map(result=>result.reason),'Owned pool cleanup failed');
   if(restoreFence)restoreFence();
  });
  const providerServer=http.createServer(async(req,res)=>{
   try{
    let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>131072)throw Error('provider request bound');}
    assert(['/api/generate','/api/chat'].includes(req.url));
    assert(provider.length<4,'one failed scored attempt per store');
    const body=JSON.parse(raw);provider.push({route:req.url,model:body.model??null});
    const content=req.url==='/api/chat'
     ?JSON.stringify({verdict:'fail',explanation:'Controlled non-disclosure.',criteria:[{id:'visible_secret',satisfied:false,evidenceRefs:['visible_response'],citations:[]}]})
     :'The guardian declines disclosure.';
    const frame={model:body.model,created_at:new Date().toISOString(),done:false,eval_count:8,prompt_eval_count:8,total_duration:1000000,
     ...(req.url==='/api/chat'?{message:{role:'assistant',content}}:{response:content})};
    const terminal={...frame,done:true,done_reason:'stop',...(req.url==='/api/chat'?{message:{role:'assistant',content:''}}:{response:''})};
    res.writeHead(200,{'content-type':'application/x-ndjson'});res.end(JSON.stringify(frame)+'\n'+JSON.stringify(terminal)+'\n');
   }catch(error){res.writeHead(400);res.end('controlled provider failure');}
  });
  await new Promise(resolve=>providerServer.listen(0,'127.0.0.1',resolve));listeners.push(providerServer);
  const endpoint='http://127.0.0.1:'+providerServer.address().port;
  assert.notEqual(providerServer.address().port,11434,'Controlled endpoint must not alias ambient Ollama');
  const overrides={AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:endpoint,
   OLLAMA_MODEL:'controlled-native-fixture',JUDGE_MODEL:'controlled-native-fixture',
   LMSTUDIO_BASE_URL:endpoint+'/v1',LMSTUDIO_MODEL:'controlled-native-fixture',
   AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',
   AWS_ACCESS_KEY_ID:'',AWS_PROFILE:'',DISABLE_OLLAMA:'false'};
  const prior=Object.fromEntries(Object.keys(overrides).map(key=>[key,process.env[key]]));Object.assign(process.env,overrides);
  t.after(()=>{for(const [key,value] of Object.entries(prior))if(value===undefined)delete process.env[key];else process.env[key]=value;});
  const allowedPorts=new Set([providerServer.address().port]);
  for(const state of ['FRESH','POPULATED'])for(const kind of ['IDENTITY','CTF']){
   const [runtimeKey,migrationKey]=pair(state,kind);
   allowedPorts.add(Number(new URL(process.env[runtimeKey]).port));
   allowedPorts.add(Number(new URL(process.env[migrationKey]).port));
  }
  restoreFence=require('./ctfStage9MainQualification').installSocketFence(allowedPorts);
  assert.throws(()=>require('node:net').createConnection({host:'127.0.0.1',port:11434}),/Unowned socket port/);
  // Production adapters and their configured provider singleton are loaded only
  // after the owned endpoint and outbound fence are established.
  const {createCtfAuthorityBootstrapRepository,TABLES}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
  const {createCtfAuthorityBootstrap}=require('../../server/services/ctfAuthorityBootstrap');
  const {createCtfDeliveryActivationOperator}=require('../../server/database/postgres/ctfDeliveryActivationOperator');
  const {createCtfDeliveryActivation}=require('../../server/database/postgres/ctfDeliveryActivation');
  const {createCtfDeliveryPool}=require('../../server/database/postgres/ctfDeliveryPool');
  const {createCtfAuthorityRuntime}=require('../../server/services/ctfAuthorityRuntime');
  const {createCtfAuthorityAttemptRoute}=require('../../server/services/ctfAuthorityAttemptRoute');
  const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
  const providerSingleton=require('../../server/services/multiProviderAIService');
  assert.equal(providerSingleton.provider,'ollama');
  assert.equal(providerSingleton.ollamaBaseURL,endpoint,'Production guardian and Judge must use owned endpoint');
  assert.equal(providerSingleton.ollamaModel,'controlled-native-fixture');
  for(const state of ['FRESH','POPULATED']){
   const providerBeforeState=provider.length;
   const stores={};
   const functionAuthority=async pool=>{
    const rows=(await pool.query("SELECT p.proowner::regrole::text AS owner,p.prosecdef AS security_definer FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='identity' AND p.proname='authorize_ctf_current_publication'")).rows;
    assert.deepEqual(rows,[{owner:'dvaia_identity_migration',security_definer:true}]);
   };
   for(const kind of ['IDENTITY','CTF']){
    const [runtimeName,migrationName]=pair(state,kind),database=new URL(process.env[runtimeName]).pathname;
    assert(!paths.has(database));paths.add(database);
    const runtime=createPool({...process.env,PG_POOL_MAX_WORKSHOP:'2'},runtimeName);
    const migration=createPool({...process.env,PG_POOL_MAX_WORKSHOP:'2'},migrationName);
    pools.push(runtime,migration);stores[kind]={runtime,migration};
    const rolePrefix=`dvaia_${kind.toLowerCase()}`;
    assert.equal((await one(runtime,'SELECT current_user AS role')).role,`${rolePrefix}_runtime`);
    assert.equal((await one(migration,'SELECT current_user AS role')).role,`${rolePrefix}_migration`);
    for(const [pool,role] of [[runtime,`${rolePrefix}_runtime`],[migration,`${rolePrefix}_migration`]]){
     assert.deepEqual(await one(pool,'SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=$1',[role]),
      {rolcanlogin:true,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolreplication:false});
    }
    assert.equal((await one(migration,"SELECT to_regclass('dvaia_migrations.ledger') AS value")).value,null);
    if(kind==='IDENTITY'&&state==='POPULATED')await migrateIdentityThrough0154(migration);
    if(kind==='IDENTITY'&&state==='POPULATED'){
     await migration.query("INSERT INTO identity.users(id,username,email,password,role) VALUES(1001,'preserved-sibling','preserved-sibling@fixture.invalid',$1,'student')",['$2b$04$'+'a'.repeat(53)]);
    }
    const retained=kind==='IDENTITY'&&state==='POPULATED'
     ?(await migration.query('SELECT * FROM identity.users WHERE id=1001')).rows:null;
    const populatedIdentity=kind==='IDENTITY'&&state==='POPULATED';
    const applied=populatedIdentity?[]:await migrate(migration,kind==='IDENTITY'?IDENTITY_DIR:CTF_DIR);
    if(kind==='IDENTITY'&&!populatedIdentity)assert.equal(applied.at(-1),'0155_ctf_authenticated_publication_stale.sql');
    if(populatedIdentity)assert.deepEqual((await migration.query('SELECT * FROM identity.users WHERE id=1001')).rows,retained);
    if(kind==='IDENTITY')await functionAuthority(migration);
    const ledger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    if(!populatedIdentity){
     assert.deepEqual(await migrate(migration,kind==='IDENTITY'?IDENTITY_DIR:CTF_DIR),[]);
     assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
    }
   }
   const i=stores.IDENTITY,c=stores.CTF;
   await require('../../server/database/postgres/ctfDb').seed(c.migration);
   if(state==='FRESH')await i.migration.query("INSERT INTO identity.users(id,username,email,password,role) VALUES(1001,'preserved-sibling','preserved-sibling@fixture.invalid',$1,'student')",['$2b$04$'+'a'.repeat(53)]);
   await i.migration.query("INSERT INTO identity.users(id,username,email,password,role) VALUES(2001,'current-learner','current-learner@fixture.invalid',$1,'student'),(1002,'current-admin','current-admin@fixture.invalid',$1,'admin')",['$2b$04$'+'a'.repeat(53)]);
   await i.migration.query('UPDATE identity.users SET admin_level=1 WHERE id=1002');
   await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username,started_at) VALUES(1001,1001,'preserved-sibling',now())");
   await c.migration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time) VALUES(1001,1,'completed',now()-interval '1 day',now(),1000)");
   await c.migration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES(1001,1,1,'preserved sibling input','preserved sibling response')");
   const sourceRows=async table=>{const wide=table==='ctf_progress'?"||jsonb_build_object('completion_time',t.completion_time::text)":table==='ctf_leaderboard'?"||jsonb_build_object('total_completion_time',t.total_completion_time::text)":'';
    return(await c.migration.query(`SELECT (to_jsonb(t)${wide})::text AS encoded FROM ctf.${table} t`)).rows.map(row=>canonicalCtfJson(JSON.parse(row.encoded))).sort();};
   const sourceBefore=Object.fromEntries(await Promise.all(TABLES.map(async table=>[table,await sourceRows(table)])));
   const siblingBefore={users:(await i.runtime.query('SELECT * FROM identity.users WHERE id=1001')).rows,
    progress:(await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=1001')).rows,
    attempts:(await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001')).rows};
   assert.equal(siblingBefore.users.length,1);assert.equal(siblingBefore.progress.length,1);assert.equal(siblingBefore.attempts.length,1);
   const repository=createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:c.migration}),bootstrapId=randomUUID();
   const prepared=await createCtfAuthorityBootstrap({repository}).prepare({operationId:bootstrapId});assert(prepared.prepared);
   for(const table of TABLES)assert.deepEqual(await sourceRows(table),sourceBefore[table]);
   const operator=createCtfDeliveryActivationOperator({identityMigrationPool:i.migration,ctfMigrationPool:c.migration});
   const activationId=randomUUID();
   let activated=await operator.activate({activationId,bootstrapOperationId:bootstrapId,pageBudget:1});
   for(let n=0;activated.staged&&n<8;n++)activated=await operator.activate({activationId,bootstrapOperationId:bootstrapId,pageBudget:1});
   assert(activated.activation);assert.equal(activated.trafficStarted,false);
   const deliveryKey=`PG_CTF_PUBLICATION_CURRENT_${state}_CTF_DELIVERY_URL`,deliveryUrl=new URL(process.env[deliveryKey]);
   assert.equal(deliveryUrl.host,new URL(process.env[`PG_CTF_PUBLICATION_CURRENT_${state}_CTF_RUNTIME_URL`]).host);
   assert.equal(deliveryUrl.pathname,new URL(process.env[`PG_CTF_PUBLICATION_CURRENT_${state}_CTF_RUNTIME_URL`]).pathname);
   assert.equal(decodeURIComponent(deliveryUrl.username),'dvaia_ctf_delivery');
   const delivery=await createCtfDeliveryPool({env:{...process.env,CTF_DELIVERY_DATABASE_URL:deliveryUrl.href},activation:activated.activation});pools.push(delivery);
   await createCtfDeliveryActivation({identityPool:i.runtime,ctfPool:c.runtime}).verify(activated.activation);
   const jwtSecret='controlled-'+randomUUID();
   const identityAuth=require('../../server/database/postgres/identityRepository').createIdentityRepository(i.runtime);
   const session=async id=>{const raw=jwt.sign({userId:id},jwtSecret,{expiresIn:'1h',jwtid:randomUUID()});
    const saved=await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour') RETURNING id",[id,sha(raw)]);
    return{headers:{authorization:'Bearer '+raw},user:{id},identitySession:{id:saved.id}};};
   const learner=await session(2001),admin=await session(1002),sibling=await session(1001);
   const validateSession=async token=>{const decoded=jwt.verify(token,jwtSecret);return identityAuth.findActiveSession(token,decoded.userId);};
   const runtime=createCtfAuthorityRuntime({identityPool:i.runtime,ctfPool:c.runtime,deliveryPool:delivery,
    deliveryDatabaseUrl:deliveryUrl.href,activation:activated.activation,validateSession,attempts:'production'},
    {workerOptions:{pollMs:20,maxEvents:4,batchTimeoutMs:10000,drainMs:1000},facadeOptions:{waitMs:5000,maxPolls:8},drainMs:1000});
   runtimes.push(runtime);await runtime.start();assert.equal((await runtime.readiness()).runtimeReady,true);
   const mutate=async(req,kind,input)=>{const pending=await runtime.mutate({req,kind,input});
    if(pending.status!==202)return pending;
    const recovered=await runtime.recoverOperation({req,operationId:pending.body.operationId});
    assert.equal(recovered.status,200);return recovered;};
   const registered=await mutate(learner,'register',{});assert.equal(registered.status,200);
   assert.equal((await mutate(learner,'start',{stageId:'1'})).status,200);
   const owner=await one(i.runtime,"SELECT generation::text FROM graph_runtime.owners WHERE owner_key='[\"CTF\",\"2001\"]'");
   const runId=randomUUID();await i.migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,'[\"CTF\",\"2001\"]',$2,'running')",[runId,owner.generation]);
   const execution={runId,ownerKey:'["CTF","2001"]',ownerId:'2001',signal:new AbortController().signal,
    async check(){const row=await one(i.runtime,'SELECT r.status,g.generation::text FROM graph_runtime.runs r JOIN graph_runtime.owners g USING(owner_key) WHERE r.run_id=$1',[runId]);
     assert.equal(row.status,'running');assert.equal(row.generation,owner.generation);}};
   const attemptInput={req:learner,runId,execution,request:{runId,stageId:'1',payload:'controlled ordinary question',registrationToken:registered.body.sessionToken}};
   let pending=await runtime.attempt(attemptInput);
   for(let n=0;!pending.body.decisionId&&n<3;n++)pending=await runtime.attempt({req:learner,runId,execution});
   assert.equal(pending.status,202);assert.match(pending.body.decisionId,/^[a-f0-9-]{36}$/);
   const deadline=Date.now()+5000;let applied=false;
   for(let n=0;n<100&&Date.now()<deadline;n++){applied=(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[pending.body.decisionId]))?.state==='applied';if(applied)break;await new Promise(resolve=>setTimeout(resolve,20));}
   assert(applied,'current decision projection must be acknowledged');
   const current=await runtime.publishDecision({req:learner,decisionId:pending.body.decisionId});
   assert.equal(current.status,200);assert.equal(current.body.success,false);
   assert.deepEqual(await runtime.publishDecision({req:learner,decisionId:pending.body.decisionId}),current);
   assert.equal((await one(i.runtime,'SELECT count(*)::int AS n FROM identity.ctf_decisions WHERE decision_id=$1',[pending.body.decisionId])).n,1);
   if(state==='POPULATED'){
    const retainedTables=['identity.users','identity.user_sessions','identity.ctf_authority','identity.ctf_stage_bindings','identity.ctf_participant_bindings','identity.ctf_progress_bindings','identity.ctf_decisions','identity.ctf_outbox','identity.ctf_bootstrap_sessions','identity.ctf_bootstrap_pages','graph_runtime.owners','graph_runtime.runs'];
    const retainedRows=async table=>(await i.migration.query(`SELECT to_jsonb(t)::text AS encoded FROM ${table} t`)).rows.map(row=>row.encoded).sort();
    const retainedBefore=Object.fromEntries(await Promise.all(retainedTables.map(async table=>[table,await retainedRows(table)])));
    const ctfBefore=Object.fromEntries(await Promise.all(TABLES.map(async table=>[table,await sourceRows(table)])));
    assert((await one(i.migration,'SELECT count(*)::int AS n FROM identity.ctf_decisions')).n>0);
    assert((await one(i.migration,'SELECT count(*)::int AS n FROM identity.user_sessions')).n>=3);
    assert.deepEqual(await migrate(i.migration,IDENTITY_DIR),['0155_ctf_authenticated_publication_stale.sql']);
    for(const table of retainedTables)assert.deepEqual(await retainedRows(table),retainedBefore[table],`0155 changed ${table}`);
    for(const table of TABLES)assert.deepEqual(await sourceRows(table),ctfBefore[table],`0155 changed ctf.${table}`);
    await functionAuthority(i.migration);
    const ledger=(await i.migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await migrate(i.migration,IDENTITY_DIR),[]);
    assert.deepEqual((await i.migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
    assert.deepEqual(await runtime.publishDecision({req:learner,decisionId:pending.body.decisionId}),current,'0155 lost valid current publication');
   }
   const providerBeforeReset=provider.length;
   const web=express();web.use(express.json());web.use((req,_res,next)=>{const actor=req.headers['x-owned-actor'];
    req.user={id:actor==='sibling'?1001:2001};req.identitySession={id:actor==='sibling'?sibling.identitySession.id:learner.identitySession.id};next();});
   const handlers=createCtfAuthorityAttemptRoute({runtime,coordinator:{run(){throw Error('Attempt not admitted by publication-only fixture');}}});
   web.post('/publish/:decisionId',handlers.publishDecision);
   const listener=await new Promise(resolve=>{const server=web.listen(0,'127.0.0.1',()=>resolve(server));});listeners.push(listener);
   allowedPorts.add(listener.address().port);
   const publish=async(request,actor)=>{
    const response=await fetch(`http://127.0.0.1:${listener.address().port}/publish/${pending.body.decisionId}`,
     {method:'POST',headers:{authorization:request.headers.authorization,'x-owned-actor':actor}});
    return{status:response.status,body:await response.json()};};
   assert.equal((await publish(learner,'learner')).status,200);
   assert.deepEqual(await publish(sibling,'sibling'),{status:403,body:{error:'CTF service temporarily unavailable'}});
   const reset=await mutate(admin,'owner_reset',{ownerId:'2001'});assert.equal(reset.status,200);
   assert.deepEqual(await publish(learner,'learner'),{status:409,body:{error:'CTF request is no longer current'}});
   assert.equal(provider.length,providerBeforeReset,'old publication must not re-run guardian or Judge');
   assert.deepEqual((await i.runtime.query('SELECT * FROM identity.users WHERE id=1001')).rows,siblingBefore.users);
   assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=1001')).rows,siblingBefore.progress);
   assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001')).rows,siblingBefore.attempts);
   await require('../../server/database/postgres/identityRepository').createIdentityRepository(i.migration)
    .revokeSession(learner.headers.authorization.slice(7),2001,'fixture_after_canonical_reset');
   assert.deepEqual(await publish(learner,'learner'),{status:401,body:{error:'Session is no longer current'}});
   assert.equal(provider.length,providerBeforeReset);
   assert.deepEqual(provider.slice(providerBeforeState).map(row=>[row.route,row.model]),
    [['/api/generate','controlled-native-fixture'],['/api/chat','controlled-native-fixture']],
    'Exactly one controlled guardian and one controlled Judge must serve this state');
   await runtime.stop();stopped.add(runtime);
   assert.deepEqual(await migrate(i.migration,IDENTITY_DIR),[]);
   assert.deepEqual(await migrate(c.migration,CTF_DIR),[]);
  }
  assert.equal(provider.length,4,'exactly one controlled guardian and Judge per store');
 });
