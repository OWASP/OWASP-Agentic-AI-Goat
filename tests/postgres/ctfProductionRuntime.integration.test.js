'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_PRODUCTION_RUNTIME_ISOLATED==='1';
const one=async(p,s,a=[])=>(await p.query(s,a)).rows[0];
const sha=s=>createHash('sha256').update(s).digest('hex');
function lostPreparationCommit(pool){let fired=false;return {get fired(){return fired;},async connect(){const c=await pool.connect();let changed=false;return {async query(s,a){const r=await c.query(s,a);if(s.startsWith("UPDATE ctf.bootstrap_control SET state='prepared'"))changed=true;if(s==='COMMIT'&&changed&&!fired){fired=true;throw Error('OWNED_POST_COMMIT_RESPONSE_LOSS');}return r;},release(d){c.release(d);}};}};}
test('production adapters with synthetic loopback transport preserve durable diagnostics and current publication',{skip:!enabled,timeout:180000},async t=>{
 // CONTROLLED SYNTHETIC TRANSPORT. No actual model or mounted HTTP proof.
 const http=require('node:http');const ledger=[];let mode='fail',secret='';
 const server=http.createServer(async(req,res)=>{try{
  let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>131072)throw Error('request bound');}
  assert(ledger.length<32,'aggregate synthetic provider ceiling');
  const body=raw?JSON.parse(raw):{};ledger.push({route:req.url,mode,model:body.model??null});
  assert(['/api/generate','/api/chat','/v1/chat/completions'].includes(req.url),'unexpected provider route');
  if(mode==='guardian-unavailable'||req.url==='/v1/chat/completions'||mode==='judge-unavailable'&&req.url==='/api/chat'){
   res.writeHead(400,{'content-type':'application/json'});res.end(JSON.stringify({error:'owned synthetic unavailable'}));return;
  }
  const response=mode==='fail'?'The guardian declines disclosure.':secret;
  const verdict=JSON.stringify(mode==='fail'
   ?{verdict:'fail',explanation:'Controlled response does not disclose the identifier.',criteria:[{id:'visible_secret',satisfied:false,evidenceRefs:['visible_response'],citations:[]}]}
   :{verdict:'pass',explanation:'Controlled visible identifier.',criteria:[{id:'visible_secret',satisfied:true,evidenceRefs:['visible_response'],citations:[{evidenceId:'visible_response',quote:secret}]}]});
  const frame={model:body.model,created_at:new Date().toISOString(),done:true,done_reason:'stop',eval_count:8,prompt_eval_count:8,total_duration:1000000,...(req.url==='/api/chat'?{message:{role:'assistant',content:verdict}}:{response})};
  // Ollama text streaming consumes content only from nonterminal frames.
  const content={...frame,done:false};delete content.done_reason;
  const terminal={...frame,...(req.url==='/api/chat'?{message:{role:'assistant',content:''}}:{response:''})};
  res.writeHead(200,{'content-type':'application/x-ndjson'});res.end(JSON.stringify(content)+'\n'+JSON.stringify(terminal)+'\n');
 }catch(error){ledger.push({failure:error.message});res.writeHead(400);res.end('controlled fixture failure');}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
 const endpoint='http://127.0.0.1:'+server.address().port;
 const overrides={AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:endpoint,OLLAMA_MODEL:'controlled-native-fixture',JUDGE_MODEL:'controlled-native-fixture',LMSTUDIO_BASE_URL:endpoint+'/v1',LMSTUDIO_MODEL:'controlled-native-fixture',AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',AWS_ACCESS_KEY_ID:'',AWS_PROFILE:'',AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'',AWS_WEB_IDENTITY_TOKEN_FILE:'',DISABLE_OLLAMA:'false'};
 const previous=Object.fromEntries(Object.keys(overrides).map(k=>[k,process.env[k]]));Object.assign(process.env,overrides);
 t.after(()=>{for(const [k,v]of Object.entries(previous))if(v===undefined)delete process.env[k];else process.env[k]=v;});
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createCtfAuthorityBootstrapRepository,TABLES}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
const {createCtfAuthorityBootstrap}=require('../../server/services/ctfAuthorityBootstrap');
const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
 const pools=[],runtimes=[],dbs=new Set();t.after(async()=>{await Promise.allSettled(runtimes.map(r=>r.stop()));await Promise.allSettled(pools.map(p=>p.end()));});
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_PRODUCTION_RUNTIME_${state}_${kind}_${role}_URL`);assert(keys.every(k=>process.env[k]));
   const urls=keys.map(k=>new URL(process.env[k]));for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_ctf_prod_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!dbs.has(urls[0].pathname));dbs.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool({...process.env,PG_POOL_MAX_WORKSHOP:'1'},k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   const directory=path.resolve(__dirname,'../../db/postgres',kind==='IDENTITY'?'identity-migrations':'workshop-migrations/ctf');
   const target=kind==='IDENTITY'?'0119_ctf_response_diagnostics.sql':'0012_ordered_telemetry_receipts.sql';
   const prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-bootstrap-prefix-'));t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
   for(const n of fs.readdirSync(directory).filter(n=>n.endsWith('.sql')&&n<target))fs.copyFileSync(path.join(directory,n),path.join(prefix,n));
   await migrate(migration,prefix);
   if(kind==='CTF'&&state==='POPULATED')await require('../../server/database/postgres/ctfDb').seed(migration);
   fs.copyFileSync(path.join(directory,target),path.join(prefix,target));await migrate(migration,prefix);assert.deepEqual(await migrate(migration,prefix),[]);
  }
  const i=stores.IDENTITY,c=stores.CTF;
  if(state==='FRESH')await require('../../server/database/postgres/ctfDb').seed(c.migration);
  const count=state==='POPULATED'?130:2;
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role) VALUES(2001,'runtime-learner','runtime-learner@fixture.invalid',$1,'student')",['$2b$04$'+'a'.repeat(53)]);
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) SELECT x,'bootstrap-'||x,'bootstrap-'||x||'@fixture.invalid',$1,'student',0 FROM generate_series(1001,$2) x",['$2b$04$'+'a'.repeat(53),1000+count]);
  await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username,started_at) SELECT x,x,'bootstrap-'||x,'2026-01-01T00:00:00.123456Z' FROM generate_series(1001,$1) x",[1000+count]);
  // Normal registered-but-never-attempted users deliberately have no graph owner.
  assert.equal((await one(i.migration,'SELECT count(*)::int AS n FROM graph_runtime.owners')).n,0);
  await c.migration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time) VALUES(1001,1,'completed','2026-01-01','2026-01-02',9007199254740993)");
  await c.migration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES(1001,1,1,'owned historical attempt','owned response')");
  const normalized='long retained payload '.repeat(100).trim();
  await c.migration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(9,$1,$2,1001)',[sha(normalized),normalized]);
  const sourceRows=async table=>{const wide=table==='ctf_progress'?"||jsonb_build_object('completion_time',t.completion_time::text)":table==='ctf_leaderboard'?"||jsonb_build_object('total_completion_time',t.total_completion_time::text)":'';return (await c.migration.query(`SELECT (to_jsonb(t)${wide})::text AS encoded FROM ctf.${table} t`)).rows.map(x=>canonicalCtfJson(JSON.parse(x.encoded))).sort();};
  await c.migration.query("INSERT INTO ctf.ctf_sessions(participant_id,session_token,is_active,total_active_time) VALUES(1001,$1,1,0),(1001,'owned-inactive',0,5000),(1002,'sibling-active',1,7000)",['owned-active 🌍 \"quoted\"\nline']);
  const before=Object.fromEntries(await Promise.all(TABLES.map(async table=>[table,await sourceRows(table)])));
  const repository=createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:c.migration});const operationId=randomUUID();
  const lost=lostPreparationCommit(c.migration);await assert.rejects(createCtfAuthorityBootstrap({repository:createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:lost})}).prepare({operationId}),/OWNED_POST_COMMIT_RESPONSE_LOSS/);assert(lost.fired);
  assert.equal((await one(c.migration,'SELECT state FROM ctf.bootstrap_control')).state,'prepared');assert.equal((await one(i.migration,'SELECT state FROM identity.ctf_bootstrap_sessions')).state,'staging');
  const result=await createCtfAuthorityBootstrap({repository}).prepare({operationId});assert(result.prepared);assert.equal(result.runtimeReady,false);
  assert.equal((await one(i.migration,'SELECT count(*)::int AS n FROM identity.ctf_participant_bindings')).n,count);
  assert.equal((await one(i.migration,'SELECT completion_time::text AS n FROM identity.ctf_progress_bindings')).n,'9007199254740993');
  assert.equal((await one(i.migration,'SELECT min(generation)::text AS g,max(generation)::text AS m FROM graph_runtime.owners')).g,'0');
  assert.equal((await one(i.migration,"SELECT normalized_payload FROM identity.ctf_adaptive_memory WHERE kind='payload'")).normalized_payload,normalized);
  for(const table of TABLES){assert.deepEqual(await sourceRows(table),before[table]);const staged=(await i.migration.query('SELECT canonical_rows,page_sha256 FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name=$2 ORDER BY page_number',[operationId,table])).rows;staged.forEach(x=>assert.equal(sha(x.canonical_rows),x.page_sha256));assert.deepEqual(staged.flatMap(x=>JSON.parse(x.canonical_rows).map(canonicalCtfJson)).sort(),before[table]);}
  if(count>128)assert.equal((await one(i.migration,"SELECT count(*)::int AS n FROM identity.ctf_bootstrap_pages WHERE table_name='ctf_participants'")).n,2);
  const receiptSnapshot=async()=>canonicalCtfJson((await i.migration.query('SELECT to_jsonb(s) AS s FROM identity.ctf_bootstrap_sessions s')).rows.concat((await i.migration.query('SELECT to_jsonb(p) AS p FROM identity.ctf_bootstrap_pages p ORDER BY table_name,page_number')).rows));
  const receipts=await receiptSnapshot();await createCtfAuthorityBootstrap({repository}).prepare({operationId});assert.equal(await receiptSnapshot(),receipts);
  await assert.rejects(c.runtime.query("UPDATE ctf.ctf_config SET value=value WHERE key='ctf_enabled'"),e=>e.code==='55000');
  await assert.rejects(i.runtime.query("UPDATE identity.ctf_bootstrap_sessions SET state='staging'"),e=>e.code==='42501');
  const {createCtfDeliveryActivationOperator}=require('../../server/database/postgres/ctfDeliveryActivationOperator');
  const {createCtfDeliveryActivation}=require('../../server/database/postgres/ctfDeliveryActivation');
  const operator=createCtfDeliveryActivationOperator({identityMigrationPool:i.migration,ctfMigrationPool:c.migration});
  const activationId=randomUUID();
  let activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:1});
  for(let n=0;activated.staged&&n<8;n++)activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:1});
  assert(activated.activation);assert.equal(activated.trafficStarted,false);
  const deliveryKey=`PG_CTF_PRODUCTION_RUNTIME_${state}_CTF_DELIVERY_URL`;
  assert(process.env[deliveryKey],'Explicit owned delivery LOGIN URL required');
  const deliveryUrl=new URL(process.env[deliveryKey]),ctfUrl=new URL(process.env[`PG_CTF_PRODUCTION_RUNTIME_${state}_CTF_RUNTIME_URL`]);
  assert.equal(deliveryUrl.host,ctfUrl.host);assert.equal(deliveryUrl.pathname,ctfUrl.pathname);assert.equal(decodeURIComponent(deliveryUrl.username),'dvaia_ctf_delivery');
  const {createCtfDeliveryPool}=require('../../server/database/postgres/ctfDeliveryPool');
  const delivery=await createCtfDeliveryPool({env:{...process.env,CTF_DELIVERY_DATABASE_URL:deliveryUrl.href},activation:activated.activation});pools.push(delivery);
  const verifier=createCtfDeliveryActivation({identityPool:i.runtime,ctfPool:c.runtime});
  await verifier.verify(activated.activation);
  assert.equal((await one(c.migration,'SELECT initialized FROM ctf.projection_cursor')).initialized,true);
  await assert.rejects(c.runtime.query("UPDATE ctf.ctf_config SET value=value WHERE key='ctf_enabled'"),e=>e.code==='42501');
  // Canonical JWT signature + actual active identity session lookup. No mounted HTTP claim.
  const jwt=require('jsonwebtoken'),jwtSecret='owned-fixture-'+randomUUID();
  const identityAuth=require('../../server/database/postgres/identityRepository').createIdentityRepository(i.runtime);
  async function userRequest(userId){
   const rawToken=jwt.sign({userId},jwtSecret,{expiresIn:'1h',jwtid:randomUUID()});
   const saved=await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour') RETURNING id",[userId,sha(rawToken)]);
   return{headers:{authorization:'Bearer '+rawToken},user:{id:userId},identitySession:{id:saved.id}};
  }
  await i.migration.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=1002");
  const learner=await userRequest(2001),admin=await userRequest(1002);
  const validateSession=async token=>{const decoded=jwt.verify(token,jwtSecret);return identityAuth.findActiveSession(token,decoded.userId);};
  const {createCtfAuthorityRuntime}=require('../../server/services/ctfAuthorityRuntime');
  let stageLossArmed=true,stageLossObserved=false,publicationBarrier=null,publicationQueries=0;
  const observedIdentity={async connect(){const client=await i.runtime.connect();let staged=false;return{async query(sql,args){
   if(sql.includes('authorize_ctf_current_publication')&&publicationBarrier&&++publicationQueries===2){const hook=publicationBarrier;publicationBarrier=null;await hook();}
   const result=await client.query(sql,args);
   if(sql.includes('stage_ctf_response_diagnostics'))staged=true;
   if(sql==='COMMIT'&&staged&&stageLossArmed){stageLossArmed=false;stageLossObserved=true;throw Object.assign(Error('owned committed diagnostics response loss'),{code:'ECONNRESET'});}
   return result;
  },release:discard=>client.release(discard)};}};
  const options={identityPool:observedIdentity,ctfPool:c.runtime,deliveryPool:delivery,deliveryDatabaseUrl:deliveryUrl.href,activation:activated.activation,validateSession};
  const bounds={workerOptions:{pollMs:20,maxEvents:4,batchTimeoutMs:10000,drainMs:1000},facadeOptions:{waitMs:5000,maxPolls:8},drainMs:1000};
  // Separate proxy identity prevents an object-equality shortcut; real SQL login is wrong.
  const wrongRole=createCtfAuthorityRuntime({...options,deliveryPool:{connect:()=>c.runtime.connect()}},bounds);
  await assert.rejects(wrongRole.start(),/ROLE_INVALID/);assert.equal(wrongRole.status().worker.state,'paused');await wrongRole.stop();
  const wrongTuple=createCtfAuthorityRuntime({...options,activation:{...activated.activation,authority_sha256:'f'.repeat(64)}},bounds);
  await assert.rejects(wrongTuple.start(),/CHECKPOINT_INVALID/);assert.equal(wrongTuple.status().worker.state,'paused');await wrongTuple.stop();
  const runtime=createCtfAuthorityRuntime({...options,attempts:'production'},bounds);
  runtimes.push(runtime);assert.equal(runtime.status().state,'paused');
  await runtime.start();assert.equal((await runtime.readiness()).runtimeReady,true);
  const siblingBefore=(await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=1001 ORDER BY id')).rows;
  const siblingAttempts=(await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001 ORDER BY id')).rows;
  async function mutate(req,kind,input){const value=await runtime.mutate({req,kind,input});if(value.status!==202)return value;const recovered=await runtime.recoverOperation({req,operationId:value.body.operationId});assert.equal(recovered.status,200,'bounded operation must have reached acknowledged projection');return recovered;}
  await mutate(admin,'config_mutation',{key:'ctf_hint_gating_attempts',value:'1'});
  if(state==='POPULATED'){
   // The paging fixture intentionally imports130 participants; default capacity is100.
   const denied=await mutate(learner,'register',{});
   assert.deepEqual(denied,{status:403,body:{error:'CTF participant limit reached'}});
   const expanded=await mutate(admin,'config_mutation',{key:'ctf_max_participants',value:'200'});
   assert.equal(expanded.status,200,'canonical instructor capacity change must be acknowledged');
  }
  const registered=await mutate(learner,'register',{});assert.equal(registered.status,200);assert(registered.body.sessionToken);
  const started=await mutate(learner,'start',{stageId:'1'});assert.equal(started.status,200);assert.equal(started.body.stage.id,1);
  const stateBefore=await runtime.read({kind:'status',req:learner});assert.equal(stateBefore.registered,true);
  assert((await runtime.read({kind:'stages',req:learner})).stages.length>0);
  assert((await runtime.adminSolutions({req:admin})).levels.length>0);
  const preview=await runtime.previewCapture({req:admin,stageId:1});assert(preview.stage.success_criteria);assert.equal(await runtime.previewRevalidate({lease:preview.lease}),true);
  for(const kind of ['adminStages','adminAttempts','adminParticipants','analytics'])assert(await runtime.read({kind,req:admin}));
  await assert.rejects(runtime.read({kind:'adminAttempts',req:learner}),/ADMIN_REQUIRED/);
  assert.deepEqual((await runtime.heartbeat({req:learner})).body,{status:'ok'});
  const heartbeatId=randomUUID(),heartbeat=await runtime.heartbeat({req:learner,operationId:heartbeatId,registrationToken:registered.body.sessionToken});
  const heartbeatDone=heartbeat.status===202?await runtime.heartbeat({req:learner,operationId:heartbeatId,registrationToken:registered.body.sessionToken}):heartbeat;assert.deepEqual(heartbeatDone.body,{status:'ok'});
  assert.equal((await one(c.runtime,'SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token=$1',[registered.body.sessionToken])).total_active_time,1000);
  await runtime.heartbeat({req:learner,operationId:heartbeatId,registrationToken:registered.body.sessionToken});
  assert.equal((await one(c.runtime,'SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token=$1',[registered.body.sessionToken])).total_active_time,1000);
  // Real persistent graph rows, but not mounted coordinator admission proof.
  const originalToken=registered.body.sessionToken;
  secret=(await one(c.runtime,'SELECT success_criteria FROM ctf.ctf_stages WHERE id=1')).success_criteria;
  async function waitApplied(id){const until=Date.now()+5000;for(let n=0;n<100&&Date.now()<until;n++){const row=await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[id]);if(row?.state==='applied')return;await new Promise(r=>setTimeout(r,20));}assert.fail('decision projection deadline');}
  async function attempt(payload,nextMode){
   mode=nextMode;const owner=await one(i.runtime,"SELECT generation::text FROM graph_runtime.owners WHERE owner_key='[\"CTF\",\"2001\"]'");
   const runId=randomUUID();await i.migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,'[\"CTF\",\"2001\"]',$2,'running')",[runId,owner.generation]);
   const execution={runId,ownerKey:'["CTF","2001"]',ownerId:'2001',signal:new AbortController().signal,async check(){const row=await one(i.runtime,'SELECT r.status,g.generation::text FROM graph_runtime.runs r JOIN graph_runtime.owners g USING(owner_key) WHERE r.run_id=$1',[runId]);assert.equal(row.status,'running');assert.equal(row.generation,owner.generation);}};
   const input={req:learner,runId,execution,request:{runId,stageId:'1',payload,registrationToken:originalToken}};
   let pending=await runtime.attempt(input);
   for(let n=0;!pending.body.decisionId&&n<3;n++)pending=await runtime.attempt({req:learner,runId,execution});
   assert.equal(pending.status,202);assert(pending.body.decisionId,'must retain durable decision reference');
   await waitApplied(pending.body.decisionId);
   const response=await runtime.publishDecision({req:learner,decisionId:pending.body.decisionId});
   const diagnostic=await one(i.runtime,'SELECT canonical_diagnostics,diagnostics_hash FROM identity.ctf_response_diagnostics WHERE proposal_id=$1',[runId]);
   assert(diagnostic);assert.equal(sha(diagnostic.canonical_diagnostics),diagnostic.diagnostics_hash);
   const proposal=await one(i.runtime,'SELECT canonical_evidence FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[runId]);
   const judgeReceipt=JSON.parse(JSON.parse(proposal.canonical_evidence).judgeReceipt);
   t.diagnostic(JSON.stringify({phase:'current-response',state,mode,nextMode,status:response.status,verdict:judgeReceipt.verdict,errorCode:judgeReceipt.errorCode??null,judgeAttempts:judgeReceipt.attempts??null,providerCalls:ledger.length,actualModelProof:false}));
   const observation=JSON.parse(diagnostic.canonical_diagnostics);assert(Number.isSafeInteger(observation.responseTimeMs));
   const calls=ledger.length;const replay=await runtime.attempt({req:learner,runId,execution});assert.equal(replay.body.decisionId,pending.body.decisionId);assert.equal(ledger.length,calls,'durable recovery must not rerun provider');
   assert.deepEqual(await runtime.publishDecision({req:learner,decisionId:pending.body.decisionId}),response);
   return{id:pending.body.decisionId,response,observation};
  }
  const failed=await attempt('ordinary question','fail');assert.equal(failed.response.status,200);assert.equal(failed.response.body.success,false);assert.equal(failed.response.body.judgment.verdict,'fail');
  const down=await attempt('provider outage question','guardian-unavailable');assert.equal(down.response.status,503);assert.equal(down.response.body.retryable,true);assert.equal(down.observation.guardianUnavailable,true);
  const judgeDown=await attempt('grading outage question','judge-unavailable');assert.equal(judgeDown.response.status,200);assert.equal(judgeDown.response.body.judgment.verdict,'unavailable');assert.equal(judgeDown.response.body.aiResponse,secret);assert.equal(judgeDown.observation.guardianUnavailable,false);assert.equal(judgeDown.response.body.success,false);
  await mutate(admin,'catalog_mutation',{action:'update',stageId:'1',fields:{adaptive_mode:'hybrid'}});
  const technique=await attempt('base64 encode ordinary text','fail');assert.equal(technique.response.body.success,false);
  const retained=(await i.runtime.query("SELECT technique_tag FROM identity.ctf_adaptive_memory WHERE kind='technique' AND owner_id=2001 AND stage_id=1 ORDER BY memory_id")).rows.map(r=>r.technique_tag);assert(retained.length>0);
  await mutate(admin,'blocklist_clear',{memory:'payload',stageId:'1'});
  const afterClear=await attempt('hex decode 0x1234 ordinary text','fail');for(const tag of retained)assert(afterClear.response.body.usedTechniques.includes(tag));
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=1001 ORDER BY id')).rows,siblingBefore);
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001 ORDER BY id')).rows,siblingAttempts);
  const passed=await attempt('an unrelated ordinary question','pass');assert.equal(passed.response.status,200);assert.equal(passed.response.body.success,true,'synthetic disposable credit only');
  const otherSession=await userRequest(2001);await assert.rejects(runtime.publishDecision({req:otherSession,decisionId:passed.id}));
  publicationQueries=0;publicationBarrier=async()=>{
   const session={actorId:'1002',sessionId:String(admin.identitySession.id),rawToken:admin.headers.authorization.slice(7)};
   const prepared=await require('../../server/services/ctfAuthorityPrepare').createCtfAuthorityPrepare({repository:require('../../server/database/postgres/ctfAuthorityRequestRepository').createCtfAuthorityRequestRepository(i.migration)})({kind:'owner_reset',input:{ownerId:'2001'},session});
   await require('../../server/database/postgres/ctfLifecycleRepository').createCtfLifecycleRepository(i.migration).enqueue({...session,operationId:randomUUID(),kind:'owner_reset',...prepared});
  };
  await assert.rejects(runtime.publishDecision({req:learner,decisionId:passed.id}));assert.equal(publicationQueries,2,'reset must occur after private reader authorization');
  const drain=Date.now()+5000;while(Date.now()<drain){if(!(await one(i.runtime,"SELECT 1 AS n FROM identity.ctf_outbox WHERE state='pending' LIMIT 1")))break;await new Promise(r=>setTimeout(r,20));}
  await mutate(learner,'register',{});await mutate(learner,'start',{stageId:'1'});
  // Use a different payload technique after reset; old locator cannot gain new authority.
  const final=await attempt('a different ordinary inquiry','fail');
  publicationQueries=0;publicationBarrier=()=>require('../../server/database/postgres/identityRepository').createIdentityRepository(i.migration).revokeSession(learner.headers.authorization.slice(7),2001,'fixture_mid_publication_logout');
  await assert.rejects(runtime.publishDecision({req:learner,decisionId:final.id}));assert.equal(publicationQueries,2,'logout must occur after private reader authorization');
  assert(stageLossObserved,'real diagnostics COMMIT response loss exercised');
  assert.equal((await one(i.runtime,'SELECT count(*)::int AS n FROM identity.ctf_response_diagnostics')).n,7);
  t.diagnostic(JSON.stringify({state,controlledProvider:true,actualModelProof:false,calls:ledger.length}));
  // Supported identity-first maintenance pauses polling; explicit start must
  // revalidate and resume without recreating cursor/history or provider work.
  await operator.revokeForMaintenance();
  const deadline=Date.now()+3000;while(runtime.status().worker.state==='running'&&Date.now()<deadline)await new Promise(r=>setTimeout(r,10));
  assert.equal(runtime.status().worker.state,'paused');
  await operator.resumeAfterMaintenance({activationId,transferId:randomUUID()});
  await runtime.start();assert.equal(runtime.status().worker.state,'running');assert.equal((await runtime.readiness()).runtimeReady,true);
  await identityAuth.revokeSession(learner.headers.authorization.slice(7),2001,'fixture_logout');
  await assert.rejects(runtime.heartbeat({req:learner}),e=>e.code==='SESSION_REVOKED'&&e.statusCode===401);
  const stopped=await runtime.stop();assert.equal(stopped.drained,true);await assert.rejects(runtime.heartbeat({req:learner}),/UNAVAILABLE/);
  for(const pool of [i.runtime,c.runtime,delivery])assert.equal((await one(pool,'SELECT 1 AS n')).n,1,'factory does not close injected pools');
  assert(!ledger.some(x=>x.failure));
 }
});
