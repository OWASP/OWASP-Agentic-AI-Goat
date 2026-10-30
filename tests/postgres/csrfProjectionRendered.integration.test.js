'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID}=require('node:crypto');
test('rendered CSRF baseline and admin parity from controlled canonical projection', {skip:process.env.CSRF_PROJECTION_NATIVE!=='1',timeout:240000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const actual=false;assert.notEqual(process.env.CSRF_TEACHING_ACTUAL,'1');let browser;
 const {Pool}=require('pg'),pools=[],servers=[],runtimes=[],routes=[],auths=[];
 const pool=(key,role,store)=>{const u=new URL(process.env[key]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,store==='identity'?/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/:/^\/owasp_ai_goat_test_csrf_teaching_[a-f0-9]+$/);assert.equal(u.username,`dvaia_${store}_${role}`);const p=new Pool({connectionString:u.href,max:4,statement_timeout:10000});pools.push(p);return p;};
 const migration=pool('WORKSHOP_RAG_MIGRATION_URL','migration','identity'),identityPool=pool('WORKSHOP_RAG_RUNTIME_URL','runtime','identity'),csrfMigration=pool('CSRF_TEACHING_MIGRATION_URL','migration','csrf'),csrfPool=pool('CSRF_TEACHING_RUNTIME_URL','runtime','csrf');
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'csrf-teaching-schema-'));
 const Module=require('node:module'),originalLoad=Module._load;let release;const storeErrors=[];
 try {
  Object.assign(process.env,{PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:process.env.WORKSHOP_RAG_RUNTIME_URL,CSRF_WORKSHOP_DATABASE_URL:process.env.CSRF_TEACHING_RUNTIME_URL,CSRF_WORKSHOP_MIGRATION_DATABASE_URL:process.env.CSRF_TEACHING_MIGRATION_URL,JWT_SECRET:'owned-native-csrf-teaching-secret-over32bytes',AI_PROVIDER:actual?'ollama':'mock'});
  Module._load=function(name,...args){if(name==='sqlite3'||name==='better-sqlite3'||/(?:^|\/)authDb$/.test(name))throw Error('Legacy database forbidden');return originalLoad.call(this,name,...args);};
  const {migrate}=require('../../db/postgres/migrate');
  for(const name of fs.readdirSync('db/postgres/identity-migrations'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/identity-migrations',name),path.join(temporary,name));
  fs.copyFileSync('docs/modernization/drafts/teaching-sessions/0095_teaching_sessions.candidate.sql',path.join(temporary,'0095_teaching_sessions.sql'));await migrate(migration,temporary);assert.deepEqual(await migrate(migration,temporary),[]);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  await migration.query("UPDATE workshop_platform.objectives SET is_enabled=false WHERE workshop_key='csrf_workshop' AND objective_id='csrf_g1'");
  const csrfStore=require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(csrfPool);await csrfStore.initialize(csrfMigration);
  const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
  const password=randomUUID(),hash=await require('bcryptjs').hash(password,4);
  const user=await adapter.repository.createUser({username:'teaching-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:hash});
  const sibling=await adapter.repository.createUser({username:'sibling-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:hash});
  for(const owner of [user,sibling])await identityPool.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'csrf_workshop','vulnerable')",[owner.id]);
  // Exact controlled provider only; the actual graph, argument validation,
  // authority capability, forge, flush, manual-credit gate and DBs are real.
  const ai=require('../../server/services/multiProviderAIService');if(!actual)ai.provider='controlled-native';
  let held=false,entered,decisionCalls=0;const waitEntered=()=>new Promise(resolve=>{entered=resolve;});
  const noLease=async()=>assert.equal((await identityPool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name='csrf-teaching-effect' AND xact_start IS NOT NULL")).rows[0].n,0,'model work must not hold effect SQL lease');
  if(!actual)ai.chatWithTools=async messages=>{await noLease();decisionCalls++;if(held){entered();await new Promise(resolve=>{release=resolve;});}const {message}=JSON.parse(messages[1].content);const email=/email="([^"]+)"/.exec(message)[1];return {content:JSON.stringify({intent:'attack',action:'change_email',vector:'direct_get',defenseOn:false,params:{email}}),provider:'controlled-fixture',model:'no-model-called'};};
  if(!actual)ai.generateResponse=async()=>{await noLease();return {response:'Controlled narration of the observed isolated effect.'};};
  const express=require('express');
  const start=async()=>{
   const effectPool=pool('WORKSHOP_RAG_RUNTIME_URL','runtime','identity');effectPool.options.application_name='csrf-teaching-effect';
   const runtime=require('../../server/services/teachingSessionRuntime').createTeachingSessionRuntime({adapter,effectPool});runtimes.push(runtime);await runtime.initialize();
   for(const method of ['get','set','touch','destroy']){const original=runtime.store[method].bind(runtime.store);runtime.store[method]=(...args)=>{const callback=args.pop();return original(...args,(error,value)=>{if(error)storeErrors.push({method,code:error.code||null,statusCode:error.statusCode||null});callback(error,value);});};}
   const routePath=require.resolve('../../server/routes/csrfWorkshop');delete require.cache[routePath];const route=require(routePath);routes.push(route);
   const app=express();app.use(runtime.middleware);app.use(express.json());app.use(express.urlencoded({extended:true}));
   const pass=(_q,_s,n)=>n();const auth=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});auths.push(auth);app.use('/auth',auth);
   app.use(route.configureTeachingSessions(runtime));
   const stores=await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
   const parity=await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({app,adapter,pool:identityPool,migration,progress:stores.progress,config:stores.config,identity:adapter.repository});auths.push(parity);
   app.use('/api/solutions',require('../../server/routes/solutions'));app.use('/api/hints',require('../../server/routes/hints'));
   app.use('/api/workshop',async(req,res,next)=>{try {const match=/^Bearer (.+)$/.exec(req.headers.authorization||'');const found=match&&await adapter.validateSession(match[1]);if(!found)return res.sendStatus(401);req.user=found.user;req.identitySession=found.session;next();}catch{res.sendStatus(401);}});
   app.use('/api/workshop/csrf',route);app.use((error,_req,res,_next)=>{if(!res.headersSent)res.status(error.statusCode||503).json({error:'Controlled route unavailable'});});
   const server=app.listen(0,'127.0.0.1');servers.push(server);await new Promise(resolve=>server.once('listening',resolve));return {origin:'http://127.0.0.1:'+server.address().port,route,parity};
  };
  const one=await start(),two=one;
  const login=async owner=>{const r=await fetch(one.origin+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:owner.username,password})});assert.equal(r.status,200);return {cookie:r.headers.get('set-cookie').split(';')[0],...(await r.json())};};
  const auth=await login(user),siblingAuth=await login(sibling);assert.equal(typeof auth.token,'string');
  const request=(suffix,options={})=>fetch(two.origin+'/api/workshop/csrf'+suffix,{...options,signal:AbortSignal.timeout(actual?90000:10000)});
  const attack=email=>'/agent-action?'+new URLSearchParams({tab:'get',message:`change email email="${email}"`});
  const state=owner=>csrfStore.getVictimState('csrf_'+owner.id);
  assert.equal((await request('/victim-state',{headers:{cookie:auth.cookie}})).status,401);
  assert.equal((await request('/victim-state',{headers:{authorization:'Bearer '+auth.token,cookie:auth.cookie}})).status,200);
  assert.equal((await request('/victim-state',{headers:{authorization:'Bearer '+siblingAuth.token,cookie:siblingAuth.cookie}})).status,200);
  const siblingBefore=await state(sibling);
  await migration.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='csrf_workshop'");
  await migration.query("UPDATE workshop_platform.exercises SET is_visible=(workshop_key='csrf_workshop')");
  // Explicit controlled projection only; this is not model-earned completion.
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'csrf_workshop','csrf_g2')",[user.id]);
  await csrfPool.query("INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,'csrf_g2')",[String(user.id)]);
  const title=(await migration.query("SELECT challenge_name FROM workshop_platform.exercises WHERE workshop_key='csrf_workshop'")).rows[0].challenge_name;
  const getObjectiveCount=(await migration.query("SELECT count(*)::int n FROM workshop_platform.objectives WHERE workshop_key='csrf_workshop' AND catalog_active=true AND is_enabled=true AND objective_id LIKE 'csrf_g%'")).rows[0].n;
  const proof=await require('../fixtures/csrfFullAppProjection').qualifyCsrfProjection({backendPort:new URL(two.origin).port,token:auth.token,adminToken:two.parity.adminToken,studentId:user.id,title,getObjectiveCount,runtimeRoot:path.dirname(process.env.WORKSHOP_RAG_EVIDENCE_PATH)});
  assert.equal(decisionCalls,0);assert.deepEqual(await state(sibling),siblingBefore);
  fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify(proof,null,2));
 } finally {
  await browser?.close();release?.();await Promise.all(servers.map(server=>new Promise(resolve=>server.close(resolve))));await Promise.all(routes.map(route=>route.closeBrowser()));await Promise.all(runtimes.map(runtime=>runtime.close()));for(const auth of auths)await auth.close?.();await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));Module._load=originalLoad;fs.rmSync(temporary,{recursive:true,force:true});
 }
});
