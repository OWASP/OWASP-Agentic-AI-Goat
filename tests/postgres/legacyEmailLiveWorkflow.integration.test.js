'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const enabled=process.env.RUN_LIVE_LEGACY_EMAIL_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
test('Legacy email actual actor and signature browser proof through native receipt',{skip:!enabled,timeout:240000},async t=>{
 if(!process.env.LEGACY_EMAIL_LIVE_ISOLATED){
  const root=path.resolve(__dirname,'../..'),copy=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-legacyemail-live-'));
  try{
   for(const dir of ['server','db','tests'])fs.cpSync(path.join(root,dir),path.join(copy,dir),{recursive:true,filter:file=>{const rel=path.relative(root,file);if(/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(rel))return false;return fs.statSync(file).isDirectory()||/\.(?:js|json|sql)$/.test(file);}});
   fs.symlinkSync(path.join(root,'node_modules'),path.join(copy,'node_modules'),'dir');
   const {spawn}=require('node:child_process');await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--test',path.join(copy,'tests/postgres/legacyEmailLiveWorkflow.integration.test.js')],{cwd:copy,env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR||os.tmpdir(),RUN_LIVE_LEGACY_EMAIL_WORKFLOW:'1',PG_TEST_DISPOSABLE:'yes',PG_LIVE_ADMIN_URL:process.env.PG_LIVE_ADMIN_URL,LEGACY_EMAIL_LIVE_ISOLATED:'1',DPI_LIVE_DIAGNOSTIC:process.env.DPI_LIVE_DIAGNOSTIC||'',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b',JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(copy,'logs')},stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`Isolated probe exited ${code}`)));
   });
  }finally{fs.rmSync(copy,{recursive:true,force:true});}return;
 }
 const Module=require('node:module'),original=Module._load;Module._load=function(name,...args){if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Working SQLite import forbidden');return original.call(this,name,...args);};
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['postgres:','postgresql:'].includes(adminUrl.protocol));assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 assert.ok((await(await fetch('http://127.0.0.1:11434/api/tags')).json()).models.some(m=>m.name==='llama3.1:8b'));
 const admin=new Pool({connectionString:adminUrl.href}),name=`dvaia_test_legacyemaillive_${process.pid}`,pools=[];let server;const finName=name+'_xss';
 try{
  await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
  const pool=role=>{const u=new URL(adminUrl);u.pathname='/'+name;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const runtime=pool('dvaia_identity_runtime'),migration=pool('dvaia_identity_migration');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),user=await identity.createUser({username:'dpi-live',email:'dpi-live@example.invalid',passwordHash:await require('bcryptjs').hash('fixture',4)});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  await admin.query(`CREATE DATABASE ${finName} OWNER dvaia_xss_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${finName} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${finName} TO dvaia_xss_runtime`);
  const finPool=role=>{const u=new URL(adminUrl);u.pathname='/'+finName;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const finRuntime=finPool('dvaia_xss_runtime'),finMigration=finPool('dvaia_xss_migration');process.env.XSS_WORKSHOP_DATABASE_URL=finRuntime.options.connectionString;
  await require('../../server/database/postgres/xssWorkshopDb').createXssWorkshopDb(finRuntime).initializeXssWorkshopDb(finMigration);
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:'dvaia-secret-key-2024'}),session=await adapter.createSession(await identity.findCredentialById(user.id),{get:()=>null,ip:'127.0.0.1'});
  const graders=[];const graderModule=require('../../server/services/xssEmailObjectiveGrader'),createGrader=graderModule.createXssEmailObjectiveGrader;
  graderModule.createXssEmailObjectiveGrader=(...args)=>{const grader=createGrader(...args);graders.push(grader);return grader;};
  const app=require('express')();app.use(require('express').json());app.use(require('../../server/middleware/adminAuth').authenticateToken);app.use(require('../../server/routes/xssEmail'));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`,headers={'content-type':'application/json',authorization:`Bearer ${session.token}`};
  try {
   const profile=await fetch(base+'/profile/'+user.id,{headers});assert.equal(profile.status,200);
   const signature='<img src=x onerror="alert(2)">';
   const update=await fetch(base+'/profile/'+user.id,{method:'PUT',headers,body:JSON.stringify({full_name:'Synthetic Alice',email_address:'alice@example.invalid',company_name:'Example',job_title:'Analyst',signature_html:signature,signature_plain:'Alice'})});assert.equal(update.status,200);
   const response=await fetch(base+'/generate',{method:'POST',headers,body:JSON.stringify({prompt:'Write a short friendly business greeting in HTML using my profile placeholders.',templateType:'general',includeSignature:true})});const body=await response.json();t.diagnostic(JSON.stringify({status:response.status,actual:body}));assert.equal(response.status,200);
   assert.ok(body.completedLevels.includes(2));assert.equal(body.judgments.find(j=>j.level===2).verdict,'pass');
   const rows=(await finRuntime.query('SELECT verdict,browser_executed FROM xss.xss_email_judge_receipts WHERE user_id=$1',[user.id])).rows;assert.ok(rows.some(row=>row.verdict==='pass'&&row.browser_executed));
   const progressRows=(await finRuntime.query('SELECT * FROM xss.xss_challenge_progress WHERE user_id=$1',[user.id])).rows;assert.ok(progressRows.length>0);
   const reset=await fetch(base+'/challenge/reset',{method:'POST',headers});assert.equal(reset.status,200);assert.equal((await finRuntime.query('SELECT count(*)::int n FROM xss.xss_challenge_progress WHERE user_id=$1',[user.id])).rows[0].n,0);
  } finally {
   const closed=await Promise.allSettled(graders.map(grader=>grader.close()));graderModule.createXssEmailObjectiveGrader=createGrader;
   const failures=closed.filter(result=>result.status==='rejected').map(result=>result.reason);if(failures.length)throw new AggregateError(failures,'Browser grader cleanup failed');
  }
 }finally{
  Module._load=original;
  if(server)await new Promise(resolve=>server.close(resolve));
  const closed=await Promise.allSettled([require('../../server/database/postgres').closePostgresPools(),...pools.map(p=>p.end())]);
  const cleanupFailures=closed.filter(result=>result.status==='rejected').map(result=>result.reason);
  for(const database of [finName,name])try{await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);}catch(error){cleanupFailures.push(error);}
  try{await admin.end();}catch(error){cleanupFailures.push(error);}
  if(cleanupFailures.length)throw new AggregateError(cleanupFailures,'XSS live workflow cleanup failed');
 }
});
