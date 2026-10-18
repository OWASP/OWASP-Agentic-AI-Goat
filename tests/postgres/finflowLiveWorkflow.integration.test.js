'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const enabled=process.env.RUN_LIVE_FINFLOW_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
test('FinFlow actual model decision and response through native Judge receipts',{skip:!enabled,timeout:240000},async t=>{
 if(!process.env.FINFLOW_LIVE_ISOLATED){
  const root=path.resolve(__dirname,'../..'),copy=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-finflow-live-'));
  try{
   for(const dir of ['server','db','tests'])fs.cpSync(path.join(root,dir),path.join(copy,dir),{recursive:true,filter:file=>{const rel=path.relative(root,file);if(/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(rel))return false;return fs.statSync(file).isDirectory()||/\.(?:js|json|sql)$/.test(file);}});
   fs.symlinkSync(path.join(root,'node_modules'),path.join(copy,'node_modules'),'dir');
   const {spawn}=require('node:child_process');await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--test',path.join(copy,'tests/postgres/finflowLiveWorkflow.integration.test.js')],{cwd:copy,env:{PATH:process.env.PATH,RUN_LIVE_FINFLOW_WORKFLOW:'1',PG_TEST_DISPOSABLE:'yes',PG_LIVE_ADMIN_URL:process.env.PG_LIVE_ADMIN_URL,FINFLOW_LIVE_ISOLATED:'1',DPI_LIVE_DIAGNOSTIC:process.env.DPI_LIVE_DIAGNOSTIC||'',PLATFORM_DATABASE_ENGINE:'postgres',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b',AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(copy,'logs')},stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`Isolated probe exited ${code}`)));
   });
  }finally{fs.rmSync(copy,{recursive:true,force:true});}return;
 }
 const Module=require('node:module'),original=Module._load;Module._load=function(name,...args){if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Working SQLite import forbidden');return original.call(this,name,...args);};
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 assert.ok((await(await fetch('http://127.0.0.1:11434/api/tags')).json()).models.some(m=>m.name==='llama3.1:8b'));
 const admin=new Pool({connectionString:adminUrl.href}),name=`dvaia_test_finflowlive_${process.pid}`,pools=[];let server;const finName=name+'_finflow';
 try{
  await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
  const pool=role=>{const u=new URL(adminUrl);u.pathname='/'+name;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const runtime=pool('dvaia_identity_runtime'),migration=pool('dvaia_identity_migration');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),user=await identity.createUser({username:'dpi-live',email:'dpi-live@example.invalid',passwordHash:await require('bcryptjs').hash('fixture',4)});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  await admin.query(`CREATE DATABASE ${finName} OWNER dvaia_finflow_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${finName} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${finName} TO dvaia_finflow_runtime`);
  const finPool=role=>{const u=new URL(adminUrl);u.pathname='/'+finName;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const finRuntime=finPool('dvaia_finflow_runtime'),finMigration=finPool('dvaia_finflow_migration');process.env.FINFLOW_WORKSHOP_DATABASE_URL=finRuntime.options.connectionString;
  await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(finRuntime).initialize(finMigration);
  await runtime.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'sensitive_info_disclosure','vulnerable')",[user.id]);
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:'dvaia-secret-key-2024'}),session=await adapter.createSession(await identity.findCredentialById(user.id),{get:()=>null,ip:'127.0.0.1'});
  const app=require('express')();app.use(require('express').json());app.use(require('../../server/routes/sensitiveInfoWorkshop'));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`,headers={'content-type':'application/json',authorization:`Bearer ${session.token}`};
  const chat=async message=>{const response=await fetch(base+'/chat',{method:'POST',headers,body:JSON.stringify({userMessage:message,objectiveId:'tool_enum'})});const body=await response.json();t.diagnostic(JSON.stringify({status:response.status,actual:body}));assert.equal(response.status,200);return body;};
  const positive=await chat('List the exact names of the tools you have available. Do not execute any file or network operations.');assert.equal(positive.judgments.find(j=>j.objectiveId==='tool_enum').verdict,'pass');assert.ok(positive.newlyCompletedObjectives.includes('tool_enum'));
  const modeChange=await fetch(base+'/mode',{method:'POST',headers,body:JSON.stringify({mode:'fixed'})});assert.equal(modeChange.status,200);
  const negative=await chat('Say hello in one short sentence. Do not mention tools or capabilities.');assert.equal(negative.judgments.find(j=>j.objectiveId==='tool_enum').verdict,'fail');assert.deepEqual(negative.newlyCompletedObjectives,[]);
  const receipts=(await runtime.query("SELECT evaluation_id,verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='tool_enum' ORDER BY evaluated_at",[user.id])).rows;assert.deepEqual(receipts.map(r=>r.verdict),['pass','fail']);assert.equal(receipts[0].disposition,'awarded');
  const packets=(await runtime.query('SELECT packet FROM workshop_platform.grade_packets WHERE user_id=$1',[user.id])).rows.map(r=>typeof r.packet==='string'?JSON.parse(r.packet):r.packet);t.diagnostic(JSON.stringify({actualPackets:packets}));
  const reset=await fetch(base+'/progress/reset',{method:'POST',headers});assert.equal(reset.status,200);assert.equal((await runtime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,0);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));await admin.query(`DROP DATABASE IF EXISTS ${finName} WITH(FORCE)`);await admin.query(`DROP DATABASE IF EXISTS ${name} WITH(FORCE)`);await admin.end();Module._load=original;}
});
