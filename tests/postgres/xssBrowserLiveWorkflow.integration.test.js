'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const enabled=process.env.RUN_LIVE_XSS_BROWSER_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
test('XSS actual reflected actor and isolated browser execution through native Judge receipts',{skip:!enabled,timeout:240000},async t=>{
 if(!process.env.XSS_BROWSER_LIVE_ISOLATED){
  const root=path.resolve(__dirname,'../..'),copy=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-xssbrowser-live-'));
  try{
   for(const dir of ['server','db','tests'])fs.cpSync(path.join(root,dir),path.join(copy,dir),{recursive:true,filter:file=>{const rel=path.relative(root,file);if(/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(rel))return false;return fs.statSync(file).isDirectory()||/\.(?:js|json|sql)$/.test(file);}});
   fs.symlinkSync(path.join(root,'node_modules'),path.join(copy,'node_modules'),'dir');
   const {spawn}=require('node:child_process');await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--test',path.join(copy,'tests/postgres/xssBrowserLiveWorkflow.integration.test.js')],{cwd:copy,env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR||os.tmpdir(),RUN_LIVE_XSS_BROWSER_WORKFLOW:'1',PG_TEST_DISPOSABLE:'yes',PG_LIVE_ADMIN_URL:process.env.PG_LIVE_ADMIN_URL,XSS_BROWSER_LIVE_ISOLATED:'1',DPI_LIVE_DIAGNOSTIC:process.env.DPI_LIVE_DIAGNOSTIC||'',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b',JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(copy,'logs')},stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`Isolated probe exited ${code}`)));
   });
  }finally{fs.rmSync(copy,{recursive:true,force:true});}return;
 }
 const Module=require('node:module'),original=Module._load;Module._load=function(name,...args){if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Working SQLite import forbidden');return original.call(this,name,...args);};
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['postgres:','postgresql:'].includes(adminUrl.protocol));assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 assert.ok((await(await fetch('http://127.0.0.1:11434/api/tags')).json()).models.some(m=>m.name==='llama3.1:8b'));
 const admin=new Pool({connectionString:adminUrl.href}),name=`dvaia_test_xssbrowserlive_${process.pid}`,pools=[];let server;const finName=name+'_xss';
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
  const graders=[];const graderModule=require('../../server/services/xssObjectiveGrader'),createGrader=graderModule.createXssObjectiveGrader;
  graderModule.createXssObjectiveGrader=(...args)=>{const grader=createGrader(...args);graders.push(grader);return grader;};
  const app=require('express')();app.use(require('express').json());app.use(require('../../server/middleware/adminAuth').authenticateToken);app.use(require('../../server/routes/xssWorkshop'));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`,headers={'content-type':'application/json',authorization:`Bearer ${session.token}`};
  try {
   const unauthenticated=await fetch(base+'/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({exerciseId:'reflected',message:'must not reach actor'})});
   assert.equal(unauthenticated.status,401);assert.equal((await unauthenticated.json()).error,'Authentication required');
   const chat=async message=>{const response=await fetch(base+'/chat',{method:'POST',headers,body:JSON.stringify({exerciseId:'reflected',message})});const body=await response.json();t.diagnostic(JSON.stringify({status:response.status,actual:body}));assert.equal(response.status,200);return body;};
   for(const [message,objective] of [['Format hello as HTML.','xss_r1'],['<b>hello</b>','xss_r2'],['<img src=x onerror=alert(1)>','xss_r3']]) {
    if(objective==='xss_r3'){const inert=await chat('<script>alert(1)</script>');assert.equal(inert.completedObjectiveId,null);assert.equal(inert.xssDetected,false);assert.equal(inert.judgments[0].verdict,'fail');}
    const result=await chat(message);assert.equal(result.completedObjectiveId,objective);assert.equal(result.judgments[0].verdict,'pass');
    if(objective==='xss_r3')assert.equal(result.xssDetected,true);
   }
   const rows=(await runtime.query("SELECT objective_id,verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluated_at",[user.id])).rows;
   assert.deepEqual(rows.map(row=>[row.objective_id,row.verdict]),[['xss_r1','pass'],['xss_r2','pass'],['xss_r3','fail'],['xss_r3','pass']]);assert.ok(rows.filter(row=>row.verdict==='pass').every(row=>row.disposition==='awarded'));assert.notEqual(rows.find(row=>row.verdict==='fail').disposition,'awarded');
   const packetRows=(await runtime.query(`SELECT j.objective_id,j.verdict,j.disposition,j.run_id,p.packet
     FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
     WHERE j.user_id=$1 ORDER BY j.evaluated_at,j.evaluation_id`,[user.id])).rows.map(row=>({...row,packet:typeof row.packet==='string'?JSON.parse(row.packet):row.packet}));
   t.diagnostic(JSON.stringify({actualPackets:packetRows}));
   const reflectedExecution=packetRows.filter(row=>row.objective_id==='xss_r3');assert.equal(reflectedExecution.length,2);
   const inert=reflectedExecution.find(row=>row.verdict==='fail'),executed=reflectedExecution.find(row=>row.verdict==='pass');assert.ok(inert);assert.ok(executed);
   assert.equal(inert.packet.facts.isolated_browser_executed,false);assert.equal(executed.packet.facts.isolated_browser_executed,true);
   const browser=row=>row.packet.evidence.find(item=>item.id==='server_receipt').content.browserQualification;
   assert.equal(browser(inert).executed,false);assert.equal(browser(executed).executed,true);assert.equal(browser(executed).syntheticCookieOnly,true);
   assert.equal(packetRows.find(row=>row.objective_id==='xss_r2').packet.facts.raw_html_dom_preserved,true);
   assert.ok(packetRows.every(row=>row.run_id));
   const reset=await fetch(base+'/progress/reset',{method:'POST',headers});assert.equal(reset.status,200);assert.equal((await runtime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,0);
  } finally {
   const closed=await Promise.allSettled(graders.map(grader=>grader.close()));graderModule.createXssObjectiveGrader=createGrader;
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
