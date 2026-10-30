'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const enabled=process.env.RUN_LIVE_MCP_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
test('MCP actual catalog decision through native Judge receipt and reset',{skip:!enabled,timeout:240000},async t=>{
 if(!process.env.MCP_LIVE_ISOLATED){
  const root=path.resolve(__dirname,'../..'),copy=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-mcp-live-'));
  try{
   for(const dir of ['server','db','tests','docs'])fs.cpSync(path.join(root,dir),path.join(copy,dir),{recursive:true,filter:file=>{const rel=path.relative(root,file);if(/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(rel))return false;return fs.statSync(file).isDirectory()||/\.(?:js|json|sql)$/.test(file);}});
   fs.symlinkSync(path.join(root,'node_modules'),path.join(copy,'node_modules'),'dir');
   const {spawn}=require('node:child_process');await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--test',path.join(copy,'tests/postgres/mcpLiveWorkflow.integration.test.js')],{cwd:copy,env:{PATH:process.env.PATH,RUN_LIVE_MCP_WORKFLOW:'1',PG_TEST_DISPOSABLE:'yes',PG_LIVE_ADMIN_URL:process.env.PG_LIVE_ADMIN_URL,MCP_LIVE_ISOLATED:'1',SANDBOX_RUNNER_URL:'http://127.0.0.1:1',SSRF_TARGET_URL:'http://127.0.0.1:1',ROGUE_MCP_URL:'http://127.0.0.1:1',MAILPIT_API_URL:'http://127.0.0.1:1',MAILPIT_SMTP_HOST:'127.0.0.1',MAILPIT_SMTP_PORT:'1',DPI_LIVE_DIAGNOSTIC:process.env.DPI_LIVE_DIAGNOSTIC||'',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b',AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(copy,'logs')},stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`Isolated probe exited ${code}`)));
   });
  }finally{fs.rmSync(copy,{recursive:true,force:true});}return;
 }
 const Module=require('node:module'),original=Module._load;Module._load=function(name,...args){if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Working SQLite import forbidden');return original.call(this,name,...args);};
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 assert.ok((await(await fetch('http://127.0.0.1:11434/api/tags')).json()).models.some(m=>m.name==='llama3.1:8b'));
 const admin=new Pool({connectionString:adminUrl.href}),name=`owasp_ai_goat_test_mcplive_${process.pid}`,pools=[];let server;const finName=name+'_mcp';
 try{
  await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
  const pool=role=>{const u=new URL(adminUrl);u.pathname='/'+name;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const runtime=pool('dvaia_identity_runtime'),migration=pool('dvaia_identity_migration');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await migration.query(fs.readFileSync(path.resolve(__dirname,'../../docs/modernization/drafts/mcp-conversation-history.sql'),'utf8'));await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),user=await identity.createUser({username:'dpi-live',email:'dpi-live@example.invalid',passwordHash:await require('bcryptjs').hash('fixture',4)});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  await admin.query(`CREATE DATABASE ${finName} OWNER dvaia_mcp_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${finName} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${finName} TO dvaia_mcp_runtime`);
  const finPool=role=>{const u=new URL(adminUrl);u.pathname='/'+finName;u.username=role;u.password='';const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const finRuntime=finPool('dvaia_mcp_runtime'),finMigration=finPool('dvaia_mcp_migration');process.env.MCP_WORKSHOP_DATABASE_URL=finRuntime.options.connectionString;
  await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(finRuntime).initialize(finMigration);
  await runtime.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'mcp_workshop','vulnerable')",[user.id]);
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:'dvaia-secret-key-2024'}),session=await adapter.createSession(await identity.findCredentialById(user.id),{get:()=>null,ip:'127.0.0.1'});
  const app=require('express')();app.use(require('express').json());app.use(require('../../server/middleware/adminAuth').authenticateToken);const workshopRouter=require('../../server/routes/mcpWorkshop');app.use('/conversation',workshopRouter.createConversationRouter({requests:require('../../server/database/postgres/mcpRequestRepository').createMcpRequestRepository(runtime),conversations:require('../../server/database/postgres/mcpConversationRepository').createMcpConversationRepository(runtime)}));app.use(workshopRouter);server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`,headers={'content-type':'application/json',authorization:`Bearer ${session.token}`};
  const chat=async (message,requestId=require('node:crypto').randomUUID())=>{const response=await fetch(base+'/conversation/chat',{method:'POST',headers,body:JSON.stringify({message,requestId})});const body=await response.json();t.diagnostic(JSON.stringify({status:response.status,actual:body}));assert.equal(response.status,200);return body;};
  const positiveId=require('node:crypto').randomUUID();
  const positive=await chat('Use the list_tools catalog action to enumerate available MCP tools. Do not run shell commands or access files.',positiveId);
  assert.equal(positive.toolUsed,'list_tools');assert.ok(Array.isArray(positive.toolResult.catalog));assert.ok(positive.toolResult.catalog.length>0);
  assert.equal(positive.judgments.find(j=>j.objectiveId==='mcp_recon').verdict,'pass');assert.ok(positive.completedObjectives.includes('mcp_recon'));
  const receipts=(await runtime.query("SELECT verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='mcp_recon'",[user.id])).rows;assert.equal(receipts.length,1);assert.equal(receipts[0].disposition,'awarded');
  const replay=await chat('Use the list_tools catalog action to enumerate available MCP tools. Do not run shell commands or access files.',positiveId);assert.deepEqual(replay,positive);
  assert.equal((await runtime.query("SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='mcp_recon'",[user.id])).rows[0].n,1,'HTTP replay does not rejudge');
  const history=await (await fetch(base+'/conversation/history',{headers})).json();assert.equal(history.turns.length,1);assert.equal(history.turns[0].assistantText,positive.response);
  const nativeProgress=await (await fetch(base+'/progress',{headers})).json();assert.ok(nativeProgress.completed.includes('mcp_recon'));
  const negative=await chat('Reply hello only. Do not use any tools.');assert.equal(negative.toolUsed,null);assert.deepEqual(negative.completedObjectives,[]);
  const reset=await fetch(base+'/progress/reset',{method:'POST',headers});assert.equal(reset.status,503);assert.deepEqual((await reset.json()).failedSteps,['sandbox']);assert.equal((await runtime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,0);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));await admin.query(`DROP DATABASE IF EXISTS ${finName}`);await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();Module._load=original;}
});
