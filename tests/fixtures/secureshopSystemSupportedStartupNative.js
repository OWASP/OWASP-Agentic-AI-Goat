'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const {spawn,spawnSync}=require('node:child_process');
const {once}=require('node:events');
const {workspaceId}=require('../../scripts/application-data-root');
const {writeLocalDockerAuthority}=require('../../scripts/local-docker-authority');
const {provision,_internals}=require('../../scripts/install/secureshop-owned-system-provision');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const {networkGuardSource}=require('./fullBackendBootControls');
const root=fs.realpathSync(path.resolve(__dirname,'../..')),out=fs.realpathSync(process.env.SYSTEM_PROVISION_NATIVE_OUT);
assert.equal(process.env.SYSTEM_PROVISION_NATIVE,'1');assert.equal(root,path.join(out,'source'));
const home='/Users/averma5',id=workspaceId(root),directory=path.join(home,'.owasp-ai-goat',id),host='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';
const state={version:1,status:'preparing',workspaceId:id,privateDirectory:directory,containers:[],children:[],ownedProcessGroups:[],outerEgressIsolationEstablished:false};
const persist=()=>fs.writeFileSync(path.join(out,'fixture-result.json'),JSON.stringify(state,null,2)+'\n');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const run=_internals.createRunner({cwd:root,env:process.env});
const docker=async args=>{const r=await run('docker',['--host',host,...args],{timeoutMs:35000,maxOutputBytes:1048576});assert.equal(r.exitCode,0,'owned Docker request');return r.stdout;};
const inspect=async(kind,name)=>JSON.parse(await docker([kind,'inspect',name]))[0];
const port=()=>new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const n=s.address().port;s.close(()=>resolve(n));});});
const delay=ms=>new Promise(r=>setTimeout(r,ms));let sequence=0;const active=[];
function collect(){
 const probe=spawnSync('ps',['-axo','pid=,ppid=,pgid=,uid='],{encoding:'utf8',timeout:3000});assert.equal(probe.status,0);
 const rows=probe.stdout.trim().split('\n').map(r=>r.trim().split(/\s+/).map(Number)).filter(r=>r[0]!==probe.pid);
 const owned=new Set([process.pid]);let changed=true;while(changed){changed=false;for(const r of rows)if(owned.has(r[1])&&!owned.has(r[0])){owned.add(r[0]);changed=true;}}
 for(const [pid,ppid,pgid,uid]of rows)if(owned.has(pid)){assert.equal(uid,process.getuid());if(pgid===pid&&!state.ownedProcessGroups.includes(pgid))state.ownedProcessGroups.push(pgid);}
 persist();return rows.filter(r=>owned.has(r[0]));
}
function launch(file,args,env){const logPath=path.join(out,`${sequence++}-${path.basename(file)}.log`),fd=fs.openSync(logPath,'wx',0o600);let c;try{c=spawn(file,args,{cwd:root,env,stdio:['ignore',fd,fd],detached:false});}finally{fs.closeSync(fd);}c.logPath=logPath;active.push(c);state.children.push(c.pid);persist();return c;}
async function wait(c,ms=30000){const until=Date.now()+ms;while(c.exitCode===null&&c.signalCode===null){collect();if(Date.now()>until)throw Error('owned child deadline');await delay(100);}return c.exitCode;}
async function command(file,args,env,ms=30000){const c=launch(file,args,env);assert.equal(await wait(c,ms),0,`owned command failed: ${path.basename(c.logPath)}`);return fs.readFileSync(c.logPath,'utf8');}
async function closed(p){await new Promise((resolve,reject)=>{const s=net.connect({host:'127.0.0.1',port:p});s.setTimeout(1000);s.once('connect',()=>{s.destroy();reject(Error('owned port remains'));});s.once('error',e=>e.code==='ECONNREFUSED'?resolve():reject(e));s.once('timeout',()=>{s.destroy();reject(Error('owned port timeout'));});});}
(async()=>{let pool;try{
 fs.mkdirSync(directory,{mode:0o700});const stat=fs.lstatSync(directory);state.privateIdentity={dev:stat.dev,ino:stat.ino};persist();
 const authority={version:1,workspaceId:id,host,daemonId:JSON.parse((await docker(['info','--format','{{json .ID}}'])).trim()),source:'environment-host',platform:'darwin'};await writeLocalDockerAuthority({directory,authority});
 const runtime=path.join(out,'runtime');fs.mkdirSync(runtime,{mode:0o700});
 const ports=[];for(let i=0;i<5;i++){let p;do{p=await port();}while(ports.includes(p));ports.push(p);}const [configPort,diagnosticPort,backendPort,clientPort,agentPort]=ports;
 const plan=await require('../../scripts/install/secureshop-owned-system').plan({root,home,platform:'darwin',architecture:'arm64',configPort,diagnosticPort});
 Object.assign(state,{authoritySha256:plan.dockerAuthoritySha256,sourceSha256:plan.source.sha256,imageTag:`owasp-ai-goat-owned-system-${id}:local`,network:`owasp-ai-goat-owned-system-${id}-bridge`,containers:[plan.config.container,plan.diagnostic.container]});persist();
 const result=await provision({root,home,architecture:'arm64',configPort,diagnosticPort});state.imageId=result.imageId;state.containerIds={};for(const n of state.containers)state.containerIds[n]=(await inspect('container',n)).Id;persist();
 const adminUrl=process.env.SYSTEM_STARTUP_PG_ADMIN_URL;assert.ok(adminUrl&&new URL(adminUrl).hostname==='127.0.0.1');
 const provisioning=await require('../../db/postgres/provision-application').provisionApplication({adminUrl,manifestPath:path.join(directory,'provisioning.json')});assert.equal(provisioning.plan.length,16);
 const reset=require('../../scripts/lib/setup-password-reset-key').ensurePasswordResetKey({directory});
 const env={...provisioning.configuration,PATH:process.env.PATH,HOME:home,TMPDIR:out,NODE_ENV:'test',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PG_TEST_DISPOSABLE:'yes',PG_ADMIN_DATABASE_URL:adminUrl,
  SS_ENABLE:'true',SS_AUDIT_SUMMARY_ENABLED:'false',SS_ENABLE_REAL_MCP_SPAWN:'false',MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',AI_PROVIDER:'mock',OLLAMA_BASE_URL:'http://127.0.0.1:1',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',EVENT_GATE_ENABLED:'false',JWT_SECRET:crypto.randomBytes(48).toString('hex'),SESSION_SECRET:crypto.randomBytes(48).toString('hex'),LANGCHAIN_TRACING_V2:'false',LANGSMITH_TRACING:'false',SS_PASSWORD_RESET_KEY_PATH:reset.filePath,PORT:String(backendPort),OWASP_AI_GOAT_CLIENT_PORT:String(clientPort),SS_AGENT_HOST_PORT:String(agentPort),SS_ALLOWED_ORIGINS:`http://127.0.0.1:${backendPort}`,SECURESHOP_REVIEW_RENDERER_ROOT:path.join(root,'client/build/secureshop-review-renderer'),OWASP_AI_GOAT_APP_DATA_ROOT:path.join(runtime,'app-data'),LOGS_DIR:path.join(runtime,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(runtime,'legacy-sensitive-files'),HF_HOME:path.join(runtime,'hf-cache'),NPM_CONFIG_UPDATE_NOTIFIER:'false'};
 for(const key of ['OWASP_AI_GOAT_APP_DATA_ROOT','LOGS_DIR','LEGACY_SENSITIVE_FILES_ROOT','HF_HOME'])fs.mkdirSync(env[key],{mode:0o700});
 await require('../../scripts/install/secureshop-qualified-local-lib').provision({root,home,enabled:true});
 const guard=path.join(runtime,'network-guard.js');fs.writeFileSync(guard,networkGuardSource({host:'127.0.0.1',port:Number(new URL(adminUrl).port)},{version:1,services:[{name:'agent_host',host:'127.0.0.1',port:agentPort},{name:'fixture_config',host:'127.0.0.1',port:configPort},{name:'fixture_diagnostic',host:'127.0.0.1',port:diagnosticPort},{name:'fixture_backend',host:'127.0.0.1',port:backendPort},{name:'fixture_frontend',host:'127.0.0.1',port:clientPort}]}),{mode:0o600});
 const spawnEvents=path.join(runtime,'spawn-events.jsonl');
 fs.appendFileSync(guard,`\nconst cp=require('node:child_process'),fs=require('node:fs'),spawn=cp.spawn;cp.spawn=function(command,args,options){const child=spawn.call(this,command,args,options);fs.appendFileSync(${JSON.stringify(spawnEvents)},JSON.stringify({pid:child.pid,parent:process.pid,kind:Array.isArray(args)&&args.includes('server/index.js')?'backend':Array.isArray(args)&&args.includes('client')?'frontend':'other'})+'\\n');return child;};\n`);
 const events=()=>fs.existsSync(spawnEvents)?fs.readFileSync(spawnEvents,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
 const childEnv={...env,NODE_OPTIONS:`--max-old-space-size=1024 --require=${guard}`};
 await command(process.execPath,['server/database/sensitiveInfoFiles.js','--initialize-missing'],childEnv);
 await command(process.execPath,['db/postgres/initialize-application.js'],childEnv,180000);
 const {Pool}=require('pg');pool=new Pool({connectionString:env.IDENTITY_DATABASE_URL,max:2});
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool);const password=crypto.randomBytes(24).toString('base64url')+'Aa1!';const user=await users.createUser({username:'system-start-'+id,email:id+'@example.invalid',passwordHash:await require('bcryptjs').hash(password,4)});
 await pool.query("UPDATE workshop_platform.exercises SET is_visible=true,updated_at=clock_timestamp() WHERE workshop_key='secureshop_agent_security' AND catalog_active=true");
 const snapshot=async()=>{const m=JSON.parse(fs.readFileSync(path.join(directory,'provisioning.json')));const ledgers=[];for(const row of m.plan){const p=new Pool({connectionString:m.configuration[row.migrationVariable],max:1});try{const tables=await p.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname='dvaia_migrations' AND tablename='ledger' ORDER BY schemaname,tablename");assert.equal(tables.rows.length,1);const entries=[];for(const t of tables.rows){assert.match(t.schemaname,/^[a-z_]+$/);assert.match(t.tablename,/^[a-z_]+$/);entries.push({table:t.schemaname+'.'+t.tablename,rows:(await p.query(`SELECT * FROM ${t.schemaname}.${t.tablename}`)).rows.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)))});}ledgers.push({schema:row.schema,entries});}finally{await p.end();}}return sha(JSON.stringify(ledgers));};
 const ledgerBefore=await snapshot();
 const {encodeEnv}=require('../../scripts/setup-application');fs.writeFileSync(path.join(root,'.env'),encodeEnv(env),{mode:0o600,flag:'wx'});
 const envHash=sha(fs.readFileSync(path.join(root,'.env'))),manifestHash=sha(fs.readFileSync(path.join(directory,'provisioning.json')));
 // No System flags or credentials in parent environment: activation is loaded
 // from the actual newly-created managed record by supported startup.
 const cliEnv={PATH:process.env.PATH,HOME:home,TMPDIR:out,PG_ADMIN_DATABASE_URL:adminUrl,NODE_OPTIONS:'--max-old-space-size=1024',MCP_SIDECARS_AUTOSTART:'false',AWS_EC2_METADATA_DISABLED:'true',NPM_CONFIG_UPDATE_NOTIFIER:'false'};
 await command(process.execPath,['scripts/setup-application.js','--upgrade','--owned-system'],cliEnv,300000);
 assert.equal(sha(fs.readFileSync(path.join(root,'.env'))),envHash);assert.equal(sha(fs.readFileSync(path.join(directory,'provisioning.json'))),manifestHash);assert.equal(await snapshot(),ledgerBefore);
 const managedBytes=sha(fs.readFileSync(path.join(directory,managed.FILE)));assert.equal(managed.load({filePath:path.join(directory,managed.FILE)}).enabled,true);
 const stateBefore=fs.readdirSync(directory).sort();const planOutput=await command('/bin/bash',['start_all.sh','--plan'],cliEnv);assert.deepEqual(fs.readdirSync(directory).sort(),stateBefore);assert.equal(sha(fs.readFileSync(path.join(root,'.env'))),envHash);for(const secret of [password,...Object.values(provisioning.configuration),managed.load({filePath:path.join(directory,managed.FILE)}).config.token,managed.load({filePath:path.join(directory,managed.FILE)}).diagnostic.token])assert.ok(!planOutput.includes(secret));state.planNoSecretOrWrites=true;
 const req=async(url,token,body,extra={})=>{const r=await fetch(`http://127.0.0.1:${backendPort}`+url,{method:body===undefined?'GET':'POST',headers:{...(token?{authorization:'Bearer '+token}:{}),...(body===undefined?{}:{'content-type':'application/json'}),...extra},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});return{status:r.status,body:await r.json()};};
 state.cycles=[];
 for(let cycle=0;cycle<2;cycle++){
  const c=launch('/bin/bash',['start_all.sh'],{...cliEnv,NODE_OPTIONS:childEnv.NODE_OPTIONS});const deadline=Date.now()+180000;
  while(true){collect();assert.equal(c.exitCode,null,'launcher exited before readiness');const text=fs.readFileSync(c.logPath,'utf8');if(text.includes(`http://localhost:${clientPort}/`)||text.includes(`http://127.0.0.1:${clientPort}/`)){try{if((await req('/api/monitoring/ping')).status===200)break;}catch{}}
   if(Date.now()>deadline)throw Error('supported startup deadline');await delay(200);
  }
  const tree=collect();assert.ok(tree.length>=4);state.cycles.push({launcherPid:c.pid,observedProcessCount:tree.length,backendAndFrontendReady:true});persist();
  const login=await req('/api/auth/login',null,{username:user.username,password});assert.equal(login.status,200);const issued=await req('/api/auth/secureshop-launch',login.body.token,{});assert.equal(issued.status,201);const header={'x-owasp-ai-goat-secureshop-launch':issued.body.bearer};const persona=await req('/api/secureshop/v2/auth/login',login.body.token,{username:'student_admin',password:'student123'},header);assert.equal(persona.status,200);
  assert.equal((await req('/api/secureshop/admin/system/config-read',persona.body.token,undefined,header)).status,200);assert.equal((await req('/api/secureshop/admin/system/diagnostic',persona.body.token,undefined,header)).status,200);const health=await req('/api/secureshop/admin/system/health',persona.body.token,undefined,header);assert.equal(health.status,200);
  // Stop command needs its random controller socket; it is trusted and separately
  // invoked without the database-only test network guard.
  await command('/bin/bash',['stop_all.sh'],cliEnv,30000);assert.equal(await wait(c,30000),0);for(const p of [backendPort,clientPort,agentPort])await closed(p);assert.ok(!fs.existsSync(path.join(directory,'launcher.json')));
  for(const n of state.containers){const info=await inspect('container',n);assert.equal(info.Id,state.containerIds[n]);assert.equal(info.State.Running,true);}assert.equal(sha(fs.readFileSync(path.join(directory,managed.FILE))),managedBytes);
 }
 const beforeConflict=events().length;const conflict=launch('/bin/bash',['start_all.sh'],{...cliEnv,NODE_OPTIONS:childEnv.NODE_OPTIONS,SS_BOUND_SYSTEM_CONFIG_ENABLED:'false'});assert.notEqual(await wait(conflict,30000),0);for(const p of [backendPort,clientPort,agentPort])await closed(p);assert.ok(!fs.existsSync(path.join(directory,'launcher.json')));
 assert.equal(events().length,beforeConflict);assert.equal(events().filter(e=>e.kind==='backend').length,2);assert.equal(events().filter(e=>e.kind==='frontend').length,2);
 await docker(['stop','--time','25',state.containers[1]]);
 const beforeUnavailable=events().length;const unavailable=launch('/bin/bash',['start_all.sh'],{...cliEnv,NODE_OPTIONS:childEnv.NODE_OPTIONS});assert.notEqual(await wait(unavailable,30000),0);assert.equal(events().length,beforeUnavailable);for(const p of [backendPort,clientPort,agentPort])await closed(p);
 await provision({root,home,architecture:'arm64',configPort,diagnosticPort,reconcileEnabled:true});assert.equal(sha(fs.readFileSync(path.join(directory,managed.FILE))),managedBytes);
 assert.equal(await snapshot(),ledgerBefore);assert.equal((await pool.query('SELECT id FROM identity.users WHERE id=$1',[user.id])).rowCount,1);
 state.proof={realSetupUpgradeCli:true,realStartStopCycles:2,all16MigrationLedgersPreserved:true,representativeUserPreserved:true,privateEnvironmentAndManifestPreserved:true,sidecarsAndCredentialsPreserved:true,explicitConflictBeforeChildren:true,unavailableBeforeChildren:true,realBackendSpawns:2,realFrontendSpawns:2,noModelOrBrowser:true};state.status='passed';persist();
 }catch(e){state.status='failed';state.errorCode=e.code||e.name;state.errorMessage=String(e.message).replace(/postgres(?:ql)?:\/\/[^\s]+/g,'[REDACTED]');persist();process.exitCode=1;}
 finally{for(const c of active)if(c.exitCode===null&&c.signalCode===null)c.kill('SIGTERM');if(pool)await pool.end();state.fixtureTerminal=true;persist();}
})().catch(e=>{state.status='failed';state.errorCode=e.code||e.name;persist();process.exitCode=1;});
