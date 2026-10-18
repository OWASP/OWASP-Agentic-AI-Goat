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
const home='/Users/averma5',id=workspaceId(root),directory=path.join(home,'.dvaia',id),host='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock';
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
 const runtime=path.join(out,'runtime');fs.mkdirSync(runtime,{mode:0o700});
 const configPort=await port(),diagnosticPort=await port();await closed(configPort);await closed(diagnosticPort);
 const backendPort=await port(),clientPort=await port(),agentPort=await port();assert.equal(new Set([configPort,diagnosticPort,backendPort,clientPort,agentPort]).size,5);
 const adminUrl=process.env.SYSTEM_STARTUP_PG_ADMIN_URL;assert.equal(new URL(adminUrl).hostname,'127.0.0.1');
 const authority={version:1,workspaceId:id,host,daemonId:JSON.parse((await docker(['info','--format','{{json .ID}}'])).trim()),source:'environment-host',platform:'darwin'};
 const authoritySha256=require('../../scripts/local-docker-authority').authorityDigest(authority),sourceSha256=require('../../scripts/install/secureshop-owned-system').sourceManifest(root).sha256;
 Object.assign(state,{authoritySha256,sourceSha256,imageTag:`dvaia-owned-system-${id}:local`,network:`dvaia-owned-system-${id}-bridge`,containers:[`dvaia-owned-system-${id}-config`,`dvaia-owned-system-${id}-diagnostic`]});persist();
 const guard=path.join(runtime,'network-guard.js'),modelEvents=path.join(out,'model-events.jsonl');
 fs.writeFileSync(guard,networkGuardSource({host:'127.0.0.1',port:Number(new URL(adminUrl).port)},{version:1,services:[{name:'fixture_ollama',host:'127.0.0.1',port:11434},{name:'agent_host',host:'127.0.0.1',port:agentPort},{name:'fixture_config',host:'127.0.0.1',port:configPort},{name:'fixture_diagnostic',host:'127.0.0.1',port:diagnosticPort},{name:'fixture_backend',host:'127.0.0.1',port:backendPort},{name:'fixture_frontend',host:'127.0.0.1',port:clientPort}]}),{mode:0o600});
 fs.appendFileSync(guard,'\nrequire('+JSON.stringify(path.join(root,'tests/fixtures/ownedBrowserCdpAllowance.js'))+').install({browserExecutable:'+JSON.stringify(process.env.SYSTEM_FRESH_BROWSER)+',ownedRoot:'+JSON.stringify(out)+',addEndpoint:e=>policy.services.push(e),removeEndpoint:e=>{const i=policy.services.indexOf(e);if(i>=0)policy.services.splice(i,1)}});\n');
 const guardCode = function(modelEvents) {
  const fs=require('node:fs'),http=require('node:http'),request=http.request;
  http.request=function(url,...args){let parsed;try{parsed=new URL(url);}catch{}
   if(parsed&&Number(parsed.port)===11434){
    if(parsed.pathname!=='/api/generate'||fs.existsSync(modelEvents))throw Error('native model call bound');
    fs.writeFileSync(modelEvents,JSON.stringify({method:'POST',path:parsed.pathname})+'\n',{flag:'wx',mode:0o600});
   }return request.call(this,url,...args);
  };
  const fetch=globalThis.fetch;globalThis.fetch=function(input,options){const u=new URL(typeof input==='string'||input instanceof URL?input:input.url);if(Number(u.port)===11434&&(!['/api/tags','/api/version'].includes(u.pathname)||(options?.method||'GET')!=='GET'))throw Error('native extra model call denied');return fetch.call(this,input,options);};
 };
 fs.appendFileSync(guard,'\n('+guardCode.toString()+')('+JSON.stringify(modelEvents)+');\n');
 const cliEnv={PATH:process.env.PATH,HOME:home,TMPDIR:out,DOCKER_HOST:host,DVAIA_SYSTEM_CONFIG_PORT:String(configPort),DVAIA_SYSTEM_DIAGNOSTIC_PORT:String(diagnosticPort),PG_ADMIN_DATABASE_URL:adminUrl,NODE_OPTIONS:`--max-old-space-size=1024 --require=${guard}`,MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',SS_ENABLE_REAL_MCP_SPAWN:'false',SS_AUDIT_SUMMARY_ENABLED:'false',SS_BOUND_PROMPT_POLICIES_ENABLED:'false',IPI_EMAIL_PROVIDER:'gmail',AWS_EC2_METADATA_DISABLED:'true',LANGCHAIN_TRACING_V2:'false',LANGSMITH_TRACING:'false',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',XENOVA_CACHE:process.env.SYSTEM_FRESH_EMBEDDING_CACHE,PUPPETEER_EXECUTABLE_PATH:process.env.SYSTEM_FRESH_BROWSER,HF_HOME:path.join(runtime,'hf'),NPM_CONFIG_CACHE:path.join(runtime,'npm'),NPM_CONFIG_UPDATE_NOTIFIER:'false',LEGACY_SENSITIVE_FILES_ROOT:path.join(runtime,'synthetic'),DVAIA_APP_DATA_ROOT:path.join(runtime,'app-data'),LOGS_DIR:path.join(runtime,'logs'),PORT:String(backendPort),DVAIA_CLIENT_PORT:String(clientPort),SS_AGENT_HOST_PORT:String(agentPort),SS_ALLOWED_ORIGINS:`http://127.0.0.1:${backendPort}`,SECURESHOP_REVIEW_RENDERER_ROOT:path.join(root,'client/build/secureshop-review-renderer')};
 for(const key of ['HF_HOME','NPM_CONFIG_CACHE','LEGACY_SENSITIVE_FILES_ROOT','DVAIA_APP_DATA_ROOT','LOGS_DIR'])fs.mkdirSync(cliEnv[key],{recursive:true,mode:0o700});
 const before=fs.readdirSync(directory);await command(process.execPath,['scripts/setup-application.js','--plan','--no-install','--qualified-secureshop','--owned-system'],cliEnv);assert.deepEqual(fs.readdirSync(directory),before);assert.ok(!fs.existsSync(path.join(root,'.env')));
 await command(process.execPath,['scripts/setup-application.js','--no-install','--qualified-secureshop','--owned-system'],cliEnv,600000);
 assert.equal(fs.readFileSync(modelEvents,'utf8').trim().split('\n').length,1);
 const env=require('dotenv').parse(fs.readFileSync(path.join(root,'.env'))),credential=JSON.parse(fs.readFileSync(path.join(directory,'administrator.json'))),provisioning=JSON.parse(fs.readFileSync(path.join(directory,'provisioning.json')));assert.equal(provisioning.plan.length,16);
 assert.ok(!fs.existsSync(path.join(directory,'mcp-owned.env')));assert.ok(!fs.existsSync(path.join(directory,'secureshop-qualified.candidate.env')));
 const record=managed.load({filePath:path.join(directory,managed.FILE)});assert.equal(record.enabled,true);assert.equal(record.dockerAuthoritySha256,state.authoritySha256);assert.equal(record.sourceManifestSha256,state.sourceSha256);state.imageId=record.imageId;state.containerIds={};for(const name of state.containers)state.containerIds[name]=(await inspect('container',name)).Id;
 const qualified=require('../../server/services/secureshopQualifiedManagedConfiguration').load({root,home});assert.equal(qualified.SS_BOUND_REVIEWS_ENABLED,'true');state.freshSetupCli=true;persist();
 const {Pool}=require('pg');pool=new Pool({connectionString:env.IDENTITY_DATABASE_URL,max:2});
 const users=await pool.query('SELECT id,username FROM identity.users WHERE username=$1',[credential.username]);assert.equal(users.rowCount,1);const user=users.rows[0],password=credential.password;
 await pool.query("UPDATE workshop_platform.exercises SET is_visible=true,updated_at=clock_timestamp() WHERE workshop_key='secureshop_agent_security' AND catalog_active=true");
 const snapshot=async()=>{const rows=[];for(const item of provisioning.plan){const p=new Pool({connectionString:provisioning.configuration[item.migrationVariable],max:1});try{rows.push({schema:item.schema,rows:(await p.query('SELECT * FROM dvaia_migrations.ledger')).rows.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)))});}finally{await p.end();}}return sha(JSON.stringify(rows));};
 const ledgerBefore=await snapshot(),envHash=sha(fs.readFileSync(path.join(root,'.env'))),manifestHash=sha(fs.readFileSync(path.join(directory,'provisioning.json'))),managedBytes=sha(fs.readFileSync(path.join(directory,managed.FILE))),credentialHash=sha(fs.readFileSync(path.join(directory,'administrator.json')));
 await command(process.execPath,['scripts/setup-application.js','--upgrade','--qualified-secureshop','--owned-system'],cliEnv,180000);
 assert.equal(sha(fs.readFileSync(path.join(root,'.env'))),envHash);assert.equal(sha(fs.readFileSync(path.join(directory,'provisioning.json'))),manifestHash);assert.equal(sha(fs.readFileSync(path.join(directory,'administrator.json'))),credentialHash);
 const repeated=launch(process.execPath,['scripts/setup-application.js','--no-install','--qualified-secureshop','--owned-system'],cliEnv);assert.notEqual(await wait(repeated,30000),0);assert.equal(sha(fs.readFileSync(path.join(root,'.env'))),envHash);
 const req=async(url,token,body,extra={})=>{const r=await fetch(`http://127.0.0.1:${backendPort}`+url,{method:body===undefined?'GET':'POST',headers:{...(token?{authorization:'Bearer '+token}:{}),...(body===undefined?{}:{'content-type':'application/json'}),...extra},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});return{status:r.status,body:await r.json()};};
 state.cycles=[];
 for(let cycle=0;cycle<2;cycle++){
  const c=launch('/bin/bash',['start_all.sh'],cliEnv);const deadline=Date.now()+180000;
  while(true){collect();assert.equal(c.exitCode,null,'launcher exited before readiness');const text=fs.readFileSync(c.logPath,'utf8');if(text.includes(`http://localhost:${clientPort}/`)||text.includes(`http://127.0.0.1:${clientPort}/`)){try{if((await req('/api/monitoring/ping')).status===200)break;}catch{}}
   if(Date.now()>deadline)throw Error('supported startup deadline');await delay(200);
  }
  const tree=collect();assert.ok(tree.length>=4);state.cycles.push({launcherPid:c.pid,observedProcessCount:tree.length,backendAndFrontendReady:true});persist();
  const login=await req('/api/auth/login',null,{username:user.username,password});assert.equal(login.status,200);const issued=await req('/api/auth/secureshop-launch',login.body.token,{});assert.equal(issued.status,201);const header={'x-dvaia-secureshop-launch':issued.body.bearer};const persona=await req('/api/secureshop/v2/auth/login',login.body.token,{username:'student_admin',password:'student123'},header);assert.equal(persona.status,200);
  assert.equal((await req('/api/secureshop/admin/system/config-read',persona.body.token,undefined,header)).status,200);assert.equal((await req('/api/secureshop/admin/system/diagnostic',persona.body.token,undefined,header)).status,200);const health=await req('/api/secureshop/admin/system/health',persona.body.token,undefined,header);assert.equal(health.status,200);
  // Stop command needs its random controller socket; it is trusted and separately
  // invoked without the database-only test network guard.
  await command('/bin/bash',['stop_all.sh'],{...cliEnv,NODE_OPTIONS:'--max-old-space-size=1024'},30000);assert.equal(await wait(c,30000),0);for(const p of [backendPort,clientPort,agentPort])await closed(p);assert.ok(!fs.existsSync(path.join(directory,'launcher.json')));
  for(const n of state.containers){const info=await inspect('container',n);assert.equal(info.Id,state.containerIds[n]);assert.equal(info.State.Running,true);}assert.equal(sha(fs.readFileSync(path.join(directory,managed.FILE))),managedBytes);
 }
 assert.equal(await snapshot(),ledgerBefore);assert.equal(fs.readFileSync(modelEvents,'utf8').trim().split('\n').length,1);
 state.proof={realFreshSetupCli:true,realUpgradeRepeat:true,realStartStopCycles:2,generatedAdministratorLogin:true,all16MigrationLedgersPreserved:true,sidecarsAndCredentialsPreserved:true,setupGenerationCalls:1,prerequisitesPresentOnly:true,noBrowserOrObjectiveCredit:true};state.status='passed';persist();
 }catch(e){state.status='failed';state.errorCode=e.code||e.name;state.errorMessage=String(e.message).replace(/postgres(?:ql)?:\/\/[^\s]+/g,'[REDACTED]');persist();process.exitCode=1;}
 finally{for(const c of active)if(c.exitCode===null&&c.signalCode===null)c.kill('SIGTERM');if(pool)await pool.end();state.fixtureTerminal=true;persist();}
})().catch(e=>{state.status='failed';state.errorCode=e.code||e.name;persist();process.exitCode=1;});
