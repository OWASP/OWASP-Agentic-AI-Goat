'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http'),{spawn}=require('node:child_process'),{once}=require('node:events'),{randomUUID,createHash}=require('node:crypto');
const {runSetupDatabasePhase}=require('../../scripts/install/setup-database-phase');
const {provisionApplication,provisioningPlan}=require('../../db/postgres/provision-application');
const {createOwnedChildren,waitForChild,networkGuardSource}=require('../fixtures/fullBackendBootControls');
const enabled=process.env.CTF_SETUP_APPLICATION_ISOLATED==='1';
const ownedRegistry=new Map();
function publishOwnedRegistry(){
 if(!enabled)return;
 const base=process.env.SETUP_PHASE_EVIDENCE_ROOT,target=path.join(base,'nested-processes.json'),temporary=target+'.next';
 require('node:fs').writeFileSync(temporary,JSON.stringify({owner:process.env.SETUP_PHASE_OWNER,parentPid:process.pid,groups:[...ownedRegistry.values()]}),{mode:0o600});require('node:fs').renameSync(temporary,target);
}
function registerGroup(pid,id){
 if(!Number.isInteger(pid)||pid<=1)throw Error('Invalid owned group');
 let birth;try{birth=require('node:child_process').execFileSync('/bin/ps',['-p',String(pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim();}catch{if(groupAbsent(pid))return;throw Error('Owned group birth unavailable');}
 ownedRegistry.set(id,{pid,id,birth});publishOwnedRegistry();
}
function retireGroup(pid,id){if(groupAbsent(pid)&&ownedRegistry.get(id)?.pid===pid){ownedRegistry.delete(id);publishOwnedRegistry();}}
function trackPhaseChild(child){
 const id=randomUUID();child.once('spawn',()=>registerGroup(child.pid,id));child.once('close',()=>retireGroup(child.pid,id));
 child.on('message',m=>{if(m.type==='child'&&m.grouped)registerGroup(m.pid,m.id);if(m.type==='child-closed')retireGroup(m.pid,m.id);});return child;
}

function groupAbsent(pid){try{process.kill(-pid,0);return false;}catch(error){if(error.code==='ESRCH')return true;throw error;}}
test('clean setup activation and real index CTF/deletion composition',{skip:!enabled,timeout:process.env.SETUP_PHASE_SCENARIO==='ctf-populated'?1800000:1680000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');const scenario=process.env.SETUP_PHASE_SCENARIO;assert(['ctf-fresh','ctf-populated'].includes(scenario));
 const root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.SETUP_PHASE_EVIDENCE_ROOT);assert.equal(root,await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(root),evidence);
 const admin=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(admin.hostname,'127.0.0.1');assert.equal(admin.pathname,'/postgres');
 const home=path.join(evidence,'home'),directory=path.join(home,'.dvaia',createHash('sha256').update(root).digest('hex').slice(0,12));await fs.mkdir(directory,{recursive:true,mode:0o700});
 const guard=path.join(evidence,'ctf-network-guard.cjs');await fs.writeFile(guard,networkGuardSource({host:'127.0.0.1',port:admin.port}),{mode:0o600});
 const env={PATH:process.env.PATH,HOME:home,NODE_ENV:'test',PG_TLS:'disable',PG_POOL_BUDGET:'78',MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',XENOVA_CACHE:path.join(root,'tests/fixtures/fullBackendModelCache'),LOGS_DIR:path.join(evidence,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(evidence,'teaching'),DVAIA_APP_DATA_ROOT:path.join(evidence,'app-data'),NODE_OPTIONS:`--require=${guard}`};
 for(const folder of [env.LOGS_DIR,env.LEGACY_SENSITIVE_FILES_ROOT,env.DVAIA_APP_DATA_ROOT])await fs.mkdir(folder,{recursive:true,mode:0o700});
 const manifestPath=path.join(directory,'provisioning.json'),provisioned=await provisionApplication({adminUrl:admin.href,manifestPath,env});assert.equal(provisioned.plan.length,16);
 const owned=createOwnedChildren(spawn),state={scenario,passed:false,actualModel:false,abruptRecoveryQualified:false,fullIndex:false,storeLifecycleCoverage:null},clients=[];let logIndex=0;
 const record=()=>fs.writeFile(path.join(evidence,'ctf-setup-result.json'),JSON.stringify(state,null,2)+'\n',{mode:0o600});
 const context={root,directory,homeDirectory:home,envPath:path.join(root,'.env'),id:path.basename(directory),platform:process.platform,databaseAdminUrl:admin.href,appDataRoot:env.DVAIA_APP_DATA_ROOT,processEnvironment:env,config:provisioned.configuration,runtime:{browser:{}},requestedEmailProvider:'gmail',localMailpit:null};
 const launch=async(file,environment,args=[])=>{const log=await fs.open(path.join(evidence,`ctf-child-${logIndex++}.log`),'wx',0o600);try{return owned.launch(process.execPath,[file,...args],{cwd:root,env:environment,stdio:['ignore',log.fd,log.fd]});}finally{await log.close();}};
 const phase=request=>runSetupDatabasePhase(request,{}, {timeoutMs:180000,killGraceMs:5000,signal:t.signal,spawn:(...args)=>trackPhaseChild(spawn(...args))});
 const privateSnapshot=async()=>Promise.all(['administrator.json','ctf-delivery.json','ctf-authority.json'].map(async name=>[name,await fs.readFile(path.join(directory,name))]));
 async function upgrade(config){const prior=await require('../../scripts/application-upgrade').inspectUpgradeState({envPath:context.envPath,manifestPath,currentPlan:provisioningPlan()});await phase({kind:'upgrade',context:{...context,manifestPath,state:prior,appDataEnvironment:{...env,...config}}});}
 async function start(config,extra={}){
  const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r));
  const child=await launch('server/index.js',{...env,...config,...extra,PORT:String(port),SS_ENABLE:'false',AI_PROVIDER:extra.AI_PROVIDER||'mock',OLLAMA_BASE_URL:extra.OLLAMA_BASE_URL||'http://127.0.0.1:1'}),base=`http://127.0.0.1:${port}`;
  const until=Date.now()+90000;let ready=false;while(Date.now()<until){t.signal.throwIfAborted();if(child.exitCode!==null)throw Error('CTF_INDEX_EXITED');try{const r=await fetch(base+'/api/monitoring/ping',{signal:AbortSignal.timeout(1000)});if(r.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,200));}assert(ready,'actual index readiness');state.fullIndex=true;
  return{base,stop:()=>owned.stop(child)};
 }
 try{
  if(scenario==='ctf-fresh'){
   await phase({kind:'fresh',context});const config=require('dotenv').parse(await fs.readFile(context.envPath)),before=await privateSnapshot(),envBefore=await fs.readFile(context.envPath);await upgrade(config);await upgrade(config);
   assert((await fs.readFile(context.envPath)).equals(envBefore),'no-op preserves private env');for(const [name,bytes]of before)assert((await fs.readFile(path.join(directory,name))).equals(bytes),`no-op preserves ${name}`);
   const app=await start(config);try{
    const credentials=JSON.parse(await fs.readFile(path.join(directory,'administrator.json'),'utf8'));
    const request=async(url,body,token)=>{const r=await fetch(app.base+url,{method:body?'POST':'GET',headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(10000)});return{status:r.status,body:await r.json()};};
    const login=await request('/api/auth/login',{username:credentials.username,password:credentials.password});assert.equal(login.status,200);assert.equal(typeof login.body.token,'string');const token=login.body.token;
    const db=new(require('pg').Client)({connectionString:config.IDENTITY_MIGRATION_DATABASE_URL});clients.push(db);await db.connect();
    const beforeCount=(await db.query('SELECT count(*)::integer AS n FROM identity.ctf_outbox')).rows[0].n;
    for(const key of ['ctf_enabled','ctf_visible_to_students','ctf_registration_open'])assert.equal((await request('/api/ctf/admin/config',{key,value:'true'},token)).status,200);
    const registered=await request('/api/ctf/register',{displayName:'Owned setup administrator'},token);assert.equal(registered.status,200);assert(Number.isInteger(registered.body.participantId));
    const stages=await request('/api/ctf/stages',null,token);assert.equal(stages.status,200);assert(stages.body.stages.length>0);
    assert.equal((await request(`/api/ctf/stage/${stages.body.stages[0].id}/start`,{},token)).status,200);
    const rows=(await db.query('SELECT state FROM identity.ctf_outbox ORDER BY sequence')).rows;assert(rows.length>beforeCount,'actual authority commands admitted');assert(rows.every(r=>r.state==='applied'),'actual authority ACKs applied');
    state.authorityMutations=true;
   }finally{await app.stop();}
   state.noop=true;
  }else{
   // Genuine pre-cutover legacy state, initialized under the supported maintenance owner.
   const config={...provisioned.configuration,PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
   const publication=require('../../scripts/lib/setup-environment-publication').prepareFreshEnvironmentPublication({root,directory,id:context.id,envPath:context.envPath,environment:config});publication.publish();Object.assign(config,publication.environment);
   const init=await launch('db/postgres/initialize-application.js',{...env,...config});assert.equal(await waitForChild(init,{timeoutMs:180000,signal:t.signal}),0);
   const teaching=await launch('server/database/sensitiveInfoFiles.js',{...env,...config},['--initialize-missing']);assert.equal(await waitForChild(teaching,{timeoutMs:30000,signal:t.signal}),0);
   Object.assign(process.env,env,config,{CTF_SETUP_APPLICATION_ISOLATED:'1'});
   state.storeLifecycleCoverage=await require('../fixtures/ctfSetupPopulatedDeletion').runPopulatedDeletion({signal:t.signal,activateAndStart:async({subject,subjectSession,adminSession,providerUrl})=>{
    await upgrade(config);const active=require('dotenv').parse(await fs.readFile(context.envPath));await upgrade(active);
    const extras=Object.fromEntries(['SS_PERSONA_INBOX_READY','SS_MCP_TRUST_READY','SS_CONTROLLED_SSRF_READY','SS_MCP_TRUST_FIXTURE_ROOT','SS_CONTROLLED_SSRF_FIXTURE_ROOT','SANDBOX_RUNNER_URL','MAILPIT_API_URL','MCP_BACKEND_TIMEOUT_MS','MCP_OWNED_TARGET_URL','MCP_OWNED_TARGET_TOKEN','MCP_OWNED_RESOURCES_ENABLED','CODEBOT_OWNED_EXECUTION_ENABLED','CODEBOT_SANDBOX_RUNNER_URL','MAILPIT_SMTP_HOST','MAILPIT_SMTP_PORT'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
    const sidecar=new URL(extras.SANDBOX_RUNNER_URL),mainGuard=path.join(evidence,'ctf-main-network-guard.cjs');await fs.writeFile(mainGuard,networkGuardSource({host:'127.0.0.1',port:admin.port},{version:1,services:[{name:'fixture_lifecycle',host:'127.0.0.1',port:Number(sidecar.port)},{name:'fixture_mail_api',host:'127.0.0.1',port:Number(new URL(extras.MAILPIT_API_URL).port)},{name:'fixture_smtp',host:'127.0.0.1',port:Number(extras.MAILPIT_SMTP_PORT)},{name:'model',host:'127.0.0.1',port:Number(new URL(providerUrl).port)}]}),{mode:0o600});extras.NODE_OPTIONS=`--require=${mainGuard} --require=${path.join(root,'tests/fixtures/ctfSetupLostCommit.cjs')}`;extras.CTF_SETUP_APPLICATION_ISOLATED='1';extras.SETUP_PHASE_EVIDENCE_ROOT=evidence;extras.AI_PROVIDER='ollama';extras.OLLAMA_BASE_URL=providerUrl;extras.OLLAMA_MODEL='llama3.1:8b';
    const app=await start(active,extras);
    for(const key of ['ctf_enabled','ctf_visible_to_students','ctf_registration_open']){const configured=await fetch(app.base+'/api/ctf/admin/config',{method:'POST',headers:{authorization:`Bearer ${adminSession.token}`,'content-type':'application/json'},body:JSON.stringify({key,value:'true'}),signal:AbortSignal.any([t.signal,AbortSignal.timeout(10000)])});assert.equal(configured.status,200,'authenticated CTF configuration');}
    const response=await fetch(app.base+'/api/ctf/status',{headers:{authorization:`Bearer ${subjectSession.token}`},signal:AbortSignal.timeout(5000)});assert.equal(response.status,200);assert.equal((await response.json()).registered,true);
    return {...app,restart:()=>start(active,extras)};
   }});
  }
  state.passed=true;
 }catch(error){state.failure={name:error.name,code:typeof error.code==='string'?error.code:null};throw error;}
 finally{const outcomes=await require('../fixtures/ctfSetupQualificationControls').boundedCleanup([()=>owned.cleanup(),...clients.map(c=>()=>c.end())]);state.cleanupComplete=outcomes.every(r=>r.status==='fulfilled');await record();if(!state.cleanupComplete)throw Error('CTF_SETUP_OWNED_CLEANUP_FAILED');}
});
