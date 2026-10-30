'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {createHash,randomUUID}=require('node:crypto'),{spawn}=require('node:child_process'),{Client}=require('pg');
const {runSetupDatabasePhase}=require('../../scripts/install/setup-database-phase');
const {provisionApplication,provisioningPlan}=require('../../db/postgres/provision-application');
const {acquireApplicationMaintenanceLease:acquire}=require('../../server/services/applicationMaintenanceLease');
const {networkGuardSource,waitForChild}=require('../fixtures/fullBackendBootControls');
const {waitForOwnedLeaseRelease}=require('../fixtures/setupDatabasePhaseLeaseBarrier');
const enabled=process.env.SETUP_DATABASE_PHASE_ISOLATED==='1';
const sourceRoot=path.resolve(__dirname,'../..');
const {selectInterruptionCases}=require('../fixtures/setupPhaseInterruptionSelection');
const interruptionCases=enabled?selectInterruptionCases(process.env.SETUP_PHASE_SCENARIO,process.env.SETUP_PHASE_INTERRUPTION_CASE):[];
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

async function deadline(promise,ms=10000){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned process deadline')),ms);})]);}finally{clearTimeout(timer);}}
// All these children use ignored stdout/stderr; exit is reaping, not IPC close.
// Caller deadlines and explicit PID/group/PG-lock checks remain authoritative.
function closed(child){return waitForChild(child,{timeoutMs:30000});}
function message(child,type){return deadline(new Promise((resolve,reject)=>{const on=value=>{if(value.type===type){child.off('message',on);resolve(value);}};child.on('message',on);child.once('close',()=>reject(Error('Child closed before '+type)));}));}
function groupAbsent(pid){try{process.kill(-pid,0);return false;}catch(error){if(error.code==='ESRCH')return true;throw error;}}
async function stopGroup(pid){if(!groupAbsent(pid)){try{process.kill(-pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}for(let n=0;n<250&&!groupAbsent(pid);n++)await new Promise(r=>setTimeout(r,20));assert.equal(groupAbsent(pid),true,'owned group drained');for(const [id,item]of ownedRegistry)if(item.pid===pid)retireGroup(pid,id);}
async function cleanCheckpoint(client,previous){
 const rows=(await client.query('SELECT installation_id,epoch::text,state FROM dvaia_maintenance.control WHERE singleton=true')).rows;
 assert.equal(rows.length,1);const row=rows[0];assert.equal(row.state,'clean');
 if(previous){assert.equal(row.installation_id,previous.installation_id);assert.equal(BigInt(row.epoch),BigInt(previous.epoch)+1n);}
 const epochs=(await client.query('SELECT epoch::text,finished_at FROM dvaia_maintenance.epochs ORDER BY epoch')).rows;
 assert.equal(epochs.length,Number(row.epoch));assert(epochs.every(e=>e.finished_at!==null));return row;
}
async function assertFreshEnvironmentPublication(context, previous){
 const pendingPath=path.join(context.directory,'fresh-environment.pending.json');
 const info=await fs.lstat(pendingPath);
 assert.equal(info.isFile()&&!info.isSymbolicLink()&&info.uid===process.getuid()&&(info.mode&0o777)===0o600&&info.nlink===1,true,'private pending publication ownership and permissions');
 const pendingBytes=await fs.readFile(pendingPath),environmentBytes=await fs.readFile(context.envPath);
 const saved=JSON.parse(pendingBytes.toString('utf8')),parsed=require('dotenv').parse(environmentBytes);
 assert.equal(saved.identity?.kind==='fresh'&&saved.identity?.id===context.id&&saved.identity?.workspace===context.root&&saved.identity?.envPath===context.envPath,true,'pending publication binds owned fresh workspace');
 assert.equal(typeof saved.bytes==='string'&&Buffer.from(saved.bytes).equals(environmentBytes),true,'pending and published environment bytes match');
 assert.equal(Object.keys(parsed).length===Object.keys(saved.environment).length&&Object.entries(parsed).every(([key,value])=>saved.environment[key]===value),true,'pending environment matches parsed publication');
 const secrets=['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET'].map(key=>parsed[key]);
 assert.equal(secrets.every(value=>typeof value==='string'&&/^[a-f0-9]{96}$/.test(value)),true,'generated secrets are present in published configuration');
 await assert.rejects(fs.lstat(path.join(context.root,'.env.setup-publication')),{code:'ENOENT'});
 if(previous){
  assert.equal(pendingBytes.equals(previous.pendingBytes)&&environmentBytes.equals(previous.environmentBytes),true,'upgrade preserves exact private publication artifacts');
  assert.equal(secrets.every((value,index)=>value===previous.secrets[index]),true,'upgrade preserves all generated secrets');
 }
 // Private values stay in memory only; never put them in result diagnostics.
 return {pendingBytes,environmentBytes,secrets};
}
async function cleanEntryBoundary(root,evidence,env){
 const observation=path.join(evidence,'entry-clean-boundary.json');
 const child=spawn(process.execPath,['--require',path.join(sourceRoot,'tests/fixtures/setupDatabasePhaseProcess.cjs'),path.join(sourceRoot,'server/index.js')],{cwd:root,env:{...env,PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',JWT_SECRET:env.JWT_SECRET||randomUUID()+randomUUID(),SETUP_PHASE_CLEAN_ENTRY_OBSERVATION:observation},stdio:'ignore'});
 try{assert.equal(await deadline(closed(child),15000),0);assert.deepEqual(JSON.parse(await fs.readFile(observation,'utf8')),{controlValidated:true,constructionBoundaryReached:true,realServerImported:false});}
 finally{if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await deadline(closed(child));}}
}
function absent(pid){try{process.kill(pid,0);return false;}catch(error){if(error.code==='ESRCH')return true;throw error;}}
test('real setup phase fresh/populated/no-op, lease exclusion and owned cancellation',{skip:!enabled||!['fresh','fresh-success','fresh-interruption'].includes(process.env.SETUP_PHASE_SCENARIO),timeout:600000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const evidence=await fs.realpath(process.env.SETUP_PHASE_EVIDENCE_ROOT);
 const privateInstall=process.env.SETUP_PHASE_INSTALLATION_ROOT;
 const root=await fs.realpath(privateInstall||process.cwd());
 if(privateInstall){
  const relativeEvidence=path.relative(sourceRoot,evidence);assert.equal(relativeEvidence==='..'||relativeEvidence.startsWith('..'+path.sep),true,'private installation must be outside source');
  assert.equal(process.env.SETUP_PHASE_SCENARIO,'fresh-interruption');
  assert.equal(await fs.realpath(process.cwd()),await fs.realpath(sourceRoot));
  assert.equal(await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE),await fs.realpath(sourceRoot));
  assert.equal(path.dirname(root),evidence);assert.equal(path.basename(root),'installation');
  const info=await fs.lstat(privateInstall);assert.equal(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===process.getuid()&&(info.mode&0o777)===0o700,true);
  assert.deepEqual(await fs.readdir(root),[]);
 }else{assert.equal(root,await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(root),evidence);}
 assert.match(path.basename(evidence),/^owasp-ai-goat-setup-phase-/);
 const adminUrl=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(adminUrl.hostname,'127.0.0.1');assert.equal(adminUrl.pathname,'/postgres');
 await assert.rejects(fs.lstat(path.join(root,'.env')),{code:'ENOENT'});
 const home=path.join(evidence,'home'),id=createHash('sha256').update(root).digest('hex').slice(0,12),directory=path.join(home,'.owasp-ai-goat',id);
 await fs.mkdir(directory,{recursive:true,mode:0o700});
 const guard=path.join(evidence,'network-guard.cjs');await fs.writeFile(guard,networkGuardSource({host:'127.0.0.1',port:adminUrl.port}),{mode:0o600});
 const environment={PATH:process.env.PATH,HOME:home,NODE_ENV:'test',PG_TLS:'disable',PG_POOL_BUDGET:'78',MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',LOGS_DIR:path.join(evidence,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(evidence,'teaching'),NODE_OPTIONS:`--require=${guard}`};
 for(const folder of [environment.LOGS_DIR,environment.LEGACY_SENSITIVE_FILES_ROOT,path.join(evidence,'app-data')])await fs.mkdir(folder,{recursive:true,mode:0o700});
 const manifestPath=path.join(directory,'provisioning.json');
 const provisioned=await provisionApplication({adminUrl:adminUrl.href,manifestPath,env:environment});
 assert.equal(provisioned.plan.length,16);
 const env={...environment,...provisioned.configuration},children=new Set(),detachedGroups=new Set(),leases=[],clients=[];
 const state={passed:false,actualModel:false,privatePhaseDispatch:Boolean(privateInstall),sourceRoot,installationRoot:root,productionPhases:[],controlledProcessBarriers:[],leaseReleaseObservations:{},cleanup:{}};
 const persist=()=>fs.writeFile(path.join(evidence,'setup-phase-result.json'),JSON.stringify(state,null,2)+'\n',{mode:0o600});
 const context={root,directory,homeDirectory:home,envPath:path.join(root,'.env'),id,platform:process.platform,databaseAdminUrl:adminUrl.href,appDataRoot:path.join(evidence,'app-data'),processEnvironment:environment,config:provisioned.configuration,runtime:{browser:{}},requestedEmailProvider:'gmail',localMailpit:null};
 const request={kind:'fresh',context};
 function launch(args,options={}){const child=spawn(process.execPath,args,{cwd:root,env,...options});children.add(child);child.on('message',m=>{if(m.type==='child'&&m.grouped&&Number.isInteger(m.pid)){detachedGroups.add(m.pid);registerGroup(m.pid,m.id);}if(m.type==='child-closed'){detachedGroups.delete(m.pid);retireGroup(m.pid,m.id);}});return child;}
 async function phase(request,options={}){return runSetupDatabasePhase(request,{}, {...options,spawn:(file,args,opts)=>{assert.equal(file,process.execPath);if(privateInstall){assert.deepEqual(args,[require.resolve('../../scripts/install/setup-database-phase'),'--owned-phase']);args=[path.join(sourceRoot,'tests/fixtures/setupDatabasePhaseProcess.cjs'),'--private-phase'];}const child=trackPhaseChild(spawn(file,args,opts));children.add(child);child.once('close',()=>children.delete(child));return child;}});}
 async function holder(){const child=launch([path.join(sourceRoot,'tests/fixtures/setupDatabasePhaseProcess.cjs')],{stdio:['ignore','ignore','ignore','ipc']});const ready=message(child,'ready');child.send({mode:'lease',environment:env});await ready;return child;}
 async function stop(child){child.send({type:'cancel'});assert.equal(await deadline(closed(child)),0);children.delete(child);}
 try{
  const a=await holder(),b=await holder();
  const manifestBefore=await fs.readFile(manifestPath);
  await assert.rejects(phase(request,{timeoutMs:30000,killGraceMs:2000}),error=>error.code==='APPLICATION_MAINTENANCE_BUSY');
  await stop(a);await assert.rejects(phase(request,{timeoutMs:30000,killGraceMs:2000}),error=>error.code==='APPLICATION_MAINTENANCE_BUSY');
  assert.deepEqual(await fs.readFile(manifestPath),manifestBefore);await assert.rejects(fs.lstat(context.envPath),{code:'ENOENT'});await stop(b);
  const exclusive=await acquire({mode:'maintenance',env});leases.push(exclusive);
  const observation=path.join(evidence,'entry-denial.json');
  const index=launch(['--require',path.join(sourceRoot,'tests/fixtures/setupDatabasePhaseProcess.cjs'),path.join(sourceRoot,'server/index.js')],{stdio:'ignore',env:{...env,PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',JWT_SECRET:randomUUID()+randomUUID(),SESSION_SECRET:randomUUID()+randomUUID(),SETUP_PHASE_ENTRY_OBSERVATION:observation}});
  assert.notEqual(await deadline(closed(index),15000),0);children.delete(index);
  assert.deepEqual(JSON.parse(await fs.readFile(observation,'utf8')),{code:'APPLICATION_MAINTENANCE_BUSY',serverConstructed:false});await exclusive.close();
  // Controlled pre-phase filesystem failure, not a failed/dirty setup child.
  const journalPath=path.join(directory,'administrator.json');
  await assert.rejects(fs.lstat(journalPath),{code:'ENOENT'});
  const syncFs=require('node:fs'),originalSync=syncFs.fsyncSync;
  let injected=false;
  try{
   syncFs.fsyncSync=function(fd){
    const opened=syncFs.fstatSync(fd),named=syncFs.lstatSync(journalPath);
    if(opened.isFile()&&opened.dev===named.dev&&opened.ino===named.ino){injected=true;throw Object.assign(Error('Controlled journal durability failure'),{code:'EIO'});}
    return originalSync.call(this,fd);
   };
   assert.throws(()=>require('../../scripts/lib/setup-administrator-journal').ensureAdministratorJournal({directory}),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
  }finally{syncFs.fsyncSync=originalSync;}
  assert.equal(injected,true,'the generated administrator file reached the injected fsync boundary');
  const retainedAdministratorBytes=await fs.readFile(journalPath);
  require('../../scripts/lib/setup-administrator-journal').ensureAdministratorJournal({directory});
  assert.equal((await fs.readFile(journalPath)).equals(retainedAdministratorBytes),true,'durability retry preserves generated bytes');
  state.administratorJournal={prePhaseFsyncFailure:true,retainedRetry:true,actualSetupChildFailure:false};
  const fresh=await phase(request,{timeoutMs:300000,killGraceMs:5000});assert.equal(fresh.envPath,context.envPath);state.productionPhases.push('fresh');
  const freshPublication=await assertFreshEnvironmentPublication(context);state.privatePublication={freshVerified:true,upgradeChecks:0,secretValuesLogged:false};
  const config=require('dotenv').parse(await fs.readFile(context.envPath));assert.equal((await fs.stat(context.envPath)).mode&0o777,0o600);
  const credentials=await fs.readFile(path.join(directory,'administrator.json'));
  assert.equal(credentials.equals(retainedAdministratorBytes),true,'real fresh bootstrap consumes the retained administrator journal');
  const identity=new Client({connectionString:config.IDENTITY_MIGRATION_DATABASE_URL});clients.push(identity);await identity.connect();
  let clean=await cleanCheckpoint(identity);state.maintenanceEpochs=[clean.epoch];
  const generatedAdministrator=JSON.parse(credentials.toString('utf8'));
  assert.equal(typeof generatedAdministrator.username==='string'&&typeof generatedAdministrator.email==='string'&&typeof generatedAdministrator.password==='string',true,'owned administrator journal must be complete');
  const administrators=(await identity.query('SELECT id,username,email,role,admin_level,is_active,password FROM identity.users WHERE username=$1 AND email=$2',[generatedAdministrator.username,generatedAdministrator.email])).rows;
  assert.equal(administrators.length,1);assert.equal(administrators[0].role,'super_admin');assert.equal(administrators[0].admin_level,2);assert.equal(administrators[0].is_active,1);
  assert.equal(await require('bcryptjs').compare(generatedAdministrator.password,administrators[0].password),true,'owned generated administrator authenticates');
  const password=await require('bcryptjs').hash(randomUUID(),4);
  const learner=(await identity.query("INSERT INTO identity.users(username,email,password,role) VALUES('setup-sibling','setup-sibling@example.invalid',$1,'student') RETURNING id",[password])).rows[0].id;
  await identity.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,'sql_injection_workshop',now(),now(),17)",[learner]);
  const snapshot=async()=> (await identity.query("SELECT u.username,u.password,t.duration_seconds FROM identity.users u JOIN workshop_platform.time_tracking t ON t.user_id=u.id WHERE u.id=$1",[learner])).rows;
  const before=await snapshot();
  for(let iteration=0;iteration<2;iteration++){
   const upgradeState=await require('../../scripts/application-upgrade').inspectUpgradeState({envPath:context.envPath,manifestPath,currentPlan:provisioningPlan()});
   const result=await phase({kind:'upgrade',context:{...context,manifestPath,state:upgradeState,appDataEnvironment:{...environment,...config}}},{timeoutMs:180000,killGraceMs:5000});
   clean=await cleanCheckpoint(identity,clean);state.maintenanceEpochs.push(clean.epoch);
   await assertFreshEnvironmentPublication(context,freshPublication);state.privatePublication.upgradeChecks++;
   assert.equal(require('node:util').isDeepStrictEqual((await identity.query('SELECT id,username,email,role,admin_level,is_active,password FROM identity.users WHERE username=$1 AND email=$2',[generatedAdministrator.username,generatedAdministrator.email])).rows,administrators),true,'upgrade preserves administrator account identity and password');
   assert.deepEqual(result.upgradedSchemas,[]);assert.deepEqual(await snapshot(),before);assert.equal(createHash('sha256').update(await fs.readFile(path.join(directory,'administrator.json'))).digest('hex'),createHash('sha256').update(credentials).digest('hex'));state.productionPhases.push(iteration?'no-op':'populated-upgrade');
  }
  await cleanEntryBoundary(root,evidence,{...environment,...config});state.cleanEntryBoundary=true;state.fullBackendStarted=false;
  const publicationBytes=await fs.readFile(context.envPath);
  // Historical destructive cohorts remain retained. Current success selector never
  // shares an identity with a dirty failure, and never clears a dirty epoch.
  for(const mode of interruptionCases){
   const child=launch([path.join(sourceRoot,'tests/fixtures/setupDatabasePhaseProcess.cjs')],{stdio:['ignore','ignore','ignore','ipc']});
   const publication=path.join(evidence,'forbidden-'+mode);let detached;
   const barrier=mode==='runner-failure'?message(child,'failure'):message(child,'barrier');
   child.send({mode,request:{...request,context:{...context,config}},publication});
   const observed=await barrier;
   if(mode!=='runner-failure'){
    detached=observed.pid;assert.equal(absent(detached),false);
    await assert.rejects(acquire({mode:'application',env}),{code:'APPLICATION_MAINTENANCE_BUSY'});
    if(mode==='signal')child.kill('SIGTERM');else if(mode==='disconnect')child.disconnect();else child.kill('SIGKILL');
   }
   await deadline(closed(child),15000);children.delete(child);
   const observeRelease=()=>waitForOwnedLeaseRelease({client:identity,assertExited:()=>{assert.equal(absent(child.pid),true,'lease owner exited');if(mode!=='abrupt'&&detached)assert.equal(groupAbsent(detached),true,'owned helper group exited');},onObservation:value=>{state.leaseReleaseObservations[mode]=value;}});
   if(mode==='abrupt'){
    await observeRelease();
    // Characterization only: dead lease owner cannot retain its session lock.
    const next=await acquire({mode:'maintenance',env});await next.close();state.abruptLockReleasedBeforeHelperCleanup=!groupAbsent(detached);
    await stopGroup(detached);
   }
   if(detached){for(let n=0;n<250&&!groupAbsent(detached);n++)await new Promise(r=>setTimeout(r,20));assert.equal(groupAbsent(detached),true);detachedGroups.delete(detached);}
   await assert.rejects(fs.lstat(publication),{code:'ENOENT'});assert.deepEqual(await fs.readFile(context.envPath),publicationBytes);
   if(mode!=='abrupt')await observeRelease();
   const next=await acquire({mode:'maintenance',env});await next.close();state.controlledProcessBarriers.push(mode);
  }
  state.passed=true;
 }catch(error){
  state.failure=require('../fixtures/setupPrivatePhaseDispatch').privateParentFailure(error);
  throw error;
 }finally{
  for(const pid of detachedGroups)await stopGroup(pid);
  for(const child of children){child.kill('SIGKILL');await deadline(closed(child)).catch(()=>{});}
  const cleanup=await Promise.allSettled([...leases.map(lease=>lease.close()),...clients.map(client=>client.end())]);
  state.cleanup.declaredGroupsAbsent=[...detachedGroups].every(pid=>groupAbsent(pid));
  state.cleanup.ownedDirectChildrenAbsent=[...children].every(child=>absent(child.pid));state.cleanup.databaseClientsClosed=cleanup.every(x=>x.status==='fulfilled');await persist();
  assert(state.cleanup.declaredGroupsAbsent);assert(state.cleanup.ownedDirectChildrenAbsent);assert(state.cleanup.databaseClientsClosed);
 }
});

test('real missing-store upgrade preserves prior learner and credentials then repeats no-op',{skip:!enabled||!['additive','additive-success'].includes(process.env.SETUP_PHASE_SCENARIO),timeout:600000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.SETUP_PHASE_EVIDENCE_ROOT);
 assert.equal(root,await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(root),evidence);assert.match(path.basename(evidence),/^owasp-ai-goat-setup-phase-/);
 const adminUrl=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(adminUrl.hostname,'127.0.0.1');assert.equal(adminUrl.pathname,'/postgres');
 const home=path.join(evidence,'home'),id=createHash('sha256').update(root).digest('hex').slice(0,12),directory=path.join(home,'.owasp-ai-goat',id),envPath=path.join(root,'.env'),manifestPath=path.join(directory,'provisioning.json');
 await fs.mkdir(directory,{recursive:true,mode:0o700});await assert.rejects(fs.lstat(envPath),{code:'ENOENT'});
 const environment={PATH:process.env.PATH,HOME:home,NODE_ENV:'test',PG_TLS:'disable',MCP_SIDECARS_AUTOSTART:'false',AWS_EC2_METADATA_DISABLED:'true',OWASP_AI_GOAT_APP_DATA_ROOT:path.join(evidence,'app-data'),LOGS_DIR:path.join(evidence,'logs')};
 for(const folder of [environment.OWASP_AI_GOAT_APP_DATA_ROOT,environment.LOGS_DIR])await fs.mkdir(folder,{recursive:true,mode:0o700});
 const guard=path.join(evidence,'network-guard.cjs');await fs.writeFile(guard,networkGuardSource({host:'127.0.0.1',port:adminUrl.port}),{mode:0o600});environment.NODE_OPTIONS=`--require=${guard}`;
 const admin=new Client({connectionString:adminUrl.href}),plan=provisioningPlan(),prior=plan.slice(0,-1),configuration={},clients=[admin];
 const quote=value=>{assert.match(value,/^owasp_ai_goat_[a-z_]+$/);return '"'+value+'"';};
 let child;const result={passed:false,scenario:'additive',actualModel:false};
 try{
  await admin.connect();
  const cluster=(await admin.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
  assert.equal((await admin.query("SELECT count(*)::int n FROM pg_database WHERE datname LIKE 'owasp_ai_goat_%'")).rows[0].n,0);
  for(const row of prior){
   for(const kind of ['migration','runtime']){
    const password=require('node:crypto').randomBytes(32).toString('hex'),role=row[kind+'Role'];
    await admin.query(`CREATE ROLE ${quote(role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
    const url=new URL(adminUrl);url.username=role;url.password=password;url.pathname='/'+row.database;configuration[row[kind+'Variable']]=url.href;
   }
   await admin.query(`CREATE DATABASE ${quote(row.database)} OWNER ${quote(row.migrationRole)}`);
   await admin.query(`REVOKE CONNECT,TEMPORARY ON DATABASE ${quote(row.database)} FROM PUBLIC`);
   await admin.query(`GRANT CONNECT ON DATABASE ${quote(row.database)} TO ${quote(row.runtimeRole)},${quote(row.migrationRole)}`);
  }
  await fs.writeFile(manifestPath,JSON.stringify({version:1,status:'complete',cluster,plan:prior,configuration,created:[]}),{mode:0o600});
  const initial=require('../../scripts/setup-application').encodeEnv({...configuration,PG_TLS:'disable',JWT_SECRET:randomUUID()+randomUUID(),SESSION_SECRET:randomUUID()+randomUUID()});
  await fs.writeFile(envPath,initial,{mode:0o600});
  const credentials=JSON.stringify({syntheticRetainedCredential:randomUUID()});await fs.writeFile(path.join(directory,'administrator.json'),credentials,{mode:0o600});
  // Real prior fifteen-store initialization under one durable maintenance scope.
  // The missing sixteenth store is added only by the supported upgrade below.
  child=spawn(process.execPath,['-e',"(async()=>{await require('./scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({},async scope=>{const pg=require('./server/database/postgres'),runtime=pg.createPool(process.env,'IDENTITY_DATABASE_URL'),migration=pg.createPool(process.env,'IDENTITY_MIGRATION_DATABASE_URL');await require('./server/database/postgres/identityRepository').initializeIdentityRepository(runtime,migration);scope.assertHeld();await require('./server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);await runtime.end();await migration.end();const schemas=require('./db/postgres/initialize-application').repositories.slice(1,-1).map(row=>row[0]);await require('./scripts/initialize-application-additions').initializeAdditions(schemas,{maintenanceScope:scope});});})().catch(()=>process.exit(1))"],{cwd:root,env:{...environment,...configuration},stdio:'ignore'});
  assert.equal(await deadline(closed(child),180000),0);child=null;
  const identity=new Client({connectionString:configuration.IDENTITY_MIGRATION_DATABASE_URL});clients.push(identity);await identity.connect();
  const hash=await require('bcryptjs').hash(randomUUID(),4);
  const user=(await identity.query("INSERT INTO identity.users(username,email,password,role) VALUES('prior-learner','prior@example.invalid',$1,'student') RETURNING id",[hash])).rows[0].id;
  await identity.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,'sql_injection_workshop',now(),now(),23)",[user]);
  const snapshot=async()=>createHash('sha256').update(JSON.stringify((await identity.query('SELECT u.*,t.duration_seconds FROM identity.users u JOIN workshop_platform.time_tracking t ON t.user_id=u.id WHERE u.id=$1',[user])).rows)).digest('hex');
  const before=await snapshot();let previous=Buffer.from(initial),clean=await cleanCheckpoint(identity);result.maintenanceEpochs=[clean.epoch];result.priorInitializedStores=15;
  for(let iteration=0;iteration<2;iteration++){
   const state=await require('../../scripts/application-upgrade').inspectUpgradeState({envPath,manifestPath,currentPlan:plan});
   const context={root,directory,homeDirectory:home,envPath,id,platform:process.platform,manifestPath,state,databaseAdminUrl:adminUrl.href,appDataRoot:environment.OWASP_AI_GOAT_APP_DATA_ROOT,processEnvironment:environment,appDataEnvironment:{...environment,...state.parsed}};
   const upgraded=await runSetupDatabasePhase({kind:'upgrade',context},{},{timeoutMs:180000,killGraceMs:5000,spawn:(file,args,opts)=>trackPhaseChild(spawn(file,args,opts))});
   clean=await cleanCheckpoint(identity,clean);result.maintenanceEpochs.push(clean.epoch);
   assert.deepEqual(upgraded.upgradedSchemas,iteration?[]:[plan.at(-1).schema]);
   const bytes=await fs.readFile(envPath);assert.equal(bytes.subarray(0,previous.length).equals(previous),true);if(iteration)assert.equal(bytes.equals(previous),true);previous=bytes;
   assert.equal(await snapshot(),before);assert.equal(createHash('sha256').update(await fs.readFile(path.join(directory,'administrator.json'))).digest('hex'),createHash('sha256').update(credentials).digest('hex'));
  }
  const final=require('dotenv').parse(previous),last=plan.at(-1),runtime=new Client({connectionString:final[last.runtimeVariable]});clients.push(runtime);await runtime.connect();
  assert.equal((await runtime.query('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1) AS present',[last.schema])).rows[0].present,true);
  for(const [key,value]of Object.entries(configuration))assert.equal(createHash('sha256').update(final[key]).digest('hex'),createHash('sha256').update(value).digest('hex'));
  await cleanEntryBoundary(root,evidence,{...environment,...final});result.cleanEntryBoundary=true;result.fullBackendStarted=false;
  result.appended=last.schema;result.learnerPreserved=true;result.noop=true;result.passed=true;
 }finally{
  if(child){child.kill('SIGKILL');await deadline(closed(child));}
  const outcomes=await Promise.allSettled(clients.map(client=>client.end()));result.clientsClosed=outcomes.every(x=>x.status==='fulfilled');
  await fs.writeFile(path.join(evidence,'setup-phase-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});assert(result.clientsClosed);
 }
});

module.exports={cleanCheckpoint};
