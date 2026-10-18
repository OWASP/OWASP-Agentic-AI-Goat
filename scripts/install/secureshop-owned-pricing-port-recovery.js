'use strict';
// Only the disabled, never-started legacy8093 collision may be retargeted.
// Retain write-ahead originals and the exact successor; never rotate identity.
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),crypto=require('node:crypto');
const managed=require('../../server/services/secureshopPricingManagedConfiguration');
const stage=require('./secureshop-owned-pricing-stage');
const activation=require('../../server/services/secureshopPricingActivation');
const {verifyDockerAuthority}=require('../local-docker-authority');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=()=>Object.assign(Error('Owned Pricing port recovery requires exact unused resources'),{code:'PRICING_PORT_RECOVERY_UNAVAILABLE'});
const encode=x=>Buffer.from(JSON.stringify(x)+'\n');
function neverStarted(container){
 return container?.State?.Status==='created'&&container.State.Running===false
  &&container.State.StartedAt==='0001-01-01T00:00:00Z'
  &&container.State.FinishedAt==='0001-01-01T00:00:00Z'&&container.RestartCount===0;
}
function readOptional(filename){try{return managed._private.captureFile(filename,65536);}catch(e){if(e.code==='ENOENT')return null;throw fail();}}
function exactKeys(value,keys){return value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join()===keys.sort().join();}
function removeExact(filename,identity){const s=fs.lstatSync(filename);if(s.isSymbolicLink()||s.dev!==identity.dev||s.ino!==identity.ino)throw fail();fs.unlinkSync(filename);}
function replaceExact(filename,original,successor){
 const current=managed._private.captureFile(filename,16384);
 if(current.bytes.equals(successor))return;
 if(current.sha256!==original.sha256||current.identity.dev!==original.identity.dev||current.identity.ino!==original.identity.ino)throw fail();
 const pending=filename+'.port-'+crypto.randomUUID()+'.pending';let identity;
 try{const fd=fs.openSync(pending,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{identity=fs.fstatSync(fd);fs.writeFileSync(fd,successor);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  const rechecked=managed._private.captureFile(filename,16384);
  if(rechecked.sha256!==current.sha256||rechecked.identity.dev!==current.identity.dev||rechecked.identity.ino!==current.identity.ino)throw fail();
  fs.renameSync(pending,filename);identity=undefined;
  const parent=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
 }finally{if(identity)removeExact(pending,identity);}
}
async function assertNoPricingRuns(environment){
 const {Pool}=require('pg');if(!environment.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL)throw fail();
 const pool=new Pool({connectionString:environment.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL,max:1,connectionTimeoutMillis:5000,statement_timeout:5000});
 try{const result=await pool.query(`SELECT NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_admissions)
  AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_outcomes)
  AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_cleanup_receipts
   WHERE admission_count IS DISTINCT FROM 0 OR outcome_count IS DISTINCT FROM 0) AS unused`);
  if(result.rows.length!==1||result.rows[0].unused!==true)throw fail();
 }finally{await pool.end();}
}
async function assertPortFree(port){
 await new Promise((resolve,reject)=>{const server=net.createServer();server.once('error',()=>reject(fail()));server.listen({host:'127.0.0.1',port,exclusive:true},()=>server.close(error=>error?reject(fail()):resolve()));});
}
async function recoverUnusedPricingPort({root,home,environment,port,run,execute,maintenanceScope,
 acquireLease=require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease,
 assertUnused=assertNoPricingRuns,checkPort=assertPortFree}={}){
 const location=managed.paths({root,home}),preparedFile=path.join(location.directory,'pricing-port-retarget.json');
 const prepared=readOptional(preparedFile),record=managed.load({root,home});
 if(!prepared&&(port!==undefined&&port!==8096||!record||record.config.enabled||record.config.port!==8093))return false;
 if(port!==undefined&&port!==8096)throw fail();
 if(fs.realpathSync(root)!==root)throw fail();managed._private.assertPrivateDirectory(location.directory);
 const scopeTools=require('../lib/application-maintenance-scope');
 if(maintenanceScope){scopeTools.assertApplicationMaintenanceScope(maintenanceScope,environment);if(!scopeTools.hasCompletedProspectiveMaintenanceScope(maintenanceScope))throw fail();}
 const lease=maintenanceScope?{assertHeld:()=>scopeTools.assertApplicationMaintenanceScope(maintenanceScope,environment),assertClean:async()=>{if(!scopeTools.hasCompletedProspectiveMaintenanceScope(maintenanceScope))throw fail();},close:async()=>{}}:await acquireLease({mode:'maintenance',env:environment});let fd,lockIdentity;
 try{
  await lease.assertClean();lease.assertHeld();
  const lock=path.join(location.directory,'.pricing-managed.lock');fd=fs.openSync(lock,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);lockIdentity=fs.fstatSync(fd);
  let journal=readOptional(preparedFile),value;
  const docker=async(args,missing=false)=>{lease.assertHeld();const r=await run('docker',['--host',record.authority.host,...args],{timeoutMs:15000,maxOutputBytes:1048576});lease.assertHeld();if(r.exitCode!==0){if(missing&&/No such|not found/.test(r.stderr||''))return null;throw fail();}return r.stdout;};
  const inspect=async id=>{const raw=await docker(['container','inspect',id],true);if(raw===null)return null;const rows=JSON.parse(raw);if(rows.length!==1)throw fail();return rows[0];};
  await verifyDockerAuthority({authority:record.authority,execute,environment});
  if(!journal){
   await assertUnused(environment);lease.assertHeld();
   const current=managed.load({root,home}),saved=stage.read({root,home});
   if(!current||current.config.enabled||current.sha256!==record.sha256||current.identity.ino!==record.identity.ino||current.identity.dev!==record.identity.dev||!saved||Object.keys(saved.value).some(k=>saved.value[k]!==current.config[k]))throw fail();
   await activation.inspectPricingBeforeStart({root,home,env:environment,execute});
   const old=await inspect(current.config.containerId);if(!neverStarted(old)||old.Id!==current.config.containerId)throw fail();
   value={version:1,workspaceId:current.config.workspaceId,toPort:8096,
    managed:{bytes:managed._private.captureFile(location.filename,16384).bytes.toString('base64'),sha256:current.sha256,identity:current.identity},
    stage:{bytes:managed._private.captureFile(stage.location({root,home}),16384).bytes.toString('base64'),sha256:saved.sha256,identity:saved.identity}};
   await checkPort(8096);
   const ids=(await docker(['ps','--all','--filter','publish=8096','--format','{{.ID}}'])).trim();if(ids)throw fail();
   managed._private.publishImmutable(preparedFile,encode(value));journal=readOptional(preparedFile);
  }
  value=JSON.parse(journal.bytes);
  if(!exactKeys(value,['version','workspaceId','toPort','managed','stage'])||value.version!==1||value.workspaceId!==record.config.workspaceId||value.toPort!==8096)throw fail();
  for(const original of [value.managed,value.stage])if(!exactKeys(original,['bytes','sha256','identity'])||sha(Buffer.from(original.bytes,'base64'))!==original.sha256)throw fail();
  const originalConfig=managed.validate(JSON.parse(Buffer.from(value.managed.bytes,'base64')),{root});
  const originalStage=stage.validate(JSON.parse(Buffer.from(value.stage.bytes,'base64')),root);
  if(originalConfig.enabled||originalConfig.port!==8093||Object.keys(originalStage).some(k=>originalStage[k]!==originalConfig[k]))throw fail();
  const currentStage=managed._private.captureFile(stage.location({root,home}),16384);
  const intendedStage=encode({...originalStage,port:8096});
  if(!currentStage.bytes.equals(intendedStage)&&(currentStage.sha256!==value.stage.sha256||currentStage.identity.dev!==value.stage.identity.dev||currentStage.identity.ino!==value.stage.identity.ino))throw fail();
  const successorFile=path.join(location.directory,'pricing-port-retarget-successor.json'),completeFile=path.join(location.directory,'pricing-port-retarget-complete.json');
  let successor=readOptional(successorFile),next=successor&&JSON.parse(successor.bytes);
  const label=journal.sha256;
  if(successor&&(!exactKeys(next,['version','preparedSha256','containerId'])||next.version!==1||next.preparedSha256!==label||!/^[a-f0-9]{64}$/.test(next.containerId)))throw fail();
  const successorConfig=()=>({...originalConfig,port:8096,containerId:next.containerId});
  const successorStage=intendedStage;
  const complete=readOptional(completeFile);
  if(complete){const done=JSON.parse(complete.bytes),current=managed.load({root,home});if(!next||JSON.stringify(done)!==JSON.stringify({version:1,preparedSha256:label,successorSha256:successor.sha256})||!current||Object.keys(successorConfig()).filter(k=>k!=='enabled').some(k=>current.config[k]!==successorConfig()[k])||!managed._private.captureFile(stage.location({root,home}),16384).bytes.equals(successorStage))throw fail();return false;}
  await assertUnused(environment);lease.assertHeld();
  if(!next){
   const current=managed._private.captureFile(location.filename,16384);
   if(current.sha256!==value.managed.sha256||current.identity.ino!==value.managed.identity.ino||current.identity.dev!==value.managed.identity.dev)throw fail();
   const old=await inspect(originalConfig.containerId);
   if(old){await activation.inspectPricingBeforeStart({root,home,env:environment,execute});if(!neverStarted(old)||old.Id!==originalConfig.containerId)throw fail();}
   const named=await inspect(originalConfig.containerName);
   if(named&&named.Id!==originalConfig.containerId&&named.Config?.Labels?.['dvaia.pricing.retarget']!==label)throw fail();
   await checkPort(8096);
   const ids=(await docker(['ps','--all','--filter','publish=8096','--format','{{.ID}}'])).trim().split('\n').filter(Boolean);
   if(ids.some(id=>!named||!named.Id.startsWith(id)||named.Config?.Labels?.['dvaia.pricing.retarget']!==label))throw fail();
   if(old)await docker(['rm',old.Id]);
   let candidate=named&&named.Id!==originalConfig.containerId?named:null;
   if(!candidate){
    const envFile=path.join(location.directory,'.pricing-port-'+crypto.randomUUID()+'.env');let envIdentity;
    try{fs.writeFileSync(envFile,`SECURESHOP_PRICING_ENABLED=true\nSECURESHOP_PRICING_TOKEN=${originalConfig.token}\nSECURESHOP_PRICING_PROFILE=${originalConfig.profile}\nSECURESHOP_PRICING_HOST=0.0.0.0\nSECURESHOP_PRICING_PORT=8093\n`,{mode:0o600,flag:'wx'});envIdentity=fs.lstatSync(envFile);
     try{await docker(['create','--name',originalConfig.containerName,
      ...Object.entries({'dvaia.pricing.owner':originalConfig.ownerId,'dvaia.pricing.workspace':originalConfig.workspaceId,'dvaia.pricing.package':originalConfig.packageSha256,'dvaia.pricing.retarget':label}).flatMap(([k,v])=>['--label',k+'='+v]),
      '--network',originalConfig.containerName+'-network','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--security-opt','seccomp=unconfined','--security-opt','apparmor='+originalConfig.profile,'--publish','127.0.0.1:8096:8093','--env-file',envFile,originalConfig.imageId]);}catch{}
    }finally{if(envIdentity)removeExact(envFile,envIdentity);}
    candidate=await inspect(originalConfig.containerName);
   }
   if(!neverStarted(candidate)||candidate.Config?.Labels?.['dvaia.pricing.retarget']!==label)throw fail();
   await activation.inspectPricingPortCandidate({root,home,env:environment,execute,portCandidate:{port:8096,containerId:candidate.Id}});
   next={version:1,preparedSha256:label,containerId:candidate.Id};managed._private.publishImmutable(successorFile,encode(next));successor=readOptional(successorFile);
  }
  const candidate=await inspect(next.containerId);if(!neverStarted(candidate)||candidate.Config?.Labels?.['dvaia.pricing.retarget']!==label)throw fail();
  const current=managed.load({root,home});if(current.config.enabled)throw fail();
  if(current.config.port===8093)await activation.inspectPricingPortCandidate({root,home,env:environment,execute,portCandidate:{port:8096,containerId:next.containerId}});
  replaceExact(location.filename,value.managed,encode(successorConfig()));
  replaceExact(stage.location({root,home}),value.stage,successorStage);
  await activation.inspectPricingBeforeStart({root,home,env:environment,execute});lease.assertHeld();
  managed._private.publishImmutable(completeFile,encode({version:1,preparedSha256:label,successorSha256:successor.sha256}));return true;
 }finally{try{if(fd!==undefined){fs.closeSync(fd);removeExact(path.join(location.directory,'.pricing-managed.lock'),lockIdentity);}}finally{await lease.close();}}
}
module.exports={recoverUnusedPricingPort,neverStarted,_internals:{assertNoPricingRuns,assertPortFree,replaceExact}};
