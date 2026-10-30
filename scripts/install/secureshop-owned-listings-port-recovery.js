'use strict';
// Exact disabled-manager repair for the never-admitted 8095 collision. The
// original container and named journal volume are retained, never removed.
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),crypto=require('node:crypto');
const managed=require('../../server/services/secureshopListingsManagedConfiguration');
const fail=()=>Object.assign(new Error('Owned Listings port recovery unavailable; retained resources preserved'),{code:'LISTINGS_PORT_RECOVERY_UNAVAILABLE'});
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const journalPath=filePath=>path.join(path.dirname(filePath),'secureshop-listings-port-recovery.json');
function readJournal(filePath){
 const filename=journalPath(filePath);let fd;
 try{
  fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=fs.fstatSync(fd),named=fs.lstatSync(filename);
  if(!before.isFile()||before.uid!==process.getuid()||before.nlink!==1||(before.mode&0o777)!==0o600
   ||before.size<2||before.size>16384||named.dev!==before.dev||named.ino!==before.ino)throw fail();
  const buffer=Buffer.alloc(before.size+1),count=fs.readSync(fd,buffer,0,buffer.length,0),after=fs.fstatSync(fd);
  if(count!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw fail();
  const bytes=buffer.subarray(0,count),value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  if(Buffer.from(JSON.stringify(value)+'\n').compare(bytes)!==0
   ||!exact(value,['version','workspaceId','originalId','originalName','originalUrl','successorUrl',
    'managedBytes','managedSha256','managedDev','managedIno','authoritySha256','imageId','networkId','volumeName',
    'sourceSha256','runtimeDigest','originalStartedAt'])
   ||value.version!==1||!/^[a-f0-9]{12}$/.test(value.workspaceId||'')
   ||!/^[a-f0-9]{64}$/.test(value.originalId||'')||!/^[a-f0-9]{64}$/.test(value.networkId||'')
   ||!/^[a-f0-9]{64}$/.test(value.managedSha256||'')||!/^[a-f0-9]{64}$/.test(value.authoritySha256||'')
   ||!/^[a-f0-9]{64}$/.test(value.sourceSha256||'')||!/^[a-f0-9]{64}$/.test(value.runtimeDigest||'')
   ||value.originalName!=='owasp-ai-goat-owned-listings-'+value.workspaceId
   ||value.volumeName!==value.originalName+'-journal'
   ||value.originalUrl!=='http://127.0.0.1:8095'||value.successorUrl!=='http://127.0.0.1:8099'
   ||!Number.isSafeInteger(value.managedDev)||!Number.isSafeInteger(value.managedIno)
   ||typeof value.managedBytes!=='string'||value.managedBytes.length>12000
   ||typeof value.originalStartedAt!=='string')throw fail();
  const original=Buffer.from(value.managedBytes,'base64');
  if(original.toString('base64')!==value.managedBytes||sha(original)!==value.managedSha256
   ||managed.encode(managed.validate(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(original))))!==original.toString('utf8'))throw fail();
  return Object.freeze({value,sha256:sha(bytes)});
 }catch(error){if(error.code==='ENOENT')return null;throw fail();}
 finally{if(fd!==undefined)fs.closeSync(fd);}
}
function writeJournal(filePath,value){
 const filename=journalPath(filePath),bytes=Buffer.from(JSON.stringify(value)+'\n');
 const temporary=filename+'.'+crypto.randomBytes(12).toString('hex')+'.pending';let fd;
 try{fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  try{fs.linkSync(temporary,filename);}catch(error){if(error.code!=='EEXIST')throw error;}
 }catch{throw fail();}
 finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=='ENOENT')throw fail();}}
 const parent=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY);
 try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
 const saved=readJournal(filePath);
 if(!saved||JSON.stringify(saved.value)!==JSON.stringify(value))throw fail();
 return saved;
}
async function assertPortFree(port){
 await new Promise((resolve,reject)=>{const server=net.createServer();
  server.once('error',()=>reject(fail()));
  server.listen({host:'127.0.0.1',port,exclusive:true},()=>server.close(error=>error?reject(fail()):resolve()));
 });
}
async function assertNoWork(environment){
 const url=environment?.SECURESHOP_REVIEW_DATABASE_URL;
 if(typeof url!=='string'||!url.startsWith('postgres'))throw fail();
 const {Pool}=require('pg'),pool=new Pool({connectionString:url,max:1,connectionTimeoutMillis:5000,
  query_timeout:10000,options:'-c statement_timeout=8000 -c lock_timeout=2000'});
 try{
  const rows=(await pool.query(`SELECT
    NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_admissions)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_events)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_publications)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_cleanup_receipts)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_generated_products)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_rewrite_saves)
    AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_scene_admissions) AS unused`)).rows;
  if(rows.length!==1||rows[0].unused!==true)throw fail();
 }catch{throw fail();}finally{await pool.end();}
}
async function assertEmptyJournal(docker,containerId){
 // Return one fixed marker only. No registration, token or journal contents
 // cross the Docker command boundary.
 const source="const f=require('node:fs'),s=f.lstatSync('/journal');if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==10001||(s.mode&0o077)||f.readdirSync('/journal').length)process.exit(13);process.stdout.write('EMPTY')";
 const output=await docker(['exec','--user','10001:10001',containerId,'node','-e',source]);
 if(output!=='EMPTY')throw fail();
}
async function assertDockerPortFree(docker,inspect,port,allowedId){
 const ids=(await docker(['ps','--all','--no-trunc','--format','{{.ID}}'])).trim().split(/\r?\n/).filter(Boolean);
 if(ids.length>256||ids.some(id=>!/^[a-f0-9]{64}$/.test(id)))throw fail();
 for(const id of ids){if(id===allowedId)continue;const row=await inspect('container',id);
  if(!row||row.Id!==id)throw fail();
  for(const bindings of Object.values(row.HostConfig?.PortBindings||{}))
   for(const binding of bindings||[])if(Number(binding.HostPort)===port)throw fail();
 }
}
async function recover({p,value,image,labels,network,volume,docker,inspect,inspectContainer,
 verifyAuthority,verifySource,health,applicationEnvironment,maintenanceScope,
 assertUnused=assertNoWork,checkPort=assertPortFree,assertMaintenance}={}){
 const scopeTools=require('../lib/application-maintenance-scope');
 const held=assertMaintenance||(()=>{scopeTools.assertApplicationMaintenanceScope(maintenanceScope,applicationEnvironment);
  if(!scopeTools.hasCompletedProspectiveMaintenanceScope(maintenanceScope))throw fail();});
 held();
 const filePath=p.managedPath,existingJournal=readJournal(filePath);
 if(!existingJournal&&(value.enabled||value.manager.url!=='http://127.0.0.1:8095'))return false;
 if(value.enabled)throw fail();
 const current=managed.capture({filePath});
 if(!current||managed.encode(current.value)!==managed.encode(value))throw fail();
 const expected={value,image,labels,network,volume};
 const named=await inspect('container',value.manager.container);
 if(!existingJournal){
  if(!named||!named.State?.Running||named.State.Status!=='running'
   ||Object.keys(named.NetworkSettings?.Networks||{}).length||Object.keys(named.NetworkSettings?.Ports||{}).length)throw fail();
  inspectContainer(named,expected,{allowRunningUnattached:true});
  const bridge=await inspect('network',network);
  if(!bridge||!/^[a-f0-9]{64}$/.test(bridge.Id||'')||bridge.Name!==network
   ||bridge.Containers&&Object.keys(bridge.Containers).length)throw fail();
  await assertUnused(applicationEnvironment);held();
  await assertEmptyJournal(docker,named.Id);held();
  await checkPort(8099);await assertDockerPortFree(docker,inspect,8099);held();
  await verifyAuthority();await verifySource();
  const refreshed=managed.capture({filePath}),again=await inspect('container',named.Id);
  if(!refreshed||refreshed.dev!==current.dev||refreshed.ino!==current.ino||refreshed.sha256!==current.sha256
   ||again?.Id!==named.Id||again.Name!==named.Name||again.State.StartedAt!==named.State.StartedAt)throw fail();
  const data={version:1,workspaceId:p.workspaceId,originalId:named.Id,originalName:value.manager.container,
   originalUrl:value.manager.url,successorUrl:'http://127.0.0.1:8099',managedBytes:Buffer.from(managed.encode(value)).toString('base64'),managedSha256:current.sha256,
   managedDev:current.dev,managedIno:current.ino,authoritySha256:p.dockerAuthoritySha256,
   imageId:value.imageId,networkId:bridge.Id,volumeName:volume,
   sourceSha256:p.source.sha256,runtimeDigest:value.runtimeDigest,originalStartedAt:named.State.StartedAt};
  writeJournal(filePath,data);
 }
 const saved=readJournal(filePath),j=saved?.value;
 if(!j||j.workspaceId!==p.workspaceId||j.originalName!==value.manager.container
  ||j.authoritySha256!==p.dockerAuthoritySha256||j.imageId!==value.imageId
  ||j.volumeName!==volume||j.sourceSha256!==p.source.sha256||j.runtimeDigest!==value.runtimeDigest)throw fail();
 const backupName=j.originalName+'-recovery-'+saved.sha256.slice(0,12);
 const originalValue=managed.validate(JSON.parse(Buffer.from(j.managedBytes,'base64').toString('utf8')));
 const next=managed.validate({...originalValue,manager:{...originalValue.manager,url:j.successorUrl}});
 if(managed.encode(value)!==managed.encode(value.manager.url===j.originalUrl?originalValue:next))throw fail();
 if(![j.originalUrl,j.successorUrl].includes(value.manager.url))throw fail();
 const config=managed.capture({filePath});
 if(!config||config.value.enabled||config.value.manager.token!==value.manager.token
  ||config.value.manager.container!==j.originalName
  ||(config.value.manager.url===j.originalUrl&&(config.sha256!==j.managedSha256
    ||config.dev!==j.managedDev||config.ino!==j.managedIno)))throw fail();
 await verifyAuthority();held();
 managed.clearRetargetLock({filePath,recoveryId:saved.sha256});
 const original=await inspect('container',j.originalId),backup=await inspect('container',backupName);
 if(!original||original.Id!==j.originalId||original.State.StartedAt!==j.originalStartedAt
  ||![('/'+j.originalName),('/'+backupName)].includes(original.Name)
  ||backup&&backup.Id!==j.originalId)throw fail();
 const oldForCheck={...original,Name:'/'+j.originalName};
 inspectContainer(oldForCheck,{...expected,value:{...value,manager:{...value.manager,url:j.originalUrl}}},
  {allowRunningUnattached:true,allowStoppedUnattached:true});
 const bridge=await inspect('network',network);
 const candidateId=named?.Id!==j.originalId&&named?.Config?.Labels?.['owasp-ai-goat.listings.portRecovery']===saved.sha256?named.Id:null;
 if(!bridge||bridge.Id!==j.networkId||bridge.Name!==network
  ||bridge.Containers&&Object.keys(bridge.Containers).some(id=>id!==j.originalId&&id!==candidateId))throw fail();
 // A completed repair is read-only and remains disabled until activation.
 if(value.manager.url===j.successorUrl){
  if(original.Name!=='/'+backupName||original.State.Running)throw fail();
  const published=await inspect('container',j.originalName);
  if(!published||published.Id===j.originalId||published.Config?.Labels?.['owasp-ai-goat.listings.portRecovery']!==saved.sha256)throw fail();
  inspectContainer(published,{...expected,value:next});
  return false;
 }
 await assertUnused(applicationEnvironment);held();
 if(original.State.Running){
  if(original.Name!=='/'+j.originalName)throw fail();
  await assertEmptyJournal(docker,j.originalId);held();await verifyAuthority();await verifySource();
  try{await docker(['stop','--time','10',j.originalId]);}catch{}
  const stopped=await inspect('container',j.originalId);
  if(stopped?.Id!==j.originalId||stopped.State?.Running||stopped.State?.Status!=='exited'
   ||stopped.State.StartedAt!==j.originalStartedAt)throw fail();
 }
 let old=await inspect('container',j.originalId);
 if(old.Name==='/'+j.originalName){
  if(await inspect('container',backupName))throw fail();
  held();await verifyAuthority();
  try{await docker(['rename',j.originalId,backupName]);}catch{}
  old=await inspect('container',j.originalId);
 }
 if(old?.Name!=='/'+backupName||old.State?.Running||old.Id!==j.originalId)throw fail();
 const successorExpected={...expected,value:next};
 let candidate=await inspect('container',j.originalName);
 if(candidate){
  if(candidate.Id===j.originalId||candidate.Config?.Labels?.['owasp-ai-goat.listings.portRecovery']!==saved.sha256)throw fail();
  inspectContainer(candidate,successorExpected,{allowCreatedUnattached:true,allowRunningUnattached:true});
 }else{
  await checkPort(8099);await assertDockerPortFree(docker,inspect,8099);held();
  await assertUnused(applicationEnvironment);await verifyAuthority();await verifySource();
  const envFile=path.join(path.dirname(filePath),'.listings-port-'+crypto.randomUUID()+'.env');let fd;
  try{
   fd=fs.openSync(envFile,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
   fs.writeFileSync(fd,`LISTINGS_MANAGER_ENABLED=true\nLISTINGS_PROFILE=${next.profile.name}\nLISTINGS_PUBLIC_ORIGIN=${next.manager.url}\nLISTINGS_CONTROL_TOKEN=${next.manager.token}\n`);
   fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
   try{await docker(['create','--name',j.originalName,
    ...Object.entries({...labels,'owasp-ai-goat.listings.portRecovery':saved.sha256}).flatMap(([k,v])=>['--label',k+'='+v]),
    '--network',network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128',
    '--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--mount',`type=volume,source=${volume},target=/journal`,
    '--security-opt','seccomp=unconfined','--security-opt','apparmor='+next.profile.name,
    '--publish','127.0.0.1:8099:8095','--env-file',envFile,image.Id]);}catch{}
  }finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(envFile);}catch(error){if(error.code!=='ENOENT')throw fail();}}
  candidate=await inspect('container',j.originalName);
  if(!candidate||candidate.Config?.Labels?.['owasp-ai-goat.listings.portRecovery']!==saved.sha256)throw fail();
  inspectContainer(candidate,successorExpected,{allowCreatedUnattached:true});
 }
 const successorId=candidate.Id;
 const assertSuccessor=row=>{
  if(row?.Id!==successorId||row.Config?.Labels?.['owasp-ai-goat.listings.portRecovery']!==saved.sha256)throw fail();
  return row;
 };
 if(!candidate.State.Running){
  try{await docker(['start',successorId]);}catch{}
  candidate=assertSuccessor(await inspect('container',j.originalName));
  if(!candidate.State?.Running)throw fail();
 }
 if(Object.keys(candidate.NetworkSettings?.Networks||{}).length===0){
  inspectContainer(candidate,successorExpected,{allowRunningUnattached:true});
  const beforeConnect=await inspect('network',network);
  if(beforeConnect?.Id!==j.networkId||Object.keys(beforeConnect.Containers||{}).length)throw fail();
  try{await docker(['network','connect',j.networkId,candidate.Id]);}catch{}
  candidate=assertSuccessor(await inspect('container',j.originalName));
 }
 // Only fixed phase names cross the setup-process boundary. In particular, a
 // transport or filesystem exception must not reveal a URL, token or host path.
 let phase='LISTINGS_PORT_RECOVERY_RESOURCE';
 try{
  assertSuccessor(candidate);
  inspectContainer(candidate,successorExpected);
  const attached=await inspect('network',network);
  if(successorId===j.originalId||attached?.Id!==j.networkId
   ||Object.keys(attached.Containers||{}).some(id=>id!==candidate.Id))throw fail();
  phase='LISTINGS_PORT_RECOVERY_HEALTH';
  await health(next);
  phase='LISTINGS_PORT_RECOVERY_NO_WORK';
  await assertUnused(applicationEnvironment);held();
  phase='LISTINGS_PORT_RECOVERY_AUTHORITY';
  await verifyAuthority();await verifySource();
  phase='LISTINGS_PORT_RECOVERY_FINAL_RESOURCE';
  const oldFinal=await inspect('container',j.originalId),newFinal=await inspect('container',j.originalName);
  if(oldFinal?.Name!=='/'+backupName||oldFinal.State.Running)throw fail();
  assertSuccessor(newFinal);
  inspectContainer(newFinal,successorExpected);
  phase='LISTINGS_PORT_RECOVERY_PUBLISH';
  await managed.retargetDisabled({filePath,expected:config,next,recoveryId:saved.sha256,verify:async()=>{held();
   await verifyAuthority();await verifySource();await assertUnused(applicationEnvironment);
   const [kept,published]=await Promise.all([inspect('container',j.originalId),inspect('container',j.originalName)]);
   if(kept?.Name!=='/'+backupName||kept.State.Running)throw fail();
   assertSuccessor(published);
   inspectContainer(published,successorExpected);await health(next);return true;
  }});
 }catch{throw Object.assign(new Error('Owned Listings port recovery unavailable; retained resources preserved'),{code:phase});}
 return true;
}
module.exports={recover,assertNoWork,assertPortFree,assertDockerPortFree,_internals:{readJournal,writeJournal,journalPath}};
