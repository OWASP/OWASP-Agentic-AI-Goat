'use strict';

// Explicit, stopped-application package replacement. No startup or fresh-install
// caller enters this path. The retained volume and network keep their provenance.
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const {workspaceId}=require('../application-data-root');
const {sourceManifest}=require('./secureshop-owned-system');
const {renderMcpSandboxAppArmor}=require('../render-mcp-sandbox-apparmor');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {captureFile,assertPrivateDirectory,publishImmutable}=require('../../server/services/secureshopPricingManagedConfiguration')._private;
const {createRunner,verifyProfile,inspectContainer,buildCaSecret}=require('./secureshop-owned-system-provision')._internals;

const fail=code=>Object.assign(new Error('Owned System package upgrade requires recovery'),{code});
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const identity=(a,b)=>a&&b&&a.dev===b.dev&&a.ino===b.ino&&a.sha256===b.sha256;
const labels=value=>({'dvaia.system.workspace':value.workspaceId,'dvaia.system.authority':value.dockerAuthoritySha256,'dvaia.system.source':value.sourceManifestSha256});
const imageCheck=(image,value)=>{
 if(!image||image.Id!==value.imageId||image.Architecture!=='arm64'||image.Os!=='linux'
  ||Object.entries(labels(value)).some(([k,v])=>image.Config?.Labels?.[k]!==v)||image.Config?.User!=='10001:10001'
  ||!equal(image.Config.Entrypoint,['/usr/local/bin/node','/opt/dvaia-owned-system/local-listener-entry.js'])
  ||image.Config.Cmd?.length||Object.keys(image.Config.Volumes||{}).length)throw fail('SYSTEM_UPGRADE_IMAGE_CONFLICT');
};
function syncDirectory(directory){const fd=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function atomicWrite(filename,bytes,check){
 const directory=path.dirname(filename);assertPrivateDirectory(directory);
 const temp=path.join(directory,'.system-upgrade-'+crypto.randomBytes(12).toString('hex'));
 let fd;try{fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;check();fs.renameSync(temp,filename);syncDirectory(directory);}
 finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(temp))fs.unlinkSync(temp);}
}
function acquireLock(filePath,recover){
 const lock=filePath+'.activation-lock',owner=path.join(lock,'upgrade-owner.json');
 try{fs.mkdirSync(lock,{mode:0o700});}catch(error){
  if(error.code!=='EEXIST'||!recover)throw fail('SYSTEM_UPGRADE_LOCKED');
  const before=assertPrivateDirectory(lock),captured=captureFile(owner,1024);let pid;
  try{const parsed=JSON.parse(captured.bytes);if(!equal(Object.keys(parsed),['pid'])||!Number.isSafeInteger(parsed.pid)||parsed.pid<1)throw Error();pid=parsed.pid;}catch{throw fail('SYSTEM_UPGRADE_LOCKED');}
  try{process.kill(pid,0);throw fail('SYSTEM_UPGRADE_LOCKED');}catch(error){if(error.code!=='ESRCH')throw fail('SYSTEM_UPGRADE_LOCKED');}
  if(fs.readdirSync(lock).join()!=='upgrade-owner.json'||!identity({...captured.identity,sha256:captured.sha256},{...captureFile(owner,1024).identity,sha256:captureFile(owner,1024).sha256}))throw fail('SYSTEM_UPGRADE_LOCKED');
  const now=assertPrivateDirectory(lock);if(now.dev!==before.dev||now.ino!==before.ino)throw fail('SYSTEM_UPGRADE_LOCKED');
  fs.unlinkSync(owner);fs.rmdirSync(lock);fs.mkdirSync(lock,{mode:0o700});
 }
 const held=fs.lstatSync(lock);fs.writeFileSync(owner,JSON.stringify({pid:process.pid}),{mode:0o600,flag:'wx'});syncDirectory(lock);
 return()=>{const now=assertPrivateDirectory(lock);if(now.dev!==held.dev||now.ino!==held.ino)throw fail('SYSTEM_UPGRADE_LOCK_CHANGED');fs.unlinkSync(owner);fs.rmdirSync(lock);};
}

async function assertApplicationStopped({root,directory,environment,probe=require('../start-application').assertApplicationPortsAvailable}){
 const state=path.join(directory,'launcher.json');
 const absent=()=>{try{fs.lstatSync(state);throw fail('SYSTEM_UPGRADE_APPLICATION_RUNNING');}catch(error){if(error.code!=='ENOENT')throw error;}};
 absent();
 let installed={};try{installed=require('dotenv').parse(fs.readFileSync(path.join(root,'.env')));}catch(error){if(error.code!=='ENOENT')throw fail('SYSTEM_UPGRADE_APPLICATION_STATE_UNKNOWN');}
 // Probe both installed and explicit override port sets; manually started
 // listeners and a launcher that appears during the check both block replacement.
 for(const configuration of [installed,{...installed,...environment}]){
  try{await probe({...configuration,SS_ENABLE:'true'});}catch{throw fail('SYSTEM_UPGRADE_APPLICATION_RUNNING');}
 }
 absent();return true;
}

async function upgrade(options={}){
 const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform;
 if(!path.isAbsolute(root)||!path.isAbsolute(home)||!['darwin','linux'].includes(platform)||(options.architecture||process.arch)!=='arm64')throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 const filePath=managed.managedPath({root,home}),directory=path.dirname(filePath),journalPath=filePath+'.upgrade.json';
 assertPrivateDirectory(directory);
 const release=acquireLock(filePath,options.recover===true);
 let temp;
 try{
  const environment=sanitizeDockerEnvironment(options.environment||process.env),run=options.run||createRunner({cwd:root,env:environment});
  const stopped=()=>assertApplicationStopped({root,directory,environment,...(options.probeApplicationPorts?{probe:options.probeApplicationPorts}:{})});
  await stopped();
  const execute=async(file,args,opts={})=>{const r=await run(file,args,{timeoutMs:opts.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('SYSTEM_UPGRADE_COMMAND_FAILED');return r;};
  const authorityPath=path.join(directory,'local-docker.json'),authorityFile=captureFile(authorityPath,8192);
  const authority=await readLocalDockerAuthority({directory,workspaceId:workspaceId(root),platform});
  if(!authority)throw fail('SYSTEM_UPGRADE_AUTHORITY_REQUIRED');
  await verifyDockerAuthority({authority,execute,environment});
  const docker=async(args,{missing=false,timeoutMs=30000}={})=>{
   let r;try{r=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});}catch{throw fail('SYSTEM_UPGRADE_COMMAND_UNCERTAIN');}
   if(r.exitCode!==0){if(missing&&/no such|not found/i.test(r.stderr||''))return null;throw fail('SYSTEM_UPGRADE_COMMAND_FAILED');}return r.stdout;
  };
  const inspect=async(kind,id,missing=false)=>{const raw=await docker([kind,'inspect',id],{missing});if(raw===null)return null;try{const rows=JSON.parse(raw);if(rows.length!==1)throw Error();return rows[0];}catch{throw fail('SYSTEM_UPGRADE_INSPECT_FAILED');}};
  let journal,journalCapture,published=false;
  let MODES,OLD_MODES;
  const save=()=>{
   const bytes=JSON.stringify(journal)+'\n';
   atomicWrite(journalPath,bytes,()=>{if(journalCapture){const now=captureFile(journalPath,32768);if(!identity({...now.identity,sha256:now.sha256},{...journalCapture.identity,sha256:journalCapture.sha256}))throw fail('SYSTEM_UPGRADE_JOURNAL_CHANGED');}else if(fs.existsSync(journalPath))throw fail('SYSTEM_UPGRADE_JOURNAL_CHANGED');});
   journalCapture=captureFile(journalPath,32768);
  };
  const clear=()=>{const now=captureFile(journalPath,32768);if(!identity({...now.identity,sha256:now.sha256},{...journalCapture.identity,sha256:journalCapture.sha256}))throw fail('SYSTEM_UPGRADE_JOURNAL_CHANGED');fs.unlinkSync(journalPath);syncDirectory(directory);};
  if(fs.existsSync(journalPath)){
   if(options.recover!==true)throw fail('SYSTEM_UPGRADE_RECOVERY_REQUIRED');
   journalCapture=captureFile(journalPath,32768);try{journal=JSON.parse(journalCapture.bytes);}catch{throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');}
   if(!journal||journal.version!==1||!/^([a-f0-9]{24})$/.test(journal.transaction)||!journal.original||!journal.next||!journal.old||!journal.created||!journal.resources||!journal.authority)throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   managed.validate(journal.original.value);managed.validate(journal.next);OLD_MODES=managed.modesFor(journal.original.value);MODES=managed.modesFor(journal.next);
   if(journal.addUploadPreview!==undefined&&journal.addUploadPreview!==true)throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   if(journal.addUploadPreview===true&&(journal.original.value.uploadPreview||!journal.next.uploadPreview))throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   if(journal.original.sha256!==sha(managed.encode(journal.original.value))||journal.original.value.workspaceId!==workspaceId(root)
     ||!equal(journal.next,managed.validate({...journal.original.value,...(journal.addUploadPreview===true?{uploadPreview:journal.next.uploadPreview}:{}),imageId:journal.next.imageId,sourceManifestSha256:journal.next.sourceManifestSha256,resourceSourceManifestSha256:journal.original.value.resourceSourceManifestSha256||journal.original.value.sourceManifestSha256})))throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   if(!equal(Object.keys(journal.old).sort(),[...OLD_MODES].sort())||Object.entries(journal.created).some(([mode,id])=>!MODES.includes(mode)||!/^[a-f0-9]{64}$/.test(id)))throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   for(const mode of OLD_MODES)if(!/^[a-f0-9]{64}$/.test(journal.old[mode]?.id)||typeof journal.old[mode].running!=='boolean'||(journal.created[mode]!==undefined&&!/^[a-f0-9]{64}$/.test(journal.created[mode])))throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   if(new Set(OLD_MODES.map(mode=>journal.old[mode].id)).size!==OLD_MODES.length)throw fail('SYSTEM_UPGRADE_JOURNAL_INVALID');
   const now=managed.capture({filePath});published=now&&managed.encode(now.value)===managed.encode(journal.next);
   if(!published&&!identity(now,journal.original))throw fail('SYSTEM_UPGRADE_STATE_CHANGED');
  }else{
   if(options.recover===true)return Object.freeze({recovered:false,changed:false});
   const original=managed.capture({filePath});if(!original)throw fail('SYSTEM_UPGRADE_EXISTING_REQUIRED');
   const source=sourceManifest(root);
   if(original.value.sourceManifestSha256===source.sha256&&options.uploadPreviewPort===undefined)throw fail('SYSTEM_UPGRADE_SOURCE_UNCHANGED');
   journal={version:1,transaction:crypto.randomBytes(12).toString('hex'),original,next:null,authority:{dev:authorityFile.identity.dev,ino:authorityFile.identity.ino,sha256:authorityFile.sha256},old:{},created:{},resources:null};
  }
  const value=journal.original.value;OLD_MODES=managed.modesFor(value);MODES=journal.next?managed.modesFor(journal.next):OLD_MODES;
  let addedPreview;
  if(options.uploadPreviewPort!==undefined){
   if(options.recover===true||value.uploadPreview||!Number.isInteger(options.uploadPreviewPort)||options.uploadPreviewPort<1024||options.uploadPreviewPort>65535||OLD_MODES.some(mode=>Number(new URL(value[mode].url).port)===options.uploadPreviewPort))throw fail('SYSTEM_UPGRADE_PREVIEW_ADMISSION_INVALID');
   addedPreview={container:`dvaia-owned-system-${value.workspaceId}-upload-preview`,url:`http://127.0.0.1:${options.uploadPreviewPort}`,token:crypto.randomBytes(48).toString('base64url')};journal.addUploadPreview=true;
  }
  if(value.workspaceId!==workspaceId(root)||authorityDigest(authority)!==value.dockerAuthoritySha256)throw fail('SYSTEM_UPGRADE_AUTHORITY_CHANGED');
  const p={workspaceId:value.workspaceId,profile:value.profile};
  const profileBytes=renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8'),'dvaia-mcp-sandbox');
  if(sha(profileBytes)!==value.profile.sha256)throw fail('SYSTEM_UPGRADE_PROFILE_CHANGED');
  await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
  const network=`dvaia-owned-system-${value.workspaceId}-bridge`,restartVolume=`dvaia-owned-system-${value.workspaceId}-restart-state`;
  const resourceLabels={...labels(value),'dvaia.system.source':value.resourceSourceManifestSha256||value.sourceManifestSha256};
  const resources=async()=>{
   const net=await inspect('network',network),volume=await inspect('volume',restartVolume);
   if(!/^[a-f0-9]{64}$/.test(net.Id)||net.Name!==network||net.Driver!=='bridge'||net.Internal!==false||Object.entries(resourceLabels).some(([k,v])=>net.Labels?.[k]!==v)
    ||volume.Name!==restartVolume||volume.Driver!=='local'||Object.keys(volume.Options||{}).length||volume.Labels?.['dvaia.system.mode']!=='restart-state'||Object.entries(resourceLabels).some(([k,v])=>volume.Labels?.[k]!==v))throw fail('SYSTEM_UPGRADE_RESOURCES_CHANGED');
   return {network:{id:net.Id,sha256:sha(JSON.stringify({Id:net.Id,Name:net.Name,Driver:net.Driver,Internal:net.Internal,Labels:net.Labels,Options:net.Options,IPAM:net.IPAM}))},volume:{name:volume.Name,sha256:sha(JSON.stringify(volume))}};
  };
  const assertState=()=>{
   const now=managed.capture({filePath});if(published?managed.encode(now?.value)!==managed.encode(journal.next):!identity(now,journal.original))throw fail('SYSTEM_UPGRADE_STATE_CHANGED');
   const a=captureFile(authorityPath,8192);if(!identity({...a.identity,sha256:a.sha256},journal.authority))throw fail('SYSTEM_UPGRADE_AUTHORITY_CHANGED');
   if(journalCapture){const current=captureFile(journalPath,32768);if(!identity({...current.identity,sha256:current.sha256},{...journalCapture.identity,sha256:journalCapture.sha256}))throw fail('SYSTEM_UPGRADE_JOURNAL_CHANGED');}
  };
  const fence=async()=>{await stopped();assertState();await verifyDockerAuthority({authority,execute,environment});if(!equal(await resources(),journal.resources))throw fail('SYSTEM_UPGRADE_RESOURCES_CHANGED');assertState();};
  const oldImage=await inspect('image',value.imageId);imageCheck(oldImage,value);
  let nextImage;
  const backup=mode=>value[mode].container+'-previous-'+journal.transaction;
  const checkContainer=(found,mode,next=false)=>{
   if(!found||!/^[a-f0-9]{64}$/.test(found.Id))throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');
   const record=next?journal.next:value,acceptedName=next?record[mode].container:found.Name==='/'+backup(mode)?backup(mode):record[mode].container;
   inspectContainer(found,{mode,p,value:{...record,[mode]:{...record[mode],container:acceptedName}},image:next?nextImage:oldImage,network,labels:labels(record),restartVolume});
   if(!next&&found.Id!==journal.old[mode]?.id)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');
   if(!['running','exited','created'].includes(found.State?.Status)||found.State.Running!==(found.State.Status==='running'))throw fail('SYSTEM_UPGRADE_CONTAINER_STATE');
  };
  const mutate=async args=>{await fence();await docker(args);};
  const originalContainers=async()=>{for(const mode of OLD_MODES){const c=await inspect('container',journal.old[mode].id);checkContainer(c,mode);}};
  const readiness=async(record,modes=MODES)=>{
   const factories={config:options.createConfigClient||require('../../server/services/secureshopSystemConfigClient').createSecureShopSystemConfigClient,diagnostic:options.createDiagnosticClient||require('../../server/services/secureshopSystemDiagnosticClient').createSecureShopSystemDiagnosticClient,restart:options.createRestartClient||require('../../server/services/secureshopSystemRestartClient').createSecureShopSystemRestartClient,uploadPreview:options.createUploadPreviewClient||require('../../server/services/secureshopUploadPreviewClient').createSecureShopUploadPreviewClient};
   for(const mode of modes){const client=factories[mode]({baseURL:record[mode].url,token:record[mode].token});let ready=false;for(let i=0;i<3&&!ready;i++){try{ready=mode==='restart'?(await client.health())?.ready===true:await client.assertReady()===true;}catch{}if(!ready&&i<2)await new Promise(r=>setTimeout(r,100));}if(!ready)throw fail('SYSTEM_UPGRADE_READINESS_FAILED');if(mode==='config'){const metrics=await client.metrics();if(metrics?.ok!==true||metrics.metricsSource!=='owned-system-listener')throw fail('SYSTEM_UPGRADE_METRICS_FAILED');}}
  };
  const rollback=async()=>{
   await fence();await originalContainers();
   for(const mode of [...MODES].reverse()){
    if(!OLD_MODES.includes(mode)){
     const added=await inspect('container',journal.next[mode].container,true);
     if(added){checkContainer(added,mode,true);if(journal.created[mode]&&added.Id!==journal.created[mode])throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');if(added.State.Running)await mutate(['stop','--time','10',added.Id]);await mutate(['rm',added.Id]);}
     continue;
    }
    let replacement=await inspect('container',value[mode].container,true);
    if(replacement&&replacement.Id!==journal.old[mode].id){checkContainer(replacement,mode,true);if(journal.created[mode]&&journal.created[mode]!==replacement.Id)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');if(replacement.State.Running){await mutate(['stop','--time','10',replacement.Id]);replacement=await inspect('container',replacement.Id);checkContainer(replacement,mode,true);}await mutate(['rm',replacement.Id]);}
    let old=await inspect('container',journal.old[mode].id);checkContainer(old,mode);
    if(old.Name!=='/'+value[mode].container)await mutate(['rename',old.Id,value[mode].container]);
    old=await inspect('container',old.Id);checkContainer(old,mode);
    if(journal.old[mode].running&&!old.State.Running)await mutate(['start',old.Id]);
    if(!journal.old[mode].running&&old.State.Running)await mutate(['stop','--time','10',old.Id]);
   }
   await originalContainers();
   for(const mode of OLD_MODES){const c=await inspect('container',journal.old[mode].id);checkContainer(c,mode);if(c.State.Running!==journal.old[mode].running)throw fail('SYSTEM_UPGRADE_ROLLBACK_UNREADY');}
   await readiness(value,OLD_MODES.filter(mode=>journal.old[mode].running));await fence();clear();
  };
  const finish=async()=>{
   await fence();
   for(const mode of MODES){const c=await inspect('container',journal.next[mode].container);checkContainer(c,mode,true);if(c.Id!==journal.created[mode]||!c.State.Running)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');}
   await readiness(journal.next);
   // Preserve the exact predecessor and successor, including private tokens and
   // immutable container IDs, before deleting any retired container or journal.
   publishImmutable(filePath+'.upgrade-'+journal.transaction+'.completed.json',Buffer.from(JSON.stringify(journal)+'\n'));
   for(const mode of OLD_MODES){const old=await inspect('container',journal.old[mode].id,true);if(!old)continue;checkContainer(old,mode);if(old.Name!=='/'+backup(mode)||old.State.Running)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');await mutate(['rm',old.Id]);}
   clear();
  };
  if(options.recover===true){
   nextImage=await inspect('image',journal.next.imageId);imageCheck(nextImage,journal.next);
   if(published)await finish();else await rollback();
   return Object.freeze({recovered:true,changed:published,activationEnabled:published?journal.next.enabled:value.enabled});
  }
  journal.resources=await resources();
  for(const mode of OLD_MODES){const found=await inspect('container',value[mode].container);journal.old[mode]={id:found?.Id,running:found?.State?.Running};checkContainer(found,mode);if(await inspect('container',backup(mode),true))throw fail('SYSTEM_UPGRADE_BACKUP_CONFLICT');}
  if(new Set(OLD_MODES.map(mode=>journal.old[mode].id)).size!==OLD_MODES.length)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');
  await fence();
  temp=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-system-upgrade-'));fs.chmodSync(temp,0o700);
  const source=sourceManifest(root),base=await inspect('image',source.baseImage);if(base?.Id!==source.baseImage||base.Architecture!=='arm64')throw fail('SYSTEM_INSTALL_BASE_UNQUALIFIED');
  const context=path.join(temp,'build');fs.mkdirSync(context,{mode:0o700});
  for(const [name,digest]of Object.entries(source.files)){const bytes=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-system',name));if(sha(bytes)!==digest)throw fail('SYSTEM_UPGRADE_SOURCE_CHANGED');fs.mkdirSync(path.dirname(path.join(context,name)),{recursive:true,mode:0o700});fs.writeFileSync(path.join(context,name),bytes,{mode:0o400,flag:'wx'});}
  if(sourceManifest(root).sha256!==source.sha256)throw fail('SYSTEM_UPGRADE_SOURCE_CHANGED');
  const tag=`dvaia-owned-system-${value.workspaceId}:upgrade-${journal.transaction}`,nextLabels={...labels(value),'dvaia.system.source':source.sha256},labelArgs=Object.entries(nextLabels).flatMap(([k,v])=>['--label',`${k}=${v}`]);
  const buildSecrets=await buildCaSecret({environment:options.environment||process.env,temp});
  await fence();await docker(['build','--pull=false','--network=default',...buildSecrets,...labelArgs,'-f',path.join(context,'Dockerfile.local'),'-t',tag,context],{timeoutMs:300000});
  nextImage=await inspect('image',tag);
  journal.next=managed.validate({...value,...(addedPreview?{uploadPreview:addedPreview}:{}),imageId:nextImage?.Id,sourceManifestSha256:source.sha256,resourceSourceManifestSha256:value.resourceSourceManifestSha256||value.sourceManifestSha256});imageCheck(nextImage,journal.next);
  MODES=managed.modesFor(journal.next);
  if(addedPreview&&await inspect('container',addedPreview.container,true))throw fail('SYSTEM_UPGRADE_PREVIEW_RESOURCE_EXISTS');
  if(nextImage.Id===value.imageId&&!addedPreview)throw fail('SYSTEM_UPGRADE_IMAGE_CONFLICT');
  await fence();await originalContainers();save();
  try{
   for(const mode of MODES){
    if(OLD_MODES.includes(mode)){
    let old=await inspect('container',journal.old[mode].id);checkContainer(old,mode);
    if(old.State.Running)await mutate(['stop','--time','10',old.Id]);
    old=await inspect('container',old.Id);checkContainer(old,mode);if(old.State.Running)throw fail('SYSTEM_UPGRADE_STOP_FAILED');
    await mutate(['rename',old.Id,backup(mode)]);
    }
    const record=journal.next;
    const envFile=path.join(temp,mode+'.env'),prefix=mode==='uploadPreview'?'SECURESHOP_UPLOAD_PREVIEW':'SECURESHOP_SYSTEM_'+mode.toUpperCase();
    fs.writeFileSync(envFile,`${prefix}_HTTP_ENABLED=true\n${prefix}_TOKEN=${record[mode].token}\n${prefix}_HOST=0.0.0.0\n${prefix}_PORT=8090\n`,{mode:0o600,flag:'wx'});
    const extra=mode==='uploadPreview'?['--tmpfs','/var/lib/dvaia-owned-upload-preview:rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001']:mode==='restart'?['--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--mount',`type=volume,source=${restartVolume},target=/var/lib/dvaia-owned-restart`]:[];
    // Lost acknowledgements are recovered from the exact owned name and image.
    try{await mutate(['create','--name',record[mode].container,...labelArgs,'--label','dvaia.system.mode='+mode,'--network',network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m',...extra,'--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile.name,'--publish',`127.0.0.1:${new URL(record[mode].url).port}:8090`,'--env-file',envFile,nextImage.Id,mode==='uploadPreview'?'upload-preview':mode]);}catch(error){if(!['SYSTEM_UPGRADE_COMMAND_FAILED','SYSTEM_UPGRADE_COMMAND_UNCERTAIN'].includes(error.code))throw error;}
    let c=await inspect('container',record[mode].container);checkContainer(c,mode,true);journal.created[mode]=c.Id;save();
    try{await mutate(['start',c.Id]);}catch(error){if(!['SYSTEM_UPGRADE_COMMAND_FAILED','SYSTEM_UPGRADE_COMMAND_UNCERTAIN'].includes(error.code))throw error;}
    c=await inspect('container',c.Id);checkContainer(c,mode,true);if(!c.State.Running)throw fail('SYSTEM_UPGRADE_START_FAILED');
   }
   await readiness(journal.next);await fence();
   for(const mode of MODES){const c=await inspect('container',journal.created[mode]);checkContainer(c,mode,true);if(!c.State.Running)throw fail('SYSTEM_UPGRADE_CONTAINER_CHANGED');}
   await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
   if(sourceManifest(root).sha256!==source.sha256)throw fail('SYSTEM_UPGRADE_SOURCE_CHANGED');
   await stopped();atomicWrite(filePath,managed.encode(journal.next),assertState);published=true;
  }catch(error){
   // Publication may have succeeded before the directory fsync failed. Never
   // restore old containers underneath an already published successor record.
   const current=managed.capture({filePath});published=current&&managed.encode(current.value)===managed.encode(journal.next);
   if(!published){try{await rollback();}catch{throw fail('SYSTEM_UPGRADE_RECOVERY_REQUIRED');}}
   throw error;
  }
  await finish();
  return Object.freeze({changed:true,ready:true,activationEnabled:journal.next.enabled,imageId:journal.next.imageId,sourceManifestSha256:journal.next.sourceManifestSha256,managedPath:filePath});
 }finally{if(temp)fs.rmSync(temp,{recursive:true});release();}
}

if(require.main===module){
 const args=process.argv.slice(2);
 if(!((args.length===1&&['--upgrade','--recover'].includes(args[0]))||(args.length===2&&args[0]==='--upgrade'&&args[1]==='--upload-preview'))){process.stderr.write('Usage: node scripts/install/secureshop-owned-system-upgrade.js --upgrade [--upload-preview]|--recover (stop the application first)\n');process.exitCode=2;}
 else upgrade({recover:args[0]==='--recover',...(args[1]==='--upload-preview'?{uploadPreviewPort:process.env.DVAIA_UPLOAD_PREVIEW_PORT===undefined?8093:Number(process.env.DVAIA_UPLOAD_PREVIEW_PORT)}:{})}).then(result=>process.stdout.write(JSON.stringify(result)+'\n'),error=>{process.stderr.write((/^SYSTEM_|^LOCAL_DOCKER_/.test(error.code||'')?error.code:'SYSTEM_UPGRADE_FAILED')+'\n');process.exitCode=1;});
}
module.exports={upgrade,_internals:{assertApplicationStopped}};
