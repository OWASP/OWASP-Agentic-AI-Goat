'use strict';
// Provision one shared manager, never a container per learner. This module does
// not edit .env, activate the application, migrate databases or choose a daemon.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {plan,sourceManifest}=require('./secureshop-owned-listings');
const managed=require('../../server/services/secureshopListingsManagedConfiguration');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {localProfilePlan}=require('./mcp-owned-local');
const {createRunner}=require('./secureshop-owned-system-provision')._internals;
const {createListingsTargetManager}=require('../../server/services/secureshopListingsTargetManager');
const fail=code=>Object.assign(new Error('Owned Listings provisioning requires recovery'),{code});
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ENTRY=['node','sidecars/sandbox-runner/owned-listings/manager-entry.js'];
async function authorityIdentity(authorityPath){const constants=require('node:fs').constants,handle=await fs.open(authorityPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await handle.stat();
  if(!before.isFile()||before.nlink!==1||before.uid!==process.getuid()||(before.mode&0o077)||before.size<1||before.size>8192)throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');
  const buffer=Buffer.alloc(before.size+1);let count=0;
  while(count<buffer.length){const result=await handle.read(buffer,count,buffer.length-count,count);if(result.bytesRead===0)break;count+=result.bytesRead;}
  const after=await handle.stat(),named=await fs.lstat(authorityPath);
  if(count!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.dev!==named.dev||before.ino!==named.ino)throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');
  return Object.freeze({dev:before.dev,ino:before.ino,sha256:sha(buffer.subarray(0,count))});
 }finally{await handle.close();}}
async function verifyProfile({p,authority,root,home,platform,run}){
 let location;
 if(platform==='linux')location=localProfilePlan({root,home,platform});
 else {const marker='/.colima/',offset=authority.host.indexOf(marker);if(!authority.host.startsWith('unix:///')||offset<8)throw fail('LISTINGS_INSTALL_PROFILE_AUTHORITY');const authorityHome=authority.host.slice(7,offset),prefix=`unix://${path.join(authorityHome,'.colima')}/`,suffix='/docker.sock';if(!authority.host.startsWith(prefix)||!authority.host.endsWith(suffix))throw fail('LISTINGS_INSTALL_PROFILE_AUTHORITY');const selected=authority.host.slice(prefix.length,-suffix.length);if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(selected))throw fail('LISTINGS_INSTALL_PROFILE_AUTHORITY');location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+selected});}
 if(location.dockerHost!==authority.host)throw fail('LISTINGS_INSTALL_PROFILE_AUTHORITY');
 async function command(args){const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,'sudo','--non-interactive',...args],{timeoutMs:10000,maxOutputBytes:1048576});if(result.exitCode!==0)throw fail('LISTINGS_INSTALL_PROFILE_UNAVAILABLE');return result.stdout;}
 const identity=(await command(['stat','-c','%u:%a:%F:%h','/etc/apparmor.d/'+p.profile.name])).trim();
 const digest=(await command(['sha256sum','/etc/apparmor.d/'+p.profile.name])).trim().split(/\s+/)[0];
 const profiles=(await command(['cat','/sys/kernel/security/apparmor/profiles'])).split(/\r?\n/);
 if(identity!=='0:600:regular file:1'||digest!==p.profile.sha256||!profiles.includes(p.profile.name+' (enforce)')||!profiles.includes(p.profile.name+'//bwrap (enforce)'))throw fail('LISTINGS_INSTALL_PROFILE_CONFLICT');
}
function inspectContainer(c,{value,image,labels,network,volume},{allowCreatedUnattached=false,allowRunningUnattached=false,allowStoppedUnattached=false}={}){
 const hc=c?.HostConfig,config=c?.Config;
 const expectedEnv=[...(image.Config.Env||[]),'LISTINGS_MANAGER_ENABLED=true','LISTINGS_PROFILE='+value.profile.name,'LISTINGS_PUBLIC_ORIGIN='+value.manager.url,'LISTINGS_CONTROL_TOKEN='+value.manager.token].sort();
 const bindings={'8095/tcp':[{HostIp:'127.0.0.1',HostPort:new URL(value.manager.url).port}]};
 const networks=c?.NetworkSettings?.Networks,attachedNetworks=networks&&Object.getPrototypeOf(networks)===Object.prototype?Object.keys(networks):null;
 // Docker may leave NetworkSettings.Networks empty until a newly created
 // container starts. HostConfig still fixes its one intended network; once
 // running (or after an earlier start), require the exact attachment.
 const neverStarted=value=>/^0001-01-01T00:00:00(?:\.0+)?Z$/.test(value||'');
 const createdUnattached=allowCreatedUnattached&&c?.State?.Status==='created'&&c.State.Running===false
  &&c.RestartCount===0&&neverStarted(c.State.StartedAt)&&neverStarted(c.State.FinishedAt)
  &&Array.isArray(attachedNetworks)&&attachedNetworks.length===0;
 const ports=c?.NetworkSettings?.Ports;
 const runningUnattached=allowRunningUnattached&&c?.State?.Status==='running'&&c.State.Running===true
  &&Array.isArray(attachedNetworks)&&attachedNetworks.length===0
  &&ports&&Object.getPrototypeOf(ports)===Object.prototype&&Object.keys(ports).length===0;
 const stoppedUnattached=allowStoppedUnattached&&c?.State?.Status==='exited'&&c.State.Running===false
  &&Array.isArray(attachedNetworks)&&attachedNetworks.length===0;
 if(!hc||!config||!/^[a-f0-9]{64}$/.test(c.Id||'')||c.Name!=='/'+value.manager.container||c.Image!==value.imageId||Object.entries(labels).some(([k,v])=>config.Labels?.[k]!==v)
  ||config.User!=='10001:10001'||config.WorkingDir!=='/app'||!same(config.Entrypoint,ENTRY)||config.Cmd?.length||!same([...(config.Env||[])].sort(),expectedEnv)
  ||hc.Privileged!==false||hc.ReadonlyRootfs!==true||hc.Memory!==536870912||hc.NanoCpus!==1000000000||hc.PidsLimit!==128||!same(hc.Tmpfs,{'/tmp':'rw,nosuid,nodev,noexec,size=16m'})
  ||hc.Binds?.length||hc.Devices?.length||hc.DeviceRequests?.length||hc.PidMode||hc.IpcMode==='host'||hc.UsernsMode==='host'||hc.CapAdd?.length||!same(hc.CapDrop,['ALL'])
  ||!same([...(hc.SecurityOpt||[])].sort(),['apparmor='+value.profile.name,'seccomp=unconfined'].sort())
  ||hc.NetworkMode!==network||(!same(attachedNetworks,[network])&&!createdUnattached&&!runningUnattached&&!stoppedUnattached)||!same(hc.PortBindings,bindings)
  ||!same((c.Mounts||[]).map(m=>({Type:m.Type,Name:m.Name,Destination:m.Destination,RW:m.RW})),[{Type:'volume',Name:volume,Destination:'/journal',RW:true}])
  ||c.State?.Running&&!same(c.NetworkSettings.Ports,bindings)&&!runningUnattached)throw fail('LISTINGS_INSTALL_CONTAINER_CONFLICT');
}
async function provision(options={}){
 const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
 const run=options.run||createRunner({cwd:root,env:environment});
 const execute=async(file,args,o)=>{const r=await run(file,args,{timeoutMs:o.timeout,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('LISTINGS_INSTALL_COMMAND_FAILED');return r;};
 let p=await plan({...options,root,home,platform,environment,execute,existingQualification:undefined});
 const authorityPath=path.join(path.dirname(p.managedPath),'local-docker.json'),initialAuthorityIdentity=await authorityIdentity(authorityPath);
 const authority=await readLocalDockerAuthority({directory:path.dirname(p.managedPath),workspaceId:p.workspaceId,platform});
 if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');
 await verifyDockerAuthority({authority,execute,environment});await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
 async function docker(args,{missing=false,timeoutMs=30000}={}){let r;try{r=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});}catch{throw fail('LISTINGS_INSTALL_COMMAND_UNCERTAIN');}if(r.exitCode!==0){if(missing&&/no such|not found/i.test(r.stderr||''))return null;throw fail('LISTINGS_INSTALL_COMMAND_FAILED');}return r.stdout;}
 async function inspect(kind,name){const raw=await docker([kind,'inspect',name],{missing:true});if(raw===null)return null;try{const a=JSON.parse(raw);if(!Array.isArray(a)||a.length!==1)throw Error();return a[0];}catch{throw fail('LISTINGS_INSTALL_INSPECT_INVALID');}}
 const portRecovery=require('./secureshop-owned-listings-port-recovery');
 if(!p.existing&&options.port===undefined){
  let selected;
  for(let candidate=8099;candidate<=8108;candidate++){
   try{await portRecovery.assertPortFree(candidate);await portRecovery.assertDockerPortFree(docker,inspect,candidate);selected=candidate;break;}catch(error){if(error.code!=='LISTINGS_PORT_RECOVERY_UNAVAILABLE')throw error;}
  }
  if(!selected)throw fail('LISTINGS_INSTALL_PORT_UNAVAILABLE');
  if(selected!==Number(new URL(p.manager.url).port))p=await plan({...options,root,home,platform,environment,execute,port:selected});
 }
 const labels={'dvaia.listings.workspace':p.workspaceId,'dvaia.listings.authority':p.dockerAuthoritySha256,'dvaia.listings.source':p.source.sha256,'dvaia.listings.runtime':p.runtimeDigest};
 const labelArgs=Object.entries(labels).flatMap(([k,v])=>['--label',k+'='+v]);
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-listings-install-'));await fs.chmod(temp,0o700);const tempStat=await fs.lstat(temp);
 try{
  const existing=managed.load({filePath:p.managedPath}),tag=`dvaia-owned-listings-${p.workspaceId}:local`;
  let image=await inspect('image',existing?.imageId||tag);if(!image&&existing)throw fail('LISTINGS_INSTALL_IMAGE_MISSING');
  if(!image){
   const context=path.join(temp,'build');await fs.mkdir(context,{mode:0o700});
   for(const [name,digest] of Object.entries(p.source.files)){const bytes=await fs.readFile(path.join(root,name));if(sha(bytes)!==digest)throw fail('LISTINGS_INSTALL_SOURCE_CHANGED');const dest=path.join(context,name);await fs.mkdir(path.dirname(dest),{recursive:true,mode:0o755});await fs.writeFile(dest,bytes,{mode:0o444,flag:'wx'});}
   if(sourceManifest(root).sha256!==p.source.sha256)throw fail('LISTINGS_INSTALL_SOURCE_CHANGED');
   const buildSecrets=[];
   if(options.buildCaFile!==undefined){
    if(!path.isAbsolute(options.buildCaFile)||!/^[a-f0-9]{64}$/.test(options.buildCaSha256||''))throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');
    const handle=await fs.open(options.buildCaFile,require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW|require('node:fs').constants.O_NONBLOCK);
    let bytes;try{const st=await handle.stat();if(!st.isFile()||st.size<1||st.size>1048576||(st.mode&0o022)||![0,process.getuid()].includes(st.uid))throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');bytes=Buffer.alloc(st.size+1);const {bytesRead}=await handle.read(bytes,0,bytes.length,0);bytes=bytes.subarray(0,bytesRead);if(bytes.length!==st.size||sha(bytes)!==options.buildCaSha256)throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');}finally{await handle.close();}
    const ca=path.join(temp,'npm-ca.pem');await fs.writeFile(ca,bytes,{mode:0o600,flag:'wx'});buildSecrets.push('--secret','id=npm_ca,src='+ca);
   }else if(options.buildCaSha256!==undefined)throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');
   await docker(['build',...buildSecrets,'--platform','linux/arm64','--pull=false',...labelArgs,'--file',path.join(context,'sidecars/sandbox-runner/owned-listings/Dockerfile.candidate'),'--tag',tag,context],{timeoutMs:300000});image=await inspect('image',tag);
  }
  if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Architecture!=='arm64'||image.Os!=='linux'||Object.entries(labels).some(([k,v])=>image.Config?.Labels?.[k]!==v)||image.Config.User!=='10001:10001'||image.Config.WorkingDir!=='/app'||!same(image.Config.Entrypoint,ENTRY)||image.Config.Cmd?.length||Object.keys(image.Config.Volumes||{}).length)throw fail('LISTINGS_INSTALL_IMAGE_CONFLICT');
  let value=existing||managed.validate({version:1,workspaceId:p.workspaceId,enabled:false,architecture:'arm64',dockerAuthoritySha256:p.dockerAuthoritySha256,imageId:image.Id,sourceManifestSha256:p.source.sha256,runtimeDigest:p.runtimeDigest,profile:p.profile,manager:{...p.manager,token:crypto.randomBytes(48).toString('base64url')}});
  if(value.enabled)throw fail('LISTINGS_INSTALL_ALREADY_ACTIVE');managed.stage({filePath:p.managedPath,value});
  const network=value.manager.container+'-bridge',volume=value.manager.container+'-journal';
  for(const [kind,name]of [['network',network],['volume',volume]]){let resource=await inspect(kind,name);if(!resource){try{await docker([kind,'create',...labelArgs,name]);}catch{}resource=await inspect(kind,name);}if(!resource||resource.Name!==name||Object.entries(labels).some(([k,v])=>resource.Labels?.[k]!==v)||(kind==='network'?(resource.Driver!=='bridge'||resource.Internal!==false):(resource.Driver!=='local'||Object.keys(resource.Options||{}).length)))throw fail('LISTINGS_INSTALL_RESOURCE_CONFLICT');}
  let container=await inspect('container',value.manager.container);
  const recoveryJournal=portRecovery._internals.readJournal(p.managedPath);
  if(recoveryJournal&&options.explicitActivation!==true&&value.manager.url==='http://127.0.0.1:8095')throw fail('LISTINGS_INSTALL_PORT_RECOVERY_PENDING');
  if(options.explicitActivation===true&&(recoveryJournal||value.manager.url==='http://127.0.0.1:8095'
    &&container?.State?.Running===true&&Object.keys(container.NetworkSettings?.Networks||{}).length===0
    &&Object.keys(container.NetworkSettings?.Ports||{}).length===0)){
   const verifyAuthority=async()=>{const now=await authorityIdentity(authorityPath);if(!same(now,initialAuthorityIdentity))throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');await verifyDockerAuthority({authority,execute,environment});await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});};
   const verifySource=async()=>{if(sourceManifest(root).sha256!==p.source.sha256)throw fail('LISTINGS_INSTALL_SOURCE_CHANGED');};
   const health=async selected=>{const denied=()=>{throw fail('LISTINGS_INSTALL_TARGET_FORBIDDEN');};const client=createListingsTargetManager({origin:selected.manager.url,controlToken:selected.manager.token,runtimeDigest:selected.runtimeDigest,launches:{assertCurrent:denied,readExistingProductsTarget:denied},products:{open:denied,readCleanupReceipt:denied},resolveMode:denied,timeoutMs:2000,fetchImpl:options.fetchImpl||fetch});await client.health();};
   await portRecovery.recover({p,value,image,labels,network,volume,docker,inspect,inspectContainer,verifyAuthority,verifySource,health,applicationEnvironment:options.applicationEnvironment,maintenanceScope:options.maintenanceScope,assertUnused:options.assertUnusedListings,checkPort:options.checkListingsPort,assertMaintenance:options.assertMaintenance});
   value=managed.load({filePath:p.managedPath});container=await inspect('container',value.manager.container);
  }
  if(!container){const envFile=path.join(temp,'manager.env');await fs.writeFile(envFile,`LISTINGS_MANAGER_ENABLED=true\nLISTINGS_PROFILE=${value.profile.name}\nLISTINGS_PUBLIC_ORIGIN=${value.manager.url}\nLISTINGS_CONTROL_TOKEN=${value.manager.token}\n`,{mode:0o600,flag:'wx'});
   try{await docker(['create','--name',value.manager.container,...labelArgs,'--network',network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--mount',`type=volume,source=${volume},target=/journal`,'--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile.name,'--publish',`127.0.0.1:${new URL(value.manager.url).port}:8095`,'--env-file',envFile,image.Id]);}catch{}
   container=await inspect('container',value.manager.container);if(!container)throw fail('LISTINGS_INSTALL_CREATE_UNCERTAIN');
  }
  const expected={value,image,labels,network,volume};inspectContainer(container,expected,{allowCreatedUnattached:true,allowRunningUnattached:true});
  if(!container.State.Running){const retainedId=container.Id;try{await docker(['start',retainedId]);}catch{}container=await inspect('container',value.manager.container);if(container?.Id!==retainedId)throw fail('LISTINGS_INSTALL_CONTAINER_CONFLICT');}
  if(!container?.State?.Running)throw fail('LISTINGS_INSTALL_START_UNCERTAIN');
  const attached=Object.keys(container.NetworkSettings?.Networks||{});
  if(attached.length===0){
   // One exact retained manager on one exact owned bridge may need a separate
   // Docker endpoint attach. No resource is replaced and no foreign endpoint
   // may be present. A lost connect acknowledgement is resolved by inspection.
   inspectContainer(container,expected,{allowRunningUnattached:true});
   const before=managed.capture({filePath:p.managedPath});
   if(!before||managed.encode(before.value)!==managed.encode(value))throw fail('LISTINGS_INSTALL_CONFIGURATION_CHANGED');
   const repairAuthority=await authorityIdentity(authorityPath);
   if(!same(repairAuthority,initialAuthorityIdentity))throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');
   const bridge=await inspect('network',network);
   const ownedBridge=candidate=>candidate&&candidate.Id===bridge.Id&&candidate.Name===network&&candidate.Driver==='bridge'&&candidate.Internal===false
    &&Object.entries(labels).every(([k,v])=>candidate.Labels?.[k]===v)
    &&candidate.Containers&&Object.getPrototypeOf(candidate.Containers)===Object.prototype;
   if(!/^[a-f0-9]{64}$/.test(bridge?.Id||'')||!ownedBridge(bridge)||Object.keys(bridge.Containers).length!==0)throw fail('LISTINGS_INSTALL_NETWORK_CONFLICT');
   await verifyDockerAuthority({authority,execute,environment});await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
   if(sourceManifest(root).sha256!==p.source.sha256)throw fail('LISTINGS_INSTALL_SOURCE_CHANGED');
   const current=managed.capture({filePath:p.managedPath}),fresh=await inspect('container',value.manager.container),freshBridge=await inspect('network',network);
   const currentAuthority=await authorityIdentity(authorityPath);
   if(!current||current.dev!==before.dev||current.ino!==before.ino||current.sha256!==before.sha256||fresh?.Id!==container.Id
    ||!same(currentAuthority,initialAuthorityIdentity)||!ownedBridge(freshBridge)||Object.keys(freshBridge.Containers).length!==0)throw fail('LISTINGS_INSTALL_RESOURCE_CHANGED');
   inspectContainer(fresh,expected,{allowRunningUnattached:true});
   try{await docker(['network','connect',bridge.Id,container.Id]);}catch{}
   container=await inspect('container',value.manager.container);
   const connectedBridge=await inspect('network',network);
   if(container?.Id!==fresh.Id||!same(await authorityIdentity(authorityPath),initialAuthorityIdentity)||!ownedBridge(connectedBridge)
    ||Object.keys(connectedBridge.Containers).length!==1||!Object.hasOwn(connectedBridge.Containers,container.Id))throw fail('LISTINGS_INSTALL_NETWORK_CONNECT_UNCERTAIN');
  }
  inspectContainer(container,expected);
  // Health-only adapter dependencies cannot admit or retire a learner target.
  const denied=()=>{throw fail('LISTINGS_INSTALL_TARGET_FORBIDDEN');};
  const client=createListingsTargetManager({origin:value.manager.url,controlToken:value.manager.token,runtimeDigest:value.runtimeDigest,launches:{assertCurrent:denied,readExistingProductsTarget:denied},products:{open:denied,readCleanupReceipt:denied},resolveMode:denied,timeoutMs:2000,fetchImpl:options.fetchImpl||fetch});
  let healthy=false;for(let attempt=0;attempt<10&&!healthy;attempt++){try{await client.health();healthy=true;}catch{}if(!healthy)await new Promise(resolve=>setTimeout(resolve,100));}
  if(!healthy)throw fail('LISTINGS_INSTALL_READINESS_FAILED');
  return Object.freeze({staged:true,managerReady:true,ready:false,capabilityAvailable:false,activationEnabled:false,managedPath:p.managedPath,imageId:value.imageId,runtimeDigest:value.runtimeDigest,sourceManifestSha256:p.source.sha256,workspaceId:p.workspaceId,installedEnvironmentModified:false});
 }finally{const now=await fs.lstat(temp);if(now.dev!==tempStat.dev||now.ino!==tempStat.ino||now.uid!==process.getuid()||now.isSymbolicLink())throw fail('LISTINGS_INSTALL_TEMP_CHANGED');await fs.rm(temp,{recursive:true});}
}
// Existing-only admission shared by explicit activation and normal startup.
// It never builds, creates, adopts or rotates any resource.
async function verifyExisting(options={}){
 const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform;
 const environment=sanitizeDockerEnvironment(options.environment||process.env),run=options.run||createRunner({cwd:root,env:environment});
 const filePath=managed.managedPath({root,home}),initial=managed.capture({filePath});
 if(!initial)throw fail('LISTINGS_INSTALL_CONFIGURATION_MISSING');
 const value=initial.value;
 const installedAdmission=!options.qualify&&!options.qualified;
 const qualify=options.qualify||(args=>require('./secureshop-owned-listings-qualified-candidate').qualifiedInstalledPackage({...args,configuration:value}));
 const qualified=options.qualified||qualify({root,architecture:options.architecture||process.arch});
 if(options.configuration&&managed.encode(options.configuration)!==managed.encode(value))throw fail('LISTINGS_INSTALL_CONFIGURATION_CHANGED');
 if(options.startStopped===true&&value.enabled!==true)throw fail('LISTINGS_INSTALL_NOT_ACTIVE');
 const execute=async(file,args,o)=>{const result=await run(file,args,{timeoutMs:o.timeout,maxOutputBytes:1048576});if(result.exitCode!==0)throw fail('LISTINGS_INSTALL_COMMAND_FAILED');return result;};
 const p=await plan({root,home,platform,architecture:options.architecture||process.arch,environment,execute,...qualified,port:Number(new URL(value.manager.url).port),...(installedAdmission?{existingQualification:qualified}:{})});
 if(!p.existing||p.runtimeDigest!==value.runtimeDigest||p.source.sha256!==value.sourceManifestSha256||p.dockerAuthoritySha256!==value.dockerAuthoritySha256)throw fail('LISTINGS_INSTALL_CONFIGURATION_CHANGED');
 const authorityPath=path.join(path.dirname(filePath),'local-docker.json');
 const initialAuthority=await authorityIdentity(authorityPath);
 const authority=await readLocalDockerAuthority({directory:path.dirname(filePath),workspaceId:p.workspaceId,platform});
 if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');
 await verifyDockerAuthority({authority,execute,environment});
 await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
 async function docker(args){let result;try{result=await run('docker',['--host',authority.host,...args],{timeoutMs:30000,maxOutputBytes:1048576});}catch{throw fail('LISTINGS_INSTALL_COMMAND_UNCERTAIN');}
  if(result.exitCode!==0)throw fail('LISTINGS_INSTALL_RESOURCE_MISSING');return result.stdout;}
 async function inspect(kind,name){let rows;try{rows=JSON.parse(await docker([kind,'inspect',name]));}catch{throw fail('LISTINGS_INSTALL_INSPECT_INVALID');}
  if(!Array.isArray(rows)||rows.length!==1)return null;return rows[0];}
 const labels={'dvaia.listings.workspace':p.workspaceId,'dvaia.listings.authority':p.dockerAuthoritySha256,'dvaia.listings.source':p.source.sha256,'dvaia.listings.runtime':p.runtimeDigest};
 const networkName=value.manager.container+'-bridge',volumeName=value.manager.container+'-journal';
 let retainedNetworkId,retainedVolumeMountpoint;
 const checkPrivate=async()=>{const current=managed.capture({filePath}),a=await authorityIdentity(authorityPath);
  if(!current||current.dev!==initial.dev||current.ino!==initial.ino||current.sha256!==initial.sha256||a.dev!==initialAuthority.dev||a.ino!==initialAuthority.ino||a.sha256!==initialAuthority.sha256)throw fail('LISTINGS_INSTALL_PRIVATE_STATE_CHANGED');};
 async function checkResources(){
  const [image,network,volume,container]=await Promise.all([inspect('image',value.imageId),inspect('network',networkName),inspect('volume',volumeName),inspect('container',value.manager.container)]);
  if(!image||image.Id!==value.imageId||image.Architecture!=='arm64'||image.Os!=='linux'||Object.entries(labels).some(([k,v])=>image.Config?.Labels?.[k]!==v)||image.Config.User!=='10001:10001'||image.Config.WorkingDir!=='/app'||!same(image.Config.Entrypoint,ENTRY)||image.Config.Cmd?.length||Object.keys(image.Config.Volumes||{}).length)throw fail('LISTINGS_INSTALL_IMAGE_CONFLICT');
  if(!network||network.Name!==networkName||network.Driver!=='bridge'||network.Internal!==false||Object.entries(labels).some(([k,v])=>network.Labels?.[k]!==v)
   ||!/^([a-f0-9]{64})$/.test(network.Id||'')
   ||!volume||volume.Name!==volumeName||volume.Driver!=='local'||Object.keys(volume.Options||{}).length||Object.entries(labels).some(([k,v])=>volume.Labels?.[k]!==v)
   ||typeof volume.Mountpoint!=='string'||!path.isAbsolute(volume.Mountpoint))throw fail('LISTINGS_INSTALL_RESOURCE_CONFLICT');
  if(retainedNetworkId&&retainedNetworkId!==network.Id||retainedVolumeMountpoint&&retainedVolumeMountpoint!==volume.Mountpoint)throw fail('LISTINGS_INSTALL_RESOURCE_CHANGED');
  retainedNetworkId=network.Id;retainedVolumeMountpoint=volume.Mountpoint;
  if(!container||!/^\/[a-z0-9-]+$/.test(container.Name||'')||!/^([a-f0-9]{64})$/.test(container.Id||''))throw fail('LISTINGS_INSTALL_CONTAINER_CONFLICT');
  inspectContainer(container,{value,image,labels,network:networkName,volume:volumeName});
  if(Object.keys(network.Containers||{}).some(id=>id!==container.Id))throw fail('LISTINGS_INSTALL_NETWORK_FOREIGN_ENDPOINT');
  if(!['running','exited'].includes(container.State?.Status)||container.State.Running!==(container.State.Status==='running'))throw fail('LISTINGS_INSTALL_CONTAINER_CONFLICT');
  return container;
 }
 let container=await checkResources(),startedHere=false;
 if(!container.State.Running){
  if(options.startStopped!==true)throw fail('LISTINGS_INSTALL_MANAGER_STOPPED');
  await checkPrivate();await verifyDockerAuthority({authority,execute,environment});await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
  const checked=await checkResources();if(checked.Id!==container.Id||checked.State.Running)throw fail('LISTINGS_INSTALL_CONTAINER_CHANGED');
  try{await docker(['start',container.Id]);}catch(error){
   const observed=await checkResources();if(observed.Id!==container.Id||!observed.State.Running)throw error;
  }
  container=await checkResources();
  if(container.Id!==checked.Id||!container.State.Running)throw fail('LISTINGS_INSTALL_START_UNCERTAIN');
  startedHere=true;
 }
 const denied=()=>{throw fail('LISTINGS_INSTALL_TARGET_FORBIDDEN');};
 const client=createListingsTargetManager({origin:value.manager.url,controlToken:value.manager.token,runtimeDigest:value.runtimeDigest,launches:{assertCurrent:denied,readExistingProductsTarget:denied},products:{open:denied,readCleanupReceipt:denied},resolveMode:denied,timeoutMs:2000,fetchImpl:options.fetchImpl||fetch});
 const readinessDeadline=Date.now()+8000;
 async function healthAfterStart(){
  for(let attempt=0;;attempt++){
   try{return await client.health();}catch(error){
    const transient=error instanceof TypeError||error?.code==='LISTINGS_MANAGER_TIMEOUT'||error?.name==='AbortError';
    if(!startedHere||!transient)throw error;
    if(attempt>=9||Date.now()>=readinessDeadline)throw fail('LISTINGS_INSTALL_READINESS_FAILED');
    await new Promise(resolve=>setTimeout(resolve,100));
    await checkPrivate();const sameContainer=await checkResources();
    if(sameContainer.Id!==container.Id||!sameContainer.State.Running)throw fail('LISTINGS_INSTALL_CONTAINER_CHANGED');
   }
  }
 }
 await healthAfterStart();await checkPrivate();await verifyDockerAuthority({authority,execute,environment});await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
 const final=await checkResources();if(final.Id!==container.Id||!final.State.Running)throw fail('LISTINGS_INSTALL_CONTAINER_CHANGED');
 await healthAfterStart();await checkPrivate();
 const finalSource=qualify({root,architecture:options.architecture||process.arch});
 if(finalSource.runtimeDigest!==value.runtimeDigest||finalSource.qualifiedSourceSha256!==value.sourceManifestSha256)throw fail('LISTINGS_INSTALL_SOURCE_CHANGED');
 const last=await checkResources();if(last.Id!==container.Id||!last.State.Running)throw fail('LISTINGS_INSTALL_CONTAINER_CHANGED');
 await checkPrivate();
 return Object.freeze({ready:true,enabled:value.enabled,containerId:container.Id});
}
module.exports={prepare:plan,provision,verifyExisting,_internals:{verifyProfile,inspectContainer}};
