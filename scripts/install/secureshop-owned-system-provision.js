'use strict';

const fs=require('node:fs');
const fsp=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {plan,sourceManifest}=require('./secureshop-owned-system');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {localProfilePlan}=require('./mcp-owned-local');
const {createSecureShopSystemConfigClient}=require('../../server/services/secureshopSystemConfigClient');
const {createSecureShopSystemDiagnosticClient}=require('../../server/services/secureshopSystemDiagnosticClient');
const {createSecureShopSystemRestartClient}=require('../../server/services/secureshopSystemRestartClient');
const fail=code=>Object.assign(new Error('Owned System provisioning requires recovery'),{code});
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const equalRecord=(a,b)=>equal(Object.entries(a||{}).sort(([x],[y])=>x.localeCompare(y)),Object.entries(b||{}).sort(([x],[y])=>x.localeCompare(y)));

function createRunner({cwd,env}) {
  return (file,args,{timeoutMs=30000,maxOutputBytes=1048576}={})=>new Promise((resolve,reject)=>{
    const child=spawn(file,args,{cwd,env,shell:false,detached:true,stdio:['ignore','pipe','pipe']});
    const stdout=[],stderr=[];let size=0,failed=false,closed=false,settled=false,escalated=false,escalation,drain,poll;
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);clearTimeout(escalation);clearTimeout(drain);clearTimeout(poll);error?reject(error):resolve(value);};
    const signal=name=>{try{process.kill(-child.pid,name);}catch(error){if(error.code!=='ESRCH')return false;}return true;};
    const absent=()=>{try{process.kill(-child.pid,0);return false;}catch(error){return error.code==='ESRCH';}};
    const joined=()=>{if(closed&&escalated&&absent())finish(fail('SYSTEM_INSTALL_COMMAND_FAILED'));else poll=setTimeout(joined,20);};
    const stop=()=>{if(failed)return;failed=true;signal('SIGTERM');escalation=setTimeout(()=>{signal('SIGKILL');escalated=true;joined();},1000);drain=setTimeout(()=>finish(fail('SYSTEM_INSTALL_COMMAND_DRAIN_FAILED')),5000);};
    for(const [stream,chunks] of [[child.stdout,stdout],[child.stderr,stderr]])stream.on('data',chunk=>{size+=chunk.length;if(size>maxOutputBytes)stop();else chunks.push(chunk);});
    const timer=setTimeout(stop,timeoutMs);
    child.on('error',()=>finish(fail('SYSTEM_INSTALL_COMMAND_FAILED')));
    child.on('close',code=>{closed=true;if(failed)return;if(!absent()){stop();return;}finish(null,{exitCode:code,stdout:Buffer.concat(stdout).toString(),stderr:Buffer.concat(stderr).toString()});});
  });
}

async function buildCaSecret({environment,temp,secrets=[]}) {
  const configured=require('./listings-setup').configuredBuildCa(environment);
  if(!configured.buildCaFile)return [];
  const bytes=await fsp.readFile(configured.buildCaFile);
  if(bytes.length>1048576||sha(bytes)!==configured.buildCaSha256)throw fail('SYSTEM_INSTALL_BUILD_CA_CHANGED');
  const file=path.join(temp,'npm-ca.pem');await fsp.writeFile(file,bytes,{mode:0o600,flag:'wx'});
  secrets.push({path:file,stat:await fsp.lstat(file)});
  return ['--secret','id=npm_ca,src='+file];
}

async function verifyProfile({p,authority,root,home,platform,run}) {
  let location;
  if(platform==='linux')location=localProfilePlan({root,home,platform});
  else {
    const prefix=`unix://${path.join(home,'.colima')}/`,suffix='/docker.sock';
    if(!authority.host.startsWith(prefix)||!authority.host.endsWith(suffix))throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
    const selected=authority.host.slice(prefix.length,-suffix.length);
    if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(selected))throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
    location=localProfilePlan({root,home,platform,colimaProfile:'colima-'+selected});
  }
  if(location.dockerHost!==authority.host)throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
  const command=async args=>{
    const file=platform==='linux'?'sudo':'ssh';
    const argv=platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,'sudo','--non-interactive',...args];
    const result=await run(file,argv,{timeoutMs:10000,maxOutputBytes:1048576});if(result.exitCode!==0)throw fail('SYSTEM_INSTALL_PROFILE_UNAVAILABLE');return result.stdout;
  };
  const digest=(await command(['sha256sum',location.destination])).trim().split(/\s+/)[0];
  const profiles=(await command(['cat','/sys/kernel/security/apparmor/profiles'])).split(/\r?\n/);
  if(digest!==p.profile.sha256||!profiles.includes(p.profile.name+' (enforce)'))throw fail('SYSTEM_INSTALL_PROFILE_CONFLICT');
}

function inspectContainer(found,{mode,p,value,image,network,labels,restartVolume}) {
  const row=value[mode],hc=found?.HostConfig,c=found?.Config;
  const envPrefix=mode==='uploadPreview'?'SECURESHOP_UPLOAD_PREVIEW':'SECURESHOP_SYSTEM_'+mode.toUpperCase();
  const expectedEnv=[...(image.Config.Env||[]),`${envPrefix}_HTTP_ENABLED=true`,`${envPrefix}_TOKEN=${row.token}`,`${envPrefix}_HOST=0.0.0.0`,`${envPrefix}_PORT=8090`].sort();
  const port=String(new URL(row.url).port),tmpfs=mode==='uploadPreview'?{'/tmp':'rw,nosuid,nodev,size=128m','/var/lib/dvaia-owned-upload-preview':'rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001'}:mode==='restart'?{'/tmp':'rw,nosuid,nodev,size=128m','/owned-restart':'rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001'}:{'/tmp':'rw,nosuid,nodev,size=128m'};
  if(!found||found.Name!=='/'+row.container||found.Image!==value.imageId||!hc||!c
    ||Object.entries(labels).some(([k,v])=>c.Labels?.[k]!==v)||c.Labels?.['dvaia.system.mode']!==mode
    ||c.User!=='10001:10001'||!equal(c.Entrypoint,['/usr/local/bin/node','/opt/dvaia-owned-system/local-listener-entry.js'])||!equal(c.Cmd,[mode==='uploadPreview'?'upload-preview':mode])
    ||!equal([...(c.Env||[])].sort(),expectedEnv)||(mode==='restart'?!equal((found.Mounts||[]).map(m=>({Type:m.Type,Name:m.Name,Destination:m.Destination,RW:m.RW})),[{Type:'volume',Name:restartVolume,Destination:'/var/lib/dvaia-owned-restart',RW:true}]):(found.Mounts?.length!==0))||hc.Privileged!==false||hc.ReadonlyRootfs!==true
    ||hc.Memory!==536870912||hc.NanoCpus!==1000000000||hc.PidsLimit!==128
    ||!equalRecord(hc.Tmpfs,tmpfs)||hc.Binds?.length||hc.Devices?.length||hc.DeviceRequests?.length
    ||hc.PidMode||hc.IpcMode==='host'||hc.UsernsMode==='host'||hc.CapAdd?.length
    ||!equal([...(hc.SecurityOpt||[])].sort(),['apparmor='+p.profile.name,'seccomp=unconfined'].sort())
    ||hc.NetworkMode!==network||!equal(Object.keys(found.NetworkSettings?.Networks||{}),[network])
    ||!equal(hc.PortBindings,{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}))throw fail('SYSTEM_INSTALL_CONTAINER_CONFLICT');
  if(found.State?.Running&&!equal(found.NetworkSettings.Ports,{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}))throw fail('SYSTEM_INSTALL_CONTAINER_CONFLICT');
}

async function provision(options={}) {
  const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform;
  const environment=sanitizeDockerEnvironment(options.environment||process.env);
  const run=options.run||createRunner({cwd:root,env:environment});
  const execute=async(file,args,commandOptions)=>{const result=await run(file,args,{timeoutMs:commandOptions.timeout,maxOutputBytes:1048576});if(result.exitCode!==0)throw fail('SYSTEM_INSTALL_COMMAND_FAILED');return result;};
  const p=await plan({...options,root,home,platform,execute,environment});
  const authority=await readLocalDockerAuthority({directory:path.dirname(p.managedPath),workspaceId:p.workspaceId,platform});
  if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('SYSTEM_INSTALL_AUTHORITY_CHANGED');
  await verifyDockerAuthority({authority,execute,environment});
  await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
  const docker=async(args,{timeoutMs=30000,allowMissing=false}={})=>{
    let result;try{result=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});}
    catch{throw fail('SYSTEM_INSTALL_COMMAND_UNCERTAIN');}
    if(result.exitCode!==0){if(allowMissing&&/no such|not found/i.test(result.stderr||''))return null;throw fail('SYSTEM_INSTALL_COMMAND_FAILED');}
    return result.stdout;
  };
  const inspect=async(kind,name)=>{const raw=await docker([kind,'inspect',name],{allowMissing:true});if(raw===null)return null;try{const rows=JSON.parse(raw);if(!Array.isArray(rows)||rows.length!==1)throw Error();return rows[0];}catch{throw fail('SYSTEM_INSTALL_INSPECT_INVALID');}};
  const labels={'dvaia.system.workspace':p.workspaceId,'dvaia.system.authority':p.dockerAuthoritySha256,'dvaia.system.source':p.source.sha256};
  const labelArgs=Object.entries(labels).flatMap(([k,v])=>['--label',`${k}=${v}`]);
  const temp=await fsp.mkdtemp(path.join(os.tmpdir(),'dvaia-system-install-'));await fsp.chmod(temp,0o700);const tempIdentity=await fsp.lstat(temp);const secrets=[];
  try {
    const existing=managed.load({filePath:p.managedPath});const tag=`dvaia-owned-system-${p.workspaceId}:local`;
    let image=await inspect('image',existing?.imageId||tag);
    if(!image&&existing)throw fail('SYSTEM_INSTALL_STAGED_IMAGE_MISSING');
    if(!image){
      const base=await inspect('image',p.source.baseImage);if(base?.Id!==p.source.baseImage||base?.Architecture!=='arm64')throw fail('SYSTEM_INSTALL_BASE_UNQUALIFIED');
      const current=sourceManifest(root);if(current.sha256!==p.source.sha256)throw fail('SYSTEM_INSTALL_SOURCE_CHANGED');
      const sourceDir=path.join(root,'sidecars/sandbox-runner/owned-system');
      const context=path.join(temp,'build');await fsp.mkdir(context,{mode:0o700});
      for(const [name,digest] of Object.entries(current.files)){
        const bytes=await fsp.readFile(path.join(sourceDir,name));if(sha(bytes)!==digest)throw fail('SYSTEM_INSTALL_SOURCE_CHANGED');
        await fsp.mkdir(path.dirname(path.join(context,name)),{recursive:true,mode:0o700});
        await fsp.writeFile(path.join(context,name),bytes,{mode:0o400,flag:'wx'});
      }
      if(sourceManifest(root).sha256!==p.source.sha256)throw fail('SYSTEM_INSTALL_SOURCE_CHANGED');
      const buildSecrets=await buildCaSecret({environment:options.environment||process.env,temp,secrets});
      await docker(['build','--pull=false','--network=default',...buildSecrets,...labelArgs,'-f',path.join(context,'Dockerfile.local'),'-t',tag,context],{timeoutMs:300000});
      image=await inspect('image',tag);
    }
    if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Architecture!=='arm64'||image.Os!=='linux'
      ||Object.entries(labels).some(([k,v])=>image.Config?.Labels?.[k]!==v)||image.Config?.User!=='10001:10001'
      ||!equal(image.Config.Entrypoint,['/usr/local/bin/node','/opt/dvaia-owned-system/local-listener-entry.js'])
      ||image.Config.Cmd?.length||image.Config.Volumes&&Object.keys(image.Config.Volumes).length)throw fail('SYSTEM_INSTALL_IMAGE_CONFLICT');
    if(options.imageId&&options.imageId!==image.Id)throw fail('SYSTEM_INSTALL_IMAGE_CONFLICT');
    const value=existing||managed.validate({version:1,workspaceId:p.workspaceId,enabled:false,architecture:'arm64',dockerAuthoritySha256:p.dockerAuthoritySha256,
      imageId:image.Id,sourceManifestSha256:p.source.sha256,profile:p.profile,
      config:{...p.config,token:crypto.randomBytes(48).toString('base64url')},diagnostic:{...p.diagnostic,token:crypto.randomBytes(48).toString('base64url')},restart:{...p.restart,token:crypto.randomBytes(48).toString('base64url')},
      ...(p.uploadPreview?{uploadPreview:{...p.uploadPreview,token:crypto.randomBytes(48).toString('base64url')}}:{})});
    if(existing?.enabled && options.reconcileEnabled!==true)throw fail('SYSTEM_INSTALL_ALREADY_ACTIVE');
    if(!value.enabled)managed.stage({filePath:p.managedPath,value});
    const resourceLabels={...labels,'dvaia.system.source':value.resourceSourceManifestSha256||value.sourceManifestSha256};
    const resourceLabelArgs=Object.entries(resourceLabels).flatMap(([k,v])=>['--label',`${k}=${v}`]);
    const network=`dvaia-owned-system-${p.workspaceId}-bridge`;
    let net=await inspect('network',network);
    if(!net){try{await docker(['network','create',...resourceLabelArgs,network]);}catch{}net=await inspect('network',network);}
    if(!net||net.Name!==network||net.Driver!=='bridge'||net.Internal!==false||Object.entries(resourceLabels).some(([k,v])=>net.Labels?.[k]!==v))throw fail('SYSTEM_INSTALL_NETWORK_CONFLICT');
    const restartVolume=`dvaia-owned-system-${p.workspaceId}-restart-state`;let volume=await inspect('volume',restartVolume);if(!volume){try{await docker(['volume','create',...resourceLabelArgs,'--label','dvaia.system.mode=restart-state',restartVolume]);}catch{}volume=await inspect('volume',restartVolume);}if(!volume||volume.Name!==restartVolume||Object.entries(resourceLabels).some(([k,v])=>volume.Labels?.[k]!==v)||volume.Labels?.['dvaia.system.mode']!=='restart-state')throw fail('SYSTEM_INSTALL_VOLUME_CONFLICT');
    const readiness={};
    for(const mode of managed.modesFor(value)){
      let found=await inspect('container',value[mode].container);
      if(!found){
        const envFile=path.join(temp,mode+'.env'),prefix=mode==='uploadPreview'?'SECURESHOP_UPLOAD_PREVIEW':'SECURESHOP_SYSTEM_'+mode.toUpperCase();
        await fsp.writeFile(envFile,`${prefix}_HTTP_ENABLED=true\n${prefix}_TOKEN=${value[mode].token}\n${prefix}_HOST=0.0.0.0\n${prefix}_PORT=8090\n`,{mode:0o600,flag:'wx'});
        secrets.push({path:envFile,stat:await fsp.lstat(envFile)});
        const modeTmpfs=mode==='uploadPreview'?['--tmpfs','/var/lib/dvaia-owned-upload-preview:rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001']:mode==='restart'?['--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--mount',`type=volume,source=${restartVolume},target=/var/lib/dvaia-owned-restart`]:[];
        try{await docker(['create','--name',value[mode].container,...labelArgs,'--label','dvaia.system.mode='+mode,
          '--network',network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128',
          '--tmpfs','/tmp:rw,nosuid,nodev,size=128m',...modeTmpfs,'--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile.name,
          '--publish',`127.0.0.1:${new URL(value[mode].url).port}:8090`,'--env-file',envFile,image.Id,mode==='uploadPreview'?'upload-preview':mode]);}catch{}
        // A timeout or create conflict never chooses another name or bearer.
        found=await inspect('container',value[mode].container);
        if(!found)throw fail('SYSTEM_INSTALL_CREATE_UNCERTAIN');
      }
      inspectContainer(found,{mode,p,value,image,network,labels,restartVolume});
      if(!found.State.Running){try{await docker(['start',value[mode].container]);}catch{}found=await inspect('container',value[mode].container);}
      inspectContainer(found,{mode,p,value,image,network,labels,restartVolume});if(!found.State.Running)throw fail('SYSTEM_INSTALL_START_UNCERTAIN');
      const factory=mode==='uploadPreview'?(options.createUploadPreviewClient||require('../../server/services/secureshopUploadPreviewClient').createSecureShopUploadPreviewClient):mode==='config'?(options.createConfigClient||createSecureShopSystemConfigClient):mode==='diagnostic'?(options.createDiagnosticClient||createSecureShopSystemDiagnosticClient):(options.createRestartClient||createSecureShopSystemRestartClient);
      const client=factory({baseURL:value[mode].url,token:value[mode].token});
      let ready=false;for(let attempt=0;attempt<3&&!ready;attempt++){try{ready=mode==='restart'?(await client.health())?.ready===true:await client.assertReady()===true;}catch{}if(!ready)await new Promise(resolve=>setTimeout(resolve,100));}
      if(!ready)throw fail('SYSTEM_INSTALL_READINESS_FAILED');
      if(mode==='config'){const metrics=await client.metrics();if(metrics?.ok!==true||metrics.metricsSource!=='owned-system-listener')throw fail('SYSTEM_INSTALL_METRICS_FAILED');}
      readiness[mode]=true;
    }
    return Object.freeze({staged:true,ready:true,activationEnabled:value.enabled,managedPath:p.managedPath,imageId:value.imageId,sourceManifestSha256:p.source.sha256,
      workspaceId:p.workspaceId,readiness:Object.freeze(readiness),outerEgressIsolationEstablished:false,installedEnvironmentModified:false});
  } finally {
    for(const item of secrets){const now=await fsp.lstat(item.path).catch(()=>null);if(now){if(now.dev!==item.stat.dev||now.ino!==item.stat.ino||now.uid!==process.getuid()||now.nlink!==1)throw fail('SYSTEM_INSTALL_TEMP_IDENTITY_CHANGED');await fsp.unlink(item.path);}}
    const now=await fsp.lstat(temp);if(now.dev!==tempIdentity.dev||now.ino!==tempIdentity.ino||now.uid!==process.getuid()||now.isSymbolicLink())throw fail('SYSTEM_INSTALL_TEMP_IDENTITY_CHANGED');
    await fsp.rm(temp,{recursive:true});
  }
}

// Runtime recovery may start only the three resources already admitted by an
// enabled private installation. It never enters the provisioning path.
async function startExisting(options={}) {
  const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir();
  const platform=options.platform||process.platform,architecture=options.architecture||process.arch;
  const filePath=managed.managedPath({root,home}),record=managed.capture({filePath});
  if(!record?.value.enabled)throw fail('SYSTEM_START_EXISTING_REQUIRED');
  const value=record.value,environment=sanitizeDockerEnvironment(options.environment||process.env);
  const run=options.run||createRunner({cwd:root,env:environment});
  const execute=async(file,args,commandOptions={})=>{
    const result=await run(file,args,{timeoutMs:commandOptions.timeout||30000,maxOutputBytes:1048576});
    if(result.exitCode!==0)throw fail('SYSTEM_START_COMMAND_FAILED');return result;
  };
  const ports=Object.fromEntries(managed.modesFor(value).map(mode=>[mode+'Port',Number(new URL(value[mode].url).port)]));
  const p=await plan({root,home,platform,architecture,environment,execute,imageId:value.imageId,...ports});
  if(!p.existing||!p.enabled)throw fail('SYSTEM_START_EXISTING_REQUIRED');
  const directory=path.dirname(filePath),authorityFile=path.join(directory,'local-docker.json');
  const captureAuthority=()=>require('../../server/services/secureshopPricingManagedConfiguration')._private.captureFile(authorityFile,8192);
  const authorityIdentity=captureAuthority();
  const authority=await readLocalDockerAuthority({directory,workspaceId:p.workspaceId,platform});
  if(!authority||authorityDigest(authority)!==value.dockerAuthoritySha256)throw fail('SYSTEM_START_AUTHORITY_CHANGED');
  await verifyDockerAuthority({authority,execute,environment});
  await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
  const docker=async args=>{
    const result=await run('docker',['--host',authority.host,...args],{timeoutMs:15000,maxOutputBytes:1048576});
    if(result.exitCode!==0)throw fail('SYSTEM_START_COMMAND_FAILED');return result.stdout;
  };
  const inspect=async(kind,id)=>{
    let rows;try{rows=JSON.parse(await docker([kind,'inspect',id]));}catch{throw fail('SYSTEM_START_INSPECT_FAILED');}
    if(!Array.isArray(rows)||rows.length!==1)throw fail('SYSTEM_START_INSPECT_FAILED');return rows[0];
  };
  const samePrivateState=()=>{
    const current=managed.capture({filePath}),now=captureAuthority();
    if(!current||current.dev!==record.dev||current.ino!==record.ino||current.sha256!==record.sha256
      ||now.identity.dev!==authorityIdentity.identity.dev||now.identity.ino!==authorityIdentity.identity.ino||now.sha256!==authorityIdentity.sha256)
      throw fail('SYSTEM_START_STATE_CHANGED');
  };
  const image=await inspect('image',value.imageId);
  const labels={'dvaia.system.workspace':p.workspaceId,'dvaia.system.authority':p.dockerAuthoritySha256,'dvaia.system.source':p.source.sha256};
  if(image.Id!==value.imageId||image.Architecture!=='arm64'||image.Os!=='linux'
    ||Object.entries(labels).some(([key,expected])=>image.Config?.Labels?.[key]!==expected)
    ||image.Config?.User!=='10001:10001'
    ||!equal(image.Config.Entrypoint,['/usr/local/bin/node','/opt/dvaia-owned-system/local-listener-entry.js'])
    ||image.Config.Cmd?.length||image.Config.Volumes&&Object.keys(image.Config.Volumes).length)
    throw fail('SYSTEM_START_IMAGE_CONFLICT');
  const resourceLabels={...labels,'dvaia.system.source':value.resourceSourceManifestSha256||value.sourceManifestSha256};
  const network=`dvaia-owned-system-${p.workspaceId}-bridge`,net=await inspect('network',network);
  if(net.Name!==network||net.Driver!=='bridge'||net.Internal!==false
    ||Object.entries(resourceLabels).some(([key,expected])=>net.Labels?.[key]!==expected))throw fail('SYSTEM_START_NETWORK_CONFLICT');
  const restartVolume=`dvaia-owned-system-${p.workspaceId}-restart-state`,volume=await inspect('volume',restartVolume);
  if(volume.Name!==restartVolume||volume.Labels?.['dvaia.system.mode']!=='restart-state'
    ||Object.entries(resourceLabels).some(([key,expected])=>volume.Labels?.[key]!==expected))throw fail('SYSTEM_START_VOLUME_CONFLICT');
  const accepted=[];
  for(const mode of managed.modesFor(value)){
    const found=await inspect('container',value[mode].container);
    inspectContainer(found,{mode,p,value,image,network,labels,restartVolume});
    if(!/^[a-f0-9]{64}$/.test(found.Id)
      ||!(found.State?.Running===true&&found.State.Status==='running'
        ||found.State?.Running===false&&found.State.Status==='exited'))throw fail('SYSTEM_START_CONTAINER_STATE');
    accepted.push({mode,id:found.Id,running:found.State.Running});
  }
  if(new Set(accepted.map(item=>item.id)).size!==accepted.length)throw fail('SYSTEM_START_CONTAINER_CHANGED');
  samePrivateState();
  for(const item of accepted){
    if(!item.running){try{await docker(['start',item.id]);}catch{/* Inspect the same ID after an uncertain acknowledgement. */}}
    const found=await inspect('container',item.id);
    if(found.Id!==item.id)throw fail('SYSTEM_START_CONTAINER_CHANGED');
    inspectContainer(found,{mode:item.mode,p,value,image,network,labels,restartVolume});
    if(found.State?.Running!==true||found.State.Status!=='running')throw fail('SYSTEM_START_UNCERTAIN');
  }
  for(const mode of managed.modesFor(value)){
    const factory=mode==='uploadPreview'?(options.createUploadPreviewClient||require('../../server/services/secureshopUploadPreviewClient').createSecureShopUploadPreviewClient):mode==='config'?(options.createConfigClient||createSecureShopSystemConfigClient)
      :mode==='diagnostic'?(options.createDiagnosticClient||createSecureShopSystemDiagnosticClient)
        :(options.createRestartClient||createSecureShopSystemRestartClient);
    const client=factory({baseURL:value[mode].url,token:value[mode].token});
    let ready=false;
    for(let attempt=0;attempt<3&&!ready;attempt++){
      try{ready=mode==='restart'?(await client.health())?.ready===true:await client.assertReady()===true;}catch{}
      if(!ready&&attempt<2)await new Promise(resolve=>setTimeout(resolve,100));
    }
    if(!ready)throw fail('SYSTEM_START_READINESS_FAILED');
    if(mode==='config'){const metrics=await client.metrics();if(metrics?.ok!==true||metrics.metricsSource!=='owned-system-listener')throw fail('SYSTEM_START_METRICS_FAILED');}
  }
  for(const item of accepted){
    const found=await inspect('container',item.id);
    if(found.Id!==item.id)throw fail('SYSTEM_START_CONTAINER_CHANGED');
    inspectContainer(found,{mode:item.mode,p,value,image,network,labels,restartVolume});
    if(found.State?.Running!==true||found.State.Status!=='running')throw fail('SYSTEM_START_CONTAINER_CHANGED');
  }
  await (options.verifyProfile||verifyProfile)({p,authority,root,home,platform,run});
  samePrivateState();
  return Object.freeze({ready:true,enabled:true,containerIds:Object.freeze(accepted.map(item=>item.id))});
}
module.exports={prepare:plan,provision,startExisting,_internals:{createRunner,verifyProfile,inspectContainer,buildCaSecret}};
