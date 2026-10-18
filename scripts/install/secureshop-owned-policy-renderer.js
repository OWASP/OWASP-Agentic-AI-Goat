'use strict';
// Policy-only owned listener. Setup/start callsites opt in separately.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),net=require('node:net'),crypto=require('node:crypto');
const managed=require('../../server/services/secureshopPolicyRendererManagedConfiguration');
const {workspaceId}=require('../application-data-root');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {createRunner}=require('./secureshop-owned-system-provision')._internals;
const {localProfilePlan}=require('./mcp-owned-local');
const {createSecureShopPolicySandboxRuntime}=require('../../server/services/secureshopPolicySandboxRuntime');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fail=code=>Object.assign(Error('Owned strict policy renderer unavailable'),{code});
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ROOT=path.resolve(__dirname,'../..');
const FILES=['Dockerfile','Dockerfile.dockerignore','listener.js','executor.js','http-handler.js','worker.js','process-supervisor.c','policy-init.c','secureshopPromptPolicyContract.js','assets/nunjucks-3.2.4.js','assets/NUNJUCKS-LICENSE.txt'];
const ENTRY=['/usr/local/bin/node','/app/policy-render/listener.js'];
const BUILD_CONTEXT_RULES=['**','!policy-render/','policy-render/**',...FILES.filter(name=>!name.startsWith('assets/')).map(name=>'!policy-render/'+name),'!policy-render/assets/','policy-render/assets/**',...FILES.filter(name=>name.startsWith('assets/')).map(name=>'!policy-render/'+name)];
function sourceManifest(root){
 const ignore=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/policy-render/Dockerfile.dockerignore'),'utf8').split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('#'));
 if(!equal(ignore,BUILD_CONTEXT_RULES))throw fail('POLICY_RENDER_BUILD_CONTEXT_INVALID');
 const files={};for(const name of FILES){const relative='sidecars/sandbox-runner/policy-render/'+name,file=path.join(root,relative),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||fs.realpathSync(file)!==file||st.size>1048576)throw fail('POLICY_RENDER_SOURCE_INVALID');files[relative]=sha(fs.readFileSync(file));}
 if(files['sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js']!==sha(fs.readFileSync(path.join(root,'server/services/secureshopPromptPolicyContract.js'))))throw fail('POLICY_RENDER_CONTRACT_DRIFT');
 return Object.freeze({files:Object.freeze(files),sha256:sha(JSON.stringify(files))});
}
function profileBytes(root,id){
 const name='dvaia-owned-policy-renderer-'+id,template=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8');
 if(!/^[a-f0-9]{12}$/.test(id)||!template.includes('@@SUPERVISOR_PROFILE@@'))throw fail('POLICY_RENDER_PROFILE_INVALID');
 const bytes=Buffer.from(template.replaceAll('@@SUPERVISOR_PROFILE@@',name));if(bytes.includes('@@'))throw fail('POLICY_RENDER_PROFILE_INVALID');return bytes;
}
async function plan({root=ROOT,home=os.homedir(),platform=process.platform,architecture=process.arch,port,execute,environment=process.env}={}){
 if(!['linux','darwin'].includes(platform)||architecture!=='arm64')throw fail('POLICY_RENDER_PLATFORM_UNQUALIFIED');
 const p=managed.paths({root,home}),id=workspaceId(root),existing=managed.capture({root,home}),saved=managed.capture({root,home},true);
 port=port??existing?.value.port??saved?.value.port??8098;if(!Number.isInteger(port)||port<1024||port>65535)throw fail('POLICY_RENDER_PORT_INVALID');
 const authority=await readLocalDockerAuthority({directory:p.directory,workspaceId:id,platform});if(!authority)throw fail('POLICY_RENDER_AUTHORITY_REQUIRED');
 await verifyDockerAuthority({authority,execute,environment});const source=sourceManifest(root),profile='dvaia-owned-policy-renderer-'+id;
 const expected={workspaceId:id,architecture:'arm64',dockerAuthoritySha256:authorityDigest(authority),sourceSha256:source.sha256,profile,profileSha256:sha(profileBytes(root,id)),port,container:'dvaia-policy-renderer-'+id};
 for(const record of [existing,saved])if(record&&Object.entries(expected).some(([k,v])=>record.value[k]!==v))throw fail('POLICY_RENDER_RETAINED_CONFLICT');
 return Object.freeze({...expected,source,network:'dvaia-policy-renderer-'+id+'-bridge',managedPath:p.filename,existing:!!existing,enabled:existing?.value.enabled===true,mutating:false});
}
async function assertPortAvailable(port){
 const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
}
async function provisionProfile({p,authority,root,home,platform,run,existingOnly=false}){
 let location;if(platform==='linux')location=localProfilePlan({root,home,platform});else{
  const marker='/.colima/',offset=authority.host.indexOf(marker);if(!authority.host.startsWith('unix:///')||offset<8||!authority.host.endsWith('/docker.sock'))throw fail('POLICY_RENDER_PROFILE_AUTHORITY');
  const authorityHome=authority.host.slice(7,offset),name=authority.host.slice(offset+marker.length,-'/docker.sock'.length);if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name))throw fail('POLICY_RENDER_PROFILE_AUTHORITY');
  location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+name});
 }
 if(location.dockerHost!==authority.host)throw fail('POLICY_RENDER_PROFILE_AUTHORITY');
 const program=`import os,sys,base64,stat,subprocess\nname=sys.argv[1]; data=base64.b64decode(sys.argv[2],validate=True)\nassert name.startswith('dvaia-owned-policy-renderer-') and len(name)==40 and all(c in '0123456789abcdef' for c in name[-12:])\np='/etc/apparmor.d/'+name\ntry:\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\nexcept FileNotFoundError:\n assert sys.argv[3]=='install'\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(fd,data); os.fsync(fd); os.close(fd)\nelse:\n st=os.fstat(fd); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and (st.st_mode & 0o022)==0; assert os.read(fd,1048577)==data; os.close(fd)\nif sys.argv[3]=='install': subprocess.run(['apparmor_parser','-r',p],check=True,timeout=15)\nassert name+' (enforce)' in open('/sys/kernel/security/apparmor/profiles').read().splitlines()\n`;
 const args=['python3','-c',program,p.profile,profileBytes(root,p.workspaceId).toString('base64'),existingOnly?'verify':'install'];
 const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,['sudo','--non-interactive',...args].map(v=>"'"+v.replaceAll("'","'\"'\"'")+"'").join(' ')],{timeoutMs:25000,maxOutputBytes:65536});
 if(result.exitCode!==0)throw fail('POLICY_RENDER_PROFILE_UNAVAILABLE');
}
function inspectImage(image,p){
 if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Architecture!=='arm64'||image.Os!=='linux'
  ||image.Config?.Labels?.['dvaia.policy.source']!==p.sourceSha256||image.Config.User!=='10001:10001'
  ||!equal(image.Config.Entrypoint,ENTRY)||image.Config.Cmd?.length||image.Config.Volumes&&Object.keys(image.Config.Volumes).length)throw fail('POLICY_RENDER_IMAGE_CONFLICT');
}
function inspectContainer(row,{p,value,image,labels}){
 const envMap=new Map([...(image.Config.Env||[]),'SECURESHOP_POLICY_RENDER_ENABLED=true','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1'].map(v=>[v.split('=',1)[0],v]));
 const h=row?.HostConfig,c=row?.Config,env=[...envMap.values()].sort();
 const attachments=row?.NetworkSettings?.Networks;
 const exactCreated=row?.State?.Status==='created'&&row.State.Running===false&&row.RestartCount===0
  &&['StartedAt','FinishedAt'].every(k=>/^0001-01-01T00:00:00(?:\.0+)?Z$/.test(row.State[k]||''));
 const attached=attachments&&typeof attachments==='object'&&!Array.isArray(attachments)
  &&(equal(Object.keys(attachments),[p.network])||exactCreated&&Object.keys(attachments).length===0);
 if(!row||row.Name!=='/'+p.container||row.Image!==value.imageId||!/^[a-f0-9]{64}$/.test(row.Id)||!h||!c
  ||Object.entries(labels).some(([k,v])=>c.Labels?.[k]!==v)||c.User!=='10001:10001'||!equal(c.Entrypoint,ENTRY)||c.Cmd?.length||!equal([...(c.Env||[])].sort(),env)
  ||row.Mounts?.length!==0||h.Binds?.length||h.Devices?.length||h.DeviceRequests?.length||h.Privileged!==false||h.ReadonlyRootfs!==true
  ||h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.CapAdd?.length||!equal(h.CapDrop,['ALL'])
  ||h.PidMode||h.IpcMode==='host'||h.UsernsMode==='host'||!equal([...(h.SecurityOpt||[])].sort(),['apparmor='+p.profile,'seccomp=unconfined'].sort())
  ||!equal(h.Tmpfs,{'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'})||h.NetworkMode!==p.network
  ||!attached
  ||!equal(h.PortBindings,{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:String(p.port)}]})
  ||row.State?.Running&&!equal(row.NetworkSettings.Ports,h.PortBindings))throw fail('POLICY_RENDER_CONTAINER_CONFLICT');
}
async function inertReadiness({p,fetchImpl,readinessAttempts=20,readinessDelayMs=250}){
 if(!Number.isInteger(readinessAttempts)||readinessAttempts<1||readinessAttempts>20||!Number.isInteger(readinessDelayMs)||readinessDelayMs<0||readinessDelayMs>1000)throw fail('POLICY_RENDER_READINESS_BOUND_INVALID');
 const transport=fetchImpl||fetch;
 const runtime=createSecureShopPolicySandboxRuntime({baseUrl:'http://127.0.0.1:'+p.port,fetchImpl:(url,options)=>transport(url,{...options,redirect:'error'}),timeoutMs:1000});
 for(let attempt=0;;attempt++){try{await runtime.checkReadiness();break;}catch(error){if(attempt+1>=readinessAttempts)throw error;await new Promise(resolve=>setTimeout(resolve,readinessDelayMs));}}
 const renderer=createSecureShopPolicySandboxRuntime({baseUrl:'http://127.0.0.1:'+p.port,fetchImpl:(url,options)=>transport(url,{...options,redirect:'error'}),timeoutMs:10000});
 const receipt=await renderer.render({operationId:crypto.randomUUID(),name:'managed-readiness',markdown:'Returns for {{ store_name }}.',targets:['admin']});
 if(receipt.rendered!=='Returns for SecureShop.')throw fail('POLICY_RENDER_INERT_FAILED');return receipt;
}
async function provision(options={}){
 const root=options.root||ROOT,home=options.home||os.homedir(),platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
 const run=options.run||createRunner({cwd:root,env:environment});
 const execute=async(file,args,opt={})=>{const r=await run(file,args,{timeoutMs:opt.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('POLICY_RENDER_COMMAND_FAILED');return r;};
 const p=await plan({...options,root,home,platform,environment,execute}),location=managed.paths({root,home}),existing=managed.capture({root,home}),saved=managed.capture({root,home},true);
 if(existing&&(!existing.value.enabled||environment.SS_BOUND_PROMPT_POLICIES_ENABLED==='false')&&options.activate!==true)return Object.freeze({ready:false,enabled:false,preservedDisabled:true});
 if(options.existingOnly&&(!existing||!saved))throw fail('POLICY_RENDER_EXISTING_REQUIRED');
 const authority=await readLocalDockerAuthority({directory:location.directory,workspaceId:p.workspaceId,platform});if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('POLICY_RENDER_AUTHORITY_CHANGED');
 const docker=async(args,timeoutMs=30000,missing=false)=>{
  const result=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});
  if(result.exitCode!==0){const name=args.at(-1),kind=args[0];if(missing&&result.exitCode===1&&[
   `Error: No such object: ${name}`,`Error: No such ${kind}: ${name}`,`Error response from daemon: No such ${kind}: ${name}`,
   ...(kind==='network'?[`Error response from daemon: network ${name} not found`]:[])
  ].includes(result.stderr.trim()))return null;throw Object.assign(fail('POLICY_RENDER_COMMAND_FAILED'),{stage:['image','network','container'].includes(kind)?'docker-'+kind+'-'+args[1]:'docker-'+kind});}return result.stdout;
 };
 const inspect=async(kind,name)=>{const raw=await docker([kind,'inspect',name],10000,true);if(raw===null)return null;try{const rows=JSON.parse(raw);if(!Array.isArray(rows)||rows.length!==1)throw Error();return rows[0];}catch{throw fail('POLICY_RENDER_INSPECT_INVALID');}};
 const daemon=JSON.parse(await docker(['info','--format','{{json .Architecture}}']));if(!['aarch64','arm64'].includes(daemon))throw fail('POLICY_RENDER_ARCHITECTURE_UNQUALIFIED');
 let image=await inspect('image',saved?.value.imageId||existing?.value.imageId||'dvaia-policy-renderer-'+p.workspaceId+':local');
 if(!image){if(saved||existing||options.existingOnly)throw fail('POLICY_RENDER_RETAINED_IMAGE_MISSING');
  await docker(['build','--pull=false','--network=default','--label','dvaia.policy.source='+p.sourceSha256,'-f',path.join(root,'sidecars/sandbox-runner/policy-render/Dockerfile'),'-t','dvaia-policy-renderer-'+p.workspaceId+':local',path.join(root,'sidecars/sandbox-runner')],300000);
  if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('POLICY_RENDER_SOURCE_CHANGED');image=await inspect('image','dvaia-policy-renderer-'+p.workspaceId+':local');
 }
 inspectImage(image,p);
 const base={version:1,workspaceId:p.workspaceId,ownerId:existing?.value.ownerId||crypto.randomUUID(),architecture:'arm64',dockerAuthoritySha256:p.dockerAuthoritySha256,sourceSha256:p.sourceSha256,imageId:image.Id,profile:p.profile,profileSha256:p.profileSha256,container:p.container,port:p.port};
 const staged=saved||managed.stage({root,home,value:{...base,activateRequested:options.activate===true}}),value=staged.value;
 if(Object.entries(base).some(([k,v])=>(k!=='ownerId'||existing)&&value[k]!==v))throw fail('POLICY_RENDER_STAGE_CONFLICT');
 if(sha(profileBytes(root,p.workspaceId))!==p.profileSha256)throw fail('POLICY_RENDER_PROFILE_INVALID');
 await(options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run,existingOnly:options.existingOnly===true});
 const labels={'dvaia.policy.workspace':p.workspaceId,'dvaia.policy.owner':value.ownerId,'dvaia.policy.source':p.sourceSha256},labelArgs=Object.entries(labels).flatMap(([k,v])=>['--label',k+'='+v]);
 let network=await inspect('network',p.network);if(!network){if(options.existingOnly)throw fail('POLICY_RENDER_NETWORK_MISSING');await docker(['network','create',...labelArgs,p.network]);network=await inspect('network',p.network);}
 if(network?.Name!==p.network||network.Driver!=='bridge'||network.Internal!==false||Object.entries(labels).some(([k,v])=>network.Labels?.[k]!==v))throw fail('POLICY_RENDER_NETWORK_CONFLICT');
 let container=await inspect('container',p.container);if(!container){if(options.existingOnly)throw fail('POLICY_RENDER_CONTAINER_MISSING');await(options.assertPortAvailable||assertPortAvailable)(p.port);
  await docker(['create','--name',p.container,...labelArgs,'--network',p.network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile,'--publish',`127.0.0.1:${p.port}:8090`,'--env','SECURESHOP_POLICY_RENDER_ENABLED=true','--env','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1',image.Id]);container=await inspect('container',p.container);
 }
 inspectContainer(container,{p,value,image,labels});if(existing&&existing.value.containerId!==container.Id)throw fail('POLICY_RENDER_CONTAINER_CONFLICT');
 if(!container.State?.Running){await docker(['start',container.Id]);container=await inspect('container',container.Id);inspectContainer(container,{p,value,image,labels});if(!container.State?.Running)throw fail('POLICY_RENDER_START_UNCERTAIN');}
 const receipt=await inertReadiness({p,fetchImpl:options.fetchImpl,readinessAttempts:options.readinessAttempts,readinessDelayMs:options.readinessDelayMs});
 managed.assertCaptured(staged,{root,home},true);
 await verifyDockerAuthority({authority,execute,environment});
 if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('POLICY_RENDER_SOURCE_CHANGED');
 if(sha(profileBytes(root,p.workspaceId))!==p.profileSha256)throw fail('POLICY_RENDER_PROFILE_INVALID');
 const finalContainer=await inspect('container',container.Id);inspectContainer(finalContainer,{p,value,image,labels});
 if(finalContainer.Id!==container.Id||!finalContainer.State?.Running)throw fail('POLICY_RENDER_CONTAINER_CONFLICT');
 const {activateRequested,...identity}=value,enabled=existing?existing.value.enabled||options.activate===true:activateRequested||options.activate===true;
 const record=managed.publish({root,home,expected:existing,expectedStage:staged,value:{...identity,containerId:container.Id,enabled}});
 return Object.freeze({ready:true,enabled:record.value.enabled,managedPath:location.filename,baseUrl:'http://127.0.0.1:'+p.port,containerId:container.Id,imageId:image.Id,inertReceiptSha256:sha(JSON.stringify(receipt)),outerEgressIsolation:false});
}
async function startExisting(options={}){return provision({...options,activate:false,existingOnly:true});}
module.exports={plan,provision,startExisting,sourceManifest,_internals:{profileBytes,inspectImage,inspectContainer,inertReadiness,provisionProfile}};
