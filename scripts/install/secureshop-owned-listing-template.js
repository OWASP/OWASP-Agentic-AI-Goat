'use strict';
// Listing-template owned listener. Setup/start callsites opt in separately.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),net=require('node:net'),crypto=require('node:crypto');
const managed=require('../../server/services/secureshopListingTemplateManagedConfiguration');
const {workspaceId}=require('../application-data-root');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {createRunner}=require('./secureshop-owned-system-provision')._internals;
const {localProfilePlan}=require('./mcp-owned-local');
const {ISOLATION,normalizeListingTemplateExecution,listingTemplateExecutionDigest,validateListingTemplateExecutionResult}=require('../../server/services/secureshopListingTemplateExecutorContract');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fail=code=>Object.assign(Error('Owned strict listing template unavailable'),{code});
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ROOT=path.resolve(__dirname,'../..');
const FILES=['Dockerfile','Dockerfile.dockerignore','listener.js','executor.js','http-handler.js','worker.js','strict-helpers.js','template-init.c','secureshopListingTemplateExecutorContract.js'];
const BORROWED=['policy-render/process-supervisor.c','policy-render/assets/nunjucks-3.2.4.js','policy-render/assets/NUNJUCKS-LICENSE.txt'];
const ENTRY=['/usr/local/bin/node','/app/listing-template/listener.js'];
const BUILD_CONTEXT_RULES=['**','!listing-template/','listing-template/**',...FILES.map(name=>'!listing-template/'+name),'!policy-render/','policy-render/**','!policy-render/process-supervisor.c','!policy-render/assets/','policy-render/assets/**','!policy-render/assets/nunjucks-3.2.4.js','!policy-render/assets/NUNJUCKS-LICENSE.txt'];
function sourceManifest(root){
 const ignore=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/listing-template/Dockerfile.dockerignore'),'utf8').split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('#'));
 if(!equal(ignore,BUILD_CONTEXT_RULES))throw fail('LISTING_TEMPLATE_BUILD_CONTEXT_INVALID');
 const files={};for(const name of [...FILES.map(name=>'listing-template/'+name),...BORROWED]){const relative='sidecars/sandbox-runner/'+name,file=path.join(root,relative),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||fs.realpathSync(file)!==file||st.size>1048576)throw fail('LISTING_TEMPLATE_SOURCE_INVALID');files[relative]=sha(fs.readFileSync(file));}
 if(files['sidecars/sandbox-runner/listing-template/secureshopListingTemplateExecutorContract.js']!==sha(fs.readFileSync(path.join(root,'server/services/secureshopListingTemplateExecutorContract.js'))))throw fail('LISTING_TEMPLATE_CONTRACT_DRIFT');
 return Object.freeze({files:Object.freeze(files),sha256:sha(JSON.stringify(files))});
}
function profileBytes(root,id){
 const name='owasp-ai-goat-owned-listing-template-'+id,template=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'),'utf8');
 if(!/^[a-f0-9]{12}$/.test(id)||!template.includes('@@SUPERVISOR_PROFILE@@'))throw fail('LISTING_TEMPLATE_PROFILE_INVALID');
 const bytes=Buffer.from(template.replaceAll('@@SUPERVISOR_PROFILE@@',name));if(bytes.includes('@@'))throw fail('LISTING_TEMPLATE_PROFILE_INVALID');return bytes;
}
async function plan({root=ROOT,home=os.homedir(),platform=process.platform,architecture=process.arch,port,execute,environment=process.env}={}){
 if(!['linux','darwin'].includes(platform)||architecture!=='arm64')throw fail('LISTING_TEMPLATE_PLATFORM_UNQUALIFIED');
 const p=managed.paths({root,home}),id=workspaceId(root),existing=managed.capture({root,home}),saved=managed.capture({root,home},true);
 port=port??existing?.value.port??saved?.value.port??8109;if(!Number.isInteger(port)||port<8109||port>8118)throw fail('LISTING_TEMPLATE_PORT_INVALID');
 const authority=await readLocalDockerAuthority({directory:p.directory,workspaceId:id,platform});if(!authority)throw fail('LISTING_TEMPLATE_AUTHORITY_REQUIRED');
 await verifyDockerAuthority({authority,execute,environment});const source=sourceManifest(root),profile='owasp-ai-goat-owned-listing-template-'+id;
 const expected={workspaceId:id,architecture:'arm64',dockerAuthoritySha256:authorityDigest(authority),sourceSha256:source.sha256,profile,profileSha256:sha(profileBytes(root,id)),port,container:'owasp-ai-goat-listing-template-'+id};
 for(const record of [existing,saved])if(record&&Object.entries(expected).some(([k,v])=>record.value[k]!==v))throw fail('LISTING_TEMPLATE_RETAINED_CONFLICT');
 return Object.freeze({...expected,source,network:'owasp-ai-goat-listing-template-'+id+'-bridge',managedPath:p.filename,existing:!!existing,enabled:existing?.value.enabled===true,mutating:false});
}
async function assertPortAvailable(port){
 const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
}
async function provisionProfile({p,authority,root,home,platform,run,existingOnly=false}){
 let location;if(platform==='linux')location=localProfilePlan({root,home,platform});else{
  const marker='/.colima/',offset=authority.host.indexOf(marker);if(!authority.host.startsWith('unix:///')||offset<8||!authority.host.endsWith('/docker.sock'))throw fail('LISTING_TEMPLATE_PROFILE_AUTHORITY');
  const authorityHome=authority.host.slice(7,offset),name=authority.host.slice(offset+marker.length,-'/docker.sock'.length);if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name))throw fail('LISTING_TEMPLATE_PROFILE_AUTHORITY');
  location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+name});
 }
 if(location.dockerHost!==authority.host)throw fail('LISTING_TEMPLATE_PROFILE_AUTHORITY');
 const program=`import os,sys,base64,stat,subprocess\nname=sys.argv[1]; data=base64.b64decode(sys.argv[2],validate=True)\nassert name.startswith('owasp-ai-goat-owned-listing-template-') and len(name)==41 and all(c in '0123456789abcdef' for c in name[-12:])\np='/etc/apparmor.d/'+name\ntry:\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\nexcept FileNotFoundError:\n assert sys.argv[3]=='install'\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(fd,data); os.fsync(fd); os.close(fd)\nelse:\n st=os.fstat(fd); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and (st.st_mode & 0o777)==0o600 and st.st_size==len(data); assert os.read(fd,1048577)==data; os.close(fd)\nif sys.argv[3]=='install': subprocess.run(['apparmor_parser','-r',p],check=True,timeout=15)\nprofiles=open('/sys/kernel/security/apparmor/profiles').read().splitlines()\nassert name+' (enforce)' in profiles and name+'//bwrap (enforce)' in profiles\n`;
 const args=['python3','-c',program,p.profile,profileBytes(root,p.workspaceId).toString('base64'),existingOnly?'verify':'install'];
 const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,['sudo','--non-interactive',...args].map(v=>"'"+v.replaceAll("'","'\"'\"'")+"'").join(' ')],{timeoutMs:25000,maxOutputBytes:65536});
 if(result.exitCode!==0)throw fail('LISTING_TEMPLATE_PROFILE_UNAVAILABLE');
}
function inspectImage(image,p){
 if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Architecture!=='arm64'||image.Os!=='linux'
  ||image.Config?.Labels?.['owasp-ai-goat.listing-template.source']!==p.sourceSha256||image.Config.User!=='10001:10001'
  ||!equal(image.Config.Entrypoint,ENTRY)||image.Config.Cmd?.length||image.Config.Volumes&&Object.keys(image.Config.Volumes).length)throw fail('LISTING_TEMPLATE_IMAGE_CONFLICT');
}
function inspectNetwork(network,{p,labels,networkId,containerId}={}){
 const endpoints=network?.Containers;
 if(!network||!/^[a-f0-9]{64}$/.test(network.Id||'')||networkId&&network.Id!==networkId
  ||network.Name!==p.network||network.Driver!=='bridge'||network.Internal!==false
  ||Object.entries(labels).some(([k,v])=>network.Labels?.[k]!==v)
  ||endpoints!==null&&endpoints!==undefined&&(typeof endpoints!=='object'||Array.isArray(endpoints))
  ||containerId&&Object.keys(endpoints||{}).some(id=>id!==containerId))throw fail('LISTING_TEMPLATE_NETWORK_CONFLICT');
 return network.Id;
}
function inspectContainer(row,{p,value,image,labels,networkId}){
 const envMap=new Map([...(image.Config.Env||[]),'SECURESHOP_LISTING_TEMPLATE_ENABLED=true','SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT=1'].map(v=>[v.split('=',1)[0],v]));
 const h=row?.HostConfig,c=row?.Config,env=[...envMap.values()].sort();
 const attachments=row?.NetworkSettings?.Networks;
 const exactCreated=row?.State?.Status==='created'&&row.State.Running===false&&row.RestartCount===0
  &&['StartedAt','FinishedAt'].every(k=>/^0001-01-01T00:00:00(?:\.0+)?Z$/.test(row.State[k]||''));
 const exactState=exactCreated||row?.State?.Status==='running'&&row.State.Running===true
  ||row?.State?.Status==='exited'&&row.State.Running===false;
 const attached=attachments&&typeof attachments==='object'&&!Array.isArray(attachments)
  &&(equal(Object.keys(attachments),[p.network])||exactCreated&&Object.keys(attachments).length===0);
 if(!row||!exactState||row.State.Paused===true||row.State.Restarting===true||row.State.Dead===true
  ||row.Name!=='/'+p.container||row.Image!==value.imageId||!/^[a-f0-9]{64}$/.test(row.Id)||!h||!c
  ||Object.entries(labels).some(([k,v])=>c.Labels?.[k]!==v)||c.User!=='10001:10001'||!equal(c.Entrypoint,ENTRY)||c.Cmd?.length||!equal([...(c.Env||[])].sort(),env)
  ||row.Mounts?.length!==0||h.Binds?.length||h.Devices?.length||h.DeviceRequests?.length||h.Privileged!==false||h.ReadonlyRootfs!==true
  ||h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.CapAdd?.length||!equal(h.CapDrop,['ALL'])
  ||h.PidMode||h.IpcMode==='host'||h.UsernsMode==='host'||!equal([...(h.SecurityOpt||[])].sort(),['apparmor='+p.profile,'seccomp=unconfined'].sort())
  ||!equal(h.Tmpfs,{'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'})||h.NetworkMode!==p.network
  ||!attached
  ||networkId&&Object.hasOwn(attachments||{},p.network)&&attachments[p.network]?.NetworkID!==networkId
  ||row.State?.Running&&row.AppArmorProfile!==p.profile
  ||!equal(h.PortBindings,{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:String(p.port)}]})
  ||row.State?.Running&&!equal(row.NetworkSettings.Ports,h.PortBindings))throw fail('LISTING_TEMPLATE_CONTAINER_CONFLICT');
}
async function inertReadiness({p,fetchImpl,readinessAttempts=20,readinessDelayMs=250}){
 if(!Number.isInteger(readinessAttempts)||readinessAttempts<1||readinessAttempts>20||!Number.isInteger(readinessDelayMs)||readinessDelayMs<0||readinessDelayMs>1000)throw fail('LISTING_TEMPLATE_READINESS_BOUND_INVALID');
 const transport=fetchImpl||fetch;
 async function request(endpoint,options,timeoutMs){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMs);
  try{
   const response=await transport('http://127.0.0.1:'+p.port+endpoint,{...options,redirect:'error',signal:controller.signal});
   if(!response?.ok)throw fail('LISTING_TEMPLATE_READINESS_FAILED');
   const length=response.headers?.get?.('content-length');if(length!==null&&length!==undefined&&(!/^\d+$/.test(length)||Number(length)>131072))throw fail('LISTING_TEMPLATE_RESPONSE_INVALID');
   const reader=response.body?.getReader?.();if(!reader)throw fail('LISTING_TEMPLATE_RESPONSE_INVALID');
   const chunks=[];let size=0;for(;;){const item=await reader.read();if(item.done)break;size+=item.value.byteLength;if(size>131072){await reader.cancel();throw fail('LISTING_TEMPLATE_RESPONSE_INVALID');}chunks.push(Buffer.from(item.value));}
   controller.signal.throwIfAborted();return JSON.parse(Buffer.concat(chunks,size).toString('utf8'));
  }finally{clearTimeout(timer);}
 }
 for(let attempt=0;;attempt++){try{
  const health=await request('/health',{},1000);
  if(health?.status!=='ok'||health.listingTemplate?.enabled!==true||health.listingTemplate?.available!==true||health.listingTemplate?.isolation!==ISOLATION)throw fail('LISTING_TEMPLATE_READINESS_FAILED');
  break;
 }catch(error){if(attempt+1>=readinessAttempts)throw error;await new Promise(resolve=>setTimeout(resolve,readinessDelayMs));}}
 const templateSource='Hello {{ title }}';
 const input=normalizeListingTemplateExecution({version:1,operationId:crypto.randomUUID(),productId:1,sourceSha256:sha(Buffer.from(templateSource)),templateSource,title:'world',description:'',price:0});
 const raw=await request('/secureshop/listing-template-render',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input)},10000);
 const receipt=validateListingTemplateExecutionResult(input,raw);
 if(receipt.requestSha256!==listingTemplateExecutionDigest(input)||receipt.rendered!=='Hello world'||receipt.exitCode!==0||receipt.commandEffectObserved!==false||receipt.effectSha256!==null)throw fail('LISTING_TEMPLATE_INERT_FAILED');
 return receipt;
}
async function provision(options={}){
 const root=options.root||ROOT,home=options.home||os.homedir(),platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
 if(!['linux','darwin'].includes(platform)||(options.architecture||process.arch)!=='arm64')throw fail('LISTING_TEMPLATE_PLATFORM_UNQUALIFIED');
 const previous=managed.capture({root,home}),previousStage=managed.capture({root,home},true);
 let port=options.port??previous?.value.port??previousStage?.value.port;
 if(port===undefined){
  const check=options.assertPortAvailable||assertPortAvailable;
  for(let candidate=8109;candidate<=8118;candidate++){
   try{await check(candidate);port=candidate;break;}
   catch(error){if(!['EADDRINUSE','EACCES'].includes(error?.code))throw error;}
  }
  if(port===undefined)throw fail('LISTING_TEMPLATE_PORT_UNAVAILABLE');
 }
 const run=options.run||createRunner({cwd:root,env:environment});
 const execute=async(file,args,opt={})=>{const r=await run(file,args,{timeoutMs:opt.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('LISTING_TEMPLATE_COMMAND_FAILED');return r;};
 const p=await plan({...options,root,home,platform,port,environment,execute}),location=managed.paths({root,home}),existing=managed.capture({root,home}),saved=managed.capture({root,home},true);
 if(existing&&!existing.value.enabled&&options.activate!==true)return Object.freeze({ready:false,enabled:false,preservedDisabled:true});
 if(options.existingOnly&&(!existing||!saved))throw fail('LISTING_TEMPLATE_EXISTING_REQUIRED');
 const authority=await readLocalDockerAuthority({directory:location.directory,workspaceId:p.workspaceId,platform});if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('LISTING_TEMPLATE_AUTHORITY_CHANGED');
 const docker=async(args,timeoutMs=30000,missing=false)=>{
  const result=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});
  if(result.exitCode!==0){const name=args.at(-1),kind=args[0];if(missing&&result.exitCode===1&&[
   `Error: No such object: ${name}`,`Error: No such ${kind}: ${name}`,`Error response from daemon: No such ${kind}: ${name}`,
   ...(kind==='network'?[`Error response from daemon: network ${name} not found`]:[])
  ].includes(result.stderr.trim()))return null;throw Object.assign(fail('LISTING_TEMPLATE_COMMAND_FAILED'),{stage:['image','network','container'].includes(kind)?'docker-'+kind+'-'+args[1]:'docker-'+kind});}return result.stdout;
 };
 const inspect=async(kind,name)=>{const raw=await docker([kind,'inspect',name],10000,true);if(raw===null)return null;try{const rows=JSON.parse(raw);if(!Array.isArray(rows)||rows.length!==1)throw Error();return rows[0];}catch{throw fail('LISTING_TEMPLATE_INSPECT_INVALID');}};
 const daemon=JSON.parse(await docker(['info','--format','{{json .Architecture}}']));if(!['aarch64','arm64'].includes(daemon))throw fail('LISTING_TEMPLATE_ARCHITECTURE_UNQUALIFIED');
 let image=await inspect('image',saved?.value.imageId||existing?.value.imageId||'owasp-ai-goat-listing-template-'+p.workspaceId+':local');
 if(!image){if(saved||existing||options.existingOnly)throw fail('LISTING_TEMPLATE_RETAINED_IMAGE_MISSING');
  await docker(['build','--pull=false','--network=default','--label','owasp-ai-goat.listing-template.source='+p.sourceSha256,'-f',path.join(root,'sidecars/sandbox-runner/listing-template/Dockerfile'),'-t','owasp-ai-goat-listing-template-'+p.workspaceId+':local',path.join(root,'sidecars/sandbox-runner')],300000);
  if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('LISTING_TEMPLATE_SOURCE_CHANGED');image=await inspect('image','owasp-ai-goat-listing-template-'+p.workspaceId+':local');
 }
 inspectImage(image,p);
 const base={version:1,workspaceId:p.workspaceId,ownerId:existing?.value.ownerId||crypto.randomUUID(),architecture:'arm64',dockerAuthoritySha256:p.dockerAuthoritySha256,sourceSha256:p.sourceSha256,imageId:image.Id,profile:p.profile,profileSha256:p.profileSha256,container:p.container,port:p.port};
 const staged=saved||managed.stage({root,home,value:{...base,activateRequested:options.activate===true}}),value=staged.value;
 if(Object.entries(base).some(([k,v])=>(k!=='ownerId'||existing)&&value[k]!==v))throw fail('LISTING_TEMPLATE_STAGE_CONFLICT');
 if(sha(profileBytes(root,p.workspaceId))!==p.profileSha256)throw fail('LISTING_TEMPLATE_PROFILE_INVALID');
 await(options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run,existingOnly:options.existingOnly===true});
 const labels={'owasp-ai-goat.listing-template.workspace':p.workspaceId,'owasp-ai-goat.listing-template.owner':value.ownerId,'owasp-ai-goat.listing-template.source':p.sourceSha256},labelArgs=Object.entries(labels).flatMap(([k,v])=>['--label',k+'='+v]);
 let network=await inspect('network',p.network);if(!network){if(options.existingOnly)throw fail('LISTING_TEMPLATE_NETWORK_MISSING');await docker(['network','create',...labelArgs,p.network]);network=await inspect('network',p.network);}
 const networkId=inspectNetwork(network,{p,labels});
 let container=await inspect('container',p.container);if(!container){if(options.existingOnly)throw fail('LISTING_TEMPLATE_CONTAINER_MISSING');await(options.assertPortAvailable||assertPortAvailable)(p.port);
  await docker(['create','--name',p.container,...labelArgs,'--network',p.network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile,'--publish',`127.0.0.1:${p.port}:8090`,'--env','SECURESHOP_LISTING_TEMPLATE_ENABLED=true','--env','SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT=1',image.Id]);container=await inspect('container',p.container);
 }
 inspectContainer(container,{p,value,image,labels,networkId});if(existing&&existing.value.containerId!==container.Id)throw fail('LISTING_TEMPLATE_CONTAINER_CONFLICT');
 inspectNetwork(await inspect('network',p.network),{p,labels,networkId,containerId:container.Id});
 if(!existing&&!options.activate&&!saved?.value.activateRequested){
  managed.assertCaptured(staged,{root,home},true);
  await verifyDockerAuthority({authority,execute,environment});
  if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('LISTING_TEMPLATE_SOURCE_CHANGED');
  return Object.freeze({ready:false,enabled:false,staged:true,managedPath:location.stage,containerId:container.Id});
 }
 if(!container.State?.Running){
  managed.assertCaptured(staged,{root,home},true);
  if(existing)managed.assertCaptured(existing,{root,home});
  await verifyDockerAuthority({authority,execute,environment});
  await(options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run,existingOnly:true});
  if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('LISTING_TEMPLATE_SOURCE_CHANGED');
  const currentImage=await inspect('image',image.Id);inspectImage(currentImage,p);
  if(currentImage.Id!==image.Id)throw fail('LISTING_TEMPLATE_IMAGE_CONFLICT');
  inspectNetwork(await inspect('network',p.network),{p,labels,networkId,containerId:container.Id});
  const fresh=await inspect('container',container.Id);inspectContainer(fresh,{p,value,image,labels,networkId});
  if(fresh.Id!==container.Id||fresh.State?.Running)throw fail('LISTING_TEMPLATE_CONTAINER_CONFLICT');
  try{await docker(['start',container.Id]);}catch(error){
   const observed=await inspect('container',container.Id);
   if(!observed||observed.Id!==container.Id||!observed.State?.Running)throw error;
  }
  container=await inspect('container',container.Id);inspectContainer(container,{p,value,image,labels,networkId});if(!container.State?.Running)throw fail('LISTING_TEMPLATE_START_UNCERTAIN');
 }
 const receipt=await inertReadiness({p,fetchImpl:options.fetchImpl,readinessAttempts:options.readinessAttempts,readinessDelayMs:options.readinessDelayMs});
 managed.assertCaptured(staged,{root,home},true);
 await verifyDockerAuthority({authority,execute,environment});
 if(sourceManifest(root).sha256!==p.sourceSha256)throw fail('LISTING_TEMPLATE_SOURCE_CHANGED');
 if(sha(profileBytes(root,p.workspaceId))!==p.profileSha256)throw fail('LISTING_TEMPLATE_PROFILE_INVALID');
 await(options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run,existingOnly:true});
 const finalImage=await inspect('image',image.Id);inspectImage(finalImage,p);
 if(finalImage.Id!==image.Id)throw fail('LISTING_TEMPLATE_IMAGE_CONFLICT');
 inspectNetwork(await inspect('network',p.network),{p,labels,networkId,containerId:container.Id});
 const finalContainer=await inspect('container',container.Id);inspectContainer(finalContainer,{p,value,image,labels,networkId});
 if(finalContainer.Id!==container.Id||!finalContainer.State?.Running)throw fail('LISTING_TEMPLATE_CONTAINER_CONFLICT');
 const {activateRequested,...identity}=value,enabled=existing?existing.value.enabled||options.activate===true:activateRequested||options.activate===true;
 const record=managed.publish({root,home,expected:existing,expectedStage:staged,value:{...identity,containerId:container.Id,enabled}});
 return Object.freeze({ready:true,enabled:record.value.enabled,managedPath:location.filename,baseUrl:'http://127.0.0.1:'+p.port,containerId:container.Id,imageId:image.Id,inertReceiptSha256:sha(JSON.stringify(receipt)),outerEgressIsolation:false});
}
async function startExisting(options={}){
 const root=options.root||ROOT,home=options.home||os.homedir(),existing=managed.capture({root,home});
 if(!existing)return Object.freeze({ready:false,enabled:false,absent:true});
 if(!existing.value.enabled)return Object.freeze({ready:false,enabled:false,preservedDisabled:true});
 return provision({...options,root,home,activate:false,existingOnly:true});
}
module.exports={plan,provision,startExisting,sourceManifest,_internals:{profileBytes,inspectImage,inspectNetwork,inspectContainer,inertReadiness,provisionProfile}};
