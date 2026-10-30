'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const planner=require('./secureshop-owned-pricing'),stage=require('./secureshop-owned-pricing-stage');
const managed=require('../../server/services/secureshopPricingManagedConfiguration');
const activation=require('../../server/services/secureshopPricingActivation');
const {readLocalDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const {createRunner}=require('./secureshop-owned-system-provision')._internals;
const {localProfilePlan}=require('./mcp-owned-local');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(Error('Owned Pricing provisioning requires recovery'),{code});
const BASE='node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const BASE_REPOSITORY_DIGEST=BASE.replace('node:26.10.0-slim@','node@');
function temporaryRoot(root,repositoryOnlyStorage){
 if(!repositoryOnlyStorage)return os.tmpdir();
 const canonical=fs.realpathSync(root),rootStat=fs.lstatSync(root);
 if(!rootStat.isDirectory()||rootStat.isSymbolicLink())throw fail('PRICING_REPOSITORY_STORAGE_UNQUALIFIED');
 const tasks=path.join(canonical,'tasks'),parent=fs.lstatSync(tasks);
 if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o022)!==0)throw fail('PRICING_REPOSITORY_STORAGE_UNQUALIFIED');
 const current=path.join(tasks,'tmp');
 try{fs.mkdirSync(current,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw fail('PRICING_REPOSITORY_STORAGE_UNQUALIFIED');}
 const st=fs.lstatSync(current);
 if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o022)!==0||fs.realpathSync(current)!==current)
  throw fail('PRICING_REPOSITORY_STORAGE_UNQUALIFIED');
 return current;
}
async function ensureBase({inspect,docker,authority,root,repositoryOnlyStorage,admitRepositoryStorage}){
 let base=await inspect('image',BASE);
 if(!base){
  if(repositoryOnlyStorage){
   if(typeof admitRepositoryStorage!=='function'||await admitRepositoryStorage({root,dockerHost:authority.host,reference:BASE,architecture:'arm64'})!==true)
    throw fail('PRICING_REPOSITORY_STORAGE_UNQUALIFIED');
  }
  await docker(['image','pull','--platform','linux/arm64',BASE],300000);
  base=await inspect('image',BASE);
 }
 if(!base||base.Architecture!=='arm64'||base.Os!=='linux'||!base.RepoDigests?.includes(BASE_REPOSITORY_DIGEST))
  throw fail('PRICING_BASE_UNQUALIFIED');
 return base;
}
async function provisionProfile({p,authority,root,home,platform,run}){
 let location;if(platform==='linux')location=localProfilePlan({root,home,platform});else{
  const marker='/.colima/',offset=authority.host.indexOf(marker);if(!authority.host.startsWith('unix:///')||offset<8)throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
  const authorityHome=authority.host.slice(7,offset);const prefix=`unix://${path.join(authorityHome,'.colima')}/`,suffix='/docker.sock';if(!authority.host.startsWith(prefix)||!authority.host.endsWith(suffix))throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
  const name=authority.host.slice(prefix.length,-suffix.length);if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name))throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+name});
 }
 if(location.dockerHost!==authority.host)throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
 // Exact namespace-specific profile only; never replace different existing bytes.
 if(!/^owasp-ai-goat-owned-pricing-http-[a-f0-9]{12}$/.test(p.profile))throw fail('PRICING_PROFILE_INVALID');
 const bytes=Buffer.from(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-pricing-http/http-profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',p.profile));
 const program=`import os,sys,base64,stat,subprocess\nname=sys.argv[1]; data=base64.b64decode(sys.argv[2],validate=True)\nassert name.startswith('owasp-ai-goat-owned-pricing-http-') and len(name)==37 and all(c in '0123456789abcdef' for c in name[-12:])\np='/etc/apparmor.d/'+name\ntry:\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nexcept FileExistsError:\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); st=os.fstat(fd); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1; assert os.read(fd,1048577)==data; os.close(fd)\nelse:\n os.write(fd,data); os.fsync(fd); os.close(fd)\nsubprocess.run(['apparmor_parser','-r',p],check=True,timeout=15)\nassert name+' (enforce)' in open('/sys/kernel/security/apparmor/profiles').read().splitlines()\n`;
 const args=['python3','-c',program,p.profile,bytes.toString('base64')];
 const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,['sudo','--non-interactive',...args].map(value=>"'"+value.replaceAll("'","'\"'\"'")+"'").join(' ')],{timeoutMs:25000,maxOutputBytes:65536});
 if(result.exitCode!==0)throw fail('PRICING_PROFILE_UNAVAILABLE');return{sha256:sha(bytes)};
}
async function provision(options={}){
 const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
 activation.activationPolicy({...environment,SS_BOUND_PRICING_ENABLED:'true'});
 const run=options.run||createRunner({cwd:root,env:environment});
 const execute=async(file,args,opt={})=>{const r=await run(file,args,{timeoutMs:opt.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('PRICING_INSTALL_COMMAND_FAILED');return r;};
 await require('./secureshop-owned-pricing-port-recovery').recoverUnusedPricingPort({root,home,environment,port:options.port,run,execute,maintenanceScope:options.maintenanceScope});
 const p=await planner.plan({...options,root,home,platform,environment,execute});
 const authority=await readLocalDockerAuthority({directory:managed.paths({root,home}).directory,workspaceId:p.workspaceId,platform});if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('PRICING_AUTHORITY_CHANGED');
 const docker=async(args,timeoutMs=30000,missing=false)=>{const r=await run('docker',['--host',authority.host,...args],{timeoutMs,maxOutputBytes:1048576});if(r.exitCode!==0){if(missing&&/No such|not found/.test(r.stderr||''))return null;throw fail('PRICING_INSTALL_COMMAND_FAILED');}return r.stdout;};
 const inspect=async(kind,id)=>{const raw=await docker([kind,'inspect',id],10000,true);if(raw===null)return null;const rows=JSON.parse(raw);if(!Array.isArray(rows)||rows.length!==1)throw fail('PRICING_INSPECT_INVALID');return rows[0];};
 const daemon=JSON.parse(await docker(['info','--format','{{json .Architecture}}']));if(!['aarch64','arm64'].includes(daemon))throw fail('PRICING_DAEMON_ARCHITECTURE_UNQUALIFIED');
 const temp=fs.mkdtempSync(path.join(temporaryRoot(root,options.repositoryOnlyStorage===true),'owasp-ai-goat-pricing-provision-'));fs.chmodSync(temp,0o700);const tempId=fs.lstatSync(temp);
 try{
  const saved=stage.read({root,home}),existing=managed.load({root,home}),tag='owasp-ai-goat-owned-pricing-'+p.workspaceId+':local';
  let image=await inspect('image',saved?.value.imageId||existing?.config.imageId||tag);
  if(!image&&(saved||existing))throw fail('PRICING_STAGED_IMAGE_MISSING');
  if(!image){
   await ensureBase({inspect,docker,authority,root,repositoryOnlyStorage:options.repositoryOnlyStorage===true,admitRepositoryStorage:options.admitRepositoryStorage});
   const capture=planner.qualifiedSource(root);if(capture.sha256!==p.source.sha256)throw fail('PRICING_SOURCE_CHANGED');
   for(const [relative,digest]of Object.entries(capture.files)){const bytes=fs.readFileSync(path.join(root,relative));if(sha(bytes)!==digest)throw fail('PRICING_SOURCE_CHANGED');const dest=path.join(temp,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,bytes,{mode:0o444,flag:'wx'});}
   if(planner.qualifiedSource(root).sha256!==capture.sha256)throw fail('PRICING_SOURCE_CHANGED');
   await docker(['build','--pull=false','--network=default','--label','owasp-ai-goat.pricing.package='+p.source.sha256,'-f',path.join(temp,'sidecars/sandbox-runner/owned-pricing-http/Dockerfile.local'),'-t',tag,temp],300000);image=await inspect('image',tag);
  }
  if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Architecture!=='arm64'||image.Os!=='linux'||image.Config?.Labels?.['owasp-ai-goat.pricing.package']!==p.source.sha256||image.Config.User!=='10001:10001'||JSON.stringify(image.Config.Entrypoint)!==JSON.stringify(['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'])||image.Config.Volumes&&Object.keys(image.Config.Volumes).length)throw fail('PRICING_IMAGE_CONFLICT');
  const staged=stage.prepare({root,home,plan:p,imageId:image.Id}),v=staged.value;
  if(existing&&['ownerId','token','imageId','port','packageSha256'].some(k=>existing.config[k]!==v[k]))throw fail('PRICING_STAGE_CONFLICT');
  await (options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run});
  const labels={'owasp-ai-goat.pricing.owner':v.ownerId,'owasp-ai-goat.pricing.workspace':p.workspaceId,'owasp-ai-goat.pricing.package':p.source.sha256},labelArgs=Object.entries(labels).flatMap(([k,val])=>['--label',k+'='+val]);
  let network=await inspect('network',p.network);if(!network){try{await docker(['network','create',...labelArgs,p.network]);}catch{}network=await inspect('network',p.network);}
  if(!network||network.Name!==p.network||network.Driver!=='bridge'||network.Internal!==false||Object.entries(labels).some(([k,val])=>network.Labels?.[k]!==val))throw fail('PRICING_NETWORK_CONFLICT');
  let container=await inspect('container',p.container);if(!container){
   const envFile=path.join(temp,'runtime.env');fs.writeFileSync(envFile,`SECURESHOP_PRICING_ENABLED=true\nSECURESHOP_PRICING_TOKEN=${v.token}\nSECURESHOP_PRICING_PROFILE=${p.profile}\nSECURESHOP_PRICING_HOST=0.0.0.0\nSECURESHOP_PRICING_PORT=8093\n`,{mode:0o600,flag:'wx'});
   try{await docker(['create','--name',p.container,...labelArgs,'--network',p.network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--security-opt','seccomp=unconfined','--security-opt','apparmor='+p.profile,'--publish',`127.0.0.1:${p.port}:8093`,'--env-file',envFile,image.Id]);}catch{}container=await inspect('container',p.container);
  }
  if(!container||container.Image!==image.Id||container.Name!=='/'+p.container||Object.entries(labels).some(([k,val])=>container.Config?.Labels?.[k]!==val))throw fail('PRICING_CONTAINER_CONFLICT');
  if(!existing)managed.stage({root,home,value:{...v,enabled:false,containerName:p.container,containerId:container.Id,profile:p.profile}});
  else if(existing.config.containerId!==container.Id)throw fail('PRICING_CONTAINER_CONFLICT');
  // Full immutable profile is checked before any stopped container is started.
  // Activation also rechecks all resources and authenticated readiness afterward.
  if(!container.State.Running){const checked=await activation.inspectPricingBeforeStart({root,home,env:environment,execute});try{await docker(['start',checked.containerId]);}catch{}container=await inspect('container',checked.containerId);if(!container?.State?.Running)throw fail('PRICING_START_UNCERTAIN');}
  const env={...environment,SS_BOUND_PRICING_ENABLED:'true'};
  if(existing?.config.enabled)await activation.preparePricingClient({root,home,env,execute,fetchImpl:options.fetchImpl,onDiagnostic:options.onDiagnostic});
  else{const proof=await activation.verifyStagedPricing({root,home,env,execute,fetchImpl:options.fetchImpl,onDiagnostic:options.onDiagnostic});activation.activateStagedPricing(proof);}
  return Object.freeze({ready:true,enabled:true,workspaceId:p.workspaceId,imageId:image.Id,containerId:container.Id,outerEgressIsolation:false});
 }finally{const now=fs.lstatSync(temp);if(now.dev!==tempId.dev||now.ino!==tempId.ino||now.isSymbolicLink())throw fail('PRICING_TEMP_IDENTITY_CHANGED');fs.rmSync(temp,{recursive:true});}
}

async function verifyExistingProfile({root,home,platform,authority,profile,run}){
  let location;if(platform==='linux')location=localProfilePlan({root,home,platform});else if(platform==='darwin'){
    const marker='/.colima/',offset=authority.host.indexOf(marker);
    if(!authority.host.startsWith('unix:///')||offset<8)throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
    const authorityHome=authority.host.slice(7,offset),prefix=`unix://${path.join(authorityHome,'.colima')}/`,suffix='/docker.sock';
    if(!authority.host.startsWith(prefix)||!authority.host.endsWith(suffix))throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
    const name=authority.host.slice(prefix.length,-suffix.length);
    if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name))throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
    location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+name});
  }else throw fail('PRICING_START_PLATFORM_UNQUALIFIED');
  if(location.dockerHost!==authority.host||!/^owasp-ai-goat-owned-pricing-http-[a-f0-9]{12}$/.test(profile))throw fail('PRICING_PROFILE_AUTHORITY_CONFLICT');
  const bytes=Buffer.from(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-pricing-http/http-profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile));
  const program=`import os,sys,hashlib,stat\nname=sys.argv[1]; expected=sys.argv[2]\np='/etc/apparmor.d/'+name\nfd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\ntry:\n st=os.fstat(fd); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1\n assert hashlib.sha256(os.read(fd,1048577)).hexdigest()==expected\nfinally: os.close(fd)\nassert name+' (enforce)' in open('/sys/kernel/security/apparmor/profiles').read().splitlines()\n`;
  const args=['python3','-c',program,profile,sha(bytes)];
  const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]
    :['-F',location.sshConfig,location.sshHost,['sudo','--non-interactive',...args].map(value=>"'"+value.replaceAll("'","'\"'\"'")+"'").join(' ')],{timeoutMs:15000,maxOutputBytes:65536});
  if(result.exitCode!==0)throw fail('PRICING_START_PROFILE_UNAVAILABLE');
}

// Foreground startup may recover the exact enabled object, never provision it.
async function startExisting(options={}){
  const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir();
  const platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
  if(!activation.activationPolicy(environment).requested)throw fail('PRICING_START_ACTIVATION_REQUIRED');
  const record=managed.load({root,home});if(!record?.config.enabled)throw fail('PRICING_START_EXISTING_REQUIRED');
  const run=options.run||createRunner({cwd:root,env:environment});
  const execute=async(file,args,commandOptions={})=>{
    const result=await run(file,args,{timeoutMs:commandOptions.timeout||30000,maxOutputBytes:1048576});
    if(result.exitCode!==0)throw fail('PRICING_START_COMMAND_FAILED');return result;
  };
  const activationOptions={root,home,env:environment,execute,fetchImpl:options.fetchImpl};
  const admitted=await activation.inspectPricingBeforeStart(activationOptions);
  if(admitted.containerId!==record.config.containerId)throw fail('PRICING_START_CONTAINER_CHANGED');
  await (options.verifyExistingProfile||verifyExistingProfile)({root,home,platform,authority:record.authority,profile:record.config.profile,run});
  const authorityFile=path.join(managed.paths({root,home}).directory,'local-docker.json');
  const authorityIdentity=managed._private.captureFile(authorityFile,8192);
  const samePrivateState=()=>{
    const current=managed.load({root,home}),now=managed._private.captureFile(authorityFile,8192);
    if(!current||current.sha256!==record.sha256||current.identity.dev!==record.identity.dev||current.identity.ino!==record.identity.ino
      ||now.sha256!==authorityIdentity.sha256||now.identity.dev!==authorityIdentity.identity.dev||now.identity.ino!==authorityIdentity.identity.ino)
      throw fail('PRICING_START_STATE_CHANGED');
  };
  const docker=async args=>{
    const result=await run('docker',['--host',record.authority.host,...args],{timeoutMs:15000,maxOutputBytes:1048576});
    if(result.exitCode!==0)throw fail('PRICING_START_COMMAND_FAILED');return result.stdout;
  };
  const inspect=async()=>{
    let rows;try{rows=JSON.parse(await docker(['container','inspect',record.config.containerId]));}catch{throw fail('PRICING_START_INSPECT_FAILED');}
    if(!Array.isArray(rows)||rows.length!==1||rows[0]?.Id!==record.config.containerId)throw fail('PRICING_START_CONTAINER_CHANGED');
    return rows[0];
  };
  const currentAdmission=await activation.inspectPricingBeforeStart(activationOptions);
  if(currentAdmission.containerId!==record.config.containerId)throw fail('PRICING_START_CONTAINER_CHANGED');
  const before=await inspect();
  if(!(before.State?.Running===true&&before.State.Status==='running'
    ||before.State?.Running===false&&before.State.Status==='exited'))throw fail('PRICING_START_CONTAINER_STATE');
  samePrivateState();
  if(!before.State.Running){try{await docker(['start',record.config.containerId]);}catch{/* Reinspect the exact ID after uncertain acknowledgement. */}}
  const after=await inspect();
  if(after.State?.Running!==true||after.State.Status!=='running')throw fail('PRICING_START_UNCERTAIN');
  await activation.preparePricingClient(activationOptions);
  const finalAdmission=await activation.inspectPricingBeforeStart(activationOptions);
  if(finalAdmission.containerId!==record.config.containerId)throw fail('PRICING_START_CONTAINER_CHANGED');
  const finalContainer=await inspect();
  if(finalContainer.State?.Running!==true||finalContainer.State.Status!=='running')throw fail('PRICING_START_CONTAINER_CHANGED');
  await (options.verifyExistingProfile||verifyExistingProfile)({root,home,platform,authority:record.authority,profile:record.config.profile,run});
  samePrivateState();
  return Object.freeze({ready:true,enabled:true,containerId:record.config.containerId});
}
module.exports={prepare:planner.plan,provision,startExisting,_internals:{provisionProfile,verifyExistingProfile,ensureBase,temporaryRoot}};
