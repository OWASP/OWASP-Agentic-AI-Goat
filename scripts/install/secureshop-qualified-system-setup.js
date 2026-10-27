'use strict';
// Explicit combined six-panel/System setup. No import-time work or profile writes.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const config=require('../../server/services/secureshopQualifiedManagedConfiguration');
const {workspaceId}=require('../application-data-root');
const authorityTools=require('../local-docker-authority');
const {sourceManifest}=require('./secureshop-owned-system');
const {_internals}=require('./secureshop-owned-system-provision');
const fail=code=>Object.assign(new Error('Combined SecureShop/System setup requires recovery'),{code});
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const encode=v=>Buffer.from(config.KEYS.map(k=>k+'='+v[k]).join('\n')+'\n');
function captured(file){let fd;try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const before=fs.fstatSync(fd);if(!before.isFile()||before.uid!==process.getuid()||before.nlink!==1||(before.mode&0o077)||before.size>8192)throw fail('SYSTEM_QUALIFIED_UNTRUSTED');const b=Buffer.alloc(8193),n=fs.readSync(fd,b,0,b.length,0),after=fs.fstatSync(fd),named=fs.lstatSync(file);if(n!==before.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.ino!==named.ino||before.dev!==named.dev||named.isSymbolicLink())throw fail('SYSTEM_QUALIFIED_UNTRUSTED');return{bytes:b.subarray(0,n),dev:before.dev,ino:before.ino};}catch(e){if(e.code==='ENOENT')return null;throw e;}finally{if(fd!==undefined)fs.closeSync(fd);}}
function matches(a,b){return(!a&&!b)||!!a&&!!b&&a.dev===b.dev&&a.ino===b.ino&&a.bytes.equals(b.bytes);}
function checkedExisting(root,home){const file=config.managedPath(root,home),value=captured(file);if(value)config.parse(value.bytes,{root,home});return value;}
// Read-only selection before preflight. Never inherit an unrelated active
// Docker context; every later setup consumer receives this same explicit host.
async function selectSetupEnvironment({root,home=os.homedir(),platform=process.platform,environment=process.env}) {
 if(!['linux','darwin'].includes(platform)||environment.DOCKER_CONTEXT)throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
 const directory=path.dirname(config.managedPath(root,home));
 const existing=fs.existsSync(directory)?await authorityTools.readLocalDockerAuthority({directory,workspaceId:workspaceId(root),platform}):null;
 const location=require('./mcp-owned-local').localProfilePlan({root,home,platform,colimaProfile:environment.DVAIA_MCP_OWNED_COLIMA_PROFILE||'colima-default'});
 const host=existing?.host||environment.DOCKER_HOST||location.dockerHost;
 if(existing&&environment.DOCKER_HOST&&environment.DOCKER_HOST!==existing.host)throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
 if(platform==='darwin'&&environment.DVAIA_MCP_OWNED_COLIMA_PROFILE&&host!==location.dockerHost)throw fail('SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT');
 authorityTools.assertLocalDockerHost(host,platform);
 const boundLocation=_internals.profileLocation({authority:{host},root,home,platform});
 return {...environment,DOCKER_HOST:host,...(platform==='darwin'?{DVAIA_MCP_OWNED_COLIMA_PROFILE:boundLocation.colimaProfile}:{})};
}
async function preflight({root,home=os.homedir(),platform=process.platform,architecture=process.arch,environment=process.env,
 run=_internals.createRunner({cwd:root,env:authorityTools.sanitizeDockerEnvironment(environment)}),verifyProfile=_internals.verifyProfile}={}){
 if(architecture!=='arm64'||!['darwin','linux'].includes(platform))throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 checkedExisting(root,home);
 for(const name of [config.managedPath(root,home)+'.setup-lock',path.join(path.dirname(config.managedPath(root,home)),'secureshop-qualified.candidate.env')])if(fs.existsSync(name))throw fail('SYSTEM_QUALIFIED_RECOVERY_REQUIRED');
 const directory=path.dirname(config.managedPath(root,home)),id=workspaceId(root);let authority;
 if(fs.existsSync(directory))authority=await authorityTools.readLocalDockerAuthority({directory,workspaceId:id,platform});
 const execute=async(file,args,o)=>{const r=await run(file,args,{timeoutMs:o.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('SYSTEM_INSTALL_AUTHORITY_UNAVAILABLE');return r;};
 if(authority)await authorityTools.verifyDockerAuthority({authority,execute,environment});
 else{
  if(!environment.DOCKER_HOST||environment.DOCKER_CONTEXT)throw fail('SYSTEM_INSTALL_AUTHORITY_REQUIRED');
  authorityTools.assertLocalDockerHost(environment.DOCKER_HOST,platform);
  authority={version:1,workspaceId:id,host:environment.DOCKER_HOST,source:'environment-host',platform};
  authority.daemonId=await authorityTools.inspectDockerDaemon({authority,execute,environment});
 }
 const source=sourceManifest(root),template=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8');
 const rendered=require('../render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(template,'dvaia-mcp-sandbox');
 const p={profile:{name:'dvaia-mcp-sandbox',sha256:hash(rendered)}};
 const profile=await verifyProfile({p,authority,root,home,platform,run,allowPreparation:true});
 return Object.freeze({architecture,sourceSha256:source.sha256,dockerAuthoritySha256:authorityTools.authorityDigest(authority),profileVerified:profile?.profileVerified===true,profilePreparationRequired:profile?.profilePreparationRequired===true,mutating:false});
}
function replace(file,expected,bytes){if(!matches(captured(file),expected))throw fail('SYSTEM_QUALIFIED_CONFLICT');const temp=file+'.pending-'+crypto.randomBytes(12).toString('hex');let fd;try{fd=fs.openSync(temp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;if(!matches(captured(file),expected))throw fail('SYSTEM_QUALIFIED_CONFLICT');fs.renameSync(temp,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temp);}catch(e){if(e.code!=='ENOENT')throw e;}}return captured(file);}
async function ensureAuthority({root,home,platform,environment,run}) {
 const directory=path.dirname(config.managedPath(root,home)),id=workspaceId(root);
 const existing=await authorityTools.readLocalDockerAuthority({directory,workspaceId:id,platform});
 if(!existing&&(!environment.DOCKER_HOST||environment.DOCKER_CONTEXT))throw fail('SYSTEM_INSTALL_AUTHORITY_REQUIRED');
 const execute=async(file,args,o)=>{const r=await run(file,args,{timeoutMs:o.timeout||30000,maxOutputBytes:1048576});if(r.exitCode!==0)throw fail('SYSTEM_INSTALL_AUTHORITY_UNAVAILABLE');return r;};
 await authorityTools.resolveDockerAuthority({directory,workspaceId:id,platform,environment,execute,persist:true});
}
async function prepare({root,homeDirectory=os.homedir(),platform=process.platform,environment=process.env,applicationEnvironment,
 run=_internals.createRunner({cwd:root,env:{...environment,...applicationEnvironment,HOME:homeDirectory}}),ensureAuthority:recordAuthority=ensureAuthority,
 prepareProfile=prepareSelectedProfile,
 activateSystem=require('./secureshop-owned-system-activate').setupOwnedSystem}={}){
 const home=homeDirectory,file=config.managedPath(root,home),previous=checkedExisting(root,home),directory=path.dirname(file);
 require('../../server/services/secureshopPasswordResetKeys').assertPrivateDirectory(directory);
 await recordAuthority({root,home,platform,environment,run});
 await prepareProfile({root,home,platform,environment,run});
 const lock=file+'.setup-lock';fs.mkdirSync(lock,{mode:0o700});const lockStat=fs.lstatSync(lock);
 let candidate,candidateIdentity,published;
 try{
  const roots=config.expectedRoots(root,home);for(const target of Object.values(roots)){try{fs.mkdirSync(target,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}require('../../server/services/secureshopPasswordResetKeys').assertPrivateDirectory(target);}
  const values={SS_ENABLE:'true',...Object.fromEntries(config.BOOLEAN_KEYS.map(k=>[k,'true'])),...roots};const bytes=encode(values);config.parse(bytes,{root,home});
  let current=previous;
  if(!current){const disabled=encode({...values,...Object.fromEntries(config.BOOLEAN_KEYS.map(k=>[k,'false']))});const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,disabled);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}current=captured(file);}
  if(!matches(captured(file),current))throw fail('SYSTEM_QUALIFIED_CONFLICT');
  candidate=path.join(directory,'secureshop-qualified.candidate.env');const fd=fs.openSync(candidate,'wx',0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}candidateIdentity=captured(candidate);
  const result=await run(process.execPath,['scripts/qualify-secureshop-qualified-activation.js','--candidate-readiness'],{timeoutMs:120000,maxOutputBytes:1048576});
  const lines=String(result.stdout||'').split(/\r?\n/).filter(line=>line.startsWith('SECURESHOP_ACTIVATION_QUALIFICATION='));let receipt;try{if(lines.length===1)receipt=JSON.parse(lines[0].slice('SECURESHOP_ACTIVATION_QUALIFICATION='.length));}catch{}
  const curriculum=require('../../server/config/secureshopCurriculum');
  if(result.exitCode!==0||receipt?.ready!==true||JSON.stringify(receipt.objectiveIds)!==JSON.stringify(curriculum.OBJECTIVES.map(r=>r.id))||JSON.stringify(receipt.structuralPanels)!==JSON.stringify(curriculum.EXERCISES.map(r=>r.id)))throw fail('SYSTEM_QUALIFIED_READINESS_FAILED');
  if(!matches(captured(candidate),candidateIdentity)||!candidateIdentity.bytes.equals(bytes))throw fail('SYSTEM_QUALIFIED_CONFLICT');
  const existingValues=config.parse(current.bytes,{root,home});
  if(!config.KEYS.every(key=>existingValues[key]===values[key]))published=replace(file,current,bytes);
  else if(!matches(captured(file),current))throw fail('SYSTEM_QUALIFIED_CONFLICT');
  const system=await activateSystem({enabled:true,root,homeDirectory,platform,environment,applicationEnvironment:{...applicationEnvironment,...values}});
  if(system.activationEnabled!==true)throw fail('SYSTEM_QUALIFIED_SYSTEM_NOT_READY');
  return Object.freeze({qualifiedSecureShop:true,panels:6,system:true,activationEnabled:true,externalConsumersEnabled:false});
 }catch(error){
  // Restore only the exact record this invocation published. No DB, credential,
  // fixture contents or instructor-edited activation is rolled back.
  if(published)replace(file,published,previous?previous.bytes:encode({...config.parse(published.bytes,{root,home}),...Object.fromEntries(config.BOOLEAN_KEYS.map(k=>[k,'false']))}));
  throw error;
 }finally{
  if(candidateIdentity){if(!matches(captured(candidate),candidateIdentity))throw fail('SYSTEM_QUALIFIED_CANDIDATE_CHANGED');fs.unlinkSync(candidate);}
  const now=fs.lstatSync(lock);if(now.ino!==lockStat.ino||now.dev!==lockStat.dev)throw fail('SYSTEM_QUALIFIED_LOCK_CHANGED');fs.rmdirSync(lock);
 }
}
async function prepareSelectedProfile({root,home,platform,environment,run}) {
 const authority=await authorityTools.readLocalDockerAuthority({directory:path.dirname(config.managedPath(root,home)),workspaceId:workspaceId(root),platform});
 if(!authority)throw fail('SYSTEM_INSTALL_AUTHORITY_REQUIRED');
 const template=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8');
 const rendered=require('../render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(template,'dvaia-mcp-sandbox');
 await _internals.prepareProfile({root,home,platform,environment,run,authority,p:{profile:{name:'dvaia-mcp-sandbox',sha256:hash(rendered)}}});
}
function loadCandidate({root,home=os.homedir()}) {
 const directory=path.dirname(config.managedPath(root,home));
 const assertDirectory=require('../../server/services/secureshopPasswordResetKeys').assertPrivateDirectory;
 assertDirectory(directory);
 const record=captured(path.join(directory,'secureshop-qualified.candidate.env'));
 if(!record)throw fail('SYSTEM_QUALIFIED_CANDIDATE_MISSING');
 const values=config.parse(record.bytes,{root,home});
 if(values.SS_BOUND_REVIEWS_ENABLED!=='true')throw fail('SYSTEM_QUALIFIED_UNTRUSTED');
 config.ROOT_KEYS.forEach(key=>assertDirectory(values[key]));
 return values;
}
module.exports={preflight,prepare,loadCandidate,selectSetupEnvironment};
