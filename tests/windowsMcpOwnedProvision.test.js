'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto'),{createRequire}=require('node:module');
const root=path.resolve(__dirname,'..');
const {createOwnedPrivateStorage,prepareOwnedManagedConfiguration}=require('../scripts/install/mcp-owned-local');
const native=require('../scripts/lib/windows-private-state');
function load(relative,overrides={}){
 const filename=path.join(root,relative),module={exports:{}},requireActual=createRequire(filename);
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,__dirname:path.dirname(filename),process,Buffer,console,setTimeout,clearTimeout,require:name=>overrides[name]||requireActual(name)});return module.exports;
}
const binding={kind:'owned-windows-lab',workspaceId:require('../scripts/application-data-root').workspaceId(root),bindingSha256:'a'.repeat(64),daemonId:'owned-daemon'};
function fixture(){
 const calls=[],session={};
 const local=load('scripts/install/mcp-owned-local.js',{'../lib/windows-owned-lab':{describeOwnedLab(value){if(value!==session)throw Error('unadmitted');return binding;}}});
 const realFs=require('node:fs/promises'),fixtureBytes=file=>Buffer.from('controlled build source: '+path.relative(root,file));
 const sourceFs={...realFs,async lstat(file){const stat=await realFs.lstat(file);if(stat.isFile()&&!file.endsWith('.apparmor.in'))return{...stat,size:fixtureBytes(file).length,isFile:()=>true,isSymbolicLink:()=>false,isDirectory:()=>false};return stat;},async readFile(file,encoding){if(file.endsWith('.apparmor.in'))return realFs.readFile(file,encoding);return fixtureBytes(file);}};
 const api=load('scripts/install/mcp-owned-provision.js',{'./mcp-owned-local':local,'node:fs/promises':sourceFs});
 session.installAndVerifyProfile=async value=>{calls.push(['profile',value]);return{name:value.name,sha256:value.sha256,destination:'/etc/apparmor.d/'+value.name,bindingSha256:binding.bindingSha256};};
 session.stageReviewedBundle=async files=>{calls.push(['bundle',files]);return'/var/lib/dvaia/owned/bundles/exact';};
 session.stagePrivateEnvironment=async value=>{calls.push(['environment',value]);return'/var/lib/dvaia/owned/private/env-exact';};
 session.executeDocker=async(args,options)=>{calls.push(['docker',args,options]);return'';};
 return{api,local,session,calls};
}
const ready={ready:true,runnerReady:true,runnerIsolation:'bwrap-seccomp-v1',supervisorProfile:'dvaia-mcp-sandbox (enforce)'};
test('Windows protected runner uses only admitted session with reviewed profile/build and private Compose values',async()=>{
 const f=fixture(),token='t'.repeat(64),result=await f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:f.session,commandEnv:{MCP_OWNED_TARGET_TOKEN:token,MCP_OWNED_TARGET_APPARMOR_PROFILE:'dvaia-mcp-sandbox',MCP_OWNED_TARGET_PORT:'8092',UNRELATED_SECRET:'excluded'},run:()=>assert.fail('host process forbidden'),readiness:async()=>ready});
 assert.equal(result.ok,true);assert.equal(result.activationEnabled,false);
 const profile=f.calls[0][1];assert(Buffer.isBuffer(profile.bytes));assert.equal(profile.sha256,createHash('sha256').update(profile.bytes).digest('hex'));
 const bundle=f.calls.find(c=>c[0]==='bundle')[1];assert(bundle.some(file=>file.path==='docker-compose.yml'));assert(bundle.some(file=>file.path==='sidecars/sandbox-runner/Dockerfile'));assert(bundle.length<=128);assert(bundle.every(file=>file.sha256===createHash('sha256').update(file.bytes).digest('hex')));assert(!bundle.some(file=>file.path==='.env'||file.path.includes('/sandbox-runner/test/')));
 const env=f.calls.find(c=>c[0]==='environment')[1];assert(env.bytes.includes(token));assert(!env.bytes.includes('UNRELATED_SECRET'));assert.equal(env.sha256,createHash('sha256').update(env.bytes).digest('hex'));
 const docker=f.calls.filter(c=>c[0]==='docker');assert.equal(docker.length,2);assert.deepEqual(Array.from(docker[0][1].slice(0,5)),['compose','--project-name','dvaia-'+binding.workspaceId,'--env-file','/var/lib/dvaia/owned/private/env-exact']);assert(docker[0][1].includes('--no-recreate'));assert(docker[1][1].includes('--build'));assert(docker.every(c=>c[2].scope==='provision'&&c[2].bundlePath==='/var/lib/dvaia/owned/bundles/exact'&&!c[1].includes('--host')));
});
test('Windows Compose project stays workspace-bound when reviewed bundle changes',async()=>{
 const f=fixture(),bundles=['a'.repeat(64),'b'.repeat(64)];let index=0;
 f.session.stageReviewedBundle=async()=>'/var/lib/dvaia/owned/bundles/'+bundles[index++];
 for(let attempt=0;attempt<2;attempt++)await f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:f.session,commandEnv:{COMPOSE_PROJECT_NAME:'ambient-is-ignored'},readiness:async()=>ready});
 const calls=f.calls.filter(c=>c[0]==='docker');assert.equal(calls.length,4);
 assert.deepEqual([...new Set(calls.map(c=>c[2].bundlePath))],bundles.map(hash=>'/var/lib/dvaia/owned/bundles/'+hash));
 for(const call of calls){assert.equal(call[1][0],'compose');assert.equal(call[1][call[1].indexOf('--project-name')+1],'dvaia-'+binding.workspaceId);assert(!call[1].includes('ambient-is-ignored'));}
});
test('Windows missing session, ambient endpoint and failed profile stop before guest build/Docker',async()=>{
 for(const mode of ['missing','ambient','profile']){const f=fixture();if(mode==='profile')f.session.installAndVerifyProfile=async()=>({name:'wrong'});await assert.rejects(f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:mode==='missing'?{}:f.session,commandEnv:mode==='ambient'?{DOCKER_HOST:'ssh://unowned'}:{},run:()=>assert.fail('host process forbidden'),readiness:async()=>ready}));assert(!f.calls.some(c=>c[0]==='docker'||c[0]==='bundle'));}
});
test('Windows conflicting Compose profile, port or token never reaches guest workload',async()=>{
 for(const commandEnv of [{MCP_OWNED_TARGET_APPARMOR_PROFILE:'unconfined'},{MCP_OWNED_TARGET_PORT:'9090'},{MCP_OWNED_TARGET_TOKEN:'invalid'}]){const f=fixture();await assert.rejects(f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:f.session,commandEnv,readiness:async()=>ready}),{code:'MCP_INSTALL_ENV_CONFLICT'});assert.equal(f.calls.length,0);}
});
test('Windows readiness and protected journal/image checks remain mandatory',async()=>{
 const f=fixture();await assert.rejects(f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:f.session,commandEnv:{},readiness:async()=>({...ready,supervisorProfile:'unconfined'})}),{code:'MCP_INSTALL_READINESS_FAILED'});
 const g=fixture(),profile=require('../scripts/render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8'),'dvaia-mcp-sandbox');
 await assert.rejects(g.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:g.session,commandEnv:{},protectedRecoveryRelease:{image:'sha256:'+'b'.repeat(64),profileSha256:createHash('sha256').update(profile).digest('hex')},readiness:async()=>ready}),{code:'MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED'});
});
test('Windows protected image and AppArmor inspection must match reviewed release',async()=>{
 for(const valid of [false,true]){
  const f=fixture(),image='sha256:'+'b'.repeat(64);let profileSha256;
  const install=f.session.installAndVerifyProfile;f.session.installAndVerifyProfile=async value=>{profileSha256=value.sha256;return install(value);};
  f.session.executeDocker=async(args,options)=>{f.calls.push(['docker',args,options]);if(args[0]==='inspect')return JSON.stringify({Image:valid?image:'sha256:'+'c'.repeat(64),AppArmorProfile:'dvaia-mcp-sandbox'});if(args.includes('ps'))return'd'.repeat(64);return'';};
  const profile=require('../scripts/render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8'),'dvaia-mcp-sandbox');
  const operation=f.api.provisionOwnedLocal({platform:'win32',root,ownedLabSession:f.session,commandEnv:{},protectedRecoveryRelease:{image,profileSha256:createHash('sha256').update(profile).digest('hex')},readiness:async()=>({...ready,protectedJournalCapability:'mcp-owned-protected-operation-journal.v1',protectedReadbackCapability:'mcp-owned-protected-readback.v1'})});
  if(valid){const result=await operation;assert.equal(result.protectedRecoveryQualified,true);assert.equal(result.profileSha256,profileSha256);}else await assert.rejects(operation,{code:'MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED'});
 }
});
function storageFixture(){
 const envPath='C:\\Source\\.env',managedPath='C:\\Users\\Learner\\private\\mcp-owned.env',files=new Map([[envPath,Buffer.from('JWT_SECRET='+'s'.repeat(48)+'\n')]]),calls=[];let denial,publicationFailure;
 const storage=createOwnedPrivateStorage({filesystemPlatform:'win32',fileSystem:{async lstat(file){calls.push(['presence',file]);if(!files.has(file))throw Object.assign(Error('absent'),{code:'ENOENT'});return{};}},privateState:{normalizePrivatePath:native.normalizePrivatePath,readPrivateWorkspaceFile(file){calls.push(['workspace-read',file]);if(denial)throw Object.assign(Error('secret'),{code:denial});return files.get(file);},readPrivateFile(file){calls.push(['private-read',file]);if(denial)throw Object.assign(Error('secret'),{code:denial});return files.get(file);}},journal:{inspectDestination(){},createJournal({filePath,bytes}){calls.push(['create']);if(publicationFailure)throw Error('secret');assert(!files.has(filePath));files.set(filePath,Buffer.from(bytes));},updateJournal({filePath,originalBytes,resultBytes}){calls.push(['update']);if(publicationFailure)throw Error('secret');assert(files.get(filePath).equals(originalBytes));files.set(filePath,Buffer.from(resultBytes));}}});
 return{storage,envPath,managedPath,files,calls,deny(){denial='ENOENT';},failPublication(){publicationFailure=true;}};
}
test('Windows managed config creates/updates exact journal bytes and preserves workspace env/token',async()=>{
 const f=storageFixture(),original=Buffer.from(f.files.get(f.envPath)),opts={envPath:f.envPath,managedPath:f.managedPath,storage:f.storage,randomToken:()=> 'T'.repeat(64)};
 await prepareOwnedManagedConfiguration(opts);assert(f.calls.some(c=>c[0]==='create'));const activated=await prepareOwnedManagedConfiguration({...opts,activateQualified:true});assert.equal(activated.activationEnabled,true);assert(f.calls.some(c=>c[0]==='update'));assert(f.files.get(f.envPath).equals(original));assert.equal(activated.values.MCP_OWNED_TARGET_TOKEN,'T'.repeat(64));
});
test('Windows native denied read is never optional absence and failed publication never activates',async()=>{
 const f=storageFixture();f.deny();await assert.rejects(prepareOwnedManagedConfiguration({envPath:f.envPath,managedPath:f.managedPath,storage:f.storage}),{code:'MCP_INSTALL_ENV_INVALID'});assert(!f.calls.some(c=>c[0]==='create'||c[0]==='update'));
 const g=storageFixture();g.failPublication();await assert.rejects(prepareOwnedManagedConfiguration({envPath:g.envPath,managedPath:g.managedPath,storage:g.storage,activateQualified:true}),{code:'MCP_INSTALL_RECOVERY_REQUIRED'});assert(!g.files.has(g.managedPath));
});
test('Windows retained pending config prevents publication and managed entrypoint passes opaque session',async()=>{
 const f=storageFixture();f.files.set(f.managedPath+'.pending',Buffer.from('retained'));await assert.rejects(prepareOwnedManagedConfiguration({envPath:f.envPath,managedPath:f.managedPath,storage:f.storage}),{code:'MCP_INSTALL_RECOVERY_REQUIRED'});assert(!f.calls.some(c=>c[0]==='create'||c[0]==='update'));
 const g=storageFixture(),h=fixture();let observed=false;
 const result=await h.api.provisionFromEnvironment({platform:'win32',root,envPath:g.envPath,managedPath:g.managedPath,storage:g.storage,ownedLabSession:h.session,targetClientFactory:()=>({readiness:async()=>ready}),codeBotReadiness:async()=>({}),provision:async options=>{observed=true;assert.equal(options.ownedLabSession,h.session);assert.equal(options.commandEnv.MCP_OWNED_RESOURCES_ENABLED,'false');return{ok:true,activationEnabled:false};}});
 assert.equal(result.activationEnabled,false);assert(observed);
});
