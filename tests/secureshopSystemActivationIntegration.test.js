'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const managed=require('../server/services/secureshopSystemManagedConfiguration');
const activation=require('../scripts/install/secureshop-owned-system-activate');
const runtime=require('../server/services/secureshopSystemManagedEnvironment');
const {workspaceId}=require('../scripts/application-data-root');
const {authorityDigest}=require('../scripts/local-docker-authority');
function fixture(t){const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'system-activation-')));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));const root=path.join(home,'source');fs.mkdirSync(root);const id=workspaceId(root),dir=path.join(home,'.dvaia',id);fs.mkdirSync(dir,{recursive:true,mode:0o700});const authority={version:1,workspaceId:id,host:'unix:///tmp/owned-test.sock',daemonId:'controlled',source:'environment-host'};fs.writeFileSync(path.join(dir,'local-docker.json'),JSON.stringify(authority),{mode:0o600});const filePath=managed.managedPath({root,home});const value={version:1,workspaceId:id,enabled:false,architecture:'arm64',dockerAuthoritySha256:authorityDigest(authority),imageId:'sha256:'+'a'.repeat(64),sourceManifestSha256:'b'.repeat(64),profile:{name:'dvaia-mcp-sandbox',sha256:'c'.repeat(64)},config:{container:`dvaia-owned-system-${id}-config`,url:'http://127.0.0.1:8090',token:'A'.repeat(43)},diagnostic:{container:`dvaia-owned-system-${id}-diagnostic`,url:'http://127.0.0.1:8091',token:'B'.repeat(43)},restart:{container:`dvaia-owned-system-${id}-restart`,url:'http://127.0.0.1:8092',token:'C'.repeat(43)}};managed.stage({filePath,value});return{root,home,filePath,value,dir};}
const prerequisites={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
test('default disabled integration performs no provisioning; missing and staged runtime return no values',async t=>{const f=fixture(t);assert.deepEqual(runtime.load({...f,environment:{}}),{});let calls=0;const result=await activation.setupOwnedSystem({enabled:false,provision:()=>{calls++;}});assert.equal(calls,0);assert.equal(result.activationEnabled,false);fs.unlinkSync(f.filePath);assert.deepEqual(runtime.load({...f,environment:{}}),{});});
test('explicit setup verifies twice then activates exact bytes, preserves credentials; repeat stays same inode',async t=>{const f=fixture(t);let calls=0;const provision=async o=>{calls++;assert.equal(o.reconcileEnabled,true);return{ready:true,managedPath:f.filePath,imageId:f.value.imageId};};const options={enabled:true,root:f.root,homeDirectory:f.home,applicationEnvironment:prerequisites,provision};await activation.setupOwnedSystem(options);assert.equal(calls,2);const value=managed.load(f);assert.equal(value.enabled,true);assert.equal(value.config.token,f.value.config.token);assert.equal(value.restart.token,f.value.restart.token);const inode=fs.statSync(f.filePath).ino;await activation.setupOwnedSystem(options);assert.equal(fs.statSync(f.filePath).ino,inode);const overlay=runtime.load({...f,environment:{}});assert.equal(overlay.SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED,'true');assert.equal(overlay.SS_BOUND_SYSTEM_RESTART_ENABLED,'true');assert.equal(overlay.SS_SYSTEM_CONFIG_TOKEN,f.value.config.token);assert.equal(overlay.SS_SYSTEM_RESTART_TOKEN,f.value.restart.token);});
test('readiness failure and changed exact file identity during final verification never activate',async t=>{for(const mode of ['failure','replace','bytes']){const f=fixture(t);let n=0;await assert.rejects(activation.setupOwnedSystem({enabled:true,root:f.root,homeDirectory:f.home,applicationEnvironment:prerequisites,provision:async()=>{if(++n===2){if(mode==='failure')throw Error('held readiness');if(mode==='replace'){fs.unlinkSync(f.filePath);managed.stage({filePath:f.filePath,value:f.value});}else fs.writeFileSync(f.filePath,managed.encode({...f.value,sourceManifestSha256:'f'.repeat(64)}));}return{ready:true,managedPath:f.filePath,imageId:f.value.imageId};}}));assert.equal(managed.load(f).enabled,false);}});
test('enabled overlay rejects explicit env conflict and wrong recorded Docker binding without exposing tokens',t=>{const f=fixture(t);activation.activate({filePath:f.filePath,expected:activation.capture(f.filePath)});assert.throws(()=>runtime.load({...f,environment:{SS_BOUND_SYSTEM_CONFIG_ENABLED:'false'}}),{code:'SYSTEM_ACTIVATION_ENV_CONFLICT'});fs.writeFileSync(path.join(f.dir,'local-docker.json'),JSON.stringify({version:1,workspaceId:workspaceId(f.root),host:'unix:///tmp/other.sock',daemonId:'wrong',source:'environment-host'}));assert.throws(()=>runtime.load({...f,environment:{}}),{code:'SYSTEM_ACTIVATION_AUTHORITY'});});
test('missing prerequisite refuses before provision; failed identity CAS preserves current bytes',async t=>{const f=fixture(t);let calls=0;await assert.rejects(activation.setupOwnedSystem({enabled:true,root:f.root,homeDirectory:f.home,applicationEnvironment:{},provision:()=>calls++}),{code:'SYSTEM_ACTIVATION_PREREQUISITES'});assert.equal(calls,0);const expected={...activation.capture(f.filePath),sha256:'0'.repeat(64)};const bytes=fs.readFileSync(f.filePath);assert.throws(()=>activation.activate({filePath:f.filePath,expected}),{code:'SYSTEM_ACTIVATION_CONFLICT'});assert.deepEqual(fs.readFileSync(f.filePath),bytes);assert.ok(!fs.existsSync(f.filePath+'.activation-lock'));});

test('unsupported host architecture fails before provisioning',async t=>{
 const f=fixture(t);let called=false;
 await assert.rejects(activation.setupOwnedSystem({enabled:true,architecture:'x64',root:f.root,homeDirectory:f.home,applicationEnvironment:prerequisites,provision:()=>{called=true;}}),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});
 assert.equal(called,false);assert.equal(managed.load(f).enabled,false);
});

test('capture rejects path replacement during descriptor-bound read instead of mixing old bytes with new inode',t=>{
 const f=fixture(t),original=fs.lstatSync;let injected=false;
 try{
  fs.lstatSync=function(file,...args){
   if(file===f.filePath&&!injected){injected=true;const replacement=f.filePath+'.replacement';fs.writeFileSync(replacement,managed.encode({...f.value,sourceManifestSha256:'f'.repeat(64)}),{mode:0o600});fs.renameSync(replacement,f.filePath);}
   return original.call(this,file,...args);
  };
  assert.throws(()=>activation.capture(f.filePath),{code:'SYSTEM_MANAGED_UNTRUSTED'});
 }finally{fs.lstatSync=original;}
 assert.equal(injected,true);assert.equal(managed.load(f).enabled,false);
});

test('parent and child share qualified prerequisites before System policy validation, without logging secrets',t=>{
 const f=fixture(t);activation.activate({filePath:f.filePath,expected:activation.capture(f.filePath)});
 const qualified=require('../server/services/secureshopQualifiedManagedConfiguration');
 const roots=qualified.expectedRoots(f.root,f.home);for(const value of Object.values(roots))fs.mkdirSync(value,{mode:0o700});
 const values={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',SS_PERSONA_INBOX_READY:'true',SS_MCP_TRUST_READY:'true',SS_CONTROLLED_SSRF_READY:'true',...roots};
 fs.writeFileSync(qualified.managedPath(f.root,f.home),Object.entries(values).map(([k,v])=>k+'='+v).join('\n')+'\n',{mode:0o600});
 const base={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};let output='';const original=console.log;
 try{console.log=(...args)=>{output+=args.join(' ');};const effective={...base,...runtime.loadWithQualified({...f,environment:base})};assert.equal(require('../server/services/secureshopSystemConfigActivation').activationPolicy(effective).requested,true);assert.equal(require('../server/services/secureshopSystemDiagnosticActivation').activationPolicy(effective).requested,true);}finally{console.log=original;}
 assert.equal(output,'');assert.throws(()=>runtime.loadWithQualified({...f,environment:{...base,SS_SYSTEM_CONFIG_TOKEN:'conflicting'}}),{code:'SYSTEM_ACTIVATION_ENV_CONFLICT'});
});

test('fresh opt-in missing persistent prerequisites fails before any setup write or execution despite ephemeral flags',async t=>{
 const f=fixture(t);fs.unlinkSync(f.filePath);let calls=0;const before=fs.readdirSync(f.dir),rootBefore=fs.readdirSync(f.root);
 await assert.rejects(require('../scripts/setup-application').setup({root:f.root,homeDirectory:f.home,ownedSystem:true,processEnvironment:prerequisites,runCommand:async()=>calls++,execute:async()=>calls++,provision:async()=>calls++}),{code:'SYSTEM_ACTIVATION_PERSISTENT_PREREQUISITES'});
 assert.equal(calls,0);assert.deepEqual(fs.readdirSync(f.dir),before);assert.deepEqual(fs.readdirSync(f.root),rootBefore);
 assert.equal(activation.assertPersistentPrerequisites({root:f.root,homeDirectory:f.home,existingEnvironment:prerequisites}),true);
 assert.throws(()=>activation.assertPersistentPrerequisites({root:f.root,homeDirectory:f.home,existingEnvironment:{...prerequisites,SS_BOUND_REVIEWS_ENABLED:'false'}}),{code:'SYSTEM_ACTIVATION_PERSISTENT_PREREQUISITES'});
});

test('explicit fresh listener ports are canonical, distinct, preserved and conflict-checked before provisioning',async t=>{
 const f=fixture(t);fs.unlinkSync(f.filePath);
 assert.deepEqual(activation.listenerPorts({root:f.root,homeDirectory:f.home,environment:{}}),{configPort:8090,diagnosticPort:8091,restartPort:8092});
 for(const bad of ['08090',' 8090','8090x','1023','65536','1e4',8090])assert.throws(()=>activation.listenerPorts({root:f.root,homeDirectory:f.home,environment:{DVAIA_SYSTEM_CONFIG_PORT:bad}}),{code:'SYSTEM_INSTALL_PORT_INVALID'});
 assert.throws(()=>activation.listenerPorts({root:f.root,homeDirectory:f.home,environment:{DVAIA_SYSTEM_CONFIG_PORT:'8091'}}),{code:'SYSTEM_INSTALL_PORT_CONFLICT'});
 const environment={DVAIA_SYSTEM_CONFIG_PORT:'19090',DVAIA_SYSTEM_DIAGNOSTIC_PORT:'19091',DVAIA_SYSTEM_RESTART_PORT:'19092'};let calls=0;
 const provision=async options=>{calls++;assert.equal(options.configPort,19090);assert.equal(options.diagnosticPort,19091);assert.equal(options.restartPort,19092);if(!fs.existsSync(f.filePath))managed.stage({filePath:f.filePath,value:{...f.value,config:{...f.value.config,url:'http://127.0.0.1:19090'},diagnostic:{...f.value.diagnostic,url:'http://127.0.0.1:19091'},restart:{...f.value.restart,url:'http://127.0.0.1:19092'}}});return{ready:true,managedPath:f.filePath,imageId:f.value.imageId};};
 const options={enabled:true,root:f.root,homeDirectory:f.home,applicationEnvironment:prerequisites,environment,provision};
 await activation.setupOwnedSystem(options);const bytes=fs.readFileSync(f.filePath);await activation.setupOwnedSystem({...options,environment:{}});assert.deepEqual(fs.readFileSync(f.filePath),bytes);assert.equal(calls,4);
 await assert.rejects(activation.setupOwnedSystem({...options,environment:{DVAIA_SYSTEM_CONFIG_PORT:'19093'}}),{code:'SYSTEM_INSTALL_PORT_CONFLICT'});assert.equal(calls,4);
 const before=fs.readdirSync(f.root);await assert.rejects(require('../scripts/setup-application').setup({root:f.root,homeDirectory:f.home,ownedSystem:true,qualifiedSecureShop:true,processEnvironment:{DVAIA_SYSTEM_CONFIG_PORT:'19093'},preflightQualifiedSystem:()=>assert.fail('must reject before preflight')}),{code:'SYSTEM_INSTALL_PORT_CONFLICT'});assert.deepEqual(fs.readdirSync(f.root),before);
});
