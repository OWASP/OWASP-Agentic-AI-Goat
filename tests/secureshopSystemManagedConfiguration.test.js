'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawn}=require('node:child_process');
const managed=require('../server/services/secureshopSystemManagedConfiguration');
const root=path.resolve(__dirname,'..');
const {workspaceId}=require('../scripts/application-data-root');
const {authorityDigest}=require('../scripts/local-docker-authority');
const installer=require('../scripts/install/secureshop-owned-system');
function fixture(t){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'system-managed-test-'));fs.chmodSync(directory,0o700);t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));const filePath=path.join(directory,'record.json');return{directory,filePath};}
function value(){return{version:1,workspaceId:'a'.repeat(12),enabled:false,architecture:'arm64',dockerAuthoritySha256:'b'.repeat(64),imageId:'sha256:'+'c'.repeat(64),sourceManifestSha256:'d'.repeat(64),profile:{name:'dvaia-mcp-sandbox',sha256:'e'.repeat(64)},config:{container:'dvaia-owned-system-'+ 'a'.repeat(12)+'-config',url:'http://127.0.0.1:8090',token:'A'.repeat(43)},diagnostic:{container:'dvaia-owned-system-'+ 'a'.repeat(12)+'-diagnostic',url:'http://127.0.0.1:8091',token:'B'.repeat(43)},restart:{container:'dvaia-owned-system-'+ 'a'.repeat(12)+'-restart',url:'http://127.0.0.1:8092',token:'C'.repeat(43)}};}

test('exclusive staging publishes complete private record; exact repeat preserves bytes and tokens',t=>{
 const{filePath,directory}=fixture(t);assert.equal(managed.load({filePath}),null);
 assert.equal(managed.stage({filePath,value:value()}).created,true);const before=fs.readFileSync(filePath),stat=fs.statSync(filePath);
 assert.equal(stat.mode&0o777,0o600);assert.equal(stat.nlink,1);assert.deepEqual(managed.load({filePath}),value());
 assert.equal(managed.stage({filePath,value:value()}).created,false);assert.deepEqual(fs.readFileSync(filePath),before);assert.equal(fs.statSync(filePath).ino,stat.ino);assert.deepEqual(fs.readdirSync(directory),['record.json']);
 for(const field of ['imageId','sourceManifestSha256','dockerAuthoritySha256']){const v=value();v[field]=(field==='imageId'?'sha256:':'')+'f'.repeat(64);assert.throws(()=>managed.stage({filePath,value:v}),{code:'SYSTEM_MANAGED_CONFLICT'});}
 const changed=value();changed.config.token='D'.repeat(43);assert.throws(()=>managed.stage({filePath,value:changed}),{code:'SYSTEM_MANAGED_CONFLICT'});assert.deepEqual(fs.readFileSync(filePath),before);
});

test('loader rejects permissions, links, ambiguous/oversized data and preserves tampered bytes',t=>{
 const{filePath,directory}=fixture(t);const original=managed.encode(value());fs.writeFileSync(filePath,original,{mode:0o600});
 fs.chmodSync(filePath,0o644);assert.throws(()=>managed.load({filePath}));fs.chmodSync(filePath,0o600);
 const linked=path.join(directory,'linked');fs.linkSync(filePath,linked);assert.throws(()=>managed.load({filePath}));fs.unlinkSync(linked);
 const alias=path.join(directory,'alias');fs.symlinkSync(filePath,alias);assert.throws(()=>managed.load({filePath:alias}));
 for(const bytes of ['{"version":0,'+original.slice(1),' '.repeat(9000),'{invalid',original.replace('"arm64"','"amd64"')]){fs.writeFileSync(filePath,bytes);assert.throws(()=>managed.load({filePath}));assert.throws(()=>managed.stage({filePath,value:value()}));assert.equal(fs.readFileSync(filePath,'utf8'),bytes);}
 fs.writeFileSync(filePath,original);fs.chmodSync(directory,0o755);assert.throws(()=>managed.load({filePath}));fs.chmodSync(directory,0o700);
});

test('closed managed schema rejects endpoint, mode, token and activation drift',()=>{
 const mutations=[v=>v.extra=true,v=>v.enabled='false',v=>v.architecture='amd64',v=>v.config.url='http://localhost:8090',v=>v.config.url='http://127.0.0.1:8090/',v=>v.config.container='foreign',v=>v.diagnostic.token=v.config.token,v=>v.restart.token=v.config.token,v=>v.diagnostic.url=v.config.url,v=>v.restart.url=v.diagnostic.url,v=>v.config.token='short',v=>v.profile.name='unconfined'];
 for(const mutate of mutations){const v=value();mutate(v);assert.throws(()=>managed.validate(v));}
 const v=value();v.enabled=true;assert.throws(()=>managed.stage({filePath:'/not-used',value:v}),{code:'SYSTEM_MANAGED_STAGE_INVALID'});
});

test('failed fsync before publication leaves no partial final or staging file',t=>{
 const{filePath,directory}=fixture(t);const original=fs.fsyncSync;
 try{fs.fsyncSync=()=>{throw Error('controlled disk failure');};assert.throws(()=>managed.stage({filePath,value:value()}));}
 finally{fs.fsyncSync=original;}
 assert.equal(fs.existsSync(filePath),false);assert.deepEqual(fs.readdirSync(directory),[]);
});

test('concurrent identical initial staging never replaces or truncates the winner',async t=>{
 const{filePath}=fixture(t);const modulePath=require.resolve('../server/services/secureshopSystemManagedConfiguration');
 const code="const fs=require('node:fs');const m=require(process.argv[1]);const r=m.stage(JSON.parse(fs.readFileSync(0,'utf8')));process.stdout.write(JSON.stringify(r));";
 const execute=()=>new Promise((resolve,reject)=>{const child=spawn(process.execPath,['-e',code,modulePath],{stdio:['pipe','pipe','pipe']});let output='',error='';child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>error+=v);child.on('error',reject);child.on('close',status=>status===0?resolve(JSON.parse(output)):reject(Error(error)));child.stdin.end(JSON.stringify({filePath,value:value()}));});
 const results=await Promise.all([execute(),execute(),execute()]);assert.equal(results.filter(r=>r.created).length,1);assert.deepEqual(managed.load({filePath}),value());assert.equal(fs.statSync(filePath).nlink,1);
});

async function planFixture(t){const {directory:home}=fixture(t);const id=workspaceId(root),directory=path.join(home,'.dvaia',id);fs.mkdirSync(directory,{recursive:true,mode:0o700});const authority={version:1,workspaceId:id,host:'unix:///tmp/owned-system-test.sock',daemonId:'controlled-daemon',source:'environment-host'};fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify(authority),{mode:0o600});const calls=[];const execute=async(file,args,options)=>{calls.push({file,args,options});assert.deepEqual(args,['--host',authority.host,'info','--format','{{json .ID}}']);return{stdout:JSON.stringify(authority.daemonId)};};return{home,id,directory,authority,calls,execute};}

test('plan verifies only recorded authority, reports ARM64 source binding and never exposes secrets or writes',async t=>{
 const f=await planFixture(t),before=fs.readdirSync(f.directory);const options={root,home:f.home,platform:'darwin',architecture:'arm64',execute:f.execute,environment:{DOCKER_HOST:'tcp://foreign',DOCKER_CONTEXT:'foreign'}};
 const p=await installer.plan(options);assert.equal(p.mutating,false);assert.equal(p.daemonIdentityVerified,true);assert.equal(p.imageRuntimeVerified,false);assert.equal(p.namespaceProfileVerified,false);assert.equal(p.dockerAuthoritySha256,authorityDigest(f.authority));assert.deepEqual(fs.readdirSync(f.directory),before);assert.equal(f.calls.length,1);assert.equal(f.calls[0].options.env.DOCKER_HOST,undefined);assert.equal(f.calls[0].options.env.DOCKER_CONTEXT,undefined);
 const v={...value(),workspaceId:f.id,dockerAuthoritySha256:p.dockerAuthoritySha256,sourceManifestSha256:p.source.sha256,profile:p.profile,config:{...p.config,token:'A'.repeat(43)},diagnostic:{...p.diagnostic,token:'B'.repeat(43)},restart:{...p.restart,token:'C'.repeat(43)}};managed.stage({filePath:p.managedPath,value:v});const bytes=fs.readFileSync(p.managedPath);const repeat=await installer.plan({...options,imageId:v.imageId});assert.equal(repeat.existing,true);assert.equal(repeat.imageId,v.imageId);assert.ok(!JSON.stringify(repeat).includes(v.config.token));assert.ok(!JSON.stringify(repeat).includes('token'));assert.deepEqual(fs.readFileSync(p.managedPath),bytes);
 await assert.rejects(installer.plan({...options,imageId:'sha256:'+'f'.repeat(64)}),{code:'SYSTEM_INSTALL_EXISTING_CONFLICT'});
 await assert.rejects(installer.plan({...options,configPort:8093}),{code:'SYSTEM_INSTALL_EXISTING_CONFLICT'});
 await assert.rejects(installer.plan({...options,architecture:'amd64'}),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});
 await assert.rejects(installer.plan({...options,execute:async()=>({stdout:'"other-daemon"'})}),{code:'LOCAL_DOCKER_AUTHORITY_INVALID'});
 fs.writeFileSync(path.join(f.directory,'local-docker.json'),JSON.stringify({...f.authority,host:'unix:///tmp/other-owned.sock'}));
 await assert.rejects(installer.plan({...options,execute:async()=>({stdout:JSON.stringify(f.authority.daemonId)})}),{code:'SYSTEM_INSTALL_EXISTING_CONFLICT'});
});

test('missing recorded authority never falls back to ambient Docker selection',async t=>{
 const f=await planFixture(t);fs.unlinkSync(path.join(f.directory,'local-docker.json'));let calls=0;
 await assert.rejects(installer.plan({root,home:f.home,platform:'darwin',architecture:'arm64',execute:async()=>{calls++;throw Error('must not execute');}}),{code:'SYSTEM_INSTALL_AUTHORITY_REQUIRED'});assert.equal(calls,0);
});

test('closed package manifest detects source tamper before any provisioning',t=>{
 const{directory}=fixture(t);const relative='sidecars/sandbox-runner/owned-system';fs.mkdirSync(path.join(directory,relative),{recursive:true});
 const original=JSON.parse(fs.readFileSync(path.join(root,relative,'local-package-manifest.json')));
 // Main package qualification stays read-only; tamper controls use synthetic data.
 assert.deepEqual(installer.sourceManifest(root).files,original.files);
 const synthetic={...original,files:{}};
 for(const file of Object.keys(original.files)){const bytes=Buffer.from('synthetic managed package: '+file+'\n');fs.mkdirSync(path.dirname(path.join(directory,relative,file)),{recursive:true});fs.writeFileSync(path.join(directory,relative,file),bytes);synthetic.files[file]=require('node:crypto').createHash('sha256').update(bytes).digest('hex');}
 fs.writeFileSync(path.join(directory,relative,'local-package-manifest.json'),JSON.stringify(synthetic));
 assert.equal(installer.sourceManifest(directory).fileCount,Object.keys(original.files).length);
 fs.appendFileSync(path.join(directory,relative,'diagnostic-init.c'),'\n/* tampered */');assert.throws(()=>installer.sourceManifest(directory),{code:'SYSTEM_PACKAGE_SOURCE_CHANGED'});
});


test('optional upload preview is closed, separately bound and preserves historical three-mode encoding',t=>{
 const legacy=value(),bytes=managed.encode(legacy);assert.equal(managed.encode(managed.validate(legacy)),bytes);
 const v={...legacy,uploadPreview:{container:`dvaia-owned-system-${legacy.workspaceId}-upload-preview`,url:'http://127.0.0.1:8093',token:'P'.repeat(43)}};
 const {filePath}=fixture(t);managed.stage({filePath,value:v});assert.deepEqual(managed.load({filePath}),v);
 assert.deepEqual(managed.modesFor(v),['config','diagnostic','restart','uploadPreview']);
 for(const mutate of [x=>x.uploadPreview.token=x.config.token,x=>x.uploadPreview.url=x.restart.url,x=>x.uploadPreview.extra=true,x=>x.uploadPreview.container+='-foreign']){
  const bad=structuredClone(v);mutate(bad);assert.throws(()=>managed.validate(bad));
 }
 const loader=require('../server/services/secureshopSystemManagedEnvironment');
 assert.equal(loader.getUploadPreviewClient({environment:{}}),null);
 assert.equal(loader.getUploadPreviewClient({environment:{SS_BOUND_UPLOAD_PREVIEW_ENABLED:'false'}}),null);
 assert.throws(()=>loader.getUploadPreviewClient({environment:{SS_BOUND_UPLOAD_PREVIEW_ENABLED:'yes'}}));
 const client=loader.getUploadPreviewClient({environment:{SS_BOUND_UPLOAD_PREVIEW_ENABLED:'true',SS_UPLOAD_PREVIEW_BASE_URL:v.uploadPreview.url,SS_UPLOAD_PREVIEW_TOKEN:v.uploadPreview.token}});
 assert.equal(typeof client.assertReady,'function');assert.equal(typeof client.preview,'function');
});
