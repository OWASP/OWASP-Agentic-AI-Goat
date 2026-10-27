'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {provision,startExisting}=require('../scripts/install/secureshop-owned-system-provision');
const {workspaceId}=require('../scripts/application-data-root');
const {sourceManifest}=require('../scripts/install/secureshop-owned-system');
const managed=require('../server/services/secureshopSystemManagedConfiguration');
const {renderMcpSandboxAppArmor}=require('../scripts/render-mcp-sandbox-apparmor');
const ROOT=path.resolve(__dirname,'..'),BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',IMAGE='sha256:'+'a'.repeat(64);
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(t){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'system-provision-test-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const root=path.join(home,'checkout');fs.mkdirSync(root);
 // Only synthetic package data reaches the mocked Docker build.
 const relative='sidecars/sandbox-runner/owned-system',directory=path.join(root,relative);fs.mkdirSync(directory,{recursive:true});
 const manifest=JSON.parse(fs.readFileSync(path.join(ROOT,relative,'local-package-manifest.json'),'utf8'));
 for(const name of Object.keys(manifest.files)){const bytes=Buffer.from('synthetic controlled package: '+name+'\n');fs.mkdirSync(path.dirname(path.join(directory,name)),{recursive:true});fs.writeFileSync(path.join(directory,name),bytes);manifest.files[name]=hash(bytes);}
 fs.writeFileSync(path.join(directory,'local-package-manifest.json'),JSON.stringify(manifest));
 const apparmor=path.join(root,'sidecars/sandbox-runner/apparmor');fs.mkdirSync(apparmor,{recursive:true});fs.writeFileSync(path.join(apparmor,'dvaia-mcp-sandbox.apparmor.in'),'profile @@SUPERVISOR_PROFILE@@ { # synthetic controlled profile\n}\n');
 const id=workspaceId(root),dir=path.join(home,'.dvaia',id);fs.mkdirSync(dir,{recursive:true,mode:0o700});
 fs.writeFileSync(path.join(dir,'local-docker.json'),JSON.stringify({version:1,workspaceId:id,host:'unix:///var/run/docker.sock',daemonId:'controlled-daemon',source:'environment-host'}),{mode:0o600});
 const profileSha=hash(renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8'),'dvaia-mcp-sandbox'));
 const calls=[],envFiles=[],images=new Map([[BASE,{Id:BASE,Architecture:'arm64'}]]),networks=new Map(),volumes=new Map(),containers=new Map();
 const controls={unknownCreate:false,missingCreate:false,readiness:false,profileSha,profileExists:true,profileEnforced:true,buildHook:null};
 const labels=args=>Object.fromEntries(args.flatMap((x,i)=>x==='--label'?[args[i+1].split(/=(.*)/s).slice(0,2)]:[]));
 const inspect=(value,kind)=>value?{exitCode:0,stdout:JSON.stringify([value]),stderr:''}:{exitCode:1,stdout:'',stderr:kind==='volume'?'Error response from daemon: no such volume':'No such object'};
 const run=async(file,args,options)=>{
  calls.push({file,args:[...args],options});assert.ok(options.timeoutMs<=300000);assert.ok(options.maxOutputBytes<=1048576);
  if(file==='sudo'){if(args[1]==='test')return{exitCode:args[2]==='-L'||!controls.profileExists?1:0,stdout:''};if(args[1]==='stat')return{exitCode:0,stdout:'0:0:600:regular file'};if(args[1]==='sha256sum')return{exitCode:0,stdout:controls.profileSha+'  /etc/apparmor.d/dvaia-mcp-sandbox\n'};if(args[1]==='cp'){assert(args.includes('--no-clobber'));controls.profileExists=true;return{exitCode:0,stdout:''};}if(args[1]==='apparmor_parser'){if(args[2]==='-r')controls.profileEnforced=true;return{exitCode:0,stdout:''};}return{exitCode:0,stdout:controls.profileEnforced?'dvaia-mcp-sandbox (enforce)\n':'dvaia-mcp-sandbox (complain)\n'};}
  assert.equal(file,'docker');assert.deepEqual(args.slice(0,2),['--host','unix:///var/run/docker.sock']);args=args.slice(2);
  if(args[0]==='info')return{exitCode:0,stdout:'"controlled-daemon"'};
  if(args[1]==='inspect')return inspect(args[0]==='container'
   ? containers.get(args[2])||[...containers.values()].find(row=>row.Id===args[2])
   : ({image:images,network:networks,volume:volumes}[args[0]]).get(args[2]),args[0]);
  if(args[0]==='build'){
   const context=args.at(-1);assert.ok(context.startsWith(os.tmpdir())||context.startsWith(fs.realpathSync(os.tmpdir())));assert.equal(fs.statSync(context).mode&0o777,0o700);
   const manifest=JSON.parse(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-system/local-package-manifest.json')));
   for(const [name,digest]of Object.entries(manifest.files))assert.equal(hash(fs.readFileSync(path.join(context,name))),digest);
   controls.buildHook?.(context);
   const image={Id:IMAGE,Architecture:'arm64',Os:'linux',Config:{Labels:labels(args),User:'10001:10001',Env:['PATH=/usr/bin'],Entrypoint:['/usr/local/bin/node','/opt/dvaia-owned-system/local-listener-entry.js'],Cmd:null}};
   images.set(args[args.indexOf('-t')+1],image);images.set(IMAGE,image);return{exitCode:0,stdout:''};
  }
  if(args[0]==='volume'&&args[1]==='create'){volumes.set(args.at(-1),{Name:args.at(-1),Labels:labels(args)});return{exitCode:0,stdout:''};}
  if(args[0]==='network'&&args[1]==='create'){networks.set(args.at(-1),{Name:args.at(-1),Driver:'bridge',Internal:false,Labels:labels(args)});return{exitCode:0,stdout:''};}
  if(args[0]==='create'){
   assert.ok(managed.load({filePath:path.join(dir,managed.FILE)}),'disabled staging must precede first container');
   const name=args[args.indexOf('--name')+1],mode=args.at(-1),network=args[args.indexOf('--network')+1],envFile=args[args.indexOf('--env-file')+1];envFiles.push(envFile);assert.equal(fs.statSync(envFile).mode&0o777,0o600);
   const env=fs.readFileSync(envFile,'utf8').trim().split('\n');assert.ok(!args.join(' ').includes(env.find(x=>x.includes('_TOKEN=')).split('=')[1]));
   if(controls.missingCreate)throw Error('controlled uncertain create');
   const port=args[args.indexOf('--publish')+1].split(':')[1];
   let tmpfs={};for(let i=0;i<args.length;i++)if(args[i]==='--tmpfs'){const [mount,...options]=args[i+1].split(':');tmpfs[mount]=options.join(':');}if(mode==='restart')tmpfs=Object.fromEntries(Object.entries(tmpfs).reverse());
   const mountIndex=args.indexOf('--mount'),mount=mountIndex<0?[]:[{Type:'volume',Name:args[mountIndex+1].match(/source=([^,]+)/)[1],Destination:'/var/lib/dvaia-owned-restart',RW:true}];
   containers.set(name,{Id:({'config':'1','diagnostic':'2','restart':'3','upload-preview':'4'}[mode]).repeat(64),Name:'/'+name,Image:IMAGE,Mounts:mount,Config:{Labels:labels(args),User:'10001:10001',Entrypoint:images.get(IMAGE).Config.Entrypoint,Cmd:[mode],Env:['PATH=/usr/bin',...env]},State:{Running:false,Status:'created'},HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,Tmpfs:tmpfs,Binds:null,Devices:[],DeviceRequests:null,PidMode:'',IpcMode:'private',UsernsMode:'',CapAdd:null,SecurityOpt:['seccomp=unconfined','apparmor=dvaia-mcp-sandbox'],NetworkMode:network,PortBindings:{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}},NetworkSettings:{Networks:{[network]:{}},Ports:null}});
   if(controls.unknownCreate)throw Error('controlled lost create acknowledgment');return{exitCode:0,stdout:'id'};
  }
  if(args[0]==='start'){const c=containers.get(args[1])||[...containers.values()].find(row=>row.Id===args[1]);assert.ok(c);c.State.Running=true;c.State.Status='running';c.NetworkSettings.Ports=c.HostConfig.PortBindings;return{exitCode:0,stdout:''};}
  assert.fail('unexpected mutating Docker operation: '+args[0]);
 };
 const client=({token})=>({async assertReady(){assert.match(token,/^[A-Za-z0-9_-]{64}$/);if(controls.readiness)throw Error('controlled private failure');return true;},async health(){assert.match(token,/^[A-Za-z0-9_-]{64}$/);if(controls.readiness)throw Error('controlled private failure');return{ready:true};},async metrics(){return{ok:true,metricsSource:'owned-system-listener'};}});
 return{root,home,dir,id,calls,envFiles,images,networks,volumes,containers,controls,options:{root,home,platform:'linux',architecture:'arm64',run,createConfigClient:client,createDiagnosticClient:client,createRestartClient:client,createUploadPreviewClient:client}};
}

test('actual main System package still matches its exact checked-in manifest',()=>{const actual=sourceManifest(ROOT),manifest=JSON.parse(fs.readFileSync(path.join(ROOT,'sidecars/sandbox-runner/owned-system/local-package-manifest.json')));assert.deepEqual(actual.files,manifest.files);assert.equal(actual.baseImage,BASE);assert.equal(actual.fileCount,Object.keys(manifest.files).length);});

test('provision stages disabled tokens before create, verifies resources, and repeats without build/create/rotation',async t=>{
 const f=fixture(t);const result=await provision(f.options);assert.equal(result.ready,true);assert.equal(result.activationEnabled,false);assert.equal(result.staged,true);assert.ok(!JSON.stringify(result).includes('token'));
 const file=path.join(f.dir,managed.FILE),bytes=fs.readFileSync(file),v=managed.load({filePath:file});assert.equal(new Set([v.config.token,v.diagnostic.token,v.restart.token]).size,3);assert.equal(v.enabled,false);assert.equal(f.containers.size,3);assert.ok(f.envFiles.every(p=>!fs.existsSync(p)));
 const count=f.calls.length;await provision(f.options);assert.deepEqual(fs.readFileSync(file),bytes);const later=f.calls.slice(count).filter(c=>c.file==='docker').map(c=>c.args[2]);assert.ok(!later.includes('build')&&!later.includes('create')&&!later.includes('start'));
});

test('uncertain create reads same owned identity without duplicate or new bearer',async t=>{
 const f=fixture(t);f.controls.unknownCreate=true;await provision(f.options);assert.equal(f.calls.filter(c=>c.args[2]==='create').length,3);assert.equal(f.containers.size,3);assert.ok(f.envFiles.every(p=>!fs.existsSync(p)));
});

test('missing uncertain create and failed readiness retain disabled staging and remove only owned temporary secrets',async t=>{
 const f=fixture(t);f.controls.missingCreate=true;await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_CREATE_UNCERTAIN'});
 const file=path.join(f.dir,managed.FILE),bytes=fs.readFileSync(file);assert.equal(managed.load({filePath:file}).enabled,false);assert.ok(f.envFiles.every(p=>!fs.existsSync(p)));
 f.controls.missingCreate=false;f.controls.readiness=true;await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_READINESS_FAILED'});assert.deepEqual(fs.readFileSync(file),bytes);assert.ok(f.envFiles.every(p=>!fs.existsSync(p)));
 f.controls.readiness=false;await provision(f.options);assert.deepEqual(fs.readFileSync(file),bytes);
});

test('foreign mounts, image, namespace, port or token stop repeat without modifying containers',async t=>{
 for(const mutate of [c=>c.Mounts.push({Source:'/private'}),c=>c.Image='sha256:'+'f'.repeat(64),c=>c.HostConfig.NetworkMode='host',c=>c.HostConfig.PortBindings['8090/tcp'][0].HostIp='0.0.0.0',c=>c.Config.Env.push('NODE_OPTIONS=--require=/private')]){
  const f=fixture(t);await provision(f.options);mutate(f.containers.values().next().value);const before=JSON.stringify([...f.containers]),count=f.calls.length;await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_CONTAINER_CONFLICT'});assert.equal(JSON.stringify([...f.containers]),before);assert.ok(f.calls.slice(count).every(c=>c.file!=='docker'||['info','image','network','volume','container'].includes(c.args[2])));
 }
});

test('profile mismatch refuses before build or credential stage; image architecture drift refuses before create',async t=>{
 const f=fixture(t);f.controls.profileSha='f'.repeat(64);await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_PROFILE_CONFLICT'});assert.equal(fs.existsSync(path.join(f.dir,managed.FILE)),false);assert.ok(!f.calls.some(c=>c.args[2]==='build'));
 f.controls.profileSha=hash(renderMcpSandboxAppArmor(fs.readFileSync(path.join(f.root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),'utf8'),'dvaia-mcp-sandbox'));await provision(f.options);f.images.get(IMAGE).Architecture='amd64';await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_IMAGE_CONFLICT'});
});

test('clean explicit System provision prepares the exact shared profile before build; startExisting never repairs it',async t=>{
 const f=fixture(t);f.controls.profileExists=false;f.controls.profileEnforced=false;
 const result=await provision(f.options);assert.equal(result.ready,true);
 const install=f.calls.findIndex(c=>c.options.stage==='profile-install'),load=f.calls.findIndex(c=>c.options.stage==='profile-load'),build=f.calls.findIndex(c=>c.file==='docker'&&c.args[2]==='build');
 assert(install>=0&&load>install&&build>load);
 const activation=require('../scripts/install/secureshop-owned-system-activate');
 activation.activate({filePath:result.managedPath,expected:activation.capture(result.managedPath)});
 const before=f.calls.length;f.controls.profileExists=false;
 await assert.rejects(startExisting(f.options),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});
 assert(!f.calls.slice(before).some(c=>['profile-install','profile-load'].includes(c.options.stage)));
});

test('build reads frozen verified bytes even if live source changes during the bounded build',async t=>{
 const f=fixture(t);f.controls.buildHook=context=>{fs.appendFileSync(path.join(f.root,'sidecars/sandbox-runner/owned-system/diagnostic-init.c'),'\n/* concurrent source edit */');assert.notEqual(fs.readFileSync(path.join(context,'diagnostic-init.c'),'utf8'),fs.readFileSync(path.join(f.root,'sidecars/sandbox-runner/owned-system/diagnostic-init.c'),'utf8'));};
 const result=await provision(f.options);assert.equal(result.ready,true);await assert.rejects(provision(f.options),{code:'SYSTEM_PACKAGE_SOURCE_CHANGED'});
});


test('real bounded command runner joins timeout and output-overflow children without exposing output',async t=>{
 const {directory}=(()=>{const directory=fs.mkdtempSync(path.join(os.tmpdir(),'system-command-test-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));return{directory};})();
 const run=require('../scripts/install/secureshop-owned-system-provision')._internals.createRunner({cwd:directory,env:{PATH:process.env.PATH}});
 const result=await run(process.execPath,['-e','process.stdout.write("ready")'],{timeoutMs:2000,maxOutputBytes:1024});assert.equal(result.exitCode,0);assert.equal(result.stdout,'ready');
 await assert.rejects(run(process.execPath,['-e','setInterval(()=>{},1000)'],{timeoutMs:30,maxOutputBytes:1024}),error=>error.code==='SYSTEM_INSTALL_COMMAND_FAILED'&&!('stdout' in error));
 await assert.rejects(run(process.execPath,['-e','process.stdout.write("private".repeat(2000));setInterval(()=>{},1000)'],{timeoutMs:2000,maxOutputBytes:100}),error=>error.code==='SYSTEM_INSTALL_COMMAND_FAILED'&&!JSON.stringify(error).includes('private'));
});

test('provision copies only captured validated manifest keys, never a second unchecked async manifest read',async t=>{
 const f=fixture(t),fsp=require('node:fs/promises'),original=fsp.readFile;
 const captured=sourceManifest(f.root);assert.equal(Object.isFrozen(captured.files),true);
 let uncheckedReads=0;
 try{
  fsp.readFile=async function(file,...args){
   if(String(file).endsWith('/local-package-manifest.json')){
    uncheckedReads++;
    // A transient replacement presented to a second read must never become a
    // source pathname. Synchronous validation still sees the original file.
    return JSON.stringify({files:{'../../../../outside-private-file':'f'.repeat(64)}});
   }
   return original.call(this,file,...args);
  };
  await provision(f.options);
 }finally{fsp.readFile=original;}
 assert.equal(uncheckedReads,0);assert.ok(Object.keys(captured.files).every(name=>!name.includes('/')||['upload-preview-runtime/package.json','upload-preview-runtime/package-lock.json'].includes(name)));
});

test('enabled reconciliation is explicit and preserves image, containers and credentials',async t=>{
 const f=fixture(t);const result=await provision(f.options);
 const activation=require('../scripts/install/secureshop-owned-system-activate');
 activation.activate({filePath:result.managedPath,expected:activation.capture(result.managedPath)});
 const before=fs.readFileSync(result.managedPath);const count=f.calls.length;
 await assert.rejects(provision(f.options),{code:'SYSTEM_INSTALL_ALREADY_ACTIVE'});
 await provision({...f.options,reconcileEnabled:true});
 assert.deepEqual(fs.readFileSync(result.managedPath),before);
 assert.ok(!f.calls.slice(count).some(c=>c.file==='docker'&&['build','create','start'].includes(c.args[2])));
});

test('enabled System startup starts only validated retained container IDs',async t=>{
 const f=fixture(t),activation=require('../scripts/install/secureshop-owned-system-activate');
 const installed=await provision(f.options);
 activation.activate({filePath:installed.managedPath,expected:activation.capture(installed.managedPath)});
 const before=fs.readFileSync(installed.managedPath);
 for(const container of f.containers.values()){container.State={Running:false,Status:'exited'};container.NetworkSettings.Ports=null;}
 const offset=f.calls.length,result=await startExisting(f.options);
 assert.equal(result.ready,true);assert.equal(result.enabled,true);
 assert.deepEqual(result.containerIds,['1'.repeat(64),'2'.repeat(64),'3'.repeat(64)]);
 assert.deepEqual(f.calls.slice(offset).filter(c=>c.file==='docker'&&c.args[2]==='start').map(c=>c.args[3]),result.containerIds);
 assert.ok(!f.calls.slice(offset).some(c=>c.file==='docker'&&['build','create','rm','network create','volume create'].includes(c.args[2])));
 assert.deepEqual(fs.readFileSync(installed.managedPath),before);
});

test('System startup refuses invalid state and private replacement before first start',async t=>{
 const f=fixture(t),activation=require('../scripts/install/secureshop-owned-system-activate');
 const installed=await provision(f.options);
 activation.activate({filePath:installed.managedPath,expected:activation.capture(installed.managedPath)});
 const first=f.containers.values().next().value;
 first.State={Running:false,Status:'paused'};
 let offset=f.calls.length;
 await assert.rejects(startExisting(f.options),{code:'SYSTEM_START_CONTAINER_STATE'});
 assert.ok(!f.calls.slice(offset).some(c=>c.file==='docker'&&c.args[2]==='start'));
 first.State={Running:false,Status:'exited'};first.NetworkSettings.Ports=null;
 const replacement=path.join(f.dir,'local-docker.json.new'),authority=path.join(f.dir,'local-docker.json');
 const original=f.options.run;
 offset=f.calls.length;
 await assert.rejects(startExisting({...f.options,run:async(...args)=>{
  const result=await original(...args);
  if(args[0]==='docker'&&args[1][2]==='container'&&args[1][3]==='inspect'){
   fs.writeFileSync(replacement,fs.readFileSync(authority),{mode:0o600});fs.renameSync(replacement,authority);
  }
  return result;
 }}),{code:'SYSTEM_START_STATE_CHANGED'});
 assert.ok(!f.calls.slice(offset).some(c=>c.file==='docker'&&c.args[2]==='start'));
});


test('explicit preview provisioning has separate private bearer, bounded writable root and existing-only recovery',async t=>{
 const f=fixture(t);const options={...f.options,uploadPreviewPort:8093};
 const result=await provision(options);assert.deepEqual(result.readiness,{config:true,diagnostic:true,restart:true,uploadPreview:true});
 const file=path.join(f.dir,managed.FILE),record=managed.load({filePath:file}),before=fs.readFileSync(file);
 assert.equal(record.uploadPreview.container,`dvaia-owned-system-${f.id}-upload-preview`);
 assert.equal(f.containers.size,4);const container=f.containers.get(record.uploadPreview.container);
 assert.deepEqual(container.Config.Cmd,['upload-preview']);assert.equal(container.Mounts.length,0);
 assert.equal(container.HostConfig.Tmpfs['/var/lib/dvaia-owned-upload-preview'],'rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001');
 assert.equal(container.Config.Env.find(x=>x.startsWith('SECURESHOP_UPLOAD_PREVIEW_TOKEN=')),`SECURESHOP_UPLOAD_PREVIEW_TOKEN=${record.uploadPreview.token}`);
 await provision(options);assert.deepEqual(fs.readFileSync(file),before);
 fs.writeFileSync(file,managed.encode({...record,enabled:true}),{mode:0o600});
 const recovered=await startExisting(f.options);assert.equal(recovered.containerIds.length,4);
 container.HostConfig.Tmpfs['/var/lib/dvaia-owned-upload-preview']='rw,size=1g';
 await assert.rejects(startExisting(f.options),{code:'SYSTEM_INSTALL_CONTAINER_CONFLICT'});
});

test('V07 package receipt decoder requires every controlled native gate and exact ordered cases',()=>{
 const code=String.raw`
import ast,json,pathlib
source=pathlib.Path('tests/run-system-local-package-native-isolated.py').read_text()
tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_upload_preview_native')
space={};exec(compile(ast.Module(body=[node],type_ignores=[]),'controlled-decoder','exec'),space);validate=space[node.name]
runtime={'nodeVersion':'v26.10.0','platform':'linux','arch':'arm64'}
flags=['fullDecodeBounded','sameByteExecution','externalEffectObserved','freshCanaryPerOperation','fixedNoOriginalInterpreter','stdoutForgeryDenied','copiedMarkerDenied','unsafeFileDenied','fifoDenied','timeoutFenced','outputLimitFenced','cleanupEmpty']
names=['ordinary_gif','valid_dual_format_without_effect','same_stored_bytes_external_effect','fresh_unpredictable_external_effect','fixed_same_original_bytes','truncated','logical_dimensions','multiple_frames','stdout_cannot_create_external_effect','copied_marker_cannot_match_external_canary','bounded_original_interpreter_time','bounded_original_interpreter_output']
statuses=['image_only','executed','executed','executed','fixed_reencoded','invalid_image','invalid_image','invalid_image','executed','executed','failed','failed']
value={'version':1,'status':'passed','scope':'Actual ARM64 owned-system namespace full GIF decode, exact-byte Node preview and externally observed synthetic effect only; no graph, model, Judge or objective credit','controlled':True,'actualModel':False,'genuineCredit':False,'fullFlowQualified':False,'isolation':'bwrap-upload-preview-v1','runtime':runtime,'cases':[],**{key:True for key in flags}}
for index,(name,status) in enumerate(zip(names,statuses)):
 row={'status':status,'runtime':runtime,'isolation':value['isolation'],'requestSha256':'a'*64,'bodySha256':'b'*64,'workerAttested':True,'drained':True,'mode':'fixed' if index==4 else 'vuln','codeEffectObserved':index in [2,3],'originalInterpreterStarted':status in ['executed','failed'],'timedOut':index==10,'truncated':index==11,'effectSha256':('c' if index==2 else 'd')*64 if index in [2,3] else None,'scriptSyntaxValid':None if index==4 else True,'decoder':{'rawSha256':'e'*64},'reencoded':{'bodySha256':'f'*64} if index==4 else None}
 value['cases'].append({'id':name,'request':{'controlledDecoderOnly':True},'requestSha256':'a'*64,'bodySha256':'b'*64,'receipt':row})
assert validate(value) is value
mutations=[lambda v:v.update(fullFlowQualified=True),lambda v:v.update(extra=True),lambda v:v.update(fifoDenied=False),lambda v:v.update(fifoDenied=1),lambda v:v['runtime'].update(arch='x64'),lambda v:v['cases'].pop(),lambda v:v['cases'][4]['receipt'].update(originalInterpreterStarted=True),lambda v:v['cases'][3]['receipt'].update(effectSha256='c'*64),lambda v:v['cases'][2]['receipt'].update(codeEffectObserved=False),lambda v:v['cases'][1].update(requestSha256='0'*64)]
for mutate in mutations:
 bad=json.loads(json.dumps(value));mutate(bad)
 try:validate(bad)
 except (AssertionError,KeyError,TypeError):pass
 else:raise AssertionError('invalid controlled receipt accepted')
print(json.dumps({'controlled':True,'genuineCredit':False,'negatives':len(mutations)}))
`;
 const result=require('node:child_process').spawnSync('python3',['-B','-c',code],{cwd:ROOT,encoding:'utf8',timeout:10000});
 assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),{controlled:true,genuineCredit:false,negatives:10});
});

test('System dependency build CA is a private ephemeral BuildKit secret and never runtime configuration',async t=>{
 const f=fixture(t),ca=path.join(f.home,'trusted-build-ca.pem'),bytes=Buffer.from('-----BEGIN CERTIFICATE-----\ncontrolled CA bytes\n-----END CERTIFICATE-----\n');
 fs.writeFileSync(ca,bytes,{mode:0o600});
 await provision({...f.options,environment:{NODE_EXTRA_CA_CERTS:ca}});
 const command=f.calls.find(call=>call.args[2]==='build').args,secret=command[command.indexOf('--secret')+1];
 assert.match(secret,/^id=npm_ca,src=/);const temporary=secret.slice('id=npm_ca,src='.length);
 assert.equal(fs.existsSync(temporary),false);assert.deepEqual(fs.readFileSync(ca),bytes);
 for(const row of f.containers.values())assert.equal(row.Config.Env.some(value=>value.includes('CA_CERT')||value.includes('npm_ca')),false);
 const docker=fs.readFileSync(path.join(ROOT,'sidecars/sandbox-runner/owned-system/Dockerfile.local'),'utf8');
 const install=docker.indexOf('RUN --mount=type=secret,id=npm_ca'),source=docker.indexOf('COPY --chown=0:0 local-listener-entry.js');
 assert.ok(install>docker.indexOf('COPY --chown=0:0 upload-preview-runtime/package.json upload-preview-runtime/package-lock.json')&&source>install);
 assert.equal(docker.slice(install,source).includes('upload-preview-worker.js'),false);
 assert.match(docker,/RUN --mount=type=secret,id=npm_ca/);assert.match(docker,/NODE_EXTRA_CA_CERTS=\/run\/secrets\/npm_ca npm ci/);
 assert.doesNotMatch(docker,/strict-ssl=false|NODE_TLS_REJECT_UNAUTHORIZED|ENV .*CA_CERT|COPY .*npm.ca/);
});
