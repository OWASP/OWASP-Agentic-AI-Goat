'use strict';
// Controlled Docker/native providers: no daemon, PostgreSQL, or OS install.
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {createLocalPostgresSetup}=require('../scripts/setup-application');
const {createWindowsProvisioningJournal}=require('../scripts/lib/windows-provisioning-journal');
const {authorityDigest}=require('../scripts/local-docker-authority');
const directory='C:\\Users\\Synthetic\\private',id='fixture',name='dvaia-postgres-fixture',statePath=directory+'\\local-postgres.json',envPath=directory+'\\postgres-container.env';
const authority={version:1,workspaceId:id,host:'npipe:////./pipe/docker_engine',daemonId:'controlled-daemon',platform:'win32',source:'environment-host'};
const state=(version=2)=>({version,id,name,port:55432,password:'a'.repeat(64),...(version===2?{dockerAuthorityDigest:authorityDigest(authority)}:{})});
function fixture({initial=state(),existing=false,volume=true,passwordFile}={}){
 const files=new Map(initial?[[statePath,Buffer.from(JSON.stringify(initial))]]:[]),events=[],intents=new Map(),requests=[];if(passwordFile!==undefined)files.set(envPath,Buffer.from(passwordFile));let created=existing,denyRead=null,denyInspect=false,denyWrite=false,wrongVolume=false,wrongMount=false;
 const privateState={inspectPrivateDirectory:p=>{events.push(['privateDirectory',p]);assert.equal(p,directory);if(denyInspect)throw Error('SECRET denied');return{};},readPrivateFile:p=>{events.push(['privateRead',p]);if(denyRead===p||!files.has(p))throw Object.assign(Error('SECRET denied'),{code:'ENOENT'});return Buffer.from(files.get(p));}};
 const publication={preparePrivatePublication:options=>{
  requests.push(options);if(denyWrite)throw Error('SECRET write denied');const previous=files.get(options.targetPath);if(options.originalBytes===null?previous:!previous?.equals(options.originalBytes))throw Error('Unexpected bytes');
  const receipt={state:'prepared',intentSha256:crypto.createHash('sha256').update(options.intentPath).digest('hex'),size:options.resultBytes.length,identity:{volumeSerial:1,fileId:(intents.size+1).toString(16).padStart(16,'0')}};intents.set(options.intentPath,{options,receipt});return receipt;
 },publishPrivatePublication:binding=>{const intent=intents.get(binding.intentPath);assert(intent);files.set(binding.targetPath,Buffer.from(intent.options.resultBytes));return{...intent.receipt,state:'committed'};}};
 const privateJournal=createWindowsProvisioningJournal({platform:'win32',privateState,publication});
 const fileSystem=new Proxy({lstat:async p=>{events.push(['stat',p]);if(files.has(p))return{};throw Object.assign(Error('Missing'),{code:'ENOENT'});}}, {get(target,key){if(key in target)return target[key];return()=>{throw Error('Raw filesystem forbidden: '+String(key));};}});
 const tools={authorityDigest,assertPrivateDirectory(){throw Error('POSIX authority forbidden');},assertPrivateStateFile(){throw Error('POSIX authority forbidden');},resolveDockerAuthority:async options=>{events.push(['resolve',options.platform]);return{authority,persisted:true};},writeLocalDockerAuthority:async()=>events.push(['writeAuthority']),verifyDockerAuthority:async()=>events.push(['verify']),executeBoundDocker:async({args})=>{
  events.push(['docker',args]);if(args[0]==='volume'&&args[1]==='inspect'){if(!volume)throw Object.assign(Error('Absent'),{code:1});return{stdout:JSON.stringify([{Labels:{'org.dvaia.workspace':wrongVolume?'foreign':id}}])};}
  if(args[0]==='inspect'){if(!created)throw Object.assign(Error('Absent'),{code:1});const current=JSON.parse(files.get(statePath));return{stdout:JSON.stringify([{Config:{Labels:{'org.dvaia.workspace':id}},State:{Running:true},Mounts:[{Type:'volume',Name:wrongMount?'foreign':name,Destination:'/var/lib/postgresql'}],HostConfig:{PortBindings:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(current.port)}]}},NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(current.port)}]}}}])};}
  if(args[0]==='run'){created=true;return{stdout:name};}if(args[0]==='volume'&&args[1]==='create')return{stdout:name};if(args[0]==='exec')return{stdout:'ready'};throw Error('Unexpected controlled Docker command');
 }};
 const localPostgres=createLocalPostgresSetup({filesystemPlatform:'win32',fileSystem,privateState,privateJournal,authorityTools:tools,findAvailablePort:async()=>55432}).localPostgres;
 return{files,events,requests,intents,invoke:options=>localPostgres({directory,id,platform:'linux',environment:{},...options}),denyRead:p=>{denyRead=p;},denyInspect(){denyInspect=true;},denyWrite(){denyWrite=true;},wrongVolume(){wrongVolume=true;},wrongMount(){wrongMount=true;}};
}
const docker=f=>f.events.filter(([op])=>op==='docker').map(([,args])=>args);
test('Windows local PostgreSQL fresh state and env compose native create while sidecar platform remains separate',async()=>{
 const f=fixture({initial:null,volume:false});await f.invoke();const saved=JSON.parse(f.files.get(statePath));assert.equal(saved.version,2);assert.equal(saved.dockerAuthorityDigest,authorityDigest(authority));assert.equal(f.requests.length,2);assert(f.requests.every(r=>r.originalBytes===null));assert.deepEqual(f.files.get(envPath),Buffer.from('POSTGRES_PASSWORD='+saved.password+'\n'));assert(f.events.some(([op,platform])=>op==='resolve'&&platform==='linux'));
 const run=docker(f).find(args=>args[0]==='run');assert(run);assert.equal(run[run.indexOf('--env-file')+1],envPath);assert(!run.join(' ').includes(saved.password));assert(run.includes('127.0.0.1:55432:5432'));assert(run.includes('org.dvaia.workspace='+id));
});
test('Windows legacy state update retains exact original and does not rotate password or adopt foreign ownership',async()=>{
 const f=fixture({initial:state(1),existing:true}),original=Buffer.from(f.files.get(statePath));await f.invoke({existingOnly:true});assert.equal(f.requests.length,1);assert.deepEqual(f.requests[0].originalBytes,original);const saved=JSON.parse(f.files.get(statePath));assert.equal(saved.version,2);assert.equal(saved.password,state(1).password);assert.equal(f.intents.size,1);assert(!docker(f).some(args=>['run','start'].includes(args[0])));
 for(const mutate of [g=>g.wrongVolume(),g=>g.wrongMount()]){const g=fixture({initial:state(1),existing:true}),before=g.files.get(statePath);mutate(g);await assert.rejects(g.invoke());assert.equal(g.files.get(statePath),before);assert.equal(g.requests.length,0);}
});
test('Windows existing matching password env is natively read exactly before container recreation',async()=>{
 const expected='POSTGRES_PASSWORD='+state().password+'\n',f=fixture({passwordFile:expected});const before=f.files.get(envPath);await f.invoke({existingOnly:true});assert.equal(f.requests.length,0);assert.equal(f.files.get(envPath),before);assert(f.events.some(([op,p])=>op==='privateRead'&&p===envPath));assert.equal(docker(f).filter(args=>args[0]==='run').length,1);
});
test('Windows stale password env is rejected before docker run without replacing or deleting bytes',async()=>{
 for(const bytes of ['POSTGRES_PASSWORD=wrong\n','POSTGRES_PASSWORD='+state().password,'POSTGRES_PASSWORD='+state().password+'\nEXTRA=value\n']){
  const f=fixture({passwordFile:bytes}),before=f.files.get(envPath);await assert.rejects(f.invoke({existingOnly:true}),{code:'LOCAL_POSTGRES_PRIVATE_STATE_INVALID'});assert.equal(f.files.get(envPath),before);assert.equal(f.requests.length,0);assert(!docker(f).some(args=>args[0]==='run'));
 }
});
test('Windows denied existing state/env reads cannot become missing repair or credential rotation',async()=>{
 for(const target of [statePath,envPath]){const f=fixture({passwordFile:'POSTGRES_PASSWORD='+state().password+'\n'}),before=f.files.get(target);f.denyRead(target);await assert.rejects(f.invoke(),e=>e.code==='LOCAL_POSTGRES_PRIVATE_STATE_INVALID'&&!String(e.stack).includes('SECRET'));assert.equal(f.files.get(target),before);assert.equal(f.requests.length,0);assert(!docker(f).some(args=>args[0]==='run'));}
});
test('Windows malformed state and private-directory denial stop before Docker authority lookup',async()=>{
 for(const configure of [f=>f.files.set(statePath,Buffer.from('{partial')),f=>f.denyInspect()]){const f=fixture();configure(f);await assert.rejects(f.invoke());assert(!f.events.some(([op])=>op==='resolve'));assert.equal(f.requests.length,0);}
});
test('Windows missing existing-only state, mismatched daemon digest and unowned volume remain fail closed',async()=>{
 const missing=fixture({initial:null});await assert.rejects(missing.invoke({existingOnly:true}),/existing owned PostgreSQL state/);assert(!missing.events.some(([op])=>op==='resolve'));
 const mismatch=fixture({initial:{...state(),dockerAuthorityDigest:'0'.repeat(64)}});await assert.rejects(mismatch.invoke(),/different Docker authority/);assert.equal(mismatch.requests.length,0);assert(!docker(mismatch).some(args=>args[0]==='run'));
 const foreign=fixture();foreign.wrongVolume();await assert.rejects(foreign.invoke(),/unowned PostgreSQL volume/);assert.equal(foreign.requests.length,0);
});
test('Windows failed fresh/legacy native publication never performs mutating container commands',async()=>{
 for(const initial of [null,state(1)]){const f=fixture({initial,existing:initial!==null,volume:initial!==null}),before=f.files.get(statePath);f.denyWrite();await assert.rejects(f.invoke(),{code:'LOCAL_POSTGRES_PRIVATE_STATE_INVALID'});assert.equal(f.files.get(statePath),before);assert(!docker(f).some(args=>args[0]==='run'||args[0]==='start'||args[0]==='volume'&&args[1]==='create'));}
});
test('POSIX existing stale password file is rejected on EEXIST before docker run',async t=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'local-postgres-password-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));const passwordFile=path.join(dir,'postgres-container.env'),stateFile=path.join(dir,'local-postgres.json');await fs.writeFile(passwordFile,'POSTGRES_PASSWORD=stale\n',{mode:0o600});await fs.writeFile(stateFile,JSON.stringify(state()),{mode:0o600});const calls=[];
 const tools={authorityDigest,assertPrivateDirectory:async()=>{},assertPrivateStateFile:async p=>{assert.equal((await fs.stat(p)).mode&0o077,0);},resolveDockerAuthority:async()=>({authority,persisted:true}),verifyDockerAuthority:async()=>{},writeLocalDockerAuthority:async()=>{},executeBoundDocker:async({args})=>{calls.push(args);if(args[0]==='inspect')throw Object.assign(Error('Absent'),{code:1});if(args[0]==='volume')return{stdout:JSON.stringify([{Labels:{'org.dvaia.workspace':id}}])};throw Error('Docker run must not happen');}};
 const localPostgres=createLocalPostgresSetup({filesystemPlatform:process.platform,authorityTools:tools}).localPostgres;await assert.rejects(localPostgres({directory:dir,id,environment:{},platform:'win32'}),{code:'LOCAL_POSTGRES_PRIVATE_STATE_INVALID'});assert.equal(await fs.readFile(passwordFile,'utf8'),'POSTGRES_PASSWORD=stale\n');assert(!calls.some(args=>args[0]==='run'));
});
