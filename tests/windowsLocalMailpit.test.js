'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {MAILPIT_IMAGE,MAILPIT_IMAGE_VERSION,MAILPIT_IMAGE_DIGEST,createMailpitStateStorage,ensureLocalMailpit,assertLocalMailpitReady}=require('../scripts/local-mailpit');
const {authorityDigest}=require('../scripts/local-docker-authority');
const directory='C:\\Users\\Learner\\private',file=directory+'\\mailpit.json',intentFile=file+'.intent';
const authority={version:1,workspaceId:'fixture',host:'unix:///controlled',daemonId:'controlled-daemon'};
function initial(){return{version:1,id:'fixture',name:'owasp-ai-goat-mailpit-fixture',nonce:'c'.repeat(64),image:MAILPIT_IMAGE,imageVersion:MAILPIT_IMAGE_VERSION,imageDigest:MAILPIT_IMAGE_DIGEST,dockerAuthorityDigest:authorityDigest(authority),smtpPort:41025,apiPort:48025};}
const encode=value=>Buffer.from(JSON.stringify(value)+'\n');
function healthyRequest(_url,callback){const response=new EventEmitter();response.statusCode=200;process.nextTick(()=>{callback(response);response.emit('end');});return Object.assign(new EventEmitter(),{destroy(){}});}
function healthyConnect(){const socket=new EventEmitter();socket.setTimeout=()=>{};socket.destroy=()=>{};process.nextTick(()=>socket.emit('data',Buffer.from('220 controlled SMTP\r\n')));return socket;}
function fixture(state=initial()){
 const files=new Map(),operations=[],commands=[];if(state)files.set(file,encode(state));
 let container=null,denyRead=false,failPublication=null,runCount=0;
 const journal={
  inspectDestination({filePath}){operations.push(['inspect',filePath]);},
  readJournal({filePath}){operations.push(['read',filePath]);if(denyRead||!files.has(filePath))throw Object.assign(Error('native read denied'),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});return Buffer.from(files.get(filePath));},
  createJournal({filePath,bytes}){operations.push(['create',filePath,Buffer.from(bytes)]);if(files.has(filePath))throw Error('CREATE_NEW conflict');if(failPublication==='create'){failPublication=null;throw Error('publication failed');}files.set(filePath,Buffer.from(bytes));},
  updateJournal({filePath,originalBytes,resultBytes}){
   operations.push(['update',filePath,Buffer.from(originalBytes),Buffer.from(resultBytes)]);
   assert(files.get(filePath)?.equals(originalBytes),'exact prior bytes required');
   if(failPublication==='before'){failPublication=null;throw Error('publication failed');}
   files.set(filePath,Buffer.from(resultBytes));
   if(failPublication==='after'){failPublication=null;throw Error('publication acknowledgement lost');}
  },
 };
 const stateStorage=createMailpitStateStorage({filesystemPlatform:'win32',journal,exists:target=>files.has(target)});
 const containerFor=s=>({Id:'d'.repeat(64),Config:{Image:MAILPIT_IMAGE,Labels:{'org.owasp-ai-goat.workspace':'fixture','org.owasp-ai-goat.mailpit.nonce':s.nonce}},Image:MAILPIT_IMAGE_DIGEST,HostConfig:{PortBindings:{'1025/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.smtpPort)}],'8025/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.apiPort)}]}},State:{Running:true}});
 const execute=async(_command,args)=>{
  commands.push(args);
  if(args.includes('image'))return{stdout:JSON.stringify([{Id:MAILPIT_IMAGE_DIGEST,RepoDigests:[MAILPIT_IMAGE]}])};
  if(args.includes('inspect')){if(!container)throw Object.assign(Error('controlled absent'),{code:1});return{stdout:JSON.stringify([container])};}
  if(args.includes('run')){runCount++;container=containerFor(JSON.parse(files.get(file)));return{stdout:''};}
  if(args.includes('rm')){assert.equal(args.at(-1),container.Id);container=null;return{stdout:''};}
  return{stdout:''};
 };
 let port=41024;
 const options={directory,id:'fixture',stateStorage,execute,resolveAuthority:async()=>({authority,persisted:true}),writeAuthority:async()=>assert.fail('unexpected authority publication'),request:healthyRequest,connect:healthyConnect,allocatePort:async()=>++port,readinessAttempts:1,pullImage:false,wait:async()=>{}};
 return{files,operations,commands,options,containerFor,get container(){return container;},set container(value){container=value;},get runCount(){return runCount;},denyRead(){denyRead=true;},fail(value){failPublication=value;}};
}

test('controlled Windows fresh Mailpit creates state/intent and retains intent after exact update',async()=>{
 const f=fixture(null),result=await ensureLocalMailpit(f.options);
 assert.equal(result.containerId,'d'.repeat(64));assert.equal(f.files.has(intentFile),true);
 assert.equal(f.operations.filter(([op,p])=>op==='create'&&p===file).length,1);
 assert.equal(f.operations.filter(([op,p])=>op==='create'&&p===intentFile).length,1);
 const transition=f.operations.find(([op])=>op==='update');assert.equal(JSON.parse(transition[2]).containerId,undefined);assert.equal(JSON.parse(transition[3]).containerId,result.containerId);
});

test('controlled Windows failed readiness cleans only owned container and retries exact retained intent',async()=>{
 const f=fixture(),saved=f.files.get(file);f.options.request=(_url,callback)=>{const response=new EventEmitter();response.statusCode=503;process.nextTick(()=>{callback(response);response.emit('end');});return Object.assign(new EventEmitter(),{destroy(){}});};
 await assert.rejects(ensureLocalMailpit(f.options),/did not become ready/);assert.equal(f.container,null);assert.equal(f.files.has(intentFile),true);assert(f.files.get(file).equals(saved));
 const retained=Buffer.from(f.files.get(intentFile));f.options.request=healthyRequest;await ensureLocalMailpit(f.options);
 assert.equal(f.runCount,2);assert(f.files.get(intentFile).equals(retained));assert.equal(f.operations.filter(([op,p])=>op==='create'&&p===intentFile).length,1);
 const updates=f.operations.filter(([op])=>op==='update');assert.equal(JSON.parse(updates[1][2]).containerId,'d'.repeat(64));assert.equal(JSON.parse(updates[1][3]).containerId,undefined);
});

test('controlled Windows mismatching creation intent is retained and denies Docker run/cleanup',async()=>{
 const f=fixture(),bytes=encode({mismatch:'retained'});f.files.set(intentFile,bytes);
 await assert.rejects(ensureLocalMailpit(f.options),/intent does not match/);assert.equal(f.runCount,0);assert(f.files.get(intentFile).equals(bytes));assert.equal(f.commands.some(args=>args.includes('rm')),false);
});

test('controlled Windows denied existing initial/runtime reads never create or reach Docker authority',async()=>{
 const f=fixture();f.denyRead();let authorityCalls=0;f.options.resolveAuthority=async()=>{authorityCalls++;throw Error('must not resolve');};
 await assert.rejects(ensureLocalMailpit(f.options),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});
 await assert.rejects(assertLocalMailpitReady({...f.options,statePath:file}),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});
 assert.equal(authorityCalls,0);assert.equal(f.commands.length,0);assert.equal(f.operations.some(([op])=>op==='create'||op==='update'),false);
});

test('controlled Windows failed fresh publication never runs a container',async()=>{
 const f=fixture(null);f.fail('create');await assert.rejects(ensureLocalMailpit(f.options),/publication failed/);assert.equal(f.runCount,0);assert.equal(f.files.has(file),false);
});

test('controlled Windows failed update acknowledgment never advances cleanup original bytes',async()=>{
 for(const stage of ['before','after']){
  const f=fixture(),saved=Buffer.from(f.files.get(file));f.fail(stage);const error=await ensureLocalMailpit(f.options).catch(error=>error);
  assert.match(error.message,/publication/);assert.equal(f.container,null);const updates=f.operations.filter(([op])=>op==='update');assert(updates[0][2].equals(saved));assert(updates[1][2].equals(saved));
  assert.equal(f.files.has(intentFile),true);
  if(stage==='before')assert(f.files.get(file).equals(saved));
  else{assert.equal(error.cleanupError,'owned Mailpit cleanup failed');assert.equal(JSON.parse(f.files.get(file)).containerId,'d'.repeat(64));await assert.rejects(ensureLocalMailpit(f.options),/unavailable/);assert.equal(f.runCount,1);}
 }
});

test('controlled Windows runtime native state read retains container identity/readiness authority',async()=>{
 const f=fixture({...initial(),containerId:'d'.repeat(64)});f.container=f.containerFor(initial());
 const state=await assertLocalMailpitReady({...f.options,statePath:file});assert.equal(state.containerId,f.container.Id);assert.equal(f.operations.some(([op])=>op==='create'||op==='update'),false);
 f.container={...f.container,Id:'e'.repeat(64)};await assert.rejects(assertLocalMailpitReady({...f.options,statePath:file}),/identity changed/);
});

test('injected Windows Docker sidecar platform does not select native filesystem storage',async()=>{
 const folder=await fs.mkdtemp(path.join(os.tmpdir(),'mailpit-sidecar-platform-'));try{
  const f=fixture({...initial(),containerId:'d'.repeat(64)});f.container=f.containerFor(initial());const filename=path.join(folder,'mailpit.json');await fs.writeFile(filename,encode({...initial(),containerId:'d'.repeat(64)}),{mode:0o600});
  const {stateStorage,...options}=f.options;
  const value=await assertLocalMailpitReady({...options,platform:'win32',statePath:filename});assert.equal(value.containerId,'d'.repeat(64));assert.deepEqual(f.operations,[]);
 }finally{await fs.rm(folder,{recursive:true,force:true});}
});
