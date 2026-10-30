'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream'),{execFileSync}=require('node:child_process');
const entry=require('./postgres/ownedSystemOriginalBrowserOwner'),I=entry._internals;
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
test('reviewed paired MAIN rejects malformed arguments and a forced closed gate precedes all reads',async()=>{
 assert.equal(entry.LIVE_ENABLED,true);
 await assert.rejects(I.main([]),{code:'SYSTEM_MAIN_ARGUMENTS'});
 await assert.rejects(I.main(['--arbitrary-command','/bin/sh']),{code:'SYSTEM_MAIN_ARGUMENTS'});
 const filename=path.join(__dirname,'postgres/ownedSystemOriginalBrowserOwner.js'),module={exports:{}};
 const original=await fs.readFile(filename,'utf8');assert.equal(original.split('const LIVE_ENABLED=true;').length,2);
 const source=original.replace('const LIVE_ENABLED=true;','const LIVE_ENABLED=false;');
 const local=require('node:module').createRequire(filename);
 vm.runInNewContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',
  {Buffer,AbortController,AbortSignal,performance,process,setTimeout,clearTimeout})(local,module,module.exports,filename,path.dirname(filename));
 let reads=0;const poison=new Proxy([], {get(){reads++;throw Error('unexpected');}});
 await assert.rejects(module.exports._internals.main(poison),{code:'V24_ORIGINAL_BROWSER_NOT_ADMITTED'});assert.equal(reads,0);
 module.exports.LIVE_ENABLED=true;
 await assert.rejects(module.exports.runOriginalSystemBrowser(poison),{code:'V24_ORIGINAL_BROWSER_NOT_ADMITTED'});assert.equal(reads,0);
});
test('MAIN grant has closed fields, original fixed timings and no endpoint/environment authority',()=>{
 const base=options(),{producer,signal,...values}=base;
 const grant={version:2,...values,recipe:{source:'controlled'},expectedPlanSha256:'a'.repeat(64),expectedProducerSha256:'b'.repeat(64),expectedDriverSha256:'c'.repeat(64)};
 const admitted=I.mainOptions(grant,signal,123);assert.equal(admitted.producer.buildDeadline,1800123);
 assert.equal(admitted.producer.signal,signal);assert.equal(admitted.pgNonce,base.pgNonce);
 for(const change of [{env:{}},{command:'sh'},{expectedPlanSha256:'bad'},{version:true},{version:1},{rendererAdmission:'/legacy/admission.json'},{root:'/other'}])
  assert.throws(()=>I.mainOptions({...grant,...change},signal));
});
test('MAIN result distinguishes clean semantic failure from missing child/producer retirement',()=>{
 const runId='a'.repeat(32),child=terminal(runId),driver={localCleanupVerified:true,remoteCleanupVerified:true,guestResourcesAbsent:true,sharedStateUnchanged:true,debts:[]};
 const ownerOutcome={childAttempted:true,childPacket:child,driverReceipt:driver};
 const passed=I.mainTerminal(runId,{ownerOutcome},null);assert.equal(passed.passed,true);assert.equal(passed.cleanupVerified,true);
 const cleanFailure=I.mainTerminal(runId,null,Object.assign(Error('semantic'),{ownerOutcome}));
 assert.equal(cleanFailure.passed,false);assert.equal(cleanFailure.cleanupVerified,true);assert.equal(cleanFailure.qualificationAccepted,false);
 for(const change of [{driverReceipt:null},{childPacket:null},{driverReceipt:{...driver,debts:['unjoined']}}]){
  const packet=I.mainTerminal(runId,null,Object.assign(Error('debt'),{ownerOutcome:{...ownerOutcome,...change}}));
  assert.equal(packet.cleanupVerified,false);assert.equal(packet.passed,false);
 }
 const noChild=I.mainTerminal(runId,null,Object.assign(Error('build'),{ownerOutcome:{childAttempted:false,childPacket:null,driverReceipt:driver}}));
 assert.equal(noChild.cleanupVerified,true);assert.equal(noChild.passed,false);
});
test('validation-only proof is process-local, run-bound, schema-closed and never inferred from a claimed phase',async()=>{
 const f=await controlled('browser-replaced');let error;
 try{await f.api._internals.runOriginal(f.options);}catch(e){error=e;}
 assert(error);assert(!f.events.includes('mkdir'));assert(!f.events.includes('producer'));
 const packet=f.api._internals.mainTerminal(f.options.runId,null,error);
 assert.equal(packet.version,2);assert.equal(packet.cleanupVerified,true);assert.equal(packet.passed,false);
 assert.equal(packet.failureCode,'SYSTEM_ORIGINAL_SOURCE');assert.equal(packet.driver,null);
 assert.deepEqual(Object.keys(packet).sort(),['version','runId','passed','childAttempted','child','driver','cleanupVerified','failure','failureCode','preallocation','qualificationAccepted'].sort());
 assert.equal(JSON.stringify(packet.preallocation),JSON.stringify({phase:'validation',ownerLocalAttempted:false,producerAttempted:false,childAttempted:false}));
 for(const bad of [Object.assign(Error('secret URL'),{code:'secret-token',preallocation:packet.preallocation}),
  Object.assign(Error('claimed'),{code:'SYSTEM_ORIGINAL_SOURCE',ownerOutcome:{phase:'validation',producerAttempted:false}})]){
  const rejected=f.api._internals.mainTerminal(f.options.runId,null,bad);
  assert.equal(rejected.cleanupVerified,false);assert.equal(rejected.preallocation,null);assert(!JSON.stringify(rejected).includes('secret'));
 }
 assert.equal(f.api._internals.mainTerminal('c'.repeat(32),null,error).preallocation,null);
 for(const fault of ['mkdir','test-failure','browser-debt']){
  const later=await controlled(fault);let failure;try{await later.api._internals.runOriginal(later.options);}catch(e){failure=e;}
  assert(failure);assert.equal(later.api._internals.mainTerminal(later.options.runId,null,failure).preallocation,null);
 }
 await assert.rejects(entry.preflightOriginalRuntime({...options(),command:'bad'}),{code:'SYSTEM_ORIGINAL_PREFLIGHT'});
});

async function runtimeFixture(){
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'v24-node-identity-'));
 const filename=path.join(__dirname,'postgres/ownedSystemOriginalBrowserOwner.js'),source=await fs.readFile(filename,'utf8');
 const node=path.join(directory,'tasks/runtime/node/node_modules/node/bin/node');
 const alias=path.join(directory,'tasks/runtime/node/node_modules/node/node_modules/node-bin-darwin-arm64/bin/node');
 await fs.mkdir(path.dirname(node),{recursive:true});await fs.mkdir(path.dirname(alias),{recursive:true});
 const bytes=Buffer.from('controlled executable identity\n');await fs.writeFile(node,bytes,{mode:0o755});await fs.link(node,alias);
 function load(io=fs){
  const module={exports:{}},local=require('node:module').createRequire(filename);
  vm.runInNewContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',
   {Buffer,AbortController,AbortSignal,Error,performance,process,setTimeout,clearTimeout})
   (id=>id==='node:fs/promises'?io:local(id),module,module.exports,path.join(directory,'tests/postgres/owner.js'),path.join(directory,'tests/postgres'));
  return module.exports._internals;
 }
 return {directory,node,alias,bytes,load,async close(){await fs.rm(directory,{recursive:true,force:true});}};
}
test('canonical runtime validator reads actual two hardlinks and rejects wrong paths, aliases, counts and permissions',async()=>{
 for(const fault of ['clean','single','third','copy','symlink','writable','wrong-path','content']){
  const f=await runtimeFixture();try{
   if(['single','copy','symlink'].includes(fault))await fs.unlink(f.alias);
   if(fault==='copy')await fs.writeFile(f.alias,f.bytes,{mode:0o755});
   if(fault==='symlink')await fs.symlink(f.node,f.alias);
   if(fault==='third')await fs.link(f.node,path.join(f.directory,'unexpected-link'));
   if(fault==='writable')await fs.chmod(f.node,0o777);
   if(fault==='content')await fs.writeFile(f.node,'changed');
   const work=f.load().nodeRuntimeHash(fault==='wrong-path'?f.alias:f.node);
   if(fault==='clean')assert.equal(await work,sha(f.bytes));
   else if(fault==='content')assert.notEqual(await work,sha(f.bytes));
   else await assert.rejects(work);
  }finally{await f.close();}
 }
});
test('runtime stable descriptors reject actual alias replacement or mutation during bounded reads',async()=>{
 for(const fault of ['rename','mutate','mode']){
  const f=await runtimeFixture();try{
   let changed=false;
   const io={...fs,open:async(...args)=>{
    const fd=await fs.open(...args);if(args[0]!==f.node)return fd;
    return {stat:()=>fd.stat(),close:()=>fd.close(),read:async(...readArgs)=>{
     const value=await fd.read(...readArgs);
     if(!changed){changed=true;
      if(fault==='rename'){await fs.rename(f.alias,f.alias+'.old');await fs.writeFile(f.alias,f.bytes,{mode:0o755});}
      if(fault==='mutate')await fs.writeFile(f.alias,Buffer.alloc(f.bytes.length,65));
      if(fault==='mode')await fs.chmod(f.alias,0o777);
     }return value;
    }};
   }};
   await assert.rejects(f.load(io).nodeRuntimeHash(f.node),{code:'SYSTEM_ORIGINAL_NODE_CHANGED'});
  }finally{await f.close();}
 }
});
test('actual emitted Python applies same canonical two-link runtime policy and leaves sources strict',async()=>{
 const f=await runtimeFixture();try{
  const conf={root:f.directory,node:f.node};
  const checks=String.raw`
fingerprint(CONF['node'],EXPECTED)
try:fingerprint(ALIAS,EXPECTED);raise AssertionError('source links accepted')
except RuntimeError:pass
os.link(ALIAS,ALIAS+'.third')
try:fingerprint(CONF['node'],EXPECTED);raise AssertionError('third link accepted')
except RuntimeError:pass
os.unlink(ALIAS+'.third')
os.chmod(CONF['node'],0o777)
try:fingerprint(CONF['node'],EXPECTED);raise AssertionError('writable runtime accepted')
except RuntimeError:pass
os.chmod(CONF['node'],0o755)
original_read=os.read
changed=[False]
def mutate_read(fd,size):
 data=original_read(fd,size)
 if not changed[0]:
  changed[0]=True
  with open(ALIAS,'r+b') as f:f.write(b'changed')
 return data
os.read=mutate_read
try:fingerprint(CONF['node'],EXPECTED);raise AssertionError('concurrent mutation accepted')
except RuntimeError:pass
os.read=original_read
os.rename(ALIAS,ALIAS+'.old')
with open(ALIAS,'wb') as f:f.write(b'replacement')
try:fingerprint(CONF['node'],EXPECTED);raise AssertionError('replaced alias accepted')
except RuntimeError:pass
os.unlink(ALIAS)
os.symlink(CONF['node'],ALIAS)
try:fingerprint(CONF['node'],EXPECTED);raise AssertionError('symlink alias accepted')
except RuntimeError:pass
print('runtime-hardlinks-checked')
`;
  const source='CONF='+JSON.stringify(conf)+'\nEXPECTED='+JSON.stringify(sha(f.bytes))+'\nALIAS='+JSON.stringify(f.alias)+'\n'+I.CONTROLLER+'\n'+checks;
  assert.equal(execFileSync('/opt/homebrew/bin/python3',['-B','-c',source],{cwd:I.ROOT,timeout:10000,maxBuffer:16384,
   env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}}).toString().trim(),'runtime-hardlinks-checked');
 }finally{await f.close();}
});
test('actual fixed CLI reads canonical private grant and atomically publishes only closed terminal bytes under VM-only admission',async()=>{
 const filename=path.join(__dirname,'postgres/ownedSystemOriginalBrowserOwner.js');
 const original=await fs.readFile(filename,'utf8');
 for(const fault of ['clean','semantic','debt','duplicate','foreign-input','terminal-close','terminal-link','terminal-dir-sync']){
  const value=options(),{signal,producer,...base}=value;
  const grant={version:2,...base,recipe:{controlled:true},expectedPlanSha256:'a'.repeat(64),expectedProducerSha256:'b'.repeat(64),expectedDriverSha256:'c'.repeat(64)};
  const directory=I.ROOT+'/tasks/qualification/run-controlled',input=directory+'/v24-owner-input.json',output=directory+'/v24-owner-terminal.json';
  const files=new Map([[input,Buffer.from(JSON.stringify(grant)+'\n')]]),events=[];
  if(fault==='duplicate')files.set(input,Buffer.from(JSON.stringify(grant).replace('"version":2','"version":2,"version":2')+'\n'));
  const info=name=>({isFile:()=>true,uid:501,mode:0o100600,nlink:1,size:files.get(name)?.length||0,dev:1,ino:1,mtimeMs:2,ctimeMs:3});
  const io={realpath:async p=>p,lstat:async p=>p===directory?{isDirectory:()=>true,uid:501,mode:0o40700}:info(p),
   open:async(name,flags)=>{
    if(flags==='wx'){assert(!files.has(name));files.set(name,Buffer.alloc(0));events.push('partial-open');}
    return {stat:async()=>info(name),read:async b=>{const raw=files.get(name);raw.copy(b);return {bytesRead:raw.length};},
     writeFile:async b=>{files.set(name,Buffer.from(b));events.push('write');},
     sync:async()=>{events.push(name===directory?'dir-sync':'file-sync');if(name===directory&&fault==='terminal-dir-sync')throw Error('sync');},
     close:async()=>{events.push('close');if(name===output+'.partial'&&fault==='terminal-close')throw Error('close');}};
   },link:async(from,to)=>{events.push('link');if(fault==='terminal-link')throw Error('collision');assert(!files.has(to));files.set(to,files.get(from));},
   unlink:async name=>{events.push('unlink');files.delete(name);}};
  const proc=new EventEmitter();proc.getuid=()=>501;
  let runs=0;
  const controlledRun=async opts=>{
   runs++;assert.equal(opts.runId,value.runId);assert(opts.producer.buildDeadline>performance.now());
   const driver={localCleanupVerified:true,remoteCleanupVerified:true,guestResourcesAbsent:true,sharedStateUnchanged:true,debts:[]};
   const ownerOutcome={childAttempted:true,childPacket:terminal(value.runId),driverReceipt:driver};
   if(fault==='debt')ownerOutcome.driverReceipt=null;
   if(['semantic','debt'].includes(fault))throw Object.assign(Error('controlled'),{ownerOutcome});
   return {ownerOutcome};
  };
  const module={exports:{}};
  const source=original.replace('return runOriginal(options);','return controlledRun(options);');
  vm.runInNewContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',{
   Buffer,AbortController,AbortSignal,Error,AggregateError,performance,process:proc,controlledRun,setTimeout,clearTimeout
  })(id=>id==='node:fs/promises'?io:require(id.startsWith('./')?path.join(path.dirname(filename),id):id),module,module.exports,filename,path.dirname(filename));
  const work=module.exports._internals.main(['--owned-main-input',fault==='foreign-input'?'/outside/grant.json':input]);
  if(['duplicate','foreign-input','terminal-close','terminal-link','terminal-dir-sync'].includes(fault))await assert.rejects(work);
  else{
   assert.equal(await work,fault==='clean'?0:fault==='semantic'?1:2);
   const packet=JSON.parse(files.get(output));assert.equal(packet.passed,fault==='clean');
   assert.equal(packet.cleanupVerified,fault!=='debt');assert.equal(packet.qualificationAccepted,false);
   assert(events.indexOf('file-sync')<events.indexOf('link'));assert(events.indexOf('close')<events.indexOf('link'));
  }
  if(['duplicate','foreign-input'].includes(fault))assert.equal(runs,0);
  if(fault==='terminal-close')assert(!files.has(output));
  assert.equal(proc.listenerCount('SIGINT'),0);assert.equal(proc.listenerCount('SIGTERM'),0);
 }
});
function options(){return {root:I.ROOT,runId:'a'.repeat(32),producer:{root:I.ROOT,runId:'a'.repeat(32)},signal:new AbortController().signal,
 node:I.ROOT+'/tasks/runtime/node/node_modules/node/bin/node',nodeSha256:sha('node'),pythonSha256:sha('python'),
 browser:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',browserSha256:sha('browser'),pgNonce:'b'.repeat(12),pgPort:15432,
 policyVersion:'configuration-readability-relative-v3'};}
function endpoint(signal){return {system:{client:{},port:18090,baseURL:'http://127.0.0.1:18090',token:'t'.repeat(43)},
 policy:{client:{},port:18091,baseURL:'http://127.0.0.1:18091'},
 signal:signal||new AbortController().signal,deadline:performance.now()+900000};}
function terminal(runId='a'.repeat(32)){return {version:1,runId,exitCode:0,child:{pid:42,birth:[123,456],reaped:true,
 groupAbsent:true,browserProcessesAbsent:true,profilesAbsent:true,errors:[]},cleanupVerified:true,failure:null,
 browser:{pid:43,birth:[124,123],pgid:43,workerPid:44,profilePath:I.locations({runId}).temporary+'/owasp-ai-goat-role-policy-instruction-abc123',birthSha256:sha('birth'),acknowledged:true,groupAbsent:true,processAbsent:true,profileAbsent:true,errors:[]},
 tap:{bytes:0,sha256:sha('')}};}
function tapHandle(bytes=Buffer.alloc(0)){
 return {fd:2,stat:async()=>({isFile:()=>true,nlink:1,size:bytes.length,dev:1,ino:2,mtimeMs:3,ctimeMs:4}),
  read:async(buffer,start,length,position)=>{const part=bytes.subarray(position,position+length);part.copy(buffer,start);return {bytesRead:part.length};}};
}
test('reviewed native owner rejects malformed options before source reads, build or child effects',async()=>{
 assert.equal(entry.LIVE_ENABLED,true);
 await assert.rejects(entry.runOriginalSystemBrowser({}),{code:'SYSTEM_ORIGINAL_OPTIONS'});
 await assert.rejects(I.runOriginal({}),{code:'SYSTEM_ORIGINAL_OPTIONS'});
});
test('fixed child environment preserves only original V24 selector, four stores, model and renderer inputs; no inherited overrides',()=>{
 const value=options(),env=I.childEnvironment(value,endpoint());
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE,'1');assert.equal(env.JUDGE_PROVIDER,'ollama');
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_VERSION,'configuration-readability-relative-v3');
 const v4=I.childEnvironment({...value,policyVersion:'configuration-readability-token-contrast-v4'},endpoint());
 assert.equal(v4.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_VERSION,'configuration-readability-token-contrast-v4');
 for(const policyVersion of ['',undefined,'unknown'])
  assert.throws(()=>I.validateOptions({...value,policyVersion}),{code:'SYSTEM_ORIGINAL_OPTIONS'});
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX,'1');
 assert.equal(env.MAC_CHROMIUM_TMPDIR,I.locations(value).temporary);
 assert.equal(I.LIMITS.tap,8*1024**2);
 assert.equal(env.OLLAMA_MODEL,'llama3.1:8b');assert.equal(env.LAB_MODE,'vuln');
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_ADMISSION,undefined);
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_RENDERER_TRANSPORT,'owned-pair-v1');
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_URL,'http://127.0.0.1:18091');
 assert.equal(env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_SYSTEM_TOKEN,'t'.repeat(43));
 assert.equal(env.PUPPETEER_EXECUTABLE_PATH,'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
 assert.equal(Object.keys(env).filter(k=>k.startsWith('PG_SECURESHOP_POLICY_INSTRUCTION_BROWSER_')).length,8);
 assert.equal(env.PG_SECURESHOP_POLICY_INSTRUCTION_BROWSER_COMMERCE_RUNTIME_URL,
  'postgresql://dvaia_secureshop_runtime@127.0.0.1:15432/owasp_ai_goat_test_agent_host_bbbbbbbbbbbb_secureshop');
 assert(!('NODE_OPTIONS' in env));assert(!('HTTPS_PROXY' in env));assert(!('DOCKER_HOST' in env));
 assert.equal(Object.keys(env).filter(k=>k.endsWith('_NATIVE')).length,1);
 for(const mutate of [v=>v.env={},v=>v.command='/bin/sh',v=>v.pgPort=true,v=>v.pgNonce='app',v=>v.node='/usr/bin/node',
  v=>v.node=I.ROOT+'/tasks/arbitrary-program',v=>v.rendererAdmission='/tmp/admission.json',v=>v.producer.runId='c'.repeat(32),
  v=>v.browser=I.ROOT+'/tasks/runtime/browser/chrome',v=>v.browser='/Applications/Chromium.app/Contents/MacOS/Chromium',
  v=>v.browser='/Applications/Google Chrome.app/Contents/MacOS/../MacOS/Google Chrome']){
  const v=options();mutate(v);assert.throws(()=>I.validateOptions(v),{code:'SYSTEM_ORIGINAL_OPTIONS'});
 }
 for(const mutate of [e=>e.system.baseURL='http://example.com:18090',e=>e.system.baseURL='http://127.0.0.1:99999',e=>e.system.token='bad',
  e=>e.policy.baseURL=e.system.baseURL,e=>e.policy.port=18090,e=>e.policy.token='foreign',
  e=>e.system.baseURL='http://127.0.0.1:18090/',e=>e.system.baseURL={toString(){throw Error('not a string');}},
  e=>e.deadline=NaN,e=>e.deadline=performance.now()+901000,e=>e.deadline=0,e=>e.extra=true]){
  const e=endpoint();mutate(e);assert.throws(()=>I.childEnvironment(value,e),{code:'SYSTEM_ORIGINAL_ENDPOINT'});
 }
});
test('terminal evidence never equates child exit with browser/profile retirement or accepts unknown keys',()=>{
 assert.equal(I.validateTerminal(terminal(),'a'.repeat(32)).cleanupVerified,true);
 for(const mutate of [v=>v.child.browserProcessesAbsent=false,v=>v.child.profilesAbsent=false,v=>v.child.groupAbsent=false,
  v=>v.child.reaped=false,v=>v.child.errors.push('CHILD_WAIT_UNPROVEN'),v=>v.child.pid=null,v=>v.exitCode=1,
  v=>v.cleanupVerified=1,v=>v.extra='secret',v=>v.tap.bytes=I.LIMITS.tap+1,v=>v.runId='f'.repeat(32),
  v=>v.browser=null,v=>v.browser.acknowledged=false,v=>v.browser.groupAbsent=false,v=>v.browser.processAbsent=false,
  v=>v.browser.profileAbsent=false,v=>v.browser.birth=[1,1000000],v=>v.browser.pgid=99,v=>v.browser.pid=42,
  v=>v.browser.birthSha256='bad',v=>v.browser.profilePath='/tmp/foreign']){
  const v=terminal();mutate(v);assert.throws(()=>I.validateTerminal(v,'a'.repeat(32)),{code:'SYSTEM_ORIGINAL_TERMINAL'});
 }
 const debt=terminal();debt.child.browserProcessesAbsent=false;debt.cleanupVerified=false;
 assert.equal(I.validateTerminal(debt,'a'.repeat(32)).cleanupVerified,false);
});

async function controlled(fault='',clock=performance){
 const filename=path.join(__dirname,'postgres/ownedSystemOriginalBrowserOwner.js');let source=await fs.readFile(filename,'utf8');
 const value=options(),events=[],files=new Map(),handles=new Map(),timers=[];let nextFd=10,child,callbackSettled=false,releaseValidationClose;
 const firstSource=path.join(I.ROOT,Object.keys(I.PINS)[0]);
 const closeTarget=fault.startsWith('source-')?firstSource:fault.startsWith('browser-close')?value.browser:null;
 for(const name of Object.keys(I.PINS))files.set(path.join(I.ROOT,name),await fs.readFile(path.join(I.ROOT,name)));
 {
  // Controlled lifecycle composition uses the actual current fixture bytes.
  // This VM-only binding cannot enable the imported production owner; the
  // separate source-pinned caller test still enforces its literal PINS.
  const pins=Object.fromEntries(Object.keys(I.PINS).map(name=>[name,sha(files.get(path.join(I.ROOT,name)))]));
  const current=source.replace(/const PINS=Object\.freeze\(\{[\s\S]*?\}\);/,'const PINS=Object.freeze('+JSON.stringify(pins)+');');
  assert.notEqual(current,source);source=current;
 }
 files.set(value.node,Buffer.from('node'));files.set(I.NODE_PACKAGE,Buffer.from('node'));files.set(value.browser,Buffer.from('browser'));
 files.set('/opt/homebrew/bin/python3',Buffer.from('python'));
 if(fault==='browser-replaced')files.set(value.browser,Buffer.from('different existing browser bytes'));
 const stat=(bytes,p)=>({isFile:()=>true,nlink:[value.node,I.NODE_PACKAGE].includes(p)?2:1,size:bytes.length,dev:1,ino:2,mtimeMs:3,ctimeMs:4,uid:process.getuid(),gid:process.getgid(),mode:0o100755});
 const io={realpath:async p=>p,lstat:async p=>stat(files.get(p),p),mkdir:async p=>{events.push('mkdir');if(fault==='mkdir')throw Error('mkdir failed');},
  async open(p,flags){
   if(!files.has(p))files.set(p,Buffer.alloc(0));let offset=0;const fd=nextFd++;handles.set(fd,p);
   return {fd,stat:async()=>stat(files.get(p),p),read:async(buffer,start,length)=>{
    if(fault==='source-primary-close'&&p===firstSource)throw Object.assign(Error('first read failure'),{code:'SYSTEM_ORIGINAL_CHANGED'});
    const bytes=files.get(p).subarray(offset,offset+length);bytes.copy(buffer,start);offset+=bytes.length;return {bytesRead:bytes.length};},
    sync:async()=>{events.push('sync');},close:async()=>{
     events.push('close-file');
     if(closeTarget===p){
      events.push('validation-close');
      if(fault.endsWith('-pending'))return new Promise(resolve=>{releaseValidationClose=resolve;});
      throw Object.assign(Error('validation descriptor close failure'),{code:'CONTROLLED_CLOSE'});
     }
     if(fault==='file-close'&&/\/(original\.tap|owner\.ndjson)$/.test(p)){events.push('close-output');throw Error('controlled close failure');}
    }};
  }};
 const native={constants:require('node:fs').constants,writeFileSync(fd,data){
  if(fault==='intent-fsync')throw Error('controlled journal failure');
  const p=handles.get(fd);if(p)files.set(p,Buffer.concat([files.get(p),Buffer.from(data)]));events.push('journal');},
  fsyncSync(){events.push('fsync');}};
 const spawn=(executable,args,settings)=>{
  events.push('spawn');assert.equal(executable,'/opt/homebrew/bin/python3');assert.deepEqual(Array.from(args.slice(0,2)),['-B','-c']);
  assert.equal(settings.cwd,I.ROOT);assert(!('SECURESHOP_POLICY_INSTRUCTION_BROWSER_SYSTEM_TOKEN' in settings.env));
  assert(!args.join(' ').includes('t'.repeat(43)));
  child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();
  child.exitCode=fault==='exited-unclosed'?0:null;child.signalCode=null;
  child.kill=sig=>{events.push('signal-'+sig);if(fault==='abort-retired'||fault==='deadline-retired')queueMicrotask(()=>{
   const row=terminal();row.exitCode=-15;row.failure='INTERRUPTED';child.exitCode=1;child.stdout.write(JSON.stringify(row));child.emit('close',1,null);
  });return true;};child.unref=()=>events.push('unref');
  let input=Buffer.alloc(0);child.stdin.on('data',data=>{events.push('input');input=Buffer.concat([input,data]);});
  child.stdin.on('finish',()=>{
   events.push('input-finished');events.push('remaining:'+JSON.parse(input).remainingMs);
   const request=JSON.parse(input);assert(request.remainingMs>0&&request.remainingMs<=900000);
   const conf=JSON.parse(JSON.parse(/CONF=json.loads\(([^\n]+)\)\n/.exec(args[2])[1]));
   const canonical=JSON.stringify(Object.fromEntries(Object.entries(request.env).sort(([a],[b])=>a<b?-1:a>b?1:0)));
   assert.equal(sha(canonical),conf.environmentSha256);
   assert.deepEqual(Object.keys(request.env).sort(),conf.environmentKeys.sort());
   assert.equal(request.env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_SYSTEM_TOKEN,'t'.repeat(43));
   assert.equal(request.env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_URL,'http://127.0.0.1:18091');
   assert.equal(request.env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_RENDERER_TRANSPORT,'owned-pair-v1');
   assert(!('SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_ADMISSION' in request.env));
   if(['exited-unclosed','abort-retired','deadline-retired','live-unclosed','pipe-error'].includes(fault)){
    if(fault==='pipe-error')queueMicrotask(()=>child.stdin.emit('error',Object.assign(Error('controlled pipe failure'),{code:'CONTROLLED_PIPE'})));
    return;
   }
   queueMicrotask(()=>{const packet=terminal();
    if(fault==='browser-debt'){packet.child.browserProcessesAbsent=false;packet.cleanupVerified=false;}
    if(fault==='test-failure'){packet.exitCode=1;packet.failure='ORIGINAL_TEST_FAILED';}
    if(fault==='tap-mismatch')packet.tap.sha256=sha('not the actual retained bytes');
    child.exitCode=fault==='browser-debt'?2:['test-failure','controller-status'].includes(fault)?1:0;
    child.stdout.write(JSON.stringify(packet));child.emit('close',child.exitCode,null);
   });
  });
  if(fault!=='manual-ready')queueMicrotask(()=>child.stdout.write(JSON.stringify({version:1,stage:'ready',runId:value.runId})+'\n'));
  return child;
 };
 const adapter={async withPrivateSystemAndPolicyImages(_opts,callback){
  events.push('producer');const signal=_opts.signal;
  if(['producer-diagnostic','producer-diagnostic-bounds','producer-diagnostic-depth','producer-diagnostic-nested-cleanup'].includes(fault)){
   const binding=Object.assign(Error('private bearer must not appear'),{code:'SYSTEM_BINDING'});
   const relay=Object.assign(Error('private relay credential must not appear'),{code:'SYSTEM_BRIDGE_RETIREMENT_UNPROVEN'});
   const cleanup=fault==='producer-diagnostic-bounds'?[relay,...Array.from({length:6},()=>Object.assign(Error('private cleanup'),{code:'untrusted-secret-code'}))]:[relay];
   const error=Object.assign(new AggregateError([binding,...cleanup],'private producer detail'),
    {code:'SYSTEM_PRODUCER_FAILED',primary:binding,cleanupErrors:cleanup,retirementUnproven:true});
   if(fault==='producer-diagnostic-bounds'){
    binding.primary=binding;error.privateToken='secret-token';
    Object.defineProperty(error,'message',{get(){throw Error('message getter must not run');}});
   }
   if(fault==='producer-diagnostic-depth'){
    let nested=binding;
    for(let i=0;i<6;i++)nested={code:'SYSTEM_CONSUMER_FAILED',primary:nested};
    error.primary=nested;
   }
   if(fault==='producer-diagnostic-nested-cleanup'){
    error.cleanupErrors=[relay,relay];binding.cleanupErrors=[relay,relay];
   }
   throw error;
  }
  const work=Promise.resolve().then(()=>callback(endpoint(signal)));
  void work.then(()=>{callbackSettled=true;},()=>{callbackSettled=true;});
  const interrupted=new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(Object.assign(Error('producer cancelled'),{retirementUnproven:true})),{once:true}));
  return Promise.race([work,interrupted]);
 }};
 const module={exports:{}};
 vm.runInNewContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',{
  Buffer,AbortController,AbortSignal,Error,AggregateError,URL,process,performance:clock,
  setTimeout:(fn,ms)=>{timers.push({fn,ms});return setTimeout(fn,ms<=I.LIMITS.controllerJoin?Math.min(ms,10):ms);},clearTimeout
 })(id=>id==='node:fs/promises'?io:id==='node:fs'?native:id==='node:child_process'?{spawn}:
  id==='./ownedSystemImageProducer'?adapter:require(id),module,module.exports,filename,path.dirname(filename));
 return {api:module.exports,options:value,events,files,timers,get child(){return child;},get callbackSettled(){return callbackSettled;},
  releaseValidationClose:()=>releaseValidationClose()};
}
test('source and browser descriptor close failures retain first cause and cannot mint preallocation cleanup authority',async()=>{
 for(const fault of ['source-close','browser-close','source-primary-close']){
  const f=await controlled(fault);let failure;
  try{await f.api._internals.runOriginal(f.options);}catch(error){failure=error;}
  assert(failure?.validationIoUnjoined);
  assert.equal(failure.code,fault==='source-primary-close'?'SYSTEM_ORIGINAL_CHANGED':'CONTROLLED_CLOSE');
  const terminal=f.api._internals.mainTerminal(f.options.runId,null,failure);
  assert.equal(terminal.cleanupVerified,false);assert.equal(terminal.preallocation,null);assert.equal(terminal.passed,false);
  assert(!f.events.includes('mkdir'));assert(!f.events.includes('producer'));assert(f.events.includes('validation-close'));
 }
});
test('pending source/browser close is actually joined before validation can settle or issue preallocation proof',async()=>{
 for(const fault of ['source-close-pending','browser-close-pending']){
  const f=await controlled(fault),abort=new AbortController();f.options.signal=abort.signal;
  let settled=false;
  const work=f.api._internals.runOriginal(f.options).then(value=>{settled=true;return{value};},error=>{settled=true;return{error};});
  for(let i=0;i<30&&!f.events.includes('validation-close');i++)await new Promise(resolve=>setImmediate(resolve));
  assert(f.events.includes('validation-close'));assert.equal(settled,false);
  assert(!f.events.includes('mkdir'));assert(!f.events.includes('producer'));
  abort.abort(Object.assign(Error('stop before owner effects'),{code:'SYSTEM_MAIN_INTERRUPTED'}));
  await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);
  f.releaseValidationClose();const outcome=await work;
  assert.equal(outcome.error?.code,'SYSTEM_MAIN_INTERRUPTED');assert(!f.events.includes('mkdir'));
  assert.equal(f.api._internals.mainTerminal(f.options.runId,null,outcome.error).cleanupVerified,true);
 }
});
test('fixed owner delegates original child, journals before dispatch and joins closed controller before settling',async()=>{
 const f=await controlled();const value=await f.api._internals.runOriginal(f.options);
 assert.equal(value.qualificationAccepted,false);assert.equal(value.originalFixture,I.TEST);
 assert(f.events.indexOf('fsync')<f.events.indexOf('spawn'));assert.equal(f.events.filter(x=>x==='spawn').length,1);
 assert.equal(f.callbackSettled,true);assert.equal(f.child.stdin.destroyed,true);assert.equal(f.child.stdout.destroyed,true);
 const journal=f.files.get(I.locations(f.options).journal).toString();assert(!journal.includes('t'.repeat(43)));
 assert(journal.includes('producer-outcome-before-file-close'));assert(!journal.includes('"qualificationAccepted":true'));
});
test('actual owner catch journals fixed producer primary before relay cleanup, bounded and without private error text',async()=>{
 for(const fault of ['producer-diagnostic','producer-diagnostic-bounds','producer-diagnostic-depth','producer-diagnostic-nested-cleanup']){
  const f=await controlled(fault);let failure;
  try{await f.api._internals.runOriginal(f.options);}catch(error){failure=error;}
  assert.equal(failure?.code,'SYSTEM_PRODUCER_FAILED');
  const lines=f.files.get(I.locations(f.options).journal).toString().trim().split('\n').map(line=>JSON.parse(line));
  const row=lines.find(item=>item.stage==='producer-outcome-before-file-close');
  assert(row);assert.equal(row.producerCompleted,false);assert.equal(row.retirementUnproven,true);
  assert.equal(row.producerFailure.outerCode,'SYSTEM_PRODUCER_FAILED');
  assert.equal(row.producerFailure.cleanupCodes[0],'SYSTEM_BRIDGE_RETIREMENT_UNPROVEN');
  assert.equal(row.producerFailure.primaryCode,['producer-diagnostic','producer-diagnostic-nested-cleanup'].includes(fault)?'SYSTEM_BINDING':'SYSTEM_OWNER_UNKNOWN');
  assert.equal(row.producerFailure.truncated,['producer-diagnostic-bounds','producer-diagnostic-depth'].includes(fault));
  assert.equal(row.producerFailure.cleanupCodes.length,fault==='producer-diagnostic-bounds'||fault==='producer-diagnostic-nested-cleanup'?4:1);
  assert(!JSON.stringify(row).includes('private'));
  assert(!JSON.stringify(row).includes('untrusted-secret-code'));
  const terminal=f.api._internals.mainTerminal(f.options.runId,null,failure);
  assert.equal(terminal.failureCode,'SYSTEM_OWNER_UNKNOWN');
  assert(!('producerFailure' in terminal));
 }
});
test('parent sends one reduced original budget only after exact ready; malformed, expired, stopped and missing readiness never admit input',async()=>{
 const frame=Buffer.from(JSON.stringify({version:1,stage:'ready',runId:'a'.repeat(32)})+'\n');
 for(const mode of ['delayed','malformed','duplicate','oversize','eof','expired','stopped','stalled']){
  let now=100;const f=await controlled('manual-ready',{now:()=>now}),controller=new AbortController();
  const life={...endpoint(controller.signal),deadline:1000};
  const pending=f.api._internals.ownChild(f.options,life,{fd:1},tapHandle());
  const outcome=pending.then(value=>({value}),error=>({error}));
  for(let n=0;n<100&&!f.child;n++)await new Promise(resolve=>setImmediate(resolve));
  assert(f.child);assert(!f.events.includes('input'));
  if(mode==='delayed'){
   now=900;f.child.stdout.write(frame.subarray(0,12));assert(!f.events.includes('input'));
   f.child.stdout.write(frame.subarray(12));
   assert((await outcome).value);assert.equal(f.events.filter(x=>x==='input-finished').length,1);
   assert(f.events.includes('remaining:100'));
  }else{
   if(mode==='expired')now=1000;
   if(mode==='stopped')controller.abort(Object.assign(Error('stopped'),{code:'STOPPED'}));
   if(mode==='stalled')f.timers.find(t=>t.ms===900).fn();
   else if(mode!=='eof')f.child.stdout.write(mode==='malformed'?Buffer.from('{}\n'):mode==='duplicate'?Buffer.concat([frame,frame]):mode==='oversize'?Buffer.alloc(I.LIMITS.terminal+1):frame);
   if(['malformed','duplicate','oversize','eof'].includes(mode)){f.child.exitCode=1;f.child.emit('close',1,null);}
   const result=await outcome;assert(result.error?.retirementUnproven,mode);
   if(mode==='oversize')assert.equal(result.error.cause.code,'SYSTEM_ORIGINAL_OUTPUT_BOUND');
   assert(!f.events.includes('input'),mode);assert(f.child.stdin.destroyed&&f.child.stdout.destroyed);
  }
 }
});
test('unproven browser retirement leaves actual producer callback unsettled and retains failure, rather than permitting cleanup',async()=>{
 const f=await controlled('browser-debt');
 await assert.rejects(f.api._internals.runOriginal(f.options),error=>error.retirementUnproven===true&&error.childFailure.retirementUnproven===true);
 await new Promise(resolve=>setImmediate(resolve));assert.equal(f.callbackSettled,false);
 assert.equal(f.events.filter(x=>x==='spawn').length,1);
});
test('original test semantic failure after proven retirement stays failed without invented cleanup debt',async()=>{
 const f=await controlled('test-failure');
 await assert.rejects(f.api._internals.runOriginal(f.options),error=>error.code==='SYSTEM_ORIGINAL_TEST_FAILED'&&error.packet.cleanupVerified===true&&!error.retirementUnproven);
 assert.equal(f.callbackSettled,true);
});
test('pre-abort/journal failure makes no child; exited-but-unclosed controller has bounded debt without signaling reused PID',async()=>{
 for(const fault of ['abort','intent-fsync']){
  const f=await controlled(fault),controller=new AbortController();if(fault==='abort')controller.abort(Error('cancel'));
  await assert.rejects(f.api._internals.ownChild(f.options,endpoint(controller.signal),{fd:1},{fd:2}));assert(!f.events.includes('spawn'));
 }
 const f=await controlled('exited-unclosed'),controller=new AbortController(),life=endpoint(controller.signal);
 const pending=f.api._internals.ownChild(f.options,life,{fd:1},tapHandle());
 for(let n=0;n<50&&!f.events.includes('spawn');n++)await new Promise(resolve=>setImmediate(resolve));
 controller.abort(Error('cancel'));
 await assert.rejects(pending,error=>error.retirementUnproven===true);
 assert(!f.events.some(x=>x.startsWith('signal-')));assert(f.events.includes('unref'));assert(f.child.stdout.destroyed);
});
test('same original absolute deadline stops work; a retired abort preserves first cause without inventing debt',async()=>{
 const f=await controlled('deadline-retired'),life=endpoint();
 life.deadline=performance.now()+40000;
 const pending=f.api._internals.ownChild(f.options,life,{fd:1},tapHandle());
 for(let n=0;n<50&&!f.timers.some(t=>t.ms>6000);n++)await new Promise(resolve=>setImmediate(resolve));
 const timer=f.timers.find(t=>t.ms>6000);assert(timer&&timer.ms<=40000&&timer.ms>39000);
 timer.fn();
 await assert.rejects(pending,e=>e.code==='SYSTEM_ORIGINAL_DEADLINE'&&e.packet.cleanupVerified&&!e.retirementUnproven);
 assert.equal(f.events.filter(x=>x==='signal-SIGTERM').length,1);assert(f.child.stdout.destroyed);
 const a=await controlled('abort-retired'),controller=new AbortController(),reason=Object.assign(Error('original cancellation'),{code:'CANCEL_ORIGINAL'});
 const work=a.api._internals.ownChild(a.options,endpoint(controller.signal),{fd:1},tapHandle());
 for(let n=0;n<50&&!a.events.includes('spawn');n++)await new Promise(resolve=>setImmediate(resolve));
 controller.abort(reason);await assert.rejects(work,e=>e===reason&&e.packet.cleanupVerified&&!e.retirementUnproven);
});
test('live controller/pipe failures retain original cause and bounded retirement debt; local endpoints always close',async()=>{
 for(const fault of ['live-unclosed','pipe-error']){
  const f=await controlled(fault),controller=new AbortController(),reason=Error('owned cancellation');
  const work=f.api._internals.ownChild(f.options,endpoint(controller.signal),{fd:1},{fd:2});
  for(let n=0;n<50&&!f.events.includes('spawn');n++)await new Promise(resolve=>setImmediate(resolve));
  if(fault==='live-unclosed')controller.abort(reason);
  await assert.rejects(work,e=>e.code==='SYSTEM_ORIGINAL_CONTROLLER_UNJOINED'&&e.retirementUnproven&&
   (fault==='pipe-error'?e.cause.code==='CONTROLLED_PIPE':e.cause===reason));
  assert(f.events.includes('signal-SIGTERM'));assert(f.events.includes('signal-SIGKILL'));
  assert(f.child.stdin.destroyed&&f.child.stdout.destroyed&&f.child.stderr.destroyed);assert(f.events.includes('unref'));
 }
});
test('changed approved browser bytes deny before producer; file close failure cannot produce accepted result',async()=>{
 const replaced=await controlled('browser-replaced');
 await assert.rejects(replaced.api._internals.runOriginal(replaced.options),{code:'SYSTEM_ORIGINAL_SOURCE'});
 assert(!replaced.events.includes('producer'));assert(!replaced.events.includes('spawn'));
 const closing=await controlled('file-close');
 await assert.rejects(closing.api._internals.runOriginal(closing.options),/controlled close failure/);
 assert(closing.events.includes('spawn'));assert.equal(closing.events.filter(x=>x==='close-output').length,2);
 const status=await controlled('controller-status');
 await assert.rejects(status.api._internals.runOriginal(status.options),e=>e.childFailure?.code==='SYSTEM_ORIGINAL_CONTROLLER_STATUS'&&e.retirementUnproven);
});
test('private TAP readback joins actual bounded bytes; evidence mismatch fails without erasing proven retirement',async()=>{
 const bytes=Buffer.alloc(131073,65);await I.verifyTap(tapHandle(bytes),{bytes:bytes.length,sha256:sha(bytes)});
 for(const expected of [{bytes:bytes.length-1,sha256:sha(bytes)},{bytes:bytes.length,sha256:sha('wrong')}])
  await assert.rejects(I.verifyTap(tapHandle(bytes),expected),{code:'SYSTEM_ORIGINAL_TAP'});
 const f=await controlled('tap-mismatch');
 await assert.rejects(f.api._internals.runOriginal(f.options),e=>e.code==='SYSTEM_ORIGINAL_TAP'&&e.packet.cleanupVerified&&!e.retirementUnproven);
 assert(f.callbackSettled);
});
test('exact emitted Python compiles and executable frame/retirement controls use no live process or browser',()=>{
 const conf={root:I.ROOT,runId:'a'.repeat(32),temporary:I.ROOT+'/tasks/tmp/controlled',pins:{},test:I.TEST};
 const checks=String.raw`
from types import SimpleNamespace
captured=[]
os.write=lambda fd,data:(captured.append(bytes(data)) or len(data))
os.fsync=lambda fd:None
private_fd=lambda fd:SimpleNamespace(st_size=0)
journal({'stage':'controlled'})
assert captured[0][-1:]==bytes([10]) and not captured[0].endswith(bytes([92,110]))
class Inventory:
 def __init__(self,rows=()):self.rows=rows
 def process_records(self,**kw):return self.rows
 def owned_group_members(self,*a,**kw):return []
class Api:
 def group_pids(self,pid):return []
 def identity(self,pid):return None
class Proc:
 pid=42
 returncode=0
 def poll(self):return self.returncode
 def wait(self,**kw):return self.returncode
os.listdir=lambda p:[]
os.killpg=lambda *a:(_ for _ in ()).throw(AssertionError('must not signal reaped child'))
clean=retire(Proc(),(1,2,42,os.getuid(),os.getuid()),Inventory(),Api())
assert clean['reaped'] and clean['groupAbsent'] and clean['browserProcessesAbsent'] and clean['profilesAbsent']
rows=[{'arguments':('--user-data-dir='+CONF['temporary']+'/profile',)}]
assert not retire(Proc(),(1,2,42,os.getuid(),os.getuid()),Inventory(rows),Api())['browserProcessesAbsent']
assert not no_child_cleanup(Inventory(rows))['browserProcessesAbsent']
class Hidden(Inventory):
 def process_records(self,**kw):raise PermissionError('unreadable live process')
assert not retire(Proc(),(1,2,42,os.getuid(),os.getuid()),Hidden(),Api())['browserProcessesAbsent']
assert not no_child_cleanup(Hidden())['browserProcessesAbsent']
os.listdir=lambda p:['profile']
assert not retire(Proc(),(1,2,42,os.getuid(),os.getuid()),Inventory(),Api())['profilesAbsent']
assert not no_child_cleanup(Inventory())['profilesAbsent']
class Members(Inventory):
 def owned_group_members(self,*a,**kw):return [SimpleNamespace(pid=42)]
class Reused(Api):
 def identity(self,pid):return SimpleNamespace(start_sec=999,start_usec=2,pgid=42,uid=os.getuid(),ruid=os.getuid())
 def group_pids(self,pid):return [42]
reused=retire(Proc(),(1,2,42,os.getuid(),os.getuid()),Members(),Reused())
assert not reused['groupAbsent'] and 'GROUP_RETIREMENT_UNPROVEN' in reused['errors']
print('controlled-emitted-python-ok')
`;
 const result=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify(conf)+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(result.toString().trim(),'controlled-emitted-python-ok');
});
test('source-pinned caller preserves original600s/four-turn/Judge/Fixed lesson and owner ACK admission',async()=>{
 for(const [name,expected]of Object.entries(I.PINS))assert.equal(sha(await fs.readFile(path.join(I.ROOT,name))),expected,name);
 const fixture=await fs.readFile(path.join(I.ROOT,I.TEST),'utf8');
 assert(fixture.includes('timeout: ADMIN_POLICY_BROWSER ? 840000 : 600000'));
 assert(fixture.includes('POLICY_INSTRUCTION_BROWSER'));assert(fixture.includes('assertPolicyInstructionRepositoryEvidencePath'));
 assert(fixture.includes('await acknowledgePolicyInstructionBrowser('));
 const env=I.childEnvironment(options(),endpoint()),source=I.controllerProgram(options(),Object.keys(env),env);
 assert(source.includes("'--test','--test-reporter=tap','--test-concurrency=1',CONF['test']"));
 assert(!source.includes('--test-name-pattern'));assert(!source.includes('shell=True'));
 assert(!source.includes('t'.repeat(43)));assert.equal(entry.LIVE_ENABLED,true);
});
test('actual emitted ready/input handshake charges startup and reply latency, rejects bad frames before inventory or fixture effects',()=>{
 const conf={runId:'a'.repeat(32),environmentKeys:['ONLY'],environmentSha256:sha(JSON.stringify({ONLY:'fixed'}))};
 const checks=String.raw`
from types import SimpleNamespace
sys.platform='darwin'
signal.signal=lambda *args:None
private_fd=lambda fd:SimpleNamespace(st_size=0)
os.set_blocking=lambda *args:None
def simulate(startup,delay,fault):
 global CANCELLED,load_inventory,run
 CANCELLED=False;now=[100.0+startup];events=[];frames=[];parts=[]
 time.monotonic=lambda:now[0]
 def write(fd,data):
  assert fd==1 and bytes(data)==json.dumps(dict(version=1,stage='ready',runId=CONF['runId']),separators=(',',':')).encode()+bytes([10])
  events.append('ready');frames.append(bytes(data))
  # Independent simulated parent clock: it samples only after ready, so the
  # startup delay is removed before choosing the remaining original budget.
  remaining=(1000.0-startup)*1000
  raw=json.dumps(dict(env={'ONLY':'fixed'},remainingMs=remaining),separators=(',',':')).encode()
  if fault=='duplicate':raw=b'{"env":{"ONLY":"fixed"},"remainingMs":1,"remainingMs":2}'
  if fault=='malformed':raw=b'not JSON'
  if fault=='oversize':raw=b'x'*65537
  if fault=='eof':raw=b''
  if fault=='expired':raw=b'{"env":{"ONLY":"fixed"},"remainingMs":1}'
  if fault=='infinite':raw=b'{"env":{"ONLY":"fixed"},"remainingMs":Infinity}'
  if fault=='environment':raw=b'{"env":{"ONLY":"forged"},"remainingMs":100000}'
  parts.extend([raw[i:i+4096] for i in range(0,len(raw),4096)]+[b''])
  return len(data)
 os.write=write
 first=[True]
 class Selector:
  def register(self,*args):pass
  def close(self):events.append('selector-close')
  def select(self,*args):
   if first[0]:now[0]+=delay;first[0]=False
   if fault=='stalled':now[0]+=.1;return []
   return [(None,None)]
 selectors.DefaultSelector=Selector
 os.read=lambda *args:parts.pop(0)
 def inventory():events.append('inventory');return SimpleNamespace(LibProc=lambda:None)
 load_inventory=inventory
 def dispatch(_inventory,_api,settings):
  events.append('fixture');assert settings['deadline']==1100.0
  assert now[0]<settings['deadline'];return 0
 run=dispatch
 try:code=main()
 except (RuntimeError,ValueError):code=2
 assert len(frames)==1 and events[0]=='ready' and 'selector-close' in events
 if fault=='clean':assert code==0 and 'fixture' in events
 else:assert code==2 and 'inventory' not in events and 'fixture' not in events
simulate(900.0,.25,'clean')
for fault in ('duplicate','malformed','oversize','eof','expired','infinite','stalled','environment'):simulate(900.0,.25,fault)
simulate(900.0,2.1,'late-reply')
print('controlled-ready-handshake-ok')
`;
 const result=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify(conf)+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(result.toString().trim(),'controlled-ready-handshake-ok');
});
test('actual emitted controller handles partial startup, expired admission and terminal persistence failure without live effects',()=>{
 const conf={root:I.ROOT,directory:I.ROOT+'/tasks/qualification/controlled',runId:'a'.repeat(32),temporary:I.ROOT+'/tasks/tmp/controlled',pins:{[I.TEST]:'0'.repeat(64)},test:I.TEST,
  node:I.NODE,nodeSha256:'0'.repeat(64),browser:I.BROWSER,browserSha256:'0'.repeat(64),rendererAdmission:I.ROOT+'/tasks/controlled',rendererSha256:'0'.repeat(64)};
 const checks=String.raw`
from types import SimpleNamespace
original_observe_browser=observe_browser
def simulate(fault):
 global CANCELLED,fingerprint,journal,private_directory,read_browser_record,observe_browser
 CANCELLED=False;events=[];packets=[];now=[10.0];source_calls=[0];body_reads=[0];tap_bytes=[0]
 time.monotonic=lambda:now[0]
 time.sleep=lambda seconds:now.__setitem__(0,now[0]+seconds)
 def source_check(*args):
  source_calls[0]+=1
  if fault=='source-deadline':now[0]=11.0
 fingerprint=source_check
 def record(row):
  global CANCELLED
  events.append(row['stage'])
  if row['stage']=='original-child-intent' and fault=='intent-abort':CANCELLED=True
  if row['stage']=='original-child-birth' and fault=='birth-journal':raise OSError('controlled journal error')
  if row['stage']=='original-child-terminal' and fault=='terminal-journal':raise OSError('controlled terminal error')
  if row['stage']=='browser-ancestry-rejected' and fault=='ancestry-diagnostic-io':raise OSError('controlled diagnostic error')
 journal=record
 observe_browser=(lambda *args:ancestry_require(False,'executable',44)) if fault=='ancestry-diagnostic-io' else original_observe_browser
 os.listdir=lambda path:[]
 os.path.lexists=lambda path:False
 private_directory=lambda path:(1,2)
 read_browser_record=lambda:None
 os.set_blocking=lambda *args:None
 def read(fd,size):
  assert size==65536
  body_reads[0]+=1
  if fault in ('bootstrap-at-bound','bootstrap-overflow') and body_reads[0]<=128+(fault=='bootstrap-overflow'):
   return b'x'*65536
  return b''
 os.read=read
 def write(fd,data):
  if fd==1:packets.append(bytes(data))
  if fd==4:tap_bytes[0]+=len(data)
  return len(data)
 os.write=write
 os.fsync=lambda fd:None
 os.killpg=lambda *args:(_ for _ in ()).throw(AssertionError('empty original group must not be signalled'))
 class Pipe:
  def fileno(self):return 50
  def close(self):events.append('pipe-close')
 class Proc:
  pid=42
  returncode=None
  stdout=Pipe()
  def poll(self):self.returncode=0;return 0
  def wait(self,timeout):events.append('wait');self.returncode=0;return 0
 def popen(args,**kwargs):
  events.append('spawn');assert args==[CONF['node'],'--test','--test-reporter=tap','--test-concurrency=1',CONF['test']]
  assert kwargs['start_new_session'] is True and kwargs['close_fds'] is True and kwargs['stdin']==subprocess.DEVNULL
  assert kwargs['stderr']==subprocess.STDOUT and kwargs['stdout']==subprocess.PIPE
  if fault=='spawn':raise OSError('controlled Popen error')
  return Proc()
 subprocess.Popen=popen
 class Inventory:
  def process_records(self,**kwargs):return []
  def owned_group_members(self,*args,**kwargs):return []
 class Api:
  def group_pids(self,pid):return []
  def identity(self,pid):
   if fault=='identity':return None
   return SimpleNamespace(start_sec=1,start_usec=2,pgid=42,uid=os.getuid(),ruid=os.getuid())
 class Selector:
  def __init__(self):
   if fault=='selector':raise OSError('controlled selector error')
   self.active=True
  def register(self,*args):pass
  def get_map(self):return {1:1} if self.active else {}
  def select(self,*args):
   if fault=='body-deadline':now[0]=11.0;return []
   return [(SimpleNamespace(fd=50,fileobj=50),None)]
  def unregister(self,*args):self.active=False
  def close(self):events.append('selector-close')
 selectors.DefaultSelector=Selector
 result=run(Inventory(),Api(),{'env':{},'deadline':10.1})
 assert len(packets)==1
 packet=json.loads(packets[0])
 if fault in ('source-deadline','intent-abort'):
  assert 'spawn' not in events and packet['failure']=='INTERRUPTED' and result==1
 elif fault=='spawn':
  assert 'pipe-close' not in events and packet['child']['pid'] is None and result==1
 else:
  assert 'pipe-close' in events and 'wait' in events
  if fault=='ancestry-diagnostic-io':
   assert result==2 and packet['cleanupVerified'] is False and packet['failure']=='BROWSER_ANCESTRY'
   assert 'ANCESTRY_DIAGNOSTIC_UNJOINED' in packet['child']['errors']
  elif fault in ('identity','terminal-journal'):
   assert result==2 and packet['cleanupVerified'] is False
  elif fault in ('birth-journal','selector'):
   assert result==1 and packet['failure']=='ORIGINAL_CHILD_FAILED' and packet['cleanupVerified']
  elif fault=='body-deadline':
   assert result==1 and packet['failure']=='COHORT_DEADLINE' and packet['cleanupVerified']
  elif fault=='bootstrap-overflow':
   assert result==1 and packet['failure']=='TAP_BOUND' and packet['cleanupVerified']
   assert tap_bytes[0]==8388608 and body_reads[0]==129
  else:assert result==1 and packet['cleanupVerified'] and packet['failure']=='BROWSER_NOT_ACKNOWLEDGED'
 if fault=='bootstrap-at-bound':assert tap_bytes[0]==8388608 and packet['tap']['bytes']==8388608
for fault in ('clean','source-deadline','intent-abort','spawn','identity','birth-journal','selector','body-deadline','terminal-journal','bootstrap-at-bound','bootstrap-overflow','ancestry-diagnostic-io'):simulate(fault)
print('controlled-partial-start-ok')
`;
 const result=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify(conf)+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(result.toString().trim(),'controlled-partial-start-ok');
 assert(I.CONTROLLER.includes("settings['deadline']=started+settings['remainingMs']/1000"));
 assert(!I.CONTROLLER.includes("end=time.monotonic()+settings['remainingMs']"));
});
test('emitted browser admission joins actual worker ancestry/executable/birth and never signals reused authority or deletes an unknown profile',()=>{
 const p=I.locations(options()),conf={root:I.ROOT,directory:p.directory,temporary:p.temporary,runId:options().runId,test:I.TEST,
  node:I.NODE,nodeSha256:sha('node'),browser:I.BROWSER,browserSha256:sha('browser')};
 const checks=String.raw`
from types import SimpleNamespace
import copy
events=[];now=[10.0]
time.monotonic=lambda:now[0]
time.sleep=lambda seconds:now.__setitem__(0,now[0]+seconds)
def info(pid,ppid,pgid,start):return SimpleNamespace(pid=pid,ppid=ppid,pgid=pgid,start_sec=start,start_usec=4,uid=os.getuid(),ruid=os.getuid())
class Api:
 def __init__(self):
  self.rows={42:info(42,1,42,100),44:info(44,42,42,101),43:info(43,44,43,102)}
  self.paths={42:CONF['node'],44:CONF['node'],43:CONF['browser']}
  self.argv={42:[CONF['node'],'--test',CONF['test']],44:[CONF['node'],CONF['root']+'/'+CONF['test']],43:[CONF['browser'],'--user-data-dir='+profile]}
  def pidpath(pid,buffer,limit):
   value=self.paths[pid].encode();buffer.value=value;return len(value)
  self.library=SimpleNamespace(proc_pidpath=pidpath)
 def identity(self,pid):return copy.copy(self.rows.get(pid))
 def arguments(self,pid):return self.argv[pid]
 def group_pids(self,pgid):return [pid for pid,row in self.rows.items() if row is not None and row.pgid==pgid]
profile=CONF['temporary']+'/owasp-ai-goat-role-policy-instruction-abc123'
record=dict(version=1,runId=CONF['runId'],workerPid=44,browserPid=43,profilePath=profile)
proc=SimpleNamespace(pid=42);identity=(100,4,42,os.getuid(),os.getuid())
fingerprint=lambda path,digest:events.append(('hash',path,digest))
journal=lambda row:events.append(('journal',row))
private_directory=lambda path:(7,8)
def admit(api):
 os.getsid=lambda pid:api.rows[pid].pgid
 return validated_browser(record,proc,identity,api)
good=admit(Api());assert good['pid']==43 and good['pgid']==43
assert {e[1] for e in events}=={CONF['node'],CONF['browser']}
for kind in ('wrong-worker-parent','wrong-worker-uid','wrong-worker-exe','wrong-browser-parent','wrong-browser-exe','wrong-profile','wrong-group','worker-cycle','wrong-child-birth'):
 api=Api()
 if kind=='wrong-worker-parent':api.rows[44].ppid=1
 elif kind=='wrong-worker-uid':api.rows[44].uid+=1
 elif kind=='wrong-worker-exe':api.paths[44]='/bin/sh'
 elif kind=='wrong-browser-parent':api.rows[43].ppid=99
 elif kind=='wrong-browser-exe':api.paths[43]='/foreign/Chrome'
 elif kind=='wrong-profile':api.argv[43]=[CONF['browser'],'--user-data-dir=/tmp/foreign']
 elif kind=='wrong-group':api.rows[43].pgid=42
 elif kind=='worker-cycle':api.rows[44].ppid=44
 else:api.rows[42].start_sec+=1
 try:admit(api);raise AssertionError(kind+' admitted')
 except RuntimeError:pass
api=Api();os.getsid=lambda pid:api.rows[pid].pgid
read_browser_record=lambda:(record,'a'*64)
journal=lambda row:events.append(('journal',row))
published=[]
publish_browser_ack=lambda row,deadline:published.append(row)
state={};observe_browser(state,proc,identity,api,20);observe_browser(state,proc,identity,api,20)
assert len(published)==1 and list(published[0])==['version','runId','birthSha256','workerPid','browserPid','profilePath','birth','pgid']
assert published[0]['workerPid']==44 and published[0]['birth']==[102,4] and state['owned']['acknowledged']
read_browser_record=lambda:(record,'b'*64)
try:observe_browser(state,proc,identity,api,20);raise AssertionError('changed record admitted')
except RuntimeError:pass
read_browser_record=lambda:(record,'a'*64)
def failed_ack(row,deadline):raise OSError('controlled ACK close failure')
publish_browser_ack=failed_ack
failed={}
try:observe_browser(failed,proc,identity,api,20);raise AssertionError('failed ACK accepted')
except OSError:pass
assert failed['owned']['pid']==43 and not failed['owned']['acknowledged']
publish_browser_ack=lambda row,deadline:published.append(row)
def cancel_journal(row):
 global CANCELLED
 CANCELLED=True
journal=cancel_journal;interrupted={};count=len(published)
try:observe_browser(interrupted,proc,identity,api,20);raise AssertionError('ACK after cancellation')
except RuntimeError:pass
assert interrupted['owned']['pid']==43 and len(published)==count and not interrupted['owned']['acknowledged']
CANCELLED=False;journal=lambda row:now.__setitem__(0,21.0);expired={}
try:observe_browser(expired,proc,identity,api,20);raise AssertionError('ACK after original deadline')
except RuntimeError:pass
assert expired['owned']['pid']==43 and len(published)==count and not expired['owned']['acknowledged']
now[0]=10.0
class Inventory:
 def owned_group_members(self,pgid,**kw):return api.group_pids(pgid)
 def process_records(self,**kw):return []
removed=[];signals=[];exists=[True]
os.path.lexists=lambda path:exists[0]
def remove(path):assert path==profile;removed.append(path);exists[0]=False
shutil.rmtree=remove
def kill(pgid,sig):
 assert pgid==43;signals.append((pgid,sig));api.rows[43]=None
os.killpg=kill
clean=retire_browser(state['owned'],Inventory(),api,now[0]+4)
assert clean['groupAbsent'] and clean['processAbsent'] and clean['profileAbsent'] and not clean['errors']
assert len(signals)==1 and removed==[profile]
api=Api();api.rows[43].start_sec=999;exists[0]=True;signals.clear();removed.clear()
debt=retire_browser(state['owned'],Inventory(),api,now[0]+4)
assert debt['errors'] and not debt['processAbsent'] and not signals and not removed
api.rows[43]=None;private_directory=lambda path:(9,9)
debt=retire_browser(state['owned'],Inventory(),api,now[0]+4)
assert debt['groupAbsent'] and not debt['profileAbsent'] and not removed
print('controlled-browser-authority-ok')
`;
 const result=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify(conf)+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(result.toString().trim(),'controlled-browser-authority-ok');
});
test('emitted ancestry admits only the FD-verified two-name Node identity and records closed failure predicates',()=>{
 const checks=String.raw`
import tempfile,copy
from types import SimpleNamespace
original_getsid=os.getsid
original_fstat=os.fstat
original_read=os.read
with tempfile.TemporaryDirectory(prefix='system-ancestry-',dir=CONF['scratch']) as folder:
 CONF['root']=folder
 CONF['node']=folder+'/tasks/runtime/node/node_modules/node/bin/node'
 alias=folder+'/tasks/runtime/node/node_modules/node/node_modules/node-bin-darwin-arm64/bin/node'
 CONF['browser']=folder+'/Chrome'
 CONF['test']='tests/original.test.js'
 CONF['nodeSha256']=hashlib.sha256(b'controlled-node').hexdigest()
 CONF['browserSha256']=hashlib.sha256(b'controlled-chrome').hexdigest()
 os.makedirs(os.path.dirname(CONF['node']));os.makedirs(os.path.dirname(alias))
 profile=folder+'/profile';os.mkdir(profile,0o700)
 for filename,data in ((CONF['node'],b'controlled-node'),(CONF['browser'],b'controlled-chrome')):
  with open(filename,'xb') as out:out.write(data)
  os.chmod(filename,0o755)
 os.link(CONF['node'],alias)
 rows=[]
 journal=lambda row:rows.append(row)
 def info(pid,ppid,pgid,start):return SimpleNamespace(pid=pid,ppid=ppid,pgid=pgid,start_sec=start,start_usec=4,uid=os.getuid(),ruid=os.getuid())
 class Api:
  def __init__(self,kind):
   self.kind=kind;self.path_reads={};self.identity_reads={};self.changed=False
   self.rows={42:info(42,1,42,100),44:info(44,42,42,101),43:info(43,44,43,102)}
   self.paths={42:CONF['node'],44:CONF['node'],43:CONF['browser']}
   self.argv={42:[CONF['node'],'--test',CONF['test']],44:[CONF['node'],CONF['test']],43:[CONF['browser'],'--user-data-dir='+profile]}
   if kind in ('alias','alias-argv','path-mutation'):self.paths[42]=self.paths[44]=alias
   if kind=='uid':self.rows[44].uid+=1
   if kind=='ruid':self.rows[44].ruid+=1
   if kind=='group':self.rows[44].pgid=44
   if kind=='cycle':self.rows[44].ppid=44
   if kind=='foreign-path':self.paths[44]=folder+'/other-node'
   if kind=='alias-argv':self.argv[44][0]=alias
   if kind=='argv':self.argv[44][0]='/bin/node'
   if kind=='test-arg':self.argv[44][1]='private-unrestricted-value'
   if kind=='depth':
    self.rows[44].ppid=100
    for pid in range(100,117):
     self.rows[pid]=info(pid,pid+1,42,103);self.paths[pid]=CONF['node'];self.argv[pid]=[CONF['node']]
   def pidpath(pid,buffer,limit):
    self.path_reads[pid]=self.path_reads.get(pid,0)+1
    value=self.paths[pid]
    if kind=='path-mutation' and pid==44 and self.path_reads[pid]>1:value=CONF['node']
    buffer.value=value.encode();return len(buffer.value)
   self.library=SimpleNamespace(proc_pidpath=pidpath)
  def identity(self,pid):
   self.identity_reads[pid]=self.identity_reads.get(pid,0)+1
   row=copy.copy(self.rows.get(pid))
   if self.kind=='identity-mutation' and pid==44 and self.identity_reads[pid]>1:row.start_sec+=1
   if self.kind=='launcher-birth' and pid==42:row.start_sec+=1
   if self.kind=='launcher-rejoin' and pid==42 and self.identity_reads[pid]>=4:row.start_sec+=1
   return row
  def arguments(self,pid):
   if self.kind=='alias-mutation' and pid==44 and not self.changed:
    self.changed=True;os.unlink(alias)
    with open(alias,'xb') as out:out.write(b'controlled-node')
    os.chmod(alias,0o755)
   return self.argv[pid]
 record=dict(workerPid=44,browserPid=43,profilePath=profile)
 proc=SimpleNamespace(pid=42);identity=(100,4,42,os.getuid(),os.getuid())
 kinds=('primary','alias','different-inode','symlink','wrong-hash','nlink','file-uid','file-mode','hash-mutation','uid','ruid','group','session','argv','alias-argv','test-arg','foreign-path','path-mutation','identity-mutation','alias-mutation','cycle','depth','launcher-birth','launcher-rejoin')
 for kind in kinds:
  rows.clear();api=Api(kind);os.getsid=lambda pid:(99 if kind=='session' and pid==44 else api.rows[pid].pgid)
  expected=CONF['nodeSha256'];extra=folder+'/extra'
  if kind=='different-inode':
   os.unlink(alias)
   with open(alias,'xb') as out:out.write(b'controlled-node')
   os.chmod(alias,0o755)
   # Both independent inodes have nlink2 and identical bytes: still rejected.
   os.link(CONF['node'],extra);os.link(alias,folder+'/alias-extra')
  if kind=='symlink':os.unlink(alias);os.symlink(CONF['node'],alias)
  if kind=='wrong-hash':CONF['nodeSha256']='0'*64
  if kind=='nlink':os.link(CONF['node'],extra)
  if kind=='file-mode':os.chmod(CONF['node'],0o777)
  if kind=='file-uid':
   def wrong_uid(fd):
    s=original_fstat(fd)
    if s.st_ino==os.lstat(CONF['node']).st_ino:
     data={key:getattr(s,key) for key in dir(s) if key.startswith('st_')};data['st_uid']+=1;return SimpleNamespace(**data)
    return s
   os.fstat=wrong_uid
  if kind=='hash-mutation':
   mutated=[False]
   def changing_read(fd,count):
    data=original_read(fd,count)
    if data and not mutated[0]:
     mutated[0]=True
     with open(CONF['node'],'ab') as out:out.write(b'x')
    return data
   os.read=changing_read
  try:
   value=validated_browser(record,proc,identity,api)
   assert kind in ('primary','alias'),kind+' admitted'
   assert value['pid']==43 and not value['acknowledged'] and not rows
  except (RuntimeError,OSError) as error:
   assert kind not in ('primary','alias'),(kind,str(error))
   if str(error)=='BROWSER_ANCESTRY':
    assert len(rows)==1 and set(rows[0])=={'stage','predicate','pid'}
    assert rows[0]['stage']=='browser-ancestry-rejected' and len(json.dumps(rows[0]))<160
    assert 'private-unrestricted-value' not in json.dumps(rows)
  finally:
   os.fstat=original_fstat;os.read=original_read;CONF['nodeSha256']=expected
   for filename in (alias,extra,folder+'/alias-extra'):
    if os.path.lexists(filename):os.unlink(filename)
   with open(CONF['node'],'wb') as out:out.write(b'controlled-node')
   os.chmod(CONF['node'],0o755);os.link(CONF['node'],alias)
 os.getsid=original_getsid
 rows.clear()
 try:ancestry_require(False,'unrestricted-private-value',44);raise AssertionError('unknown diagnostic admitted')
 except RuntimeError as error:assert str(error)=='BROWSER_ANCESTRY' and error.ancestry_diagnostic_unjoined and not rows
 print('actual-two-name-ancestry-ok')
`;
 const output=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify({root:I.ROOT,scratch:require('node:os').tmpdir()})+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(output.toString().trim(),'actual-two-name-ancestry-ok');
});
test('emitted birth reader and ACK publisher enforce bounded canonical private records and fsync-before-exclusive-publication',()=>{
 const p=I.locations(options()),conf={root:I.ROOT,directory:p.directory,temporary:p.temporary,runId:options().runId};
 const checks=String.raw`
from types import SimpleNamespace
record=dict(version=1,runId=CONF['runId'],workerPid=44,browserPid=43,profilePath=CONF['temporary']+'/owasp-ai-goat-role-policy-instruction-abc123')
def encoded(row):return json.dumps(row,separators=(',',':'),ensure_ascii=False).encode()+b'\n'
raw=encoded(record);flags=[];closed=[];mode=stat.S_IFREG|0o600;links=1;inode=7
def snapshot():return SimpleNamespace(st_mode=mode,st_uid=os.getuid(),st_nlink=links,st_size=len(raw),st_dev=1,st_ino=inode,st_mtime_ns=3,st_ctime_ns=4)
os.open=lambda name,value,*args:(flags.append(value) or 7)
os.fstat=lambda fd:snapshot()
def named(name):
 if name.endswith('.partial'):raise FileNotFoundError()
 return snapshot()
os.lstat=named
os.read=lambda fd,count:raw
os.close=lambda fd:closed.append(fd)
row,digest=read_browser_record();assert row==record and digest==hashlib.sha256(raw).hexdigest()
assert flags[-1]&os.O_NONBLOCK and flags[-1]&os.O_NOFOLLOW and closed[-1]==7
for kind in ('duplicate','unknown','wrong-order','no-LF','wrong-run','bool-version','foreign-profile','large','fifo','hardlink','changed-inode'):
 row=dict(record);mode=stat.S_IFREG|0o600;links=1;inode=7;os.lstat=named
 if kind=='unknown':row['extra']='no'
 elif kind=='wrong-run':row['runId']='b'*32
 elif kind=='bool-version':row['version']=True
 elif kind=='foreign-profile':row['profilePath']='/tmp/foreign'
 elif kind=='wrong-order':row=dict(reversed(list(row.items())))
 raw=encoded(row)
 if kind=='duplicate':raw=raw.replace(b'"version":1,',b'"version":1,"version":1,')
 elif kind=='no-LF':raw=raw[:-1]
 elif kind=='large':raw=b'x'*4097
 elif kind=='fifo':mode=stat.S_IFIFO|0o600
 elif kind=='hardlink':links=2
 elif kind=='changed-inode':
  def altered(name):
   result=snapshot();result.st_ino=99;return result
  os.lstat=altered
 try:read_browser_record();raise AssertionError(kind+' accepted')
 except (RuntimeError,ValueError):pass
raw=encoded(record);mode=stat.S_IFREG|0o600;links=2;inode=7
os.lstat=lambda name:snapshot()
assert read_browser_record() is None # same private inode still has two names; never admitted
reads=[0]
def completing(fd):
 global links
 reads[0]+=1
 if reads[0]>1:links=1
 return snapshot()
os.fstat=completing;os.lstat=named
assert read_browser_record() is None # completed unlink during read; re-poll rather than accepting mixed snapshot
os.fstat=lambda fd:snapshot()
assert read_browser_record()[0]==record
links=2
def unlink_during_partial_stat(name):
 global links
 if name.endswith('.partial'):
  links=1;raise FileNotFoundError()
 return snapshot()
os.lstat=unlink_during_partial_stat
assert read_browser_record() is None # unlink after prior final stat is a known transition, not admission
os.lstat=named
assert read_browser_record()[0]==record
ack=dict(version=1,runId=CONF['runId'],birthSha256='a'*64,workerPid=44,browserPid=43,profilePath=record['profilePath'],birth=[102,4],pgid=43)
for fault in ('clean','close','link','expired'):
 events=[];written=[];now=[10.0];time.monotonic=lambda:now[0]
 def opened(name,flags,*args):events.append(('open',name,flags));return 8 if name.endswith('.partial') else 9
 def write(fd,data):events.append(('write',fd));written.append(bytes(data));return len(data)
 def closed(fd):
  events.append(('close',fd))
  if fd==8 and fault=='close':raise OSError('controlled close error')
  if fd==8 and fault=='expired':now[0]=21.0
 def linked(a,b,**kwargs):
  events.append(('link',a,b));assert kwargs=={'follow_symlinks':False}
  if fault=='link':raise FileExistsError('already exists')
 os.open=opened;os.write=write;os.fsync=lambda fd:events.append(('fsync',fd));os.close=closed;os.link=linked;os.unlink=lambda name:events.append(('unlink',name))
 try:
  publish_browser_ack(ack,20)
  assert fault=='clean'
 except (OSError,RuntimeError):assert fault!='clean'
 assert b''.join(written)==encoded(ack)
 if fault in ('close','expired'):assert not any(e[0]=='link' for e in events)
 if fault=='clean':
  link=next(i for i,e in enumerate(events) if e[0]=='link')
  assert events.index(('fsync',8))<events.index(('close',8))<link<events.index(('fsync',9))
print('controlled-browser-files-ok')
`;
 const result=execFileSync('/opt/homebrew/bin/python3',['-B','-c','CONF='+JSON.stringify(conf)+'\n'+I.CONTROLLER+'\n'+checks],
  {cwd:I.ROOT,env:{PATH:'/usr/bin:/bin',HOME:I.ROOT,TMPDIR:path.join(I.ROOT,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'},timeout:10000,maxBuffer:16384});
 assert.equal(result.toString().trim(),'controlled-browser-files-ok');
});
