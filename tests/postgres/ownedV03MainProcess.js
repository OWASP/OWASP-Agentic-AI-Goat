'use strict';
// Single fixed MAIN owner. Not exported as a generic process runner. The live
// factory stays closed until the complete admission/producer path is reviewed.
const {spawn}=require('node:child_process');
const path=require('node:path');
const fs=require('node:fs/promises'),native=require('node:fs'),crypto=require('node:crypto');
const LIVE_ENABLED=true;
const handles=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code});
function assertMainProcess(value,owner){if(!handles.has(value)||owner&&handles.get(value).owner!==owner)throw fail('V03_MAIN_PROCESS_REQUIRED');return value;}
function inspector(root,python,sourceHash,journal,launch=spawn){
 const pending=new Set(),debts=[];
 async function observe(request){
  let child;
  try{child=launch(python,['-B',path.join(root,'tests/postgres/v03_private_process.py'),root,sourceHash],
   {cwd:root,detached:true,stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});}
  catch(error){error.cleanupDebt=true;debts.push('V03_PROCESS_CONTROL_LAUNCH');
   journal.push({pid:null,closed:false,code:null,receipt:null,failure:'V03_PROCESS_CONTROL_LAUNCH'});throw error;}
  const row={pid:child.pid,closed:false,code:null,receipt:null};pending.add(row);journal.push(row);
  let bytes=0,errors=0,chunks=[],timer;
  const work=new Promise((resolve,reject)=>{
   let primary;
   const deny=error=>{primary ||= error;};
   child.once('error',deny);
   child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384)deny(fail('V03_PROCESS_OUTPUT_BOUND'));else chunks.push(chunk);});
   child.stderr.on('data',chunk=>{errors+=chunk.length;if(errors>16384)deny(fail('V03_PROCESS_STDERR_BOUND'));});
   child.stdin.on('error',deny);
   child.once('close',(code,signal)=>{
    row.closed=true;row.code=code;pending.delete(row);
    try{
     if(primary)throw primary;
     if(code!==0||signal)throw fail('V03_PROCESS_CONTROL_FAILED');
     const packet=JSON.parse(Buffer.concat(chunks));
     if(packet.version!==1||packet.controller?.pid!==child.pid||packet.controller?.pgid!==child.pid
       ||packet.controller?.ppid!==process.pid||packet.controller?.uid!==process.getuid())throw fail('V03_PROCESS_CONTROL_IDENTITY');
     row.receipt=packet;resolve(packet.result);
    }catch(error){reject(error);}
   });
   child.stdin.end(JSON.stringify(request));
  });
  // Never signal an unobserved helper identity. Timeout remains explicit debt;
  // its eventual terminal is retained and cannot retroactively clear the debt.
  const timeout=new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(fail('V03_PROCESS_CONTROL_UNJOINED')),10000);});
  try{return await Promise.race([work,timeout]);}
  catch(error){error.cleanupDebt=true;debts.push(error.code||'V03_PROCESS_CONTROL_FAILED');throw error;}
  finally{clearTimeout(timer);}
 }
 return {observe,pending,debts};
}
function childTerminal(child,clock=()=>Math.floor(performance.now())){
 const record={pid:child.pid,closed:false,code:null,signal:null,spawnFailure:null,observedAtMs:null};
 let resolve;const done=new Promise(value=>{resolve=value;});
 child.once('error',error=>{record.spawnFailure=error.code||'V03_MAIN_SPAWN_FAILED';});
 child.once('close',(code,signal)=>{record.closed=true;record.code=code;record.signal=signal;record.observedAtMs=clock();resolve(Object.freeze({...record}));});
 return Object.freeze({done,snapshot:()=>Object.freeze({...record})});
}
function handleFor(child,channel,control,initial,terminal=null,owner=null,schedule=setTimeout,cancel=clearTimeout){
 let main=initial,browser=null,retirement=null,shutdown=null;
 const wrapper=owner?.wrapperWindow(),expiry=owner?.binding().expiresAtMs;
 const request=(op,pid,mainIdentity,expected)=>({version:1,op,pid,mainIdentity,expected});
 const current=async()=>{
  const result=await control.observe(request('inspect',child.pid,null,null));
  if(JSON.stringify(result.observed)!==JSON.stringify(main))throw fail('V03_MAIN_PROCESS_CHANGED');
 };
 const value=Object.freeze({
  channel:()=>channel,
  terminal:()=>{if(!terminal)throw fail('V03_MAIN_TERMINAL_UNAVAILABLE');return terminal.done;},
  terminalSnapshot:()=>terminal?.snapshot()||null,
  shutdownTimedOutWork(){
   if(shutdown)return shutdown;
   shutdown=(async()=>{
    if(!owner||!terminal||owner.nowMs()<wrapper.deadlineMs)throw fail('V03_MAIN_TIMEOUT_STAGE');
    const waitUntil=async end=>{
     if(terminal.snapshot().closed)return terminal.snapshot();
     const remaining=end-owner.nowMs();if(remaining<=0)return null;
     let timer;
     try{return await Promise.race([terminal.done,new Promise(resolve=>{timer=schedule(()=>resolve(null),remaining);})]);}
     finally{cancel(timer);}
    };
    const signalUntil=async(op,end)=>{
     // The fixed identity inspector itself may consume ten seconds. Never
     // dispatch it unless that entire bound fits the immutable stage.
     if(end-owner.nowMs()<10000)throw fail('V03_MAIN_SIGNAL_RESERVE');
     await control.observe(request(op,child.pid,null,main));
     if(owner.nowMs()>=end)throw fail('V03_MAIN_SIGNAL_LATE');
    };
    const graceEnd=Math.min(expiry,wrapper.graceDeadlineMs);
    let result=terminal.snapshot().closed?terminal.snapshot():null;
    if(!result){
     if(owner.nowMs()<graceEnd)await signalUntil('term',graceEnd);
     result=await waitUntil(graceEnd);
    }
    if(!result){
     // Original forced-join allowance starts at the original grace boundary,
     // not at a late callback or completed identity lookup.
     const killEnd=Math.min(expiry,wrapper.graceDeadlineMs+30000);
     await signalUntil('kill',killEnd);
     result=await waitUntil(killEnd);
     if(!result)throw fail('V03_MAIN_KILL_UNJOINED');
    }
    return Object.freeze({timedOut:true,qualificationComplete:false,terminal:result});
   })().catch(error=>{error.cleanupDebt=true;throw error;});return shutdown;
  },
  assertCurrent:current,
  async attachBrowser(birth){
   if(browser||retirement||!birth||birth.ppid!==child.pid)throw fail('V03_MAIN_BROWSER_BINDING');
   await current();
   const result=await control.observe(request('inspect',birth.pid,main.identity,null));
   if(JSON.stringify(result.observed?.identity)!==JSON.stringify(birth))throw fail('V03_MAIN_BROWSER_CHANGED');
   browser=result.observed;
  },
  async requireBrowserAbsent(){
   if(browser){
    const result=await control.observe(request('retire',browser.identity.pid,main.identity,browser));
    if(result.groupAbsent!==true)throw fail('V03_MAIN_BROWSER_UNJOINED');
   }
   if(control.pending.size||control.debts.length)throw fail('V03_MAIN_CONTROL_DEBT');
  },
  retire(){
   if(retirement)return retirement;
   retirement=(async()=>{
    const errors=[];
    if(browser)try{await value.requireBrowserAbsent();}catch(error){errors.push(error.code||'V03_BROWSER_RETIREMENT');}
    let result;
    try{result=await control.observe(request('retire',child.pid,null,main));}catch(error){errors.push(error.code||'V03_MAIN_RETIREMENT');}
    if(errors.length||control.pending.size||control.debts.length||result?.groupAbsent!==true)
     throw Object.assign(fail('V03_MAIN_RETIREMENT_UNPROVEN'),{cleanupDebt:true,errors});
    return Object.freeze({groupAbsent:true});
   })();return retirement;
  }
 });handles.set(value,{child,control,owner});return value;
}
async function createMainProcess(options){
 if(!LIVE_ENABLED)throw fail('V03_MAIN_PROCESS_NOT_ADMITTED');
 if(!options||Object.keys(options).sort().join(',')!=='expectedMainArgvSha256,expectedPythonSha256,mainArgv,owner,root,sourcePins')throw fail('V03_MAIN_PROCESS_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.owner);
 const admission=require('./ownedV03MainAdmission'),root=path.resolve(__dirname,'../..');
 if(options.root!==root||owner.isRevoked())throw fail('V03_MAIN_PROCESS_BINDING');
 const binding=owner.binding(),window=owner.wrapperWindow();
 const expectedParent=[path.join(root,'tasks/runtime/node/node_modules/node/bin/node'),
  path.join(root,'tests/postgres/ownedV03PrivateExecutors.js'),'--v03-main-parent',binding.runId,binding.planSha256];
 if(JSON.stringify(process.argv)!==JSON.stringify(expectedParent))throw fail('V03_MAIN_PARENT_ARGV');
 const mainArgv=options.mainArgv;
 const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
 if(!Array.isArray(mainArgv)||mainArgv[0]!==path.join(root,'tests/postgres/run-secureshop-agent-host-transport-main.py')
  ||mainArgv.some(x=>typeof x!=='string'||x.includes('\0'))
  ||sha(JSON.stringify(mainArgv))!==options.expectedMainArgvSha256)throw fail('V03_MAIN_ARGV');
 for(const [flag,value]of [['--v03-private-run-id',binding.runId],['--v03-private-plan-sha256',binding.planSha256],
  ['--v03-private-channel-fd','3'],['--v03-private-admission-fd','4']]){
  const indexes=mainArgv.flatMap((x,i)=>x===flag?[i]:[]);
  if(indexes.length!==1||mainArgv[indexes[0]+1]!==value)throw fail('V03_MAIN_ARGV');
 }
 await admission.verifySources(root,options.sourcePins);
 const python='/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python';
 const bytes=await require('./ownedSystemConfigPhaseDriver')._internals.regular(python,64*1024**2);
 if(sha(bytes)!==options.expectedPythonSha256)throw fail('V03_MAIN_PYTHON');
 for(const file of ['v03_private_process.py','ownedV03MainProcess.js','ownedV03MainAdmission.js','ownedV03ParentProtocol.js'])
  if(!/^[a-f0-9]{64}$/.test(options.sourcePins['tests/postgres/'+file]||''))throw fail('V03_MAIN_SOURCE_SET');
 const directory=path.join(root,'tasks/tmp','v03-main-'+binding.runId);
 await fs.mkdir(directory,{mode:0o700});
 const journal=[],control=inspector(root,python,options.sourcePins['tests/postgres/darwin_process_inventory.py'],journal);
 let fd4,stdout,stderr,child,handle,primary,terminal;
 try{
  const parent=await control.observe({version:1,op:'parent',pid:process.pid,mainIdentity:null,expected:null});
  if(JSON.stringify(parent.observed.argv)!==JSON.stringify(expectedParent))throw fail('V03_MAIN_PARENT_ARGV');
  fd4=await admission.writeAdmission(owner,directory,options.sourcePins,parent.observed.identity,mainArgv);
  for(const name of ['stdout','stderr']){
   const fd=await fs.open(path.join(directory,'main.'+name),native.constants.O_WRONLY|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
   if(name==='stdout')stdout=fd;else stderr=fd;
  }
  await admission.verifySources(root,options.sourcePins);
  if(owner.wrapperWindow()!==window||owner.nowMs()>=window.deadlineMs)throw fail('V03_MAIN_WRAPPER_EXPIRED');
  child=spawn(python,['-B',...mainArgv],{cwd:root,detached:true,
   stdio:['ignore',stdout.fd,stderr.fd,'pipe',fd4.fd],env:{PATH:path.join(root,'tasks/runtime/node/node_modules/node/bin')+':/usr/bin:/bin',
    ...(process.env.HOME?{HOME:process.env.HOME}:{}),TMPDIR:path.join(root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});
  // Subscribe before any asynchronous birth lookup, including a very early
  // spawn/exit failure. Process disappearance is not a successful child exit.
  terminal=childTerminal(child,owner.nowMs);
  // Retain the child immediately. No absence claim follows a failed birth read.
  const birth=await control.observe({version:1,op:'inspect',pid:child.pid,mainIdentity:null,expected:null});
  if(JSON.stringify(birth.observed.argv)!==JSON.stringify([python,'-B',...mainArgv]))throw fail('V03_MAIN_CHILD_ARGV');
  handle=handleFor(child,child.stdio[3],control,birth.observed,terminal,owner);
 }catch(error){primary=error;primary.cleanupDebt=true;primary.mainPid=child?.pid||null;primary.processJournal=journal;
  primary.mainTerminal=terminal?.snapshot()||null;
 }finally{
  for(const fd of [fd4,stdout,stderr])if(fd)try{await fd.close();}catch(error){
   primary ||= error;primary.cleanupDebt=true;primary.mainFileCloseUnproven=true;
  }
 }
 if(primary){
  if(handle)try{await handle.retire();}catch{primary.mainRetirementUnproven=true;}
  throw primary;
 }
 return handle;
}
async function createLocalObserver(options){
 if(!options||Object.keys(options).sort().join(',')!=='expectedPythonSha256,owner,root,sourcePins')throw fail('V03_LOCAL_OBSERVER_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.owner);
 const root=path.resolve(__dirname,'../..');if(options.root!==root||owner.isRevoked())throw fail('V03_LOCAL_OBSERVER_BINDING');
 await require('./ownedV03MainAdmission').verifySources(root,options.sourcePins);
 for(const name of ['v03_private_process.py','ownedV03MainProcess.js'])
  if(!/^[a-f0-9]{64}$/.test(options.sourcePins['tests/postgres/'+name]||''))throw fail('V03_LOCAL_OBSERVER_SOURCE');
 const python='/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python';
 const bytes=await require('./ownedSystemConfigPhaseDriver')._internals.regular(python,64*1024**2);
 if(crypto.createHash('sha256').update(bytes).digest('hex')!==options.expectedPythonSha256)throw fail('V03_MAIN_PYTHON');
 const journal=[],control=inspector(root,python,options.sourcePins['tests/postgres/darwin_process_inventory.py'],journal);
 return Object.freeze({observe:control.observe,status:()=>Object.freeze({pending:control.pending.size,debts:control.debts.length}),
  receipts:()=>JSON.parse(JSON.stringify(journal))});
}
module.exports={createMainProcess,assertMainProcess,createLocalObserver};
