'use strict';
// Fixed pipe-owned listener process. Only the real combined owner can create it.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const {spawn}=require('node:child_process');
const handles=new WeakMap(),CAP=16384;
const fail=code=>Object.assign(new Error(code),{code});
function assertListingsBridgeHost(value){if(!handles.has(value))throw fail('V03_BRIDGE_HOST_REQUIRED');return value;}
function terminalClean(terminal,local){
 return terminal?.failure===null&&terminal.cleanupDebt===false&&terminal.leaseSourceCloseUnproven===false
  &&JSON.stringify(terminal.local)===JSON.stringify(local)&&local?.listenerClosed===true&&local.localChannelsRetired===true;
}
function clockMap(packet,sent,received){
 if(!Number.isSafeInteger(sent)||!Number.isSafeInteger(received)||received<sent||received-sent+1>2000
  ||!Number.isSafeInteger(packet.monotonicMs)||packet.monotonicMs<0)throw fail('V03_BRIDGE_CLOCK');
 const lower=packet.monotonicMs-received-1,uncertaintyMs=received-sent+1;
 return Object.freeze({uncertaintyMs,map(value){
  if(!Number.isSafeInteger(value)||value<=received)throw fail('V03_BRIDGE_CLOCK');
  return value+lower;
 }});
}
async function createListingsBridgeHost(options){
 if(!options||Object.keys(options).sort().join(',')!=='expectedPythonSha256,owner,root,sourcePins')throw fail('V03_BRIDGE_HOST_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.owner);
 const binding=owner.producerBinding('listings'),window=owner.phaseWindow('listingsStartupMs');
 const signal=owner.phaseSignal('listingsStartupMs'),root=path.resolve(__dirname,'../..');
 if(options.root!==root)throw fail('V03_BRIDGE_HOST_ROOT');
 await require('./ownedV03MainAdmission').verifySources(root,options.sourcePins);
 for(const name of ['v03_listings_bridge_host.py','v03_listings_bridge.py','ownedV03ListingsBridgeHost.js','ownedV03ListingsLease.js'])
  if(!/^[a-f0-9]{64}$/.test(options.sourcePins['tests/postgres/'+name]||''))throw fail('V03_BRIDGE_HOST_SOURCE');
 const observer=await require('./ownedV03MainProcess').createLocalObserver(options);
 const python='/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python';
 const directory=path.join(root,'tasks/tmp','v03-listings-bridge-'+binding.runId);
 await fs.mkdir(directory,{mode:0o700});
 let journal,stderr,child,birth,primary;
 const debts=[];let terminal=null,closed=false,exitCode=null,buffer=Buffer.alloc(0),sequence=0,waiting=null,hello=null;
 let writes=Promise.resolve();
 const record=row=>{writes=writes.then(async()=>{
  const raw=Buffer.from(JSON.stringify(row)+'\n');if(raw.length>65536)throw fail('V03_BRIDGE_JOURNAL_BOUND');
  await journal.writeFile(raw);await journal.sync();
 });writes.catch(()=>{if(!debts.includes('V03_BRIDGE_JOURNAL'))debts.push('V03_BRIDGE_JOURNAL');});};
 function waitFor(predicate,deadline){
  return new Promise((resolve,reject)=>{
   const check=()=>{
    if(predicate())return resolve();
    if(owner.nowMs()>=deadline)return reject(fail('V03_BRIDGE_WAIT_EXPIRED'));
    setTimeout(check,Math.min(20,deadline-owner.nowMs()));
   };check();
  });
 }
 try{
  journal=await fs.open(path.join(directory,'host.jsonl'),native.constants.O_WRONLY|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
  stderr=await fs.open(path.join(directory,'host.stderr'),native.constants.O_WRONLY|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
  signal.throwIfAborted();if(owner.phaseWindow('listingsStartupMs')!==window)throw fail('V03_BRIDGE_PHASE');
  const sent=owner.nowMs();
  child=spawn(python,['-B',path.join(root,'tests/postgres/v03_listings_bridge_host.py'),root,binding.runId,binding.parentRunId,
   binding.planSha256,options.sourcePins['tests/postgres/ownedV03ListingsLease.js']],{cwd:root,detached:true,
   stdio:['pipe','pipe',stderr.fd],env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});
  child.once('error',()=>debts.push('V03_BRIDGE_SPAWN'));
  child.stdin.on('error',()=>debts.push('V03_BRIDGE_PIPE'));
  child.once('close',code=>{closed=true;exitCode=code;});
  child.stdout.on('data',chunk=>{
   buffer=Buffer.concat([buffer,chunk]);if(buffer.length>CAP){debts.push('V03_BRIDGE_FRAME_BOUND');child.stdin.end();return;}
   for(let at;(at=buffer.indexOf(10))>=0;){
    const raw=buffer.subarray(0,at+1).toString();buffer=buffer.subarray(at+1);
    try{
     const row=JSON.parse(raw);if(JSON.stringify(row)+'\n'!==raw||row.version!==1||row.runId!==binding.runId||row.planSha256!==binding.planSha256)throw fail('V03_BRIDGE_RESPONSE');
     record(row);
     if(row.stage==='hello'&&!hello){hello={row,received:owner.nowMs()};}
     else if(row.stage==='terminal'&&!terminal)terminal=row;
     else if(waiting&&row.sequence===waiting.sequence&&row.op===waiting.op){waiting.result=row.result;waiting.done=true;}
     else throw fail('V03_BRIDGE_UNEXPECTED_RESPONSE');
    }catch{debts.push('V03_BRIDGE_RESPONSE');child.stdin.end();}
   }
  });
  await waitFor(()=>hello||closed||debts.length,Math.min(window.deadlineMs,sent+2000));
  if(!hello||debts.length||hello.row.pid!==child.pid||hello.row.parentPid!==process.pid)throw fail('V03_BRIDGE_HELLO');
  const mapping=clockMap(hello.row,sent,hello.received);
  birth=(await observer.observe({version:1,op:'inspect',pid:child.pid,mainIdentity:null,expected:null})).observed;
  const expected=[python,'-B',path.join(root,'tests/postgres/v03_listings_bridge_host.py'),root,binding.runId,binding.parentRunId,binding.planSha256,options.sourcePins['tests/postgres/ownedV03ListingsLease.js']];
  if(JSON.stringify(birth.argv)!==JSON.stringify(expected))throw fail('V03_BRIDGE_CHILD_ARGV');
  async function exchange(op,payload,deadline){
   if(waiting||closed||debts.length||owner.nowMs()>=deadline)throw fail('V03_BRIDGE_INACTIVE');
   const request={version:1,runId:binding.runId,planSha256:binding.planSha256,sequence:sequence++,op,payload};
   const raw=Buffer.from(JSON.stringify(request)+'\n');if(raw.length>CAP)throw fail('V03_BRIDGE_FRAME_BOUND');
   waiting={op,sequence:request.sequence,done:false};
   try{
    child.stdin.write(raw,error=>{if(error)debts.push('V03_BRIDGE_PIPE');});
    await waitFor(()=>waiting.done||closed||debts.length,deadline);
    if(!waiting.done||debts.length)throw fail('V03_BRIDGE_RESPONSE_UNPROVEN');return waiting.result;
   }catch(error){debts.push(error.code||'V03_BRIDGE_EXCHANGE');throw error;}
   finally{waiting=null;}
  }
  let stage='new',retirement=null;
  const value=Object.freeze({
   uncertaintyMs:()=>mapping.uncertaintyMs,
   async start(){
    if(stage!=='new')throw fail('V03_BRIDGE_START_ONCE');stage='starting';
    const current=owner.phaseWindow('listingsStartupMs');
    const result=await exchange('start',{startupDeadlineMs:mapping.map(current.deadlineMs),parentDeadlineMs:mapping.map(binding.expiresAtMs)},current.deadlineMs);
    if(!result||!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/.test(result.origin||''))throw fail('V03_BRIDGE_ORIGIN');
    stage='ready';return result;
   },
   async claim(handoff,guestRecord){
    if(stage!=='ready')throw fail('V03_BRIDGE_CLAIM_ONCE');stage='claiming';
    const current=owner.phaseWindow('cohortClaim'),uncertainty=owner.clockMapping().uncertaintyMs();
    const result=await exchange('claim',{handoff,guestRecord,hostDeadlineMs:mapping.map(owner.cohortDeadlineMs()-uncertainty),
     activationDeadlineMs:mapping.map(current.deadlineMs-uncertainty)},current.deadlineMs);
    if(result?.claimed!==true)throw fail('V03_BRIDGE_CLAIM_UNPROVEN');stage='claimed';return result;
   },
   close(){
    if(retirement)return retirement;
    const current=owner.phaseWindow('listingsRetirementMs');
    if(!owner.isRevoked())throw fail('V03_BRIDGE_RETIREMENT_ORDER');
    retirement=(async()=>{
     let local,failure=null,observed=null;
     try{local=await exchange('close',{},current.deadlineMs);}catch(error){failure=error;}
     try{child.stdin.end();}catch(error){failure ||= error;}
     try{await waitFor(()=>closed,current.deadlineMs);await writes;}catch(error){failure ||= error;}
     try{
      if(owner.phaseWindow('listingsRetirementMs')!==current||current.deadlineMs-owner.nowMs()<10000)throw fail('V03_BRIDGE_JOIN_RESERVE');
      owner.phaseSignal('listingsRetirementMs').throwIfAborted();
      observed=await observer.observe({version:1,op:'retire',pid:child.pid,mainIdentity:null,expected:birth});
     }
     catch(error){failure ||= error;}
     for(const fd of [journal,stderr])if(fd)try{await fd.close();}catch(error){failure ||= error;}
     journal=null;stderr=null;
     if(failure||exitCode!==0||!terminalClean(terminal,local)
      ||observed?.groupAbsent!==true||observer.status().pending||observer.status().debts||debts.length)
      throw Object.assign(failure||fail('V03_BRIDGE_RETIREMENT_UNPROVEN'),{cleanupDebt:true});
     stage='closed';return local;
    })();return retirement;
   },
   status:()=>Object.freeze({stage,closed,cleanupDebt:debts.length>0})
  });handles.set(value,{child,birth,observer});return value;
 }catch(error){primary=error;primary.cleanupDebt=true;primary.bridgePid=child?.pid||null;
  // A failed constructor still owns its spawned process. Retain the exact
  // observation and attempt retirement inside the original startup window;
  // an exhausted window or unknown identity never authorizes a signal.
  const partial={birth:birth||null,groupAbsent:false,closed:false,errors:[]};
  primary.bridgePartial=partial;
  try{child?.stdin.end();}catch(failure){partial.errors.push(failure.code||'V03_BRIDGE_EOF');}
  if(child?.pid){
   try{
    if(!birth){
     if(window.deadlineMs-owner.nowMs()<20000)throw fail('V03_BRIDGE_PARTIAL_OBSERVE_RESERVE');
     birth=(await observer.observe({version:1,op:'inspect',pid:child.pid,mainIdentity:null,expected:null})).observed;
     partial.birth=birth;
    }
    if(!birth||window.deadlineMs-owner.nowMs()<10000)throw fail('V03_BRIDGE_PARTIAL_JOIN_RESERVE');
    const proof=await observer.observe({version:1,op:'retire',pid:child.pid,mainIdentity:null,expected:birth});
    partial.groupAbsent=proof?.groupAbsent===true;
    await waitFor(()=>closed,window.deadlineMs);
   }catch(failure){partial.errors.push(failure.code||'V03_BRIDGE_PARTIAL_JOIN');}
  }
  partial.closed=closed;
  // Stop further journal producers before draining writes and closing files.
  // Destroying a local pipe does not establish process/group retirement.
  try{child?.stdout.removeAllListeners('data');child?.stdout.destroy();}catch(failure){partial.errors.push(failure.code||'V03_BRIDGE_PIPE_CLOSE');}
  try{await writes;}catch(failure){partial.errors.push(failure.code||'V03_BRIDGE_JOURNAL');}
  partial.observer=observer.status();
  throw primary;
 }finally{
  if(primary)for(const fd of [journal,stderr])if(fd)try{await fd.close();}catch{primary.bridgeFileCloseUnproven=true;}
 }
}
module.exports={createListingsBridgeHost,assertListingsBridgeHost};
