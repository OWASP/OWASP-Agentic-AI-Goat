'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process'),{randomUUID}=require('node:crypto'),vm=require('node:vm');
const file=path.resolve(__dirname,'../scripts/lib/setup-local-process-identity.js'),api=require(file);
const retainedRoots=new Set();
function ownedCapture(child,target){
 let timer,settled=false;
 const captured=new Promise((resolve,reject)=>{
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);child.off('message',message);child.off('exit',exit);error?reject(error):resolve(value);};
  const message=value=>finish(null,value),exit=()=>finish(Error('Owned child exited before capture'));
  child.once('message',message);child.once('exit',exit);
  child.on('error',error=>finish(error));
  timer=setTimeout(()=>finish(Error('Owned IPC readiness deadline')),15000);
 });
 async function close(){
  if(child.exitCode!==null||child.signalCode!==null)return;
  if(!Number.isSafeInteger(child.pid)||child.pid<=1){retainedRoots.add(target.workspaceRoot);throw Error('Owned child identity unavailable; fixture retained');}
  const exited=new Promise(resolve=>child.once('exit',()=>resolve(true)));
  let deadline;
  try{
   if(child.connected)child.send('finish',()=>{});
   const gone=await Promise.race([exited,new Promise(resolve=>{deadline=setTimeout(()=>resolve(false),15000);})]);
   if(!gone){retainedRoots.add(target.workspaceRoot);throw Error('Owned cooperative exit deadline; fixture retained for outer group retirement');}
  }finally{clearTimeout(deadline);}
 }
 return {captured,close};
}
function expected(t){const workspaceRoot=fs.mkdtempSync(path.join(os.tmpdir(),'local-process-proof-'));t.after(()=>{if(!retainedRoots.has(workspaceRoot))fs.rmSync(workspaceRoot,{recursive:true,force:true});});return{workspaceRoot,installationId:randomUUID(),operationId:randomUUID()};}
function variant(overrides,localProcess=process){const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,require:n=>overrides[n]||require(n),process:localProcess,Buffer});return module.exports;}
test('real owned parent and child refuse while alive then establish only recorded absence after cooperative exit',async t=>{
 const target=expected(t);const worker=`const a=require(${JSON.stringify(file)});setTimeout(()=>process.exit(2),10000).unref();process.send(a.captureLocalProcessBinding(${JSON.stringify(target)}));process.on('message',()=>process.exit(0));`;
 const parent=`const {spawn}=require('child_process');setTimeout(()=>process.exit(2),12000).unref();const c=spawn(process.execPath,['-e',${JSON.stringify(worker)}],{stdio:['ignore','ignore','inherit','ipc']});c.on('message',x=>process.send(x));process.on('message',()=>c.send('finish'));c.on('exit',code=>process.exit(code||0));`;
 const child=cp.spawn(process.execPath,['-e',parent],{stdio:['ignore','ignore','inherit','ipc']});const owned=ownedCapture(child,target);let record;
 try{record=await owned.captured;assert.equal(record.owner.ppid,record.parent.pid);assert.equal(record.ancestry,'unqualified');assert.throws(()=>api.verifyRecordedProcessesAbsent(record,target),{code:'LOCAL_PROCESS_STILL_PRESENT'});}finally{await owned.close();}
 assert.deepEqual(api.verifyRecordedProcessesAbsent(record,target),{recordedProcessesAbsent:true,recoveryAuthorized:false,ancestry:'unqualified',databaseDrain:'not-checked'});
});
test('closed identities reject malformed foreign host boot operation and parent binding',t=>{const target=expected(t),record=api.captureLocalProcessBinding(target);for(const patch of [{version:2},{hostSha256:'0'.repeat(64)},{bootId:randomUUID()},{operationId:randomUUID()},{extra:true},{ancestry:'trusted'}])assert.throws(()=>api.verifyRecordedProcessesAbsent({...record,...patch},target));assert.throws(()=>api.verifyRecordedProcessesAbsent({...record,parent:{...record.parent,pid:record.parent.pid+1}},target));assert.throws(()=>api.captureLocalProcessBinding({...target,extra:true}));});
test('live reused identity is refused without birth comparison or signaling',t=>{const target=expected(t),record=api.captureLocalProcessBinding(target);const changed={...record,owner:{...record.owner,startTicks:record.platform==='linux'?'1':null}};assert.throws(()=>api.verifyRecordedProcessesAbsent(changed,target),{code:'LOCAL_PROCESS_STILL_PRESENT'});assert.deepEqual([...fs.readFileSync(file,'utf8').matchAll(/process\.kill\(([^)]*)\)/g)].map(m=>m[1]),['pid,0']);});
test('permission and malformed process probe responses are unknown, never absent',t=>{const target=expected(t);const native=process.platform;const bad=native==='darwin'?variant({'node:child_process':{...cp,execFileSync:(bin,args,opts)=>{if(bin==='/bin/ps')throw Object.assign(Error('denied'),{code:'EACCES'});return cp.execFileSync(bin,args,opts);}}}):variant({'node:fs':{...fs,readFileSync:(p,...args)=>{if(String(p).startsWith('/proc/'))throw Object.assign(Error('denied'),{code:'EACCES'});return fs.readFileSync(p,...args);}}});assert.throws(()=>bad.captureLocalProcessBinding(target),{code:'LOCAL_PROCESS_PROBE_UNKNOWN'});if(native==='darwin'){const malformed=variant({'node:child_process':{...cp,execFileSync:(bin,args,opts)=>bin==='/bin/ps'?'not a process table':cp.execFileSync(bin,args,opts)}});assert.throws(()=>malformed.captureLocalProcessBinding(target),{code:'LOCAL_PROCESS_PROBE_UNKNOWN'});}});
test('symlink workspace cannot bind a process proof',t=>{const target=expected(t),link=target.workspaceRoot+'-link';fs.symlinkSync(target.workspaceRoot,link);t.after(()=>fs.unlinkSync(link));assert.throws(()=>api.captureLocalProcessBinding({...target,workspaceRoot:link}),{code:'LOCAL_PROCESS_BINDING_INVALID'});});

test('Linux proc start ticks parse losslessly and PID reuse still refuses before absence',t=>{const target=expected(t),uid=process.getuid(),local=Object.create(process);Object.defineProperties(local,{platform:{value:'linux'},pid:{value:500},ppid:{value:400},kill:{value:()=>{throw Object.assign(Error('absent'),{code:'ESRCH'});}}});const live=new Map([[500,400],[400,300]]);let ticks='9007199254740993';const controlled=variant({'node:fs':{...fs,readlinkSync:p=>p.endsWith('/pid')?'pid:[123]':'user:[456]',readFileSync:(p,...args)=>{if(p==='/etc/machine-id')return 'a'.repeat(32);if(p==='/proc/sys/kernel/random/boot_id')return 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';if(p==='/proc/self/stat')return 'observable';const m=String(p).match(/^\/proc\/(\d+)\/(stat|status)$/);if(!m)return fs.readFileSync(p,...args);const pid=Number(m[1]);if(!live.has(pid))throw Object.assign(Error('gone'),{code:'ENOENT'});if(m[2]==='status')return `Uid: ${uid} ${uid} ${uid} ${uid}\n`;const fields=Array(20).fill('0');fields[0]='S';fields[1]=String(live.get(pid));fields[2]='400';fields[19]=ticks;return `${pid} (name with ) parentheses) ${fields.join(' ')}`;}}},local);const record=controlled.captureLocalProcessBinding(target);assert.equal(record.owner.startTicks,'9007199254740993');for(const startTicks of [1,9007199254740993])assert.throws(()=>controlled.verifyRecordedProcessesAbsent({...record,owner:{...record.owner,startTicks}},target),{code:'LOCAL_PROCESS_BINDING_INVALID'});ticks='2';assert.throws(()=>controlled.verifyRecordedProcessesAbsent(record,target),{code:'LOCAL_PROCESS_STILL_PRESENT'});live.clear();assert.equal(controlled.verifyRecordedProcessesAbsent(record,target).recoveryAuthorized,false);});

test('Linux hidden proc entries require ESRCH; live, EPERM, unknown and unavailable procfs deny',t=>{
 const target=expected(t),local=Object.create(process),uid=process.getuid();let hidden=false,unavailable=false,probeResult='ESRCH',probes=[];Object.defineProperties(local,{platform:{value:'linux'},pid:{value:500},ppid:{value:400},kill:{value:(pid,signal)=>{probes.push([pid,signal]);assert.equal(signal,0);if(probeResult==='present')return true;throw Object.assign(Error('probe'),{code:probeResult});}}});
 const api=variant({'node:fs':{...fs,readlinkSync:p=>p.endsWith('/pid')?'pid:[123]':'user:[456]',readFileSync:(p,...args)=>{if(p==='/etc/machine-id')return 'a'.repeat(32);if(p==='/proc/sys/kernel/random/boot_id')return 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';if(p==='/proc/self/stat'){if(unavailable)throw Object.assign(Error('proc unavailable'),{code:'EACCES'});return 'observable';}const m=String(p).match(/^\/proc\/(\d+)\/(stat|status)$/);if(!m)return fs.readFileSync(p,...args);if(hidden)throw Object.assign(Error('hidden or absent'),{code:'ENOENT'});if(m[2]==='status')return `Uid: ${uid} ${uid} ${uid} ${uid}\n`;const f=Array(20).fill('0');f[0]='S';f[1]=Number(m[1])===500?'400':'300';f[2]='400';f[19]='100';return `${m[1]} (owned) ${f.join(' ')}`;}}},local);
 const record=api.captureLocalProcessBinding(target);assert.throws(()=>api.verifyRecordedProcessesAbsent({...record,pidNamespace:'pid:[999]'},target),{code:'LOCAL_PROCESS_BINDING_MISMATCH'});hidden=true;for(const code of ['present','EPERM','EACCES','UNKNOWN']){probeResult=code;assert.throws(()=>api.verifyRecordedProcessesAbsent(record,target),{code:code==='present'?'LOCAL_PROCESS_STILL_PRESENT':'LOCAL_PROCESS_PROBE_UNKNOWN'});}probeResult='ESRCH';assert.equal(api.verifyRecordedProcessesAbsent(record,target).recordedProcessesAbsent,true);assert(probes.every(([,s])=>s===0));unavailable=true;const count=probes.length;assert.throws(()=>api.verifyRecordedProcessesAbsent(record,target),{code:'LOCAL_PROCESS_PROBE_UNKNOWN'});assert.equal(probes.length,count);
});
test('unsafe integer process table values fail closed on macOS',t=>{if(process.platform!=='darwin')return;const target=expected(t),bad=variant({'node:child_process':{...cp,execFileSync:(bin,args,opts)=>bin==='/bin/ps'?`${process.pid} ${process.ppid} 9007199254740993 ${process.getuid()}`:cp.execFileSync(bin,args,opts)}});assert.throws(()=>bad.captureLocalProcessBinding(target),{code:'LOCAL_PROCESS_PROBE_UNKNOWN'});});

function ancestryHarness(t){
 const target=expected(t),uid=process.getuid(),local=Object.create(process);Object.defineProperties(local,{platform:{value:'darwin'},pid:{value:500},ppid:{value:400}});
 const rows=new Map([[500,{ppid:400,uid}],[400,{ppid:300,uid}],[300,{ppid:1,uid}],[1,{ppid:0,uid:0}]]);let calls=0,alter;
 const controlled=variant({'node:child_process':{...cp,execFileSync:(bin)=>{if(bin==='/usr/sbin/sysctl')return 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';if(bin==='/usr/sbin/ioreg')return '"IOPlatformUUID" = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"';if(bin==='/bin/ps'){calls++;if(alter)alter(calls,rows);return [...rows].map(([pid,p])=>`${pid} ${p.ppid} ${pid} ${p.uid}`).join('\n');}throw Error('Unexpected process command');}}},local);
 return {target,rows,api:controlled,setAlter:fn=>{alter=fn;},uid};
}
test('v2 captures complete bounded chain and rejects every live ancestor or reused PID',t=>{
 const h=ancestryHarness(t),r=h.api.captureLocalAncestorBinding(h.target);assert.equal(r.version,2);assert.deepEqual(Array.from(r.ancestors,p=>p.pid),[500,400,300]);assert.equal(r.boundary.kind,'init');assert.equal(r.ancestors[0].startTicks,null);
 assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent(r,h.target),{code:'LOCAL_PROCESS_STILL_PRESENT'});
 // Keep observer self row present while recorded PIDs are absent using a distinct probe identity.
 const original=r.ancestors.map(p=>({...p,pid:p.pid+1000,ppid:p.ppid===1?1:p.ppid+1000}));const absent={...r,ancestors:original};
 assert.equal(h.api.verifyRecordedAncestorChainAbsent(absent,h.target).recoveryAuthorized,false);
 h.rows.set(1300,{ppid:1,uid:h.uid+1});assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent(absent,h.target),{code:'LOCAL_PROCESS_STILL_PRESENT'});
});
test('v2 refuses reparenting, cycles, truncation and malformed boundary',t=>{
 let h=ancestryHarness(t);h.setAlter((n,rows)=>{if(n===5)rows.get(400).ppid=1;});assert.throws(()=>h.api.captureLocalAncestorBinding(h.target),{code:'LOCAL_PROCESS_ANCESTRY_CHANGED'});
 h=ancestryHarness(t);h.rows.get(300).ppid=400;assert.throws(()=>h.api.captureLocalAncestorBinding(h.target),{code:'LOCAL_PROCESS_ANCESTRY_CYCLE'});
 h=ancestryHarness(t);h.rows.clear();for(let pid=500;pid>460;pid--)h.rows.set(pid,{ppid:pid-1,uid:h.uid});assert.throws(()=>h.api.captureLocalAncestorBinding(h.target),{code:'LOCAL_PROCESS_ANCESTRY_TRUNCATED'});
 h=ancestryHarness(t);const r=h.api.captureLocalAncestorBinding(h.target);assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent({...r,ancestors:r.ancestors.slice(0,2)},h.target),{code:'LOCAL_PROCESS_BINDING_INVALID'});
 assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent({...r,boundary:{kind:'trusted-shell',process:r.boundary.process}},h.target),{code:'LOCAL_PROCESS_BINDING_INVALID'});
});
test('v2 records foreign UID boundary without treating it as owned or authorizing recovery',t=>{const h=ancestryHarness(t);h.rows.get(300).uid=h.uid+1;const r=h.api.captureLocalAncestorBinding(h.target);assert.equal(r.boundary.kind,'foreign-uid');assert.equal(r.ancestors.length,2);assert.equal(r.boundary.process.pid,300);});
test('real cooperative child v2 retains live test parent in complete chain after child exit',async t=>{
 const target=expected(t),program=`const a=require(${JSON.stringify(file)});process.send(a.captureLocalAncestorBinding(${JSON.stringify(target)}));process.on('message',()=>process.exit(0));setTimeout(()=>process.exit(2),10000).unref();`;
 const child=cp.spawn(process.execPath,['-e',program],{stdio:['ignore','ignore','inherit','ipc']});const owned=ownedCapture(child,target);let record;
 try{record=await owned.captured;assert(record.ancestors.some(p=>p.pid===process.pid));assert.throws(()=>api.verifyRecordedAncestorChainAbsent(record,target),{code:'LOCAL_PROCESS_STILL_PRESENT'});}finally{await owned.close();}
 assert.throws(()=>api.verifyRecordedAncestorChainAbsent(record,target),{code:'LOCAL_PROCESS_STILL_PRESENT'});
});
