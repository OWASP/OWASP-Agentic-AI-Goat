'use strict';
// Observation only. Linux kill(pid, 0) probes existence without delivering a signal.
// No nonzero signal, recovery token, process termination or PID adoption.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),{createHash}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail=code=>Object.assign(new Error('Local process proof unavailable'),{code});
const hash=value=>createHash('sha256').update(value).digest('hex');
const keys=(o,want)=>{if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).sort().join(',')!==want.split(',').sort().join(','))throw fail('LOCAL_PROCESS_BINDING_INVALID');};
function host(){
 if(process.platform==='linux'){const machine=fs.readFileSync('/etc/machine-id','utf8').trim(),boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();if(!/^[0-9a-f]{32}$/i.test(machine)||!UUID.test(boot))throw fail('LOCAL_PROCESS_HOST_UNAVAILABLE');const pidNamespace=fs.readlinkSync('/proc/self/ns/pid'),userNamespace=fs.readlinkSync('/proc/self/ns/user');if(!/^pid:\[[0-9]+\]$/.test(pidNamespace)||!/^user:\[[0-9]+\]$/.test(userNamespace))throw fail('LOCAL_PROCESS_HOST_UNAVAILABLE');return{platform:'linux',hostSha256:hash(machine.toLowerCase()),bootId:boot.toLowerCase(),pidNamespace,userNamespace};}
 if(process.platform==='darwin'){const run=(bin,args)=>cp.execFileSync(bin,args,{encoding:'utf8',timeout:3000,maxBuffer:4*1024*1024,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LC_ALL:'C'}});const boot=run('/usr/sbin/sysctl',['-n','kern.bootsessionuuid']).trim(),matches=[...run('/usr/sbin/ioreg',['-rd1','-c','IOPlatformExpertDevice']).matchAll(/"IOPlatformUUID"\s*=\s*"([0-9a-f-]+)"/gi)];if(!UUID.test(boot)||matches.length!==1||!UUID.test(matches[0][1]))throw fail('LOCAL_PROCESS_HOST_UNAVAILABLE');return{platform:'darwin',hostSha256:hash(matches[0][1].toLowerCase()),bootId:boot.toLowerCase(),pidNamespace:null,userNamespace:null};}
 throw fail('LOCAL_PROCESS_PLATFORM_UNSUPPORTED');
}
function probe(pid){
 if(process.platform==='linux'){
  // Missing proc entry means absence only when procfs itself remains observable.
  fs.readFileSync('/proc/self/stat','utf8');let stat;
  try{stat=fs.readFileSync(`/proc/${pid}/stat`,'utf8');}catch(e){
   if(e.code!=='ENOENT')throw e;
   // hidepid and namespace restrictions can hide live proc entries. ESRCH from
   // an independent zero-signal kernel probe is required; EPERM is not absence.
   try{process.kill(pid,0);}catch(probeError){if(probeError.code==='ESRCH')return null;throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');}
   throw fail('LOCAL_PROCESS_STILL_PRESENT');
  }
  const match=stat.match(/^(\d+) \(.*\) (.+)$/s);if(!match||Number(match[1])!==pid)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');const fields=match[2].trim().split(/\s+/),status=fs.readFileSync(`/proc/${pid}/status`,'utf8'),uids=status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)$/m);
  if(!uids||!uids.slice(1).every(x=>x===uids[1])||!/^\d+$/.test(fields[19]||''))throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');const ppid=Number(fields[1]),pgid=Number(fields[2]),uid=Number(uids[1]);if(![pid,ppid,pgid,uid].every(Number.isSafeInteger)||pid<1||ppid<0||pgid<0||uid<0)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');return{pid,ppid,pgid,uid,startTicks:fields[19]};
 }
 if(process.platform==='darwin'){
  // A successful complete table avoids treating ps exit1/permission errors as absence.
  const output=cp.execFileSync('/bin/ps',['-axo','pid=,ppid=,pgid=,uid='],{encoding:'utf8',timeout:3000,maxBuffer:4*1024*1024,env:{PATH:'/usr/bin:/bin',LC_ALL:'C'}});let found=null,own=false;
  for(const line of output.trim().split('\n')){const m=line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)$/);if(!m)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');const [p,ppid,pgid,uid]=m.slice(1).map(Number);if(![p,ppid,pgid,uid].every(Number.isSafeInteger)||p<1||ppid<0||pgid<0)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');if(p===process.pid)own=true;if(p===pid){if(found)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');found={pid:p,ppid,pgid,uid,startTicks:null};}}
  if(!own)throw fail('LOCAL_PROCESS_PROBE_UNKNOWN');return found;
 }
 throw fail('LOCAL_PROCESS_PLATFORM_UNSUPPORTED');
}
function target(value){keys(value,'workspaceRoot,installationId,operationId');if(!path.isAbsolute(value.workspaceRoot)||!UUID.test(value.installationId)||!UUID.test(value.operationId))throw fail('LOCAL_PROCESS_BINDING_INVALID');const st=fs.lstatSync(value.workspaceRoot);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid())throw fail('LOCAL_PROCESS_BINDING_INVALID');return{workspaceSha256:hash(fs.realpathSync(value.workspaceRoot)),installationId:value.installationId,operationId:value.operationId};}
function windowsTarget(value){
 keys(value,'workspaceRoot,installationId,operationId');
 if(typeof value.workspaceRoot!=='string'||!path.isAbsolute(value.workspaceRoot)||typeof value.installationId!=='string'||!UUID.test(value.installationId)||typeof value.operationId!=='string'||!UUID.test(value.operationId))throw fail('LOCAL_PROCESS_BINDING_INVALID');
 const observed=require('./windows-private-state').inspectWorkspaceDirectory(value.workspaceRoot);
 // Keep the same realpath spelling/hash used by workspaceId; native admission
 // checks the requested directory and every ancestor before realpath is read.
 const canonical=fs.realpathSync(value.workspaceRoot);
 return {binding:{workspaceSha256:hash(canonical),installationId:value.installationId,operationId:value.operationId},canonical,path:observed.path,identity:observed.identity};
}
function recheckWindowsTarget(expected,first){
 const next=windowsTarget(expected);
 if(next.canonical!==first.canonical||next.path!==first.path||next.identity.volumeSerial!==first.identity.volumeSerial||next.identity.fileId!==first.identity.fileId)throw fail('LOCAL_PROCESS_BINDING_MISMATCH');
}
const WINDOWS_FIELDS='version,workspaceSha256,installationId,operationId,platform,hostSha256,bootFileTime,currentSid,ancestors,boundary,ancestry';
function windowsObserver(record){
 keys(record,WINDOWS_FIELDS);
 if(record.version!==3||record.platform!=='win32'||typeof record.workspaceSha256!=='string'||!/^[a-f0-9]{64}$/.test(record.workspaceSha256)||typeof record.installationId!=='string'||!UUID.test(record.installationId)||typeof record.operationId!=='string'||!UUID.test(record.operationId))throw fail('LOCAL_PROCESS_BINDING_INVALID');
 const {workspaceSha256,installationId,operationId,version,...observer}=record;
 return require('./windows-process-identity').validateWindowsProcessIdentityRecord({version:1,...observer});
}
function captureWindowsAncestorBinding(expected){
 const observed=windowsTarget(expected),native=require('./windows-process-identity').captureWindowsProcessIdentity();
 recheckWindowsTarget(expected,observed);
 const {version,...observer}=native;
 return Object.freeze({version:3,...observed.binding,...observer});
}
function verifyWindowsAncestorChainAbsent(record,expected){
 const observer=windowsObserver(record),observed=windowsTarget(expected);
 if(Object.entries(observed.binding).some(([k,v])=>record[k]!==v))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');
 const result=require('./windows-process-identity').verifyWindowsRecordedProcessesAbsent(observer);
 recheckWindowsTarget(expected,observed);return result;
}
function tuple(value,platform){keys(value,'pid,ppid,pgid,uid,startTicks');if(![value.pid,value.pgid].every(x=>Number.isSafeInteger(x)&&x>1)||!Number.isSafeInteger(value.ppid)||value.ppid<0||!Number.isSafeInteger(value.uid)||value.uid<0||(platform==='linux'?(typeof value.startTicks!=='string'||!/^[1-9][0-9]*$/.test(value.startTicks)):value.startTicks!==null))throw fail('LOCAL_PROCESS_BINDING_INVALID');}
function captureLocalProcessBinding(expected){try{if(process.platform==='win32')throw fail('LOCAL_PROCESS_PLATFORM_UNSUPPORTED');const binding=target(expected),h=host(),owner=probe(process.pid),parent=probe(process.ppid);tuple(owner,h.platform);tuple(parent,h.platform);if(owner.ppid!==parent.pid||owner.uid!==process.getuid()||parent.uid!==owner.uid)throw fail('LOCAL_PROCESS_PARENT_UNAVAILABLE');return Object.freeze({version:1,...binding,...h,owner:Object.freeze(owner),parent:Object.freeze(parent),ancestry:'unqualified'});}catch(e){throw fail(e.code?.startsWith('LOCAL_PROCESS_')?e.code:'LOCAL_PROCESS_PROBE_UNKNOWN');}}
function verifyRecordedProcessesAbsent(record,expected){try{
 if(process.platform==='win32')throw fail('LOCAL_PROCESS_PLATFORM_UNSUPPORTED');
 keys(record,'version,workspaceSha256,installationId,operationId,platform,hostSha256,bootId,pidNamespace,userNamespace,owner,parent,ancestry');const binding=target(expected),h=host();if(record.version!==1||record.ancestry!=='unqualified'||Object.entries({...binding,...h}).some(([k,v])=>record[k]!==v))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');tuple(record.owner,h.platform);tuple(record.parent,h.platform);if(record.owner.ppid!==record.parent.pid||record.owner.uid!==process.getuid()||record.parent.uid!==record.owner.uid)throw fail('LOCAL_PROCESS_BINDING_INVALID');
 // Any observable or kernel-present PID denies, including a different birth/UID.
 // No delivered signal or PID adoption; Linux zero-signal probe only after ENOENT.
 for(const p of [record.owner,record.parent])if(probe(p.pid)!==null)throw fail('LOCAL_PROCESS_STILL_PRESENT');
 if(JSON.stringify(host())!==JSON.stringify(h))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');return Object.freeze({recordedProcessesAbsent:true,recoveryAuthorized:false,ancestry:'unqualified',databaseDrain:'not-checked'});
 }catch(e){throw fail(e.code?.startsWith('LOCAL_PROCESS_')?e.code:'LOCAL_PROCESS_PROBE_UNKNOWN');}}
const MAX_ANCESTORS=32;
function boundaryTuple(value,platform){
 keys(value,'pid,ppid,pgid,uid,startTicks');
 if(![value.pid,value.pgid].every(x=>Number.isSafeInteger(x)&&x>=1)||!Number.isSafeInteger(value.ppid)||value.ppid<0||!Number.isSafeInteger(value.uid)||value.uid<0||(platform==='linux'?(typeof value.startTicks!=='string'||!/^[1-9][0-9]*$/.test(value.startTicks)):value.startTicks!==null))throw fail('LOCAL_PROCESS_BINDING_INVALID');
}
function validateChain(record,h){
 if(!Array.isArray(record.ancestors)||!record.ancestors.length||record.ancestors.length>MAX_ANCESTORS)throw fail('LOCAL_PROCESS_BINDING_INVALID');
 keys(record.boundary,'kind,process');boundaryTuple(record.boundary.process,h.platform);
 const seen=new Set();
 for(let i=0;i<record.ancestors.length;i++){
  const p=record.ancestors[i];tuple(p,h.platform);
  if(p.uid!==process.getuid()||seen.has(p.pid)||p.ppid!==(record.ancestors[i+1]||record.boundary.process).pid)throw fail('LOCAL_PROCESS_BINDING_INVALID');seen.add(p.pid);
 }
 const b=record.boundary.process;
 if(seen.has(b.pid)||!(record.boundary.kind==='init'&&b.pid===1||record.boundary.kind==='foreign-uid'&&b.pid!==1&&b.uid!==process.getuid()))throw fail('LOCAL_PROCESS_BINDING_INVALID');
}
function captureLocalAncestorBinding(expected){try{
 if(process.platform==='win32')return captureWindowsAncestorBinding(expected);
 const binding=target(expected),h=host(),deadline=Date.now()+10000,ancestors=[],seen=new Set();let pid=process.pid,boundary;
 while(true){
  if(Date.now()>deadline)throw fail('LOCAL_PROCESS_ANCESTRY_TIMEOUT');
  const p=probe(pid);boundaryTuple(p,h.platform);
  if(seen.has(pid))throw fail('LOCAL_PROCESS_ANCESTRY_CYCLE');seen.add(pid);
  if(pid===1||p.uid!==process.getuid()){boundary={kind:pid===1?'init':'foreign-uid',process:p};break;}
  tuple(p,h.platform);if(ancestors.length===MAX_ANCESTORS)throw fail('LOCAL_PROCESS_ANCESTRY_TRUNCATED');ancestors.push(p);
  if(p.ppid<1)throw fail('LOCAL_PROCESS_ANCESTRY_BOUNDARY_UNKNOWN');pid=p.ppid;
 }
 const record={version:2,...binding,...h,ancestors,boundary,ancestry:'complete-supported-chain'};validateChain(record,h);
 // Every parent link and observed tuple must survive a second observation.
 for(const p of [...ancestors,boundary.process]){
  if(Date.now()>deadline)throw fail('LOCAL_PROCESS_ANCESTRY_TIMEOUT');
  if(JSON.stringify(probe(p.pid))!==JSON.stringify(p))throw fail('LOCAL_PROCESS_ANCESTRY_CHANGED');
 }
 if(JSON.stringify(host())!==JSON.stringify(h))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');
 return Object.freeze({...record,ancestors:Object.freeze(ancestors.map(Object.freeze)),boundary:Object.freeze({...boundary,process:Object.freeze(boundary.process)})});
 }catch(e){throw fail(e.code?.startsWith('LOCAL_PROCESS_')?e.code:'LOCAL_PROCESS_PROBE_UNKNOWN');}}
function verifyRecordedAncestorChainAbsent(record,expected){try{
 if(process.platform==='win32')return verifyWindowsAncestorChainAbsent(record,expected);
 keys(record,'version,workspaceSha256,installationId,operationId,platform,hostSha256,bootId,pidNamespace,userNamespace,ancestors,boundary,ancestry');
 const binding=target(expected),h=host();
 if(record.version!==2||record.ancestry!=='complete-supported-chain'||Object.entries({...binding,...h}).some(([k,v])=>record[k]!==v))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');validateChain(record,h);
 const deadline=Date.now()+10000;
 for(const p of record.ancestors){if(Date.now()>deadline)throw fail('LOCAL_PROCESS_ANCESTRY_TIMEOUT');if(probe(p.pid)!==null)throw fail('LOCAL_PROCESS_STILL_PRESENT');}
 if(JSON.stringify(host())!==JSON.stringify(h))throw fail('LOCAL_PROCESS_BINDING_MISMATCH');
 return Object.freeze({recordedProcessesAbsent:true,recoveryAuthorized:false,ancestry:'complete-supported-chain',boundary:record.boundary.kind,databaseDrain:'not-checked'});
 }catch(e){throw fail(e.code?.startsWith('LOCAL_PROCESS_')?e.code:'LOCAL_PROCESS_PROBE_UNKNOWN');}}
// Schema-admission selector only, never identity or absence proof. Preserve
// legacy v2 consumer marker semantics; actual capture/absence validate v2.
// Windows v3 admission requires its complete distinct, strictly bounded shape.
function isSupportedLocalAncestorBinding(record){try{
 if(record?.version===3){windowsObserver(record);return true;}
 return record?.version===2&&record.ancestry==='complete-supported-chain';
 }catch{return false;}}
module.exports={captureLocalProcessBinding,verifyRecordedProcessesAbsent,captureLocalAncestorBinding,verifyRecordedAncestorChainAbsent,isSupportedLocalAncestorBinding};
