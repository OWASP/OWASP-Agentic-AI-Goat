'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawn,spawnSync}=require('node:child_process');
const {isDeepStrictEqual:equal}=require('node:util');
const C=require('./upload-preview-contract');
const {RUNTIME_ROOT,verifyRuntimeManifest}=require('./upload-preview-dependencies');
const INIT='/usr/local/libexec/dvaia-upload-preview-init',SUPERVISOR='/usr/local/libexec/dvaia-system-config-supervisor';
const ROOT='/var/lib/dvaia-owned-upload-preview';
const ATTESTATION=Buffer.from('upload-preview-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n');
const fail=code=>Object.assign(Error('Owned upload preview unavailable'),{code});
function buildPreviewArgv({marker,mounts=['/usr','/bin','/lib','/lib64'],canaryPath,effectDirectory,probe=false}){
 if(!/^__UPLOAD_PREVIEW_[a-f0-9]{64}__$/.test(marker))throw fail('UPLOAD_PREVIEW_FRAME_INVALID');
 const argv=['--cap-drop','ALL','--cap-add','CAP_SETPCAP','--unshare-user','--unshare-net','--unshare-pid','--unshare-uts','--unshare-ipc',
  '--die-with-parent','--new-session','--clearenv',...mounts.flatMap(file=>['--ro-bind',file,file]),
  '--tmpfs','/usr/local/libexec','--ro-bind',INIT,INIT,'--dev','/dev','--dir','/proc','--tmpfs','/tmp','--tmpfs','/work','--chdir','/work',
  '--tmpfs','/preview','--dir','/opt','--dir','/opt/upload-preview',
  '--ro-bind','/opt/dvaia-owned-system/upload-preview-worker.js','/opt/upload-preview/upload-preview-worker.js',
  '--ro-bind','/opt/dvaia-owned-system/upload-preview-contract.js','/opt/upload-preview/upload-preview-contract.js',
  '--ro-bind',path.join(RUNTIME_ROOT,'node_modules'),'/opt/upload-preview/node_modules'];
 if(!probe){
  if(!path.isAbsolute(canaryPath||'')||!path.isAbsolute(effectDirectory||''))throw fail('UPLOAD_PREVIEW_TARGET_INVALID');
  argv.push('--ro-bind-data','3','/preview/request.json','--ro-bind-data','4','/preview/original.gif',
   '--ro-bind',canaryPath,'/preview/canary','--bind',effectDirectory,'/effect');
 }
 argv.push('--remount-ro','/preview','--hostname','owned-upload-preview',INIT,marker);
 if(probe)argv.push('--probe');return argv;
}
function decodeWorkerOutput(bytes,marker){
 if(!Buffer.isBuffer(bytes)||!bytes.subarray(0,ATTESTATION.length).equals(ATTESTATION))throw fail('UPLOAD_PREVIEW_ATTESTATION_INVALID');
 const text=bytes.subarray(ATTESTATION.length).toString('utf8');
 if(!text.startsWith(marker))throw fail('UPLOAD_PREVIEW_FRAME_INVALID');
 const body=text.slice(marker.length);let result;try{result=JSON.parse(body);}catch{throw fail('UPLOAD_PREVIEW_OUTPUT_INVALID');}
 if(JSON.stringify(result)!==body)throw fail('UPLOAD_PREVIEW_OUTPUT_INVALID');return result;
}
function observeEffect(directory,canary,{filesystem=fs,expectedUid=10001}={}){
 const names=filesystem.readdirSync(directory).sort();if(!names.length)return{codeEffectObserved:false,effectSha256:null};
 if(!equal(names,['command-effect']))throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');
 let fd;
 try{
  const file=path.join(directory,'command-effect'),entry=filesystem.lstatSync(file);
  if(!entry.isFile()||entry.isSymbolicLink()||entry.nlink!==1||entry.uid!==expectedUid||(entry.mode&0o777)!==0o600||entry.size!==canary.length)throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');
  // A malicious FIFO must never block this external observer after the process
  // deadline. Nonblocking/no-follow open also closes the lstat/open race.
  fd=filesystem.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=filesystem.fstatSync(fd);
  if(!before.isFile()||before.dev!==entry.dev||before.ino!==entry.ino||before.nlink!==1||before.uid!==expectedUid||(before.mode&0o777)!==0o600||before.size!==canary.length)throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');
  const data=Buffer.alloc(canary.length+1);let count=0,read;
  while((read=filesystem.readSync(fd,data,count,data.length-count,null))>0){count+=read;if(count===data.length)break;}
  const after=filesystem.fstatSync(fd);
  if(count!==canary.length||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');
  const matches=data.subarray(0,count).equals(canary);
  return{codeEffectObserved:matches,effectSha256:matches?C.hash(data.subarray(0,count)):null};
 }catch(error){if(error.code?.startsWith('UPLOAD_PREVIEW'))throw error;throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');}
 finally{if(fd!==undefined)filesystem.closeSync(fd);}
}
function createUploadPreviewExecutor({root=ROOT,spawnImpl=spawn,spawnSyncImpl=spawnSync,verify=verifyRuntimeManifest,
 filesystem=fs,timeoutMs=C.TIMEOUT_MS,drainGraceMs=1000}={}){
 if(!path.isAbsolute(root)||timeoutMs!==C.TIMEOUT_MS||!Number.isInteger(drainGraceMs)||drainGraceMs<100||drainGraceMs>2000)throw TypeError('Fixed upload preview bounds required');
 const mounts=['/usr','/bin','/lib','/lib64'].filter(file=>filesystem.existsSync(file));
 let ready;
 function assertReady(){
  const manifest=verify();
  if(ready){if(!equal(ready,manifest.runtime))throw fail('UPLOAD_PREVIEW_RUNTIME_CHANGED');return Object.freeze({ready:true,isolation:C.ISOLATION});}
  const marker=`__UPLOAD_PREVIEW_${crypto.randomBytes(32).toString('hex')}__`;
  const probe=spawnSyncImpl(SUPERVISOR,buildPreviewArgv({marker,mounts,probe:true}),
   {env:{PATH:'/usr/local/bin:/usr/bin:/bin'},timeout:C.TIMEOUT_MS,maxBuffer:C.MAX_OUTPUT_BYTES});
  if(probe.status!==0||probe.signal||probe.error)throw fail('UPLOAD_PREVIEW_ISOLATION_UNAVAILABLE');
  const value=decodeWorkerOutput(Buffer.from(probe.stdout),marker);
  if(!equal(Object.keys(value).sort(),['ready','isolation','runtime','sharpVersion','vipsVersion'].sort())||value.ready!==true||value.isolation!==C.ISOLATION
   ||!equal(value.runtime,manifest.runtime)||value.sharpVersion!==manifest.sharpVersion||value.vipsVersion!==manifest.vipsVersion)throw fail('UPLOAD_PREVIEW_RUNTIME_CHANGED');
  ready=manifest.runtime;return Object.freeze({ready:true,isolation:C.ISOLATION});
 }
 async function preview(raw,{signal}={}){
  const request=C.normalizeUploadPreviewRequest(raw);signal?.throwIfAborted();assertReady();signal?.throwIfAborted();
  const rootStat=filesystem.lstatSync(root);
  if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||rootStat.uid!==process.getuid()||(rootStat.mode&0o777)!==0o700)throw fail('UPLOAD_PREVIEW_ROOT_INVALID');
  const operation=filesystem.mkdtempSync(path.join(root,'preview-')),birth=filesystem.lstatSync(operation),effectDirectory=path.join(operation,'effect');
  const canary=Buffer.from('TRAINING_V07_'+crypto.randomBytes(32).toString('hex')),canaryPath=path.join(operation,'canary');
  const marker=`__UPLOAD_PREVIEW_${crypto.randomBytes(32).toString('hex')}__`;
  let drained=true;
  try{
   filesystem.mkdirSync(effectDirectory,{mode:0o700});filesystem.writeFileSync(canaryPath,canary,{flag:'wx',mode:0o400});
   const captured=await new Promise((resolve,reject)=>{
    if(signal?.aborted){reject(signal.reason);return;}
    let child;try{drained=false;child=spawnImpl(SUPERVISOR,buildPreviewArgv({marker,mounts,canaryPath,effectDirectory}),
     {env:{PATH:'/usr/local/bin:/usr/bin:/bin'},stdio:['ignore','pipe','pipe','pipe','pipe']});}
    catch{drained=true;reject(fail('UPLOAD_PREVIEW_SPAWN_FAILED'));return;}
    let stdout=Buffer.alloc(0),size=0,reason=null,forced=false,spawnFailed=false,killTimer,closeTimer;
    const stop=code=>{if(reason)return;reason=code;child.kill('SIGTERM');killTimer=setTimeout(()=>{forced=true;child.kill('SIGKILL');
      closeTimer=setTimeout(()=>reject(fail('UPLOAD_PREVIEW_CLEANUP_UNCONFIRMED')),1000);},drainGraceMs);};
    const abort=()=>stop('UPLOAD_PREVIEW_ABORTED');signal?.addEventListener('abort',abort,{once:true});
    const timer=setTimeout(()=>stop('UPLOAD_PREVIEW_TIMEOUT'),timeoutMs);
    for(const [stream,output]of [[child.stdout,true],[child.stderr,false]])stream.on('data',chunk=>{
     size+=chunk.length;if(size>C.MAX_OUTPUT_BYTES){stop('UPLOAD_PREVIEW_OUTPUT_LIMIT');return;}if(output)stdout=Buffer.concat([stdout,chunk]);
    });
    child.once('error',()=>{spawnFailed=true;stop('UPLOAD_PREVIEW_SPAWN_FAILED');});
    for(const [fd,bytes]of [[3,Buffer.from(JSON.stringify(request))],[4,Buffer.from(request.bytesBase64,'base64')]]){
     child.stdio[fd].on('error',()=>{});child.stdio[fd].end(bytes);
    }
    if(signal?.aborted)abort();
    child.once('close',code=>{
     clearTimeout(timer);clearTimeout(killTimer);clearTimeout(closeTimer);signal?.removeEventListener('abort',abort);
     drained=!forced&&(!spawnFailed||!child.pid);
     if(reason||code!==0||!drained){reject(fail(reason||'UPLOAD_PREVIEW_CHILD_FAILED'));return;}
     resolve(stdout);
    });
   });
   const worker=decodeWorkerOutput(captured,marker);
   if(worker.codeEffectObserved!==false||worker.effectSha256!==null||!equal(worker.runtime,ready))throw fail('UPLOAD_PREVIEW_OUTPUT_INVALID');
   C.validateUploadPreviewReceipt(worker,request);
   const effect=observeEffect(effectDirectory,canary,{filesystem});
   if((!worker.originalInterpreterStarted||request.mode==='fixed')&&effect.codeEffectObserved)throw fail('UPLOAD_PREVIEW_EFFECT_INVALID');
   return C.validateUploadPreviewReceipt({...worker,...effect,drained:true},request);
  }finally{
   // Never retire files while a process tree might retain the writable mount.
   // Unconfirmed cleanup leaves this private operation for coordinator recovery.
   if(drained){
    const current=filesystem.lstatSync(operation),currentRoot=filesystem.lstatSync(root);
    if(current.ino!==birth.ino||current.dev!==birth.dev||current.uid!==birth.uid||currentRoot.ino!==rootStat.ino||currentRoot.dev!==rootStat.dev)throw fail('UPLOAD_PREVIEW_CLEANUP_UNCONFIRMED');
    filesystem.rmSync(operation,{recursive:true,force:false});
   }
  }
 }
 return Object.freeze({isolation:C.ISOLATION,assertReady,preview});
}
module.exports={ROOT,INIT,SUPERVISOR,ATTESTATION,buildPreviewArgv,decodeWorkerOutput,observeEffect,createUploadPreviewExecutor};
