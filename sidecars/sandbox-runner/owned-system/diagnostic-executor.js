'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const {normalizeDiagnosticRequest, diagnosticCommand, diagnosticRequestDigest, VERSION} = require('./diagnostic-contract');
const INIT = '/usr/local/libexec/dvaia-system-diagnostic-init';
const SUPERVISOR = '/usr/local/libexec/dvaia-system-diagnostic-supervisor';
const {decodeDiagnosticStatus}=require('./diagnostic-receipt');
const {normalizeDiagnosticWire,diagnosticHostname,bindDiagnosticResult}=require('./diagnostic-wire');
const ISOLATION = 'bwrap-system-diagnostic-v1';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const failure = code => Object.assign(new Error('Owned diagnostic execution unavailable'), {code});
function buildDiagnosticArgv(raw, mounts, trustedTargetId) {
  const command = diagnosticCommand(raw);
  return ['--cap-drop','ALL','--cap-add','CAP_SETPCAP',
    '--unshare-user','--unshare-net','--unshare-pid','--unshare-uts','--unshare-ipc',
    '--die-with-parent','--new-session','--clearenv',
    ...mounts.flatMap(name => ['--ro-bind',name,name]),
    '--tmpfs','/usr/local/libexec','--ro-bind',INIT,INIT,
    '--dev','/dev','--dir','/proc','--tmpfs','/tmp','--tmpfs','/work',
    '--tmpfs','/app','--dir','/app/config','--remount-ro','/app',
    '--chdir','/work','--hostname',trustedTargetId===undefined?'system-diagnostic':diagnosticHostname(trustedTargetId),INIT,command];
}
function verifyHelper(file) {
  for (const name of [file,file+'.sha256']) {
    const stat=fs.lstatSync(name);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid!==0 || stat.nlink!==1 || (stat.mode&0o022)) throw failure('SYSTEM_DIAGNOSTIC_ASSET_INVALID');
  }
  const expected=fs.readFileSync(file+'.sha256','utf8');
  if (!/^[a-f0-9]{64}\n$/.test(expected) || hash(fs.readFileSync(file))!==expected.trim()) throw failure('SYSTEM_DIAGNOSTIC_ASSET_INVALID');
}
function createSystemDiagnosticExecutor({spawnImpl=spawn,verify=verifyHelper,exists=fs.existsSync,timeoutMs=4000,drainGraceMs=2000,maxOutputBytes=200*1024}={}) {
  if (!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000||!Number.isInteger(drainGraceMs)||drainGraceMs<100||drainGraceMs>5000||!Number.isInteger(maxOutputBytes)||maxOutputBytes<1||maxOutputBytes>1024*1024) throw new TypeError('Invalid diagnostic bounds');
  const mounts=['/usr','/bin','/lib','/lib64'].filter(exists);
  function assertAssets(){verify(INIT);verify(SUPERVISOR);}
  async function execute(raw,{signal}={},trustedTargetId) {
    const request=normalizeDiagnosticRequest(raw);signal?.throwIfAborted();assertAssets();
    return new Promise((resolve,reject)=>{
      let child;try{child=spawnImpl(SUPERVISOR,buildDiagnosticArgv(request,mounts,trustedTargetId),{env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe','pipe']});}catch{return reject(failure('SYSTEM_DIAGNOSTIC_SPAWN_FAILED'));}
      const stdout=[],stderr=[],status=[];let count=0,statusBytes=0,reason=null,drainTimer,closeTimer;
      const stop=code=>{if(reason)return;reason=code;child.kill('SIGTERM');drainTimer=setTimeout(()=>{child.kill('SIGKILL');closeTimer=setTimeout(()=>{signal?.removeEventListener('abort',abort);reject(failure('SYSTEM_DIAGNOSTIC_CLEANUP_UNCONFIRMED'));},1000);},drainGraceMs);};
      const timer=setTimeout(()=>stop('SYSTEM_DIAGNOSTIC_TIMEOUT'),timeoutMs);
      const abort=()=>stop('SYSTEM_DIAGNOSTIC_ABORTED');signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
      for(const [stream,chunks] of [[child.stdout,stdout],[child.stderr,stderr]])stream.on('data',bytes=>{count+=bytes.length;if(count>maxOutputBytes)return stop('SYSTEM_DIAGNOSTIC_OUTPUT_LIMIT');chunks.push(Buffer.from(bytes));});
      child.stdio[3].on('data',bytes=>{statusBytes+=bytes.length;if(statusBytes>96)return stop('SYSTEM_DIAGNOSTIC_STATUS_INVALID');status.push(Buffer.from(bytes));});
      child.once('error',()=>stop('SYSTEM_DIAGNOSTIC_SPAWN_FAILED'));
      child.once('close',code=>{
        clearTimeout(timer);clearTimeout(drainTimer);clearTimeout(closeTimer);signal?.removeEventListener('abort',abort);
        // Failed/forced drain never produces an executed receipt. Effects may have
        // occurred: callers must retain admission as unknown, never redispatch.
        if(reason)return reject(failure(reason));
        try{
          const observed=decodeDiagnosticStatus(Buffer.concat(status),code),out=Buffer.concat(stdout),err=Buffer.concat(stderr);
          resolve(Object.freeze({version:VERSION,isolation:ISOLATION,operationId:request.operationId,requestSha256:diagnosticRequestDigest(request),command:diagnosticCommand(request),executed:true,...observed,
            stdout:out.toString('base64'),stderr:err.toString('base64'),encoding:'base64',stdoutBytes:out.length,stderrBytes:err.length,stdoutSha256:hash(out),stderrSha256:hash(err),timedOut:false,truncated:false}));
        }catch(error){
          Object.defineProperty(error,'diagnostics',{value:Object.freeze({supervisorExitCode:code,stderr:Buffer.concat(stderr).subarray(0,4096).toString('utf8'),statusBase64:Buffer.concat(status).subarray(0,96).toString('base64')}),enumerable:false});
          reject(error);
        }
      });
    });
  }
  async function assertReady({signal}={}){
    const result=await execute({operationId:'00000000-0000-4000-8000-000000000001',cmd_template:'exit',args:'0'},{signal});
    if(result.exitCode!==0||!result.drained)throw failure('SYSTEM_DIAGNOSTIC_ISOLATION_UNAVAILABLE');
    return Object.freeze({ready:true,isolation:ISOLATION});
  }
  return Object.freeze({execute,assertReady,async executeBound(raw,{signal}={}){const wire=normalizeDiagnosticWire(raw);const result=await execute(wire.request,{signal},wire.targetId);return bindDiagnosticResult(wire,result);}});
}
module.exports={createSystemDiagnosticExecutor,buildDiagnosticArgv,decodeDiagnosticStatus};
