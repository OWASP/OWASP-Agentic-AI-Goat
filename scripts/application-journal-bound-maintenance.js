'use strict';
const path=require('node:path');
const PROFILE='canonical16-ctf-inprocess-v1';
// Closed diagnostic vocabulary: never serialize error messages, stacks, SQL or
// arbitrary code strings. Diagnostics are observations and cannot grant success.
const FAILURE_CODES=new Set(['APPLICATION_INITIALIZATION_REQUIRES_EXIT', 'APPLICATION_MAINTENANCE_UNAVAILABLE', 'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE', 'APPLICATION_MAINTENANCE_PROFILE_UNAVAILABLE', 'APPLICATION_MAINTENANCE_RECOVERY_INVALID', 'APPLICATION_MAINTENANCE_RECOVERY_UNCERTAIN', 'APPLICATION_MAINTENANCE_RECOVERY_STATE_MISMATCH', 'APPLICATION_MAINTENANCE_INSTALLATION_INVALID', 'APPLICATION_MAINTENANCE_PREPARATION_INVALID', 'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE', 'APPLICATION_MAINTENANCE_UPGRADE_UNAVAILABLE', 'APPLICATION_MAINTENANCE_UPGRADE_UNCERTAIN', 'APPLICATION_MAINTENANCE_VERSION_MISMATCH', 'APPLICATION_MAINTENANCE_CONTROL_INVALID', 'APPLICATION_MAINTENANCE_CONTROL_UNAVAILABLE', 'APPLICATION_MAINTENANCE_DIRTY', 'APPLICATION_MAINTENANCE_EPOCH_MISMATCH', 'APPLICATION_MAINTENANCE_LOCK_REQUIRED', 'APPLICATION_MAINTENANCE_BUSY', 'APPLICATION_MAINTENANCE_QUERY_TIMEOUT', 'APPLICATION_MAINTENANCE_PREPARED_UNCERTAIN', 'APPLICATION_LEASE_ACQUIRE_AND_CLOSE_FAILED', 'APPLICATION_LEASE_ACQUIRE_FAILED', 'APPLICATION_LEASE_CLIENT_FAILED', 'APPLICATION_LEASE_CLOSED', 'APPLICATION_LEASE_CLOSE_FAILED', 'APPLICATION_LEASE_CLOSE_TIMEOUT', 'APPLICATION_LEASE_CONNECT_TIMEOUT', 'APPLICATION_LEASE_LOST', 'APPLICATION_LEASE_NOT_HELD', 'APPLICATION_LEASE_PROBE_TIMEOUT', 'APPLICATION_LEASE_QUERY_TIMEOUT', 'APPLICATION_LEASE_SETUP_FAILED', 'MAINTENANCE_INSPECTION_ACTIVITY_UNKNOWN', 'MAINTENANCE_INSPECTION_BUSY', 'MAINTENANCE_INSPECTION_CLUSTER_MISMATCH', 'MAINTENANCE_INSPECTION_CONFIGURATION_MISMATCH', 'MAINTENANCE_INSPECTION_CONNECTION_LOST', 'MAINTENANCE_INSPECTION_DELIVERY_MISMATCH', 'MAINTENANCE_INSPECTION_DRAIN_UNKNOWN', 'MAINTENANCE_INSPECTION_LEASE_MISMATCH', 'MAINTENANCE_INSPECTION_MANIFEST_INVALID', 'MAINTENANCE_INSPECTION_OTHER_BACKEND', 'MAINTENANCE_INSPECTION_SESSION_UNKNOWN', 'MAINTENANCE_INSPECTION_STORE_MISMATCH', 'MAINTENANCE_INSPECTION_TIMEOUT', 'MAINTENANCE_INSPECTION_TLS_MISMATCH', 'MAINTENANCE_INSPECTION_UNAVAILABLE', 'MAINTENANCE_INSPECTION_VISIBILITY_REQUIRED']);
function sanitizedFailureCode(error){
 try{const pending=[error];for(let i=0;i<pending.length&&i<8;i++){const value=pending[i];if(FAILURE_CODES.has(value?.diagnosticCode))return value.diagnosticCode;if(FAILURE_CODES.has(value?.code))return value.code;if(Array.isArray(value?.errors))pending.push(...value.errors.slice(0,8-pending.length));}}catch{}
 return 'APPLICATION_MAINTENANCE_UNAVAILABLE';
}
const fail=diagnosticCode=>Object.assign(Error('Journal-bound maintenance unavailable; preserve configuration and inspect maintenance --plan'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'},FAILURE_CODES.has(diagnosticCode)?{diagnosticCode}:{});

function selectProfile(args,{startup=false}={}){
 const flags=args.filter(x=>x.startsWith('--maintenance-profile'));
 if(flags.length>1||flags.some(x=>x!=='--maintenance-profile='+PROFILE)||startup&&flags.length&&!args.includes('--init-db'))throw TypeError('Invalid maintenance profile arguments');
 return PROFILE;
}
async function supervise({prospective=false,installation,spawn=require('node:child_process').spawn,stop=require('./start-application').stopOwnedChild,environment=process.env}={}){
 if(process.platform==='win32')return superviseWindows({prospective,installation,spawn,environment});
 const root=path.resolve(__dirname,'..');
 const child=spawn(process.execPath,[__filename,prospective?'--owned-prospective-original':'--owned-journal-bound',...(prospective?[installation.installationRoot]:[])],{cwd:root,env:{...environment},detached:process.platform!=='win32',stdio:['ignore','ignore','ignore','ipc']});
 let result=false,failed=false,timer,stopping,rejectWait,diagnosticCode;
 const stopOnce=()=>stopping||(stopping=Promise.resolve().then(()=>stop({child})));
 const cancel=()=>{failed=true;void stopOnce().then(()=>rejectWait?.(fail(diagnosticCode)),()=>rejectWait?.(fail(diagnosticCode)));};
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
 try{
  await new Promise((resolve,reject)=>{
   rejectWait=reject;
   let granted=false;
   child.on('message',m=>{
    if(m?.type==='journal-bound-failed'){
     if(Object.keys(m).sort().join(',')==='code,type'&&FAILURE_CODES.has(m.code)&&!diagnosticCode)diagnosticCode=m.code;
     cancel();return;
    }
    if(prospective&&m?.type==='prospective-original-ready'){
     if(granted||Object.keys(m).sort().join(',')!=='childPid,installationBinding,nonce,parentPid,type'||m.childPid!==child.pid||m.parentPid!==process.pid||m.installationBinding!==installation.bindingSha256||!/^[-a-f0-9]{36}$/.test(m.nonce||'')){cancel();return;}
     try{installation.assertCurrent();}catch{cancel();return;}
     granted=true;child.send({type:'prospective-original-grant',nonce:m.nonce,childPid:child.pid,parentPid:process.pid,installationBinding:installation.bindingSha256},e=>{if(e)cancel();});return;
    }
    if(m?.type==='journal-bound-complete'&&m.completed===true&&(!prospective||granted))result=true;
   });
   child.once('error',reject);
   child.once('exit',(code,signal)=>{if(code===0&&!signal&&result&&!failed)resolve();else reject(fail(diagnosticCode));});
   timer=setTimeout(cancel,210000);
  });
  await stopOnce(); // Verify owned group absence before caller can start application.
  if(failed)throw fail(diagnosticCode);
 }catch{try{await stopOnce();}catch{}try{if(child.connected)child.disconnect();}catch{}throw fail(diagnosticCode);}
 finally{clearTimeout(timer);process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
async function superviseWindows({prospective=false,recovery=false,installation,spawn=require('node:child_process').spawn,environment=process.env,createJob=require('./lib/windows-owned-process').createWindowsOwnedProcess,timeoutMs=210000,joinMs=10000}={}){
 let job;try{job=await createJob({platform:'win32'});}catch{throw fail();}const root=path.resolve(__dirname,'..');
 let child,admission,admitted=false,granted=false,completed=false,failed=false,diagnosticCode,timer,rejectOutcome,resolveOutcome,completionStarted=false,recoveryResult;
 let resolveClosed;const closed=new Promise(resolve=>{resolveClosed=resolve;});
 const bounded=async promise=>{let limit;try{return await Promise.race([promise,new Promise((_,reject)=>{limit=setTimeout(()=>reject(fail()),joinMs);})]);}finally{clearTimeout(limit);}};
 const cancel=()=>{failed=true;rejectOutcome?.(fail(diagnosticCode));};
 const outcome=new Promise((resolve,reject)=>{resolveOutcome=resolve;rejectOutcome=reject;});outcome.catch(()=>{});
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
 try{
  if(recovery&&prospective)throw fail();
  const entry=recovery?path.join(root,'scripts/application-maintenance-recovery.js'):__filename;
  const args=recovery?[entry,'--owned-windows-recovery',installation.installationRoot]:[entry,prospective?'--owned-prospective-original':'--owned-journal-bound',...(prospective?[installation.installationRoot]:[])];
  child=spawn(process.execPath,args,{cwd:root,env:{...environment},detached:false,stdio:['ignore','ignore','ignore','ipc']});
  let exited=false,exitCode,exitSignal;
  child.once('error',()=>{if(!child.pid)resolveClosed();cancel();});child.once('exit',(code,signal)=>{exited=true;exitCode=code;exitSignal=signal;if(code!==0||signal||!completed)cancel();});
  child.once('close',()=>{resolveClosed();if(exited&&exitCode===0&&!exitSignal&&completed&&!failed)resolveOutcome();else cancel();});
  child.on('message',message=>{
   if(message?.type==='journal-bound-failed'){
    if(Object.keys(message).sort().join(',')==='code,type'&&FAILURE_CODES.has(message.code)&&!diagnosticCode)diagnosticCode=message.code;
    cancel();return;
   }
   if(message?.type==='prospective-original-ready'){
    void(async()=>{try{
     await admission;
     if(failed||!prospective||granted||Object.keys(message).sort().join(',')!=='childPid,installationBinding,nonce,parentPid,type'||message.childPid!==child.pid||message.parentPid!==process.pid||message.installationBinding!==installation.bindingSha256||!/^[-a-f0-9]{36}$/.test(message.nonce||''))throw fail();
     installation.assertCurrent();granted=true;child.send({type:'prospective-original-grant',nonce:message.nonce,childPid:child.pid,parentPid:process.pid,installationBinding:installation.bindingSha256},error=>{if(error)cancel();});
    }catch{cancel();}})();return;
   }
   if(message?.type==='journal-bound-complete'){
    if(completionStarted){cancel();return;}completionStarted=true;
    void(async()=>{try{
     await admission;
     if(failed||prospective&&!granted||Object.keys(message).sort().join(',')!==(recovery?'completed,nonce,result,type':'completed,nonce,type')||message.completed!==true||typeof message.nonce!=='string'||!/^[a-f0-9]{64}$/.test(message.nonce))throw fail();
     if(recovery){installation.assertCurrent();recoveryResult=require('./lib/windows-maintenance-activation').validateRecoveryResult(message.result);}
     await job.assertGuardianOnly();if(failed||!child.connected)throw fail();
     job.expectGuardianExit();completed=true;
     child.send({type:'journal-bound-completion-approved',nonce:message.nonce},error=>{if(error)cancel();});
    }catch{cancel();}})();
   }
  });
  admission=bounded(Promise.race([job.admitGuardian(child),job.failure]));admission.catch(cancel);
  job.failure.catch(cancel);timer=setTimeout(cancel,timeoutMs);
  await admission;admitted=true;await outcome;
  await bounded(job.waitForDrain());await bounded(job.close());if(failed)throw fail(diagnosticCode);
  if(recovery){installation.assertCurrent();return recoveryResult;}
 }catch{
  failed=true;
  // Revoke live IPC before joining late admission. Never abandon an activation
  // that could otherwise launch database work after the parent has failed.
  try{if(child?.connected)child.disconnect();}catch{}
  try{await admission;admitted=true;}catch{}
  try{if(admitted)await bounded(job.stop({graceMs:5000,drainTimeoutMs:joinMs}));else await bounded(job.waitForDrain());}catch{}
  try{if(child)await bounded(closed);}catch{}
  try{await bounded(job.close());}catch{}
  throw fail(diagnosticCode);
 }finally{clearTimeout(timer);process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
async function runJournalBoundMaintenance(options={}){if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).length)throw fail();return runProspectiveJournalBoundMaintenance({installationRoot:path.resolve(__dirname,'..')});}
async function runProspectiveJournalBoundMaintenance(options={}){if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).some(k=>k!=='installationRoot'||!Object.hasOwn(Object.getOwnPropertyDescriptor(options,k),'value'))||process.execArgv.length||process.env.NODE_OPTIONS)throw fail();const installation=require('./lib/application-maintenance-installation').resolveMaintenanceInstallation(options.installationRoot);return supervise({prospective:true,installation});}
async function childMain(){
 const root=path.resolve(__dirname,'..'),prospective=process.argv[2]==='--owned-prospective-original',installation=prospective?require('./lib/application-maintenance-installation').resolveMaintenanceInstallation(process.argv[3]):null,homeDirectory=installation?.homeDirectory||require('node:os').homedir(),configurationRoot=installation?.installationRoot||root;
 const config=require('./lib/application-maintenance-plan-configuration').loadMaintenancePlanConfiguration({root:configurationRoot,homeDirectory,adminUrl:prospective?undefined:process.env.PG_ADMIN_DATABASE_URL});
 Object.assign(process.env,require('dotenv').parse(require('../server/services/applicationMaintenanceInprocessAdmission').workspacePrivateRead(path.join(configurationRoot,'.env'))),config.environment);
 const lease=await require('../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:process.env});
 const admissions=require('../server/services/applicationMaintenanceInprocessAdmission');
 const prepare=process.argv[2]==='--owned-prospective-original'?admissions.prepareProspectiveInprocessAdmission:admissions.prepareInprocessAdmission;
 const prepared=await prepare({lease,root,homeDirectory,adminUrl:config.environment.PG_ADMIN_DATABASE_URL,...(installation?{installationRoot:installation.installationRoot}:{})});
 await require('../server/services/applicationMaintenanceInprocessWorkflow').runInprocessMaintenance({lease,prepared});
 await lease.close();
 if(process.platform==='win32')await require('./lib/windows-maintenance-activation').completeWindowsMaintenance();
 else await new Promise((resolve,reject)=>process.send({type:'journal-bound-complete',completed:true},e=>e?reject(e):resolve()));
}
if(require.main===module){
 if(!((process.argv.length===3&&process.argv[2]==='--owned-journal-bound')||(process.argv.length===4&&process.argv[2]==='--owned-prospective-original'))||!process.send)process.exit(1);
 const watchdog=setTimeout(()=>process.exit(1),205000);process.once('disconnect',()=>process.exit(1));
 const activate=process.platform==='win32'?require('./lib/windows-maintenance-activation').awaitWindowsMaintenanceActivation():Promise.resolve();
 activate.then(childMain).then(()=>{clearTimeout(watchdog);process.exit(0);},error=>{
  clearTimeout(watchdog);const timer=setTimeout(()=>process.exit(1),1000);
  try{process.send({type:'journal-bound-failed',code:sanitizedFailureCode(error)},()=>{clearTimeout(timer);process.exit(1);});}catch{clearTimeout(timer);process.exit(1);}
 });
}
module.exports={PROFILE,sanitizedFailureCode,selectProfile,runJournalBoundMaintenance,runProspectiveJournalBoundMaintenance,superviseWindows};
