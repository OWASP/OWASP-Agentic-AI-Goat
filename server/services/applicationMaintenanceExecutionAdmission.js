'use strict';
// Prospective original-writer admission only; never a recovery proof issuer.
const fs=require('node:fs'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
// The retained SQL launchPolicy label prohibits independent writer helpers;
// bounded synchronous read-only native observation remains explicitly permitted.
const POLICY=Object.freeze({version:'maintenance-owned-original-launch-v3',profile:'canonical16-ctf-recovery-v1',launchPolicy:'exclusive-inprocess-no-helpers-v1',controller:'single-child-no-restart',admission:'default-exclusive-lease-exact-clean-ledger5',schemaUpgrade:'clean-exclusive-known-prefix-after-parent-grant',observationHelpers:'bounded-synchronous-read-only-native-observation',failure:'dirty-deny-no-fallback',configuration:'private-installation-root-main-source-v1',authority:'trusted-application-code-not-hostile-os-user'});
const entry=path.resolve(__dirname,'../../scripts/application-journal-bound-maintenance.js');
const fail=()=>Object.assign(Error('Prospective maintenance launch unavailable'),{code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});
let attempted=false;
const ownedLaunches=new WeakMap();
const digest=x=>createHash('sha256').update(x).digest('hex');
const executionPolicySha256=()=>digest(JSON.stringify({policy:POLICY,issuerSha256:digest(fs.readFileSync(__filename)),entrySha256:digest(fs.readFileSync(entry))}));
async function admitOwnedLaunch(options){
 if(attempted)throw fail();attempted=true;
 if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).some(k=>!['lease','root','homeDirectory','adminUrl','installationRoot'].includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(options,k),'value')))throw fail();
 const {lease,root}=options;
 require('./applicationMaintenanceLease').inprocessLeaseIdentity(lease);
 if(root!==path.resolve(__dirname,'../..')||fs.realpathSync(root)!==root||process.argv.length!==4||fs.realpathSync(process.argv[1])!==entry||process.argv[2]!=='--owned-prospective-original'||require.main?.filename!==entry||!process.connected||typeof process.send!=='function'||process.execArgv.length||process.env.NODE_OPTIONS)throw fail();
 const installation=require('../../scripts/lib/application-maintenance-installation').resolveMaintenanceInstallation(options.installationRoot);
 if(process.argv[3]!==installation.installationRoot||options.homeDirectory!==installation.homeDirectory)throw fail();
 const clean=await lease.assertClean();lease.assertHeld();
 const operationId=randomUUID(),nonce=randomUUID();
 const observe=()=>require('../../scripts/lib/setup-local-process-identity').captureLocalAncestorBinding({workspaceRoot:installation.installationRoot,installationId:clean.installationId,operationId});
 const observed=observe();if(observed.ancestors?.[0]?.pid!==process.pid||observed.ancestors?.[1]?.pid!==process.ppid)throw fail();
 const binding=Object.freeze({policySha256:executionPolicySha256()});
 await new Promise((resolve,reject)=>{
  let done=false;const finish=e=>{if(done)return;done=true;clearTimeout(timer);process.removeListener('message',message);process.removeListener('disconnect',disconnected);lease.signal.removeEventListener('abort',disconnected);e?reject(fail()):resolve();};
  const disconnected=()=>finish(true),message=m=>{if(!m||Object.keys(m).sort().join(',')!=='childPid,installationBinding,nonce,parentPid,type'||m.type!=='prospective-original-grant'||m.nonce!==nonce||m.childPid!==process.pid||m.parentPid!==process.ppid||m.installationBinding!==installation.bindingSha256)return finish(true);finish(false);};
  const timer=setTimeout(()=>finish(true),5000);process.on('message',message);process.once('disconnect',disconnected);lease.signal.addEventListener('abort',disconnected,{once:true});
  if(lease.signal.aborted)return finish(true);
  try{process.send({type:'prospective-original-ready',nonce,childPid:process.pid,parentPid:process.ppid,installationBinding:installation.bindingSha256},e=>{if(e)finish(true);});}catch{finish(true);}
 });
 installation.assertCurrent();lease.assertHeld();lease.signal.throwIfAborted();if(!process.connected||JSON.stringify(observe())!==JSON.stringify(observed))throw fail();
 const upgraded=await lease.upgradeExecutionSchema(clean);lease.assertHeld();
 const ready=await lease.assertExecutionReady();if(upgraded.epoch!==clean.epoch||upgraded.installationId!==clean.installationId||ready.epoch!==clean.epoch||ready.installationId!==clean.installationId)throw fail();
 const assertCurrent=()=>{installation.assertCurrent();lease.assertHeld();lease.signal.throwIfAborted();if(!process.connected||JSON.stringify(observe())!==JSON.stringify(observed))throw fail();};assertCurrent();
 const launch=Object.freeze({binding,installation,assertCurrent});ownedLaunches.set(launch,lease);return launch;
}
function assertOwnedLaunch(launch,lease){if(!launch||ownedLaunches.get(launch)!==lease)throw fail();launch.assertCurrent();lease.assertHeld();lease.signal.throwIfAborted();return launch;}
module.exports={admitOwnedLaunch,assertOwnedLaunch,executionPolicySha256};
