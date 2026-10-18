#!/usr/bin/env node
'use strict';
// --plan is read-only. --execute resumes only a verified prospective epoch;
// neither mode force-clears state, kills processes, or shuts down databases.
function fatalOutput(stream,text){
 let timer,done=false;const finish=()=>{if(done)return;done=true;clearTimeout(timer);stream.removeListener?.('error',finish);process.exit(1);};
 timer=setTimeout(finish,1000);stream.once?.('error',finish);
 try{stream.write(text,finish);}catch{finish();}
}
const unavailable=code=>({status:'unavailable',code,recoveryAuthorized:false});
const safe=error=>/^(MAINTENANCE_INSPECTION_|MAINTENANCE_PLAN_|APPLICATION_LEASE_|APPLICATION_MAINTENANCE_)[A-Z_]+$/.test(error?.code||'')?error.code:'MAINTENANCE_PLAN_UNAVAILABLE';
function verifiedCompletedRecovery(completed,sourceRoot,configurationRoot){
 const {createHash}=require('node:crypto'),admission=require('../server/services/applicationMaintenanceInprocessAdmission');
 if(!completed||completed.workspaceSha256!==createHash('sha256').update(configurationRoot).digest('hex')||!admission.recoverySourceBinding(sourceRoot,completed.sourceManifestSha256)||completed.launcherPolicySha256!==require('../server/services/applicationMaintenanceExecutionAdmission').executionPolicySha256())throw Object.assign(Error('Recovery outcome unavailable'),{code:'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE'});
 return Object.freeze({completed:true,recovery:true,observed:true,epoch:completed.epoch});
}
async function maintenanceRecoveryPlan(environment=process.env){
 const lease=await require('../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:environment});
 try{return await lease.maintenancePlan();}finally{await lease.close();}
}
async function maintenanceInspectionPlan(options={}){
 const config=require('./lib/application-maintenance-plan-configuration').loadMaintenancePlanConfiguration(options);
 const lease=await require('../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:config.environment});
 let plan,inspection,primary;const failures=[];
 try{
  plan=await lease.maintenancePlan();
  // Await inspector-owned bounded observation AND cleanup; never race this work
  // against closing its borrowed lease. Its own deadline rejects late success.
  const value=await require('../server/database/postgres/applicationMaintenanceStoreInspection').createApplicationMaintenanceStoreInspection({...config,lease}).inspect();
  const final=await lease.maintenancePlan();lease.assertHeld();
  if(['state','epoch','operationId','installationId','ownerHostSha256'].some(k=>plan[k]!==final[k]))throw Object.assign(Error('Maintenance epoch changed'),{code:'MAINTENANCE_PLAN_EPOCH_CHANGED'});
  inspection={status:'observed',storeCount:value.stores.length,deliveryPresent:value.stores.some(x=>x.deliveryRole!==null),observedAt:value.observedAt,recordedBackendsAbsent:true,recoveryAuthorized:false};
 }catch(e){primary=safe(e);failures.push(primary);}
 try{await lease.close();}catch(e){failures.push(safe(e));}
 if(failures.length)inspection={...unavailable(primary||failures[0]),causes:failures};
 return {...(plan||{}),recoveryExecutable:false,recoveryAuthorized:false,storeInspection:inspection,observationLimit:'Instantaneous store observation only; original owner, ancestors, relaunchers, reconciliation and publication remain unproved.'};
}
async function maintenanceRecoveryExecute(options={}){
 if(process.execArgv.length||process.env.NODE_OPTIONS)throw Object.assign(Error('Recovery runtime injection unavailable'),{code:'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE'});
 require('./application-node-runtime').assertSupportedApplicationNodeVersion(process.versions.node);
 const path=require('node:path'),sourceRoot=options.root||path.resolve(__dirname,'..'),installation=require('./lib/application-maintenance-installation').resolveMaintenanceInstallation(options.configurationRoot);
 if(installation.sourceRoot!==sourceRoot)throw Object.assign(Error('Recovery installation unavailable'),{code:'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE'});installation.assertCurrent();
 const configurationRoot=installation.installationRoot,homeDirectory=installation.homeDirectory,config=require('./lib/application-maintenance-plan-configuration').loadMaintenancePlanConfiguration({root:configurationRoot,homeDirectory,adminUrl:options.adminUrl});
 Object.assign(process.env,require('dotenv').parse(require('../server/services/applicationMaintenanceInprocessAdmission').workspacePrivateRead(installation.envPath)),config.environment);installation.assertCurrent();
 const lease=await require('../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:process.env});
 try{installation.assertCurrent();const completed=await lease.readRecoveryOutcome();if(completed){installation.assertCurrent();const result=verifiedCompletedRecovery(completed,sourceRoot,configurationRoot);await lease.close();return result;}const session=await require('../server/services/applicationMaintenanceDirtyProfile').prepareDirtyRecovery({lease,root:sourceRoot,configurationRoot,homeDirectory,adminUrl:config.environment.PG_ADMIN_DATABASE_URL});const result=await require('../server/services/applicationMaintenanceInprocessWorkflow').runRecoveryMaintenance({lease,session});installation.assertCurrent();await lease.close();return result;}catch(error){try{await lease.close();}catch{}throw error;}
}
async function runWindowsRecovery(configurationRoot,{resolve=require('./lib/application-maintenance-installation').resolveMaintenanceInstallation,supervise=require('./application-journal-bound-maintenance').superviseWindows}={}){
 const installation=resolve(configurationRoot);installation.assertCurrent();
 // The lifecycle only owns the child. Recovery authorization remains entirely
 // in maintenanceRecoveryExecute and its opaque lease/proof/session checks.
 return supervise({recovery:true,installation});
}
async function runWindowsRecoveryChild(configurationRoot,{runtime=process,platform=process.platform,execute=maintenanceRecoveryExecute,activation=require('./lib/windows-maintenance-activation')}={}){
 if(platform!=='win32'||!runtime.connected||typeof runtime.send!=='function')throw Object.assign(Error('Recovery child unavailable'),{code:'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE'});
 await activation.awaitWindowsMaintenanceActivation({runtime});
 const result=await execute({root:require('node:path').resolve(__dirname,'..'),configurationRoot,adminUrl:runtime.env.PG_ADMIN_DATABASE_URL});
 // execute has closed its lease and verified the outcome before this protocol.
 await activation.completeWindowsMaintenance({runtime,result});
 return result;
}
if(require.main===module&&process.argv[2]==='--owned-windows-recovery'){
 if(process.platform!=='win32'||process.argv.length!==4||!process.send||!require('node:path').isAbsolute(process.argv[3]))process.exit(1);
 else{
  const watchdog=setTimeout(()=>process.exit(1),205000);process.once('disconnect',()=>process.exit(1));
  runWindowsRecoveryChild(process.argv[3]).then(()=>{clearTimeout(watchdog);process.exit(0);},error=>{
   clearTimeout(watchdog);const timer=setTimeout(()=>process.exit(1),1000);
   try{process.send({type:'journal-bound-failed',code:require('./application-journal-bound-maintenance').sanitizedFailureCode(error)},()=>{clearTimeout(timer);process.exit(1);});}catch{clearTimeout(timer);process.exit(1);}
  });
 }
}else if(require.main===module){const arg=process.argv[2],configurationArg=process.argv[3],configurationRoot=configurationArg?.startsWith('--configuration-root=')?configurationArg.slice('--configuration-root='.length):undefined,valid=arg==='--plan'?process.argv.length===3:arg==='--execute'&&(process.argv.length===3||process.argv.length===4&&configurationRoot&&require('node:path').isAbsolute(configurationRoot));if(!valid){console.error('Usage: node scripts/application-maintenance-recovery.js --plan | --execute [--configuration-root=/absolute/path]');process.exitCode=1;}else if(arg==='--plan'){maintenanceInspectionPlan({adminUrl:process.env.PG_ADMIN_DATABASE_URL}).then(r=>{const output=JSON.stringify(r,null,2)+'\n';if(r.storeInspection.status!=='observed'){process.exitCode=1;fatalOutput(process.stdout,output);}else console.log(output.trimEnd());},()=>{process.exitCode=1;fatalOutput(process.stderr,'Maintenance recovery plan unavailable\n');});}else (process.platform==='win32'?runWindowsRecovery(configurationRoot):maintenanceRecoveryExecute({root:require('node:path').resolve(__dirname,'..'),configurationRoot,adminUrl:process.env.PG_ADMIN_DATABASE_URL})).then(r=>console.log(JSON.stringify(r)),()=>{process.exitCode=1;fatalOutput(process.stderr,'Maintenance recovery unavailable; restore the reviewed recovery closure in the main checkout or inspect --plan\n');});}
module.exports={maintenanceRecoveryPlan,maintenanceInspectionPlan,maintenanceRecoveryExecute,verifiedCompletedRecovery,runWindowsRecovery,runWindowsRecoveryChild};
