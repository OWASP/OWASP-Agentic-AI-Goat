'use strict';
// Finite original writer only. No injected actions, helper subprocesses or recovery issuance.
const completions=new WeakMap(),running=new WeakSet();
const caps=require('./applicationMaintenanceInprocessAdmission');
const path=require('node:path');
const fail=()=>Object.assign(Error('In-process maintenance requires owned process termination'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
function consumeCompletion(value,token,identity){const e=completions.get(value);if(!e||e.token!==token||e.identity!==identity)throw fail();completions.delete(value);}
async function runInprocessMaintenance(options){
 if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).sort().join(',')!=='lease,prepared'||Reflect.ownKeys(options).some(k=>!Object.hasOwn(Object.getOwnPropertyDescriptor(options,k),'value')))throw fail();
 const {lease,prepared}=options;
 const identity=require('./applicationMaintenanceLease').inprocessLeaseIdentity(lease);
 if(running.has(lease))throw fail();running.add(lease);let admission,journal;const deadline=AbortSignal.timeout(180000);
 try{
  admission=await lease.beginPrepared(prepared);const a=caps.admittedState(admission,identity);
  const verify=()=>{caps.admittedState(admission,identity);lease.assertHeld();lease.signal.throwIfAborted();deadline.throwIfAborted();journal?.assertCurrent();if(caps.sourceBinding(a.sourceRoot||a.root)!==a.sourceManifestSha256)throw fail();for(const [name,bytes]of a.retained)if(!caps.privateRead(path.join(a.directory,name)).equals(bytes))throw fail();for(const [key,value]of Object.entries(a.env))if(key!=='PG_ADMIN_DATABASE_URL'&&process.env[key]!==value)throw fail();};
  verify();await require('../../scripts/lib/application-maintenance-scope').withPreparedMaintenanceScope({lease,admission,environment:a.env,signal:deadline},async scope=>{
   await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});verify();
   await require('../../scripts/install/ctf-authority-setup').prepareCtfAuthority({root:a.root,directory:a.directory,environment:a.env,maintenanceScope:scope});journal=caps.completedJournalSnapshot(admission,identity);verify();
  });
  const observation=await require('../database/postgres').drainAndInspectPreparedMaintenance({lease,admission});verify();
  if(JSON.stringify(observation.stores)!==JSON.stringify(a.stores))throw fail();verify();
  a.publication.publish();if(!caps.workspacePrivateRead(path.join(a.root,'.env')).equals(a.publication.resultBytes))throw fail();verify();
  const completion=Object.freeze({});completions.set(completion,{token:admission,identity});await lease.finishPrepared(admission,completion);lease.assertHeld();
  return Object.freeze({completed:true,recovery:false,epoch:a.epoch});
 }catch{if(admission)caps.invalidateAdmitted(admission);throw fail();}
 finally{running.delete(lease);}
}
async function runRecoveryMaintenance(options){
 if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).sort().join(',')!=='lease,session')throw fail();
 const {lease,session}=options,identity=require('./applicationMaintenanceLease').inprocessLeaseIdentity(lease),proofs=require('../database/postgres/applicationMaintenanceRecoveryProof'),state=proofs.sessionState(session,identity),deadline=AbortSignal.timeout(180000);let recoveryToken;
 const verify=()=>{proofs.sessionState(session,identity);lease.assertHeld();lease.signal.throwIfAborted();deadline.throwIfAborted();};
 try{
  verify();recoveryToken=await lease.claimRecovery(state.expected,proofs.issueVerifiedRecoveryProof(session,identity,'claim'));verify();
  const tokenState=require('../database/postgres/applicationMaintenanceRecoveryControl').recoveryTokenState(recoveryToken,identity);
  if(!tokenState.finishOnly){
   await require('../../scripts/lib/application-maintenance-scope').withRecoveryMaintenanceScope({lease,session,recoveryToken,environment:state.env,signal:deadline},async scope=>{
    await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});verify();
    await require('../../scripts/install/ctf-authority-setup').prepareCtfAuthority({root:state.root,directory:state.directory,environment:state.env,maintenanceScope:scope});verify();
   });
   const observation=await require('../database/postgres').drainAndInspectPreparedMaintenance({lease,recoverySession:session,recoveryToken});verify();
   if(JSON.stringify(observation.stores)!==JSON.stringify(state.stores))throw fail();
   await lease.advanceRecovery(recoveryToken,'reconciled',proofs.issueVerifiedRecoveryProof(session,identity,'reconciled'));verify();
   state.publication.publish();proofs.acceptRecoveryPublication(session,identity,recoveryToken);verify();
   await lease.advanceRecovery(recoveryToken,'published',proofs.issueVerifiedRecoveryProof(session,identity,'published',{publicationId:state.binding.publication_id,publicationSha256:state.binding.publication_sha256}));verify();
  }
  await lease.finishRecovery(recoveryToken,proofs.issueVerifiedRecoveryProof(session,identity,'finish'));lease.assertHeld();
  proofs.closeVerifiedRecoverySession(session);return Object.freeze({completed:true,recovery:true,epoch:state.expected.epoch});
 }catch{proofs.closeVerifiedRecoverySession(session);throw fail();}
}
module.exports={runInprocessMaintenance,runRecoveryMaintenance,consumeCompletion};
