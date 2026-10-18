'use strict';
// Same-process recovery authority. Stored digests are evidence; only tokens in
// these WeakMaps can authorize a control transition.
const {createHash}=require('node:crypto');
const {isSupportedLocalAncestorBinding}=require('../../../scripts/lib/setup-local-process-identity');
const sessions=new WeakMap(),proofs=new WeakMap();
const fail=code=>Object.assign(Error(code),{code});
const uuid=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sameExpected=(a,b)=>a&&b&&a.epoch===b.epoch&&a.operationId===b.operationId&&a.installationId===b.installationId;
function createVerifiedRecoverySession(value){
 if(!value||['assertCurrent','assertPhaseCurrent','acceptJournalSnapshot','acceptPublication'].some(name=>typeof value[name]!=='function')||!value.identity||!value.lease||!value.expected||!uuid(value.expected.operationId)||!uuid(value.expected.installationId)||!/^[1-9][0-9]*$/.test(value.expected.epoch)||!hex(value.closureSha256)||!hex(value.installationBindingSha256)||!value.ownerRecord||!isSupportedLocalAncestorBinding(value.ownerRecord))throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');
 value.assertCurrent();const session=Object.freeze({}),{assertCurrent,assertPhaseCurrent,acceptJournalSnapshot,acceptPublication,...view}=value;sessions.set(session,{...value,view:Object.freeze(view),closed:false,issued:new Set()});return session;
}
function sessionState(session,identity){const state=sessions.get(session);if(!state||state.closed||state.identity!==identity)throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');state.assertCurrent();return state.view;}
function issueVerifiedRecoveryProof(session,identity,phase,details={}){
 sessionState(session,identity);const state=sessions.get(session);if(!['claim','reconciled','published','finish'].includes(phase)||state.issued.has(phase))throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');
 if(phase==='published'&&(!uuid(details.publicationId)||!hex(details.publicationSha256)))throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');
 state.assertPhaseCurrent(phase);
 const canonical=JSON.stringify({phase,expected:state.expected,closureSha256:state.closureSha256,installationBindingSha256:state.installationBindingSha256,ownerRecordSha256:createHash('sha256').update(JSON.stringify(state.ownerRecord)).digest('hex'),publicationId:details.publicationId||null,publicationSha256:details.publicationSha256||null,priorAttempt:state.priorAttempt?{attemptId:state.priorAttempt.attempt_id,state:state.priorAttempt.state,ownerSha256:createHash('sha256').update(JSON.stringify(state.priorAttempt.recovery_owner_record)).digest('hex')}:null});
 const token=Object.freeze({});proofs.set(token,{phase,identity,expected:state.expected,ownerRecord:state.ownerRecord,proofDigest:createHash('sha256').update(canonical).digest('hex'),publicationId:details.publicationId||null,publicationSha256:details.publicationSha256||null,priorAttempt:state.priorAttempt||null,observerRecord:state.ownerRecord,session});state.issued.add(phase);return token;
}
function mutationState(session,identity,recoveryToken){const state=sessions.get(session);if(!state||state.closed||state.identity!==identity)throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');const attempt=require('./applicationMaintenanceRecoveryControl').recoveryTokenState(recoveryToken,identity);if(attempt.epoch!==state.expected.epoch||attempt.operationId!==state.expected.operationId)throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');return{state,attempt};}
function acceptRecoveryJournalSnapshot(session,identity,recoveryToken,bytes){if(!Buffer.isBuffer(bytes))throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');const{state,attempt}=mutationState(session,identity,recoveryToken);try{state.acceptJournalSnapshot(bytes,attempt);}catch(error){state.closed=true;sessions.delete(session);throw error;}}
function acceptRecoveryPublication(session,identity,recoveryToken){const{state,attempt}=mutationState(session,identity,recoveryToken);try{state.acceptPublication(attempt);}catch(error){state.closed=true;sessions.delete(session);throw error;}}
function assertVerifiedRecoveryProof(token,context){
 const value=proofs.get(token);proofs.delete(token);
 const state=value&&sessions.get(value.session);if(!value||!state||state.closed||value.identity!==context?.identity||value.phase!==context.phase||!sameExpected(value.expected,context.expected))throw fail('APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE');
 state.assertPhaseCurrent(value.phase);return Object.freeze({...value});
}
function closeVerifiedRecoverySession(session){const state=sessions.get(session);if(state){state.closed=true;sessions.delete(session);}}
module.exports={createVerifiedRecoverySession,sessionState,issueVerifiedRecoveryProof,assertVerifiedRecoveryProof,acceptRecoveryJournalSnapshot,acceptRecoveryPublication,closeVerifiedRecoverySession};
