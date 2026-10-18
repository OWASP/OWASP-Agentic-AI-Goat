'use strict';
// Explicit historical read/resume path. It accepts no provider/loader callbacks
// and cannot consume a new inference claim. Never interprets elapsed time as
// authority to retry a provider after ambiguous execution.
function createCtfDecisionRecoveryService({recovery,decisions}){
 if(typeof recovery?.read!=='function'||typeof decisions?.authorize!=='function')throw new TypeError('CTF recovery repositories required');
 const result=value=>Object.freeze({...value,currentCompletion:false,publication:'requires_current_validation'});
 return Object.freeze({async recover({admissionId,session,resumeAuthorization=false,signal}){
  if(typeof resumeAuthorization!=='boolean')throw new TypeError('Explicit resume flag required');
  const stored=await recovery.read({admissionId,session},{signal});
  if(!stored||!['not_found','claimed_without_proposal','proposal_staged','decided'].includes(stored.state))throw new Error('CTF_RECOVERY_INVALID');
  if(stored.state==='decided')return result({state:'historical_receipt',receipt:stored.receipt,admissionId});
  if(stored.state!=='proposal_staged'||!resumeAuthorization)return result({state:stored.state,receipt:null,admissionId});
  try{
   const receipt=await decisions.authorize({proposalId:stored.proposalId,decisionId:stored.proposalId,session},{signal});
   return result({state:'authorized_receipt',receipt,admissionId});
  }catch(error){
   if(error?.code==='P0001'&&['CTF decision scope stale','CTF decision membership unavailable'].includes(error.message))return result({state:'ineligible_staged_proposal',receipt:null,admissionId});
   if(error?.code==='CTF_TRANSACTION_UNCERTAIN'||/^08[A-Z0-9]{3}$/.test(error?.code||'')||['ECONNRESET','EPIPE','ETIMEDOUT','57P01','57P02','57P03'].includes(error?.code))return result({state:'authorization_uncertain',receipt:null,admissionId});
   throw error;
  }
 }});
}
module.exports={createCtfDecisionRecoveryService};
