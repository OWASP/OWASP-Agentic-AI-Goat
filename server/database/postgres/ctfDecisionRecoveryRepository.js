'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
function createCtfDecisionRecoveryRepository(pool){
 return Object.freeze({async read({admissionId,session},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw new TypeError('Canonical admitted session required');
  const tokenHash=createHash('sha256').update(session.rawToken,'utf8').digest('hex');
  return withCtfTransaction(pool,async client=>(await client.query('SELECT identity.read_ctf_decision_recovery($1,$2,$3,$4) AS recovery',[admissionId,session.actorId,session.sessionId,tokenHash])).rows[0].recovery,options);
 }});
}
module.exports={createCtfDecisionRecoveryRepository};
