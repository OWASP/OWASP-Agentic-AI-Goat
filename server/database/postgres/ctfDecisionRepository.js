'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const token=session=>{
 if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw new TypeError('Canonical admitted session required');
 return [session.actorId,session.sessionId,createHash('sha256').update(session.rawToken,'utf8').digest('hex')];
};
function createCtfDecisionRepository(pool){
 return Object.freeze({
  capture({session,canonicalInput,inputHash},options){return withCtfTransaction(pool,async client=>(await client.query('SELECT identity.capture_ctf_decision_input($1,$2,$3,$4,$5) AS capture',[...token(session),canonicalInput,inputHash])).rows[0].capture,options);},
  stage({proposalId,session,canonicalEvidence,evidenceHash},options){return withCtfTransaction(pool,async client=>(await client.query('SELECT identity.stage_ctf_server_proposal($1,$2,$3,$4,$5,$6) AS proposal_id',[proposalId,...token(session),canonicalEvidence,evidenceHash])).rows[0],options);},
  authorize({proposalId,decisionId,session},options){return withCtfTransaction(pool,async client=>(await client.query('SELECT * FROM identity.authorize_ctf_decision($1,$2,$3,$4,$5)',[proposalId,...token(session),decisionId])).rows[0],options);}
 });
}
module.exports={createCtfDecisionRepository};
