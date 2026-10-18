'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateRegistrationLocator}=require('./ctfAttemptRegistrationLocator');
const {inputDocument,outcomeDocument}=require('../../services/ctfPredefenseContract');
function auth(session){if(!session||!/^\d+$/.test(session.actorId)||!/^\d+$/.test(session.sessionId)||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)throw TypeError('Original admitted platform session required');return[session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')];}
function createCtfPredefenseRepository(pool){
 const call=(sql,args,options)=>withCtfTransaction(pool,async c=>(await c.query(sql,args)).rows[0].value,options);
 return Object.freeze({
  claim({session,input,stageSnapshot,registrationToken=null},options){registrationToken=validateRegistrationLocator(registrationToken);const d=inputDocument(input,stageSnapshot);return call('SELECT identity.claim_ctf_predefense_with_locator($1,$2,$3,$4,$5,$6,$7) AS value',[...auth(session),d.canonicalDocument,d.documentHash,d.stageSnapshot,registrationToken],options);},
  storeOutcome({session,runId,outcome},options){const d=outcomeDocument(outcome);return call('SELECT identity.store_ctf_predefense_outcome($1,$2,$3,$4,$5,$6) AS value',[...auth(session),runId,d.canonicalDocument,d.documentHash],options);},
  consume({session,runId},options){return call('SELECT identity.consume_ctf_predefense($1,$2,$3,$4) AS value',[...auth(session),runId],options);}
 });
}
module.exports={createCtfPredefenseRepository};
