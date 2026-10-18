'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
function createCtfCurrentPublicationRepository(pool){
 return Object.freeze({async pending({decisionId,session},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw new TypeError('Canonical admitted session required');
  const tokenHash=createHash('sha256').update(session.rawToken,'utf8').digest('hex');
  const result=await withCtfTransaction(pool,async client=>(await client.query('SELECT identity.ctf_current_decision_pending($1,$2,$3,$4) AS pending',[decisionId,session.actorId,session.sessionId,tokenHash])).rows[0]?.pending,options);
  if(typeof result!=='boolean')throw new Error('CTF_PENDING_PUBLICATION_INVALID');
  return result;
 },async authorize({decisionId,session},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw new TypeError('Canonical admitted session required');
  const tokenHash=createHash('sha256').update(session.rawToken,'utf8').digest('hex');
  const result=await withCtfTransaction(pool,async client=>(await client.query('SELECT identity.authorize_ctf_current_publication($1,$2,$3,$4) AS publication',[decisionId,session.actorId,session.sessionId,tokenHash])).rows[0]?.publication,options);
  if(!result||result.decisionId!==decisionId||typeof result.currentCompletion!=='boolean')throw new Error('CTF_PUBLICATION_INVALID');
  return Object.freeze(result);
 }});
}
module.exports={createCtfCurrentPublicationRepository};
