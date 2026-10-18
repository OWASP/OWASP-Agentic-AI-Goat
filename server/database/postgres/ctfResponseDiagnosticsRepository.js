'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {parseStrictJson}=require('../../agent-runtime/referenceComparisonVerifier');
const {validateCtfDecisionDocument}=require('../../services/ctfDecisionService');
const {encodeResponseDiagnostics}=require('../../services/ctfResponseDiagnostics');
function createCtfResponseDiagnosticsRepository(pool){
 return Object.freeze({stage({proposalId,session,canonicalEvidence,evidenceHash,diagnostics},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384||session.rawToken.includes('\0'))throw TypeError('Canonical admitted session required');
  const evidence=parseStrictJson(canonicalEvidence),checked=validateCtfDecisionDocument(evidence);
  if(checked.canonicalEvidence!==canonicalEvidence||checked.evidenceHash!==evidenceHash)throw TypeError('CTF proposal bytes mismatch');
  const encoded=encodeResponseDiagnostics(diagnostics,evidence);
  const values=[proposalId,session.actorId,session.sessionId,createHash('sha256').update(session.rawToken,'utf8').digest('hex'),canonicalEvidence,evidenceHash,encoded.canonicalDiagnostics,encoded.diagnosticsHash];
  return withCtfTransaction(pool,async client=>(await client.query('SELECT identity.stage_ctf_response_diagnostics($1,$2,$3,$4,$5,$6,$7,$8) AS proposal_id',values)).rows[0],options);
 }});
}
module.exports={createCtfResponseDiagnosticsRepository};
