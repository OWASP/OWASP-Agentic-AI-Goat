'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateCtfLifecycleCommand,canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
function createCtfOperationRecoveryRepository(pool){
 return Object.freeze({async readAuthorized({operationId,session},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw TypeError('Canonical admitted session required');
  const hash=createHash('sha256').update(session.rawToken,'utf8').digest('hex');
  const row=await withCtfTransaction(pool,async c=>(await c.query('SELECT identity.read_ctf_user_operation($1,$2,$3,$4) AS operation',[operationId,session.actorId,session.sessionId,hash])).rows[0]?.operation,options);
  if(row===null)return null;
  if(!row||row.currentState!==false||row.actorId!==String(session.actorId)||row.sessionId!==String(session.sessionId)||!['pending','applied','blocked'].includes(row.state))throw Error('CTF_OPERATION_INVALID');
  const command=validateCtfLifecycleCommand({...JSON.parse(row.canonicalCommand),commandHash:row.commandHash});
  const {commandHash,...content}=command;
  if(command.operationId!==operationId||command.actorId!==row.actorId||canonicalCtfJson(content)!==row.canonicalCommand)throw Error('CTF_OPERATION_INVALID');
  if(row.canonicalResult!==null)validateCtfProjectionResult(command,row.sequence,row.canonicalResult,row.resultHash);
  else if(row.state==='applied')throw Error('CTF_OPERATION_INVALID');
  return Object.freeze({...row,command});
 }});
}
module.exports={createCtfOperationRecoveryRepository};
