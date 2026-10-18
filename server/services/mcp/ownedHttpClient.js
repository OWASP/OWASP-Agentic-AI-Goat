'use strict';
// Unmounted internal client. A production composition must provide an
// authenticated private transport and admitted target; this is not a Judge.
const crypto = require('node:crypto');
const {canonicalDigest} = require('../../../sidecars/sandbox-runner/owned-http/canonical');
const protocol = require('./protocolContext');
function fail(code) { throw Object.assign(Error(code), {code}); }
function operationId(value) {
 const hex=crypto.createHash('sha256').update(value).digest('hex').slice(0,32).split('');
 hex[12]='5';hex[16]='8';const s=hex.join('');return `${s.slice(0,8)}-${s.slice(8,12)}-${s.slice(12,16)}-${s.slice(16,20)}-${s.slice(20)}`;
}
function createOwnedHttpClient({request,scope,capability,readMode,receiptRepository=null}={}) {
 if(receiptRepository&&(typeof receiptRepository.begin!=='function'||typeof receiptRepository.complete!=='function'))throw TypeError('Central HTTP receipt repository required');
 if(typeof request!=='function'||typeof readMode!=='function'||typeof capability!=='string'||!scope)throw TypeError('Trusted owned HTTP composition required');
 const bound=Object.freeze({...scope});
 return Object.freeze({centralPersistence:receiptRepository!==null,async fetch(sessionId,rawUrl) {
  const invocation=protocol.requireProtocolContext(sessionId);const current=invocation.execution;
  if(sessionId!==`mcp_${bound.platformOwnerId}`||current.ownerKey!==JSON.stringify(['MCP',String(bound.platformOwnerId)])
   ||protocol._internals.normalizeGeneration(current)!==String(bound.generation))fail('HTTP_OWNER_MISMATCH');
  if(typeof rawUrl!=='string'||!rawUrl||Buffer.byteLength(rawUrl)>2048)fail('HTTP_REQUEST_INVALID');
  await current.check();const mode=await readMode();if(!['fixed','vuln'].includes(mode))fail('HTTP_MODE_UNAVAILABLE');
  const input={url:rawUrl,runId:current.runId,invocationId:invocation.invocationId,
   operationId:operationId(`${current.runId}:${invocation.effectKey}:owned-http`),mcpSessionId:sessionId,mode};
  const identity={...input,binding:{targetId:bound.targetId,ownerId:String(bound.platformOwnerId),platformSessionId:String(bound.platformSessionId),generation:String(bound.generation)}};
  const digest=canonicalDigest(identity);
  const admission=receiptRepository?await receiptRepository.begin({identity,execution:current}):null;
  let receipt;
  try {
  receipt=admission?.state==='replay'?admission.receipt:await request('/owned-http/execute',{capability,request:input},{signal:current.signal});
  if(!receipt||receipt.version!=='mcp-owned-http-operation.v1'||receipt.requestDigest!==digest
   ||canonicalDigest(receipt.identity)!==digest)fail('HTTP_RECEIPT_MISMATCH');
  if(receiptRepository)require('./ownedHttpReceipt').verifyOwnedHttpReceipt(receipt,identity);
  await current.check();
  if(receiptRepository&&admission?.state!=='replay')await receiptRepository.complete({identity,execution:current,receipt});
  }catch(error){if(error?.code==='HTTP_LEGACY_RECEIPT_RESET_REQUIRED')throw error;if(receiptRepository)throw Object.assign(Error('HTTP_OPERATION_UNCERTAIN'),{code:'HTTP_OPERATION_UNCERTAIN',cause:error});throw error;}
  // Evidence/Judge adapters remain a separate qualification gate;
  // a transport receipt by itself cannot award an objective.
  return receipt;
 }});
}
module.exports={createOwnedHttpClient};
