'use strict';
const protocol=require('./protocolContext');
const {verifyOwnedHttpReceipt}=require('./ownedHttpReceipt');
const VERSION='mcp-owned-http-model-observation.v1';
const receipts=new WeakMap(),decisions=new WeakMap(),witnesses=new WeakSet(),witnessByResult=new WeakMap();
const manifest=require('../../../sidecars/sandbox-runner/owned-http/network-manifest.json');
function freezeTree(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(freezeTree);Object.freeze(value);}return value;}
function createOwnedHttpToolAdapter({client}={}){
 if(typeof client?.fetch!=='function'||client.centralPersistence!==true)throw TypeError('Owned HTTP client required');
 return Object.freeze({async fetch(sessionId,url){
  const context=protocol.requireProtocolContext(sessionId);await context.execution.check();
  const receipt=await client.fetch(sessionId,url);verifyOwnedHttpReceipt(receipt,receipt.identity);
  if(receipt.identity.url!==url||receipt.identity.runId!==context.execution.runId||receipt.identity.invocationId!==context.invocationId)throw Object.assign(Error('HTTP_RECEIPT_MISMATCH'),{code:'HTTP_RECEIPT_MISMATCH'});
  await context.execution.check();const last=receipt.result.hops.at(-1);
  const result={output:last?.body||'',error:receipt.result.status==='completed'?null:`Owned HTTP request failed: ${receipt.result.category||'network_failure'}`,
   blocked:receipt.result.status!=='completed',real:true,targetUrl:url,objective:'mcp_ssrf',achieved:false,
   operationId:receipt.identity.operationId,receiptDigest:receipt.requestDigest};
  receipts.set(result,freezeTree(receipt));return result;
 }});
}
function readOwnedHttpToolReceipt(result){return receipts.get(result)||null;}
function adoptTool(source,target){
 if(target&&typeof target==='object'){
  const receipt=receipts.get(source);
  receipts.delete(target);decisions.delete(target);witnessByResult.delete(target);
  if(receipt)receipts.set(target,receipt);
 }
 return target;
}
function bindModelDecision(result,{decisionSource,tool,args,execution}={}){
 if(result&&typeof result==='object'){decisions.delete(result);witnessByResult.delete(result);}
 const receipt=receipts.get(result),invocation=protocol.readProtocolReceipt(result);
 if(decisionSource!=='model'||tool!=='fetch_url'||!receipt||!invocation||Object.keys(args||{}).join(',')!=='url'
  ||args.url!==receipt.identity.url||receipt.identity.runId!==execution?.runId||invocation.runId!==execution.runId
  ||invocation.invocationId!==receipt.identity.invocationId||invocation.argsSha256!==protocol.canonicalDigest(args)
  ||invocation.ownerKey!==execution.ownerKey||invocation.generation!==String(execution.durableGeneration))return null;
 const witness=Object.freeze({receipt,decisionSource:'model',invocationId:invocation.invocationId,argsSha256:invocation.argsSha256});decisions.set(result,witness);return witness;
}
function modelWitnessFor(result){return decisions.get(result)||null;}
function isCandidate(result){
 const decision=decisions.get(result),receipt=decision?.receipt,last=receipt?.result?.hops?.at(-1);
 if(!receipt||receipt.identity.mode!=='vuln'||receipt.result.status!=='completed'||last?.status!==200
  ||result.output!==last.body||!last.body||result.error!==null||result.blocked!==false||result.real!==true)return false;
 try{verifyOwnedHttpReceipt(receipt,receipt.identity);}catch{return false;}
 return manifest.listeners.some(target=>target.sensitive&&target.address===last.resolvedAddress&&target.port===last.port);
}
function witnessFor(result,{scope,execution}={}){
 if(!isCandidate(result)||!scope||!execution)return null;
 const decision=decisions.get(result),receipt=decision.receipt,id=receipt.identity,binding=id.binding;
 if(binding.targetId!==scope.targetId||String(binding.ownerId)!==String(scope.platformOwnerId)
  ||String(binding.platformSessionId)!==String(scope.platformSessionId)||String(binding.generation)!==String(scope.generation)
  ||id.runId!==execution.runId||execution.ownerKey!==JSON.stringify(['MCP',String(scope.platformOwnerId)])
  ||String(execution.durableGeneration??execution.generation)!==String(scope.generation))return null;
 const cached=witnessByResult.get(result);if(cached)return cached;
 const witness=Object.freeze({version:VERSION,receipt,decision:Object.freeze({invocationId:decision.invocationId,argsSha256:decision.argsSha256}),
  platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId,targetId:scope.targetId,generation:scope.generation,runId:execution.runId});
 witnesses.add(witness);witnessByResult.set(result,witness);return witness;
}
function isTrustedWitness(value){return Boolean(value&&witnesses.has(value));}
function matchesWitness(result,value){return witnessByResult.get(result)===value&&isCandidate(result);}
module.exports={VERSION,createOwnedHttpToolAdapter,readOwnedHttpToolReceipt,adoptTool,bindModelDecision,modelWitnessFor,isCandidate,witnessFor,isTrustedWitness,matchesWitness};
