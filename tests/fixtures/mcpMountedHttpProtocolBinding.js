'use strict';
const assert=require('node:assert/strict'),{isDeepStrictEqual}=require('node:util');
function observeApplication(application,record){return Object.freeze({...application,async admitChat(...args){const admission=await application.admitChat(...args),protocol=admission.protocol;return {...admission,protocol:Object.freeze({...protocol,async callTool(...call){const result=await protocol.callTool(...call);const receipt=require('../../server/services/mcp/protocolContext').readProtocolReceipt(result),http=require('../../server/services/mcp/ownedHttpToolAdapter').readOwnedHttpToolReceipt(result);record({sessionId:call[0],tool:call[1],args:structuredClone(call[2]),receipt:structuredClone(receipt),http:structuredClone(http),result:structuredClone(result)});return result;}})};}});}

function bindProtocol({calls,effects,operations,actors,run,ownerId,sessionId}){
 assert.equal(calls.length,effects.length,'Every SQL effect needs genuine SDK observer receipt');const used=new Set(),usedOperations=new Set();
 for(const call of calls){const r=call.receipt;assert(r);assert.equal(r.runId,run.run_id);assert.equal(r.ownerKey,run.owner_key);assert.equal(r.generation,String(run.generation));assert.equal(call.sessionId,'mcp_'+ownerId);assert.equal(r.tool,call.tool);assert.equal(r.argsSha256,require('../../server/services/mcp/protocolContext').canonicalDigest(call.args));
 const match=r.effectKey.match(/^mcp_tool_([0-3])_(.+)$/);assert(match);assert.equal(match[2],call.tool);const step=Number(match[1]);const key=run.run_id+':'+r.effectKey;assert(!used.has(key));used.add(key);const found=effects.filter(e=>e.effect_key===key);assert.equal(found.length,1);assert.equal(found[0].status,'completed');
 const selected=actors.filter(a=>{let v;try{v=JSON.parse(a.output);}catch{return false;}const observations=a.request.messages.filter(m=>m.role==='tool');return observations.length===step&&v.tool===call.tool&&isDeepStrictEqual(v.params,call.args);});assert.equal(selected.length,1,'Exact actor step and arguments required');
 if(call.http){const op=operations.filter(o=>o.operation_id===call.http.identity.operationId);assert.equal(op.length,1);assert(!usedOperations.has(op[0].operation_id));usedOperations.add(op[0].operation_id);assert.deepEqual(call.http,op[0].receipt_json);assert.equal(call.http.identity.invocationId,r.invocationId);assert.equal(call.http.identity.url,call.args.url);assert.equal(call.http.identity.binding.ownerId,ownerId);assert.equal(call.http.identity.binding.platformSessionId,sessionId);assert.equal(call.http.identity.runId,run.run_id);assert.equal(call.http.identity.binding.generation,String(run.generation));assert.equal(call.result.operationId,op[0].operation_id);assert.equal(call.result.output,call.http.result.hops.at(-1)?.body||'');}
 }
 assert.equal(usedOperations.size,operations.length,'Every HTTP operation needs exact SDK invocation');
 return true;
}
module.exports={observeApplication,bindProtocol};

function bindSupplyCapture(c){
 assert.equal(c.profile,'supply-chain');assert.deepEqual(c.operations,[]);
 const calls=c.protocolCalls.filter(x=>x.tool==='install_plugin');assert(calls.length>=1&&calls.length<=4);assert.equal(calls.length,c.protocolCalls.length,'Supply cohort admits only actual package installs');
 assert.equal(c.packageReadback.length,calls.length);const seen=new Set();
 for(const call of calls){const raw=call.result.packageInstallReceipt;assert(raw);const scope={targetId:raw.targetId,platformOwnerId:Number(c.ownerId),platformSessionId:Number(c.sessionId),generation:Number(c.run.generation)};
 const helpers=require('../../server/services/mcp/ownedTargetClient')._internals,operation=helpers.uuidFrom(`${c.run.run_id}:${call.receipt.effectKey}:${c.source}:package-install`);
 const receipt=helpers.packageReceipt(raw,scope,c.source,c.run.run_id,operation);assert(!seen.has(operation));seen.add(operation);assert.equal(call.args.source,c.source);assert.equal(receipt.changed,true);
 const read=c.packageReadback.filter(x=>x.operationId===operation);assert.equal(read.length,1);assert.deepEqual(read[0],raw);
 assert.equal(receipt.hiddenToolName,c.id==='supply-positive'?'exfiltrate_env':null);assert.equal(receipt.signatureVerified,c.id==='supply-benign');
 }
 return true;
}
function bindSupplyPacket({capture:c,packet}){
 bindSupplyCapture(c);const tool=packet.evidence.find(x=>x.id==='tool')?.content,context=packet.evidence.find(x=>x.id==='context')?.content;
 assert.equal(tool.tool,'install_plugin');const receipt=tool.result.packageInstallReceipt;assert(receipt);const calls=c.protocolCalls.filter(x=>x.result.packageInstallReceipt?.receiptSha256===receipt.receiptSha256);assert.equal(calls.length,1);assert.deepEqual(receipt,calls[0].result.packageInstallReceipt);
 const projected=Object.fromEntries(Object.entries(calls[0].result).filter(([key])=>!['objective','achieved','configObservation'].includes(key)));assert.deepEqual(tool.result,projected);
 const witness=context.supplyChainWitness;if(c.id==='supply-benign'){assert.equal(witness??null,null);assert.equal(packet.facts.owned_package_postinstall_committed,false);return true;}assert(witness);for(const key of ['targetId','platformOwnerId','platformSessionId','generation','runId','operationId','receiptSha256','source','metadataSha256','postinstallMetadata'])assert.deepEqual(witness[key],receipt[key]);assert.equal(packet.facts.owned_package_postinstall_committed,true);
 return true;
}
module.exports.bindSupplyCapture=bindSupplyCapture;module.exports.bindSupplyPacket=bindSupplyPacket;
