'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createOwnedHttpCompositeTargets}=require('../server/services/mcp/ownedHttpCompositeTargets');
const scope={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:8,generation:0};
function cleanupReceipt(value){const body={version:1,targetId:value.targetId,ownerId:value.platformOwnerId,platformSessionId:value.platformSessionId,generation:value.generation,operationId:value.operationId,status:'completed',completedAt:new Date(0).toISOString(),cleanupPending:false};return {...body,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(key=>[key,body[key]])))).digest('hex')};}
test('disabled HTTP still retires recorded child before CLI and exposes cleanup debt',async()=>{
 const calls=[];let receipt=null;const cli={admit:async()=>{},retire:async()=>calls.push('cli'),readRetirement:async()=>({cli:true})};
 const leases={read:async()=>({state:'active'}),beginRetirement:async()=>receipt,completeRetirement:async(_value,result)=>{calls.push('persist');receipt=result;},assertRetired:async()=>{assert.ok(receipt);}};
 const absent=createOwnedHttpCompositeTargets({cli,leases,enabled:false});await assert.rejects(absent.retire({scope,operationId:crypto.randomUUID()}),{code:'HTTP_CHILD_CLEANUP_REQUIRED'});assert.deepEqual(calls,[]);
 let value;const http={retire:async input=>{value=input;calls.push('http');},readRetirement:async()=>cleanupReceipt(value)};
 const wired=createOwnedHttpCompositeTargets({cli,leases,http,enabled:false});await wired.retire({scope,operationId:crypto.randomUUID()});assert.deepEqual(calls,['http','persist','cli']);
 await absent.retire({scope,operationId:crypto.randomUUID()});assert.deepEqual(calls,['http','persist','cli','cli']);
});
test('child reservation precedes HTTP creation; reset blocks admission publication',async()=>{
 const calls=[];let checks=0;const execution={check:async()=>{if(++checks===3)throw Error('reset');}};
 const cli={admit:async()=>({scope,runner:{exec:async()=>{}}}),retire:async()=>{}};
 const leases={read:async()=>null,reserve:async()=>calls.push('reserve'),activate:async()=>calls.push('activate')};
 const http={admit:async()=>{calls.push('create');return {scope,capability:'http-only'};}};
 const value=createOwnedHttpCompositeTargets({cli,http,leases,receiptRepository:{},enabled:true});await assert.rejects(value.admit({scope,execution}),/reset/);assert.deepEqual(calls,['reserve','create']);
});
