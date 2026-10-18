'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {canonicalDigest}=require('../sidecars/sandbox-runner/owned-http/canonical');
const {receiptFor}=require('./fixtures/mcpOwnedShadowReceipt');
const {createMcpShadowReceiptRepository}=require('../server/database/postgres/mcpShadowReceiptRepository');

function fixture({keepRuntime=false,current=false}={}){
 const runId=crypto.randomUUID(),binding={ownerId:41,platformSessionId:7,targetId:crypto.randomUUID(),generation:0};
 const execution={ownerKey:JSON.stringify(['MCP','41']),runId,durableGeneration:'0',check:async()=>{}};
 const identity={binding,request:{action:'register',registrationId:crypto.randomUUID(),operationId:crypto.randomUUID(),runId,invocationId:crypto.randomUUID(),mode:'vuln',endpoint:'http://10.0.1.100:8080/mcp'}};
 const original=receiptFor(identity),raw=crypto.createHash('sha256').update(JSON.stringify(original.result.catalog)).digest('hex');
 assert.notEqual(raw,original.result.catalogDigest);
 const legacy=current?original:{...original,result:{...original.result,catalogDigest:raw}};
 if(!keepRuntime)delete legacy.runtimeDigest;
 const row={request_json:identity,request_digest:canonicalDigest(identity),receipt_json:legacy,receipt_sha256:canonicalDigest(legacy)};
 let queries=0;
 const client={release(){},async query(sql,values=[]){queries++;if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
  if(sql.includes('FROM graph_runtime.owners'))return{rows:[{generation:0}]};
  if(sql.includes('FROM graph_runtime.runs'))return{rows:[{owner_key:execution.ownerKey,generation:0,status:'running'}]};
  if(sql.includes('registration_id=$1'))return{rows:values[1]===binding.ownerId&&values[2]===binding.targetId&&values[4]===binding.platformSessionId?[row]:[]};
  if(sql.includes('ORDER BY created_at,operation_id'))return{rows:values[0]===binding.ownerId?[row]:[]};
  throw Error('Unexpected controlled query');}};
 return{repo:createMcpShadowReceiptRepository({connect:async()=>client}),binding,execution,identity,legacy,queries:()=>queries};
}

test('legacy registration is immutable read-only evidence, absent from model catalog and refused before invocation',async()=>{
 const f=fixture(),registrationId=f.identity.request.registrationId;
 const evidence=await f.repo.inspectRegistration({binding:f.binding,registrationId,execution:f.execution});
 assert.equal(evidence.qualification,'legacy_unqualified');assert.equal(evidence.reason,'missing_runtime_digest');assert.deepEqual(evidence.receipt,f.legacy);
 assert.deepEqual(await f.repo.listRegistrations({binding:f.binding,execution:f.execution}),[]);
 await assert.rejects(f.repo.readRegistration({binding:f.binding,registrationId,execution:f.execution}),{code:'SHADOW_REGISTRATION_REQUIRES_REREGISTRATION'});
 assert.deepEqual((await f.repo.inspectRegistration({binding:f.binding,registrationId,execution:f.execution})).receipt,f.legacy);
});

test('legacy inspection remains owner, session and target fenced',async()=>{
 const f=fixture(),registrationId=f.identity.request.registrationId;
 for(const binding of [{...f.binding,ownerId:42},{...f.binding,platformSessionId:8},{...f.binding,targetId:crypto.randomUUID()}])
  await assert.rejects(f.repo.inspectRegistration({binding,registrationId,execution:{...f.execution,ownerKey:JSON.stringify(['MCP',String(binding.ownerId)])}}),error=>['STALE_RUN','SHADOW_REGISTRATION_UNAVAILABLE'].includes(error.code));
});

test('historical raw catalog digest stays unqualified even with a runtime digest',async()=>{
 const f=fixture({keepRuntime:true}),registrationId=f.identity.request.registrationId;
 const value=await f.repo.inspectRegistration({binding:f.binding,registrationId,execution:f.execution});
 assert.equal(value.qualification,'legacy_unqualified');assert.equal(value.reason,'noncanonical_catalog_digest');
 assert.deepEqual(await f.repo.listRegistrations({binding:f.binding,execution:f.execution}),[]);
 await assert.rejects(f.repo.readRegistration({binding:f.binding,registrationId,execution:f.execution}),{code:'SHADOW_REGISTRATION_REQUIRES_REREGISTRATION'});
});

test('current receipt remains available to the catalog and invocation lookup',async()=>{
 const f=fixture({keepRuntime:true,current:true}),registrationId=f.identity.request.registrationId;
 assert.equal((await f.repo.inspectRegistration({binding:f.binding,registrationId,execution:f.execution})).qualification,'current');
 assert.deepEqual(await f.repo.listRegistrations({binding:f.binding,execution:f.execution}),[f.legacy]);
 assert.deepEqual(await f.repo.readRegistration({binding:f.binding,registrationId,execution:f.execution}),f.legacy);
});
