'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
test('registry owned envelopes and read-only recovery survive exact bridge compiler',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 for(const [name,body,params] of [
 ['admin.mcp.register',{version:1,action:'register',operationId:randomUUID(),expectedVersion:'4',name:'owned',transport:'sse',url:'http://owned.invalid',stdio_cmd:''},{}],
 ['admin.mcp.importManifest',{version:1,action:'import',operationId:randomUUID(),expectedVersion:'4',xml_url:'http://owned.invalid/m.xml'},{}],
 ['admin.mcp.delete',{version:1,action:'retire',operationId:randomUUID(),expectedVersion:'4',name:'owned'},{name:'owned'}]]){
  const request=compileOperation(name,{body,params});assert.deepEqual(request.body,body);assert.equal(matchOperationRequest({pathname:request.path,method:request.method,body}).name,name);
  assert.throws(()=>compileOperation(name,{body:{...body,ownerId:7},params}));
 }
 const request=compileOperation('admin.mcp.operation',{params:{operationId:randomUUID()}});assert.equal(request.method,'GET');assert.equal(Object.hasOwn(request,'body'),false);
});
test('registry recovery key is scoped and bounded, not arbitrary storage admission',async()=>{
 const {validateShopSnapshot}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const base={secureshop_v2_token:null,ss_guest_cart:null};
 const valid=validateShopSnapshot({...base,ss_mcp_registry_pending:'saved'});assert.equal(valid.ss_mcp_registry_pending,'saved');
 assert.throws(()=>validateShopSnapshot({...base,ss_mcp_registry_pending:'x'.repeat(8193)}));
 assert.throws(()=>validateShopSnapshot({...base,private_key:'forbidden'}));
});
