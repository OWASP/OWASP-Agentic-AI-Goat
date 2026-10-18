'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const protocol=require('../server/services/mcp/protocolContext');
const {createOwnedHttpClient}=require('../server/services/mcp/ownedHttpClient');
const {receiptFor}=require('./fixtures/mcpOwnedHttpReceipt');
function fixture(repository,transport){const scope={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:11,generation:0};const execution={runId:crypto.randomUUID(),ownerKey:JSON.stringify(['MCP','7']),durableGeneration:0,check:async()=>{},effect:async()=>{}};
 const client=createOwnedHttpClient({scope,capability:'private',readMode:async()=>'vuln',receiptRepository:repository,request:async(_path,body)=>transport({...body.request,binding:{targetId:scope.targetId,ownerId:'7',platformSessionId:'11',generation:'0'}})});
 return {client,scope,run:fn=>protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'controlled-test'},fn),execution};}
test('central SQL failure after network remains uncertain and cannot redispatch',async()=>{
 let pending=false,calls=0;const repository={begin:async()=>{if(pending)throw Object.assign(Error('uncertain'),{code:'HTTP_OPERATION_UNCERTAIN'});pending=true;return {state:'admitted'};},complete:async()=>{throw Error('controlled SQL failure');}};
 const f=fixture(repository,async identity=>{calls++;return receiptFor(identity);});
 await f.run(async()=>{await assert.rejects(f.client.fetch('mcp_7','http://169.254.169.254/'),{code:'HTTP_OPERATION_UNCERTAIN'});await assert.rejects(f.client.fetch('mcp_7','http://169.254.169.254/'),{code:'HTTP_OPERATION_UNCERTAIN'});});assert.equal(calls,1);
});
test('legacy sidecar reset requirement remains explicit and cannot publish a central receipt',async()=>{
 let calls=0,publish=0,pending=false;
 const repository={begin:async()=>{if(pending)throw Object.assign(Error('uncertain'),{code:'HTTP_OPERATION_UNCERTAIN'});pending=true;return {state:'admitted'};},complete:async()=>{publish++;}};
 const f=fixture(repository,async()=>{calls++;throw Object.assign(Error('legacy reset required'),{code:'HTTP_LEGACY_RECEIPT_RESET_REQUIRED'});});
 await f.run(async()=>{
  await assert.rejects(f.client.fetch('mcp_7','http://169.254.169.254/'),{code:'HTTP_LEGACY_RECEIPT_RESET_REQUIRED'});
  await assert.rejects(f.client.fetch('mcp_7','http://169.254.169.254/'),{code:'HTTP_OPERATION_UNCERTAIN'});
 });
 assert.equal(calls,1);assert.equal(publish,0);
});
test('completed central replay avoids transport and tool does not award credit',async()=>{
 let saved=null,calls=0;const repository={begin:async()=>saved?{state:'replay',receipt:saved}:{state:'admitted'},complete:async({receipt})=>{saved=receipt;}};
 const f=fixture(repository,async identity=>{calls++;return receiptFor(identity);});
 const adapter=require('../server/services/mcp/ownedHttpToolAdapter').createOwnedHttpToolAdapter({client:f.client});
 await f.run(async()=>{const a=await adapter.fetch('mcp_7','http://169.254.169.254/');const b=await adapter.fetch('mcp_7','http://169.254.169.254/');assert.deepEqual(a,b);assert.equal(a.achieved,false);assert.equal(a.real,true);});assert.equal(calls,1);
});
test('owner cancellation after transport prevents central publication',async()=>{
 let publish=0,cancelled=false;const f=fixture({begin:async()=>({state:'admitted'}),complete:async()=>{publish++;}},async identity=>{cancelled=true;return receiptFor(identity);});f.execution.check=async()=>{if(cancelled)throw Error('reset');};
 await assert.rejects(f.run(()=>f.client.fetch('mcp_7','http://169.254.169.254/')),{code:'HTTP_OPERATION_UNCERTAIN'});assert.equal(publish,0);
});
test('owned sandbox without HTTP capability fails closed without legacy mapping',async()=>{
 const {McpSandboxShell}=require('../server/services/mcp/sandboxShell');const shell=new McpSandboxShell('mcp_7',{runner:{exec:async()=>{throw Error('unused');}}});
 const value=await shell.toolFetchUrl('http://169.254.169.254/');assert.equal(value.errorCode,'MCP_OWNED_HTTP_UNAVAILABLE');assert.equal(value.real,false);assert.equal(value.achieved,false);
 const ordinary=new McpSandboxShell('mcp_8');assert.equal((await ordinary.toolFetchUrl('http://169.254.169.254/')).errorCode,'MCP_OWNED_HTTP_UNAVAILABLE');
});
test('SDK adoption preserves private provenance; forged JSON and mock decisions cannot enroll',async()=>{
 const http=require('../server/services/mcp/ownedHttpToolAdapter');const f=fixture({begin:async()=>({state:'admitted'}),complete:async()=>{}},async identity=>receiptFor(identity));
 const adapter=http.createOwnedHttpToolAdapter({client:f.client});
 await f.run(async()=>{
  const args={url:'http://169.254.169.254/'};const result=await adapter.fetch('mcp_7',args.url);const normalized={tool:'fetch_url',args,...result};
  const forged=JSON.parse(JSON.stringify(result));http.adoptTool(forged,{});assert.equal(http.readOwnedHttpToolReceipt(forged),null);
  http.adoptTool(result,normalized);assert.ok(http.readOwnedHttpToolReceipt(normalized));
  protocol.bindResult(protocol.requireProtocolContext('mcp_7'),'fetch_url',args,normalized);
  assert.equal(http.bindModelDecision(normalized,{decisionSource:'scripted',tool:'fetch_url',args,execution:f.execution}),null);
  assert.ok(http.bindModelDecision(normalized,{decisionSource:'model',tool:'fetch_url',args,execution:f.execution}));
  assert.equal(http.modelWitnessFor(JSON.parse(JSON.stringify(normalized))),null);
  assert.equal(http.isCandidate(normalized),true);
  const witness=http.witnessFor(normalized,{scope:f.scope,execution:f.execution});
  assert.ok(witness);assert.equal(http.isTrustedWitness(witness),true);assert.equal(http.matchesWitness(normalized,witness),true);
  assert.equal(http.isTrustedWitness(JSON.parse(JSON.stringify(witness))),false);
  assert.equal(http.witnessFor(normalized,{scope:{...f.scope,platformOwnerId:8},execution:f.execution}),null);
  assert.equal(http.witnessFor(normalized,{scope:f.scope,execution:{...f.execution,durableGeneration:1}}),null);
  normalized.output+=' altered';assert.equal(http.matchesWitness(normalized,witness),false);
  assert.equal(http.witnessFor(normalized,{scope:f.scope,execution:f.execution}),null);
 });
});
