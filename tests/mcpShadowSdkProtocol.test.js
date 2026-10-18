'use strict';
const test=require('node:test'),assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const {createShadowSdkProtocolFixture}=require('../server/services/mcp/shadowSdkProtocol');
const {createOwnedShadowPeer,controlledConnector}=require('./fixtures/mcpShadowPeer.cjs');
const scope=()=>({ownerId:7,platformSessionId:9,targetId:randomUUID(),generation:'0'});
test('real SDK initialize/list/imported call follows exact selected peer and reads its actual editable file',async t=>{
 const approved=await createOwnedShadowPeer({text:'Approved original policy.'}),rogue=await createOwnedShadowPeer({text:'Rogue replacement policy.'});approved.approved=true;
 const runtime=createShadowSdkProtocolFixture({connector:controlledConnector([approved,rogue]),checkCurrent:async()=>{}});t.after(async()=>{await runtime.close();await approved.close();await rogue.close();});
 const owned=scope(),registered=await runtime.register({scope:owned,endpoint:rogue.endpoint});assert.equal(registered.productionQualified,false);assert.equal(registered.observation.endpoint,rogue.endpoint);
 assert.ok(registered.catalog[0].name.startsWith('shadow_'));assert.notEqual(registered.catalog[0].name,'read_policy');
 await rogue.replacePolicy('Actual modified owner policy content.');const result=await runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name,args:{section:'policy'}});
 assert.equal(result.result.content[0].text,'Actual modified owner policy content.');assert.equal(rogue.reads.length,1);assert.equal(approved.reads.length,0);
 assert.ok(['initialize','tools/list','tools/call'].every(method=>rogue.requests.some(r=>r.method===method)));assert.equal(approved.requests.length,0);
 await assert.rejects(runtime.invoke({scope:owned,handle:{...registered.handle},name:registered.catalog[0].name,args:{section:'policy'}}),{code:'SHADOW_HANDLE_DENIED'});
 await assert.rejects(runtime.invoke({scope:{...owned,ownerId:8},handle:registered.handle,name:registered.catalog[0].name,args:{section:'policy'}}),{code:'SHADOW_HANDLE_DENIED'});
 await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name,args:{section:'other'}}),{code:'SHADOW_ARGUMENTS_INVALID'});
 await runtime.retire({scope:owned,handle:registered.handle});await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name}),{code:'SHADOW_HANDLE_DENIED'});
});
test('fixed mode requires control-manifest approval even when rogue self-reports identical approved server name',async t=>{
 const approved=await createOwnedShadowPeer({text:'Clean',name:'same-peer'}),rogue=await createOwnedShadowPeer({text:'Poison',name:'same-peer'});approved.approved=true;
 const runtime=createShadowSdkProtocolFixture({connector:controlledConnector([approved,rogue]),checkCurrent:async()=>{}});t.after(async()=>{await runtime.close();await approved.close();await rogue.close();});
 await assert.rejects(runtime.register({scope:scope(),endpoint:rogue.endpoint,mode:'fixed'}),{code:'SHADOW_UNAPPROVED_PEER'});assert.equal(rogue.requests.length,0);
 const good=await runtime.register({scope:scope(),endpoint:approved.endpoint,mode:'fixed'});assert.equal(good.observation.peerKey,approved.endpoint);
 await assert.rejects(runtime.register({scope:scope(),endpoint:'http://127.0.0.1:1/mcp'}),{code:'SHADOW_ENDPOINT_DENIED'});
});
test('scope, schema catalog and current authority remain bound across calls; unrelated static names never dispatch',async t=>{
 const peer=await createOwnedShadowPeer({text:'Namespace-private training policy.'});let current=true;
 const runtime=createShadowSdkProtocolFixture({connector:controlledConnector([peer]),checkCurrent:async()=>{if(!current)throw Object.assign(Error('stale'),{code:'SHADOW_SCOPE_STALE'});}});t.after(async()=>{await runtime.close();await peer.close();});
 const owned=scope(),registered=await runtime.register({scope:owned,endpoint:peer.endpoint});
 for(const changed of [{ownerId:8},{platformSessionId:10},{targetId:randomUUID()},{generation:'1'}])await assert.rejects(runtime.invoke({scope:{...owned,...changed},handle:registered.handle,name:registered.catalog[0].name,args:{section:'policy'}}),{code:'SHADOW_HANDLE_DENIED'});
 await assert.rejects(runtime.register({scope:{...owned,ownerId:8},endpoint:peer.endpoint}),{code:'SHADOW_ENDPOINT_DENIED'});
 await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:'run_command',args:{command:'ignored'}}),{code:'SHADOW_TOOL_DENIED'});
 const schemaDigest=registered.observation.catalogDigest;registered.catalog[0].inputSchema.properties.section={type:'string'};
 await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name,args:{section:'invalid'}}),{code:'SHADOW_ARGUMENTS_INVALID'});assert.equal(registered.observation.catalogDigest,schemaDigest);
 current=false;await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name,args:{section:'policy'}}),{code:'SHADOW_SCOPE_STALE'});assert.equal(peer.reads.length,0);
});
test('oversized peer result is rejected and no call is automatically replayed',async t=>{
 const peer=await createOwnedShadowPeer({text:'x'.repeat(40000)}),runtime=createShadowSdkProtocolFixture({connector:controlledConnector([peer]),checkCurrent:async()=>{}});t.after(async()=>{await runtime.close();await peer.close();});
 const owned=scope(),registered=await runtime.register({scope:owned,endpoint:peer.endpoint});await assert.rejects(runtime.invoke({scope:owned,handle:registered.handle,name:registered.catalog[0].name,args:{section:'policy'}}),{code:'SHADOW_LIMIT'});assert.equal(peer.reads.length,1);
});
test('forged endpoint attestation is rejected before initializing SDK session',async()=>{
 let close=0;const runtime=createShadowSdkProtocolFixture({connector:{open:async()=>({attestation:{endpoint:'http://different.invalid'},close:async()=>{close++;}})},checkCurrent:async()=>{}});
 await assert.rejects(runtime.register({scope:scope(),endpoint:'http://selected.invalid/mcp'}),{code:'SHADOW_ENDPOINT_DENIED'});assert.equal(close,1);
});
