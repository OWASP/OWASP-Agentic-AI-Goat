'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createOwnedHttpOperationStore } = require('../sidecars/sandbox-runner/owned-http/operationStore');
async function fixture(t, executor, bindingOverride) {
 const root = await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-http-journal-'));
 t.after(() => fs.rm(root,{recursive:true,force:true}));
 const binding = bindingOverride||{targetId:crypto.randomUUID(),ownerId:'7',platformSessionId:'trusted',generation:'0'};
 const request = {runId:crypto.randomUUID(),invocationId:crypto.randomUUID(),operationId:crypto.randomUUID(),mcpSessionId:'mcp_7',mode:'vuln',url:'http://169.254.169.254/latest/meta-data/'};
 const targetStore = {withTarget: async (capability,authority,work) => { if(capability!=='trusted')throw Object.assign(Error('invalid capability'),{code:'TARGET_CAPABILITY_INVALID'});await authority();return work({rootfs:path.join(root,'rootfs'),binding}); }};
 const store = createOwnedHttpOperationStore({targetStore,executor,checkReadiness:async()=>({ready:true,manifestSha256:'a'.repeat(64)}),timeoutMs:100});
 return {root,binding,request,store,run:(r=request,options)=>store.execute('trusted',async()=>true,r,options)};
}
function result(input) { return {drained:true,result:{isolationAttestation:Object.fromEntries(['zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors','udpExternalRouteDenied','ipv6ExternalRouteDenied'].map(key=>[key,true])),hops:[],hits:[],status:'completed',mode:input.mode,originalUrlSha256:crypto.createHash('sha256').update(input.url).digest('hex')}}; }
test('exact replay returns durable receipt without another network operation', async t => {
 let calls=0; const f=await fixture(t,async({input})=>{calls++;return result(input);});
 const first=await f.run(); assert.deepEqual(await f.run(),first); assert.equal(calls,1);
 await assert.rejects(f.run({...f.request,url:'http://admin.training:8080/'}),{code:'HTTP_REPLAY_MISMATCH'});
 assert.equal(calls,1); assert.equal(first.identity.url,f.request.url);
});
test('historical numeric-binding journal stays readable but requires owner-fenced reset without redispatch',async t=>{
 let calls=0;const binding={targetId:crypto.randomUUID(),ownerId:7,platformSessionId:11,generation:0};
 const f=await fixture(t,async()=>{calls++;throw Error('must not execute');},binding);
 const {canonicalDigest}=require('../sidecars/sandbox-runner/owned-http/canonical');
 const identity={...f.request,binding:{...binding}},requestDigest=canonicalDigest(identity);
 const receipt={version:'mcp-owned-http-operation.v1',identity,requestDigest,result:{status:'completed'}};
 const row={state:'completed',requestDigest,receipt,receiptDigest:canonicalDigest(receipt)};
 const journal=path.join(f.root,'http-operations');await fs.mkdir(journal,{mode:0o700});
 const file=path.join(journal,`${f.request.operationId}.json`);await fs.writeFile(file,JSON.stringify(row),{mode:0o600});
 await assert.rejects(f.run(),{code:'HTTP_LEGACY_RECEIPT_RESET_REQUIRED'});
 assert.deepEqual(await f.store.readReceipt('trusted',async()=>true,{operationId:f.request.operationId,requestDigest}),{state:'completed',receipt});
 await assert.rejects(f.store.readReceipt('wrong',async()=>true,{operationId:f.request.operationId,requestDigest}),{code:'TARGET_CAPABILITY_INVALID'});
 await assert.rejects(f.store.readReceipt('trusted',async()=>{throw Object.assign(Error('owner denied'),{code:'TARGET_OWNER_DENIED'});},{operationId:f.request.operationId,requestDigest}),{code:'TARGET_OWNER_DENIED'});
 assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),row);
 const pending={...f.request,operationId:crypto.randomUUID()},pendingDigest=canonicalDigest({...pending,binding:{targetId:binding.targetId,ownerId:7,platformSessionId:11,generation:0}});
 await fs.writeFile(path.join(journal,`${pending.operationId}.json`),JSON.stringify({state:'pending',requestDigest:pendingDigest}),{mode:0o600});
 await assert.rejects(f.run(pending),{code:'HTTP_LEGACY_RECEIPT_RESET_REQUIRED'});
 assert.deepEqual(await f.store.readReceipt('trusted',async()=>true,{operationId:pending.operationId,requestDigest:pendingDigest}),{state:'uncertain'});
 await assert.rejects(f.run({...f.request,url:'http://admin.training:8080/'}),{code:'HTTP_REPLAY_MISMATCH'});
 binding.platformSessionId=12;
 await assert.rejects(f.run(),{code:'HTTP_REPLAY_MISMATCH'});
 assert.equal(calls,0);
});
test('abort drains executor before release; pending replay is actionable uncertainty',async t=>{
 let drained=false,calls=0; const f=await fixture(t,async({signal})=>{calls++;await new Promise(resolve=>signal.addEventListener('abort',()=>setTimeout(resolve,20),{once:true}));drained=true;throw Error('aborted');});
 const control=new AbortController();const pending=f.run(undefined,{signal:control.signal});setTimeout(()=>control.abort(),30);
 await assert.rejects(pending,{code:'HTTP_OPERATION_UNCERTAIN'});assert.equal(drained,true);
 await assert.rejects(f.run(),{code:'HTTP_OPERATION_UNCERTAIN'});assert.equal(calls,1);
});
test('owner mismatch and symlink journal fail before executor',async t=>{
 let calls=0; const f=await fixture(t,async({input})=>{calls++;return result(input);});
 await assert.rejects(f.run({...f.request,mcpSessionId:'mcp_8'}),{code:'HTTP_OWNER_MISMATCH'});
 await fs.symlink(f.root,path.join(f.root,'http-operations'));
 await assert.rejects(f.run(),{code:'HTTP_JOURNAL_UNSAFE'});assert.equal(calls,0);
});
test('private API rejects absent token before reaching target authority',async()=>{
 const {createOwnedHttpApi}=require('../sidecars/sandbox-runner/owned-http/api');let calls=0;
 const api=createOwnedHttpApi({token:'a'.repeat(43),store:{execute:async()=>{calls++;}},authority:async()=>true});
 await assert.rejects(api.execute('',{capability:'x',request:{}}),{code:'HTTP_TRANSPORT_UNAUTHORIZED'});
 assert.equal(calls,0);
});
test('backend client requires private invocation context before sending',async()=>{
 const {createOwnedHttpClient}=require('../server/services/mcp/ownedHttpClient');let calls=0;
 const client=createOwnedHttpClient({request:async()=>{calls++;},scope:{platformOwnerId:'7'},capability:'trusted',readMode:async()=>'vuln'});
 await assert.rejects(client.fetch('mcp_7','http://169.254.169.254/'),{code:'MCP_PROTOCOL_CONTEXT_REQUIRED'});assert.equal(calls,0);
});
test('trusted backend context sends exact raw URL and rejects forged receipt identity',async()=>{
 const protocol=require('../server/services/mcp/protocolContext');const {createOwnedHttpClient}=require('../server/services/mcp/ownedHttpClient');
 const scope={targetId:crypto.randomUUID(),platformOwnerId:'7',platformSessionId:'trusted',generation:'0'};let sent;
 const execution={ownerKey:JSON.stringify(['MCP','7']),runId:crypto.randomUUID(),durableGeneration:'0',check:async()=>{},effect:async()=>{}};
 const raw='http://169.254.169.254/a/../latest/?x=%2f';
 const client=createOwnedHttpClient({scope,capability:'trusted',readMode:async()=>'fixed',request:async(_path,body)=>{
  sent=body;const identity={...body.request,binding:{targetId:scope.targetId,ownerId:'7',platformSessionId:'trusted',generation:'0'}};
  return {version:'mcp-owned-http-operation.v1',identity,requestDigest:protocol.canonicalDigest(identity)};
 }});
 await protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'fixture'},()=>client.fetch('mcp_7',raw));
 assert.equal(sent.request.url,raw);assert.equal(sent.request.mode,'fixed');assert.equal(sent.request.runId,execution.runId);
 const forged=createOwnedHttpClient({scope,capability:'trusted',readMode:async()=>'fixed',request:async()=>({version:'mcp-owned-http-operation.v1',identity:{},requestDigest:'0'.repeat(64)})});
 await assert.rejects(protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'fixture'},()=>forged.fetch('mcp_7',raw)),{code:'HTTP_RECEIPT_MISMATCH'});
});
test('packaged canonical serializer matches protocol digest for nested identities',()=>{
 const shared=require('../sidecars/sandbox-runner/owned-http/canonical');
 const protocol=require('../server/services/mcp/protocolContext');
 const a={result:{hops:[{status:200,url:'http://example/'}]},identity:{generation:'1',ownerId:'7'}};
 assert.equal(shared.canonicalDigest(a),protocol.canonicalDigest(a));
 assert.equal(shared.canonicalDigest(a),shared.canonicalDigest({identity:{ownerId:'7',generation:'1'},result:{hops:[{url:'http://example/',status:200}]}}));
});
test('executor cannot select the ordinary CLI profile or caller command',()=>{
 const {createOwnedHttpExecutor}=require('../sidecars/sandbox-runner/owned-http/executor');
 assert.throws(()=>createOwnedHttpExecutor({expectedProfile:'owasp-ai-goat-mcp-sandbox'}),TypeError);
 assert.throws(()=>createOwnedHttpExecutor({expectedProfile:'owasp-ai-goat-owned-http-123456789abc',timeoutMs:30001}),TypeError);
});
