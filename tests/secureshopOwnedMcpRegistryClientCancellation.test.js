'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createOwnedMcpRegistryClient}=require('../server/services/secureshopOwnedMcpRegistryClient');
const baseURL='http://127.0.0.1:8099',token='a'.repeat(43);
function stalledResponse(onCancel){return new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('{'));},cancel(){onCancel();}}));}
test('private registry deadline covers a stalled response body after headers', {timeout:2000}, async()=>{
 let cancelled=0;
 const client=createOwnedMcpRegistryClient({baseURL,token,timeoutMs:100,fetchImpl:async()=>stalledResponse(()=>cancelled++)});
 await assert.rejects(client.health(),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});
 assert.equal(cancelled,1);
});
test('parent cancellation remains connected while consuming the response body', {timeout:2000}, async()=>{
 const controller=new AbortController();let cancelled=0,headers;
 const ready=new Promise(resolve=>headers=resolve);
 const client=createOwnedMcpRegistryClient({baseURL,token,fetchImpl:async()=>{headers();return stalledResponse(()=>cancelled++);}});
 const result=client.health({signal:controller.signal});await ready;await new Promise(resolve=>setImmediate(resolve));controller.abort();
 await assert.rejects(result,{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});assert.equal(cancelled,1);
});
test('already cancelled caller never initiates a private HTTP request',async()=>{
 let calls=0;const controller=new AbortController();controller.abort();
 const client=createOwnedMcpRegistryClient({baseURL,token,fetchImpl:async()=>{calls++;throw Error('unexpected fetch');}});
 await assert.rejects(client.health({signal:controller.signal}),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});assert.equal(calls,0);
});
test('deadline settles caller even when injected fetch ignores cancellation',{timeout:2000},async()=>{
 const client=createOwnedMcpRegistryClient({baseURL,token,timeoutMs:100,fetchImpl:()=>new Promise(()=>{})});
 await assert.rejects(client.health(),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});
});
test('deadline settles caller when body read and cancel both never settle',{timeout:2000},async()=>{
 let cancelled=0;
 const client=createOwnedMcpRegistryClient({baseURL,token,timeoutMs:100,fetchImpl:async()=>({ok:true,body:{getReader:()=>({read:()=>new Promise(()=>{}),cancel:()=>{cancelled++;return new Promise(()=>{});},releaseLock(){}})}})});
 await assert.rejects(client.health(),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});assert.equal(cancelled,1);
});
test('publication rejects executor changes that differ from admitted register target before SQL',async()=>{
 const {createOwnedMcpRegistryRepository}=require('../server/database/postgres/secureshopOwnedMcpRegistryRepository');
 const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:11};
 const persona={id:3,role:'admin'},personaSession={sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'1'};
 const fence={binding:{...scope,personaId:3,role:'admin',...personaSession},withPersonaEffect:()=>assert.fail('invalid publication reached SQL')};
 const repository=createOwnedMcpRegistryRepository({pool:{query:async()=>{}},personaAuthority:{capture:()=>fence}});
 const request={action:'register',name:'expected',transport:'sse',url:'http://owned/mcp',expectedVersion:'0'};
 const admission={prepared:{scope,persona,personaSession,request},fence,workerToken:'50000000-0000-4000-8000-000000000001'};
 const valid={name:'expected',entryId:'60000000-0000-4000-8000-000000000001',action:'register',transport:'sse',endpoint:'http://owned/mcp',schemaSha256:'a'.repeat(64),tools:[],effect:{}};
 for(const changes of [[{...valid,name:'different'}],[{...valid,endpoint:'http://different/mcp'}],[valid,{...valid,name:'extra'}],[{...valid,action:'import'}]])await assert.rejects(repository.publish(admission,changes),{code:'MCP_REGISTRY_EXECUTOR_INVALID'});
});
test('retired-name publication restores stable identity and fixed mode rejects changed pins',async()=>{
 const {createOwnedMcpRegistryRepository}=require('../server/database/postgres/secureshopOwnedMcpRegistryRepository');
 const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:11};
 const persona={id:3,role:'admin'},personaSession={sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'1'};
 const oldId='60000000-0000-4000-8000-000000000001',newId='60000000-0000-4000-8000-000000000002';let publications=0,storedMode='vuln',storedAction='register';
 const client={query:async(sql,args)=>{
  if(sql.startsWith('SET LOCAL'))return{rows:[]};
  if(sql.startsWith('SELECT name')){assert.match(sql,/lifecycle='retired' AND name=ANY/);assert.deepEqual(args.slice(0,5),Object.values(scope));return{rows:[{name:'expected',entry_id:oldId,transport:'sse',endpoint_text:'http://owned/mcp',schema_sha256:'a'.repeat(64)}]};}
  publications++;const receipt=JSON.parse(args[9]),changes=JSON.parse(args[11]);assert.equal(changes[0].entryId,oldId);assert.equal(receipt.changes[0].entryId,oldId);
  return{rows:[{persona_id:3,persona_session_id:personaSession.sessionId,authority_version:'1',request_sha256:Buffer.from('b'.repeat(64),'hex'),binding_sha256:Buffer.from('c'.repeat(64),'hex'),mode:storedMode,action:storedAction,expected_version:'0',state:'completed',receipt_json:receipt,receipt_sha256:Buffer.from(args[10],'hex')}]};
 }};
 const fence={binding:{...scope,personaId:3,role:'admin',...personaSession},withPersonaEffect:fn=>fn(client),assertRemoteAdmission:async()=>{}};
 const repository=createOwnedMcpRegistryRepository({pool:{query:async()=>{}},personaAuthority:{capture:()=>fence}});
 const prepared={scope,persona,personaSession,mode:'vuln',requestSha256:'b'.repeat(64),bindingSha256:'c'.repeat(64),operationId:'40000000-0000-4000-8000-000000000001',request:{action:'register',name:'expected',transport:'sse',url:'http://owned/mcp',expectedVersion:'0'}};
 const admission={prepared,fence,workerToken:'50000000-0000-4000-8000-000000000001'};
 const change={name:'expected',entryId:newId,action:'register',transport:'sse',endpoint:'http://owned/mcp',schemaSha256:'a'.repeat(64),tools:[],effect:{}};
 assert.equal((await repository.publish(admission,[change])).changes[0].entryId,oldId);assert.equal(publications,1);
 await assert.rejects(repository.publish({...admission,prepared:{...prepared,mode:'fixed'}},[{...change,schemaSha256:'d'.repeat(64)}]),{code:'MCP_REGISTRY_FIXED_IDENTITY_DENIED'});assert.equal(publications,1);
 storedMode='fixed';
 assert.equal((await repository.publish({...admission,prepared:{...prepared,mode:'fixed'}},[change])).changes[0].entryId,oldId);
 storedMode='vuln';storedAction='import';
 assert.equal((await repository.publish({...admission,prepared:{...prepared,request:{...prepared.request,action:'import'}}},[{...change,action:'import',schemaSha256:'e'.repeat(64)}])).changes[0].entryId,oldId);
 assert.equal(publications,3);
});
test('forward-only candidate closes SQL request publication and fixed identity boundaries',()=>{
 const fs=require('node:fs');const sql=fs.readFileSync(require('node:path').join(__dirname,'../docs/modernization/drafts/secureshop-owned-mcp-registry/0036_owned_mcp_registry_publication.sql'),'utf8');
 assert.match(sql,/CREATE OR REPLACE FUNCTION secureshop_agents\.publish_owned_mcp_registry_operation/);
 assert.match(sql,/op.action IN \('register','retire'\) AND jsonb_array_length\(requested_changes\)<>1/);
 assert.match(sql,/item->>'name' IS DISTINCT FROM op.request_json->>'name'/);
 assert.match(sql,/item->>'endpoint' IS DISTINCT FROM CASE WHEN op.request_json->>'transport'='stdio'/);
 assert.match(sql,/op.mode='fixed' AND existing.name IS NOT NULL/);
 assert.match(sql,/existing.entry_id::text IS DISTINCT FROM item->>'entryId'/);
});
