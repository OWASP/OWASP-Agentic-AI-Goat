'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const P=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const {mcpSchemaDigest}=require('../server/services/secureshopMcpSchemaDigest');
const digest=require('../server/services/mcp/protocolContext').canonicalDigest;
function request(){const tools=[{name:'search_catalog',description:'preserved',inputSchema:{type:'object',properties:{query:{type:'string',maxLength:256}},required:['query'],additionalProperties:false}}];return{version:1,instanceId:'30000000-0000-4000-8000-000000000001',operationId:'10000000-0000-4000-8000-000000000001',entry:{entryId:'20000000-0000-4000-8000-000000000001',registryVersion:'1',transport:'sse',endpoint:'http://attacker.training:8080/mcp',schemaSha256:mcpSchemaDigest(tools),tools},toolName:'search_catalog',args:{query:'owned'}};}
test('SDK discovery precedes exact-schema selected call and receipt binds every identity',async()=>{
 const q=request(),calls=[];const client={listTools:async()=>{calls.push('list');return{tools:q.entry.tools};},callTool:async(args,_schema,options)=>{calls.push('call');assert.deepEqual(args,{name:q.toolName,arguments:q.args});assert.equal(options.timeout,10000);return{content:[{type:'text',text:'actual transport result'}]};}};
 const r=await P.callCapturedTool(q,client);assert.deepEqual(calls,['list','call']);assert.deepEqual(P.receipt(r,q),r);
 for(const key of ['instanceId','operationId','entryId','registryVersion','requestSha256','schemaSha256','endpointSha256','argumentsSha256','resultSha256','isolation'])assert.throws(()=>P.receipt({...r,[key]:'changed'},q));
 assert.throws(()=>P.receipt({...r,extra:true},q));
 for(const result of [null,[], 'text',{}, {content:'text'}, {content:[],isError:'true'},{content:[{type:'text',text:3}]},{content:[],_meta:[]}])assert.throws(()=>P.receipt({...r,result,resultSha256:digest(result)},q));
 calls.length=0;client.listTools=async()=>({tools:[{...q.entry.tools[0],description:'rotated'}]});await assert.rejects(P.callCapturedTool(q,client));assert.deepEqual(calls,[]);
});
test('closed request denies malformed schema arguments/getters/versions before SDK dispatch',()=>{
 for(const mutate of [q=>q.args.query=4,q=>q.args.extra=true,q=>q.entry.registryVersion='0',q=>q.entry.registryVersion='9007199254740992',q=>q.entry.tools.push(q.entry.tools[0])]){const q=request();mutate(q);assert.throws(()=>P.request(q));}
 let read=false;const q=request();Object.defineProperty(q,'args',{enumerable:true,get(){read=true;return{};}});assert.throws(()=>P.request(q));assert.equal(read,false);
});
test('HTTP disconnect drain waits executor retirement; unknown and expired outcomes never prove absence',async()=>{
 const {EventEmitter}=require('node:events'),{Readable}=require('node:stream');
 const {createOwnedMcpRegistryHttpHandler}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
 let finish,aborted=false,clock=0;const token='a'.repeat(43),q=request();
 const handler=createOwnedMcpRegistryHttpHandler({token,now:()=>clock,executor:{checkReadiness:async()=>({runtimeDigest:"a".repeat(64)}),assertReady:async()=>{},execute:async(_input,{signal})=>new Promise((_resolve,reject)=>{signal.addEventListener('abort',()=>{aborted=true;});finish=()=>reject(Object.assign(Error('cancelled'),{drained:true}));})}});
 function exchange(url,body){const req=Readable.from([Buffer.from(JSON.stringify(body))]);req.method=url.endsWith('/health')?'GET':'POST';req.url=url;req.headers={authorization:'Bearer '+token};const res=new EventEmitter();res.writeHead=status=>{res.status=status;};res.end=bytes=>{res.body=JSON.parse(bytes);};return{req,res,done:handler.handle(req,res)};}
 const health=exchange('/secureshop/mcp-registry/invoke/health',{});health.req.method='GET';await health.done;q.instanceId=health.res.body.instanceId;
 const active=exchange('/secureshop/mcp-registry/invoke',q);await new Promise(resolve=>setImmediate(resolve));active.res.emit('close');assert.equal(aborted,true);
 let drained=false;const lookup={instanceId:q.instanceId,operationId:q.operationId,requestSha256:digest(q)},drain=exchange('/secureshop/mcp-registry/invoke/drain',lookup);drain.done.then(()=>drained=true);await new Promise(resolve=>setImmediate(resolve));assert.equal(drained,false);finish();await Promise.all([active.done,drain.done]);assert.equal(drain.res.body.drained,true);assert.equal(drain.res.body.state,'retired');
 clock=60000;const expired=exchange('/secureshop/mcp-registry/invoke/status',lookup);await expired.done;assert.deepEqual(expired.res.body,{version:1,...lookup,state:'unknown',drained:false});await handler.close();
});
test('actual SDK call returns actual owned file bytes through shared packaged peer handler',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
 const {InMemoryTransport}=require('@modelcontextprotocol/sdk/inMemory.js'),{Client}=require('@modelcontextprotocol/sdk/client/index.js');
 const worker=require('../sidecars/sandbox-runner/owned-mcp-registry/worker');
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'registry-tool-control-')),file=path.join(root,'catalog.json');
 const value=[{id:'controlled-file-value',title:'Actual owned bytes'}];await fs.writeFile(file,JSON.stringify(value),{mode:0o600});
 const server=worker.mcpServer(worker.PEERS[1],{readCatalog:()=>worker.readOwnedCatalog(file)}),client=new Client({name:'control',version:'1'},{capabilities:{}}),[a,b]=InMemoryTransport.createLinkedPair();
 try{await server.connect(a);await client.connect(b);const q=request(),found=await client.listTools();q.entry.tools=JSON.parse(JSON.stringify(found.tools));q.entry.schemaSha256=mcpSchemaDigest(q.entry.tools);const r=await P.callCapturedTool(q,client);assert.deepEqual(JSON.parse(r.result.content[0].text).catalog,value);}
 finally{await client.close();await server.close();await fs.rm(root,{recursive:true,force:true});}
});

test('packaged digest retains established lexical canonical ordering including numeric keys',()=>{for(const value of [{2:'two',10:'ten',nested:{20:2,3:3}},[{12:'a',1:'b'}],request()])assert.equal(P.digest(value),digest(value));});
