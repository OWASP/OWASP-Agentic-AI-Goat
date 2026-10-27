'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {Readable}=require('node:stream');
const {createOwnedMcpRegistryHttpHandler}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
const {createOwnedMcpRegistryClient,isOwnedMcpRegistryRegistrationNotDispatched}=require('../server/services/secureshopOwnedMcpRegistryClient');
const {registryRequestDigest}=require('../server/services/secureshopMcpRegistryContract');

const TOKEN='q'.repeat(43),RUNTIME='a'.repeat(64),OP='11111111-1111-4111-8111-111111111111';
const next=()=>new Promise(resolve=>setImmediate(resolve));
const request=()=>({version:1,action:'register',operationId:OP,expectedVersion:'0',name:'owned-test',transport:'stdio',url:'',stdio_cmd:'exact original command --serve'});
function envelope(instanceId){const r=request();return{version:1,instanceId,operationId:OP,requestSha256:registryRequestDigest(r),mode:'vuln',request:r,activeEntries:[]};}
function fixture(executor,now=Date.now){return createOwnedMcpRegistryHttpHandler({token:TOKEN,executor:{checkReadiness:async()=>({runtimeDigest:RUNTIME}),assertReady:async()=>{},execute:executor},now});}
function exchange(handler,path,body,method='POST'){
 const req=Readable.from(body===undefined?[]:[Buffer.from(JSON.stringify(body))]);req.method=method;req.url=path;req.headers={authorization:'Bearer '+TOKEN};
 const res=new EventEmitter();res.destroyed=false;res.writeHead=status=>{res.status=status;};res.end=bytes=>{res.body=JSON.parse(bytes);};
 return {req,res,done:handler.handle(req,res)};
}
async function instance(handler){const x=exchange(handler,'/secureshop/mcp-registry/registration/health',undefined,'GET');await x.done;assert.equal(x.res.status,200);assert.equal(x.res.body.registrationCapability,'owned-mcp-registration-v1');return x.res.body.instanceId;}

test('tracked registration binds exact request, instance and completion; legacy health is insufficient',async()=>{
 let calls=0,clock=0;const handler=fixture(async(input)=>{calls++;assert.deepEqual(input.request,request());return[{kind:'observed'}];},()=>clock);
 const id=await instance(handler),q=envelope(id),path='/secureshop/mcp-registry/registration';
 for(const bad of [{...q,requestSha256:'b'.repeat(64)},{...q,instanceId:OP},{...q,request:{...q.request,stdio_cmd:'changed'}}]){
  const x=exchange(handler,path,bad);await x.done;assert.notEqual(x.res.status,200);
 }
 assert.equal(calls,0);
 const x=exchange(handler,path,q);await x.done;assert.equal(x.res.status,200);
 assert.deepEqual(x.res.body,{version:1,instanceId:id,operationId:OP,requestSha256:q.requestSha256,state:'completed',drained:true,changes:[{kind:'observed'}]});
 assert.equal(calls,1);
 const replay=exchange(handler,path,q);await replay.done;assert.equal(replay.res.status,409);assert.equal(calls,1);
 const identity={instanceId:id,operationId:OP,requestSha256:q.requestSha256};
 const status=exchange(handler,path+'/status',identity);await status.done;assert.equal(status.res.body.state,'completed');
 clock=60000;const expired=exchange(handler,path+'/status',identity);await expired.done;assert.equal(expired.res.body.state,'unknown');assert.equal(expired.res.body.drained,false);
 await handler.close();
});

test('disconnect and drain wait for actual executor retirement; unknown is never drained proof',async()=>{
 let release,aborted=false;const handler=fixture(async(_input,{signal})=>new Promise((_resolve,reject)=>{
  signal.addEventListener('abort',()=>{aborted=true;});release=()=>reject(Object.assign(Error('retired'),{drained:true}));
 }));
 const id=await instance(handler),q=envelope(id),path='/secureshop/mcp-registry/registration';
 const x=exchange(handler,path,q);await next();x.res.emit('close');assert.equal(aborted,true);
 const identity={instanceId:id,operationId:OP,requestSha256:q.requestSha256};
 const drain=exchange(handler,path+'/drain',identity);let settled=false;drain.done.then(()=>settled=true);await next();assert.equal(settled,false);
 release();await Promise.all([x.done,drain.done]);assert.equal(drain.res.body.state,'retired');assert.equal(drain.res.body.drained,true);
 await handler.close();
});

test('unknown executor settlement cannot make handler close a cleanup receipt',async()=>{
 const handler=fixture(async()=>{throw Error('worker outcome unknown');});
 const id=await instance(handler),q=envelope(id),path='/secureshop/mcp-registry/registration';
 const x=exchange(handler,path,q);await x.done;assert.equal(x.res.status,503);
 const status=exchange(handler,path+'/status',{instanceId:id,operationId:OP,requestSha256:q.requestSha256});
 await status.done;assert.equal(status.res.body.state,'unknown');assert.equal(status.res.body.drained,false);
 await assert.rejects(handler.close(),{code:'MCP_REGISTRY_REGISTRATION_UNDRAINED'});
});

test('client demands registration-specific health and never retries a possibly dispatched POST',async()=>{
 let posts=0,drains=0;const id='22222222-2222-4222-8222-222222222222',q=envelope(id);
 const validHealth={version:1,instanceId:id,runtimeDigest:RUNTIME,registrationCapability:'owned-mcp-registration-v1'};
 function client(fetchImpl){return createOwnedMcpRegistryClient({baseURL:'http://127.0.0.1:43001',token:TOKEN,expectedRuntimeDigest:RUNTIME,fetchImpl});}
 const absent=client(async()=>Response.json({version:1,instanceId:id,runtimeDigest:RUNTIME}));
 await assert.rejects(absent.registerOwned(q),error=>isOwnedMcpRegistryRegistrationNotDispatched(error,q.requestSha256));
 const transport=client(async(url,options)=>{
  if(url.pathname.endsWith('/registration/health'))return Response.json(validHealth);
  if(url.pathname.endsWith('/registration/drain')){drains++;return Response.json({version:1,instanceId:id,operationId:OP,requestSha256:q.requestSha256,state:'retired',drained:true});}
  if(url.pathname.endsWith('/registration')){posts++;throw Error('lost response after dispatch');}
  throw Error('unexpected request');
 });
 await assert.rejects(transport.registerOwned(q),error=>error.code==='MCP_REGISTRY_REGISTRATION_UNCERTAIN'
  &&error.automaticRetry===false&&error.drained===true);
 assert.equal(posts,1);assert.equal(drains,1);
 const malformed=client(async(url)=>url.pathname.endsWith('/health')?Response.json(validHealth):
  url.pathname.endsWith('/drain')?Response.json({version:1,instanceId:id,operationId:OP,requestSha256:q.requestSha256,state:'unknown',drained:false}):
   Response.json({version:1,instanceId:id,operationId:OP,requestSha256:q.requestSha256,state:'completed',drained:true,changes:[],extra:true}));
 await assert.rejects(malformed.registerOwned(q),error=>error.code==='MCP_REGISTRY_REGISTRATION_UNCERTAIN'
  &&error.automaticRetry===false&&error.drained===false);
});

test('original tracked client and HTTP handler agree on physical protocol bytes',async()=>{
 let calls=0;const handler=fixture(async input=>{calls++;assert.equal(input.request.stdio_cmd,request().stdio_cmd);
  return[{action:'register',name:'owned-test'}];});
 const id=await instance(handler),q=envelope(id);
 const fetchImpl=async(url,options)=>{
  const req=Readable.from(options.body?[Buffer.from(options.body)]:[]);req.method=options.method;
  req.url=url.pathname;req.headers=options.headers;
  const res=new EventEmitter();res.destroyed=false;res.writeHead=status=>{res.status=status;};
  res.end=bytes=>{res.body=bytes;};await handler.handle(req,res);
  return new Response(res.body,{status:res.status,headers:{'content-type':'application/json'}});
 };
 const client=createOwnedMcpRegistryClient({baseURL:'http://127.0.0.1:43001',token:TOKEN,
  expectedRuntimeDigest:RUNTIME,fetchImpl});
 assert.deepEqual(await client.registerOwned(q),{version:1,instanceId:id,operationId:OP,
  requestSha256:q.requestSha256,state:'completed',drained:true,
  changes:[{action:'register',name:'owned-test'}]});
 assert.equal(calls,1);await handler.close();
});
