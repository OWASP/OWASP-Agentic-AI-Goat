'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {Readable}=require('node:stream');
const {createOwnedMcpRegistryClient,isOwnedMcpRegistryOutcomeUncertain}=require('../server/services/secureshopOwnedMcpRegistryClient');
const {createOwnedMcpRegistryHttpHandler}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
const {registryRequestDigest}=require('../server/services/secureshopMcpRegistryContract');
const {DISCOVERY_POLICY_SHA256}=require('../server/services/secureshopMcpRegistryDiscoveryContract');
const token='a'.repeat(43),request={version:1,action:'register',operationId:'10000000-0000-4000-8000-000000000001',expectedVersion:'0',name:'internal',transport:'streamable-http',url:'http://metadata.training/mcp',stdio_cmd:''};
const denial=()=>({version:1,error:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',effectNotStarted:true,
 operationId:request.operationId,registryRequestSha256:registryRequestDigest(request),policySha256:DISCOVERY_POLICY_SHA256});
function client(response,status=403){let posts=0;return{get posts(){return posts;},value:createOwnedMcpRegistryClient({baseURL:'http://owned.invalid',token,
 fetchImpl:async(url)=>{if(url.pathname.endsWith('/health'))return Response.json({version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:'secureshop-owned-mcp-registry.v1',runtimeDigest:'b'.repeat(64)});
 posts++;return Response.json(response,{status});}})};}
test('only exact fixed operation denial becomes a pre-effect error; malformed and generic failures remain uncertain',async()=>{
 const c=client(denial());let checks=0;
 await assert.rejects(c.value.execute(request,{activeEntries:[],mode:'fixed',assertCurrent:async()=>checks++}),e=>e.code===denial().error&&e.effectNotStarted===true&&e.drained===true&&!isOwnedMcpRegistryOutcomeUncertain(e));
 assert.equal(c.posts,1);assert.equal(checks,3);
 for(const [body,status,mode]of [[denial(),403,'vuln'],[denial(),503,'fixed'],[{error:'MCP_REGISTRY_CHILD_FAILED'},503,'fixed'],
  [{...denial(),operationId:'10000000-0000-4000-8000-000000000002'},403,'fixed'],[{...denial(),registryRequestSha256:'0'.repeat(64)},403,'fixed'],
  [{...denial(),policySha256:'0'.repeat(64)},403,'fixed'],[{...denial(),extra:true},403,'fixed']]){
  const bad=client(body,status);await assert.rejects(bad.value.execute(request,{activeEntries:[],mode,assertCurrent:async()=>{}}),e=>isOwnedMcpRegistryOutcomeUncertain(e)&&e.effectNotStarted!==true);assert.equal(bad.posts,1);
 }
});
test('authenticated HTTP projection requires drained exact executor denial and rejects forged coordinates',async()=>{
 for(const change of [()=>{},e=>{e.drained=false;},e=>{e.operationId='10000000-0000-4000-8000-000000000002';},e=>{e.code='MCP_REGISTRY_CHILD_FAILED';}]){
  const body=denial(),error=Object.assign(Error('denied'),{code:body.error,effectNotStarted:true,drained:true,operationId:body.operationId,registryRequestSha256:body.registryRequestSha256,policySha256:body.policySha256});change(error);
  const handler=createOwnedMcpRegistryHttpHandler({token,executor:{checkReadiness:async()=>({}),assertReady:async()=>{},execute:async()=>{throw error;}}});
  const req=Readable.from([Buffer.from(JSON.stringify({request,mode:'fixed',activeEntries:[]}))]);Object.assign(req,{method:'POST',url:'/secureshop/mcp-registry/execute',headers:{authorization:'Bearer '+token}});
  let response;const res={writeHead(status){response={status};},end(text){response.body=JSON.parse(text);}};
  if(error.drained===true&&error.code===body.error&&error.operationId===request.operationId){await handler.handle(req,res);assert.deepEqual(response,{status:403,body});}
  else{await assert.rejects(handler.handle(req,res));assert.equal(response,undefined);}
  await handler.close();
 }
});
