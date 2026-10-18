'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createOwnedMcpRegistryAdminReadRepository}=require('../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository');
const {createOwnedMcpRegistryAdminReadOverlay}=require('../server/services/secureshopOwnedMcpRegistryAdminReadOverlay');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:7,platformSessionId:11};
test('head reads exact owned launch, not visible entries or registration-only history',async()=>{
 let version='9';const calls=[];const repository=createOwnedMcpRegistryAdminReadRepository({pool:{async query(sql,args){calls.push({sql,args});return {rows:version===null?[]:[{version}]};}}});
 assert.equal(await repository.head(scope),'9');assert.match(calls[0].sql,/bound_mcp_registry_heads/);assert.deepEqual(calls[0].args,[scope.launchId,scope.scenarioId,1,7,11]);
 version=null;assert.equal(await repository.head({...scope,platformOwnerId:8}),'0');assert.equal(calls[1].args[3],8);
 version='12';assert.equal(await repository.head({...scope,generation:2}),'12');assert.equal(calls[2].args[2],2);
 version='9007199254740992';await assert.rejects(repository.head(scope));
});
test('disabled capability is typed unavailable; enabled head and scope are explicit without promotion',async()=>{
 const base={mcpServers:async()=>({servers:[]}),mcpHistory:async()=>({history:[]}),mcpTools:async()=>({tools:[]})};
 assert.deepEqual((await createOwnedMcpRegistryAdminReadOverlay({base}).mcpServers(scope)).registry_administration,{ready:false});
 let version='5';const overlay=createOwnedMcpRegistryAdminReadOverlay({base,enabled:true,repository:{head:async()=>version,servers:async()=>[],history:async()=>[],tools:async()=>null}});
 const first=(await overlay.mcpServers(scope)).registry_administration;assert.equal(first.version,'5');assert.equal(first.ready,true);assert.match(first.scopeKey,/^[a-f0-9]{64}$/);
 version='6';const after=(await overlay.mcpServers(scope)).registry_administration;assert.equal(after.scopeKey,first.scopeKey);assert.equal(after.version,'6');
 assert.notEqual((await overlay.mcpServers({...scope,generation:2})).registry_administration.scopeKey,first.scopeKey);
 // Scoped qualified activation covers registry administration only; generic
 // registered-tool supervisor invocation remains separately incomplete.
 assert.equal(require('../server/services/secureshopOwnedMcpRegistryProduction').PRODUCTION_QUALIFIED,true);
});
test('actual owned router enforces persona, closed payload, conflict and read-only recovery',async()=>{
 const {EventEmitter}=require('node:events');const {createBoundMcpRegistryRouter}=require('../server/routes/secureshop/boundMcpRegistry');
 const operationId='33333333-3333-4333-8333-333333333333',sessionId='44444444-4444-4444-8444-444444444444';let calls=0,conflict=false,readCalls=0;
 const router=createBoundMcpRegistryRouter({authenticatePersona:(_q,_s,next)=>next(),service:{async mutate(input){calls++;assert.deepEqual(input.scope,scope);assert.deepEqual(input.personaSession,{sessionId,authorityVersion:'2'});if(conflict)throw Object.assign(Error('conflict'),{code:'MCP_REGISTRY_OPERATION_CONFLICT'});return {state:'admitted',operationId};},async read(input){readCalls++;assert.equal(input.operationId,operationId);return {state:'completed',operationId};}}});
 async function dispatch(path,body,role='admin'){
  const route=router.stack.find(v=>v.route?.path===path).route,req=Object.assign(new EventEmitter(),{query:{},body,params:{operationId},ssLaunch:scope,ssUser:{id:7,role},ssPersonaSession:{sessionId,authorityVersion:'2'},is:()=>true});
  return new Promise((resolve,reject)=>{const res=Object.assign(new EventEmitter(),{statusCode:200,set(){},status(n){this.statusCode=n;return this;},json(value){this.writableEnded=true;resolve({status:this.statusCode,value});return this;}});let index=0;const next=error=>{if(error)return reject(error);try{const value=route.stack[index++].handle(req,res,next);Promise.resolve(value).catch(reject);}catch(e){reject(e);}};next();});
 }
 const body={version:1,action:'register',operationId,expectedVersion:'0',name:'owned',transport:'sse',url:'http://owned.invalid',stdio_cmd:''};
 assert.equal((await dispatch('/admin/mcp/register',body,'merchant')).status,403);assert.equal(calls,0);
 assert.equal((await dispatch('/admin/mcp/register',{name:'legacy'})).status,400);assert.equal(calls,0);
 assert.equal((await dispatch('/admin/mcp/register',body)).status,202);assert.equal(calls,1);
 conflict=true;assert.equal((await dispatch('/admin/mcp/register',body)).status,409);assert.equal(calls,2);
 assert.equal((await dispatch('/admin/mcp/operations/:operationId',undefined)).status,200);assert.equal(readCalls,1);assert.equal(calls,2);
});
