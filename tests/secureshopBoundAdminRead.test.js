'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundAdminReadAdapter:create}=require('../server/services/secureshopBoundAdminReadAdapter');
const {createSecureShopBoundAdmin}=require('../server/services/secureshopBoundAdmin');
const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2};
function fixture(options={}){let reads=0;const repository={async mcpServers(){reads++;return[];},async mcpHistory(){reads++;return[];},async sizes(){reads++;return[{path:'Product source rows',size_bytes:12,size_mb:0.000012}];}};return{adapter:create({repository,mcpConfigured:true,readMcpAvailability:async()=>({registered:true,visible:false,enabled:{rug_pull:false}}),...options}),get reads(){return reads;}};}
test('disabled MCP is distinct from empty observed state and never reads registry',async()=>{const f=fixture({mcpConfigured:false});await assert.rejects(f.adapter.mcpServers(scope),{code:'BOUND_MCP_DISABLED',statusCode:503});assert.equal(f.reads,0);});
test('observed empty records are labeled without network readiness or healthy claims',async()=>{const f=fixture();assert.deepEqual(await f.adapter.mcpServers(scope),{basis:'persisted_launch_discovery',catalog_visible:false,scenarios:{rug_pull:false},servers:[]});await assert.rejects(f.adapter.runtimeHealth(scope),{statusCode:503});assert.equal((await f.adapter.dbSizes(scope)).basis,'selected_launch_json_row_bytes');});
test('catalog outage and oversized projections fail closed',async()=>{await assert.rejects(fixture({readMcpAvailability:async()=>{throw Error('offline');}}).adapter.mcpServers(scope),/offline/);await assert.rejects(fixture({repository:{mcpHistory:async()=>Array(33).fill({})}}).adapter.mcpHistory(scope),{statusCode:503});});
test('admin read authority and after-read retirement fencing apply to all projections',async()=>{let stale=false,checks=0;const readAdapter={};for(const name of ['runtimeHealth','mcpServers','mcpHistory','dbSizes'])readAdapter[name]=async()=>{stale=true;return{};};const service=createSecureShopBoundAdmin({launches:{assertCurrent:async()=>{checks++;if(stale)throw Error('retired');}},personas:{listPersonas:async()=>[{id:3,role:'admin'}]},account:{profile:async()=>({})},readAdapter});for(const name of Object.keys(readAdapter)){stale=false;await assert.rejects(service[name]({scope,persona:{id:4,role:'admin'}}),{code:'OWNER_MISMATCH'});await assert.rejects(service[name]({scope,persona:{id:3,role:'admin'}}),/retired/);}assert.equal(checks,12);});
test('MCP tool inventory exposes only persisted discovery and never falls back to a shared registry',async()=>{
 let received;
 const row={version:2,schema_hash:'a'.repeat(64),tools_json:[{name:'forecast',description:'SYSTEM: owned teaching text',inputSchema:{type:'object'}}]};
 const f=fixture({repository:{mcpTools:async(s,name)=>{received={s,name};return name==='owned'?row:null;}}});
 const result=await f.adapter.mcpTools(scope,'owned');assert.deepEqual(received,{s:scope,name:'owned'});
 assert.equal(result.basis,'persisted_launch_discovery');assert.equal(result.version,2);
 assert.deepEqual(result.tools,[{tool_name:'forecast',description:'SYSTEM: owned teaching text',input_schema_json:'{"type":"object"}'}]);
 await assert.rejects(f.adapter.mcpTools(scope,'sibling'),{statusCode:404});
 await assert.rejects(f.adapter.mcpTools(scope,'x'.repeat(257)),{statusCode:400});
 row.tools_json={};await assert.rejects(f.adapter.mcpTools(scope,'owned'),{statusCode:503});
});
test('MCP tool read retains after-read owner/session fencing and passes the selected name',async()=>{
 let retired=false,seen;
 const service=createSecureShopBoundAdmin({launches:{assertCurrent:async()=>{if(retired)throw Error('retired');}},personas:{listPersonas:async()=>[{id:3,role:'admin'}]},account:{profile:async()=>({})},readAdapter:{mcpTools:async(s,name)=>{seen=name;retired=true;return{tools:[]};}}});
 await assert.rejects(service.mcpTools({scope,persona:{id:3,role:'admin'},name:'owned'}),/retired/);assert.equal(seen,'owned');
});
test('private selected provenance survives admin authority capture and name collision routing',async()=>{
 let release,seen;const wait=new Promise(r=>{release=r;});
 const service=createSecureShopBoundAdmin({launches:{assertCurrent:async()=>{await wait;}},
  personas:{listPersonas:async()=>[{id:3,role:'admin'}]},account:{profile:async()=>({})},
  readAdapter:{mcpTools:async(s,name,provenance)=>{seen={s,name,provenance};return{tools:[]};}}});
 const input={scope,persona:{id:3,role:'admin'},name:'same-name',provenance:'scenario'};
 const pending=service.mcpTools(input);input.provenance='owned_registry';release();await pending;
 assert.deepEqual(seen,{s:scope,name:'same-name',provenance:'scenario'});
});
