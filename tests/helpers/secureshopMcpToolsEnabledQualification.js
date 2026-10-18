'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
// Persisted discovery fixtures qualify reads, never a network discovery or model claim.
async function seedMcpTools({identityPool,agentsMigration,bearer}){
 const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identityPool);
 const s=await launches.resolveCapability(bearer);assert.ok(s);
 const id=randomUUID(),name='owned-inventory',tools=[{name:'forecast',description:'Owned teaching description',inputSchema:{type:'object',properties:{city:{type:'string'}}}}];
 await agentsMigration.query(`INSERT INTO secureshop_agents.bound_mcp_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,server_identity,trust_scenario,current_schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,'rug_pull',1)`,[id,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,name]);
 await agentsMigration.query('INSERT INTO secureshop_agents.bound_mcp_schema_versions(target_id,version,schema_sha256,discovery_receipt_sha256) VALUES($1,1,$2,$3)',[id,Buffer.alloc(32,1),Buffer.alloc(32,2)]);
 await agentsMigration.query('INSERT INTO secureshop_agents.bound_mcp_tool_payloads(target_id,version,tools_json) VALUES($1,1,$2::jsonb)',[id,JSON.stringify(tools)]);
 return {name,tools};
}
async function qualifyMcpTools({identityPool,agentsMigration,request,bearer,headers,adminToken,studentToken,siblingHeaders,siblingAdminToken}){
 const {name,tools}=await seedMcpTools({identityPool,agentsMigration,bearer});
 const url='/api/secureshop/admin/mcp/servers/'+name+'/tools';
 const registry=await request('/api/secureshop/admin/mcp/servers',adminToken,undefined,headers);assert.equal(registry.status,200);
 const server=registry.body.servers.find(row=>row.name===name);assert.ok(server);assert.equal(server.last_schema_hash,'01'.repeat(32));assert.equal(server.status,'discovered');assert.equal(server.added_at,server.registered_at);
 const result=await request(url,adminToken,undefined,headers);assert.equal(result.status,200,JSON.stringify(result.body));
 assert.equal(result.body.basis,'persisted_launch_discovery');assert.equal(result.body.version,1);assert.equal(result.body.schema_hash,'01'.repeat(32));assert.deepEqual(result.body.tools,[{tool_name:'forecast',description:tools[0].description,input_schema_json:JSON.stringify(tools[0].inputSchema)}]);
 assert.equal((await request(url,siblingAdminToken,undefined,siblingHeaders)).status,404);
 assert.equal((await request(url,studentToken,undefined,headers)).status,403);
 assert.equal((await request(url+'?owner=another',adminToken,undefined,headers)).status,400);
 return {persistedDiscovery:true,siblingNotFound:true,nonAdminDenied:true,queryAuthorityDenied:true,networkDiscovery:false,modelCalls:0};
}
module.exports={qualifyMcpTools,seedMcpTools};
