'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto');
async function qualifyBoundAdminReads({agentsRuntime,agentsMigration,reviewRuntime,personaRepository,launches,fixtures}) {
 const {createSecureShopBoundAdminReadRepository}=require('../../server/database/postgres/secureshopBoundAdminReadRepository');
 const {createSecureShopBoundAdminReadAdapter}=require('../../server/services/secureshopBoundAdminReadAdapter');
 const {createSecureShopBoundAdmin}=require('../../server/services/secureshopBoundAdmin');
 for(const [i,f] of fixtures.slice(0,2).entries()){
  const s=f.binding,target=crypto.randomUUID();
  await agentsMigration.query(`INSERT INTO secureshop_agents.bound_mcp_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,server_identity,trust_scenario,current_schema_version)
   VALUES($1,$2,$3,$4,$5,$6,$7,'rug_pull',1)`,[target,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,'owned-read-'+i]);
  await agentsMigration.query(`INSERT INTO secureshop_agents.bound_mcp_schema_versions(target_id,version,schema_sha256,discovery_receipt_sha256) VALUES($1,1,$2,$3)`,[target,Buffer.alloc(32,i+1),Buffer.alloc(32,i+3)]);
  await agentsMigration.query(`INSERT INTO secureshop_agents.bound_mcp_tool_payloads(target_id,version,tools_json) VALUES($1,1,$2::jsonb)`,[target,JSON.stringify([{name:'owned_tool_'+i,description:'Owned persisted teaching description '+i,inputSchema:{type:'object'}}])]);
 }
 const repository=createSecureShopBoundAdminReadRepository({agentsPool:agentsRuntime,reviewPool:reviewRuntime});
 assert.equal(await repository.probe({...fixtures[0].binding,launchId:crypto.randomUUID()}),true);
 const adapter=createSecureShopBoundAdminReadAdapter({repository,readRuntimeHealth:require('../../server/services/secureshopBoundRuntimeHealth').createSecureShopBoundRuntimeHealth({repository,isServing:()=>true}),mcpConfigured:true,readMcpAvailability:async()=>({registered:true,visible:true,enabled:{rug_pull:true}})});
 const admin=createSecureShopBoundAdmin({launches,personas:personaRepository,account:{profile:async()=>{throw Error('not used');}},readAdapter:adapter});
 for(const [i,f] of fixtures.slice(0,2).entries()){
  const input={scope:f.binding,persona:f.persona};
  assert.deepEqual((await admin.mcpServers(input)).servers.map(r=>r.name),['owned-read-'+i]);
  const history=(await admin.mcpHistory(input)).history;assert.equal(history.length,1);assert.equal(history[0].schema_hash,Buffer.alloc(32,i+1).toString('hex'));
  const tools=await admin.mcpTools({...input,name:'owned-read-'+i});assert.equal(tools.version,1);assert.equal(tools.schema_hash,history[0].schema_hash);assert.deepEqual(tools.tools,[{tool_name:'owned_tool_'+i,description:'Owned persisted teaching description '+i,input_schema_json:'{"type":"object"}'}]);
  await assert.rejects(admin.mcpTools({...input,name:'owned-read-'+(1-i)}),{statusCode:404});
  const health=await admin.runtimeHealth(input);assert.equal(health.status,'SERVICE_READY');assert.equal(health.model_execution,'not_tested');
  const sizes=await admin.dbSizes(input);assert.ok(sizes.files[0].size_bytes>0);assert.equal(sizes.basis,'selected_launch_json_row_bytes');
  await assert.rejects(admin.mcpServers({...input,persona:{...f.persona,role:'customer'}}),{code:'OWNER_MISMATCH'});
  await assert.rejects(admin.mcpServers({...input,scope:{...f.binding,platformSessionId:fixtures[1-i].binding.platformSessionId}}));
  await assert.rejects(admin.mcpServers({...input,scope:{...f.binding,generation:f.binding.generation+1}}));
 }
 return {admin,scope:'Native scoped read projections; controlled catalog availability, no network/model health claim',ownerAndSibling:true,foreignSessionDenied:true,staleGenerationDenied:true,nonAdminDenied:true,logicalBytesMeasured:true};
}
module.exports={qualifyBoundAdminReads};
