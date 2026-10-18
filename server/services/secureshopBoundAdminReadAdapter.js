'use strict';
function unavailable(message, code='BOUND_ADMIN_READ_UNAVAILABLE') {
 return Object.assign(new Error(message),{code,statusCode:503});
}
function createSecureShopBoundAdminReadAdapter({repository,mcpConfigured,readMcpAvailability,readRuntimeHealth}={}) {
 if(!repository || typeof mcpConfigured!=='boolean') throw new TypeError('Bound read dependencies required');
 async function mcp() {
  if(!mcpConfigured)throw unavailable('Owned MCP teaching service is configured disabled','BOUND_MCP_DISABLED');
  if(typeof readMcpAvailability!=='function')throw unavailable('Owned MCP availability probe unavailable');
  const state=await readMcpAvailability();
  if(!state?.registered)throw unavailable('Owned MCP catalog is unavailable');
  // This is configuration status, never a synthetic network-health claim.
  return {basis:'persisted_launch_discovery',catalog_visible:state.visible===true,scenarios:state.enabled};
 }
 return Object.freeze({
  async mcpTools(scope,name){
   const state=await mcp();
   if(typeof name!=='string'||!name.length||Buffer.byteLength(name)>256)throw Object.assign(new Error('Invalid server name'),{statusCode:400});
   const row=await repository.mcpTools(scope,name);
   if(!row)throw Object.assign(new Error('No discovered server in this launch'),{statusCode:404});
   if(!Array.isArray(row.tools_json)||row.tools_json.length>64)throw unavailable('Owned tool projection unavailable');
   const tools=row.tools_json.map(tool=>{
    if(!tool||typeof tool.name!=='string'||typeof tool.description!=='string'||!tool.inputSchema||typeof tool.inputSchema!=='object'||Array.isArray(tool.inputSchema))throw unavailable('Owned tool projection unavailable');
    return {tool_name:tool.name,description:tool.description,input_schema_json:JSON.stringify(tool.inputSchema)};
   });
   return {...state,name,version:row.version,schema_hash:row.schema_hash,tools};
  },
  async mcpServers(scope){const state=await mcp();const servers=await repository.mcpServers(scope);if(servers.length>2)throw unavailable('Owned MCP target bound exceeded');return {...state,servers};},
  async mcpHistory(scope){const state=await mcp();const history=await repository.mcpHistory(scope);if(history.length>32)throw unavailable('Owned MCP history bound exceeded');return {...state,history};},
  async dbSizes(scope){return {basis:'selected_launch_json_row_bytes',files:await repository.sizes(scope)};},
  async runtimeHealth(scope){
   if(typeof readRuntimeHealth!=='function')throw unavailable('In-process LangGraph health probe unavailable; no separate agent-host health is inferred');
   const health=await readRuntimeHealth(scope);
   if(health?.ready!==true)throw unavailable('Bound LangGraph runtime is not ready');
   return {status:'SERVICE_READY',runtime:'in-process LangGraph',basis:health.basis,providers:health.providers,model_execution:'not_tested',port:null,agents:null};
  },
 });
}
module.exports={createSecureShopBoundAdminReadAdapter};
