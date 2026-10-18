'use strict';
const unavailable=(message,statusCode=503)=>Object.assign(new Error(message),{code:'BOUND_MCP_REGISTRY_READ_UNAVAILABLE',statusCode});
function tools(row){
 if(!row||!Array.isArray(row.tools_json)||row.tools_json.length>64)throw unavailable('Owned registry tool projection unavailable');
 return row.tools_json.map(tool=>{if(!tool||typeof tool.name!=='string'||typeof tool.description!=='string'||!tool.inputSchema||typeof tool.inputSchema!=='object'||Array.isArray(tool.inputSchema))throw unavailable('Owned registry tool projection unavailable');return{tool_name:tool.name,description:tool.description,input_schema_json:JSON.stringify(tool.inputSchema)};});
}
function createOwnedMcpRegistryAdminReadOverlay({base,repository,enabled=false,readDiscoveryAssessment}={}){
 if(readDiscoveryAssessment!==undefined&&typeof readDiscoveryAssessment!=='function')throw new TypeError('Discovery readiness reader required');
 if(typeof enabled!=='boolean'||!base)throw new TypeError('Owned MCP registry read overlay dependencies required');
 if(!enabled)return Object.freeze({...base,async mcpServers(scope){return {...await base.mcpServers(scope),registry_administration:{ready:false}};}});
 if(!['head','servers','history','tools'].every(name=>typeof repository?.[name]==='function')||!['mcpServers','mcpHistory','mcpTools'].every(name=>typeof base?.[name]==='function'))throw new TypeError('Owned MCP registry read overlay dependencies required');
 async function baseRows(method,scope){try{return await base[method](scope);}catch(error){if(error?.code!=='BOUND_MCP_DISABLED')throw error;return{basis:'persisted_launch_discovery',catalog_visible:false,scenarios:[],servers:[],history:[]};}}
 return Object.freeze({...base,
  async mcpServers(scope){const [prior,extra,version]=await Promise.all([baseRows('mcpServers',scope),repository.servers(scope),repository.head(scope)]);if(typeof version!=='string'||!/^(0|[1-9][0-9]{0,15})$/.test(version)||BigInt(version)>9007199254740991n)throw unavailable('Owned registry version unavailable');const scopeKey=require('node:crypto').createHash('sha256').update(JSON.stringify(require('./secureshopConversationBinding').createLaunchScope(scope))).digest('hex');if(extra.length>32)throw unavailable('Owned registry server bound exceeded');return{...prior,...(readDiscoveryAssessment?{registry_discovery_assessment:{ready:await readDiscoveryAssessment(scope)===true}}:{}),registry_capability:'secureshop-owned-mcp-registry.v1',registry_versioned:true,registry_administration:{ready:true,version,scopeKey},servers:[...prior.servers,...extra]};},
  async mcpHistory(scope){const [prior,extra]=await Promise.all([baseRows('mcpHistory',scope),repository.history(scope)]);if(extra.length>256)throw unavailable('Owned registry history bound exceeded');return{...prior,registry_capability:'secureshop-owned-mcp-registry.v1',history:[...prior.history,...extra].sort((a,b)=>String(a.ts).localeCompare(String(b.ts))||String(a.name).localeCompare(String(b.name)))};},
  async mcpTools(scope,name,provenance){if(provenance!==undefined&&!['owned_registry','scenario'].includes(provenance))throw unavailable('Owned registry provenance unavailable');if(provenance==='scenario')return base.mcpTools(scope,name);const row=await repository.tools(scope,name);if(!row){if(provenance==='owned_registry')throw unavailable('Owned registry server unavailable',404);return base.mcpTools(scope,name);}return{basis:'persisted_launch_discovery',catalog_visible:true,scenarios:[],registry_capability:'secureshop-owned-mcp-registry.v1',name,version:row.version,schema_hash:row.schema_hash,tools:tools(row)};}
 });
}
module.exports={createOwnedMcpRegistryAdminReadOverlay};
