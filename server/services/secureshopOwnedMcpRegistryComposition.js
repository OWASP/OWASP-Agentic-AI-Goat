'use strict';
const CAPABILITY='secureshop-owned-mcp-registry.v1';
async function createOwnedMcpRegistryComposition({enabled=false,agentsPool,personaAuthority,authenticatePersona,executorClient,readMode,expectedDatabase,
 readiness,repositoryFactory,serviceFactory,routerFactory,wrapService=value=>value}={}){
 if(typeof enabled!=='boolean')throw new TypeError('Owned MCP registry flag must be boolean');
 if(!enabled)return undefined;
 if(typeof agentsPool?.query!=='function'||typeof personaAuthority?.capture!=='function'||typeof authenticatePersona!=='function'
  ||typeof executorClient?.health!=='function'||typeof executorClient?.execute!=='function'||typeof readMode!=='function'||typeof expectedDatabase!=='string'||!expectedDatabase)throw new TypeError('Owned MCP registry composition dependencies required');
 const ready=readiness||require('../database/postgres/secureshopOwnedMcpRegistryRepository').assertOwnedMcpRegistryReady;
 const createRepository=repositoryFactory||require('../database/postgres/secureshopOwnedMcpRegistryRepository').createOwnedMcpRegistryRepository;
 const createService=serviceFactory||require('./secureshopOwnedMcpRegistry').createOwnedMcpRegistry;
 const createRouter=routerFactory||require('../routes/secureshop/boundMcpRegistry').createBoundMcpRegistryRouter;
 await ready({pool:agentsPool,expectedDatabase});await executorClient.health();
 const repository=createRepository({pool:agentsPool,personaAuthority}),service=wrapService(createService({repository,executor:executorClient,readMode})),router=createRouter({service,authenticatePersona});
 return Object.freeze({capability:CAPABILITY,router,service,repository});
}
module.exports={createOwnedMcpRegistryComposition,OWNED_MCP_REGISTRY_CAPABILITY:CAPABILITY};
