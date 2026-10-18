'use strict';
const {createSecureShopMcpOwnedFixture,retireSecureShopMcpOwnedFixturePath}=require('./secureshopMcpOwnedFixture');
const {createSecureShopControlledMcpServer}=require('./secureshopMcpControlledServer');
const {createSecureShopMcpSdkTransport}=require('./secureshopMcpSdkTransport');
function createSecureShopMcpControlledTargetPool({root,createFixture=createSecureShopMcpOwnedFixture,
  createServer=createSecureShopControlledMcpServer,createTransport=createSecureShopMcpSdkTransport,
  retireFixturePath=retireSecureShopMcpOwnedFixturePath}={}){
  const targets=new Map();const pending=new Map();let closed=false;let closing;
  function phase(trustScenario,schemaVersion){if(schemaVersion===undefined)return 0;
    if(!Number.isSafeInteger(schemaVersion)||schemaVersion<1||(trustScenario==='rogue_registration'&&schemaVersion!==1)
      ||(trustScenario==='rug_pull'&&schemaVersion>2))throw new Error('Controlled MCP target schema version mismatch');return schemaVersion-1;}
  async function get(targetId,trustScenario='rug_pull',schemaVersion){const initialPhase=phase(trustScenario,schemaVersion);
    if(closed)throw new Error('Controlled MCP target pool is closed');
    if(targets.has(targetId)){const value=targets.get(targetId);if(value.server.trustScenario!==trustScenario
      ||(schemaVersion!==undefined&&value.schemaVersion!==schemaVersion))throw new Error('Controlled MCP target scenario mismatch');return value;}
    if(pending.has(targetId)){const value=pending.get(targetId);if(value.trustScenario!==trustScenario
      ||value.initialPhase!==initialPhase)throw new Error('Controlled MCP target scenario mismatch');return value.promise;}
    const creation=(async()=>{const resource=await createFixture({root,targetId});
      try{const server=await createServer({targetId,resource,trustScenario,initialPhase});const transport=createTransport({controlledServer:server});
        const value={resource,server,transport,schemaVersion:initialPhase+1};targets.set(targetId,value);return value;}
      catch(error){let cleanupError;try{await resource.cleanup(resource.cleanupOperationId);}catch(cause){cleanupError=cause;}
        if(cleanupError)throw new AggregateError([error,cleanupError],'Controlled MCP target creation and cleanup failed');throw error;}})().finally(()=>pending.delete(targetId));pending.set(targetId,{trustScenario,initialPhase,promise:creation});return creation;}
  return Object.freeze({
    async discover(input){return(await get(input.targetId,input.trustScenario)).transport.discover(input);},
    async ensure(input){return(await get(input.targetId,input.trustScenario,input.schemaVersion)).transport.discover(input);},
    async callTool(input){const value=targets.get(input.targetId);if(!value)throw Object.assign(new Error('Controlled MCP target unavailable'),{code:'BOUND_MCP_TRANSPORT_UNAVAILABLE'});return value.transport.callTool(input);},
    async rotate(targetId){const value=await get(targetId,'rug_pull');const rotated=value.server.rotate();
      if(rotated)value.schemaVersion=2;return rotated;},
    async retire(targetId){const value=targets.get(targetId)||await pending.get(targetId)?.promise;if(!value)return retireFixturePath({root,targetId});
      await value.transport.close();targets.delete(targetId);return Object.freeze({ok:true,replayed:false,operationId:value.resource.cleanupOperationId});},
    async close(){if(closing)return closing;closed=true;closing=(async()=>{const creations=await Promise.allSettled([...pending.values()].map(row=>row.promise));
      const values=creations.filter(row=>row.status==='fulfilled').map(row=>row.value);
      const outcomes=await Promise.allSettled([...new Set([...targets.values(),...values])].map(value=>value.transport.disconnect()));
      targets.clear();const failures=[...creations,...outcomes].filter(row=>row.status==='rejected').map(row=>row.reason);
      if(failures.length)throw new AggregateError(failures,'Controlled MCP target pool shutdown failed');})();return closing;},
    state:targetId=>targets.has(targetId)?Object.freeze({active:true}):null,
  });
}
module.exports={createSecureShopMcpControlledTargetPool};
