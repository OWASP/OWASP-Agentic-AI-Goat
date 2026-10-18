'use strict';
const {digestMcpValue}=require('./secureshopMcpTrustTools');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KINDS=Object.freeze({mcp_rogue:Object.freeze({trustScenario:'rogue_registration',serverIdentity:'secureshop-rogue-weather-lab'}),
  mcp_rug_pull:Object.freeze({trustScenario:'rug_pull',serverIdentity:'secureshop-weather-lab'})});
function failure(message){return Object.assign(new Error(message),{code:'BOUND_MCP_UNAVAILABLE'});}
function uuid(value){if(typeof value!=='string'||!UUID.test(value))throw failure('Bound MCP cleanup coordinate is invalid');return value.toLowerCase();}
function positive(value,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(value)||value<1||value>max)throw failure('Bound MCP cleanup coordinate is invalid');return value;}
function scope(input,operationId){const kind=KINDS[input?.targetKind];if(!kind)throw failure('Bound MCP cleanup target is invalid');
  return Object.freeze({targetId:uuid(input.targetId),targetKind:input.targetKind,launchId:uuid(input.launchId),scenarioId:uuid(input.scenarioId),
    generation:positive(input.fromGeneration),platformOwnerId:positive(input.platformOwnerId,2147483647),
    platformSessionId:positive(input.platformSessionId,2147483647),operationId:uuid(operationId),...kind});}
function createSecureShopMcpTrustResetAdapter({repository,targetPool,cleanupAuthority}={}){
  if(typeof repository?.retire!=='function'||typeof repository?.readCleanupReceipt!=='function'
    ||typeof targetPool?.retire!=='function'||typeof cleanupAuthority?.checkTarget!=='function')throw failure('Bound MCP cleanup dependencies are required');
  async function authorize(value){const result=await cleanupAuthority.checkTarget(Object.freeze({...value,fromGeneration:value.generation}));
    if(!['fenced','committed','aborted'].includes(result?.status))throw failure('Bound MCP cleanup authority is unavailable');}
  async function readCleanupReceipt(input,{operationId}={}){const value=scope(input,operationId||input?.operationId);await authorize(value);
    const stored=await repository.readCleanupReceipt(value,{operationId:value.operationId,targetKind:value.targetKind,
      fromGeneration:value.generation});return Object.freeze({targetId:stored.targetId,kind:value.targetKind,
      launchId:stored.launchId,scenarioId:stored.scenarioId,generation:stored.fromGeneration,
      platformOwnerId:stored.platformOwnerId,platformSessionId:stored.platformSessionId,operationId:stored.operationId,
      version:stored.targetReceiptVersion,receiptSha256:stored.targetReceiptSha256,completedAt:stored.targetCompletedAt});}
  return Object.freeze({async cleanup(input,{operationId}={}){const value=scope(input,operationId);await authorize(value);
    await targetPool.retire(value.targetId);await authorize(value);
    const receiptSha256=digestMcpValue({version:1,operationId:value.operationId,targetId:value.targetId,targetKind:value.targetKind,
      launchId:value.launchId,scenarioId:value.scenarioId,generation:value.generation,platformOwnerId:value.platformOwnerId,
      platformSessionId:value.platformSessionId,ownedFixtureAbsent:true});
    await repository.retire(value,{operationId:value.operationId,targetKind:value.targetKind,fromGeneration:value.generation,receiptSha256});
    return readCleanupReceipt(input,{operationId:value.operationId});},readCleanupReceipt});
}
module.exports={createSecureShopMcpTrustResetAdapter,MCP_TRUST_TARGET_KINDS:KINDS};
