'use strict';
const crypto=require('node:crypto');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {digestMcpValue}=require('./secureshopMcpTrustTools');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable(message='Bound MCP exercise unavailable'){return Object.assign(new Error(message),{code:'BOUND_MCP_UNAVAILABLE'});}
function createSecureShopMcpTrustApplication({launches,repository,transport,serverIdentity,trustScenario,endpoint,authorizeRotation}={}){
  if(typeof launches?.assertCurrent!=='function'||typeof launches?.reserveMcpTarget!=='function'
    ||typeof repository?.provision!=='function'||typeof repository?.recordDiscovery!=='function'
    ||typeof repository?.currentSchema!=='function'
    ||typeof transport?.discover!=='function'||typeof authorizeRotation!=='function'
    ||(trustScenario==='rug_pull'&&typeof transport?.rotate!=='function')
    ||typeof serverIdentity!=='string'||!serverIdentity||!['rogue_registration','rug_pull'].includes(trustScenario)
    ||typeof endpoint!=='string'||!endpoint)throw unavailable();
  function validateFence(scope,fence){
    if(fence===undefined)return;
    if(!fence?.binding||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withCrossStoreEffect!=='function')throw unavailable('Bound MCP persona authority unavailable');
    const expected=createLaunchScope(scope),actual=createLaunchScope(fence.binding);
    if(Object.keys(expected).some(key=>expected[key]!==actual[key])||!Number.isSafeInteger(scope.shopUserId)||scope.shopUserId<1||!['customer','merchant','admin'].includes(scope.role)||scope.shopUserId!==fence.binding.personaId||scope.role!==fence.binding.role)throw unavailable('Bound MCP persona authority mismatch');
  }
  async function check(value,fence){
    await launches.assertCurrent(value);
    if(fence!==undefined){await fence.assertRemoteAdmission();await launches.assertCurrent(value);}
  }
  function uncertain(cause){
    if(cause?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN')return cause;
    const error=Object.assign(new Error('Remote MCP outcome requires authoritative reconciliation'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});
    Object.defineProperty(error,'cause',{value:cause});return error;
  }
  async function target(scope,fence){validateFence(scope,fence);await check(scope,fence);
    const request={launchId:scope.launchId,platformSessionId:scope.platformSessionId,platformOwnerId:scope.platformOwnerId,expectedGeneration:scope.generation};
    const reserved=fence===undefined?await launches.reserveMcpTarget(request,trustScenario)
      :await fence.withCrossStoreEffect(()=>launches.reserveMcpTarget(request,trustScenario,{bounded:true}));
    const expectedKind=trustScenario==='rogue_registration'?'mcp_rogue':'mcp_rug_pull';
    if(!UUID.test(reserved?.targetId)||reserved.launchId!==scope.launchId||reserved.scenarioId!==scope.scenarioId
      ||reserved.generation!==scope.generation||reserved.kind!==expectedKind||reserved.trustScenario!==trustScenario)throw unavailable('Bound MCP target reservation mismatch');
    const value=Object.freeze({...scope,targetId:reserved.targetId,serverIdentity,trustScenario,kind:expectedKind});
    if(fence===undefined)await repository.provision(value);else await repository.provision(value,fence);
    await check(value,fence);return value;}
  async function discover(scope,{rotate=false}={},fence){const value=await target(scope,fence);
    const current=fence===undefined?await repository.currentSchema(value):await repository.currentSchema(value,fence);
    let revoke,dispatched=false;
    try{
      if(current&&!rotate){if(typeof transport.ensure!=='function')throw unavailable('Bound MCP target rehydration unavailable');
        if(fence!==undefined)await check(value,fence);dispatched=true;
        const remote=await transport.ensure({endpoint,serverIdentity,trustScenario,targetId:value.targetId,schemaVersion:current.version});
        if(remote?.serverIdentity!==serverIdentity||remote?.trustScenario!==trustScenario
          ||digestMcpValue(remote.tools)!==current.schemaSha256)throw unavailable('Bound MCP rehydrated schema mismatch');
        await check(value,fence);return current;}
      if(rotate){revoke=await authorizeRotation({...value,previousSchemaSha256:current?.schemaSha256});
        if(typeof revoke!=='function')throw unavailable('Bound MCP rotation authority unavailable');
        if(fence!==undefined)await check(value,fence);dispatched=true;await transport.rotate(value.targetId);}
      if(fence!==undefined)await check(value,fence);dispatched=true;
      const remote=await transport.discover({endpoint,serverIdentity,trustScenario,targetId:value.targetId});
      if(remote?.serverIdentity!==serverIdentity||remote?.trustScenario!==trustScenario
        ||!Array.isArray(remote.tools)||typeof remote.receiptSha256!=='string')throw unavailable();
      const schemaSha256=digestMcpValue(remote.tools);
      if(current?.schemaSha256===schemaSha256)throw unavailable('Bound MCP schema did not change');
      if(fence!==undefined)await check(value,fence);
      const input={expectedVersion:current?.version||0,schemaSha256,discoveryReceiptSha256:remote.receiptSha256,tools:remote.tools},persona={id:scope.shopUserId,role:scope.role};
      const recorded=fence===undefined?await repository.recordDiscovery(value,input,persona):await repository.recordDiscovery(value,input,persona,fence);
      await check(value,fence);return recorded;
    }catch(cause){if(fence!==undefined&&dispatched)throw uncertain(cause);throw cause;}
    finally{revoke?.();}}
  return Object.freeze({target,initialize:(scope,fence)=>discover(scope,{},fence),rotate:(scope,fence)=>discover(scope,{rotate:true},fence),trustScenario,serverIdentity});
}
module.exports={createSecureShopMcpTrustApplication};
