'use strict';
const crypto=require('node:crypto');const {digestMcpValue}=require('./secureshopMcpTrustTools');
const {featureModeForFence}=require('./secureshopFeatureModeAuthority');
const {CONTROLLED_MCP_SCENARIOS}=require('./secureshopMcpControlledServer');
const APPROVED_SCHEMA_SHA256=digestMcpValue(CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[0]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CALL_ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FENCE_SCOPE_KEYS=Object.freeze(['launchId','scenarioId','generation','platformOwnerId','platformSessionId']);
function unavailable(message='Bound MCP external observation unavailable'){return Object.assign(new Error(message),{code:'BOUND_MCP_UNAVAILABLE'});}
function authInvalid(){return Object.assign(new Error('Shop authentication required'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});}
function uncertain(cause){const error=Object.assign(new Error('MCP operation outcome is unknown; do not automatically retry'),
  {code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true,automaticRetry:false});
  Object.defineProperty(error,'cause',{value:cause});return error;}
function createSecureShopMcpTrustExternalAdapter({application,repository,transport,checkCurrent,serverIdentity,trustScenario,expectedSchemaSha256}={}){
  if(typeof application?.target!=='function'||typeof repository?.currentSchema!=='function'||typeof repository?.recordInvocation!=='function'
    ||typeof transport?.callTool!=='function'||typeof checkCurrent!=='function'||typeof serverIdentity!=='string'
    ||typeof expectedSchemaSha256!=='string'||!/^[0-9a-f]{64}$/.test(expectedSchemaSha256)
    ||!['rogue_registration','rug_pull'].includes(trustScenario))throw unavailable();
  function assertFence(binding,fence){if(fence===undefined)return;
    if(typeof fence?.assertRemoteAdmission!=='function'||typeof fence?.withPersonaEffect!=='function'||!fence.binding
      ||FENCE_SCOPE_KEYS.some(key=>fence.binding[key]!==binding?.[key])
      ||fence.binding.personaId!==binding?.shopUserId||fence.binding.role!==binding?.role)throw authInvalid();}
  async function current(value,fence){try{await checkCurrent(value);if(fence)await fence.assertRemoteAdmission();}
    catch(error){if(fence)error.executionBoundary=true;throw error;}}
  async function createToolPool(binding,context,fence){const execution=context?.execution;
    if(!execution||!UUID.test(execution.runId)||typeof execution.ownerKey!=='string'||!execution.ownerKey
      ||execution.durableGeneration===undefined||execution.durableGeneration===null||typeof execution.check!=='function'
      ||!UUID.test(context?.requestId)||typeof context?.sessionId!=='string'||!context.sessionId)throw unavailable();
    assertFence(binding,fence);const fixed=featureModeForFence(fence)?.effectiveMode==='fixed';
    if(fixed&&trustScenario!=='rug_pull')throw unavailable('Unapproved connector blocked by fixed policy');
    await execution.check();const target=fence?await application.target(binding,fence):await application.target(binding);await current(target,fence);
    const presented=fence?await repository.currentSchema(target,fence):await repository.currentSchema(target);
    const schema=presented?structuredClone(presented):null;
    if(!schema||schema.serverIdentity!==serverIdentity||schema.schemaSha256!==expectedSchemaSha256||!Array.isArray(schema.tools))throw unavailable('Presented MCP schema is no longer current');
    if(fixed&&(schema.version!==1||schema.schemaSha256!==APPROVED_SCHEMA_SHA256||digestMcpValue(schema.tools)!==APPROVED_SCHEMA_SHA256))throw unavailable('Changed MCP schema blocked by fixed policy');
    return Object.freeze({async callTool(agent,toolName,args,callContext){await execution.check();if(fence)await current(target,fence);
      if(agent!==serverIdentity||!CALL_ID.test(callContext?.callId||'')||!schema.tools.some(tool=>tool.name===toolName))throw unavailable('Selected MCP tool is unavailable');
      if(fixed){
        const latest=await repository.currentSchema(target,fence);
        if(latest?.version!==1||latest.schemaSha256!==APPROVED_SCHEMA_SHA256||digestMcpValue(latest.tools)!==APPROVED_SCHEMA_SHA256)throw unavailable('MCP schema changed before invocation');
        await current(target,fence);
      }
      const operationId=crypto.randomUUID();let remote;
      try{remote=await transport.callTool({serverIdentity,toolName,args,schemaSha256:schema.schemaSha256,
        targetId:target.targetId,signal:execution.signal});await execution.check();await current(target,fence);
        if(remote?.trustScenario!==trustScenario||remote.serverIdentity!==serverIdentity||remote.schemaSha256!==schema.schemaSha256
          ||!['receiptSha256','trustPolicySha256'].every(key=>typeof remote[key]==='string'&&/^[0-9a-f]{64}$/.test(remote[key]))
          ||typeof remote.approved!=='boolean'||typeof remote.serverApproved!=='boolean'||typeof remote.schemaApproved!=='boolean'
          ||remote.approved!==(remote.serverApproved&&remote.schemaApproved)
          ||!['public_forecast_lookup','protected_record_export'].includes(remote.behaviorClass))throw unavailable('Remote MCP receipt mismatch');
        if(fixed&&(!remote.approved||remote.behaviorClass!=='public_forecast_lookup'||remote.schemaSha256!==APPROVED_SCHEMA_SHA256))throw unavailable('Unapproved MCP effect blocked');
      }catch(cause){if(fence)throw uncertain(cause);throw cause;}
      return Object.freeze({content:Object.freeze([{type:'text',text:JSON.stringify(remote.result)}]),_meta:Object.freeze({version:1,operationId,
        targetId:target.targetId,serverIdentity,trustScenario,schemaVersion:schema.version,schemaSha256:schema.schemaSha256,
        runId:execution.runId,ownerKey:execution.ownerKey,generation:String(execution.durableGeneration),
        requestId:context.requestId,sessionId:context.sessionId,callId:callContext.callId,
        remoteReceiptSha256:remote.receiptSha256,trustPolicySha256:remote.trustPolicySha256,approved:remote.approved,
        serverApproved:remote.serverApproved,schemaApproved:remote.schemaApproved,behaviorClass:remote.behaviorClass,
        argumentsSha256:digestMcpValue(args),resultSha256:digestMcpValue(remote.result)})});}});}
  async function observeExternalTool(packet,fence){const observation=packet?.observation;const meta=observation?.result?._meta;const execution=packet?.run;
    if(!execution||!UUID.test(execution.runId)||typeof execution.ownerKey!=='string'||!execution.ownerKey
      ||execution.durableGeneration===undefined||execution.durableGeneration===null||typeof execution.check!=='function'
      ||!UUID.test(packet.requestId)||typeof packet.sessionId!=='string'||!packet.sessionId
      ||!CALL_ID.test(observation?.callId||'')||observation.tool!==`${serverIdentity}.forecast_lookup`
      ||meta?.version!==1||meta.serverIdentity!==serverIdentity||meta.trustScenario!==trustScenario
      ||meta.runId!==execution.runId||meta.ownerKey!==execution.ownerKey
      ||meta.generation!==String(execution.durableGeneration)||meta.requestId!==packet.requestId
      ||meta.sessionId!==packet.sessionId||meta.callId!==observation.callId||!UUID.test(meta.operationId)
      ||digestMcpValue(observation.args)!==meta.argumentsSha256)throw unavailable();
    if(featureModeForFence(fence)?.effectiveMode==='fixed'&&(trustScenario!=='rug_pull'||meta.schemaVersion!==1
      ||meta.schemaSha256!==APPROVED_SCHEMA_SHA256||meta.approved!==true||meta.behaviorClass!=='public_forecast_lookup'))throw unavailable('Fixed MCP receipt unavailable');
    await execution.check();
    const receipt=observation.effectReceipt;const expectedKey=`${packet.requestId}:${JSON.stringify([observation.step,observation.callId,observation.tool])}`;
    if(receipt?.version!==1||receipt.status!=='completed'||receipt.runId!==execution.runId||receipt.ownerKey!==execution.ownerKey
      ||receipt.generation!==String(execution.durableGeneration)||receipt.effectKey!==expectedKey)throw unavailable('Completed MCP effect receipt mismatch');
    let result;try{result=JSON.parse(observation.result.content?.[0]?.text);}catch{throw unavailable('Remote MCP result unavailable');}
    if(digestMcpValue(result)!==meta.resultSha256)throw unavailable('Remote MCP result mismatch');
    assertFence(packet.binding,fence);let recorded;
    try{const target=fence?await application.target(packet.binding,fence):await application.target(packet.binding);if(target.targetId!==meta.targetId)throw unavailable();await current(target,fence);await execution.check();
      const invocation={operationId:meta.operationId,runId:execution.runId,requestId:packet.requestId,
        callId:observation.callId,toolName:'forecast_lookup',argumentsSha256:meta.argumentsSha256,schemaVersion:meta.schemaVersion,
        schemaSha256:meta.schemaSha256,remoteReceiptSha256:meta.remoteReceiptSha256,trustPolicySha256:meta.trustPolicySha256,
        trustScenario,approved:meta.approved,serverApproved:meta.serverApproved,schemaApproved:meta.schemaApproved,
        behaviorClass:meta.behaviorClass,resultSha256:meta.resultSha256,result};
      const actor={id:packet.binding.shopUserId,role:packet.binding.role};
      recorded=fence?await repository.recordInvocation(target,invocation,actor,fence):await repository.recordInvocation(target,invocation,actor);
    // A remote effect whose canonical invocation write fails is cleanup debt,
    // never grading evidence. Propagate that failure so the turn cannot finish.
      await current(target,fence);await execution.check();
    }catch(cause){if(fence)throw uncertain(cause);throw cause;}
    return Object.freeze({invocation:recorded,effectReceipt:receipt,observation});}
  return Object.freeze({createToolPool,observeExternalTool});
}
module.exports={createSecureShopMcpTrustExternalAdapter};
