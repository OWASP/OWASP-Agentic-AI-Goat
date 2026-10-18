'use strict';
const crypto=require('node:crypto');
const normalize=value=>Array.isArray(value)?value.map(normalize):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,normalize(value[key])])):value;
const canonical=value=>JSON.stringify(normalize(value));
const digest=value=>crypto.createHash('sha256').update(typeof value==='string'?value:canonical(value)).digest('hex');
function unavailable(message='Bound MCP exercise unavailable'){return Object.assign(new Error(message),{code:'BOUND_MCP_UNAVAILABLE'});}
function createSecureShopMcpTrustTools({repository,transport,resolveTarget,checkCurrent,serverIdentity}={}){
  if(!repository||typeof repository.currentSchema!=='function'||typeof repository.recordInvocation!=='function'
    ||typeof transport?.callTool!=='function'||typeof resolveTarget!=='function'||typeof checkCurrent!=='function'
    ||typeof serverIdentity!=='string'||!serverIdentity)throw unavailable();
  return Object.freeze({
    async manifest(binding){const target=await resolveTarget(binding);await checkCurrent(target);
      const schema=await repository.currentSchema(target);
      if(!schema||schema.serverIdentity!==serverIdentity||!Array.isArray(schema.tools))throw unavailable();
      return Object.freeze(schema.tools.map(tool=>Object.freeze({agent:serverIdentity,tool:tool.name,
        description:tool.description,inputSchema:tool.inputSchema,isExternalMcp:true,
        schemaVersion:schema.version,schemaSha256:schema.schemaSha256})));
    },
    async call(binding,{execution,requestId,callId,toolName,args}={}){
      const target=await resolveTarget(binding);await checkCurrent(target);await execution?.check?.();
      const schema=await repository.currentSchema(target);
      const tool=schema?.tools?.find(row=>row.name===toolName);
      if(!tool||schema.serverIdentity!==serverIdentity)throw unavailable('Selected MCP tool is unavailable');
      const remote=await transport.callTool({serverIdentity,toolName,args,schemaSha256:schema.schemaSha256,
        targetId:target.targetId,signal:execution.signal});
      await execution?.check?.();await checkCurrent(target);
      if(remote?.serverIdentity!==serverIdentity||remote?.schemaSha256!==schema.schemaSha256
        ||typeof remote.receiptSha256!=='string'||!/^[0-9a-f]{64}$/.test(remote.receiptSha256)
        ||typeof remote.trustPolicySha256!=='string'||!/^[0-9a-f]{64}$/.test(remote.trustPolicySha256)
        ||remote.trustScenario!==target.trustScenario||typeof remote.approved!=='boolean'
        ||typeof remote.serverApproved!=='boolean'||typeof remote.schemaApproved!=='boolean'
        ||remote.approved!==(remote.serverApproved&&remote.schemaApproved)
        ||!['public_forecast_lookup','protected_record_export'].includes(remote.behaviorClass))throw unavailable('Remote MCP receipt mismatch');
      const recorded=await repository.recordInvocation(target,{operationId:crypto.randomUUID(),runId:execution.runId,
        requestId,callId,toolName,argumentsSha256:digest(args),schemaVersion:schema.version,
        schemaSha256:schema.schemaSha256,remoteReceiptSha256:remote.receiptSha256,
        trustPolicySha256:remote.trustPolicySha256,trustScenario:remote.trustScenario,approved:remote.approved,
        serverApproved:remote.serverApproved,schemaApproved:remote.schemaApproved,behaviorClass:remote.behaviorClass,
        resultSha256:digest(remote.result),result:remote.result},{id:binding.shopUserId,role:binding.role});
      await execution?.check?.();await checkCurrent(target);return recorded;
    },
  });
}
module.exports={createSecureShopMcpTrustTools,digestMcpValue:digest};
