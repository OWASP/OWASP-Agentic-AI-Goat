'use strict';
// Qualified source release still requires the authenticated, fingerprint-pinned
// managed transport at every admission. This does not activate an installation.
const {createOwnedShadowCompositeTargets}=require('./ownedShadowCompositeTargets');
async function composeOwnedShadowProduction({resourcePool,identityPool,targets,configuration,env=process.env}={}){
 if(configuration===undefined)configuration=require('./ownedShadowManagedConfiguration').load();
 if(configuration?.enabled&&!/^[a-f0-9]{64}$/.test(configuration.runtimeDigest||''))throw Error('SHADOW_RUNTIME_PIN_REQUIRED');
 const relation=(await resourcePool.query("SELECT to_regclass('mcp.shadow_target_leases')::text AS name")).rows[0]?.name;
 if(!relation&&!configuration?.enabled)return targets;
 if(!relation)throw Object.assign(Error('SHADOW_LEASE_UNAVAILABLE'),{code:'SHADOW_LEASE_UNAVAILABLE'});
 const service=configuration?require('./ownedShadowServiceClient').createOwnedShadowServiceClient({baseUrl:configuration.url,token:configuration.token}):null;
 return createOwnedShadowCompositeTargets({base:targets,shadow:service,leases:require('../../database/postgres/mcpShadowLeaseRepository').createMcpShadowLeaseRepository(resourcePool),receiptRepository:require('../../database/postgres/mcpShadowReceiptRepository').createMcpShadowReceiptRepository(identityPool),readMode:async()=>{if(!['fixed','vuln'].includes((configuration?.mode||env.LAB_MODE)))throw Error('SHADOW_MODE_UNAVAILABLE');return configuration.mode||env.LAB_MODE;},enabled:configuration?.enabled===true,expectedRuntimeDigest:configuration?.runtimeDigest||null,objectiveQualified:true});
}
module.exports={composeOwnedShadowProduction};
