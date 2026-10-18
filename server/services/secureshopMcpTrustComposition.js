'use strict';
const {createSecureShopMcpTrustApplication}=require('./secureshopMcpTrustApplication');
const {createSecureShopMcpTrustTools}=require('./secureshopMcpTrustTools');
const {createSecureShopMcpTrustAssessment}=require('./secureshopMcpTrustAssessment');
const {createSecureShopMcpTrustExternalAdapter}=require('./secureshopMcpTrustExternalAdapter');
function unavailable(){return Object.assign(new Error('Bound MCP composition unavailable'),{code:'BOUND_MCP_UNAVAILABLE'});}
function createSecureShopMcpTrustComposition({enabled=false,launches,repository,transport,serverIdentity,trustScenario,endpoint,
  authorizeRotation,receipts,progress,judge,qualifyModel,personaBindings}={}){
  if(personaBindings!==undefined&&typeof personaBindings?.capture!=='function')throw unavailable();
  if(typeof enabled!=='boolean')throw unavailable();if(!enabled)return Object.freeze({ready:false});
  if(typeof repository?.readInvocation!=='function'||typeof repository?.readPriorSchema!=='function')throw unavailable();
  const application=createSecureShopMcpTrustApplication({launches,repository,transport,serverIdentity,trustScenario,endpoint,authorizeRotation});
  const assessment=createSecureShopMcpTrustAssessment({receipts,progress,judge,qualifyModel,
    ...(personaBindings===undefined?{}:{personaBindings}),trustScenario,resolveTarget:application.target,
    readInvocation:(binding,id)=>repository.readInvocation(binding,id),
    readPriorSchema:(binding,invocation)=>repository.readPriorSchema(binding,invocation)});
  return Object.freeze({ready:true,application,assessment,
    createExternalAdapter:({checkCurrent,schemaSha256})=>createSecureShopMcpTrustExternalAdapter({application,repository,transport,
      checkCurrent,serverIdentity,trustScenario,expectedSchemaSha256:schemaSha256}),
    createTools:({checkCurrent})=>createSecureShopMcpTrustTools({repository,transport,serverIdentity,
      resolveTarget:application.target,checkCurrent})});
}
module.exports={createSecureShopMcpTrustComposition};
