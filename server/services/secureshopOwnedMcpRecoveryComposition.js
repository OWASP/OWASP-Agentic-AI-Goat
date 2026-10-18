'use strict';
// Private status-only composition. No route, claim client or invocation signer.
const {createSecureShopLaunchRepository}=require('../database/postgres/secureshopLaunchRepository');
const {createSecureShopBoundPersonaAuthority}=require('../database/postgres/secureshopBoundPersonaAuthority');
const {createInvocationRecoveryRepository}=require('../database/postgres/secureshopOwnedMcpInvocationRecovery');
const {createInvocationRecovery}=require('./secureshopOwnedMcpInvocationRecovery');
function createOwnedMcpRecoveryComposition({identityPool,agentsPool,manager}={}){
 let repository;
 const launches=createSecureShopLaunchRepository(identityPool,{get ownedMcpInvocationRecovery(){return repository;}});
 const personaAuthority=createSecureShopBoundPersonaAuthority({pool:agentsPool,checkCurrent:scope=>launches.assertCurrent(scope)});
 repository=createInvocationRecoveryRepository({pool:agentsPool,personaAuthority,launches,recoveryAuthority:{assertCurrent:query=>launches.assertCurrent(query.scope)}});
 return createInvocationRecovery({repository,manager});
}
module.exports={createOwnedMcpRecoveryComposition};
