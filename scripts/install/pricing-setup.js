'use strict';
const {activationPolicy}=require('../../server/services/secureshopPricingActivation');
const fail=()=>Object.assign(Error('Owned Pricing requires persistent bound SecureShop prerequisites'),{code:'PRICING_SETUP_PREREQUISITES_REQUIRED'});
function assertPrerequisites(environment){try{activationPolicy({...environment,SS_BOUND_PRICING_ENABLED:'true'});}catch{throw fail();}}
async function setupOwnedPricing({requested=false,root,homeDirectory,platform,environment={},applicationEnvironment={},provision,maintenanceScope}={}){
 if(!requested)return Object.freeze({requested:false,activationEnabled:false});
 assertPrerequisites(applicationEnvironment);
 const portText=environment.DVAIA_OWNED_PRICING_PORT;let port;if(portText!==undefined){if(!/^[1-9][0-9]{3,4}$/.test(portText)||Number(portText)>65535||Number(portText)<1024)throw Object.assign(Error('Owned Pricing port is invalid'),{code:'PRICING_INSTALL_PORT_INVALID'});port=Number(portText);}
 const result=await(provision||require('./secureshop-owned-pricing-provision').provision)({root,home:homeDirectory,platform,port,maintenanceScope,environment:{...environment,...applicationEnvironment}});
 return Object.freeze({requested:true,activationEnabled:result.enabled===true,workspaceId:result.workspaceId});
}
module.exports={assertPrerequisites,setupOwnedPricing};
