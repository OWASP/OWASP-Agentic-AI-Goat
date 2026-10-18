'use strict';
function createSecureShopStandaloneCartImport({bootstrap,launches,personaAuth,commerce}) {
 if(typeof bootstrap!=='function'||typeof launches?.resolveCapability!=='function'
  ||typeof personaAuth?.authenticateBoundToken!=='function'||typeof commerce?.importGuestCart!=='function')
  throw new TypeError('Standalone cart import dependencies required');
 return async function importCart(principal,input){
  if(principal?.role!=='customer')throw Object.assign(new Error('Customer required'),{code:'SHOP_AUTH_INVALID'});
  const prepared=await bootstrap(principal);
  const scope=await launches.resolveCapability(prepared.bearer);
  if(!scope)throw Object.assign(new Error('Shop session unavailable'),{code:'SHOP_AUTH_INVALID'});
  const actor=await personaAuth.authenticateBoundToken({scope,token:prepared.persona.token});
  if(actor?.user?.role!=='customer'||actor.user.id!==(principal.shopUserId??principal.id))
   throw Object.assign(new Error('Shop actor mismatch'),{code:'SHOP_AUTH_INVALID'});
  return commerce.importGuestCart({scope,persona:actor.user,
   personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},
   requestId:input.requestId,items:input.items});
 };
}
module.exports={createSecureShopStandaloneCartImport};
