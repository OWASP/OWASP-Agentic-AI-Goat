'use strict';
// Read-only diagnostic. PREPARED cannot authorize runtime publication or writes.
function createCtfAuthorityBootstrapReadiness({repository}){
 if(typeof repository?.preparationStatus!=='function')throw TypeError('Bootstrap status repository required');
 return Object.freeze({async inspect(operationId,options){
  const state=await repository.preparationStatus(operationId,options);
  return Object.freeze({prepared:state.prepared===true,runtimeReady:false,reason:state.prepared===true?'writer_cutover_required':'bootstrap_checkpoint_unavailable'});
 }});
}
module.exports={createCtfAuthorityBootstrapReadiness};
