'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
function createOwnedAuditLifecycle({cleanupAuthority,client}){
 if(typeof cleanupAuthority?.getOperation!=='function'||typeof client?.retire!=='function'||typeof client?.destroy!=='function')throw TypeError('Canonical cleanup authority and retained audit client required');
 async function authority(resetId){const value=await cleanupAuthority.getOperation(resetId);if(value?.resetId!==resetId||!['fenced','committed','aborted'].includes(value.status))throw Error('Audit cleanup authority unavailable');return createLaunchScope(value.binding);}
 return Object.freeze({
  async retireGeneration(resetId,{signal}={}){signal?.throwIfAborted();const binding=await authority(resetId);await client.retire({binding});signal?.throwIfAborted();if(JSON.stringify(await authority(resetId))!==JSON.stringify(binding))throw Error('Audit cleanup authority changed');return{resetId,retired:true};},
  async destroyForDeletion({resetIds,subjectId,check,signal}){
   if(!Array.isArray(resetIds)||typeof check!=='function')throw TypeError('Deletion mapping required');
   for(const resetId of resetIds){signal?.throwIfAborted();await check();const binding=await authority(resetId);if(binding.platformOwnerId!==subjectId)throw Error('Audit deletion owner mismatch');const receipt=await client.destroy({binding});if(receipt?.destroyed!==true)throw Error('Audit destruction incomplete');await check();}
   return{completed:true};
  }
 });
}
module.exports={createOwnedAuditLifecycle};
