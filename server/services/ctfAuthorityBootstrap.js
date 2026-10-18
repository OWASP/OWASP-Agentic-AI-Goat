'use strict';
// Explicit migration operation only. No startup hook, route or provider call.
const {createHash}=require('node:crypto');
const {TABLES}=require('../database/postgres/ctfAuthorityBootstrapRepository');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const digest=x=>createHash('sha256').update(canonicalCtfJson(x)).digest('hex');
function createCtfAuthorityBootstrap({repository}){
 if(!repository||['fence','begin','sourcePage','stagePage','verifySource','importAndPrepare'].some(k=>typeof repository[k]!=='function'))throw TypeError('Complete bootstrap repository required');
 return Object.freeze({async prepare({operationId,signal}){
  if(typeof operationId!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(operationId))throw TypeError('Bootstrap operation UUID required');
  const options={signal};const revision=await repository.fence(operationId,options);await repository.begin(operationId,revision,options);
  const manifest=[];
  for(const table of TABLES){let after=null,page=0;for(;;){
   if(signal?.aborted)throw new Error('CTF_BOOTSTRAP_CANCELLED');
   const doc=await repository.sourcePage(operationId,revision,table,after,options);
   await repository.stagePage(operationId,revision,table,page,doc,options);
   manifest.push({table,page,hash:doc.hash});
   if(doc.done)break;if(doc.after===after)throw new Error('CTF_BOOTSTRAP_PAGE_STALLED');after=doc.after;page++;
  }}
  await repository.verifySource(operationId,revision,options);
  return repository.importAndPrepare({operationId,revision,manifest,manifestSha256:digest(manifest)},options);
 }});
}
module.exports={createCtfAuthorityBootstrap};
