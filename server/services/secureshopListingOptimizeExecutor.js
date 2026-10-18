'use strict';
const {normalizeListingRequest}=require('./secureshopListingRequestContract');
const {normalizeDiagnosticWire,validateBoundDiagnosticResult}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const fail=code=>Object.assign(new Error('Listing image optimization unavailable'),{code});
function createListingOptimizeExecutor({client}={}){
 if(typeof client?.execute!=='function')throw TypeError('Private diagnostic client required');
 return Object.freeze({
  async execute({admission,signal,checkCurrent}={}){
   if(typeof checkCurrent!=='function')throw TypeError('Trusted Listings authority check required');
   const request=normalizeListingRequest(admission?.request);
   const binding=admission?.binding||admission;
   if(request.action!=='optimize'||!binding||!['vuln','fixed'].includes(binding.mode))throw fail('INVALID_ARGUMENT');
   await checkCurrent();signal?.throwIfAborted();
   if(binding.mode==='fixed')throw fail('LISTING_OPTIMIZE_DENIED');
   const wire=normalizeDiagnosticWire({targetId:binding.targetId,request:{operationId:request.operationId,
    cmd_template:'convert',args:`${request.imageUrl} -strip -quality 82 ${request.imageUrl}.opt.jpg`}});
   const returned=await client.execute(wire,{signal,assertCurrent:checkCurrent});
   let receipt;try{receipt=validateBoundDiagnosticResult(wire,returned);}
   catch{throw fail('LISTING_OPTIMIZE_EFFECT_MISMATCH');}
   await checkCurrent();signal?.throwIfAborted();
   return Object.freeze({version:1,operationId:request.operationId,productId:request.productId,
    imageUrlSha256:request.imageUrlSha256,command:receipt.result.command,targetId:binding.targetId,
    hostname:receipt.hostname,diagnosticBindingSha256:receipt.bindingSha256,remoteReceipt:receipt});
  },
 });
}
module.exports={createListingOptimizeExecutor};
