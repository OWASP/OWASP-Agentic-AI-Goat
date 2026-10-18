'use strict';
// Private backend adapter. Never expose controlToken or returned target configs
// to browser code; canonical products/launches own admission and cleanup.
const {createLaunchScope}=require('./secureshopConversationBinding');
const {createOwnedListingsClient}=require('./secureshopOwnedListingsClient');
const {executionScope,withSceneLease,isSceneMerchant}=require('./secureshopSceneBinding');
const fail=code=>Object.assign(new Error('Listings target unavailable'),{code});
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,SHA=/^[a-f0-9]{64}$/;
function createListingsTargetManager({origin,controlToken,runtimeDigest,launches,products,resolveMode,fetchImpl=fetch,timeoutMs=15000}={}){
 if(new URL(origin).origin!==origin||!/^[A-Za-z0-9_-]{43,128}$/.test(controlToken||'')||!SHA.test(runtimeDigest||'')||typeof launches?.assertCurrent!=='function'||typeof launches?.readExistingProductsTarget!=='function'||typeof products?.open!=='function'||typeof products?.readCleanupReceipt!=='function'||typeof resolveMode!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<10||timeoutMs>30000)throw TypeError('Managed Listings dependencies required');
 async function call(path,body){const c=new AbortController();let timer;
  const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{c.abort();reject(fail('LISTINGS_MANAGER_TIMEOUT'));},timeoutMs);});
  try{return await Promise.race([deadline,(async()=>{const response=await fetchImpl(origin+path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+controlToken,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),redirect:'error',credentials:'omit',signal:c.signal});if(!response.ok){try{Promise.resolve(response.body?.cancel?.()).catch(()=>{});}catch{}throw fail('LISTINGS_MANAGER_UNAVAILABLE');}if(!response.body?.getReader)throw fail('LISTINGS_MANAGER_PROTOCOL');const reader=response.body.getReader();const cancel=()=>{try{Promise.resolve(reader.cancel()).catch(()=>{});}catch{}};c.signal.addEventListener('abort',cancel,{once:true});let size=0;const chunks=[];
   try{if(c.signal.aborted)cancel();while(true){c.signal.throwIfAborted();const v=await reader.read();if(v.done)break;size+=v.value.byteLength;if(size>65536){cancel();throw fail('LISTINGS_MANAGER_LIMIT');}chunks.push(v.value);}c.signal.throwIfAborted();return JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks,size)));}finally{c.signal.removeEventListener('abort',cancel);try{reader.releaseLock();}catch{}}})()]);}finally{clearTimeout(timer);}
 }
 function capture(raw){if(!raw||Object.keys(raw).sort().join(',')!=='mode,scope,targetId'||!UUID.test(raw.targetId||'')||!['vuln','fixed'].includes(raw.mode))throw fail('LISTINGS_TARGET_INVALID');return{scope:createLaunchScope(raw.scope),targetId:raw.targetId,mode:raw.mode};}
 async function current(b,target){
  const scope=createLaunchScope(target?executionScope(target):b.scope);await launches.assertCurrent(scope);
  if(target){if(target.targetId!==b.targetId||JSON.stringify(createLaunchScope(target))!==JSON.stringify(b.scope)||!await products.open(target))throw fail('LISTINGS_TARGET_MISMATCH');}
  else {const reserved=await launches.readExistingProductsTarget(scope);if(reserved?.targetId!==b.targetId||!await products.open({...b.scope,targetId:b.targetId}))throw fail('LISTINGS_TARGET_MISMATCH');}
  if(await resolveMode(scope)!==b.mode)throw fail('LISTINGS_TARGET_MISMATCH');await launches.assertCurrent(scope);
 }
 async function health(){const result=await call('/manager/health');if(!result||Object.keys(result).sort().join(',')!=='capability,limits,ready,runtimeDigest,version'||result.version!==1||result.ready!==true||result.capability!=='owned-listings-manager.v1'||result.runtimeDigest!==runtimeDigest||!result.limits||Object.keys(result.limits).sort().join(',')!=='maxConcurrentExecutions,maxPersistedTargets,maxQueuedExecutions,maxResidentTargets'||Object.entries({maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16}).some(([key,value])=>result.limits[key]!==value))throw fail('LISTINGS_MANAGER_IDENTITY');return result;}
 return Object.freeze({health,
  async resolveConfiguration(raw,options){const b=capture(raw),target=options?.targetBinding;
   if(options!==undefined&&(!target?.scene||!isSceneMerchant(target,options.merchantId)))throw fail('LISTINGS_TARGET_MISMATCH');
   const work=async()=>{await current(b,target);await health();const value=await call('/targets',b);
   if(!value||Object.keys(value).sort().join(',')!=='executorId,mode,origin,runtimeDigest,runtimeIdentity,scope,targetId,token'||JSON.stringify(createLaunchScope(value.scope))!==JSON.stringify(b.scope)||value.targetId!==b.targetId||value.mode!==b.mode||value.origin!==origin||value.runtimeDigest!==runtimeDigest)throw fail('LISTINGS_MANAGER_BINDING');
   const {scope,targetId,...config}=value;await createOwnedListingsClient({...config,fetchImpl,timeoutMs}).health();await current(b,target);return Object.freeze({...value,scope:b.scope});};
   return target?withSceneLease(target,work):work();
  },
  async acknowledgeRetirement(raw,{operationId}={}){const b=capture(raw);if(!UUID.test(operationId||''))throw fail('LISTINGS_RETIRE_INVALID');
   const proof=await products.readCleanupReceipt({...b.scope,targetId:b.targetId},{operationId});if(!proof||proof.operationId!==operationId||proof.targetId!==b.targetId||Object.keys(b.scope).some(k=>proof[k]!==b.scope[k])||!SHA.test(proof.receiptSha256||''))throw fail('LISTINGS_CLEANUP_PROOF');
   await health();const receipt=await call('/targets/forget',{...b,operationId,canonicalReceiptSha256:proof.receiptSha256});
   if(!receipt||Object.keys(receipt).sort().join(',')!=='canonicalReceiptSha256,forgotten,operationId,replayed,targetId,version'||receipt.version!==1||receipt.forgotten!==true||typeof receipt.replayed!=='boolean'||receipt.targetId!==b.targetId||receipt.operationId!==operationId||receipt.canonicalReceiptSha256!==proof.receiptSha256)throw fail('LISTINGS_CLEANUP_RECEIPT');return Object.freeze(receipt);
  },
  async retire(raw,{operationId}={}){const b=capture(raw);if(!UUID.test(operationId||''))throw fail('LISTINGS_RETIRE_INVALID');
   // This repository verifies canonical cleanup authority, retired target scope,
   // zero remaining mutable state and its immutable cleanup receipt digest.
   const proof=await products.readCleanupReceipt({...b.scope,targetId:b.targetId},{operationId});
   if(!proof||proof.operationId!==operationId||proof.targetId!==b.targetId||Object.keys(b.scope).some(k=>proof[k]!==b.scope[k])||!SHA.test(proof.receiptSha256||''))throw fail('LISTINGS_CLEANUP_PROOF');
   await health();const result=await call('/targets/retire',{...b,operationId,canonicalReceiptSha256:proof.receiptSha256});
   if(!result||Object.keys(result).sort().join(',')!=='bindingSha256,canonicalReceiptSha256,operationCount,operationId,retired,targetId,tombstonesSha256,version'||result.version!==1||result.retired!==true||result.operationId!==operationId||result.targetId!==b.targetId||result.canonicalReceiptSha256!==proof.receiptSha256||!Number.isInteger(result.operationCount)||result.operationCount<0||!SHA.test(result.tombstonesSha256||''))throw fail('LISTINGS_CLEANUP_RECEIPT');
   const expected=require('node:crypto').createHash('sha256').update(JSON.stringify(b)).digest('hex');if(result.bindingSha256!==expected)throw fail('LISTINGS_CLEANUP_RECEIPT');return Object.freeze(result);
  }
 });
}
module.exports={createListingsTargetManager};
