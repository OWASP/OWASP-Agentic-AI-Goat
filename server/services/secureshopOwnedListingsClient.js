'use strict';
const crypto = require('node:crypto');
const { prepareListingAdmission } = require('./secureshopListingJournalContract');
const HEX=/^[a-f0-9]{64}$/, UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=code=>Object.assign(new Error('Owned Listings executor unavailable'),{code});
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function exact(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))throw fail('LISTINGS_PROTOCOL');}
function createOwnedListingsClient({origin,token,runtimeIdentity,runtimeDigest,mode,executorId,timeoutMs=15000,fetchImpl=fetch,maxAdmissions=1024}={}){
 const url=new URL(origin);
 if(url.origin!==origin||url.username||url.password||!['http:','https:'].includes(url.protocol)||!/^[A-Za-z0-9_-]{43,128}$/.test(token||'')||!HEX.test(runtimeIdentity||'')||!HEX.test(runtimeDigest||'')||!UUID.test(executorId||'')||!['fixed','vuln'].includes(mode)||!Number.isInteger(timeoutMs)||timeoutMs<10||timeoutMs>30000||typeof fetchImpl!=='function')throw TypeError('Trusted Listings registration required');
 if(!Number.isSafeInteger(maxAdmissions)||maxAdmissions<1||maxAdmissions>4096)throw TypeError('Bounded Listings admission capacity required');
 const admissions=new Map(),admissionUsers=new Map();
 function registerAdmission(prepared){
  // Only application composition may call this function with its persisted
  // admission. HTTP request bodies must never be passed as registration data.
  const admission=prepareListingAdmission({...prepared?.binding,request:prepared?.request});
  if(admission.binding.mode!==mode||admission.request.action!=='import')throw fail('LISTINGS_ADMISSION');
  const record=JSON.parse(JSON.stringify({request:admission.request,operationId:admission.request.operationId,requestSha256:admission.requestSha256,bindingSha256:admission.bindingSha256,targetId:admission.binding.targetId,mode}));
  const old=admissions.get(record.operationId);if(old&&JSON.stringify(old)!==JSON.stringify(record))throw fail('LISTINGS_ADMISSION_CONFLICT');
  if(!old&&admissions.size>=maxAdmissions)throw fail('LISTINGS_ADMISSION_CAPACITY');
  admissions.set(record.operationId,Object.freeze(record));return record.operationId;
 }
 function registered(id){if(!UUID.test(id||'')||!admissions.has(id))throw fail('LISTINGS_UNREGISTERED');return admissions.get(id);}
 async function bounded(work,signal){
  if(signal?.aborted)throw fail('LISTINGS_ABORTED');
  const controller=new AbortController();let timer,abort;
  const cancelled=new Promise((_,reject)=>{
   abort=()=>{controller.abort();reject(fail('LISTINGS_ABORTED'));};
   timer=setTimeout(()=>{controller.abort();reject(fail('LISTINGS_TIMEOUT'));},timeoutMs);
   signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  });
  try{return await Promise.race([work(controller.signal),cancelled]);}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
 }
 async function request(path,method,body,signal){
  signal.throwIfAborted();
  const response=await fetchImpl(origin+path,{method,redirect:'error',credentials:'omit',headers:{authorization:'Bearer '+token,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)}),signal});
  if(!response.ok){
   // Release failed HTTP bodies without allowing a non-cooperative stream to
   // extend the deadline or mask the original status failure.
   try{Promise.resolve(response.body?.cancel?.()).catch(()=>{});}catch{}
   throw fail('LISTINGS_HTTP');
  }
  if(!response.body?.getReader)throw fail('LISTINGS_PROTOCOL');
  if(signal.aborted){try{Promise.resolve(response.body.cancel?.()).catch(()=>{});}catch{}signal.throwIfAborted();}
  const reader=response.body.getReader();const cancel=()=>{try{Promise.resolve(reader.cancel()).catch(()=>{});}catch{}};signal.addEventListener('abort',cancel,{once:true});if(signal.aborted)cancel();let size=0;const chunks=[];
  try{while(true){signal.throwIfAborted();const next=await reader.read();if(next.done)break;size+=next.value.byteLength;if(size>2097152){void reader.cancel().catch(()=>{});throw fail('LISTINGS_LIMIT');}chunks.push(next.value);}signal.throwIfAborted();return JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks,size)));}
  finally{signal.removeEventListener('abort',cancel);try{reader.releaseLock();}catch{}}
 }
 async function health(signal){const value=await request('/health','GET',undefined,signal);exact(value,['version','ready','identity','runtimeDigest','mode','isolation']);if(value.version!==1||value.ready!==true||value.identity!==runtimeIdentity||value.runtimeDigest!==runtimeDigest||value.mode!==mode||value.isolation!=='owned-listings.v1')throw fail('LISTINGS_IDENTITY');return value;}
 function verify(value,admission){
  if(value?.operationId!==admission.operationId||value.requestSha256!==admission.requestSha256||value.identity!==runtimeIdentity||value.version!==1)throw fail('LISTINGS_RECEIPT');
  if(value.status==='retired'){
   exact(value,['version','status','operationId','identity','requestSha256','receiptSha256','tombstoneSha256']);
   const {tombstoneSha256,...body}=value;if((body.receiptSha256!==null&&!HEX.test(body.receiptSha256))||digest(body)!==tombstoneSha256)throw fail('LISTINGS_RECEIPT');
  }else if(value.status==='unknown')exact(value,['version','operationId','status','requestSha256','identity']);
  else{
   exact(value,['version','identity','mode','operationId','requestSha256','status',value.status==='completed'?'result':'error','receiptSha256']);
   if(!['completed','failed'].includes(value.status)||value.mode!==mode)throw fail('LISTINGS_RECEIPT');
   const {receiptSha256,...body}=value;if(digest(body)!==receiptSha256)throw fail('LISTINGS_RECEIPT');
   if(value.status==='completed'){
    exact(value.result,['version','operationId','requestSha256','mode','products','sources']);
    if(value.result.version!==1||value.result.operationId!==admission.operationId||value.result.requestSha256!==admission.requestSha256||value.result.mode!==mode||!Array.isArray(value.result.products)||!Array.isArray(value.result.sources))throw fail('LISTINGS_RECEIPT');
   }else if(typeof value.error!=='string'||!/^LISTING_[A-Z_]+$/.test(value.error))throw fail('LISTINGS_RECEIPT');
  }return value;
 }
 function operation(id,method,suffix,body,signal){const admission=registered(id);return bounded(async combined=>{await health(combined);return verify(await request('/operations'+suffix,method,body,combined),admission);},signal);}
 return Object.freeze({registerAdmission,
  async withAdmission(prepared,work){
   if(typeof work!=='function')throw TypeError('Scoped Listings admission work required');
   const handle=registerAdmission(prepared);admissionUsers.set(handle,(admissionUsers.get(handle)||0)+1);
   try{return await work(handle);}finally{const users=admissionUsers.get(handle)-1;if(users)admissionUsers.set(handle,users);else{admissionUsers.delete(handle);admissions.delete(handle);}}
  },
  // Internal lifecycle hook. The canonical journal remains authoritative and
  // can restore registration for later authorized readback after eviction.
  releaseAdmission(id){if(!UUID.test(id||''))throw fail('LISTINGS_UNREGISTERED');if(admissionUsers.has(id))return false;return admissions.delete(id);},
  health:({signal}={})=>bounded(health,signal),
  execute(id,{signal}={}){return operation(id,'POST','',registered(id).request,signal);},
  get(id,{signal}={}){return operation(id,'GET','/'+id,undefined,signal);},
  retire(id,{signal}={}){return operation(id,'POST','/'+id+'/retire',{},signal);},
  async readVerifiedResult(handle,expected){
   const admission=registered(handle);
   exact(expected,['operationId','requestSha256','bindingSha256','targetId','mode']);
   for(const key of Object.keys(expected))if(expected[key]!==admission[key])throw fail('LISTINGS_ATTESTATION_MISMATCH');
   const receipt=await operation(handle,'GET','/'+handle,undefined);
   if(receipt.status!=='completed')throw fail('LISTINGS_RESULT_UNAVAILABLE');
   return {bytes:Buffer.from(JSON.stringify(receipt.result)),context:{operationId:admission.operationId,requestSha256:admission.requestSha256,bindingSha256:admission.bindingSha256,targetId:admission.targetId,mode:admission.mode,receiptHandle:handle,executorId,packageSha256:runtimeDigest,isolation:'owned-listings.v1'}};
  }
 });
}
module.exports={createOwnedListingsClient};
