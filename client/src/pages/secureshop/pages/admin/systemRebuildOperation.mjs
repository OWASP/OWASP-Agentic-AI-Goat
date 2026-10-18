// Manual rebuild receipt validation. This operation never awards objective credit.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const CORPORA=new Set(['products','reviews','manuals','policies']);
const invalid=()=>{throw new Error('Invalid rebuild receipt');};
export function rebuildRequest(operationId,corpus){
 if(!UUID.test(operationId)||!CORPORA.has(corpus))invalid();
 return Object.freeze({version:1,operationId,corpus});
}
export async function rebuildRequestDigest(operationId,corpus){
 const bytes=new TextEncoder().encode(JSON.stringify(rebuildRequest(operationId,corpus)));
 const digest=await globalThis.crypto.subtle.digest('SHA-256',bytes);
 return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export async function validateCompletedRebuild(value,operationId,expectedCorpus){
 if(!value||value.ok!==true||value.state!=='completed'||value.operationId!==operationId
  ||value.revisionId!==operationId||!UUID.test(value.targetId)||!CORPORA.has(value.corpus)
  ||!['initialize','selective'].includes(value.operationMode)
  ||(expectedCorpus!==undefined&&value.corpus!==expectedCorpus)
  ||!Number.isSafeInteger(value.generation)||value.generation<1
  ||!Number.isSafeInteger(value.documentCount)||value.documentCount<1||value.documentCount>4096
  ||typeof value.replayed!=='boolean'
  ||['requestSha256','bindingSha256','sourceSetDigest','runtimeSha256','vectorDigest'].some(k=>!HASH.test(value[k])))invalid();
 if(value.requestSha256!==await rebuildRequestDigest(operationId,value.corpus))invalid();
 // Render an explicit projection; extra server fields must not become UI content.
 return Object.freeze(Object.fromEntries(['ok','state','operationId','operationMode','corpus','revisionId','targetId','generation','documentCount','replayed',
  'requestSha256','bindingSha256','sourceSetDigest','runtimeSha256','vectorDigest'].map(k=>[k,value[k]])));
}

export async function validateFailedRebuild(value,operationId,expectedCorpus){
 const codes=new Set(['ABORTED','AUTHORITY_REVOKED','RUNTIME_CHANGED','SOURCE_CHANGED','PUBLICATION_REJECTED','EXECUTION_FAILED']);
 if(!value||value.ok!==false||value.state!=='failed'||value.operationId!==operationId
  ||!UUID.test(value.targetId)||!CORPORA.has(value.corpus)
  ||!['initialize','selective'].includes(value.operationMode)
  ||(expectedCorpus!==undefined&&value.corpus!==expectedCorpus)
  ||!Number.isSafeInteger(value.generation)||value.generation<1
  ||typeof value.replayed!=='boolean'||!codes.has(value.failureCode)
  ||!HASH.test(value.requestSha256)||!HASH.test(value.bindingSha256)
  ||value.revisionId!=null)invalid();
 if(value.requestSha256!==await rebuildRequestDigest(operationId,value.corpus))invalid();
 return Object.freeze(Object.fromEntries(['ok','state','operationId','operationMode','corpus','targetId','generation','replayed',
  'requestSha256','bindingSha256','failureCode'].map(k=>[k,value[k]])));
}
