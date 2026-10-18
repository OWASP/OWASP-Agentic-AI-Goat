'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { unavailable } = require('./csrfRagResources');
function operation(runId, name) {
  const value=createHash('sha256').update(`${runId}:${name}`).digest('hex').slice(0,32).split('');value[12]='5';value[16]='8';const id=value.join('');
  return `${id.slice(0,8)}-${id.slice(8,12)}-${id.slice(12,16)}-${id.slice(16,20)}-${id.slice(20)}`;
}
// Saved legacy text is never reconstructed/imported here. An explicit upload or
// reset is the only route out of a missing durable poison selection.
async function createCsrfDurableRagResources({ composition, request, execution, tab, cleanText, noteReceipt=()=>{}, mutateTab }) {
  if((mutateTab!==undefined||execution?.withTeachingEffect!==undefined)&&typeof mutateTab!=='function')throw new TypeError('Trusted tab mutation callback required');
  const mutate=mutateTab|| (async work=>work());
  const authority=await composition.resolveRequest(request),bindings=new Map();
  const bind=async slot=>{if(!bindings.has(slot))bindings.set(slot,await authority.bind(execution,{family:'CSRF',slot}));return bindings.get(slot);};
  const read=slot=>authority.read({family:'CSRF',slot});
  async function ensureClean(){
    const current=await read('clean');
    if(current.document){await mutate(()=>{tab.ragCleanSessionId=current.documentId;tab.ragCleanSeeded=true;});return current.documentId;}
    const bound=await bind('clean'),documentId=randomUUID();
    const result=await bound.ingestAndSelect({documentId,operationId:operation(execution.runId,'canonical-clean'),sourceBuffer:Buffer.from(cleanText,'utf8'),filename:'vaultlink-kb.txt',ingestionKind:'canonical_clean'});
    await mutate(()=>{tab.ragCleanSessionId=result.documentId;tab.ragCleanSeeded=true;});return result.documentId;
  }
  async function state(){
    const clean=await read('clean'),poison=await read('poison');
    const poisonRecorded=Boolean(poison.document||tab.ragPoisoned||tab.ragDocText);
    return {cleanReady:Boolean(clean.document),poisonRecorded,poisonReady:Boolean(poison.document),available:Boolean(clean.document)&&(!poisonRecorded||Boolean(poison.document))};
  }
  async function assertPoisonAvailable(){
    const poison=await read('poison');
    if(!poison.document&&(tab.ragPoisoned||tab.ragDocText))throw unavailable('Retained legacy poison has no durable source; explicitly re-upload or reset it');
    if(poison.document){await mutate(()=>{tab.ragSessionId=poison.documentId;tab.ragPoisoned=true;});}
  }
  const receipts=[];
  return Object.freeze({authority,ensureClean,state,assertPoisonAvailable,
    async uploadPoison(text){
      const bound=await bind('poison');
      return bound.ingestAndSelect({documentId:randomUUID(),operationId:operation(execution.runId,'poison-upload'),sourceBuffer:Buffer.from(text,'utf8'),filename:'poisoned-kb.txt',ingestionKind:'poison_upload'});
    },
    store:Object.freeze({async similaritySearch(owner,documentId,question,limit){
      if(String(owner)!==String(authority.ownerId))throw unavailable();
      let slot;if(documentId===tab.ragCleanSessionId)slot='clean';else if(documentId===tab.ragSessionId)slot='poison';else throw unavailable();
      const bound=await bind(slot),current=await read(slot);if(current.documentId!==documentId)throw unavailable();
      const result=await bound.search({documentId,question,limit,operationId:operation(execution.runId,JSON.stringify(['retrieve',slot,documentId,question,limit]))});
      receipts.push(result.receipt);noteReceipt({type:'rag_retrieval',receipts:[...receipts]});return result.chunks;
    }}),
  });
}
module.exports={createCsrfDurableRagResources};
