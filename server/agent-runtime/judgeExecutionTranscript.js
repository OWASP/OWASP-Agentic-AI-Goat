'use strict';
// Private adapter-level diagnostics only: not wire bytes, model identity or credit authority.
const {createHash,randomUUID}=require('node:crypto');
const LIMITS=Object.freeze({calls:64,requestBytes:524288,responseBytes:262144,totalBytes:16777216,metadataBytes:8192});
const hash=text=>createHash('sha256').update(text,'utf8').digest('hex');
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
function createJudgeExecutionTranscript(observer,header){
 if(!observer)return null;
 let failure=null,bytes=0,closed=false;const calls=[],keys=new Map();let retainedHeader;
 const fail=code=>{failure ||= code;};
 const snapshot=(value,limit)=>{const text=JSON.stringify(value);if(typeof text!=='string'||Buffer.byteLength(text)>limit)throw Error('TRANSCRIPT_LIMIT');bytes+=Buffer.byteLength(text);if(bytes>LIMITS.totalBytes)throw Error('TRANSCRIPT_LIMIT');return{value:JSON.parse(text),text,sha256:hash(text)};};
 try{retainedHeader=snapshot(header,LIMITS.requestBytes).value;}catch{fail('HEADER_UNAVAILABLE');}
 const safe=fn=>{try{if(!closed&&!failure)return fn();}catch{fail('TRANSCRIPT_LIMIT_OR_INVALID');}};
 return Object.freeze({
  protocolBudget(maximumCalls){safe(()=>{if(!Number.isSafeInteger(maximumCalls)||maximumCalls<0||calls.length){fail('PROTOCOL_BUDGET_INVALID');return;}retainedHeader.maximumCalls=maximumCalls;});},
  parsed(stage,attempt,text){safe(()=>{const entry=keys.get(JSON.stringify([stage,attempt]));if(!entry||entry.index!==calls.length||entry.transport!=='returned'||text!==entry.response){fail('VALIDATED_TEXT_MISMATCH');return;}entry.validatedTextSha256=hash(text);});},
  begin(stage,attempt,request){return safe(()=>{
   if(Number.isSafeInteger(retainedHeader?.maximumCalls)&&calls.length>=retainedHeader.maximumCalls){fail('PROTOCOL_CALL_BUDGET_EXCEEDED');return;}
   if(calls.length>=LIMITS.calls)throw Error('TRANSCRIPT_LIMIT');
   const key=JSON.stringify([stage,attempt]);if(keys.has(key)){fail('DUPLICATE_CALL');return;}
   const saved=snapshot(request,LIMITS.requestBytes),entry={index:calls.length+1,stage,attempt,request:saved.value,requestSha256:saved.sha256,transport:'pending',disposition:'pending'};
   calls.push(entry);keys.set(key,entry);return entry.index;
  });},
  returned(index,response){safe(()=>{const entry=calls[index-1];if(!entry||entry.transport!=='pending'){fail('CALL_ORDER_INVALID');return;}
   const raw=typeof response?.response==='string'?response.response:null;
   if(raw===null){fail('RESPONSE_TEXT_UNAVAILABLE');return;}if(Buffer.byteLength(raw)>LIMITS.responseBytes)throw Error('TRANSCRIPT_LIMIT');
   bytes+=Buffer.byteLength(raw);if(bytes>LIMITS.totalBytes)throw Error('TRANSCRIPT_LIMIT');
   entry.response=raw;entry.responseBytes=Buffer.byteLength(raw);entry.responseSha256=hash(raw);
   entry.metadata=snapshot({provider:response.provider??null,model:response.model??null,mocked:response.mocked??null,fallback:response.fallback??null,tokens:response.tokens??null,evalCount:response.metadata?.eval_count??null},LIMITS.metadataBytes).value;entry.transport='returned';
  });},
  transportError(index,error){safe(()=>{const entry=calls[index-1];if(entry){entry.transport='error';entry.errorCode=typeof error?.code==='string'?error.code.slice(0,100):'TRANSPORT_ERROR';entry.disposition='unvalidated';}});},
  disposition(stage,attempt,status){safe(()=>{const entry=keys.get(JSON.stringify([stage,attempt]));if(!entry||entry.index!==calls.length||entry.transport!=='returned'||entry.disposition!=='pending'||!['accepted','rejected'].includes(status)){fail('DISPOSITION_ORDER_INVALID');return;}if(entry.validatedTextSha256!==entry.responseSha256){fail('VALIDATED_TEXT_MISSING');return;}entry.disposition=status;});},
  async finish(result,error){if(closed)return;let outcome=null;try{if(result!==undefined&&!failure)outcome=snapshot(result,LIMITS.requestBytes);}catch{fail('OUTCOME_UNAVAILABLE');}
   closed=true;if(error)fail('EVALUATION_INTERRUPTED');if(calls.some(c=>c.transport!=='returned'||c.disposition==='pending'))fail('INCOMPLETE_EXECUTION');
   const document={version:1,kind:'adapter-level-diagnostic',qualification:false,evaluationId:randomUUID(),complete:!failure,failure,header:retainedHeader??null,limits:LIMITS,calls,outcome:outcome?{value:outcome.value,bytes:outcome.text,sha256:outcome.sha256}:null};
   if(Buffer.byteLength(JSON.stringify(document))>LIMITS.totalBytes){document.complete=false;document.failure='TRANSCRIPT_LIMIT';document.calls=[];document.outcome=null;}
   const transcript=freeze({...document,transcriptSha256:hash(JSON.stringify(document))});
   let timer;try{const delivered=Promise.resolve().then(()=>observer(transcript));delivered.catch(()=>{});await Promise.race([delivered,new Promise(resolve=>{timer=setTimeout(resolve,100);})]);}catch{/* Diagnostic observer cannot alter grading or cause inference. */}finally{clearTimeout(timer);}
  },
 });
}
module.exports={createJudgeExecutionTranscript,LIMITS};
