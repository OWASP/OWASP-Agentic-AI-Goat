// Explicit v4 compatibility regression; original v3 remains unchanged.
'use strict';
// Unmounted diagnostic seam. Caller owns admitted real provider/transport and final physical close.
const assert=require('node:assert/strict');
const {createRagWholeEvidenceDefenseContractV4}=require('../../server/agent-runtime/ragWholeEvidenceDefenseContractV4');
const {sha}=require('../../server/agent-runtime/pricingEvidenceCatalogue');
const MODEL='llama3.1:8b';
function createRagWholeEvidenceDefenseDiagnosticV4({provider,transport,record=()=>{}}){
 assert.equal(typeof provider?.chat,'function');for(const k of ['beginCase','endCase','snapshot'])assert.equal(typeof transport?.[k],'function');
 const seen=new Set(),pending=new Set();let busy=false,poisoned=false,expected=null,dispatches=0;
 // Install this at the existing transport's upstream fetch seam, before actual network dispatch.
 function admitWire(body){assert(!poisoned&&expected,'No admitted request');const next=expected;expected=null;assert.deepEqual(JSON.parse(body),next);dispatches++;assert(dispatches<=18);}
 async function run(id,fields,{signal}={}){
  assert(!busy&&!poisoned&&typeof id==='string'&&id.length<=100&&!seen.has(id)&&seen.size<18,'Diagnostic admission');
  const contract=createRagWholeEvidenceDefenseContractV4(fields);signal?.throwIfAborted();busy=true;seen.add(id);
  const controller=new AbortController(),joined=signal?AbortSignal.any([signal,controller.signal]):controller.signal,deadline=performance.now()+60000;
  const timer=setTimeout(()=>controller.abort(Object.assign(Error('Diagnostic deadline'),{code:'DIAGNOSTIC_DEADLINE'})),60000);
  const check=()=>{joined.throwIfAborted();assert(performance.now()<deadline,'Diagnostic deadline');};
  const row={id,contractVersion:contract.version,assessmentRequestSha256:contract.requestSha256,request:contract.request,response:null,result:null,creditAuthorized:false,genuineActor:false,status:'pending'};
  try{transport.beginCase(id);record(structuredClone(row));check();assert.equal(expected,null);
   expected={model:MODEL,messages:contract.request.messages,stream:true,format:contract.request.schema,options:{temperature:0,num_predict:4096,num_ctx:32768}};
   const options={temperature:0,max_tokens:4096,num_predict:4096,num_ctx:32768,format:contract.request.schema,timeout:Math.max(1,Math.floor(deadline-performance.now())),signal:joined,ownerId:'rag-whole-evidence-defense-diagnostic'};
   const operation=Promise.resolve().then(()=>provider.chat(contract.request.messages,[],options));pending.add(operation);operation.then(()=>pending.delete(operation),()=>pending.delete(operation));
   let onAbort;const aborted=new Promise((_,reject)=>{onAbort=()=>{expected=null;poisoned=true;reject(joined.reason);};joined.addEventListener('abort',onAbort,{once:true});if(joined.aborted)onAbort();});
   let value;try{value=await Promise.race([operation,aborted]);}finally{joined.removeEventListener('abort',onAbort);}check();assert.equal(expected,null,'Request was not admitted at wire seam');
   assert.equal(value.provider,'ollama');assert.equal(value.model,MODEL);assert(!value.mocked&&!value.fallback&&!value._error);assert.equal(typeof value.response,'string');assert(Buffer.byteLength(value.response)<=262144);
   row.response=value.response;row.responseSha256=sha(value.response);record(structuredClone(row));
   const wire=transport.snapshot().calls.filter(x=>x.caseId===id&&x.kind==='external/api/chat');assert.equal(wire.length,1);const w=wire[0];assert.equal(w.status,'returned');assert.equal(w.httpStatus,200);assert.equal(w.requestSha256,sha(w.request));assert.equal(w.responseSha256,sha(w.response));
   assert.deepEqual(JSON.parse(w.request),{model:MODEL,messages:contract.request.messages,stream:true,format:contract.request.schema,options:{temperature:0,num_predict:4096,num_ctx:32768}});
   let text='';const frames=w.response.trim().split('\n').map(JSON.parse);assert(frames.length);frames.forEach((f,i)=>{assert.equal(f.model,MODEL);assert(!f.error&&!f.message?.tool_calls);assert.equal(f.message?.role,'assistant');assert.equal(typeof f.message.content,'string');assert.equal(f.done,i===frames.length-1);text+=f.message.content;});const termination=frames.at(-1).done_reason;assert(['stop','length'].includes(termination),'Unknown model termination');assert.equal(text,value.response);row.terminationReason=termination;
   row.wireRequestSha256=w.requestSha256;row.wireResponseSha256=w.responseSha256;
   if(termination==='length'){row.result=null;row.modelOutputStatus='invalid';row.modelOutputError='MODEL_OUTPUT_LIMIT';}else{try{row.result=contract.validate(JSON.parse(value.response));row.modelOutputStatus='valid';}catch{row.result=null;row.modelOutputStatus='invalid';row.modelOutputError='INVALID_MODEL_CONTRACT';}}check();transport.endCase();row.status='complete';record(structuredClone(row));return row;
  }catch(error){poisoned=true;expected=null;row.status='incomplete';row.errorCode='DIAGNOSTIC_MECHANICAL_FAILURE';record(structuredClone(row));throw error;}
  finally{clearTimeout(timer);controller.abort();busy=false;}
 }
 return{run,admitWire,state:()=>({busy,poisoned,dispatches,cases:seen.size,providerPending:pending.size,physicalCloseRequired:true})};
}
module.exports={createRagWholeEvidenceDefenseDiagnosticV4};
