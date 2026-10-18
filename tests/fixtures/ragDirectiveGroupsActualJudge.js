'use strict';
// Actual Judge transport on declared controlled inputs. No actor, database or credit.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const DECLARATIONS=[['tests/release-inputs/rag-directive-groups-canonical-task-24-declaration-2026-09-27.json','56c23dd1789a28d02245f40e691a6cd92bd0f62f61b7b04fb6a0c4070b4c11ae']];
const sha=value=>createHash('sha256').update(value).digest('hex');
function cases(root){const docs=DECLARATIONS.map(([name,digest])=>{const bytes=fs.readFileSync(path.join(root,name));assert.equal(sha(bytes),digest);return JSON.parse(bytes);});const result=docs.flatMap(doc=>doc.cases);assert.equal(result.length,24);assert.equal(new Set(result.map(c=>c.id)).size,24);result.forEach((c,i)=>{assert.equal(c.id,`rag-prospective-${String(i+1).padStart(2,'0')}`);assert(['attack','defense'].includes(c.mode));for(const key of ['task','source','question','response'])assert.equal(sha(c[key]),c.sha256[key]);});return {cases:result};}
function reconstruct(raw){
 let frames;try{frames=[JSON.parse(raw)];}catch{frames=raw.trim().split('\n').map(line=>JSON.parse(line));}
 assert(frames.length>0);let text='';frames.forEach((f,i)=>{assert.equal(f.model,MODEL);assert.equal(f.done,i===frames.length-1);assert(!f.error);assert.equal(f.message?.role,'assistant');assert.equal(typeof f.message.content,'string');text+=f.message.content;});return text;
}
function transport({fetch:upstream,signal,record=()=>{}}){
 const calls=[],controllers=new Set();let active=null,totalBytes=0,closed=false;const counts=new Map();
 return {calls,beginCase(id){assert(!closed);assert.equal(active,null);assert(!counts.has(id));active=id;counts.set(id,0);},endCase(){active=null;},close(){closed=true;for(const c of controllers)c.abort();},
  async fetch(url,options={}){
   assert(!closed);const target=new URL(typeof url==='string'?url:url.url||String(url));assert.equal(target.origin,'http://127.0.0.1:11434');assert(!target.search&&!target.hash);assert(calls.length<144,'Global HTTP budget exhausted');
   const chat=target.pathname==='/api/chat';assert(chat||target.pathname==='/api/tags');assert.equal(options.method||'GET',chat?'POST':'GET');
   let request=null;if(chat){assert(active,'No active declared case');assert(counts.get(active)<6,'Case HTTP budget exhausted');assert.equal(typeof options.body,'string');assert(Buffer.byteLength(options.body)<=262144);request=JSON.parse(options.body);assert.equal(request.model,MODEL);counts.set(active,counts.get(active)+1);}else{assert.equal(active,null);assert.equal(calls.length,0,'Only one model admission read');}
   const call={index:calls.length+1,caseId:active,kind:chat?'inference':'metadata',request:options.body||null,requestSha256:sha(options.body||''),status:'pending'};calls.push(call);record();
   const controller=new AbortController();controllers.add(controller);const combined=AbortSignal.any([controller.signal,signal,AbortSignal.timeout(60000),...(options.signal?[options.signal]:[])]);const chunks=[];let size=0,finished=false;
   function finish(error){if(finished)return;finished=true;call.response=Buffer.concat(chunks).toString('utf8');call.responseSha256=sha(Buffer.concat(chunks));call.responseBytes=chunks.reduce((n,c)=>n+c.length,0);call.observedBytes=size;call.status=error?'incomplete':'returned';if(error)call.errorCode='TRANSPORT_INCOMPLETE';controllers.delete(controller);record();}
   try{
    const response=await upstream(url,{...options,redirect:'error',signal:combined});call.httpStatus=response.status;const reader=response.body.getReader();
    return new Response(new ReadableStream({async pull(out){try{const item=await reader.read();if(item.done){finish();out.close();return;}size+=item.value.byteLength;totalBytes+=item.value.byteLength;if(size>4194304||totalBytes>576*1024*1024){controller.abort();throw Error('Wire byte bound');}chunks.push(Buffer.from(item.value));out.enqueue(item.value);}catch(error){controller.abort();finish(error);out.error(error);}},async cancel(reason){controller.abort();finish(Error('Cancelled'));await reader.cancel(reason);}}),{status:response.status,headers:response.headers});
   }catch(error){controller.abort();finish(error);throw error;}
  }
 };
}
function packet(rubric,item){assert.equal(rubric.sourceComparison.task,item.task);return {rubric,facts:Object.fromEntries(rubric.requiredFacts.map(k=>[k,true])),evidence:[{id:'context',source:'tool_result',content:item.source},{id:'raw_response',source:'assistant_response',content:item.response},{id:'question',source:'student_input',content:item.question}]};}
function acceptedStages(transcript,result){
 if(transcript?.complete!==true||!Array.isArray(transcript.calls))return false;
 const accepted=new Set(transcript.calls.filter(c=>c.disposition==='accepted').map(c=>c.stage));
 if(!accepted.has('compare:source')||!accepted.has('compare:effect'))return false;
 if(result.verdict==='unavailable')return result.semanticObservation?.coverageComplete===true&&result.semanticObservation.directiveGroups?.some(g=>g.eligible===true)===true;
 if(result.semanticObservation?.directiveGroups?.some(g=>g.eligible===true)&&!accepted.has('compare:support'))return false;
 return true;
}
function compare(result,item){
 const expected=item.mode==='attack'?item.expected.attackCriterion:item.expected.defenseCriterion;
 const ids=item.mode==='attack'?['redirected_output']:['poisoning_recognized','injection_refused'];
 const criteria=Array.isArray(result.criteria)?result.criteria:[];
 const criterionShape=criteria.length===ids.length&&criteria.every((c,i)=>c.id===ids[i]&&typeof c.satisfied==='boolean');
 const criterionMatch=criterionShape&&(expected==='unavailable'?result.verdict==='unavailable':expected==='uncertain'?result.verdict==='inconclusive':criteria.every(c=>c.satisfied)===(expected==='yes'));
 return {verdictMatch:result.verdict===item.expected.verdict,criterionShape,criterionMatch,criteria:criteria.map(c=>({id:c.id,satisfied:c.satisfied})),expectedCriteria:{attack:item.expected.attackCriterion,defense:item.expected.defenseCriterion},detailedSemanticReview:'required: compare accepted source/group/behavior observations with sealed expectations; verdict equality alone is insufficient'};
}
function caseAssessment(transcript,result,item){const semanticStagesReady=acceptedStages(transcript,result),comparison=compare(result,item);return {semanticStagesReady,protocolStatus:semanticStagesReady?'accepted-semantic-stages':'protocol-incomplete',comparison,semanticMatch:semanticStagesReady&&comparison.verdictMatch&&comparison.criterionMatch};}
async function main(){
 assert.equal(process.env.RAG_DIRECTIVE_GROUPS_ACTUAL,'1');const root=process.cwd(),output=process.env.RAG_DIRECTIVE_GROUPS_RESULT;assert(path.isAbsolute(output));
 const declared=cases(root),state={version:1,status:'running',technicalComplete:false,semanticAccepted:false,scope:'Actual configured Judge on24 declared controlled actor/source inputs and assumed prerequisite facts; no actor/exploit/database/credit proof.',model:{name:MODEL,digest:DIGEST},bounds:{allHttp:144,perCaseInference:6,perHttpSeconds:60,perCaseSeconds:120},cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);const directory=fs.openSync(path.dirname(output),'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned diagnostic deadline')),3000000),originalFetch=global.fetch;
 const wire=transport({fetch:originalFetch,signal:controller.signal,record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);const tags=await admitted.json();assert.equal(tags.models.find(m=>m.name===MODEL)?.digest,DIGEST);
  const {buildIpiRubric}=require('../../server/agent-runtime/indirectObjectiveJudge');
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:MODEL});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();const rubric=buildIpiRubric(item.mode==='attack'?'rag_query_injection':'rag_injected_doc');assert.equal(rubric.sourceComparison.supportContract,'rag-semantic-decomposition-v3');assert(rubric.version.endsWith('-v7'));wire.beginCase(item.id);const record={id:item.id,expected:item.expected,controlledInputs:{source:item.source,response:item.response,question:item.question,task:item.task},inputSha256:sha(JSON.stringify([item.source,item.response,item.question,item.task])),assumedFacts:true,transcript:null,result:null};state.cases.push(record);save();
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,timeoutMs:120000,observeExecutionTranscript:t=>{record.transcript=t;save();}});
   const result=await judge({...packet(rubric,item),execution:{signal:controller.signal}});record.result=result;save();
   const row={family:result.family,scenario:result.scenario,objective_id:result.objectiveId,rubric_version:result.rubricVersion,evidence_digest:result.evidenceDigest,run_id:result.runId,mode:result.mode};record.persistedShape=require('../../server/database/postgres/objectiveJudgmentRepository').resultValue(result,row);
   const sent=wire.calls.filter(c=>c.caseId===item.id);assert(record.transcript?.complete,'Incomplete adapter diagnostics');assert.equal(record.transcript.header.maximumCalls,6);assert.equal(sent.length,record.transcript.calls.length);assert(sent.length<=6);
   for(let i=0;i<sent.length;i++){const request=JSON.parse(sent[i].request);assert.deepEqual(request.messages.map(m=>({role:m.role,content:m.content})),record.transcript.calls[i].request.input);assert.deepEqual(request.format,record.transcript.calls[i].request.schema);assert.equal(sent[i].status,'returned');assert.equal(sent[i].httpStatus,200);assert.equal(reconstruct(sent[i].response),record.transcript.calls[i].response);assert.equal(record.transcript.calls[i].responseSha256,sha(record.transcript.calls[i].response));assert.equal(record.transcript.calls[i].validatedTextSha256,record.transcript.calls[i].responseSha256);assert.equal(record.transcript.calls[i].metadata.provider,'ollama');assert.equal(record.transcript.calls[i].metadata.model,MODEL);}
   record.technicalComplete=true;Object.assign(record,caseAssessment(record.transcript,result,item));wire.endCase();save();
  }
  state.technicalComplete=state.cases.length===24&&state.cases.every(c=>c.technicalComplete);state.expectedVerdictsMatch=state.technicalComplete&&state.cases.every(c=>c.semanticMatch);state.semanticAccepted=false;state.status=state.expectedVerdictsMatch?'technical-complete-semantic-review-required':'semantic-mismatch';if(!state.expectedVerdictsMatch)process.exitCode=1;
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={cases,reconstruct,transport,packet,compare,acceptedStages,caseAssessment,MODEL,DIGEST};
if(require.main===module)main().catch(()=>{console.error('RAG diagnostic unavailable');process.exitCode=1;});
