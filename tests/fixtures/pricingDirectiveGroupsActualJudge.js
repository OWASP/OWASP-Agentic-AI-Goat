'use strict';
// Actual Judge transport on declared controlled inputs. No actor, database or credit.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const DEFAULT_JUDGE=Object.freeze({model:MODEL,digest:DIGEST});
const STRONG_JUDGE=Object.freeze({model:'llama3.3:70b',digest:'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'});
const DECLARATIONS=[['tests/release-inputs/pricing-directive-group-prospective-cases-2026-09-27.json','55c3945570111e8d13b6d4df34edd4dfa563791e26225251a9892a723fe84a6b'],['tests/release-inputs/pricing-directive-group-prospective-supplement-2026-09-27.json','ddecff4343c060ca8883dce2fe0a6f31c5a59d4d72a5a13be6bc32335ef21bd8']];
const sha=value=>createHash('sha256').update(value).digest('hex');
function identityError(){const error=Error('JUDGE_IDENTITY_CONFIG');error.code='JUDGE_IDENTITY_CONFIG';return error;}
function admitJudgeIdentity(value){if(value===undefined)return DEFAULT_JUDGE;if(!value||Object.keys(value).sort().join(',')!=='digest,model'||value.model!==STRONG_JUDGE.model||value.digest!==STRONG_JUDGE.digest)throw identityError();return STRONG_JUDGE;}
function assertMetadataIdentity(metadata,judgeIdentity){const identity=admitJudgeIdentity(judgeIdentity);assert(metadata&&typeof metadata==='object'&&!Array.isArray(metadata));assert.equal(metadata.models?.find(model=>model?.name===identity.model)?.digest,identity.digest);return identity;}
function cases(root){const docs=DECLARATIONS.map(([name,digest])=>{const bytes=fs.readFileSync(path.join(root,name));assert.equal(sha(bytes),digest);return JSON.parse(bytes);});const result=docs.flatMap(doc=>doc.cases);assert.equal(result.length,14);assert.equal(new Set(result.map(c=>c.id)).size,14);return {cases:result,question:docs[0].learnerQuestion};}
function reconstruct(raw,judgeIdentity){
 const identity=admitJudgeIdentity(judgeIdentity);let frames;try{frames=[JSON.parse(raw)];}catch{frames=raw.trim().split('\n').map(line=>JSON.parse(line));}
 assert(frames.length>0);let text='';frames.forEach((f,i)=>{assert.equal(f.model,identity.model);assert.equal(f.done,i===frames.length-1);assert(!f.error);assert.equal(f.message?.role,'assistant');assert.equal(typeof f.message.content,'string');text+=f.message.content;});return text;
}
function transport({fetch:upstream,signal,record=()=>{},profile='historical84',judgeIdentity}){
 const identity=admitJudgeIdentity(judgeIdentity);
 const limits={historical84:84,factored6:37,factored18:109,grounding10:11,manual24:25,manual16:17,mcpDescription32:32};assert(Object.hasOwn(limits,profile)&&typeof profile==='string');
 const perCaseLimit={grounding10:2,manual16:4,mcpDescription32:4}[profile]||6;
 const calls=[],controllers=new Set();let active=null,totalBytes=0,closed=false;const counts=new Map();
 return {calls,beginCase(id){assert(!closed);assert.equal(active,null);assert(!counts.has(id));active=id;counts.set(id,0);},endCase(){active=null;},close(){closed=true;for(const c of controllers)c.abort();},
  async fetch(url,options={}){
   assert(!closed);const target=new URL(typeof url==='string'?url:url.url||String(url));assert.equal(target.origin,'http://127.0.0.1:11434');assert(!target.search&&!target.hash);assert(calls.length<limits[profile],'Global HTTP budget exhausted');
   const chat=target.pathname==='/api/chat';assert(chat||target.pathname==='/api/tags');assert.equal(options.method||'GET',chat?'POST':'GET');
   let request=null;if(chat){assert(active,'No active declared case');assert(counts.get(active)<perCaseLimit,'Case HTTP budget exhausted');assert.equal(typeof options.body,'string');assert(Buffer.byteLength(options.body)<=262144);request=JSON.parse(options.body);assert.equal(request.model,identity.model);counts.set(active,counts.get(active)+1);}else{assert.equal(active,null);assert.equal(calls.length,0,'Only one model admission read');}
   const call={index:calls.length+1,caseId:active,kind:chat?'inference':'metadata',request:options.body||null,requestSha256:sha(options.body||''),status:'pending'};calls.push(call);record();
   const controller=new AbortController();controllers.add(controller);const combined=AbortSignal.any([controller.signal,signal,AbortSignal.timeout(60000),...(options.signal?[options.signal]:[])]);const chunks=[];let size=0,finished=false;
   function finish(error){if(finished)return;finished=true;call.response=Buffer.concat(chunks).toString('utf8');call.responseSha256=sha(Buffer.concat(chunks));call.responseBytes=chunks.reduce((n,c)=>n+c.length,0);call.observedBytes=size;call.status=error?'incomplete':'returned';if(error)call.errorCode='TRANSPORT_INCOMPLETE';controllers.delete(controller);record();}
   try{
    const response=await upstream(url,{...options,redirect:'error',signal:combined});call.httpStatus=response.status;const reader=response.body.getReader();
    return new Response(new ReadableStream({async pull(out){try{const item=await reader.read();if(item.done){finish();out.close();return;}size+=item.value.byteLength;totalBytes+=item.value.byteLength;if(size>4194304||totalBytes>384*1024*1024){controller.abort();throw Error('Wire byte bound');}chunks.push(Buffer.from(item.value));out.enqueue(item.value);}catch(error){controller.abort();finish(error);out.error(error);}},async cancel(reason){controller.abort();finish(Error('Cancelled'));await reader.cancel(reason);}}),{status:response.status,headers:response.headers});
   }catch(error){controller.abort();finish(error);throw error;}
  }
 };
}
function packet(rubric,item,question){return {rubric,facts:Object.fromEntries(rubric.requiredFacts.map(k=>[k,true])),evidence:[{id:'pricing_manual_source',source:'tool_result',content:item.source},{id:'pricing_final_answer',source:'assistant_response',content:item.response},{id:'pricing_learner_question',source:'student_input',content:question}]};}
async function main(){
 assert.equal(process.env.PRICING_DIRECTIVE_GROUPS_ACTUAL,'1');const root=process.cwd(),output=process.env.PRICING_DIRECTIVE_GROUPS_RESULT;assert(path.isAbsolute(output));
 const declared=cases(root),state={version:1,status:'running',technicalComplete:false,semanticAccepted:false,scope:'Actual configured Judge on14 declared controlled actor/source inputs and assumed prerequisite facts; no actor/exploit/database/credit proof.',model:{name:MODEL,digest:DIGEST},bounds:{allHttp:84,perCaseInference:6,perHttpSeconds:60,perCaseSeconds:120},cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);const directory=fs.openSync(path.dirname(output),'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned diagnostic deadline')),1740000),originalFetch=global.fetch;
 const wire=transport({fetch:originalFetch,signal:controller.signal,record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);const tags=await admitted.json();assertMetadataIdentity(tags);
  const {PRICING_RUBRICS}=require('../../server/services/secureshopPricingAssessment'),current=PRICING_RUBRICS.ss_pricing_manual_injection,rubric={...current,version:'secureshop-pricing-manual-v7',sourceComparison:{...current.sourceComparison,supportContract:'pricing-semantic-decomposition-v4'},mode:'vuln'};assert.equal(rubric.version,'secureshop-pricing-manual-v7');assert.equal(rubric.sourceComparison.supportContract,'pricing-semantic-decomposition-v4');
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:MODEL});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();wire.beginCase(item.id);const record={id:item.id,expected:item.expected,controlledInputs:{source:item.source,response:item.response,question:declared.question},inputSha256:sha(JSON.stringify([item.source,item.response,declared.question])),assumedFacts:true,transcript:null,result:null};state.cases.push(record);save();
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,timeoutMs:120000,observeExecutionTranscript:t=>{record.transcript=t;save();}});
   const result=await judge({...packet(rubric,item,declared.question),execution:{signal:controller.signal}});record.result=result;save();
   const row={family:result.family,scenario:result.scenario,objective_id:result.objectiveId,rubric_version:result.rubricVersion,evidence_digest:result.evidenceDigest,run_id:result.runId,mode:result.mode};record.persistedShape=require('../../server/database/postgres/objectiveJudgmentRepository').resultValue(result,row);
   const sent=wire.calls.filter(c=>c.caseId===item.id);assert(record.transcript?.complete,'Incomplete adapter diagnostics');assert.equal(record.transcript.header.maximumCalls,6);assert.equal(sent.length,record.transcript.calls.length);assert(sent.length<=6);
   for(let i=0;i<sent.length;i++){const request=JSON.parse(sent[i].request);assert.deepEqual(request.messages.map(m=>({role:m.role,content:m.content})),record.transcript.calls[i].request.input);assert.deepEqual(request.format,record.transcript.calls[i].request.schema);assert.equal(sent[i].status,'returned');assert.equal(sent[i].httpStatus,200);assert.equal(reconstruct(sent[i].response),record.transcript.calls[i].response);assert.equal(record.transcript.calls[i].responseSha256,sha(record.transcript.calls[i].response));assert.equal(record.transcript.calls[i].validatedTextSha256,record.transcript.calls[i].responseSha256);assert.equal(record.transcript.calls[i].metadata.provider,'ollama');assert.equal(record.transcript.calls[i].metadata.model,MODEL);}
   record.technicalComplete=true;record.semanticMatch=result.verdict===item.expected;wire.endCase();save();
  }
  state.technicalComplete=state.cases.length===14&&state.cases.every(c=>c.technicalComplete);state.semanticAccepted=state.technicalComplete&&state.cases.every(c=>c.semanticMatch);state.status=state.semanticAccepted?'semantic-accepted-controlled-inputs':'semantic-mismatch';if(!state.semanticAccepted)process.exitCode=1;
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={cases,reconstruct,transport,packet,MODEL,DIGEST,DEFAULT_JUDGE,STRONG_JUDGE,admitJudgeIdentity,assertMetadataIdentity};
if(require.main===module)main().catch(()=>{console.error('Pricing diagnostic unavailable');process.exitCode=1;});
