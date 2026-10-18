'use strict';
// Phase A mechanics only. Never reads labels, mints private actor proof, or persists credit.
const {createHash,randomUUID}=require('node:crypto');
const {z}=require('zod');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const contract=require('../../server/agent-runtime/dpiTechniqueWitnessAudit');
const INPUT_SHA256='fcda5a92b79d9c014c029a7dbd078d049411188e6ce61198de43cad128231c8e';
const sha=x=>createHash('sha256').update(x).digest('hex');
const inputSchema=z.object({version:z.literal('dpi-technique-semantic-inputs-v1'),provenance:z.string(),protocol:z.literal('dpi-technique-witness-v1'),cases:z.array(z.object({id:z.string(),objective:z.enum(['jailbreak','role_playing','side_stepping']),request:z.string().min(1),response:z.string().min(1),responseComplete:z.literal(true)}).strict()).length(18)}).strict();
function admitInput(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length>100000||sha(bytes)!==INPUT_SHA256)throw Error('SEALED_INPUT_REQUIRED');
 const value=inputSchema.parse(JSON.parse(bytes.toString('utf8')));
 if(value.cases.some((c,i)=>c.id!==`DT${String(i+1).padStart(2,'0')}`||c.objective!==['jailbreak','role_playing','side_stepping'][Math.floor(i/6)]))throw Error('CASE_SEQUENCE_INVALID');
 return value;
}
function controlledPacket(c,runId){
 const actor={version:'dpi-owned-actor-v2',objective:c.objective,runId,ownerKey:'["DPI","1"]',generation:'0',mode:'vuln',requestSha256:sha(c.request),responseSha256:sha(c.response),modelResponseSha256:sha(c.response),provider:'controlled-evidence',model:'synthetic-phase-a-not-an-actor-run'};
 return {rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:c.objective,version:contract.versionFor(c.objective),mode:'vuln',dpiTechniqueWitness:contract.VERSION,criteria:[{id:'observed_objective',allowedSources:['assistant_response'],description:contract.POLICY.slice(0,1999),quoteRequired:true,citationPolicy:'verbatim'}],requiredFacts:[...contract.FACTS],authoritativeVerdictFacts:['owned_actor_observed']},evidence:[{id:'request',source:'student_input',content:c.request},{id:'response',source:'assistant_response',content:c.response},{id:'owned_actor',source:'server_observation',content:actor}],facts:Object.fromEntries(contract.FACTS.map(k=>[k,true]))};
}
async function predict(options){
 const allowed=['inputBytes','model','signal','onCaseStart','onCaseEnd','onRecord','perCallTimeoutMs','workTimeoutMs'];
 if(!options||Object.keys(options).some(k=>!allowed.includes(k)))throw Error('CLOSED_PREDICTOR_OPTIONS');
 const {inputBytes,model,signal,onCaseStart,onCaseEnd,onRecord,perCallTimeoutMs=90000,workTimeoutMs=1800000}=options;
 const input=admitInput(inputBytes); // Before provider/callback access or invocation.
 if(!model||typeof model.chat!=='function')throw Error('INJECTED_CHAT_REQUIRED');
 if(!Number.isInteger(perCallTimeoutMs)||perCallTimeoutMs<100||perCallTimeoutMs>90000||!Number.isInteger(workTimeoutMs)||workTimeoutMs<100||workTimeoutMs>1800000)throw Error('INVALID_DEADLINE');
 for(const fn of [onCaseStart,onCaseEnd,onRecord])if(fn!==undefined&&typeof fn!=='function')throw Error('INVALID_CALLBACK');
 const controller=new AbortController(),deadline=performance.now()+workTimeoutMs;
 const abort=()=>controller.abort(signal.reason);if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(Error('PHASE_A_DEADLINE')),workTimeoutMs);
 const records=[];let totalAttempts=0,failure=null,active=null,pending=0,providerPending=0;
 const check=()=>{controller.signal.throwIfAborted();if(performance.now()>=deadline)throw Error('PHASE_A_DEADLINE');};
 async function bounded(work){check();let listener;const promise=Promise.resolve().then(work);pending++;promise.then(()=>pending--,()=>pending--);try{const value=await Promise.race([promise,new Promise((_,reject)=>{listener=()=>reject(controller.signal.reason||Error('CANCELLED'));controller.signal.addEventListener('abort',listener,{once:true});if(controller.signal.aborted)listener();})]);check();return value;}finally{controller.signal.removeEventListener('abort',listener);}}
 try{
  for(const c of input.cases){
   check();active=c.id;let transcript=null,calls=0,result=null;
   const packet=controlledPacket(c,randomUUID()),prepared=prepareJudgeInput(packet);
   if(prepared.evidenceError)throw Error('PACKET_LIMIT');
   const record={id:c.id,objective:c.objective,actorProvenance:'controlled-synthetic-evidence',genuineActor:false,credit:false,packet:JSON.parse(prepared.packet),evidenceDigest:prepared.evidenceDigest,result:null,transcript:null};
   records.push(record);
   try{
    if(onCaseStart)await bounded(()=>onCaseStart(c.id));check();
    const remaining=Math.floor(deadline-performance.now());if(remaining<100)throw Error('PHASE_A_DEADLINE');
    const judge=createObjectiveJudge({timeoutMs:Math.min(perCallTimeoutMs,remaining),model:{chat:async(...args)=>{check();if(++calls>2||++totalAttempts>36)throw Error('TRANSPORT_BUDGET');providerPending++;try{return await model.chat(...args);}finally{providerPending--;}}},observeExecutionTranscript:t=>{transcript=t;}});
    result=await bounded(()=>judge({...packet,execution:{runId:packet.evidence[2].content.runId,signal:controller.signal,check:async()=>check()}}));check();
    record.result=result;record.transcript=transcript;record.attempts=calls;
    if(!transcript?.complete||transcript.calls.length!==calls||calls<1||calls>2||result.attempts!==calls||!['pass','fail','inconclusive'].includes(result.verdict)||!result.dpiTechniqueWitness||result.evidenceDigest!==prepared.evidenceDigest)throw Error('MECHANICAL_EVALUATION_FAILURE');
    const derived=contract.derive(result.dpiTechniqueWitness.input,record.packet);
    if(JSON.stringify(derived.dpiTechniqueWitness)!==JSON.stringify(result.dpiTechniqueWitness)||derived.verdict!==result.verdict)throw Error('AUDIT_MISMATCH');
   }catch(error){record.result=result;record.transcript=transcript;record.attempts=calls;record.failure='MECHANICAL_OR_AUTHORITY_FAILURE';throw error;}
   finally{if(onCaseEnd)await bounded(()=>onCaseEnd(c.id));if(onRecord)await bounded(()=>onRecord(structuredClone(record)));}
   active=null;
  }
  check();
 }catch{failure='MECHANICAL_OR_AUTHORITY_FAILURE';}
 finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
 return {version:'dpi-technique-phase-a-predictions-v1',inputSha256:INPUT_SHA256,status:failure?'incomplete':'predictions-complete-semantic-review-pending',semanticAccepted:null,credit:false,genuineActor:false,records,totalAttempts,failedCase:failure?active:null,unattempted:input.cases.slice(records.length).map(c=>c.id),failure,physicalPending:pending>0||providerPending>0,transportDrainVerified:false};
}
module.exports={INPUT_SHA256,admitInput,predict};
