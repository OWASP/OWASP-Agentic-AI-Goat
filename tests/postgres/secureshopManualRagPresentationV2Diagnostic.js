'use strict';
// Prospective, diagnostic-only semantic calibration. The original fact gate is
// recorded truthfully; only this versioned in-memory rubric omits requiredFacts
// so the genuine clean capture can receive the same original semantic criteria.
// It cannot publish a canonical assessment, retry an actor, or award credit.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const P=require('../fixtures/secureshopManualRagPresentationDiagnosticV2');
const {RUBRIC}=require('../../server/services/secureshopManualRagEvidence');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const transport=require('./secureshopMcpDescriptionAtomicRetainedDiagnostic');
const metadata=require('./secureshopAuditRetainedTransportDiagnostic');
const closure=require('../fixtures/studentDeletionSourceClosure');
require('../../server/agent-runtime/judgeExecutionTranscript');

const ROOT=path.resolve(__dirname,'../..');
const NAME='v26-presentation-v2-diagnostic.json';
const CLAIM=path.join(ROOT,'tasks/qualification/v26-presentation-v2-one-shot.claim.json');
const LIVE_ENABLED=true;
// One deadline covers four original 90-second Judge requests, two bounded
// model-identity probes, local settlement, and 35 seconds of orchestration.
const WALL_MS=420000,JOIN_MS=5000,MODEL_PROBE_MS=10000,SOCKET_RETIRE_MS=5000;
const MAX_REPORT=32*1024*1024,MAX_ALL_RESPONSES=16*1024*1024;
const ORIGINAL_FORMAT_SHA='75ccdfa6b3958ddfb15417da4de6c54af652154ed19d9aa0105eecd327264b0b';
const PINS=Object.freeze({
 'tests/fixtures/secureshopManualRagPresentationDiagnosticV2.js':'2843409b937c600e246bbe8ef5746940d0f1cfd8240185e23e0aae9e3d19560c',
 'server/services/secureshopManualRagEvidence.js':'96bd22eb6ce89c45191c7162b7366fc8432eb995469995a7eb2e972c1857f12e',
 'server/agent-runtime/objectiveJudge.js':'186b7169cbc7161bca4a4c64f88790b3a40da3e512a7c1c9331a3928c1ed46a1',
 'tests/postgres/secureshopMcpDescriptionAtomicRetainedDiagnostic.js':'c93abce1a1c6bca49313eb979dbdebe9778daf6946d33c06d2384629555f8e91',
 'tests/postgres/secureshopAuditRetainedTransportDiagnostic.js':'67cc1348a6469e1edab42c79adc1b79046aec296d9422dd4791f8760a40bddcb',
 'tests/fixtures/studentDeletionSourceClosure.js':'b1d3daef8c0541c95b296b8fff1557a8d19d75d63896b0e7ad37a7f44565f7f2',
});
const sha=x=>createHash('sha256').update(x).digest('hex');
function pins(){for(const [name,digest]of Object.entries(PINS)){
 const file=path.join(ROOT,name),s=fs.lstatSync(file);
 assert(s.isFile()&&!s.isSymbolicLink()&&sha(fs.readFileSync(file))===digest,'reviewed source changed');
}return PINS;}
function sourceSnapshot(){
 // The closure parser itself uses an intentionally dynamic parser import;
 // pin its exact bytes and loaded module separately, not as an AST root.
 const found=closure.collect(ROOT,Object.keys(PINS).filter(name=>
  name!=='tests/fixtures/studentDeletionSourceClosure.js'));
 const result={};for(const file of [...new Set([...found.map(f=>path.join(ROOT,f)),...Object.keys(require.cache),__filename])].sort()){
  assert(file.startsWith(ROOT+path.sep),'repository-only module closure');
  const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink());
  result[path.relative(ROOT,file)]=sha(fs.readFileSync(file));
 }return result;
}
function originalFacts(label,wire){
 const facts=structuredClone(wire.originalCapture.judgeInput.facts);
 assert.deepEqual(Object.keys(facts).sort(),[...RUBRIC.requiredFacts].sort());
 assert(RUBRIC.requiredFacts.every(id=>facts[id]===true));
 if(label==='clean'){
  facts.original_uploaded_manual_bound=false;
  facts.exact_selected_chunk_retrieved=false;
 }
 return facts;
}
function diagnosticRubric(){
 const rubric=structuredClone(RUBRIC);rubric.version='secureshop-manual-rag-presentation-diagnostic-v2';
 rubric.requiredFacts=[];
 assert(isDeepStrictEqual(rubric.criteria,RUBRIC.criteria));
 return rubric;
}
function casePacket(label,retained){
 const formatted=P.formatCase(label,retained.cases),facts=originalFacts(label,retained.wire);
 const originalFactGateEligible=RUBRIC.requiredFacts.every(id=>facts[id]===true);
 assert.equal(originalFactGateEligible,label==='poisoned');
 const diagnostic={rubric:diagnosticRubric(),facts:{},evidence:[
  {id:'manual_comparison',source:'server_observation',content:formatted.modelInput.nonCitableServerReference.content},
  formatted.modelInput.citableObservedEvidence[0],
 ]};
 assert.equal(prepareJudgeInput(diagnostic).evidenceError,undefined);
 return {diagnostic,originalFacts:facts,originalFactGateEligible,formatted,
  presentationSha256:sha(JSON.stringify(formatted.modelInput))};
}
function exactRequest(messages,tools,options,packet,criterionId){
 assert.deepEqual(tools,[]);assert.equal(messages.length,2);
 assert.equal(messages[0].role,'system');assert.equal(messages[1].role,'user');
 assert.equal(options.temperature,0);assert.equal(options.num_ctx,32768);
 assert.equal(options.num_predict,900);assert.equal(options.max_tokens,900);assert.equal(options.timeout,90000);
 assert.equal(sha(JSON.stringify(options.format)),ORIGINAL_FORMAT_SHA,'original citation output schema required');
 assert(messages[0].content.endsWith('\nOUTPUT JSON SCHEMA:\n'+JSON.stringify(options.format)));
 assert.equal(messages[0].content.includes('REPAIR:'),false,'repair is not admitted');
 const criterion=RUBRIC.criteria.find(x=>x.id===criterionId);assert(criterion);
 assert(messages[0].content.includes(criterion.description),'original criterion text required');
 const expected={nonCitableServerReference:packet.formatted.modelInput.nonCitableServerReference,
  citableObservedEvidence:packet.formatted.modelInput.citableObservedEvidence};
 assert(isDeepStrictEqual(JSON.parse(messages[1].content),expected),'exact reviewed presentation required');
 const body=Buffer.from(JSON.stringify({model:transport.MODEL,messages,
  format:options.format,options:{temperature:0,num_ctx:32768,num_predict:900},stream:true}));
 assert(body.length>0&&body.length<=262144);return body;
}
function syncRecord(record,report){const outcome=record(report);assert(!outcome||typeof outcome.then!=='function');}
async function joinPending(pending,budgetMs=JOIN_MS){let timer;try{return await Promise.race([
 Promise.allSettled([...pending]).then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),budgetMs);})
]);}finally{clearTimeout(timer);}}
function rawReply(result){
 assert(Buffer.isBuffer(result.body)&&result.responseBytes===result.body.length,'complete untruncated response required');
 const decoded=transport.decodeChat(result);
 const frames=result.body.toString('utf8').trimEnd().split('\n').map(line=>JSON.parse(line));
 const raw=frames.map(frame=>frame.message?.content||'').join('');
 assert(isDeepStrictEqual(JSON.parse(raw),decoded));return {raw,terminal:frames.at(-1)};
}
async function execute({send,probe,record,signal,controlled=false,expectedSourcePins,controlledWallMs}){
 assert.equal(typeof send,'function');assert.equal(typeof probe,'function');assert.equal(typeof record,'function');
 assert(controlled||controlledWallMs===undefined,'deadline override is controlled-only');
 assert(controlledWallMs===undefined||Number.isSafeInteger(controlledWallMs)
  &&controlledWallMs>0&&controlledWallMs<=WALL_MS,'bounded controlled deadline required');
 pins();const retained=P.loadRetainedPair(),sourcePins=sourceSnapshot();
 if(expectedSourcePins)assert(isDeepStrictEqual(sourcePins,expectedSourcePins),'reviewed source snapshot changed');
 const packets=['poisoned','clean'].map(label=>casePacket(label,retained));
 const report={version:1,kind:'v26-presentation-v2-diagnostic',controlled,diagnosticOnly:true,
  canonicalCredit:false,qualificationAccepted:false,productionPromotion:false,actorCalls:0,
  originalRubricVersion:RUBRIC.version,diagnosticRubricVersion:packets[0].diagnostic.rubric.version,
  semanticCriteriaUnchanged:true,originalFactGate:{poisoned:packets[0].originalFacts,clean:packets[1].originalFacts},
  originalGateEligible:{poisoned:true,clean:false},referenceCitable:false,
  model:transport.MODEL,modelDigest:transport.DIGEST,sourcePins,retainedWireSha256:P.PINS.wire,
  provenance:packets.map(p=>({...p.formatted.hostProvenance,presentationSha256:p.presentationSha256})),
  calls:[],results:[],failure:null,postflightFailures:{model:null,source:null},
  reservations:0,physicalAttempts:0,blockedRepairs:0,pendingTransportDebt:false,localRetirementVerified:false,
  remoteCancellationProven:false,status:'pending',calibrationMatched:false};
 const controller=new AbortController(),pending=new Set(),used=new Set();let responseBytes=0,recordFailure=null,sealed=false;
 const deadline=performance.now()+(controlledWallMs??WALL_MS);
 // The controlled short-deadline seam exercises overdue settlement without
 // waiting through production's reserved 15-second postflight window.
 const remaining=(limit,reserve=0)=>{const available=Math.floor(deadline-performance.now()
  -(controlledWallMs===undefined?reserve:0));
  assert(available>0,'single diagnostic wall deadline exceeded');return Math.min(limit,available);};
 const abort=()=>controller.abort(signal?.reason||Error('DIAGNOSTIC_ABORTED'));
 if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(Error('DIAGNOSTIC_WALL_DEADLINE')),controlledWallMs??WALL_MS);
 const save=()=>{if(sealed)return;if(recordFailure)throw recordFailure;
  try{syncRecord(record,report);}catch(error){recordFailure=error;controller.abort(error);throw error;}};
 try{
  controller.signal.throwIfAborted();save();
  report.preModel=await probe('http://127.0.0.1:11434',remaining(MODEL_PROBE_MS));save();
  assert(report.preModel.identityMatched&&report.preModel.localSocketRetired,'local model identity unavailable');
  for(let index=0;index<2;index++){
   const packet=packets[index],label=index===0?'poisoned':'clean';let stage=null;
   controller.signal.throwIfAborted();
   const model={provider:'ollama',model:transport.MODEL,chat(messages,tools,options){
    const operation=(async()=>{
     controller.signal.throwIfAborted();options.signal.throwIfAborted();
     assert(stage,'original Judge criterion stage required');
     if(stage.attempt!==1){report.blockedRepairs++;save();throw Error('DIAGNOSTIC_REPAIR_FORBIDDEN');}
     const criterion=RUBRIC.criteria.findIndex(x=>x.id===stage.criterionId);
     assert(criterion>=0&&criterion<2,'original criterion only');
     const key=`${index}:${criterion}`;assert(!used.has(key)&&report.reservations<4,'physical cap');
     const body=exactRequest(messages,tools,options,packet,stage.criterionId);
     used.add(key);stage=null;
     const row={caseIndex:index,criterionIndex:criterion,physicalOrdinal:++report.reservations,
      request:body.toString(),requestSha256:sha(body),physicalAttempt:false,status:null,termination:'intent',
      localSocketRetired:null,responseBase64:null,responseSha256:null,responseBytes:0};
     report.calls.push(row);save();let callbackFailure=null;
     try{
      const result=await send({origin:'http://127.0.0.1:11434',method:'POST',pathname:'/api/chat',body,
       timeoutMs:remaining(90000,MODEL_PROBE_MS+JOIN_MS),byteLimit:transport.MAX_RESPONSE_BYTES,
       signal:AbortSignal.any([controller.signal,options.signal]),onPhysicalAttempt(){
        try{assert(!sealed,'terminal report sealed');assert(!row.physicalAttempt&&report.physicalAttempts<4);row.physicalAttempt=true;
         report.physicalAttempts++;save();}catch(error){callbackFailure=error;controller.abort(error);}
       }});
      assert(!sealed,'terminal report sealed');
      row.status=result.status;row.termination=result.termination;row.localSocketRetired=result.localSocketRetired;
      row.responseBytes=result.responseBytes;row.responseBase64=result.body.toString('base64');
      row.responseSha256=sha(result.body);responseBytes+=result.body.length;save();
      if(callbackFailure)throw callbackFailure;
      assert(responseBytes<=MAX_ALL_RESPONSES&&row.physicalAttempt,'physical response bound');
      const {raw,terminal}=rawReply(result);row.rawReplySha256=sha(raw);save();
      return {provider:'ollama',model:transport.MODEL,response:raw,mocked:false,fallback:false,
       metadata:{eval_count:terminal.eval_count}};
     }catch(error){if(sealed)throw error;row.failure={name:error.name,code:error.code||null};
      if(Buffer.isBuffer(error.body)){row.responseBase64=error.body.toString('base64');
       row.responseSha256=sha(error.body);row.responseBytes=error.body.length;}
      if(typeof error.localSocketRetired==='boolean')row.localSocketRetired=error.localSocketRetired;
      if(error.termination)row.termination=error.termination;
      if(!recordFailure)save();throw callbackFailure||error;}
    })();pending.add(operation);operation.then(()=>pending.delete(operation),()=>pending.delete(operation));return operation;
   }};
   const judge=createObjectiveJudge({model,timeoutMs:90000,contextTokens:32768});
   const result=await judge({...packet.diagnostic,execution:{signal:controller.signal,
    emit(event){if(event.node==='judge_scoped_model'&&event.type==='start')stage=event.data;}}});
   if(!await joinPending(pending,remaining(JOIN_MS,MODEL_PROBE_MS))){
    report.pendingTransportDebt=true;throw Error('TRANSPORT_JOIN_DEADLINE');}
   report.results.push({caseIndex:index,result});save();
   assert(!['unavailable','inconclusive'].includes(result.verdict)&&!result.errorCode,'Judge unavailable');
   assert.equal(result.criteria.length,2);
  }
 }catch(error){report.failure={name:error.name,code:error.code||null};}
 finally{
  controller.abort(Error('DIAGNOSTIC_FINISHED'));signal?.removeEventListener('abort',abort);
  if(!report.pendingTransportDebt){let joined=false;
   try{joined=await joinPending(pending,remaining(JOIN_MS,MODEL_PROBE_MS));}catch{}
   if(!joined)report.pendingTransportDebt=true;}
  report.localRetirementVerified=!report.pendingTransportDebt&&report.calls.every(x=>!x.physicalAttempt||x.localSocketRetired===true);
  if(!report.localRetirementVerified)report.failure||={code:'LOCAL_RETIREMENT_UNVERIFIED'};
  try{report.postModel=await probe('http://127.0.0.1:11434',remaining(MODEL_PROBE_MS));
   assert(report.postModel.identityMatched&&report.postModel.localSocketRetired);
  }catch(error){report.postflightFailures.model={code:'MODEL_POSTFLIGHT_UNVERIFIED',name:error.name};}
  try{remaining(1);pins();assert(isDeepStrictEqual(sourceSnapshot(),sourcePins));remaining(1);
  }catch(error){report.postflightFailures.source={code:'SOURCE_POSTFLIGHT_UNVERIFIED',name:error.name};}
  if(report.postflightFailures.model||report.postflightFailures.source)
   report.failure||={code:'POSTFLIGHT_UNVERIFIED'};
  report.calibrationMatched=!report.failure&&report.results.length===2&&report.physicalAttempts===4
   &&report.results.every((x,i)=>x.result.criteria.length===2&&x.result.criteria.every(c=>c.satisfied===(i===0)));
  report.status=report.failure?'diagnostic-failed':report.calibrationMatched?'calibration-matched':'calibration-mismatched';
  clearTimeout(timer);try{if(!recordFailure)save();}finally{sealed=true;}
 }
 return structuredClone(report);
}
function privateRecorder(output){
 assert.equal(path.basename(output),NAME);const run=path.dirname(output),base=path.join(ROOT,'tasks/qualification');
 assert.equal(path.dirname(run),base);assert.match(path.basename(run),/^run-v26-presentation-[A-Za-z0-9_-]+$/);
 for(const dir of [ROOT,path.join(ROOT,'tasks'),base,run]){const s=fs.lstatSync(dir);
  assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&fs.realpathSync(dir)===dir);}
 assert.equal(fs.statSync(run).mode&0o777,0o700);
 let fd=fs.openSync(output,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 const syncDir=()=>{const d=fs.openSync(run,fs.constants.O_RDONLY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}};
 try{fs.writeSync(fd,'{"status":"allocated","qualificationAccepted":false}\n');fs.fsyncSync(fd);syncDir();}
 catch(error){fs.closeSync(fd);throw error;}
 let owned=fs.fstatSync(fd),sequence=0;
 return {record(report){const data=Buffer.from(JSON.stringify(report)+'\n');assert(data.length<=MAX_REPORT);
  const current=fs.lstatSync(output);assert(current.isFile()&&!current.isSymbolicLink()
   &&current.ino===owned.ino&&current.dev===owned.dev,'owned checkpoint changed');
  const temporary=output+'.checkpoint-'+(++sequence);let next;
  try{next=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
   let at=0;while(at<data.length)at+=fs.writeSync(next,data,at,data.length-at,at);fs.fsyncSync(next);
   const same=fs.lstatSync(output);assert(same.ino===owned.ino&&same.dev===owned.dev&&!same.isSymbolicLink());
   fs.renameSync(temporary,output);fs.closeSync(fd);fd=next;next=undefined;owned=fs.fstatSync(fd);syncDir();
  }finally{if(next!==undefined)fs.closeSync(next);}
 },close(){fs.closeSync(fd);}};
}
function exclusiveClaim(planSha256,output,claim=CLAIM){
 assert(claim.startsWith(path.join(ROOT,'tasks/qualification')+path.sep));
 const base=path.dirname(claim);assert.equal(fs.realpathSync(base),base);
 const data=Buffer.from(JSON.stringify({version:1,profile:P.PROFILE,planSha256,output,
  retainedWireSha256:P.PINS.wire,canonicalCredit:false,consumed:true})+'\n');
 const fd=fs.openSync(claim,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{let at=0;while(at<data.length)at+=fs.writeSync(fd,data,at,data.length-at,at);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 const d=fs.openSync(base,fs.constants.O_RDONLY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
}
function plan(){
 pins();const retained=P.loadRetainedPair(),sourcePins=sourceSnapshot();
 const packets=['poisoned','clean'].map(label=>casePacket(label,retained));
 const p={liveEnabled:LIVE_ENABLED,profile:P.PROFILE,diagnosticOnly:true,canonicalCredit:false,
  originalRubricVersion:RUBRIC.version,diagnosticRubricVersion:packets[0].diagnostic.rubric.version,
  originalFactGateEligible:{poisoned:true,clean:false},semanticCriteriaUnchanged:true,
  physicalJudgeCallsMax:4,perCaseCriterionCallsMax:1,repairs:0,actorCalls:0,
  model:transport.MODEL,modelDigest:transport.DIGEST,sourcePins,retainedWireSha256:P.PINS.wire,
  taskSha256:P.PINS.task,caseProvenance:packets.map(x=>({...x.formatted.hostProvenance,
   presentationSha256:x.presentationSha256})),
  workDeadlineMs:WALL_MS,localSettlementMs:JOIN_MS,postModelTimeoutMs:MODEL_PROBE_MS,
  socketRetirementAllowanceMs:SOCKET_RETIRE_MS,outerTerminalBudgetMs:WALL_MS+2*SOCKET_RETIRE_MS+JOIN_MS,
  remoteCancellationProven:false};return {...p,planSha256:sha(JSON.stringify(p))};
}
async function main(argv=process.argv.slice(2)){
 const current=plan();if(argv.length===0||argv.length===1&&argv[0]==='--plan')return current;
 assert(argv.length===5&&argv[0]==='--run'&&argv[1]==='--expected-plan'
  &&argv[3]==='--output','exact CLI required');
 assert.equal(argv[2],current.planSha256,'reviewed current plan required');
 assert(LIVE_ENABLED,'public live diagnostic gate closed');
 const writer=privateRecorder(argv[4]);
 try{exclusiveClaim(current.planSha256,argv[4]);}catch(error){writer.close();throw error;}
 const controller=new AbortController(),interrupt=()=>controller.abort(Error('DIAGNOSTIC_INTERRUPTED'));
 process.on('SIGINT',interrupt);process.on('SIGTERM',interrupt);
 try{const report=await execute({send:transport.singlePost,probe:metadata.checkModel,
  record:writer.record,signal:controller.signal,expectedSourcePins:current.sourcePins});
  if(report.status!=='calibration-matched')process.exitCode=1;
  return {output:argv[4],status:report.status,physicalAttempts:report.physicalAttempts,
   localRetirementVerified:report.localRetirementVerified,qualificationAccepted:false};
 }finally{writer.close();process.removeListener('SIGINT',interrupt);process.removeListener('SIGTERM',interrupt);}
}
function runControlled(options){return execute({...options,controlled:true});}
if(require.main===module)main().then(value=>process.stdout.write(JSON.stringify(value)+'\n')).catch(()=>{process.exitCode=1;});
module.exports={main,runControlled,plan,casePacket,diagnosticRubric,exactRequest,privateRecorder,exclusiveClaim,
 NAME,CLAIM,LIVE_ENABLED};
