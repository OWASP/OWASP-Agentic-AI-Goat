'use strict';
// Prospective V21 diagnostic runner. No actor, DB, canonical publication or
// objective credit. Live CLI requires an exact reviewed plan and private output.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const V8=require('../fixtures/secureshopUserLookupObservationV8');
const E=require('../../server/services/secureshopUserLookupEvidence');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
const T=require('./secureshopMcpDescriptionAtomicRetainedDiagnostic');
const metadata=require('./secureshopAuditRetainedTransportDiagnostic');
const closure=require('../fixtures/studentDeletionSourceClosure');
require('../../server/agent-runtime/judgeExecutionTranscript');
const ROOT=path.resolve(__dirname,'../..'),NAME='v21-v8-retained-diagnostic.json';
const LIVE_ENABLED=true,MAX_REPORT=32*1024*1024,MAX_RESPONSES=16*1024*1024;
const PINS=Object.freeze({
 'tests/fixtures/secureshopUserLookupObservationV8.js':'402ffb0bb86b9884d94e413c754b7d2fb7f1ccedd3f71e64de9903f97f8e6744',
 'tests/fixtures/secureshopUserLookupResponseFormatV5.js':'17f44d0373d002d850a4ca8cfe48ac75873c9c0308390511ffd2c9b8560322d4',
 'tests/fixtures/secureshopUserLookupBenignRetained.js':'19371ce120c96fb8a63027d9a8129e55d8ff0615f8566b8d88251028f78a9540',
 'tests/postgres/secureshopMcpDescriptionAtomicRetainedDiagnostic.js':'c93abce1a1c6bca49313eb979dbdebe9778daf6946d33c06d2384629555f8e91',
 'tests/postgres/secureshopAuditRetainedTransportDiagnostic.js':'67cc1348a6469e1edab42c79adc1b79046aec296d9422dd4791f8760a40bddcb',
 'server/agent-runtime/objectiveJudge.js':'186b7169cbc7161bca4a4c64f88790b3a40da3e512a7c1c9331a3928c1ed46a1',
});
const sha=x=>createHash('sha256').update(x).digest('hex');
function pins(){for(const [name,digest]of Object.entries(PINS)){
 const file=path.join(ROOT,name),s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink());
 assert.equal(sha(fs.readFileSync(file)),digest,'diagnostic source changed');
}return PINS;}
function sourceSnapshot(){
 const files=closure.collect(ROOT,Object.keys(PINS));
 const result={};for(const file of [...new Set([...files.map(f=>path.join(ROOT,f)),...Object.keys(require.cache),__filename])].sort()){
  assert(file.startsWith(ROOT+path.sep),'repository-only module closure required');
  const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink());
  result[path.relative(ROOT,file)]=sha(fs.readFileSync(file));
 }return result;
}
function createAccounting(){
 const counts=Array.from({length:2},()=>Array(4).fill(0));let total=0;
 return {reserve(control,criterion){assert(Number.isInteger(control)&&control>=0&&control<2&&Number.isInteger(criterion)&&criterion>=0&&criterion<4);
  assert(total<16&&counts[control][criterion]<2,'physical budget exhausted');total++;counts[control][criterion]++;
  return {control,criterion,attempt:counts[control][criterion],physicalOrdinal:total};}};
}
function syncRecord(record,value){const result=record(value);assert(!result||typeof result.then!=='function','synchronous durable recorder required');}
async function joinPending(pending){
 let timer;try{return await Promise.race([Promise.allSettled([...pending]).then(()=>true),
  new Promise(resolve=>{timer=setTimeout(()=>resolve(false),5000);})]);}finally{clearTimeout(timer);}
}
function requestBytes(plan,input,messages,tools,options){
 assert.deepEqual(tools,[]);assert.equal(messages.length,2);
 assert.equal(messages[0].role,'system');assert.equal(messages[1].role,'user');
 assert.equal(options.temperature,0);assert.equal(options.num_ctx,32768);
 assert.equal(options.num_predict,900);assert.equal(options.max_tokens,900);assert.equal(options.timeout,90000);
 const format=V8.format(plan,options.format);
 const suffix='\nOUTPUT JSON SCHEMA:\n'+JSON.stringify(options.format);
 assert(messages[0].content.endsWith(suffix),'exact canonical schema suffix required');
 const actual=[{role:'system',content:messages[0].content.slice(0,-suffix.length)+'\n'+input.instructionAddition
  +'\nOUTPUT JSON SCHEMA:\n'+JSON.stringify(format)}, {role:'user',content:messages[1].content}];
 assert(Buffer.byteLength(JSON.stringify(actual))+Buffer.byteLength(JSON.stringify(format))+900+1024<=32768,'diagnostic context exceeded');
 const body=Buffer.from(JSON.stringify({model:T.MODEL,messages:actual,format,
  options:{temperature:0,num_ctx:32768,num_predict:900},stream:true}));
 assert(body.length<=262144);return body;
}
async function execute({send,probe,record,signal,controlled=false}){
 assert.equal(typeof send,'function');assert.equal(typeof probe,'function');assert.equal(typeof record,'function');
 assert(record.constructor.name!=='AsyncFunction','synchronous durable recorder required');
 pins();const plan=V8.prepare(),sourcePins=sourceSnapshot(),account=createAccounting();
 const report={version:1,kind:'v21-v8-retained-diagnostic',controlled,diagnosticOnly:true,
  actorCalls:0,canonicalCredit:false,qualificationAccepted:false,productionPromotion:false,
  remoteCancellationProven:false,model:T.MODEL,modelDigest:T.DIGEST,sourcePins,
  protocol:V8.PROTOCOL,provenance:plan.provenance,calls:[],results:[],failure:null,
  physicalAttempts:0,reservations:0,localRetirementVerified:false,status:'pending',
  evaluationCompleted:false,calibrationPassed:false,matchedControls:[],pendingTransportDebt:false};
 const pending=new Set();let bytes=0,primary=null;
 const controller=new AbortController();const abort=()=>controller.abort(signal?.reason||Error('DIAGNOSTIC_ABORTED'));
 if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(Error('DIAGNOSTIC_WALL_DEADLINE')),210000);
 const save=()=>syncRecord(record,report);
 try{
  controller.signal.throwIfAborted();save();
  report.preModel=await probe('http://127.0.0.1:11434',10000);save();
  assert(report.preModel.identityMatched&&report.preModel.localSocketRetired,'model identity unavailable');
  for(let control=0;control<2;control++){
   controller.signal.throwIfAborted();const input=V8.modelInput(plan,control);let stage=null;
   const model={provider:'ollama',model:T.MODEL,chat(messages,tools,options){
    const operation=(async()=>{
     controller.signal.throwIfAborted();options.signal.throwIfAborted();
     assert(stage&&stage.attempt>=1&&stage.attempt<=2,'canonical criterion stage required');
     const criterion=E.RUBRIC.criteria.findIndex(c=>c.id===stage.criterionId);assert(criterion>=0);
     const body=requestBytes(plan,input,messages,tools,options),slot=account.reserve(control,criterion);
     assert.equal(slot.attempt,stage.attempt);stage=null;
     const row={...slot,originalMessages:structuredClone(messages),request:body.toString(),requestSha256:sha(body),
      physicalAttempt:false,status:null,termination:'intent',localSocketRetired:null,responseBase64:null,responseSha256:null};
     report.calls.push(row);report.reservations++;save();
     try{
      const result=await send({origin:'http://127.0.0.1:11434',method:'POST',pathname:'/api/chat',body,
       timeoutMs:90000,byteLimit:T.MAX_RESPONSE_BYTES,signal:AbortSignal.any([controller.signal,options.signal]),
       onPhysicalAttempt(){assert(!row.physicalAttempt&&report.physicalAttempts<16);row.physicalAttempt=true;report.physicalAttempts++;save();}});
      row.status=result.status;row.termination=result.termination;row.localSocketRetired=result.localSocketRetired;
      const retained=result.body.subarray(0,Math.max(0,MAX_RESPONSES-bytes));
      row.responseBase64=retained.toString('base64');row.responseSha256=sha(retained);row.observedResponseBytes=result.responseBytes;
      row.responseTruncated=retained.length!==result.body.length;row.observedBodySha256=sha(result.body);
      bytes+=retained.length;save();assert(!row.responseTruncated,'aggregate response limit');
      assert(row.physicalAttempt,'missing physical dispatch');
      const decoded=T.decodeChat(result);
      const frames=result.body.toString('utf8').trim().split('\n').map(line=>JSON.parse(line));
      const raw=frames.map(frame=>frame.message?.content||'').join('');
      row.rawExtendedReply=raw;row.rawExtendedReplySha256=sha(raw);save();
      const projection=V8.project(plan,control,criterion,raw,options.format);
      row.diagnosticProjection=projection;save();
      const terminal=frames.at(-1);
      return {provider:'ollama',model:T.MODEL,response:V8.projectedReply(projection),mocked:false,fallback:false,
       metadata:{eval_count:terminal.eval_count}};
     }catch(error){row.failure={name:error.name,code:error.code||null};
      if(Buffer.isBuffer(error.body)){const retained=error.body.subarray(0,Math.max(0,MAX_RESPONSES-bytes));
       row.responseBase64=retained.toString('base64');row.responseSha256=sha(retained);bytes+=retained.length;
       row.responseTruncated=retained.length!==error.body.length;row.observedBodySha256=sha(error.body);}
      if(typeof error.localSocketRetired==='boolean')row.localSocketRetired=error.localSocketRetired;
      if(error.termination)row.termination=error.termination;save();throw error;}
    })();pending.add(operation);operation.then(()=>pending.delete(operation),()=>pending.delete(operation));return operation;
   }};
   const judge=createObjectiveJudge({model,timeoutMs:90000,contextTokens:32768});
   const result=await judge({...input.original,execution:{signal:controller.signal,
    emit(event){if(event.node==='judge_scoped_model'&&event.type==='start')stage=event.data;}}});
   // Canonical Judge can return after an abort race; join the actual owned
   // transport before the next control or terminal publication.
   if(!await joinPending(pending)){report.pendingTransportDebt=true;throw Error('TRANSPORT_JOIN_DEADLINE');}
   report.results.push(result);save();
   assert(!['unavailable','inconclusive'].includes(result.verdict)&&!result.errorCode,'diagnostic Judge unavailable');
  }
 }catch(error){primary=error;report.failure={name:error.name,code:error.code||null};}
 finally{
  controller.abort(Error('DIAGNOSTIC_FINISHED'));clearTimeout(timer);signal?.removeEventListener('abort',abort);
  if(!report.pendingTransportDebt&&!await joinPending(pending))report.pendingTransportDebt=true;
  report.localRetirementVerified=!report.pendingTransportDebt&&report.calls.every(c=>!c.physicalAttempt||c.localSocketRetired===true);
  if(!report.localRetirementVerified)report.failure ||= {code:'LOCAL_RETIREMENT_UNVERIFIED'};
  try{report.postModel=await probe('http://127.0.0.1:11434',10000);
   assert(report.postModel.identityMatched&&report.postModel.localSocketRetired);pins();assert.deepEqual(sourceSnapshot(),sourcePins);
  }catch{report.failure ||= {code:'POSTFLIGHT_UNVERIFIED'};}
  report.evaluationCompleted=!report.failure&&report.results.length===2;
  report.matchedControls=report.results.map((r,i)=>({control:i,matched:r.verdict===(i===0?'pass':'fail')
   &&r.criteria.length===4&&r.criteria.every(c=>c.satisfied===(i===0))}));
  report.calibrationPassed=report.evaluationCompleted&&report.matchedControls.every(c=>c.matched);
  report.status=report.failure?'diagnostic-failed':report.calibrationPassed?'calibration-matched':'calibration-mismatched';save();
 }
 return {report,primary};
}
function privateRecorder(output){
 assert.equal(path.basename(output),NAME);const run=path.dirname(output),base=path.join(ROOT,'tasks/qualification');
 assert.equal(path.dirname(run),base);assert.match(path.basename(run),/^run-[A-Za-z0-9_-]+$/);
 for(const dir of [ROOT,path.join(ROOT,'tasks'),base,run]){const s=fs.lstatSync(dir);
  assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&fs.realpathSync(dir)===dir);}
 assert.equal(fs.statSync(run).mode&0o777,0o700);
 let fd=fs.openSync(output,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 const directorySync=()=>{const d=fs.openSync(run,fs.constants.O_RDONLY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}};
 fs.writeSync(fd,'{"status":"allocated","qualificationAccepted":false}\n',0,'utf8');fs.fsyncSync(fd);
 try{directorySync();}catch(error){fs.closeSync(fd);throw error;}let owned=fs.fstatSync(fd),sequence=0;
 return {record(report){const data=Buffer.from(JSON.stringify(report)+'\n');assert(data.length<=MAX_REPORT,'report limit');
  const current=fs.lstatSync(output);assert(current.isFile()&&!current.isSymbolicLink()&&current.ino===owned.ino&&current.dev===owned.dev,'owned checkpoint changed');
  const temporary=output+'.checkpoint-'+(++sequence);let next;
  try{next=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
   let at=0;while(at<data.length)at+=fs.writeSync(next,data,at,data.length-at,at);fs.fsyncSync(next);
   const same=fs.lstatSync(output);assert(same.ino===owned.ino&&same.dev===owned.dev&&!same.isSymbolicLink());
   fs.renameSync(temporary,output);fs.closeSync(fd);fd=next;next=undefined;owned=fs.fstatSync(fd);directorySync();
  }finally{if(next!==undefined)fs.closeSync(next);}
 },close(){fs.closeSync(fd);}};
}
async function main(argv=process.argv.slice(2)){
 pins();const prepared=V8.prepare();const plan={liveEnabled:LIVE_ENABLED,protocol:V8.PROTOCOL,model:T.MODEL,
  modelDigest:T.DIGEST,sourcePins:sourceSnapshot(),inputPacketHashes:prepared.inputs.map(x=>sha(JSON.stringify(x))),
  maxReportBytes:MAX_REPORT,maxAggregateResponseBytes:MAX_RESPONSES,workDeadlineMs:210000,
  localSettlementMs:5000,postModelTimeoutMs:10000,remoteCancellationProven:false};
 if(argv.length===0||argv.length===1&&argv[0]==='--plan')return {...plan,planSha256:sha(JSON.stringify(plan))};
 assert(argv.length===5&&argv[0]==='--run'&&argv[1]==='--expected-plan'&&argv[3]==='--output','exact CLI required');
 assert.equal(argv[2],sha(JSON.stringify(plan)),'reviewed current plan required');
 assert(LIVE_ENABLED,'live diagnostic admission is closed');
 const writer=privateRecorder(argv[4]),controller=new AbortController();
 const interrupted=()=>controller.abort(Error('DIAGNOSTIC_INTERRUPTED'));
 process.on('SIGINT',interrupted);process.on('SIGTERM',interrupted);
 try{const {report}=await execute({send:T.singlePost,probe:metadata.checkModel,record:writer.record,signal:controller.signal});
  if(report.status!=='calibration-matched')process.exitCode=1;
  return {output:argv[4],status:report.status,physicalAttempts:report.physicalAttempts,
   localRetirementVerified:report.localRetirementVerified,qualificationAccepted:false};}
 finally{writer.close();process.removeListener('SIGINT',interrupted);process.removeListener('SIGTERM',interrupted);}
}
// Injection is explicitly controlled-only. No exported path defaults to live.
function runControlled(options){return execute({...options,controlled:true});}
if(require.main===module)main().then(x=>process.stdout.write(JSON.stringify(x)+'\n')).catch(()=>{process.exitCode=1;});
module.exports={main,runControlled,requestBytes,privateRecorder,NAME,LIVE_ENABLED};
