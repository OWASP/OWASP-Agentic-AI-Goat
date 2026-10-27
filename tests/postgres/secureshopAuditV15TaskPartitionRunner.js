'use strict';
// Explicit opt-in retained-evidence diagnostic; default/import never dispatches.
// Exact reviewed plan and private output required; never publishes canonical judgments.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const H=require('../fixtures/secureshopAuditV15TaskPartitionDiagnostic');
const T=require('./secureshopMcpDescriptionAtomicRetainedDiagnostic');
const metadata=require('./secureshopAuditRetainedTransportDiagnostic');
const closure=require('../fixtures/studentDeletionSourceClosure');
const ROOT=path.resolve(__dirname,'../..'),LIVE_ENABLED=true,NAME='v15-task-partition.ndjson';
const LIMITS=Object.freeze({physical:4,perCase:2,caseMs:90000,workMs:210000,joinMs:5000,responseBytes:8*1024*1024});
const sha=x=>createHash('sha256').update(x).digest('hex');
function snapshot(){
 // As in the reviewed V9 runner, parse the fixed executable dependency roots,
 // then retain the collector/parser and runner themselves from loaded modules.
 // The collector's deliberately dynamic parser import is not an application edge.
 const files=closure.collect(ROOT,['tests/fixtures/secureshopAuditV15TaskPartitionDiagnostic.js',
  'tests/postgres/secureshopMcpDescriptionAtomicRetainedDiagnostic.js',
  'tests/postgres/secureshopAuditRetainedTransportDiagnostic.js']),out={};
 const loaded=Object.keys(require.cache).map(file=>{assert(file.startsWith(ROOT+path.sep));return path.relative(ROOT,file);});
 for(const name of [...new Set([...files,...loaded,path.relative(ROOT,__filename)])].sort()){
  const file=path.join(ROOT,name),s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&fs.realpathSync(file)===file);out[name]=sha(fs.readFileSync(file));
 }return out;
}
function plan(schemaPresentation='original-v1'){const pair=H.preparePair(schemaPresentation);return {version:1,kind:H.VERSION,
 schemaPresentation:pair.schemaPresentation,grammarEnforcementProven:false,model:T.MODEL,modelDigest:T.DIGEST,
 limits:LIMITS,sourcePins:snapshot(),inputs:pair.cases.map(c=>c.provenance),diagnosticOnly:true,qualificationAccepted:false};}
function bounded(promise,ms){let timer;return Promise.race([Promise.resolve(promise),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('DIAGNOSTIC_JOIN_TIMEOUT')),ms);})]).finally(()=>clearTimeout(timer));}
function abortRace(promise,signal){return new Promise((resolve,reject)=>{
 const abort=()=>reject(signal.reason||Error('DIAGNOSTIC_ABORTED'));
 if(signal.aborted){Promise.resolve(promise).catch(()=>{});return abort();}
 signal.addEventListener('abort',abort,{once:true});Promise.resolve(promise).then(resolve,reject).finally(()=>signal.removeEventListener('abort',abort));
});}
async function execute({send,probe,record,signal,controlled,schemaPresentation='original-v1'}){
 assert.equal(typeof send,'function');assert.equal(typeof probe,'function');assert.equal(typeof record,'function');
 assert.notEqual(record.constructor.name,'AsyncFunction');
 const admitted=plan(schemaPresentation),pair=H.preparePair(schemaPresentation),pending=new Set(),controller=new AbortController();
 const report={version:1,kind:H.VERSION,schemaPresentation,grammarEnforcementProven:false,controlled,diagnosticOnly:true,actorCalls:0,canonicalCredit:false,
 qualificationAccepted:false,productionPromotion:false,remoteCancellationProven:false,admission:admitted,planSha256:sha(JSON.stringify(admitted)),
 calls:[],results:[],physicalAttempts:0,failure:null,pendingTransportDebt:false};
 let sealed=false,bytes=0;
 const save=()=>{assert(!sealed);const value=record(structuredClone(report));assert(!value||typeof value.then!=='function','synchronous recorder required');};
 const track=p=>{pending.add(p);p.then(()=>pending.delete(p),()=>pending.delete(p));return p;};
 const abort=()=>controller.abort(signal?.reason||Error('DIAGNOSTIC_ABORTED'));
 if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(Error('DIAGNOSTIC_WORK_TIMEOUT')),LIMITS.workMs);
 try{
  controller.signal.throwIfAborted();save();
  report.preModel=await abortRace(track(probe('http://127.0.0.1:11434',10000)),controller.signal);
  assert(report.preModel.identityMatched&&report.preModel.localSocketRetired);save();
  for(let control=0;control<2;control++){
   const local=new AbortController(),end=performance.now()+LIMITS.caseMs;
   const caseTimer=setTimeout(()=>local.abort(Error('DIAGNOSTIC_CASE_TIMEOUT')),LIMITS.caseMs);
   const combined=AbortSignal.any([controller.signal,local.signal]);let previous=null;
   try{for(let attempt=1;attempt<=LIMITS.perCase;attempt++){
    combined.throwIfAborted();assert(performance.now()<end);
    const request=pair.cases[control].request();
    if(previous){
     // The neutral ablation must not feed model-invented claim/role metadata
     // back through an invalid previous reply. Raw failures stay in the journal.
     if(schemaPresentation!=='evidence-only-v3')request.messages.push({role:'assistant',content:previous});
     request.messages.push({role:'user',content:'The prior diagnostic reply failed structural or exact evidence validation. Return the same strict schema using only the supplied evidence. Do not infer a desired verdict.'});
    }
    const body=Buffer.from(JSON.stringify({model:T.MODEL,messages:request.messages,format:request.format,
     options:{temperature:0,num_ctx:32768,num_predict:1800},stream:true}));assert(body.length<=262144);
    const row={control,attempt,request:body.toString(),requestSha256:sha(body),physicalAttempt:false,localSocketRetired:null};
    report.calls.push(row);save();let result;
    const retainBody=body=>{const retained=body.subarray(0,Math.max(0,LIMITS.responseBytes-bytes));bytes+=retained.length;
     row.responseBase64=retained.toString('base64');row.responseSha256=sha(retained);row.truncated=retained.length!==body.length;};
    // The transport may retire after the case abort wins. Join and retain its
    // failed/partial wire, but never validate a late answer or mutate a sealed report.
    const received=value=>{if(!sealed){row.status=value.status;row.termination=value.termination;row.localSocketRetired=value.localSocketRetired;
     assert(Buffer.isBuffer(value.body));retainBody(value.body);save();}return value;};
    const failed=error=>{if(!sealed){if(Buffer.isBuffer(error.body))retainBody(error.body);
     row.localSocketRetired=error.localSocketRetired===true;row.failure=error.code||error.name;save();}throw error;};
    try{
     result=await abortRace(track(Promise.resolve().then(()=>{combined.throwIfAborted();return send({origin:'http://127.0.0.1:11434',method:'POST',pathname:'/api/chat',body,
      timeoutMs:Math.max(1,Math.floor(end-performance.now())),byteLimit:T.MAX_RESPONSE_BYTES,signal:combined,
      onPhysicalAttempt(){combined.throwIfAborted();assert(!sealed&&!row.physicalAttempt&&report.physicalAttempts<LIMITS.physical);row.physicalAttempt=true;report.physicalAttempts++;save();}});}).then(received,failed)),combined);
    }catch(error){row.failure||=error.code||error.name;save();throw error;}
    combined.throwIfAborted();assert(!row.truncated&&row.physicalAttempt);assert.equal(result.status,200);assert.equal(result.termination,'complete');assert.equal(result.localSocketRetired,true);
    // Raw wire is durable before either decoder or typed validation executes.
    let value,validationError;
    try{
     let supplied;
     if(schemaPresentation==='evidence-only-v3'){
      supplied=new TextDecoder('utf-8',{fatal:true}).decode(result.body).trim().split('\n').map(line=>JSON.parse(line).message?.content||'').join('');
      assert(Buffer.byteLength(supplied)<=65536);
      row.rawReply=supplied;row.rawReplySha256=sha(supplied);save();
     }
     const decoded=T.decodeChat(result),raw=JSON.stringify(decoded);row.normalizedReply=raw;row.normalizedReplySha256=sha(raw);
     if(schemaPresentation==='evidence-only-v3'){
      row.projection=pair.cases[control].project(supplied);save();
     }else supplied=raw;
     value=pair.cases[control].validate(supplied);
    }catch(error){validationError=error;}
    save();
    if(!validationError){row.validated=value;report.results.push({control,observed:value.typed.supportStatus});save();break;}
    {const error=validationError;row.validationFailure=error.code||error.name;save();if(attempt===LIMITS.perCase)throw error;
     previous=new TextDecoder('utf-8',{fatal:true}).decode(result.body).trim().split('\n').map(line=>JSON.parse(line).message?.content||'').join('');
     assert(Buffer.byteLength(previous)<=65536);
    }
   }}finally{clearTimeout(caseTimer);}
  }
 }catch(error){report.failure={name:error.name,code:error.code||null,message:String(error.message).slice(0,160)};}
 finally{
  try{
  controller.abort(Error('DIAGNOSTIC_FINISHED'));clearTimeout(timer);signal?.removeEventListener('abort',abort);
  try{await bounded(Promise.allSettled([...pending]),LIMITS.joinMs);}catch{report.pendingTransportDebt=true;}
  report.localRetirementVerified=report.preModel?.localSocketRetired===true&&!report.pendingTransportDebt&&report.calls.every(c=>!c.physicalAttempt||c.localSocketRetired===true);
  if(!report.localRetirementVerified)report.failure||={code:'LOCAL_RETIREMENT_UNVERIFIED'};
  let postflightSettled=false;
  try{const postflight=Promise.resolve().then(()=>probe('http://127.0.0.1:11434',10000));
   postflight.then(()=>{postflightSettled=true;},()=>{postflightSettled=true;});
   report.postModel=await bounded(postflight,15000);assert(report.postModel.identityMatched&&report.postModel.localSocketRetired);assert.deepEqual(snapshot(),admitted.sourcePins);
  }catch{report.failure||={code:'POSTFLIGHT_UNVERIFIED'};}
  report.postflightTransportDebt=!postflightSettled;
  if(report.postflightTransportDebt||report.postModel?.localSocketRetired!==true)report.localRetirementVerified=false;
  report.evaluationCompleted=!report.failure&&report.results.length===2;
  report.matchedControls=report.results.map(r=>({...r,expected:r.control===0?'supported':'not_supported',matched:r.observed===(r.control===0?'supported':'not_supported')}));
  report.calibrationPassed=report.evaluationCompleted&&report.matchedControls.every(r=>r.matched);
  report.status=report.failure?'diagnostic-failed':report.calibrationPassed?'calibration-matched':'calibration-mismatched';save();
  }finally{sealed=true;}
 }return report;
}
function journal(output){
 const run=path.dirname(output),base=path.join(ROOT,'tasks/qualification');assert.equal(path.basename(output),NAME);assert.equal(path.dirname(run),base);assert.match(path.basename(run),/^run-[A-Za-z0-9_-]+$/);
 for(const p of [ROOT,path.join(ROOT,'tasks'),base,run]){const s=fs.lstatSync(p);assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&fs.realpathSync(p)===p);}assert.equal(fs.statSync(run).mode&0o777,0o700);
 const fd=fs.openSync(output,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);let total=0;
 const identity=fs.fstatSync(fd);
 try{const d=fs.openSync(run,'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}catch(error){fs.closeSync(fd);throw error;}
 return {record(value){const current=fs.lstatSync(output);assert(current.isFile()&&!current.isSymbolicLink()&&current.dev===identity.dev&&current.ino===identity.ino&&current.nlink===1&&current.uid===identity.uid&&(current.mode&0o777)===0o600);
  const b=Buffer.from(JSON.stringify(value)+'\n');assert(b.length<=16*1024*1024&&total+b.length<=256*1024*1024);let at=0;while(at<b.length){const written=fs.writeSync(fd,b,at,b.length-at);assert(written>0);at+=written;}fs.fsyncSync(fd);total+=b.length;},close(){fs.closeSync(fd);}};
}
async function main(argv=process.argv.slice(2)){
 const args=[...argv];let schemaPresentation='original-v1';
 if(args.length>=2&&args.at(-2)==='--schema-presentation'){
  schemaPresentation=args.pop();args.pop();assert(H.SCHEMA_PRESENTATIONS.includes(schemaPresentation),'Unknown schema presentation');
 }
 const value=plan(schemaPresentation),planSha256=sha(JSON.stringify(value));if(!args.length||(args.length===1&&args[0]==='--plan'))return {...value,planSha256,liveEnabled:LIVE_ENABLED};
 assert(LIVE_ENABLED,'V15_TASK_PARTITION_LIVE_DISABLED');assert.equal(args.length,5);assert.equal(args[0],'--run');assert.equal(args[1],'--plan-sha256');assert.equal(args[2],planSha256);assert.equal(args[3],'--output');
 const writer=journal(args[4]),controller=new AbortController(),abort=()=>controller.abort(Error('INTERRUPTED'));
 process.on('SIGINT',abort);process.on('SIGTERM',abort);try{const result=await execute({send:T.singlePost,probe:metadata.checkModel,record:writer.record,signal:controller.signal,controlled:false,schemaPresentation});
  result.evidencePath=args[4];return result;
 }finally{writer.close();process.removeListener('SIGINT',abort);process.removeListener('SIGTERM',abort);}
}
function publicSummary(value){
 const status=value.status===undefined?'diagnostic-plan':value.status;
 assert(['diagnostic-plan','diagnostic-failed','calibration-matched','calibration-mismatched'].includes(status));
 assert.match(value.planSha256,/^[a-f0-9]{64}$/);
 const evidencePath=value.evidencePath??null;
 if(evidencePath!==null){assert(typeof evidencePath==='string'&&evidencePath.length<=4096);
  assert.equal(path.dirname(path.dirname(evidencePath)),path.join(ROOT,'tasks/qualification'));assert.equal(path.basename(evidencePath),NAME);
  assert.match(path.basename(path.dirname(evidencePath)),/^run-[A-Za-z0-9_-]+$/);}
 return {status,liveEnabled:LIVE_ENABLED,planSha256:value.planSha256,resultSha256:sha(JSON.stringify(value)),evidencePath};
}
async function cli(argv=process.argv.slice(2)){
 try{return publicSummary(await main(argv));}catch{return {status:'diagnostic-failed',liveEnabled:LIVE_ENABLED,planSha256:null,resultSha256:null,evidencePath:null};}
}
module.exports={main,plan,journal,cli,publicSummary,LIMITS,NAME,LIVE_ENABLED,runControlled:options=>execute({...options,controlled:true})};
if(require.main===module)cli().then(value=>{process.stdout.write(JSON.stringify(value)+'\n');if(!['diagnostic-plan','calibration-matched'].includes(value.status))process.exitCode=1;});
