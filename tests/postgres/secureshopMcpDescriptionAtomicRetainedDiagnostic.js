'use strict';
// Diagnostic replay of one retained original V39 source. No actor, database,
// canonical Judge publication, objective credit, or automatic retry.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const {createHash}=require('node:crypto');
const D=require('../fixtures/secureshopMcpDescriptionAtomicDiagnostic');
const transport=require('./secureshopAuditRetainedTransportDiagnostic');
const ROOT=path.resolve(__dirname,'../..');
const ORIGINAL='tasks/qualification/dvaia-mcp-assembly-iw6u2bic';
const INPUTS=Object.freeze({
 'mcp-description-qualification.json':'904b7629f4c36cd53bea6dc2d434f7997b759115d65da3cc36f17e0e1e0aeab5',
 'mcp-description-wire.json':'d10b81c2a3c848e25c7c4d72a1cf0efe320af153718705ac18f244a3bbef0d8c',
 'mcp-description-model.json':'bda973665691b4fcfc512fa559fcad3652cbce520f4e47d547ea563bfdd4949e',
});
const SOURCES=Object.freeze({
 'tests/fixtures/secureshopMcpDescriptionAtomicDiagnostic.js':'fb4a7547109ce6d771a21726f6128c181b32f2652495af6372f02bf560a49dbb',
 'tests/postgres/secureshopAuditRetainedTransportDiagnostic.js':'67cc1348a6469e1edab42c79adc1b79046aec296d9422dd4791f8760a40bddcb',
 'server/agent-runtime/mcpDescriptionRangeRelationsV6.js':'009b2bf2ec98556edced88199995bcc27252424e66144035a8246d6f2ba3a85a',
 'server/services/secureshopMcpDescriptionEvidence.js':'c861668a8da61e2b51606765b40296352a7a19f1038f8d2ae89a81fbf3134d4e',
 'server/services/secureshopModelQualification.js':'3cc8b9067fb992cc6b534c451fb541acac64378c859d7758e77164787c60fc77',
 'server/services/secureshop/providers/ollamaProvider.js':'26344bea17155a3bf572ce8fdd0b1ad67796efc4af9a8012dabd0acbf2e35ed0',
 'server/agent-runtime/objectiveJudge.js':'186b7169cbc7161bca4a4c64f88790b3a40da3e512a7c1c9331a3928c1ed46a1',
});
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const NAME='v39-atomic-retained-diagnostic.json',JOURNAL='v39-atomic-retained-attempt.jsonl';
const PER_CALL_MS=90000,MAX_WALL_MS=12*PER_CALL_MS+30000,MAX_RESPONSE_BYTES=8*1024*1024;
const sha=value=>createHash('sha256').update(value).digest('hex');
const safeValidationCode=error=>error?.validationCode==='MCP_DESCRIPTION_CAUSAL_FINDING_CONTRADICTION'
 ? error.validationCode:null;
function privateBytes(relative,expected){
 const file=path.join(ROOT,relative),stat=fs.lstatSync(file);
 assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&stat.size>0&&stat.size<=32*1024*1024);
 const bytes=fs.readFileSync(file);assert.equal(sha(bytes),expected,relative);return bytes;
}
function sourcePins(){
 for(const [relative,expected]of Object.entries(SOURCES))privateBytes(relative,expected);
 const own={};for(const relative of ['tests/postgres/secureshopMcpDescriptionAtomicRetainedDiagnostic.js',
  'tests/postgres/secureshopMcpDescriptionAtomicRetainedDiagnostic.test.js']){
  const file=path.join(ROOT,relative),stat=fs.lstatSync(file);
  assert(stat.isFile()&&!stat.isSymbolicLink());own[relative]=sha(fs.readFileSync(file));
 }
 return {...SOURCES,...own};
}
function admitOriginal(){
 const source=JSON.parse(privateBytes(`${ORIGINAL}/mcp-description-qualification.json`,INPUTS['mcp-description-qualification.json']));
 const wire=JSON.parse(privateBytes(`${ORIGINAL}/mcp-description-wire.json`,INPUTS['mcp-description-wire.json']));
 privateBytes(`${ORIGINAL}/mcp-description-model.json`,INPUTS['mcp-description-model.json']);
 assert.equal(wire.modelDigest,DIGEST);assert.equal(wire.calls.length,10);
 assert.deepEqual(wire.calls.map(x=>x.kind),[...Array(6).fill('actor'),...Array(4).fill('judge')]);
 for(const call of wire.calls){assert.equal(call.status,200);assert.equal(call.responseComplete,true);
  assert.equal(sha(call.request),call.requestSha256);assert.equal(sha(call.response),call.responseSha256);}
 assert.deepEqual(Object.keys(source.original).sort(),['binding','effects','publications','run','sourceBinding','stored','traces','turn']);
 const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
 const {createSecureShopModelQualifier}=require('../../server/services/secureshopModelQualification');
 const provider=new OllamaProvider({baseUrl:'http://127.0.0.1:11434',model:MODEL});
 const plan=D.prepareOriginal({source:source.original,qualifyModelTrace:createSecureShopModelQualifier(provider)});
 assert.equal(plan.provenance,'validated-original-source');assert.equal(plan.maxJudgeCalls,12);
 return {plan,inputs:INPUTS,pins:sourcePins(),originalSourceSha256:sha(JSON.stringify(source.original))};
}
function stageRequest(stage,schema,instructions,input){
 assert.match(stage,/^(prefix|titles|preference)\.(source_witness|task_relation|result_relation|final_judgment)$/);
 const format=require('zod-to-json-schema').zodToJsonSchema(schema,{$refStrategy:'none'});
 const inputText=JSON.stringify(input),formatText=JSON.stringify(format);
 assert(Buffer.byteLength(instructions)+Buffer.byteLength(formatText)+Buffer.byteLength(inputText)+900+1024<=32768,
  'Original Judge context guard exceeded before dispatch');
 const messages=[{role:'system',content:`${instructions}\nOUTPUT JSON SCHEMA:\n${formatText}`},
  {role:'user',content:inputText}];
 const bytes=Buffer.from(JSON.stringify({model:MODEL,format,options:{temperature:0,num_ctx:32768,num_predict:900},messages,stream:true}));
 assert(bytes.length>0&&bytes.length<=262144);
 return bytes;
}
function decodeChat(result){
 assert.equal(result.status,200);assert.equal(result.termination,'complete');assert.equal(result.localSocketRetired,true);
 assert(Buffer.isBuffer(result.body)&&result.body.length>0&&result.body.length<=MAX_RESPONSE_BYTES);
 const text=new TextDecoder('utf-8',{fatal:true}).decode(result.body);
 assert(text.endsWith('\n'),'Terminal newline required');
 const lines=text.trimEnd().split('\n');
 assert(lines.length>0&&lines.length<=4096&&lines.every(line=>Buffer.byteLength(line)<=1024*1024));
 const frames=lines.map(line=>JSON.parse(line));assert(frames.every(frame=>frame.model===MODEL));
 assert(frames.every(frame=>!Object.hasOwn(frame,'error')),'Provider error frame forbidden');
 assert(frames.slice(0,-1).every(frame=>frame.done===false),'Early terminal frame forbidden');
 const terminal=frames.at(-1);assert.equal(terminal.done,true);assert.equal(terminal.done_reason,'stop');
 assert(frames.every(frame=>frame.message===undefined||typeof frame.message?.content==='string'));
 const answer=frames.map(frame=>frame.message?.content||'').join('');
 assert(Buffer.byteLength(answer)>0&&Buffer.byteLength(answer)<=65536);
 return JSON.parse(answer);
}
function singlePost({origin,method,pathname,body,timeoutMs,byteLimit,signal,onPhysicalAttempt}){
 const url=new URL(origin);
 assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');
 assert.equal(url.pathname,'/');assert.equal(url.username,'');assert.equal(url.password,'');assert.equal(url.port,'11434');
 assert.equal(method,'POST');assert.equal(pathname,'/api/chat');
 assert(Buffer.isBuffer(body)&&body.length>0&&body.length<=262144);
 assert(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=PER_CALL_MS);
 assert.equal(byteLimit,MAX_RESPONSE_BYTES);
 return new Promise((resolve,reject)=>{
  if(signal?.aborted){resolve({status:null,termination:'aborted',body:Buffer.alloc(0),responseBytes:0,
   socketAssigned:false,localSocketRetired:true});return;}
  let status=null,settled=false,responseBytes=0,retainedBytes=0,chunkCount=0,requestClosed=false,socketAssigned=false,socketClosed=false;
  let retirementCheck=null;const parts=[];
  const request=http.request({hostname:'127.0.0.1',port:Number(url.port||11434),method:'POST',path:'/api/chat',agent:false,
   headers:{'content-type':'application/json','content-length':body.length}});
  request.once('socket',socket=>{socketAssigned=true;socketClosed=socket.destroyed;
   socket.once('close',()=>{socketClosed=true;retirementCheck?.();});});
  request.once('close',()=>{requestClosed=true;retirementCheck?.();});
  const finish=(termination,complete=false,primary=null)=>{
   if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',onAbort);
   if(!complete)request.destroy();
   new Promise(done=>{const timeout=setTimeout(()=>done(false),5000);
    retirementCheck=()=>{if(requestClosed&&(!socketAssigned||socketClosed)){clearTimeout(timeout);done(true);}};
    retirementCheck();}).then(localSocketRetired=>{
     if(primary){primary.localSocketRetired=localSocketRetired;primary.termination=termination;reject(primary);return;}
     resolve({status,termination,body:Buffer.concat(parts),responseBytes,socketAssigned,localSocketRetired});
    });
  };
  const onAbort=()=>finish('aborted');
  const timer=setTimeout(()=>finish('deadline'),timeoutMs);
  signal?.addEventListener('abort',onAbort,{once:true});
  request.once('response',response=>{status=response.statusCode;
   response.on('data',chunk=>{if(settled)return;responseBytes+=chunk.length;chunkCount++;
    const remaining=byteLimit-retainedBytes;
    if(remaining>0){const copy=Buffer.from(chunk.subarray(0,remaining));parts.push(copy);retainedBytes+=copy.length;}
    if(responseBytes>byteLimit||chunkCount>16384)finish('response_limit');});
   response.once('end',()=>finish(response.complete?'complete':'incomplete',response.complete));
   response.once('aborted',()=>finish('response_aborted'));
   response.once('error',()=>finish('response_error'));
   response.once('close',()=>{if(!response.complete)finish('response_closed');});
  });
  request.once('error',()=>finish('request_error'));
  // http.request has already constructed the transport here; this records a
  // dispatch attempt, never a claim that the server received the POST.
  try{onPhysicalAttempt?.();}catch(error){finish('record_error',false,error);return;}
  if(signal?.aborted)onAbort();else try{request.end(body);}catch(error){finish('dispatch_error',false,error);}
 });
}
function createInvoker({send,record,signal}){
 assert.equal(typeof send,'function');assert.equal(typeof record,'function');
 const seen=new Set(),state={reservations:0,physicalAttempts:0};
 async function invoke(stage,schema,instructions,input){
  assert(state.reservations<D.MAX_JUDGE_CALLS,'Twelve physical Judge POST cap');
  assert(!seen.has(stage),'No automatic Judge retry or duplicate stage');
  if(signal?.aborted)throw signal.reason||Error('DIAGNOSTIC_WALL_DEADLINE');
  const body=stageRequest(stage,schema,instructions,input);
  seen.add(stage);state.reservations++;
  const row={index:state.reservations,stage,request:body.toString(),requestSha256:sha(body),requestBytes:body.length,
   physicalAttempt:false,
   responseBase64:null,responseSha256:null,responseBytes:0,status:null,termination:'pending',localSocketRetired:null};
  record(row);
  try{
   const result=await send({origin:'http://127.0.0.1:11434',method:'POST',pathname:'/api/chat',body,
    timeoutMs:PER_CALL_MS,byteLimit:MAX_RESPONSE_BYTES,signal,onPhysicalAttempt:()=>{
     assert.equal(row.physicalAttempt,false,'One physical request per stage');
     assert(state.physicalAttempts<D.MAX_JUDGE_CALLS,'Physical request budget');
     state.physicalAttempts++;row.physicalAttempt=true;record(row);
    }});
   row.status=result.status;row.termination=result.termination;row.localSocketRetired=result.localSocketRetired;
   row.responseBytes=result.responseBytes;
   row.responseBase64=result.body?.toString('base64')??null;
   row.responseSha256=result.body?sha(result.body):null;
   record(row);
   return decodeChat(result);
  }catch(error){if(typeof error.localSocketRetired==='boolean')row.localSocketRetired=error.localSocketRetired;
   if(typeof error.termination==='string')row.termination=error.termination;
   row.failure={name:error.name||'Error',code:/^[A-Z_]{1,48}$/.test(error.code||'')?error.code:null,
    validationCode:safeValidationCode(error)};record(row);throw error;}
 }
 return {invoke,state};
}
function admittedOutput(file){
 assert.equal(path.basename(file),NAME);const root=path.join(ROOT,'tasks/qualification');
 const run=path.dirname(file);assert.equal(path.dirname(run),root);assert.match(path.basename(run),/^run-[A-Za-z0-9_-]+$/);
 for(const directory of [ROOT,path.join(ROOT,'tasks'),root,run]){
  const stat=fs.lstatSync(directory);assert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid());
  assert.equal(fs.realpathSync.native(directory),directory);
 }
 const stat=fs.lstatSync(run);assert.equal(stat.mode&0o777,0o700);return file;
}
async function runDiagnostic({admitted=admitOriginal(),probe=transport.checkModel,send=singlePost,
 deadlineMs=MAX_WALL_MS,record=()=>{}}={}){
 assert(Number.isSafeInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=MAX_WALL_MS);
 const started=performance.now(),report={version:1,kind:'v39-atomic-retained-diagnostic',diagnosticOnly:true,
  actorCalls:0,canonicalJudgeCalls:0,canonicalCredit:false,qualificationAccepted:false,
  model:MODEL,modelDigest:DIGEST,inputs:admitted.inputs,sourcePins:admitted.pins,
  originalSourceSha256:admitted.originalSourceSha256,evidenceSha256:admitted.plan.evidenceSha256,
  maxPhysicalJudgePosts:12,reservedJudgeSlots:0,physicalJudgePosts:0,perCallTimeoutMs:PER_CALL_MS,
  remoteModelCancellationProven:false,preModel:null,postModel:null,calls:[],result:null,failure:null};
 let primary=null,controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('DIAGNOSTIC_WALL_DEADLINE')),deadlineMs);
 const recorder=row=>{report.calls[row.index-1]=structuredClone(row);
  report.reservedJudgeSlots=Math.max(report.reservedJudgeSlots,row.index);
  report.physicalJudgePosts=report.calls.filter(call=>call.physicalAttempt).length;record(report);};
 try{
  report.preModel=await probe('http://127.0.0.1:11434',10000);record(report);
  assert(report.preModel.identityMatched&&report.preModel.localSocketRetired);
  const invoker=createInvoker({send,record:recorder,signal:controller.signal});
  report.result=await D.evaluate({plan:admitted.plan,invoke:invoker.invoke});
  assert.equal(invoker.state.reservations,12);assert.equal(invoker.state.physicalAttempts,12);
 }catch(error){primary=error;report.failure={phase:'judge',name:error.name||'Error',
  code:/^[A-Z_]{1,48}$/.test(error.code||'')?error.code:null,
  validationCode:safeValidationCode(error)};record(report);
 }finally{
  clearTimeout(timer);
  try{report.postModel=await probe('http://127.0.0.1:11434',10000);}
  catch(error){report.postModelFailure={name:error.name||'Error',code:/^[A-Z_]{1,48}$/.test(error.code||'')?error.code:null};}
  if(!report.postModel?.identityMatched||!report.postModel?.localSocketRetired)report.failure ||= {phase:'post_model',name:'Error',code:'MODEL_IDENTITY_UNVERIFIED'};
  try{if(Object.entries(admitted.pins).some(([relative,digest])=>sha(fs.readFileSync(path.join(ROOT,relative)))!==digest))
   report.failure ||= {phase:'post_source',name:'Error',code:'SOURCE_CHANGED'};}
  catch{report.failure ||= {phase:'post_source',name:'Error',code:'SOURCE_UNREADABLE'};}
  report.status=report.failure?'diagnostic-failed':'diagnostic-complete';record(report);
 }
 return {report,primary};
}
async function main(argv=process.argv.slice(2)){
 assert(argv.length===0||argv[0]==='--plan'||argv[0]==='--run');
 const admitted=admitOriginal();
 const plan={kind:'v39-atomic-retained-diagnostic',nativeStarted:false,diagnosticOnly:true,
  inputPins:admitted.inputs,sourcePins:admitted.pins,evidenceSha256:admitted.plan.evidenceSha256,
  model:MODEL,modelDigest:DIGEST,maxPhysicalJudgePosts:12,perCallTimeoutMs:PER_CALL_MS,
  maxWallMs:MAX_WALL_MS,actorCalls:0,canonicalJudgeCalls:0,canonicalCredit:false};
 if(!argv.length||argv[0]==='--plan'){assert(argv.length<=1);process.stdout.write(JSON.stringify(plan)+'\n');return plan;}
 assert.deepEqual(argv.slice(0,2),['--run','--output']);assert.equal(argv.length,3);
 assert.equal(process.env.V39_ATOMIC_RETAINED_DIAGNOSTIC_ADMITTED,'1','Root-admitted diagnostic run required');
 const output=admittedOutput(argv[2]),handle=fs.openSync(output,'wx',0o600);
 let journal;
 try{
  journal=fs.openSync(path.join(path.dirname(output),JOURNAL),'wx',0o600);
  const append=report=>{fs.writeSync(journal,JSON.stringify({version:1,event:'checkpoint',physicalJudgePosts:report.physicalJudgePosts,
   status:report.status||'running',lastStage:report.calls.at(-1)?.stage||null})+'\n');fs.fsyncSync(journal);
   fs.ftruncateSync(handle,0);fs.writeSync(handle,JSON.stringify(report)+'\n',0,'utf8');fs.fsyncSync(handle);};
  const {report}=await runDiagnostic({admitted,record:append});
  process.stdout.write(JSON.stringify({output,status:report.status,physicalJudgePosts:report.physicalJudgePosts,
   canonicalCredit:false})+'\n');
  if(report.status!=='diagnostic-complete')process.exitCode=1;return report;
 }finally{if(journal!==undefined)fs.closeSync(journal);fs.closeSync(handle);}
}
if(require.main===module)main().catch(error=>{process.stderr.write(`V39 atomic diagnostic failed: ${error.name||'Error'}\n`);process.exitCode=1;});
module.exports={admitOriginal,sourcePins,stageRequest,decodeChat,createInvoker,admittedOutput,runDiagnostic,main,
 singlePost,MODEL,DIGEST,PER_CALL_MS,MAX_WALL_MS,MAX_RESPONSE_BYTES};
