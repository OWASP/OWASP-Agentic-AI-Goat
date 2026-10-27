'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {isDeepStrictEqual}=require('node:util');
const D=require('./secureshopManualRagPresentationV2Diagnostic');
const P=require('../fixtures/secureshopManualRagPresentationDiagnosticV2');
const {RUBRIC}=require('../../server/services/secureshopManualRagEvidence');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
const ROOT=path.resolve(__dirname,'../..');
const probe=async()=>({identityMatched:true,localSocketRetired:true});
function complete(reply){const body=Buffer.from(JSON.stringify({model:'llama3.1:8b',message:{content:JSON.stringify(reply)},
  done:true,done_reason:'stop',eval_count:4})+'\n');
 return {status:200,termination:'complete',localSocketRetired:true,responseBytes:body.length,body};}
function controlled(reply){const sends=[],records=[];return {sends,records,
 send:async request=>{sends.push(request);request.onPhysicalAttempt();return complete(reply);},
 record:report=>{records.push({status:report.status,reservations:report.reservations,
  physicalAttempts:report.physicalAttempts,calls:report.calls.length});}};}

test('original clean fact gate remains ineligible while diagnostic criteria are exact originals',()=>{
 const retained=P.loadRetainedPair(),clean=D.casePacket('clean',retained),poison=D.casePacket('poisoned',retained);
 assert.equal(clean.originalFactGateEligible,false);
 assert.equal(clean.originalFacts.original_uploaded_manual_bound,false);
 assert.equal(clean.originalFacts.exact_selected_chunk_retrieved,false);
 assert.equal(poison.originalFactGateEligible,true);
 assert.ok(RUBRIC.requiredFacts.every(id=>poison.originalFacts[id]===true));
 assert.ok(isDeepStrictEqual(clean.diagnostic.rubric.criteria,RUBRIC.criteria));
 assert.ok(isDeepStrictEqual(poison.diagnostic.rubric.criteria,RUBRIC.criteria));
 assert.deepEqual(clean.diagnostic.rubric.requiredFacts,[]);
 assert.deepEqual(poison.diagnostic.rubric.requiredFacts,[]);
 assert.notEqual(clean.diagnostic.rubric.version,RUBRIC.version);
 assert.equal(clean.diagnostic.evidence[1].id,'manual_consumer_response');
 assert.equal(clean.diagnostic.evidence[0].id,'manual_comparison');
 assert.ok(!JSON.stringify(clean.diagnostic).includes('candidatePositive'));
});

test('unchanged original whole-objective Judge rejects clean facts before a physical call',async()=>{
 const clean=D.casePacket('clean',P.loadRetainedPair());let calls=0;
 const judge=createObjectiveJudge({model:{provider:'ollama',model:'llama3.1:8b',chat(){calls++;throw Error('unexpected model call');}},
  timeoutMs:90000,contextTokens:32768});
 const result=await judge({rubric:RUBRIC,facts:clean.originalFacts,evidence:clean.diagnostic.evidence,
  execution:{signal:new AbortController().signal,emit(){}}});
 assert.equal(result.verdict,'fail');assert.equal(result.attempts,0);assert.equal(calls,0);
});

test('prospective plan is exact four-call scope, one sufficient deadline, and no credit',async()=>{
 const p=D.plan();assert.equal(p.liveEnabled,true);assert.equal(p.physicalJudgeCallsMax,4);
 assert.equal(p.perCaseCriterionCallsMax,1);assert.equal(p.repairs,0);assert.equal(p.actorCalls,0);
 assert.equal(p.workDeadlineMs,420000);
 assert(p.workDeadlineMs>=4*90000+2*p.postModelTimeoutMs+p.localSettlementMs+35000);
 assert.equal(p.socketRetirementAllowanceMs,5000);
 assert.equal(p.outerTerminalBudgetMs,p.workDeadlineMs+2*p.socketRetirementAllowanceMs+p.localSettlementMs);
 assert.equal(p.originalFactGateEligible.clean,false);assert.equal(p.originalFactGateEligible.poisoned,true);
 assert.equal(p.canonicalCredit,false);assert.equal(p.diagnosticOnly,true);
 const output=path.join(ROOT,'tasks/qualification/run-v26-presentation-notcreated',D.NAME);
 await assert.rejects(D.main(['--run','--expected-plan','0'.repeat(64),'--output',output]));
 await assert.rejects(D.main(['--run','--expected-plan',p.planSha256,'--output',output]));
 assert.equal(fs.existsSync(output),false);
 assert.equal(fs.existsSync(D.CLAIM),false);
});

test('stale reviewed source snapshot is rejected before any physical dispatch',async()=>{
 let sends=0;await assert.rejects(D.runControlled({probe,record:()=>{},expectedSourcePins:{},
  send:async()=>{sends++;throw Error('unexpected send');}}),/reviewed source snapshot changed/);
 assert.equal(sends,0);
});

test('controlled canonical criterion engine spends four physical attempts with false replies but no credit',async()=>{
 const mock=controlled({satisfied:false,citations:[]});
 const report=await D.runControlled({...mock,probe});
 assert.equal(report.status,'calibration-mismatched');
 assert.equal(report.physicalAttempts,4);assert.equal(report.reservations,4);
 assert.equal(report.calls.length,4);assert.equal(mock.sends.length,4);
 assert.equal(report.results.length,2);assert.equal(report.pendingTransportDebt,false);
 assert.equal(report.localRetirementVerified,true);assert.equal(report.canonicalCredit,false);
 assert.equal(report.qualificationAccepted,false);assert.equal(report.productionPromotion,false);
 assert.ok(report.calls.every(c=>c.physicalAttempt&&c.localSocketRetired===true));
 assert.ok(mock.records.some(r=>r.reservations===1&&r.physicalAttempts===0));
 assert.ok(mock.records.some(r=>r.reservations===4&&r.physicalAttempts===4));
});

test('synthetic positive mechanics use original answer citations without creating credit',async()=>{
 const answer=P.loadRetainedPair().cases.poisoned.answer;let count=0;
 const report=await D.runControlled({probe,record:()=>{},send:async request=>{
  request.onPhysicalAttempt();count++;
  return complete(count<=2?{satisfied:true,citations:[{evidenceId:'manual_consumer_response',quote:answer}]}:
   {satisfied:false,citations:[]});
 }});
 assert.equal(count,4);assert.equal(report.status,'calibration-matched');
 assert.equal(report.controlled,true);assert.equal(report.canonicalCredit,false);
 assert.equal(report.qualificationAccepted,false);assert.equal(report.productionPromotion,false);
});

test('wire request verifier rejects changed answer, criterion, schema, or options',async()=>{
 const mock=controlled({satisfied:false,citations:[]});
 const report=await D.runControlled({...mock,probe});assert.equal(report.physicalAttempts,4);
 const request=JSON.parse(report.calls[0].request);
 const packet=D.casePacket('poisoned',P.loadRetainedPair());
 const options={...request.options,format:request.format,max_tokens:900,timeout:90000};
 assert.doesNotThrow(()=>D.exactRequest(request.messages,[],options,packet,'source_instruction_adopted'));
 const answerChanged=structuredClone(request.messages);
 const user=JSON.parse(answerChanged[1].content);user.citableObservedEvidence[0].content+=' ';
 answerChanged[1].content=JSON.stringify(user);
 assert.throws(()=>D.exactRequest(answerChanged,[],options,packet,'source_instruction_adopted'));
 const criterionChanged=structuredClone(request.messages);criterionChanged[0].content='unreviewed criterion';
 assert.throws(()=>D.exactRequest(criterionChanged,[],options,packet,'source_instruction_adopted'));
 assert.throws(()=>D.exactRequest(request.messages,[],{...options,format:{}},packet,'source_instruction_adopted'));
 assert.throws(()=>D.exactRequest(request.messages,[],{...options,temperature:0.1},packet,'source_instruction_adopted'));
});

test('invalid first reply cannot cause a second physical repair call',async()=>{
 const mock=controlled({});const report=await D.runControlled({...mock,probe});
 assert.equal(report.status,'diagnostic-failed');
 assert.equal(report.physicalAttempts,1);assert.equal(mock.sends.length,1);
 assert.equal(report.blockedRepairs,1);
 assert.equal(report.canonicalCredit,false);assert.equal(report.qualificationAccepted,false);
 assert.equal(report.localRetirementVerified,true);
});

test('noncitable source quote is rejected with no physical repair call',async()=>{
 const quote=P.loadRetainedPair().cases.poisoned.manual.text;let count=0;
 const report=await D.runControlled({probe,record:()=>{},send:async request=>{
  request.onPhysicalAttempt();count++;
  return complete({satisfied:true,citations:[{evidenceId:'manual_comparison',quote}]});
 }});
 assert.equal(count,1);assert.equal(report.status,'diagnostic-failed');
 assert.equal(report.physicalAttempts,1);assert.equal(report.canonicalCredit,false);
 assert.equal(report.blockedRepairs,1);
});

test('incomplete physical response length is retained and rejected before semantic parsing',async()=>{
 let count=0;const report=await D.runControlled({probe,record:()=>{},send:async request=>{
  request.onPhysicalAttempt();count++;const result=complete({satisfied:false,citations:[]});
  result.responseBytes++;return result;
 }});
 assert.equal(count,1);assert.equal(report.status,'diagnostic-failed');
 assert.equal(report.physicalAttempts,1);assert.equal(report.calls[0].responseBytes,
  Buffer.from(report.calls[0].responseBase64,'base64').length+1);
 assert.equal(report.localRetirementVerified,true);
});

test('transport failure consumes the physical reservation and retains terminal failure',async()=>{
 const calls=[];const report=await D.runControlled({probe,record:()=>{},send:async request=>{
  calls.push(request);request.onPhysicalAttempt();const error=Error('controlled transport loss');
  error.code='CONTROLLED_LOSS';error.localSocketRetired=true;error.termination='request_error';throw error;
 }});
 assert.equal(calls.length,1);assert.equal(report.physicalAttempts,1);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.localRetirementVerified,true);
 assert.equal(report.calls[0].failure.code,'CONTROLLED_LOSS');
});

test('primary failure and post-model failure retain separate causes without hiding source verification',async()=>{
 let probes=0,sends=0;
 const report=await D.runControlled({record:()=>{},probe:async()=>{
  if(++probes===1)return {identityMatched:true,localSocketRetired:true};
  const error=Error('controlled post-model failure');error.code='CONTROLLED_POST_MODEL';throw error;
 },send:async request=>{
  sends++;request.onPhysicalAttempt();const error=Error('controlled transport loss');
  error.code='CONTROLLED_LOSS';error.localSocketRetired=true;error.termination='request_error';throw error;
 }});
 assert.equal(probes,2);assert.equal(sends,1);
 assert.equal(report.calls[0].failure.code,'CONTROLLED_LOSS');
 assert.equal(report.failure.code,'ERR_ASSERTION','the original semantic failure remains primary');
 assert.deepEqual(report.postflightFailures.model,
  {code:'MODEL_POSTFLIGHT_UNVERIFIED',name:'Error'});
 assert.equal(report.postflightFailures.source,null);
 assert.equal(report.localRetirementVerified,true);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.qualificationAccepted,false);
});

test('short controlled deadline seals terminal report before delayed transport settles',async()=>{
 let release,terminal=false,afterTerminalRecords=0;
 const report=await D.runControlled({controlledWallMs:750,probe,record:r=>{
  if(terminal)afterTerminalRecords++;
  if(r.status!=='pending')terminal=true;
 },send:request=>{
  request.onPhysicalAttempt();return new Promise(resolve=>{release=()=>resolve(complete({satisfied:false,citations:[]}));});
 }});
 assert.equal(typeof release,'function');assert.equal(terminal,true);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.physicalAttempts,1);
 assert.equal(report.pendingTransportDebt,true);assert.equal(report.localRetirementVerified,false);
 const terminalSnapshot=JSON.stringify(report);release();
 await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
 assert.equal(JSON.stringify(report),terminalSnapshot,'late transport cannot mutate returned report');
 assert.equal(afterTerminalRecords,0,'late transport cannot rewrite terminal evidence');
});

test('short controlled deadline terminates with truthful debt when send never settles',async()=>{
 let sends=0,terminal=false;
 const report=await D.runControlled({controlledWallMs:750,probe,record:r=>{
  if(r.status!=='pending')terminal=true;
 },send:request=>{sends++;request.onPhysicalAttempt();return new Promise(()=>{});}});
 assert.equal(sends,1);assert.equal(terminal,true);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.pendingTransportDebt,true);
 assert.equal(report.localRetirementVerified,false);assert.equal(report.remoteCancellationProven,false);
 assert.equal(report.qualificationAccepted,false);
});

test('abort after physical reservation retires transport without remote-cancellation claim',async()=>{
 const abort=new AbortController();let calls=0;
 const report=await D.runControlled({probe,record:()=>{},signal:abort.signal,send:async request=>{
  request.onPhysicalAttempt();calls++;abort.abort(Error('controlled interruption'));
  return {status:null,termination:'aborted',body:Buffer.alloc(0),responseBytes:0,localSocketRetired:true};
 }});
 assert.equal(calls,1);assert.equal(report.physicalAttempts,1);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.pendingTransportDebt,false);
 assert.equal(report.localRetirementVerified,true);assert.equal(report.remoteCancellationProven,false);
});

test('initial durable recorder failure prevents every physical dispatch',async()=>{
 let sends=0;const report=await D.runControlled({probe,record:()=>{throw Error('controlled disk failure');},
  send:async()=>{sends++;throw Error('unexpected send');}});
 assert.equal(sends,0);assert.equal(report.physicalAttempts,0);
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.qualificationAccepted,false);
});

test('private output and one-shot claim are exclusive, owned, and repository-local',()=>{
 const base=path.join(ROOT,'tasks/qualification');
 const run=fs.mkdtempSync(path.join(base,'run-v26-presentation-controlled-'));
 fs.chmodSync(run,0o700);
 const output=path.join(run,D.NAME),claim=path.join(run,'claim.json');
 let writer;
 try{
  writer=D.privateRecorder(output);writer.record({status:'controlled',qualificationAccepted:false});
  assert.equal(fs.statSync(output).mode&0o777,0o600);
  assert.throws(()=>D.privateRecorder(output));
  D.exclusiveClaim('a'.repeat(64),output,claim);
  assert.equal(fs.statSync(claim).mode&0o777,0o600);
  assert.throws(()=>D.exclusiveClaim('a'.repeat(64),output,claim));
 }finally{
  writer?.close();
  if(fs.existsSync(output))fs.unlinkSync(output);
  if(fs.existsSync(claim))fs.unlinkSync(claim);
  fs.rmdirSync(run);
 }
});

test('failed atomic checkpoint retains the previous durable dispatch intent',()=>{
 const base=path.join(ROOT,'tasks/qualification');
 const run=fs.mkdtempSync(path.join(base,'run-v26-presentation-controlled-'));
 fs.chmodSync(run,0o700);const output=path.join(run,D.NAME);
 const writer=D.privateRecorder(output),originalWrite=fs.writeSync;
 try{
  writer.record({status:'dispatch-intent',physicalAttempt:false});
  fs.writeSync=()=>{throw Error('controlled write failure');};
  assert.throws(()=>writer.record({status:'unverified-replacement'}),/controlled write failure/);
 }finally{fs.writeSync=originalWrite;writer.close();}
 try{assert.deepEqual(JSON.parse(fs.readFileSync(output)),{status:'dispatch-intent',physicalAttempt:false});}
 finally{for(const name of fs.readdirSync(run))fs.unlinkSync(path.join(run,name));fs.rmdirSync(run);}
});
