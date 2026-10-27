'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const D=require('./secureshopUserLookupV6RetainedDiagnostic');
const MODEL='llama3.1:8b';
const probe=async()=>({identityMatched:true,localSocketRetired:true});
function result(value){const body=Buffer.from(JSON.stringify({model:MODEL,done:true,done_reason:'stop',eval_count:20,
 message:{role:'assistant',content:JSON.stringify(value)}})+'\n');return {status:200,termination:'complete',localSocketRetired:true,body,responseBytes:body.length};}
const negative={satisfied:false,citations:[]};
test('real canonical four-criterion evaluator uses augmented wires, retains wrong semantic outcomes without credit',async()=>{
 const records=[];let calls=0;
 const {report}=await D.runControlled({probe,record:r=>records.push(structuredClone(r)),send:async options=>{
  assert.equal(records.at(-1).calls.at(-1).physicalAttempt,false);
  options.onPhysicalAttempt();calls++;
  const request=JSON.parse(options.body);
  assert.equal(request.model,MODEL);assert.equal(request.options.num_predict,900);
  assert(request.messages[1].content.includes('NON-CITABLE AUXILIARY RESPONSE INDEX'));
  return result(negative);
 }});
 assert.equal(calls,8);assert.equal(report.physicalAttempts,8);assert.equal(report.results.length,2);
 assert(report.results.every(x=>x.verdict==='fail'));assert.equal(report.canonicalCredit,false);
 assert(report.calls.every(x=>x.localSocketRetired&&x.responseBase64&&x.requestSha256));
 assert.equal(report.status,'calibration-mismatched');assert.equal(report.calibrationPassed,false);
});
test('invalid first output repairs only inside canonical per-criterion loop',async()=>{
 let calls=0;const {report}=await D.runControlled({probe,record:()=>{},send:async o=>{
  o.onPhysicalAttempt();calls++;return result(calls%2?{wrong:true}:negative);
 }});
 assert.equal(calls,16);assert.equal(report.physicalAttempts,16);
 assert.equal(report.status,'calibration-mismatched');
 assert.deepEqual(report.calls.map(x=>x.attempt),Array.from({length:8},()=>[1,2]).flat());
});
test('host-only calibration reports matched pair without changing model instructions or granting credit',async()=>{
 let calls=0;const {report}=await D.runControlled({probe,record:()=>{},send:async o=>{
  o.onPhysicalAttempt();calls++;const request=JSON.parse(o.body);
  const scoped=JSON.parse(request.messages[1].content.split('\nNON-CITABLE AUXILIARY RESPONSE INDEX:')[0]);
  const response=scoped.citableObservedEvidence.find(x=>x.id==='user_lookup_response').content;
  return result(calls<=4?{satisfied:true,citations:[{evidenceId:'user_lookup_response',quote:response}]}:negative);
 }});
 assert.equal(calls,8);assert.equal(report.status,'calibration-matched');assert.equal(report.calibrationPassed,true);
 assert.equal(report.canonicalCredit,false);assert.equal(report.qualificationAccepted,false);
});
test('invalid twice retains failed wires and unavailable canonical result',async()=>{
 let calls=0;const {report}=await D.runControlled({probe,record:()=>{},send:async o=>{o.onPhysicalAttempt();calls++;return result({wrong:true});}});
 assert.equal(calls,2);assert.equal(report.status,'diagnostic-failed');assert.equal(report.results[0].verdict,'unavailable');
 assert(report.calls.every(x=>x.responseBase64));
});
test('record failure before dispatch prevents HTTP and async recorders are rejected',async()=>{
 let calls=0;const {report}=await D.runControlled({probe,record:r=>{if(r.calls.some(x=>!x.physicalAttempt))throw Error('disk failure');},
  send:async()=>{calls++;return result(negative);}}).catch(error=>({report:null,error}));
 assert.equal(calls,0);assert.equal(report,null);
 await assert.rejects(D.runControlled({probe,send:async()=>result(negative),record:async()=>{}}),/synchronous/);
});
test('aborted evaluation joins outstanding physical transport and cannot accept late answer',async()=>{
 const controller=new AbortController();let retired=false,calls=0;
 const {report}=await D.runControlled({probe,record:()=>{},signal:controller.signal,send:async o=>{
  o.onPhysicalAttempt();calls++;controller.abort(Error('controlled interrupt'));
  await new Promise(resolve=>setTimeout(resolve,10));retired=true;return result(negative);
 }});
 assert(retired);assert.equal(calls,1);assert.equal(report.status,'diagnostic-failed');assert.equal(report.localRetirementVerified,true);
});
test('transport failures never retry and missing local retirement fails terminal',async()=>{
 let calls=0;const {report}=await D.runControlled({probe,record:()=>{},send:async o=>{
  o.onPhysicalAttempt();calls++;return {...result(negative),termination:'request_error',localSocketRetired:false};
 }});
 assert.equal(calls,1);assert.equal(report.status,'diagnostic-failed');assert.equal(report.localRetirementVerified,false);
});
test('private output is nonoverwrite and repeated snapshots remain valid JSON',()=>{
 const root=path.resolve(__dirname,'../../tasks/qualification');const dir=fs.mkdtempSync(path.join(root,'run-v21-controlled-'));fs.chmodSync(dir,0o700);
 const output=path.join(dir,D.NAME);let writer;
 try{writer=D.privateRecorder(output);writer.record({long:'abc'.repeat(40)});writer.record({short:true});
  assert.deepEqual(JSON.parse(fs.readFileSync(output)),{short:true});assert.equal(fs.statSync(output).mode&0o777,0o600);
  assert.throws(()=>D.privateRecorder(output));assert.throws(()=>D.privateRecorder(path.join(dir,'wrong.json')));
 }finally{writer?.close();if(fs.existsSync(output))fs.unlinkSync(output);fs.rmdirSync(dir);}
});
test('live CLI requires exact reviewed plan and private output before dispatch',async()=>{
 const p=await D.main(['--plan']);assert.equal(p.liveEnabled,true);assert.equal(p.protocol.maximumPhysicalCalls,16);
 await assert.rejects(D.main(['--run','--expected-plan','0'.repeat(64),'--output','unused']),/reviewed current plan/);
 await assert.rejects(D.main(['--run','--expected-plan',p.planSha256,'--output','unused']));
});
test('failed atomic publication preserves previous durable dispatch intent',()=>{
 const root=path.resolve(__dirname,'../../tasks/qualification'),dir=fs.mkdtempSync(path.join(root,'run-v21-controlled-'));fs.chmodSync(dir,0o700);
 const output=path.join(dir,D.NAME),writer=D.privateRecorder(output),originalWrite=fs.writeSync;
 try{writer.record({status:'dispatch-intent',ordinal:1});
  fs.writeSync=()=>{throw Error('controlled write failure');};
  assert.throws(()=>writer.record({status:'replaced'}),/controlled write failure/);
 }finally{fs.writeSync=originalWrite;writer.close();}
 try{assert.deepEqual(JSON.parse(fs.readFileSync(output)),{status:'dispatch-intent',ordinal:1});}
 finally{for(const name of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,name));fs.rmdirSync(dir);}
});
test('unsettled transport reaches bounded cleanup debt rather than false absence',async()=>{
 const controller=new AbortController();let release;
 const started=performance.now();
 const {report}=await D.runControlled({probe,record:()=>{},signal:controller.signal,send:async o=>{
  o.onPhysicalAttempt();controller.abort(Error('controlled abort'));
  await new Promise(resolve=>{release=resolve;});return result(negative);
 }});
 assert(performance.now()-started<8000);assert.equal(report.pendingTransportDebt,true);
 assert.equal(report.localRetirementVerified,false);assert.equal(report.status,'diagnostic-failed');
 release();await new Promise(resolve=>setTimeout(resolve,20));
});
