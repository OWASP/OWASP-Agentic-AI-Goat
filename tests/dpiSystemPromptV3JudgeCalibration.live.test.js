'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/dpiSystemPromptV3JudgeCalibration');

const LIVE = process.env.RUN_LIVE_DPI_SYSTEM_PROMPT_V3_CALIBRATION === '1';
function modelUrl() {
  assert.equal(process.env.JUDGE_PROVIDER,'ollama'); assert.equal(process.env.JUDGE_MODEL,calibration.MODEL);
  const value=new URL(process.env.OLLAMA_BASE_URL);assert.equal(value.protocol,'http:');assert.equal(value.hostname,'127.0.0.1');
  assert.match(value.port,/^[1-9][0-9]{1,4}$/);assert.equal(value.username,'');assert.equal(value.password,'');
  assert.equal(value.pathname,'/');assert.equal(value.search,'');assert.equal(value.hash,'');return value.toString().replace(/\/$/,'');
}
const sha=value=>createHash('sha256').update(value).digest('hex');
function validateOwnedCaptureRoot(target,ownedRoot,filename){
  assert.equal(typeof ownedRoot,'string');assert.equal(path.isAbsolute(ownedRoot),true);
  assert.equal(fs.realpathSync(ownedRoot),ownedRoot);
  const stat=fs.lstatSync(ownedRoot);assert.equal(stat.isDirectory(),true);assert.equal(stat.isSymbolicLink(),false);
  assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o777,0o700);
  assert.equal(target,path.join(ownedRoot,'evidence',filename));
  assert.equal(fs.realpathSync(path.dirname(target)),path.dirname(target));
}
function createPrivateInvalidAttemptCapture(invalidPath,{ownedRoot}={}){
  if(ownedRoot===undefined)assert.match(invalidPath||'',/^\/private\/tmp\/[^/]+\/evidence\/invalid-attempts\.jsonl$/);
  else validateOwnedCaptureRoot(invalidPath,ownedRoot,'invalid-attempts.jsonl');
  const parent=path.dirname(invalidPath);const parentStat=fs.lstatSync(parent);assert.equal(parentStat.isSymbolicLink(),false);assert.equal(parentStat.uid,process.getuid());assert.equal(parentStat.mode&0o077,0);
  let fd=null,count=0,closed=false;
  const capture=async row=>{
    assert.equal(closed,false);
    const raw=typeof row.rawResponse==='string'?row.rawResponse:null;const bytes=raw===null?null:Buffer.byteLength(raw);const digest=raw===null?null:sha(raw);
    assert.ok(raw===null||bytes<=16384);assert.equal(row.rawResponseByteCount,bytes);assert.equal(row.rawResponseSha256,digest);
    const safe=Object.freeze({...row,rawResponse:raw});
    if(fd===null){fd=fs.openSync(invalidPath,'wx',0o600);fs.fchmodSync(fd,0o600);}
    fs.writeSync(fd,JSON.stringify(safe)+'\n',null,'utf8');fs.fsyncSync(fd);count+=1;
  };
  Object.defineProperties(capture,{close:{value(){if(!closed){if(fd!==null)fs.closeSync(fd);closed=true;}}},count:{get(){return count;}}});
  return Object.freeze(capture);
}
function createPrivateModelAttemptCapture(attemptsPath,{ownedRoot}={}){
  if(ownedRoot===undefined)assert.match(attemptsPath||'',/^\/private\/tmp\/[^/]+\/evidence\/model-attempts\.jsonl$/);
  else validateOwnedCaptureRoot(attemptsPath,ownedRoot,'model-attempts.jsonl');
  const parent=path.dirname(attemptsPath);const parentStat=fs.lstatSync(parent);assert.equal(parentStat.isSymbolicLink(),false);assert.equal(parentStat.uid,process.getuid());assert.equal(parentStat.mode&0o077,0);
  const fd=fs.openSync(attemptsPath,'wx',0o600);fs.fchmodSync(fd,0o600);let count=0,closed=false;
  return Object.freeze({record(row){
    assert.equal(closed,false);assert.ok(count<calibration.MAX_PROVIDER_CALLS);
    const raw=typeof row.rawResponse==='string'?row.rawResponse:null;const bytes=raw===null?null:Buffer.byteLength(raw);const digest=raw===null?null:sha(raw);
    assert.ok(raw!==null&&bytes<=16384);assert.equal(row.rawResponseByteCount,bytes);assert.equal(row.rawResponseSha256,digest);
    fs.writeSync(fd,JSON.stringify(Object.freeze({...row,rawResponse:raw}))+'\n',null,'utf8');fs.fsyncSync(fd);count+=1;
  },close(){if(!closed){fs.closeSync(fd);closed=true;}},get count(){return count;}});
}
const SAFE_PROVIDER_FAILURE_CODES=Object.freeze([
  'AI_QUEUE_FULL','ABORT_ERR','ERR_ABORTED',
]);
const SAFE_PROVIDER_FAILURE_NAMES=Object.freeze(['Error','TypeError','AbortError','TimeoutError']);
function providerFailureDiagnostic(error){
  const code=typeof error?.code==='string'?error.code:'';
  const message=typeof error?.message==='string'?error.message:'';
  const safeCode=SAFE_PROVIDER_FAILURE_CODES.includes(code)||/^UND_ERR_[A-Z0-9_]{1,48}$/.test(code)
    || /^DPI_CALIBRATION_[A-Z0-9_]{1,64}$/.test(code)?code
    : /^DPI_CALIBRATION_[A-Z0-9_]{1,64}$/.test(message)?message:'UNCLASSIFIED_PROVIDER_FAILURE';
  const name=SAFE_PROVIDER_FAILURE_NAMES.includes(error?.name)?error.name:'UnknownError';
  return Object.freeze({providerFailureCode:safeCode,providerFailureName:name});
}
function assertRetainedCalibrationCase(item){
  assert.ok(['pass','fail','inconclusive','unavailable'].includes(item?.judgment?.verdict));
  if(item.judgment.verdict==='unavailable')assert.ok([0,1,2].includes(item.attempts),'unavailable must be pre-dispatch or a failed bounded stage');
  else assert.ok([1,2].includes(item.attempts),'completed case must use one classification call and at most one support call');
}
function diagnostic(item){return Object.freeze({caseId:item.caseId,kind:item.kind,trial:item.trial,
  expectedVerdict:item.expectedVerdict,expectedSatisfied:item.expectedSatisfied,packetSha256:item.packetSha256,
  resultSha256:item.resultSha256,provider:item.provider,model:item.model,attempts:item.attempts,
  verdict:item.judgment?.verdict??null,criteria:item.judgment?.criteria??[]});}

test('local llama3.1:8b compares representative actor fixtures with the DPI v12 protected reference',
  {skip:!LIVE,timeout:660000},async t=>{
    const provider=createLangChainProvider({provider:'ollama',model:calibration.MODEL,baseURL:modelUrl()});
    let providerCalls=0,current=null,fatalError=null;const attempts=[];const stageAttempts=new Map();
    const model=Object.freeze({async chat(...args){
      if(fatalError)throw fatalError;
      const messages=args[0];const input=JSON.parse(messages.at(-1)?.content||'{}');
      const stage=Array.isArray(input.candidates)?'support':Array.isArray(input.response_passages)?'effect':'source';
      if(!((stage==='support'&&input.candidates.every(row=>Array.isArray(row.cited_reference_passages)))||(stage==='source'&&Array.isArray(input.reference_passages))||(stage==='effect'&&Array.isArray(input.reference_passages)&&Array.isArray(input.response_passages)))){fatalError=Object.assign(new Error('Unexpected DPI Judge stage payload'),{code:'DPI_STAGE_WIRE'});throw fatalError;}
      const key=`${current?.caseId}:${current?.trial}:${stage}`;const stageAttempt=(stageAttempts.get(key)||0)+1;stageAttempts.set(key,stageAttempt);
      if(stageAttempt!==1){throw Object.assign(new Error('A repair is blocked by exact calibration'),{code:'DPI_CALIBRATION_REPAIR_BLOCKED'});}
      providerCalls+=1;if(providerCalls>calibration.MAX_PROVIDER_CALLS){fatalError=Object.assign(new Error('DPI provider call cap exceeded'),{code:'DPI_CALL_CAP'});throw fatalError;}
      let response;try{response=await provider.chat(...args);}catch(error){
        const safe=providerFailureDiagnostic(error);
        t.diagnostic(JSON.stringify({scope:'dpi_system_prompt_v12_transport_failure',caseId:current?.caseId??null,
          trial:current?.trial??null,stage,stageAttempt,attempt:providerCalls,...safe}));
        fatalError=Object.assign(new Error('DPI provider transport failed'),{code:'DPI_PROVIDER_TRANSPORT',...safe});throw fatalError;}
      const raw=typeof response?.response==='string'?response.response:'';
      if(Buffer.byteLength(raw)>16384){fatalError=Object.assign(new Error('Raw Judge response exceeds diagnostic bound'),{code:'DPI_RAW_BOUND'});throw fatalError;}
      const audit=Object.freeze({caseId:current?.caseId??null,trial:current?.trial??null,stage,stageAttempt,attempt:providerCalls,
        provider:response?.provider??null,model:response?.model??null,mocked:response?.mocked??null,
        fallback:response?.fallback??null,rawByteCount:Buffer.byteLength(raw),rawSha256:sha(raw),raw});
      try{privateAttempts.record(Object.freeze({version:1,scope:'dpi_system_prompt_v12_model_attempt',caseId:audit.caseId,
        trial:audit.trial,stage:audit.stage,stageAttempt:audit.stageAttempt,attempt:audit.attempt,
        provider:audit.provider,model:audit.model,mocked:audit.mocked,fallback:audit.fallback,
        rawResponse:raw,rawResponseByteCount:audit.rawByteCount,rawResponseSha256:audit.rawSha256}));}
      catch{fatalError=Object.assign(new Error('DPI model attempt retention failed'),{code:'DPI_ATTEMPT_RETENTION'});throw fatalError;}
      attempts.push(audit);
      // Raw output may copy the grading-only protected reference, so public
      // diagnostics retain only its bounded size and digest. Invalid output is
      // durably captured in the owner-only evidence file for diagnosis.
      t.diagnostic(JSON.stringify({scope:'dpi_system_prompt_v12_model_attempt',
        ...Object.fromEntries(Object.entries(audit).filter(([key])=>key!=='raw'))}));return response;}});
    const invalidPath=process.env.DPI_CALIBRATION_INVALID_ATTEMPTS_PATH;
    const captureInvalidAttempt=createPrivateInvalidAttemptCapture(invalidPath);
    const privateAttempts=createPrivateModelAttemptCapture(process.env.DPI_CALIBRATION_MODEL_ATTEMPTS_PATH);
    const judge=createObjectiveJudge({model,timeoutMs:60000,captureInvalidAttempt});const controller=new AbortController();
    const deadline=setTimeout(()=>controller.abort(new Error('DPI system-prompt v12 calibration deadline exceeded')),600000);deadline.unref?.();let run=0;
    try{const output=await calibration.runCalibration({async evaluate(packet,metadata){current=metadata;run+=1;
      const result=await judge({...packet,execution:Object.freeze({ownerId:'synthetic-dpi-calibration',runId:`dpi-system-prompt-v12-${metadata.trial}-${run}`,
        signal:controller.signal,async check(){controller.signal.throwIfAborted();},async emit(){}})});
      if(fatalError)throw fatalError;
      return result;},
      async recordResult(item){t.diagnostic(JSON.stringify({scope:'dpi_system_prompt_v12_case',...diagnostic(item)}));assertRetainedCalibrationCase(item);}});
      if(fatalError)throw fatalError;
      t.diagnostic(JSON.stringify({scope:'dpi_system_prompt_v12_calibration_summary',provider:'ollama',model:calibration.MODEL,
        actorEvidence:'controlled_fixtures',realActorQualified:false,durableCreditAttempted:false,toolsExecuted:0,databaseWrites:0,
        cases:output.results.length,mismatches:output.mismatches,providerCalls,minimumProviderCalls:calibration.MIN_PROVIDER_CALLS,
        maximumProviderCalls:calibration.MAX_PROVIDER_CALLS,attempts:attempts.map(({raw,...row})=>row),results:output.results.map(diagnostic)}));
      assert.ok(providerCalls>=calibration.MIN_PROVIDER_CALLS&&providerCalls<=calibration.MAX_PROVIDER_CALLS);assert.equal(attempts.length,providerCalls);assert.equal(stageAttempts.size,providerCalls);
      assert.ok(output.results.every(item=>item.provider==='ollama'&&item.model===calibration.MODEL&&[1,2].includes(item.attempts)));
      assert.ok(attempts.every(item=>item.provider==='ollama'&&item.model===calibration.MODEL&&item.mocked===false&&item.fallback!==true));
      assert.deepEqual(output.mismatches,[]);
      t.diagnostic(JSON.stringify({qualification:'judge_only_actor_fixture_calibration',objectiveId:'system_prompt',
        rubricVersion:'dpi-system-prompt-v12',actualJudge:true,actualActor:false,durableCredit:false,providerCalls}));
    }finally{clearTimeout(deadline);current=null;captureInvalidAttempt.close();privateAttempts.close();}
  });

module.exports={createPrivateInvalidAttemptCapture,createPrivateModelAttemptCapture,
  providerFailureDiagnostic,assertRetainedCalibrationCase};
