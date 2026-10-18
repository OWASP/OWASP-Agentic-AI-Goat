'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/secureshopReviewContentJudgeCalibration');

const LIVE = process.env.RUN_LIVE_SECURESHOP_REVIEW_CONTENT_JUDGE_CALIBRATION === '1';
const PRODUCT_SUMMARY_LIVE=process.env.RUN_LIVE_SECURESHOP_PRODUCT_SUMMARY_JUDGE_CALIBRATION==='1';
assert.equal(LIVE&&PRODUCT_SUMMARY_LIVE,false,'Select exactly one calibration cohort');

function modelUrl() {
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama');
  assert.equal(process.env.JUDGE_MODEL, calibration.MODEL);
  assert.ok(process.env.OLLAMA_BASE_URL);
  const value = new URL(process.env.OLLAMA_BASE_URL);
  assert.equal(value.protocol, 'http:'); assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.port, /^[1-9][0-9]{1,4}$/);
  assert.equal(value.username, ''); assert.equal(value.password, '');
  assert.equal(value.pathname, '/'); assert.equal(value.search, ''); assert.equal(value.hash, '');
  return value.toString().replace(/\/$/, '');
}

function diagnostic(item) {
  return Object.freeze({ caseId: item.caseId, kind: item.kind, trial: item.trial,
    expectedVerdict: item.expectedVerdict, expectedCriteria: item.expectedCriteria,
    packetSha256: item.packetSha256, resultSha256: item.resultSha256,
    provider: item.provider, model: item.model, attempts: item.attempts,
    verdict: item.judgment?.verdict ?? null, criteria: item.judgment?.criteria ?? [],
    scopedCriteria: item.scopedCriteria });
}

test('local llama3.1:8b separates followed moderation action from policy violation', {
  skip: !LIVE, timeout: 900000,
}, async t => {
  const provider = createLangChainProvider({ provider: 'ollama', model: calibration.MODEL,
    baseURL: modelUrl() });
  let providerCalls = 0;
  const model = Object.freeze({ async chat(...args) {
    providerCalls += 1;
    assert.ok(providerCalls <= calibration.MAX_PROVIDER_CALLS,
      'Review-content calibration exceeded the canonical repair bound');
    return provider.chat(...args);
  } });
  const judge = createObjectiveJudge({ model, timeoutMs: 60000 });
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(new Error('Review-content calibration deadline exceeded')), 840000);
  deadline.unref?.(); let run = 0;
  try {
    const output = await calibration.runCalibration({
      async evaluate(packet, metadata) {
        run += 1;
        return judge({ ...packet, execution: Object.freeze({ ownerId: 'synthetic-calibration',
          runId: `review-content-v2-${metadata.trial}-${run}`, signal: controller.signal,
          async check() { controller.signal.throwIfAborted(); }, async emit() {} }) });
      },
      async recordResult(item) { t.diagnostic(JSON.stringify(diagnostic(item))); },
    });
    t.diagnostic(JSON.stringify({ scope: 'secureshop_review_content_v2_calibration_summary',
      provider: 'ollama', model: calibration.MODEL, cases: output.results.length,
      providerCalls, expectedProviderCalls: calibration.EXPECTED_PROVIDER_CALLS,
      maximumProviderCalls: calibration.MAX_PROVIDER_CALLS,
      results: output.results.map(diagnostic) }));
    assert.equal(output.results.length, calibration.TRIALS_PER_CASE * calibration.CASES_PER_TRIAL);
    assert.equal(providerCalls, calibration.EXPECTED_PROVIDER_CALLS,
      'Any canonical Judge repair is retained evidence but does not qualify this calibration');
    assert.equal(providerCalls, output.results.reduce((count, item) => count + item.attempts, 0));
    assert.ok(output.results.every(item => item.provider === 'ollama'
      && item.model === calibration.MODEL && item.attempts === 2));
    t.diagnostic(JSON.stringify({ qualification: 'judge_only_semantic_calibration',
      objectiveId: 'ss_content_followed', rubricVersion: 'secureshop-review-content-v2',
      provider: 'ollama', model: calibration.MODEL, toolsExecuted: 0, databaseWrites: 0,
      creditsAttempted: 0, mountedWorkflowQualified: false,
      providerCalls, expectedProviderCalls: calibration.EXPECTED_PROVIDER_CALLS,
      maximumProviderCalls: calibration.MAX_PROVIDER_CALLS }));
  } finally { clearTimeout(deadline); }
});

test('local llama3.1:8b V16 typed-comparison candidate, fixed six cases without credit',{
 skip:!PRODUCT_SUMMARY_LIVE,timeout:840000,
},async()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
 const hash=value=>createHash('sha256').update(value).digest('hex'),root=path.resolve(__dirname,'..');
 const sourcePath=process.env.V16_CALIBRATION_INPUT,output=process.env.V16_CALIBRATION_OUTPUT;
 assert.ok(path.isAbsolute(sourcePath)&&path.isAbsolute(output));assert.ok(!path.resolve(output).startsWith(root+path.sep));
 assert.equal(fs.statSync(path.dirname(output)).mode&0o777,0o700);assert.equal(fs.existsSync(output),false);
 assert.equal(process.env.JUDGE_PROVIDER,'ollama');assert.equal(process.env.JUDGE_MODEL,'llama3.1:8b');
 const contract=process.env.V16_CALIBRATION_CONTRACT||'separate-v3';
 assert.ok(['separate-v3','joint-v4'].includes(contract),'Closed V16 calibration contract required');
 const joint=contract==='joint-v4',maximumProviderCalls=joint?6:12;
 const bytes=fs.readFileSync(sourcePath),declaration=(joint?calibration.productSummaryJointCases:calibration.productSummaryCases)(bytes,calibration.PRODUCT_SUMMARY_ORIGINAL_SHA);
 const declarationSha256=hash(JSON.stringify(declaration));assert.equal(process.env.V16_CALIBRATION_DECLARATION_SHA,declarationSha256);
 const files=['tests/secureshopReviewContentJudgeCalibration.live.test.js','tests/fixtures/secureshopReviewContentJudgeCalibration.js',
  'server/services/secureshopProductSummaryEvidence.js','server/agent-runtime/objectiveJudge.js','server/agent-runtime/providers/langchainProvider.js',
  'tests/postgres/secureshopMailActualTransport.js','tests/fixtures/secureshopAnalyticsRenderedBrowser.js','package-lock.json'];
 const pins=()=>Object.fromEntries(files.map(file=>[file,hash(fs.readFileSync(path.join(root,file)))]));
 const pinsBefore=pins();
 if(joint)assert.equal(process.env.V16_CALIBRATION_SOURCE_PINS_SHA,hash(JSON.stringify(pinsBefore)),'Exact reviewed joint source pins required');
 const state={version:1,status:'running',declarationSha256,declaration,pinsBefore,cases:[],http:[],transcripts:[],
  executable:{path:process.execPath,version:process.version,sha256:hash(fs.readFileSync(process.execPath))},
  credit:false,qualification:false,runtimeActivated:false,actualActorCalls:0,databaseCalls:0,browserCalls:0,contract,maximumProviderCalls};
 const fd=fs.openSync(output,'wx',0o600);fs.closeSync(fd);
 const record=()=>fs.writeFileSync(output,JSON.stringify(state,null,2),{mode:0o600});record();
 let transport,providerCalls=0,failure;const controller=new AbortController();
 const deadline=setTimeout(()=>controller.abort(Error('V16 calibration deadline exceeded')),780000);deadline.unref?.();
 try{
  transport=await require('./postgres/secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:maximumProviderCalls,
   record:value=>{state.http=value.calls;state.modelDigest=value.modelDigest;record();}});
  const provider=createLangChainProvider({provider:'ollama',model:calibration.MODEL,baseURL:transport.judgeUrl});
  const model=calibration.createProductSummaryNoRepairModel(provider,()=>assert.ok(++providerCalls<=maximumProviderCalls,'Closed calibration call bound'));
  if(joint){
   const evaluate=calibration.createProductSummaryJointEvaluator({model,signal:controller.signal,
    recordTranscript:transcript=>{state.transcripts.push(transcript);record();}});
   await calibration.runProductSummaryJointCalibration({declaration,evaluate,recordResult:row=>{state.cases.push(row);record();}});
  }else{
  const judge=createObjectiveJudge({model,timeoutMs:60000,observeExecutionTranscript:transcript=>{state.transcripts.push(transcript);record();}});
  let run=0;
  await calibration.runProductSummaryCalibration({declaration,
   evaluate:packet=>judge({...packet,execution:{ownerId:'synthetic-v16-calibration',runId:`product-summary-v3-calibration-${++run}`,
    signal:controller.signal,check:async()=>controller.signal.throwIfAborted(),emit:async()=>{}}}),
   recordResult:row=>{state.cases.push(row);record();}});
  }
  assert.equal(providerCalls,maximumProviderCalls);assert.equal(state.http.length,maximumProviderCalls);state.status='semantic_matrix_passed';
 }catch(error){failure=error;state.status='failed';state.error={name:error.name,message:error.message};}
 finally{
  clearTimeout(deadline);state.providerCalls=providerCalls;
  try{await transport?.close();state.transportClosed=true;}catch(error){state.cleanupError=error.message;failure??=error;}
  try{
   state.pinsAfter=pins();assert.deepEqual(state.pinsAfter,state.pinsBefore);assert.equal(hash(fs.readFileSync(sourcePath)),calibration.PRODUCT_SUMMARY_ORIGINAL_SHA);
   const response=await fetch('http://127.0.0.1:11434/api/tags',{redirect:'error',signal:AbortSignal.timeout(5000)});assert.equal(response.ok,true);
   const tags=await response.json();const identity=tags.models?.find(row=>(row.name===calibration.MODEL||row.model===calibration.MODEL)&&row.digest===state.modelDigest);
   assert.ok(identity,'Pinned model unchanged after calibration');state.modelAfter={name:calibration.MODEL,digest:identity.digest};
   for(const wire of state.http){assert.equal(wire.responseComplete,true);assert.equal(wire.responseCaptureTruncated,false);
    assert.equal(hash(wire.response),wire.responseSha256);assert.equal(hash(wire.request),wire.requestSha256);
    require('./fixtures/secureshopAnalyticsRenderedBrowser').analyticsWireText({status:'returned',httpStatus:wire.status,request:JSON.parse(wire.request),responseBody:wire.response});}
   if(joint){assert.equal(state.http.length,providerCalls);calibration.verifyProductSummaryJointWires(state.http,state.transcripts);}
   state.physicalVerified=true;
  }catch(error){state.verificationError=error.message;failure??=error;}
  state.status=failure?'failed':state.status;state.finishedAt=new Date().toISOString();record();
 }
 if(failure)throw failure;
});
