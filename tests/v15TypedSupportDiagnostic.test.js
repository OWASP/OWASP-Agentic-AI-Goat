'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {createHash} = require('node:crypto');
const runner = require('./postgres/run-v15-typed-support-diagnostic');
const {createActualCallBudget} = require('./postgres/secureshopMailActualTransport');

const retained = [runner.POSITIVE,runner.BENIGN].every(name=>fs.existsSync(path.join(runner.ROOT,name)));
const requested = process.env.V15_TYPED_SUPPORT_RETAINED_TEST === '1';
const gated = {skip:!retained&&!requested?'Retained private pair absent; portable controls are separate':false};

test('closed CLI defaults to plan; explicit run is still rejected without reviewed authority',async()=>{
  assert.equal(runner.parseArgs([]),'plan');
  assert.equal(runner.parseArgs(['--plan']),'plan');
  assert.equal(runner.parseArgs(['--run']),'run');
  for(const args of [['--run','--plan'],['--run','--run'],['--native'],['--plan','--output','/tmp/x']])
    assert.throws(()=>runner.parseArgs(args),/only default/);
  assert.throws(()=>runner.admissionRun(),/explicit reviewed local-model/);
  const before=fs.readdirSync(path.join(runner.ROOT,'tasks/qualification')).length;
  await assert.rejects(runner.runReal({cases:[]}),/explicit reviewed local-model/);
  assert.equal(fs.readdirSync(path.join(runner.ROOT,'tasks/qualification')).length,before);
});

test('pinned source and physical one-call budget reject drift or a second reservation',()=>{
  runner.verifySourcePins();
  const name=Object.keys(runner.SOURCE_SHA)[0];
  assert.throws(()=>runner.pinnedFile(name,'0'.repeat(64),1024*1024),/source pin/);
  const budget=createActualCallBudget({maxHttpCalls:1});
  assert.equal(budget.reserve('judge'),true);
  assert.equal(budget.reserve('judge'),false);
  assert.deepEqual(budget.snapshot(),{total:1,actor:0,judge:1});
});

test('genuine retained pair has exact immutable packets, physical provenance and one typed check each',gated,()=>{
  const pair=runner.preparePair(),plan=runner.publicPlan(pair);
  assert.equal(plan.nativeStarted,false);
  assert.equal(plan.maxPhysicalModelCalls,2);
  assert.equal(plan.maxPerCase,1);
  assert.equal(plan.canonicalCredit,false);
  assert.deepEqual(pair.cases.map(row=>row.name),['positive','benign']);
  for(const row of pair.cases){
    assert.equal(row.originalVerdict,'unavailable');
    assert.equal(row.originalObjectiveCredit,false);
    assert.equal(row.diagnostic.packet.diagnosticOnly,true);
    assert.equal(row.diagnostic.packet.canonicalCredit,false);
    assert.equal(row.diagnostic.packet.checks.length,1);
    assert.equal(row.diagnostic.packetSha256,runner.DIAGNOSTIC_SHA[row.name]);
    assert.equal(row.originalPacketSha256,runner.PACKET_SHA[row.name]);
  }
  assert.equal(pair.cases[0].diagnostic.packet.checks[0].sourceQuoteId,'q3');
  assert.equal(pair.cases[0].diagnostic.packet.checks[0].spanId,'p0');
  assert.equal(pair.cases[1].diagnostic.packet.checks[0].sourceQuoteId,'q2');
  assert.equal(pair.cases[1].diagnostic.packet.checks[0].spanId,'p1');
  assert.equal(pair.cases[0].diagnostic.packet.trusted_task,pair.cases[1].diagnostic.packet.trusted_task);
});

test('default plan neither contacts a model nor allocates evidence',gated,async()=>{
  const originalFetch=global.fetch,originalMkdir=fs.mkdirSync,originalWrite=process.stdout.write;
  const writes=[];
  global.fetch=()=>{throw Error('plan attempted network');};
  fs.mkdirSync=()=>{throw Error('plan attempted write');};
  process.stdout.write=(value)=>{writes.push(value);return true;};
  try{assert.equal(await runner.main([]),0);}finally{
    global.fetch=originalFetch;fs.mkdirSync=originalMkdir;process.stdout.write=originalWrite;
  }
  const plan=JSON.parse(writes.join(''));
  assert.equal(plan.nativeStarted,false);
  assert.equal(plan.canonicalCredit,false);
  assert.equal(plan.originalCases.length,2);
});

test('retained benign source, answer, packet, artifact and Judge lineage mutations fail closed',gated,()=>{
  const original=runner.readBenign().capture;
  const changed=edit=>{const copy=structuredClone(original);edit(copy);return copy;};
  const checks=[
    value=>{value.originalSource.entry.event.params_json+=' ';},
    value=>{value.runs.vuln.artifactReads.log.sha256='0'.repeat(64);},
    value=>{value.runs.vuln.judgeInput.packet+=' ';},
    value=>{value.runs.vuln.physical.renderedText='substituted';},
    value=>{value.observed.judgeTranscripts[0].calls[0].disposition='accepted';},
    value=>{value.runs.vuln.judgments[0].verdict='fail';},
  ];
  for(const edit of checks)assert.throws(()=>runner.validateBenignCapture(changed(edit),'synthetic-test'),/V15 typed diagnostic/);
  assert.throws(()=>runner.pinnedFile(runner.BENIGN,'0'.repeat(64),16*1024*1024),/source pin/);
});

test('typed output cannot borrow another tuple or promote historical credit',gated,()=>{
  const pair=runner.preparePair();
  const positive=pair.cases[0].diagnostic;
  assert.throws(()=>positive.validate(JSON.stringify({version:positive.version,checks:[],explanation:'No valid tuple.'})));
  assert.equal(runner.publicPlan(pair).originalCases.every(row=>row.originalVerdict==='unavailable'
    && row.originalObjectiveCredit===false),true);
});

test('exact physical Judge request and terminal NDJSON join survives no rehashed substitution',gated,()=>{
  const diagnostic=runner.preparePair().cases[0].diagnostic;
  const expected=diagnostic.request(),model='llama3.1:8b';
  const raw='{"version":"synthetic-controlled-only"}';
  const hash=value=>createHash('sha256').update(value).digest('hex');
  const make=(request={model,messages:expected.messages,format:expected.format,stream:true,
    options:{num_ctx:32768,num_predict:1800,temperature:0}},frames=[
      {model,message:{content:raw.slice(0,18)},done:false},
      {model,message:{content:raw.slice(18)},done:true}])=>{
    const requestText=JSON.stringify(request),responseText=frames.map(value=>JSON.stringify(value)).join('\n')+'\n';
    return {kind:'judge',model,status:200,request:requestText,requestBytes:Buffer.byteLength(requestText),
      requestSha256:hash(requestText),response:responseText,responseBytes:Buffer.byteLength(responseText),
      responseObservedBytes:Buffer.byteLength(responseText),responseSha256:hash(responseText),
      responseComplete:true,responseCaptureTruncated:false,terminalReason:'end'};
  };
  const normalized={response:raw};
  const good=make();
  assert.equal(runner.verifyPhysicalJoin(diagnostic,good,normalized).normalizedSha256,hash(raw));
  const base=JSON.parse(good.request);
  for(const edit of [
    value=>{value.messages[1].content+=' ';},
    value=>{value.format={type:'object'};},
    value=>{value.options.num_predict=1801;},
    value=>{value.model='another-model';},
    value=>{value.stream=false;},
    value=>{value.options.seed=1;},
  ]){const changed=structuredClone(base);edit(changed);
    assert.throws(()=>runner.verifyPhysicalJoin(diagnostic,make(changed),normalized),/physical Judge request/);
  }
  const other=make(base,[{model,message:{content:'different'},done:true}]);
  assert.throws(()=>runner.verifyPhysicalJoin(diagnostic,other,normalized),/response differs/);
  const noTerminal=make(base,[{model,message:{content:raw},done:false}]);
  assert.throws(()=>runner.verifyPhysicalJoin(diagnostic,noTerminal,normalized),/response differs/);
  const trailing=make(base,[{model,message:{content:raw},done:true},{model,message:{content:''},done:false}]);
  assert.throws(()=>runner.verifyPhysicalJoin(diagnostic,trailing,normalized),/terminal/);
  for(const changed of [{...good,status:503},{...good,responseComplete:false},
    {...good,responseCaptureTruncated:true},{...good,requestSha256:hash('other')},
    {...good,responseSha256:hash('other')}])
    assert.throws(()=>runner.verifyPhysicalJoin(diagnostic,changed,normalized),/complete physical Judge wire/);
});

test('bounded postflight metadata admits only the original local model digest',async()=>{
  const digest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
  const respond=value=>async(url,options)=>{
    assert.equal(url,'http://127.0.0.1:11434/api/tags');
    assert.equal(options.redirect,'error');
    return new Response(JSON.stringify(value),{status:200});
  };
  const good=await runner.verifyLocalModelDigest(respond({models:[{name:'llama3.1:8b',digest}]}));
  assert.equal(good.digest,digest);
  assert.equal(good.model,'llama3.1:8b');
  await assert.rejects(runner.verifyLocalModelDigest(respond({models:[{name:'llama3.1:8b',digest:'0'.repeat(64)}]})),/digest changed/);
  await assert.rejects(runner.verifyLocalModelDigest(respond({models:[]})),/digest changed/);
  await assert.rejects(runner.verifyLocalModelDigest(async()=>new Response('{}',{status:503})),/metadata unavailable/);
  await assert.rejects(runner.verifyLocalModelDigest(respond({models:[],padding:'x'.repeat(1024*1024)})),/exceeds bound/);
});

test('oversized metadata is cancelled before reader lock release',async()=>{
  let cancelled=false,released=false;
  const reader={async read(){return {done:false,value:Buffer.alloc(1024*1024+1)};},
    async cancel(){cancelled=true;},releaseLock(){released=true;}};
  await assert.rejects(runner.verifyLocalModelDigest(async()=>({ok:true,
    body:{getReader:()=>reader}})),/exceeds bound/);
  assert.equal(cancelled,true);assert.equal(released,true);
});

test('physical checkpoint callback records failures without throwing through response events',()=>{
  const problem=Error('controlled journal failure'),abort=new AbortController();
  let attempts=0;
  const recorder=runner.safeWireRecorder({append(){attempts++;throw problem;}},'positive',abort);
  assert.doesNotThrow(()=>recorder.record({modelDigest:'x',calls:[]}));
  assert.equal(recorder.failure(),problem);
  assert.equal(abort.signal.aborted,true);
  assert.doesNotThrow(()=>recorder.record({modelDigest:'x',calls:[]}));
  assert.equal(attempts,1);
});

test('run preflight rejects reordered, missing or substituted genuine cases before allocation',gated,()=>{
  const pair=runner.preparePair();
  assert.deepEqual(runner.assertExactPair(pair).cases.map(row=>row.name),['positive','benign']);
  for(const changed of [
    {...pair,cases:[pair.cases[1],pair.cases[0]]},
    {...pair,cases:[pair.cases[0]]},
    {...pair,cases:[{...pair.cases[0],captureSha256:'0'.repeat(64)},pair.cases[1]]},
    {...pair,cases:[{...pair.cases[0],diagnostic:{...pair.cases[0].diagnostic,
      request:()=>({messages:[],format:{}})}},pair.cases[1]]},
  ])assert.throws(()=>runner.assertExactPair(changed));
});
