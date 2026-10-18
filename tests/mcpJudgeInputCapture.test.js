'use strict';
const assert=require('node:assert/strict');const test=require('node:test');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {createMcpJudgeInputCapture}=require('./postgres/mcpJudgeInputCapture');
const packet=(runId='run-1',objectiveId='objective-1')=>({rubric:{family:'SecureShop',scenario:'capture',objectiveId,
  version:'v1',mode:'vuln',outcomeIntent:'attack',requiredFacts:['observed'],criteria:[{id:'effect',description:'Effect occurred.',
    allowedSources:['server_observation']}]},facts:{observed:true},evidence:[{id:'receipt',source:'server_observation',content:{runId,effect:'completed'}}]});
const verdict=input=>({evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'pass'});
test('capture persists exact prepared packet before provider rejection and preserves the original failure',async()=>{const entries=[],failure=Object.assign(new Error('provider down'),{code:'PROVIDER_DOWN'});
  const capture=createMcpJudgeInputCapture({entries,judge:async()=>{throw failure;}});await assert.rejects(capture.judge(packet()),error=>error===failure);
  assert.equal(entries.length,1);assert.equal(entries[0].status,'threw');assert.equal(entries[0].errorCode,'PROVIDER_DOWN');
  assert.equal(entries[0].evidenceDigest,prepareJudgeInput(packet()).evidenceDigest);assert.deepEqual(entries[0].packet.evidence,packet().evidence);});
test('capture correlates distinct repeated calls and rejects a changed result digest',async()=>{const entries=[],capture=createMcpJudgeInputCapture({entries,judge:async input=>verdict(input)});
  await capture.judge(packet('run-1','one'));await capture.judge(packet('run-2','two'));assert.deepEqual(entries.map(x=>[x.objectiveId,x.runId,x.status]),
    [['one','run-1','returned'],['two','run-2','returned']]);const mismatch=createMcpJudgeInputCapture({entries:[],judge:async()=>({evidenceDigest:'0'.repeat(64),verdict:'pass'})});
  await assert.rejects(mismatch.judge(packet()),{code:'JUDGE_EVIDENCE_DIGEST_MISMATCH'});assert.equal(mismatch.entries[0].status,'threw');});
test('capture enforces independent count and aggregate byte ceilings',async()=>{const count=createMcpJudgeInputCapture({judge:async input=>verdict(input),maxEntries:1});
  await count.judge(packet());await assert.rejects(count.judge(packet('run-2')),/count capacity/);
  const bytes=createMcpJudgeInputCapture({judge:async input=>verdict(input),maxBytes:1024});
  await assert.rejects(bytes.judge({...packet(),evidence:[{id:'receipt',source:'server_observation',content:{runId:'run',effect:'x'.repeat(2000)}}]}),/byte capacity/);});

test('concurrent captures reserve terminal space and preserve the original provider failure',async()=>{
  const entries=[],failure=Object.assign(new Error('provider failed'),{code:'\u0000'.repeat(1000)});
  let release,calls=0;const wait=new Promise(resolve=>{release=resolve;});
  const capture=createMcpJudgeInputCapture({entries,maxBytes:2200,judge:async()=>{calls++;await wait;throw failure;}});
  const first=capture.judge(packet());
  await assert.rejects(capture.judge(packet('run-2')),/byte capacity/);
  release();await assert.rejects(first,error=>error===failure);
  assert.equal(calls,1);assert.equal(entries[0].status,'threw');assert.equal(entries[0].errorCode.length,128);
  assert.ok(Buffer.byteLength(JSON.stringify(entries))<=2200);
});
