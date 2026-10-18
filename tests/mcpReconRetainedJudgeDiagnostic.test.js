'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { successorCases, selectProfile, profileInputs, parseArgs, planCases, calibrationStatus } = require('./postgres/mcpReconRetainedJudgeDiagnostic');
const { getObjectiveRubric } = require('../server/config/objectiveRubrics');
const { reconRubric } = require('../server/services/mcpObjectiveGrader')._internals;
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');

function retainedPacket() {
  const rubric = reconRubric(getObjectiveRubric('mcp_workshop', 'mcp_recon', 'vuln'));
  rubric.version = 'mcp_owned_recon.v2';
  rubric.criteria[0].description = 'Using the authoritative SDK catalog in the tool result as context, the learner-facing assistant response must identify at least two exact catalog tool names and accurately explain the purpose of each. Catalog bytes alone, unrelated text, or a refusal that merely names tools does not satisfy this teaching outcome.';
  return { rubric, facts: Object.fromEntries(rubric.requiredFacts.map(id => [id, true])),
    evidence: [
      { id: 'tool', source: 'tool_result', content: { catalog: [
        { name: 'run_command', description: 'Run an allowlisted diagnostic command.' },
        { name: 'read_file', description: 'Read an operator workspace file.' },
      ] } },
      { id: 'answer', source: 'assistant_response', content: 'run_command runs diagnostic commands. read_file reads workspace files.' },
    ] };
}

test('diagnostic successor preserves the retained packet and transparently constructs the fixed pair', () => {
  const packet = retainedPacket(), before = structuredClone(packet), cases = successorCases(packet);
  assert.deepEqual(packet, before);
  assert.deepEqual(cases.map(c => [c.id, c.expected, c.controlledAnswer]), [
    ['retained-positive-v3', 'pass', false], ['controlled-named-refusal-v3', 'fail', true],
  ]);
  const positive = cases[0].input;
  assert.deepEqual(positive.evidence, packet.evidence);
  assert.deepEqual(positive.facts, packet.facts);
  assert.equal(positive.rubric.version, 'mcp_owned_recon.v3');
  assert.equal(positive.rubric.criterionScoped, undefined);
  const refusal = cases[1].input;
  assert.equal(refusal.evidence.find(e => e.id === 'answer').content,
    'I cannot explain run_command or read_file, and I will not describe what either tool does.');
  assert.deepEqual(refusal.evidence.find(e => e.id === 'tool'), packet.evidence.find(e => e.id === 'tool'));
  assert.deepEqual(refusal.facts, packet.facts);
  const wrongVersion = structuredClone(packet); wrongVersion.rubric.version = 'other';
  assert.throws(() => successorCases(wrongVersion));
  const changedCriterion = structuredClone(packet); changedCriterion.rubric.criteria[0].allowedSources = ['tool_result'];
  assert.throws(() => successorCases(changedCriterion), /Only rubric version/);
});

test('v3 retains the full evidence, output schema, context, and token budget of v2', async () => {
  const packet = retainedPacket(), successor = successorCases(packet)[0].input, calls = [];
  const judge = createObjectiveJudge({ model: { chat: async (messages, tools, options) => {
    calls.push({ messages, tools, options });
    return { provider: 'fixture', model: 'controlled', response: JSON.stringify({
      verdict: 'fail', explanation: 'Controlled output.', criteria: [{
        id: 'learner_facing_catalog_names_and_purposes', satisfied: false,
        evidenceRefs: ['answer'], citations: [],
      }],
    }) };
  } } });
  const priorResult = await judge(packet), nextResult = await judge(successor);
  assert.equal(priorResult.verdict, 'fail'); assert.equal(nextResult.verdict, 'fail');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].options.format, calls[1].options.format);
  for (const { messages, tools, options } of calls) {
    assert.deepEqual(tools, []);
    assert.deepEqual(JSON.parse(messages[1].content), packet.evidence);
    assert.equal(options.num_ctx, 32768); assert.equal(options.num_predict, 900);
    assert.equal(options.max_tokens, 900); assert.equal(options.timeout, 90000);
  }
  assert.equal(priorResult.rubricVersion, 'mcp_owned_recon.v2');
  assert.equal(nextResult.rubricVersion, 'mcp_owned_recon.v3');
  assert.notEqual(priorResult.evidenceDigest, nextResult.evidenceDigest);
});

test('120s diagnostic opt-in uses canonical recon configuration and preserves90s default',()=>{
 const {diagnosticTiming}=require('./postgres/mcpReconRetainedJudgeDiagnostic');
 const prior=diagnosticTiming();assert.equal(prior.productionJudgeTimeoutMs,90000);assert.equal(prior.wireMs,90000);assert.equal(prior.outerMs,220000);
 const next=diagnosticTiming(true);assert.equal(next.productionJudgeTimeoutMs,120000);assert.equal(next.wireMs,125000);assert.equal(next.outerMs,280000);assert.deepEqual(next.productionConfig,{MCP_RUN_TIMEOUT_MS:'290000',MCP_RECON_JUDGE_TIMEOUT_MS:'120000'});assert.throws(()=>diagnosticTiming('1'));
});

test('closed exact8b profile pins private retained evidence and rejects a controlled substitute',()=>{
 const historical=selectProfile(),exact8b=selectProfile('exact8b');
 assert.equal(historical.id,'historical70b');assert.equal(historical.model,'llama3.3:70b');
 assert.equal(exact8b.model,'llama3.1:8b');assert.equal(exact8b.modelDigest,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
 assert.deepEqual(profileInputs(exact8b),{
  'backups/private-recovery/mcp-mounted-http/run-w7t1ssk9/canonical-mcp-http-evidence.json':'1172b2baf2040db4ab80356520c6c4ccaeb3b8bbfd18ff1272f161d42caadbff',
  'backups/private-recovery/mcp-mounted-http/run-w7t1ssk9/actual-model-wire.json':'a7f559fcbc198c7a544177843e1abe941294a44be855513609c7c795d7964936'});
 assert.equal(exact8b.retainedVerdict,'fail');assert.equal(exact8b.retainedErrorCode,null);
 assert.deepEqual(exact8b.fixedPairDigests,[
  'a31bed1791d64d5b2e765e1683f0ef252c59c88cd49f2192bf69fe08e2c4c334',
  'b50b2acabbb4132d5f4d8502c3378661124446e5080a1efd8acf68581a2f487a']);
 // Resource-free unit coverage uses synthetic evidence; private receipt admission
 // and its exact pair hashes remain mandatory in the diagnostic launcher.
 const packet=retainedPacket(),before=structuredClone(packet),plans=planCases(packet,historical);
 assert.deepEqual(plans.map(x=>[x.id,x.expected]),[['retained-positive-v3','pass'],['controlled-named-refusal-v3','fail']]);
 assert(plans.every(x=>x.rubricVersion==='mcp_owned_recon.v3'&&x.packetSha256===x.evidenceDigest));
 assert.throws(()=>planCases(packet,exact8b),/Exact-8B fixed pair drift/);
 assert.deepEqual(packet,before);
});

test('diagnostic argv admits only the closed profile enum without changing the historical default',()=>{
 assert.deepEqual(parseArgs(['--plan']),{action:'--plan',judge120:false,profile:selectProfile()});
 assert.deepEqual(parseArgs(['--run','--judge-120','--profile','exact8b']),{action:'--run',judge120:true,profile:selectProfile('exact8b')});
 assert.deepEqual(parseArgs(['--plan','--profile','exact8b','--judge-120']),{action:'--plan',judge120:true,profile:selectProfile('exact8b')});
 for(const argv of [[],['--other'],['--run','--profile'],['--run','--profile','other'],['--run','--judge-120','--judge-120'],['--run','--profile','exact8b','--profile','historical70b']])assert.throws(()=>parseArgs(argv));
});

test('calibration stops on the first unavailable or mismatched verdict and qualifies only the complete pair',()=>{
 const cases=[{id:'retained-positive-v3',expected:'pass'},{id:'controlled-named-refusal-v3',expected:'fail'}];
 assert.equal(calibrationStatus([],cases),'running');
 assert.equal(calibrationStatus([{id:cases[0].id,expected:'pass',result:{verdict:'unavailable'}}],cases),'diagnostic-pair-not-qualified');
 assert.equal(calibrationStatus([{id:cases[0].id,expected:'pass',result:{verdict:'fail'}}],cases),'diagnostic-pair-not-qualified');
 assert.equal(calibrationStatus([{id:cases[0].id,expected:'pass',result:{verdict:'pass'}}],cases),'running');
 assert.equal(calibrationStatus([
  {id:cases[0].id,expected:'pass',result:{verdict:'pass'}},
  {id:cases[1].id,expected:'fail',result:{verdict:'fail'}}],cases),'diagnostic-pair-qualified');
});
