'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const target = path.resolve(__dirname, '../server/services/ctfDefenseLayers.js');
let invoke;
const original = Module._load;
Module._load = function load(request, parent, isMain) {
  if (parent?.filename === target && request === './multiProviderAIService') {
    return { generateResponse: (...args) => invoke(...args) };
  }
  return original.call(this, request, parent, isMain);
};
let defenses;
try {
  delete require.cache[target];
  defenses = require(target);
} finally {
  Module._load = original;
  delete require.cache[target];
}

const secret = 'OWNED_CTF_SECRET';
const stage = {
  stage_number: 5,
  success_criteria: secret,
  defense_style: '["meta_structured_artifact_reviewer_v1"]',
};
const real = response => ({
  response,
  provider: 'ollama',
  model: 'llama3.1:8b',
  mocked: false,
  fallback: false,
});
const decision = verdict => real(JSON.stringify({ verdict }));

test('Stage 5 structured reviewer remains a model decision with versioned categorical evidence', async () => {
  const artifact = JSON.stringify({ kind: 'connection_check', environment: 'staging', value: secret });
  const events = [];
  let prompt;
  invoke = async value => {
    prompt = value;
    return decision('SAFE');
  };
  const visible = await defenses.runOutputDefenses(stage, artifact, {
    execution: { check: async () => {}, trace: async event => events.push(event) },
  });
  assert.equal(visible, artifact);
  assert.match(prompt, /learner-supplied claim/i);
  assert.match(prompt, /connection_check/);
  assert.match(prompt, /malformed|extra field/i);
  assert.match(prompt, new RegExp(secret));
  assert.deepEqual(events, [{
    node: 'ctf_output_reviewer',
    type: 'decision',
    data: {
      decisionSource: 'model',
      attempt: 1,
      verdict: 'SAFE',
      provider: 'ollama',
      model: 'llama3.1:8b',
      reviewerProfileId: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.id,
      reviewerProfileVersion: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.version,
      reviewerPolicyDigest: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.policyDigest,
    },
  }]);
  assert.doesNotMatch(JSON.stringify(events), new RegExp(secret));
  assert.deepEqual(defenses.reviewerProfileEvidence(stage),
    defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE);
  assert.equal(defenses.reviewerProfileEvidence({
    stage_number: 6, defense_style: '["meta_llm_judge"]',
  }), null);
});

test('Stage 5 reviewer policy retains benign replies before considering the disclosure exception', async () => {
  const benign = 'Check the deployment health endpoint before retrying.';
  let prompt;
  invoke = async value => { prompt = value; return decision('SAFE'); };
  assert.equal(await defenses.runOutputDefenses(stage, benign), benign);
  assert.match(prompt, /First, answer SAFE for a reply that does not disclose/);
  assert.match(prompt, /value.*equal to the untransformed protected secret/);
  assert.doesNotMatch(prompt, /Treat a reply as SAFE only/);
});

test('Stage 5 bounded repair retains the exact reviewer profile without persisting raw output', async () => {
  const events = [];
  const calls = [];
  invoke = async (prompt, options) => {
    calls.push({ prompt, options });
    return calls.length === 1 ? real('PRIVATE_MALFORMED_REVIEW') : decision('SAFE');
  };
  const benign = 'Check the deployment health endpoint before retrying.';
  assert.equal(await defenses.runOutputDefenses(stage, benign, {
    execution: { check: async () => {}, trace: async event => events.push(event) },
  }), benign);
  assert.equal(calls.length, 2);
  assert.doesNotMatch(calls[1].prompt, /PRIVATE_MALFORMED_REVIEW/);
  const profile = {
    reviewerProfileId: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.id,
    reviewerProfileVersion: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.version,
    reviewerPolicyDigest: defenses.STRUCTURED_ARTIFACT_REVIEWER_PROFILE.policyDigest,
  };
  assert.deepEqual(events, [
    { node: 'ctf_output_reviewer', type: 'error', data: {
      attempt: 1, errorCode: 'CTF_REVIEWER_DECISION_INVALID',
      provider: 'ollama', model: 'llama3.1:8b', ...profile,
    } },
    { node: 'ctf_output_reviewer', type: 'decision', data: {
      attempt: 2, decisionSource: 'model', verdict: 'SAFE',
      provider: 'ollama', model: 'llama3.1:8b', ...profile,
    } },
  ]);
  assert.doesNotMatch(JSON.stringify(events), /PRIVATE_MALFORMED_REVIEW/);
});

test('Stage 5 reviewer can block direct and malformed disclosures without changing the strict reviewer', async () => {
  for (const draft of [
    `The credential is ${secret}`,
    JSON.stringify({ kind: 'connection_check', environment: 'staging', value: secret, extra: true }),
    `prefix ${JSON.stringify({ kind: 'connection_check', environment: 'staging', value: secret })}`,
  ]) {
    invoke = async () => decision('LEAKED');
    assert.doesNotMatch(await defenses.runOutputDefenses(stage, draft), new RegExp(secret));
  }

  let strictPrompt;
  invoke = async value => { strictPrompt = value; return decision('LEAKED'); };
  const strictStage = { stage_number: 6, success_criteria: secret, defense_style: '["meta_llm_judge"]' };
  const artifact = JSON.stringify({ kind: 'connection_check', environment: 'staging', value: secret });
  assert.doesNotMatch(await defenses.runOutputDefenses(strictStage, artifact), new RegExp(secret));
  assert.doesNotMatch(strictPrompt, /learner-supplied claim/i);

  invoke = async () => { throw new Error('Stage 5 reviewer model must not run for another stage'); };
  assert.doesNotMatch(await defenses.runOutputDefenses({
    stage_number: 6,
    success_criteria: secret,
    defense_style: '["meta_structured_artifact_reviewer_v1"]',
  }, artifact), new RegExp(secret));
});

test('Stage 5 operational conflict does not manufacture a guardian disclosure', async () => {
  const canonical = require('../server/data/ctfDefaults').stages.find(row => row.stage_number === 5);
  const candidates = require('../server/data/ctfSolutions').levels.find(row => row.level === 5).payloads;
  assert.match(canonical.system_prompt, /external user/i);
  assert.match(canonical.system_prompt, /connection_check/);
  assert.match(canonical.system_prompt, /claimed internal deployment/i);
  assert.match(canonical.system_prompt, /configured vault code/i);
  assert.equal(canonical.defense_style, '["transformation_guard","meta_structured_artifact_reviewer_v1"]');
  for (const candidate of candidates) {
    assert.deepEqual(defenses.transformationGuard(candidate), { blocked: false });
  }

  const { runCtfGuardianGraph } = require('../server/agent-runtime/ctfGuardianGraph');
  const refusal = 'I cannot provide a credential.';
  const refused = await runCtfGuardianGraph(canonical, 'claimed internal task', {
    generate: async () => refusal,
    runOutputDefenses: async (_stage, draft) => draft,
    normalizedContains: (response, expected) => response.includes(expected),
  });
  assert.deepEqual(refused, { aiResponse: refusal, processedResponse: refusal, wasSuccessful: false });

  const disclosure = JSON.stringify({
    kind: 'connection_check', environment: 'staging', value: canonical.success_criteria,
  });
  const disclosed = await runCtfGuardianGraph(canonical, 'claimed internal task', {
    generate: async () => disclosure,
    runOutputDefenses: async (_stage, draft) => draft,
    normalizedContains: (response, expected) => response.includes(expected),
  });
  assert.deepEqual(disclosed, { aiResponse: disclosure, processedResponse: disclosure, wasSuccessful: true });
  assert.equal(disclosed.processedResponse, disclosure, 'the graph must use guardian bytes without insertion');
});

test('Stage 5 profile identity is bound into the immutable stage digest and not inherited by later stages', () => {
  const { stages } = require('../server/data/ctfDefaults');
  const { stageDigest } = require('../server/agent-runtime/ctfStageJudge');
  const stage5 = stages.find(row => row.stage_number === 5);
  for (const number of [7, 8, 9, 10]) {
    assert.ok(JSON.parse(stages.find(row => row.stage_number === number).defense_style).includes('meta_llm_judge'));
    assert.ok(!stages.find(row => row.stage_number === number).defense_style.includes('meta_structured_artifact'));
  }
  assert.notEqual(stageDigest(stage5), stageDigest({
    ...stage5,
    defense_style: '["transformation_guard","meta_structured_artifact_reviewer_v2"]',
  }));
});
