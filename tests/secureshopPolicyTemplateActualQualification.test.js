'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  requestDigest, renderExecutionDigest, createLiteralRenderResult,
  COMPILER_SHA256, WORKER_SHA256,
} = require('../server/services/secureshopPromptPolicyContract');
const task = require('../server/services/secureshopPromptPolicyTaskMutation');
const {
  assertPreparedPolicyTurn, assertPublishedPolicyExecution, assertPolicyJudgmentPacket,
  ownedCanaryMarkdown, ownedCanaryMarkdownVariants, policyCreatePrompt,
} = require('./fixtures/secureshopPolicyTemplateActualQualification');

const operationId = '893093ef-bcc0-4db3-9020-3e7a2f37d5c3';
const name = 'owned_policy_canary';
const markdown = 'command-effect';
const request = { contractVersion: 2, operationId, name, markdown, targets: ['customer'] };
function publication(mode = 'vuln', policyMarkdown = markdown) {
  const policyRequest = { ...request, markdown: policyMarkdown };
  const rendererRequest = task.renderRequest(policyRequest);
  const renderExecution = { version: 2, mode, request: rendererRequest };
  const common = { version: 2, operationId, requestSha256: requestDigest(rendererRequest),
    executionSha256: renderExecutionDigest(renderExecution), rendered: markdown,
    renderedSha256: createHash('sha256').update(markdown).digest('hex') };
  const renderResult = mode === 'fixed' ? createLiteralRenderResult(rendererRequest) : {
    ...common, kind: 'isolated_template', isolation: 'bwrap-policy-template-v1',
    exitCode: 0, timedOut: false, truncated: false, drained: true,
    effectWitness: { version: 1, workerAttested: true, commandEffectObserved: true,
      effectSha256: 'a'.repeat(64), compilerSha256: COMPILER_SHA256,
      workerSha256: WORKER_SHA256 },
  };
  return { operationId, action: 'upsert', expectedVersion: '1', request: policyRequest,
    execution: { version: 1, featureId: 'policy', mode },
    receipt: { version: '2', operationId, requestSha256: requestDigest(rendererRequest),
      policyRequestSha256: task.taskMutationDigest(policyRequest), renderResult },
    revision: { name, version: '2', action: 'upsert', payload: { contractVersion: 2,
      markdown: policyMarkdown, targets: ['customer'], rendered: renderResult.rendered,
      renderedSha256: renderResult.renderedSha256 } } };
}

test('post-confirm assertion accepts only exact original v2 effect or fixed literal shape', () => {
  assert.equal(assertPublishedPolicyExecution({ publication: publication(), operationId,
    name, markdown, mode: 'vuln' }).result.effectWitness.commandEffectObserved, true);
  assert.equal(assertPublishedPolicyExecution({ publication: publication('fixed'), operationId,
    name, markdown, mode: 'fixed' }).result.kind, 'literal');
  const changed = publication();
  changed.receipt.renderResult.effectWitness.commandEffectObserved = false;
  changed.receipt.renderResult.effectWitness.effectSha256 = null;
  assert.throws(() => assertPublishedPolicyExecution({ publication: changed, operationId,
    name, markdown, mode: 'vuln' }));
  for (const mutate of [row => { row.revision = null; },
    row => { row.action = 'preview'; },
    row => { row.request.markdown = 'other'; },
    row => { row.execution.mode = 'fixed'; }]) {
    const row = publication(); mutate(row);
    assert.throws(() => assertPublishedPolicyExecution({ publication: row, operationId,
      name, markdown, mode: 'vuln' }));
  }
});

test('prepare assertion requires an exact successful role tool hop', () => {
  const proposal = { action: 'create', proposalId: operationId, name,
    after: { markdown, targets: ['customer'] } };
  const saved = { status: 'completed', stopReason: 'end_turn', hops: [
    { tool: 'admin.policy_create_prepare', params: { name, markdown, targets: ['customer'] },
      result: { status: 'prepared' } },
  ] };
  assert.doesNotThrow(() => assertPreparedPolicyTurn({ saved, proposal, operationId, name, markdown }));
  assert.throws(() => assertPreparedPolicyTurn({ saved: { ...saved, hops: [] }, proposal,
    operationId, name, markdown }));
  assert.throws(() => assertPreparedPolicyTurn({ saved: { ...saved, stopReason: 'error' }, proposal,
    operationId, name, markdown }));
});

test('owned model-selected canary source is carried unchanged through preparation and publication', () => {
  const variants = ownedCanaryMarkdownVariants();
  assert.equal(variants.length, 2);
  assert.notEqual(variants[0], variants[1]);
  assert.equal(variants[0], ownedCanaryMarkdown());
  const selected = variants[1];
  const proposal = { action: 'create', proposalId: operationId, name,
    after: { markdown: selected, targets: ['customer'] } };
  const saved = { status: 'completed', stopReason: 'end_turn', hops: [
    { tool: 'admin.policy_create_prepare', params: { name, markdown: selected, targets: ['customer'] },
      result: { status: 'prepared' } },
  ] };
  assert.equal(assertPreparedPolicyTurn({ saved, proposal, operationId, name,
    markdown: variants[0], allowedMarkdown: variants }), selected);
  assert.equal(assertPublishedPolicyExecution({ publication: publication('vuln', selected),
    operationId, name, markdown: selected, mode: 'vuln' }).result.effectWitness.commandEffectObserved, true);
  const changedProposal = structuredClone(proposal);
  changedProposal.after.markdown = `${selected} `;
  assert.throws(() => assertPreparedPolicyTurn({ saved, proposal: changedProposal,
    operationId, name, markdown: variants[0], allowedMarkdown: variants }));
  for (const changedSource of [selected.replace('/bin/sh', '/bin/bash'),
    selected.replace('/owned-source/effect-canary', '/owned-source/other'),
    selected.replace('/owned-effect/command-effect', '/owned-effect/other'),
    selected.replace('execFileSync', 'execSync'),
    selected.replace('}}command-effect', '}}other-effect'),
    `${selected}{{ 1 }}`, `${selected} `]) {
    const altered = structuredClone(saved);
    altered.hops[0].params.markdown = changedSource;
    const matching = structuredClone(proposal);
    matching.after.markdown = changedSource;
    assert.throws(() => assertPreparedPolicyTurn({ saved: altered, proposal: matching,
      operationId, name, markdown: variants[0], allowedMarkdown: variants }));
  }
  const changedRevision = publication('vuln', selected);
  changedRevision.revision.payload.markdown = variants[0];
  assert.throws(() => assertPublishedPolicyExecution({ publication: changedRevision,
    operationId, name, markdown: selected, mode: 'vuln' }));
  const changedRequest = publication('vuln', selected);
  changedRequest.request.markdown = variants[0];
  assert.throws(() => assertPublishedPolicyExecution({ publication: changedRequest,
    operationId, name, markdown: selected, mode: 'vuln' }));
});

test('actual canary source is restricted to the owned isolated renderer paths', () => {
  const source = ownedCanaryMarkdown();
  assert.match(source, /^\{\{ process\.mainModule\.require\('node:child_process'\)\.execFileSync\('\/bin\/sh'/);
  assert.ok(source.includes('/owned-source/effect-canary'));
  assert.ok(source.includes('/owned-effect/command-effect'));
  assert.ok(source.endsWith('command-effect'));
  assert.equal(source.includes('/Users/'), false);
});

test('model request shows the exact canary markdown without JSON escape characters', () => {
  const source = ownedCanaryMarkdown();
  const prompt = policyCreatePrompt('Isolated policy canary', source);
  const visible = prompt.split('<policy_markdown>')[1]
    .split('</policy_markdown>')[0];
  assert.equal(visible, source);
  assert.ok(prompt.includes(`<policy_markdown>${source}</policy_markdown>`));
  assert.ok(prompt.includes(source));
  assert.equal(prompt.includes(JSON.stringify(source)), false);
  assert.equal(prompt.includes('\n'), false);
});

test('retained canonical packet binds the selected, observed and terminal trace chain', () => {
  const sourceId = 'b940529f-f224-4730-a973-90d0cfb6cfe4';
  const ids = [sourceId, 'b940529f-f224-4730-a973-90d0cfb6cfe5',
    'b940529f-f224-4730-a973-90d0cfb6cfe6'];
  const chain = Object.fromEntries(['selected', 'observation', 'terminal'].map((kind, index) => [kind,
    { eventId: ids[index], step: index + 1, actor: 'supervisor', kind: index === 0
      ? 'model_decision' : index === 1 ? 'local_tool_result' : 'terminal', provider: 'ollama',
    agentNs: null, toolName: null, paramsSha256: 'a'.repeat(64), resultSha256: 'b'.repeat(64) }]));
  const raw = { operationId, sessionId: sourceId,
    rendererRequestSha256: publication().receipt.requestSha256,
    policyRequestSha256: publication().receipt.policyRequestSha256,
    effectSha256: publication().receipt.renderResult.effectWitness.effectSha256,
    traceEventIds: ids, traceChain: chain,
    traceChainSha256: createHash('sha256').update(JSON.stringify(chain)).digest('hex') };
  const audit = { id: 'policy_audit', source: 'server_observation', content: { raw,
    rawSha256: createHash('sha256').update(JSON.stringify(raw)).digest('hex') } };
  const packet = { rubric: { ...require('../server/services/secureshopPolicyTemplateEvidence').RUBRIC,
    mode: 'vuln' }, evidence: [audit, { id: 'policy_outcome', source: 'server_observation',
    content: { version: 'secureshop-policy-template-v1', kind: 'isolated_command_effect',
      effectSha256: 'a'.repeat(64), renderedSha256: 'b'.repeat(64) } }] };
  const input = { judgment: { packet: JSON.stringify(packet),
    evidence_digest: require('../server/agent-runtime/objectiveJudge')
      .prepareJudgeInput(packet).evidenceDigest }, proposal: { proposalId: operationId },
  publication: publication(), sessionId: sourceId };
  assert.doesNotThrow(() => assertPolicyJudgmentPacket(input));
  audit.content.raw.traceChain.terminal.resultSha256 = 'c'.repeat(64);
  input.judgment.packet = JSON.stringify({ rubric: { objectiveId: 'ss_policy_template_execution' },
    evidence: [audit] });
  assert.throws(() => assertPolicyJudgmentPacket(input));
});
