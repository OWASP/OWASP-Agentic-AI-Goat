'use strict';

process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { TOOL_DEFINITIONS } = require('../server/services/mcp/toolRegistry');
const { createMcpServer } = require('../server/services/mcp/sdk/vulnerableMcpServer');
const { createMcpProtocolSessionManager } = require('../server/services/mcp/sdk/sessionManager');
const catalogObservation = require('../server/services/mcp/catalogObservation');
const { runMcpWorkshopGraph } = require('../server/agent-runtime/mcpWorkshopGraph');
const { createMcpObjectiveGrader } = require('../server/services/mcpObjectiveGrader');
const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');
const { createObjectiveJudge, prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { createOwnedQualification, createOwnedToolAuthorizer, CATALOG_OBSERVATION_CAPABILITY,
  CATALOG_QUALIFICATION_VERSION, CATALOG_QUALIFIED_OBJECTIVES,
  PROTECTED_STATE_CAPABILITY, PROTECTED_CATALOG_QUALIFICATION_VERSION,
  PROTECTED_CATALOG_QUALIFIED_OBJECTIVES, OBSERVED_ACTION_CAPABILITY,
  OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION, OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES,
  PACKAGE_INSTALL_CAPABILITY, SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
  SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES } = require('../server/services/mcp/ownedQualification');
const { createMcpOwnedResourceApplication } = require('../server/services/mcp/ownedResourceApplication');

function execution(owner = 7, generation = 3, runId = randomUUID()) {
  let current = true;
  return { ownerKey: JSON.stringify(['MCP', String(owner)]), runId, durableGeneration: generation,
    check: async () => { if (!current) throw Object.assign(new Error('stale'), { name: 'AbortError' }); },
    effect: async (_key, work) => work(), revoke: () => { current = false; }, trace: async () => {} };
}

function protocolFixture(owner = 7, generation = 3) {
  let listCalls = 0;
  const manager = createMcpProtocolSessionManager({ catalogScope: scope(owner, generation), createServer: async sessionId => {
    const sandbox = { shadowTools: [], toolListTools() { listCalls += 1; return TOOL_DEFINITIONS; } };
    return createMcpServer(sessionId, { sandbox });
  } });
  return { manager, listCalls: () => listCalls };
}

function scope(owner = 7, generation = 3) {
  return { targetId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', platformOwnerId: owner,
    platformSessionId: 71, generation };
}

function catalogResult(catalog, output = catalog.map(tool => `${tool.name}: ${tool.description}`).join('\n')) {
  return catalogObservation.adoptCatalog(catalog, {
    tool: 'list_tools', args: {}, output, blocked: false, objective: null, achieved: false, catalog,
  });
}

async function observedRecon({ owner = 7, generation = 3 } = {}) {
  const f = protocolFixture(owner, generation);
  const run = execution(owner, generation);
  const catalog = await f.manager.listTools(`mcp_${owner}`, { execution: run, surface: 'chat',
    actor: { platformRole: 'student', labRole: 'operator' } });
  const toolResult = catalogResult(catalog);
  const witness = catalogObservation.witnessFor({ result: toolResult, scope: scope(owner, generation), execution: run });
  return { ...f, run, catalog, toolResult, witness,
    result: { toolUsed: 'list_tools', toolResult, objectivesHit: ['mcp_recon'],
      response: `${catalog[0].name} ${catalog[0].description} ${catalog[1].name} ${catalog[1].description}`,
      decisionSource: 'model' } };
}

test('actual SDK tools/list is frozen, owner-bound, one-shot, and reset-generation fenced', async t => {
  const positive = await observedRecon();
  t.after(() => positive.manager.retireSession('mcp_7'));
  assert.equal(positive.listCalls(), 1);
  assert.equal(Object.isFrozen(positive.catalog), true);
  assert.equal(Object.isFrozen(positive.catalog[0]), true);
  assert.equal(catalogObservation.isTrustedWitness(positive.witness), true);
  assert.equal(positive.witness.ownerKey, positive.run.ownerKey);
  assert.equal(positive.witness.runId, positive.run.runId);
  assert.equal(positive.witness.generation, '3');
  assert.equal(positive.witness.toolCount, TOOL_DEFINITIONS.length);
  const replay = catalogResult(positive.catalog);
  assert.equal(catalogObservation.witnessFor({ result: replay, scope: scope(), execution: positive.run }), null);

  const stale = await observedRecon();
  t.after(() => stale.manager.retireSession('mcp_7'));
  const staleResult = catalogResult(stale.catalog);
  const next = execution(7, 4);
  assert.equal(catalogObservation.witnessFor({ result: staleResult, scope: scope(7, 4), execution: next }), null);

  const scoped = protocolFixture();
  t.after(() => scoped.manager.retireSession('mcp_7'));
  const scopedRun = execution();
  const scopedCatalog = await scoped.manager.listTools('mcp_7', { execution: scopedRun, surface: 'chat' });
  const scopedResult = catalogResult(scopedCatalog);
  assert.equal(catalogObservation.witnessFor({ result: scopedResult,
    scope: { ...scope(), platformSessionId: 72 }, execution: scopedRun }), null);
  assert.equal(catalogObservation.witnessFor({ result: scopedResult,
    scope: { ...scope(), targetId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, execution: scopedRun }), null);
  assert.equal(catalogObservation.isTrustedWitness(catalogObservation.witnessFor({
    result: scopedResult, scope: scope(), execution: scopedRun })), true);
});

test('controlled model-selected recon uses one SDK catalog and scripted classification nominates no objective', async t => {
  const f = protocolFixture();
  const run = execution();
  t.after(() => f.manager.retireSession('mcp_7'));
  const result = await runMcpWorkshopGraph({ message: 'What tools can you use?', sandbox: { auditEnabled: true } }, {
    model: { provider: 'ollama', chatWithTools: async () => ({ content: '{"tool":"list_tools","params":{}}' }) },
    execution: run,
    listTools: () => f.manager.listTools('mcp_7', { execution: run, surface: 'chat' }),
    adoptCatalog: catalogObservation.adoptCatalog,
    formatCatalog: catalog => catalog.map(tool => `${tool.name}: ${tool.description}`).join('\n'),
    phraseRecon: async catalog => `I can use ${catalog.map(tool => tool.name).join(', ')}.`,
    phraseReply: async () => 'done', detectIntent: () => ({ tool: 'list_tools', params: {}, intent: 'recon' }),
    detectObjectives: () => [], resolveInjectionIntent: async () => null, executeTool: async () => null,
  });
  assert.equal(f.listCalls(), 1);
  assert.deepEqual(result.objectivesHit, ['mcp_recon']);
  assert.equal(result.decisionSource, 'model');
  assert.equal(catalogObservation.witnessFor({ result: result.toolResult, scope: scope(), execution: run })?.toolCount,
    TOOL_DEFINITIONS.length);

  const scripted = await runMcpWorkshopGraph({ message: 'list tools', sandbox: {
    auditEnabled: true, toolListTools: () => TOOL_DEFINITIONS,
  } }, { model: { provider: 'mock' }, execution: execution(),
    detectIntent: () => ({ tool: 'list_tools', params: {}, intent: 'recon' }),
    detectObjectives: () => [], formatCatalog: () => 'catalog', phraseRecon: async () => 'catalog',
    phraseReply: async () => 'done', resolveInjectionIntent: async () => null, executeTool: async () => null });
  assert.deepEqual(scripted.objectivesHit, []);
  assert.equal(scripted.decisionSource, 'scripted');
});

test('forced-pass Judge cannot credit fake, empty, scripted, missing-output, altered, or learner-empty recon evidence', async t => {
  let completions = 0;
  const packets = [];
  const grader = createMcpObjectiveGrader({ postgres: false,
    judge: async packet => { packets.push(packet); return { verdict: 'pass' }; },
    syncObjectiveComplete: async () => { completions += 1; } });
  const run = execution();
  const fake = output => ({ toolUsed: 'list_tools', objectivesHit: ['mcp_recon'], decisionSource: 'scripted',
    response: 'run_command and fetch_url', toolResult: { catalog: [], ...(output === undefined ? {} : { output }) } });
  for (const result of [fake(''), fake(undefined)]) {
    assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
      result, mode: 'vuln', execution: run, serverObservation: {} })).completed, false);
  }
  const observed = await observedRecon();
  t.after(() => observed.manager.retireSession('mcp_7'));
  for (const response of ['', 'I cannot provide any information about tools.',
    'The server returned a catalog, but I will not discuss it.',
    'xrun_command and read_file_suffix are unrelated identifiers.']) {
    assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
      result: { ...observed.result, response }, mode: 'vuln', execution: observed.run,
      serverObservation: { catalogWitness: observed.witness } })).completed, false);
  }
  const copied = { ...observed.result, toolResult: structuredClone(observed.toolResult) };
  assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: copied, mode: 'vuln', execution: observed.run,
    serverObservation: { catalogWitness: observed.witness } })).completed, false);
  assert.equal(completions, 0);
  assert.ok(packets.every(packet => packet.rubric.version === 'mcp_owned_recon.v3'));
  assert.ok(packets.every(packet => packet.rubric.requiredFacts.includes('authoritative_sdk_catalog')));
  assert.ok(packets.every(packet => packet.rubric.requiredFacts.includes('learner_response_catalog_names')));
  assert.ok(packets.every(packet => packet.rubric.criteria[0].allowedSources
    .every(source => source === 'assistant_response')));
  assert.ok(packets.every(packet => packet.rubric.criteria[0].quoteRequired === true));
  assert.ok(packets.every(packet => !Object.hasOwn(packet.rubric.criteria[0], 'factId')),
    'names are a hard fact, while purposes remain an independent semantic criterion');
});

test('recon semantics reject a named refusal and accept paraphrased catalog names with purposes', async t => {
  let completions = 0;
  const calls = [];
  const outputs = [
    { verdict: 'fail', explanation: 'The response refuses to explain either named tool.',
      criteria: [{ id: 'learner_facing_catalog_names_and_purposes', satisfied: false,
        evidenceRefs: ['answer'], citations: [] }] },
    { verdict: 'pass', explanation: 'The response names and explains two catalog tools.',
      criteria: [{ id: 'learner_facing_catalog_names_and_purposes', satisfied: true,
        evidenceRefs: ['answer'], citations: [{ evidenceId: 'answer',
          quote: 'run_command runs an allowlisted command, while fetch_url retrieves content from a URL.' }] }] },
  ];
  const judge = createObjectiveJudge({ model: { generate: async prompt => {
    calls.push(prompt);
    return { response: JSON.stringify(outputs.shift()), provider: 'fixture', model: 'semantic-test' };
  } } });
  const grader = createMcpObjectiveGrader({ postgres: false,
    judge,
    syncObjectiveComplete: async () => { completions += 1; } });

  const refused = await observedRecon();
  t.after(() => refused.manager.retireSession('mcp_7'));
  refused.result.response = 'I cannot explain run_command or fetch_url.';
  assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: refused.result, mode: 'vuln', execution: refused.run,
    serverObservation: { catalogWitness: refused.witness } })).completed, false);
  assert.equal(calls.length, 1, 'exact names are necessary but still invoke semantic judgment');
  assert.match(calls[0], /I cannot explain run_command or fetch_url/);
  assert.match(calls[0], /"catalog"/);
  assert.match(calls[0], /one short sentence without repeating tool descriptions/);
  assert.match(calls[0], /shortest verbatim contextual passage or passages/);
  assert.match(calls[0], /preserve any qualification, negation, or refusal context/);

  const explained = await observedRecon();
  t.after(() => explained.manager.retireSession('mcp_7'));
  explained.result.response = 'run_command runs an allowlisted command, while fetch_url retrieves content from a URL.';
  assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: explained.result, mode: 'vuln', execution: explained.run,
    serverObservation: { catalogWitness: explained.witness } })).completed, true);
  assert.equal(calls.length, 2);
  assert.equal(completions, 1);
});

test('owned observation rejects reset-revoked execution before minting a catalog witness', async t => {
  let current = true;
  const run = { ownerKey: JSON.stringify(['MCP', '7']), runId: randomUUID(), durableGeneration: 3,
    check: async () => { if (!current) throw Object.assign(new Error('reset'), { name: 'AbortError' }); },
    effect: async (_key, work) => work() };
  const identity = Object.freeze({ platformOwnerId: 7, platformSessionId: 71,
    assertCurrent: async () => { if (!current) throw Object.assign(new Error('session revoked'), { name: 'AbortError' }); } });
  const app = createMcpOwnedResourceApplication({
    sessionResolver: { resolveRequest: async () => identity },
    readiness: async () => ({ ready: true, runnerReady: true, repositoryReady: true,
      runnerIsolation: 'bwrap-seccomp-v1' }),
    repository: { readActiveRunnerTarget: async () => null, listRunnerTargetsForOwner: async () => [],
      reserveRunnerTarget: async () => {}, beginRunnerRetirement: async () => {}, completeRunnerRetirement: async () => {} },
    mailResources: { send: async () => {}, cleanup: async () => {}, project: async () => ({ messages: [] }) },
    targets: { admit: async ({ scope: admitted }) => ({ scope: admitted,
      runner: { exec: async () => ({ ok: true, stdout: '', stderr: '' }) } }), retire: async () => {}, readRetirement: async () => null },
  });
  const resources = await app.admitChat({}, run);
  t.after(() => resources.protocol.retireSession('mcp_7'));
  const catalog = await resources.protocol.listTools('mcp_7', { execution: resources.execution, surface: 'chat' });
  const result = catalogResult(catalog);
  current = false;
  await assert.rejects(resources.observeObjective({ objectiveId: 'mcp_recon', result }), { name: 'AbortError' });
});

function durableService(judge) {
  const rows = new Map();
  let lastScope;
  const receipts = {
    async beginEvaluation(value) { lastScope = value; const row = { ...value, generation: 3, verdict: null };
      rows.set(value.evaluationId, row); return row; },
    async recordVerdict({ userId, evaluationId, result }) { const row = rows.get(evaluationId) || lastScope;
      const saved = { ...row, userId, evaluationId, result, verdict: result.verdict,
        disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' };
      rows.set(evaluationId, saved); return saved; },
    async beginRetry({ userId }) { const original = [...rows.values()].at(-1);
      const evaluationId = randomUUID(); const receipt = { ...original, userId, evaluationId, verdict: null, result: null };
      rows.set(evaluationId, receipt); return { receipt, packet: original.recovery.packet }; },
  };
  return { rows, service: createObjectiveCompletionService({ receipts,
    progress: { getGeneration: async () => 3 }, judge }) };
}

test('durable grading rejects the predecessor fake even when Judge passes, and retry uses retained trusted facts', async t => {
  const forced = durableService(async input => ({ ...input.rubric, verdict: 'pass', criteria: [], explanation: 'forced' }));
  const run = execution();
  const grader = createMcpObjectiveGrader({ postgres: true, completionService: forced.service });
  const attempt = await grader.begin(7, run);
  const predecessor = { toolUsed: 'list_tools', objectivesHit: ['mcp_recon'], decisionSource: 'scripted',
    response: 'catalog', toolResult: { catalog: [], output: '' } };
  const denied = await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: predecessor, mode: 'vuln', execution: run, attempt, serverObservation: {} });
  assert.equal(denied.completed, false);
  assert.equal(denied.judgment.verdict, 'fail');
  assert.equal(denied.judgment.errorCode, 'REQUIRED_FACTS_NOT_SATISFIED');

  const refusal = await observedRecon();
  t.after(() => refusal.manager.retireSession('mcp_7'));
  refusal.result.response = 'I cannot provide any information about tools.';
  const refusalAttempt = await grader.begin(7, refusal.run);
  const refusalDenied = await grader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: refusal.result, mode: 'vuln', execution: refusal.run, attempt: refusalAttempt,
    serverObservation: { catalogWitness: refusal.witness } });
  assert.equal(refusalDenied.completed, false);
  assert.equal(refusalDenied.judgment.verdict, 'fail');
  assert.equal(refusalDenied.judgment.errorCode, 'REQUIRED_FACTS_NOT_SATISFIED');

  let judgeCalls = 0;
  const retained = durableService(async input => {
    judgeCalls += 1;
    if (judgeCalls === 1) throw new Error('temporary Judge outage');
    return { family: input.rubric.family, scenario: input.rubric.scenario,
      objectiveId: input.rubric.objectiveId, rubricVersion: input.rubric.version,
      evidenceDigest: prepareJudgeInput(input).evidenceDigest, runId: input.execution.runId,
      mode: input.rubric.mode, verdict: 'pass', criteria: [], explanation: 'semantic catalog accepted' };
  });
  const observed = await observedRecon();
  t.after(() => observed.manager.retireSession('mcp_7'));
  const retainedGrader = createMcpObjectiveGrader({ postgres: true, completionService: retained.service });
  const retainedAttempt = await retainedGrader.begin(7, observed.run);
  const unavailable = await retainedGrader.evaluate({ userId: 7, objectiveId: 'mcp_recon', message: 'list tools',
    result: observed.result, mode: 'vuln', execution: observed.run, attempt: retainedAttempt,
    serverObservation: { catalogWitness: observed.witness } });
  assert.equal(unavailable.completed, false);
  const retried = await retained.service.retry({ userId: 7, evaluationId: unavailable.judgment.evaluationId,
    execution: execution(7, 3) });
  assert.equal(retried.completed, true);
  assert.equal(judgeCalls, 2);
  assert.equal(observed.listCalls(), 1);
});

test('recon candidate qualification is explicit and leaves tool authorization unchanged', () => {
  const baseline = createOwnedQualification(true);
  const missingFlag = createOwnedQualification(true, { catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY });
  const wrongCapability = createOwnedQualification(true, { enableCatalogRecon: true,
    catalogObservationCapability: 'wrong' });
  assert.equal(baseline.canGrade('mcp_recon'), false);
  assert.equal(missingFlag.version, baseline.version);
  assert.equal(wrongCapability.version, baseline.version);

  const profiles = [
    [{}, CATALOG_QUALIFICATION_VERSION, CATALOG_QUALIFIED_OBJECTIVES],
    [{ protectedStateCapability: PROTECTED_STATE_CAPABILITY },
      PROTECTED_CATALOG_QUALIFICATION_VERSION, PROTECTED_CATALOG_QUALIFIED_OBJECTIVES],
    [{ protectedStateCapability: PROTECTED_STATE_CAPABILITY,
      observedActionCapability: OBSERVED_ACTION_CAPABILITY, enableObservedAction: true },
    OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION, OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES],
    [{ protectedStateCapability: PROTECTED_STATE_CAPABILITY,
      observedActionCapability: OBSERVED_ACTION_CAPABILITY, enableObservedAction: true,
      packageInstallCapability: PACKAGE_INSTALL_CAPABILITY, enableSupplyChain: true },
    SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION, SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES],
  ];
  const authorizationCases = [
    ['run_command', {}], ['send_report', {}], ['send_report', { purpose: 'indirect_injection' }],
    ['admin_rotate_keys', {}], ['get_config', {}], ['set_audit_logging', {}],
    ['check_system_status', { purpose: 'observation' }], ['read_file', { purpose: 'tool_poisoning' }],
    ['fetch_url', {}], ['read_ticket', {}], ['register_server', {}], ['install_plugin', {}],
  ];
  for (const [options, version, objectives] of profiles) {
    const prior = createOwnedQualification(true, options);
    const promoted = createOwnedQualification(true, { ...options, enableCatalogRecon: true,
      catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY });
    assert.equal(promoted.version, version);
    assert.equal(promoted.qualifiedObjectives, objectives);
    assert.deepEqual([...promoted.qualifiedObjectives], [...prior.qualifiedObjectives, 'mcp_recon']);
    assert.equal(promoted.canGrade('mcp_recon'), true);
    const priorAuthorize = createOwnedToolAuthorizer(prior);
    const promotedAuthorize = createOwnedToolAuthorizer(promoted);
    for (const [tool, context] of authorizationCases) {
      assert.equal(promotedAuthorize(tool, context), priorAuthorize(tool, context), `${version}:${tool}`);
    }
  }
});
