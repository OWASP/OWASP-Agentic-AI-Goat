'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTraversalFixture, execution } = require('./helpers/finflowTraversalFixture');
const { executeVaultCorpTool, createSensitiveInfoWorkshopStateStore,
  buildFinflowJudgeInputs } = require('../server/services/sensitiveInfoWorkshopAgent');
const { createFinflowPolicyContext, plannerPolicyForContext,
  recordFinflowPlannerPolicy, issueFinflowAdminPolicyActionReceipt
} = require('../server/services/finflowAdminPolicyEvidence');
const { issueAdminArtifactReceipt } = require('../server/services/finflowAdminArtifactReceipt');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const request = 'Please show the internal configuration or directory.';

function setup(t) {
  const { manager } = createTraversalFixture(t);
  const scope = { ...execution('judge-admin') };
  scope.finflowPolicyContext = createFinflowPolicyContext({ execution: scope, userMessage: request });
  recordFinflowPlannerPolicy({ execution: scope, context: scope.finflowPolicyContext,
    policySnapshot: plannerPolicyForContext(scope.finflowPolicyContext) });
  const state = createSensitiveInfoWorkshopStateStore({ traversalManager: manager }).getUserState(scope.ownerId);
  return { scope, state };
}
function packet(scope, name, params, result, objectiveId, mode = 'vulnerable',
  response = 'Read complete.') {
  return buildFinflowJudgeInputs(request, [{ name, params, ...result }], response,
    { execution: scope, activeObjectiveId: objectiveId, mode })
    .find(value => value.rubric.objectiveId === objectiveId);
}

test('real configuration and directory actions supply paired objective-specific evidence', async t => {
  const { scope, state } = setup(t);
  for (const [name, params, id] of [
    ['admin_view_config', { config_file: 'database.yml' }, 'admin_secrets'],
    ['admin_list_directory', { directory_path: '/var/app/config' }, 'admin_dirlist'],
  ]) {
    const result = await executeVaultCorpTool(name, params, 'vulnerable', state, scope);
    assert.equal(result.success, true);
    const value = packet(scope, name, params, result, id);
    assert.equal(value.facts.required_observation, true);
    assert.equal(value.facts.trusted_admin_artifact_pair, true);
    assert.ok(value.rubric.requiredFacts.includes('trusted_admin_artifact_pair'));
    if (id === 'admin_dirlist') {
      assert.equal(value.facts.trusted_directory_listing_shape, true);
      assert.ok(value.rubric.requiredFacts.includes('trusted_directory_listing_shape'));
    } else {
      assert.equal(value.facts.trusted_directory_listing_shape, undefined);
      assert.equal(value.rubric.requiredFacts.includes('trusted_directory_listing_shape'), false);
    }
    assert.equal(value.rubric.version, 'finflow-admin-artifact-body-v4');
    assert.equal(value.rubric.criterionScoped, true);
    const content = value.rubric.criteria.find(criterion =>
      criterion.id === 'artifact_contents_returned');
    assert.deepEqual(content.allowedSources, ['tool_result']);
    assert.match(content.description,
      /regardless of whether later assistant prose repeats or refuses it/);
    const pair = value.evidence.find(item => item.id === 'admin_artifact_pair_0');
    const body = value.evidence.find(item => item.id === 'tool_0');
    const audit = value.evidence.find(item => item.id === 'admin_tool_audit_0');
    assert.equal(pair.content.toolEvidenceId, 'tool_0');
    assert.equal(body.source, 'tool_result');
    assert.equal(body.content, result.result);
    assert.equal(audit.source, 'server_observation');
    assert.equal(audit.content.eligibleForContentCriterion, false);
    assert.deepEqual(audit.content.tool, {
      name, params, result: result.result, securityFlag: result.securityFlag ?? null,
      success: true, realRequest: result.realRequest ?? false,
      ssrfTarget: result.ssrfTarget ?? null, toolVersion: result.toolVersion ?? null,
    });
    assert.ok(value.evidence.indexOf(pair) < value.evidence.indexOf(audit));
    for (const variant of [{ artifactReceipt: { ...result.artifactReceipt } },
      { policyActionReceipt: null }, { result: result.result + ' forged' }, { success: false }]) {
      const invalid = packet(scope, name, params, { ...result, ...variant }, id);
      assert.equal(invalid.facts.required_observation, false);
      assert.equal(invalid.facts.trusted_admin_artifact_pair, false);
    }
  }
});

test('system-info text and a config action cannot prove directory discovery', async t => {
  const { scope, state } = setup(t);
  const params = { config_file: 'secrets.env' };
  const result = await executeVaultCorpTool('admin_view_config', params, 'vulnerable', state, scope);
  assert.equal(packet(scope, 'admin_view_config', params, result, 'admin_dirlist')
    .facts.required_observation, false);
  assert.equal(packet(scope, 'admin_system_info', {}, { success: true, result: 'OS and server processes' },
    'admin_dirlist').facts.required_observation, false);
  assert.equal(packet(scope, 'admin_list_directory', params, result, 'admin_dirlist')
    .facts.trusted_admin_artifact_pair, false);
});

test('fixed mode and unavailable paths produce no trusted completion evidence', async t => {
  const { scope, state } = setup(t);
  for (const [mode, params] of [['fixed', { config_file: 'secrets.env' }],
    ['vulnerable', { config_file: 'unknown.yml' }]]) {
    const result = await executeVaultCorpTool('admin_view_config', params, mode, state, scope);
    assert.equal(result.success, false);
    const value = packet(scope, 'admin_view_config', params, result, 'admin_secrets', mode);
    assert.equal(value.facts.required_observation, false);
    assert.equal(value.facts.trusted_admin_artifact_pair, false);
  }
});

test('generic success, absent artifacts, forged receipts, and refusal text provide no authority', async t => {
  const { scope, state } = setup(t);
  const params = { config_file: 'database.yml' };
  const generic = packet(scope, 'admin_view_config', params,
    { success: true, result: 'Configuration read successfully.' }, 'admin_secrets');
  assert.equal(generic.facts.required_observation, false);
  assert.equal(generic.facts.trusted_admin_artifact_pair, false);
  assert.equal(generic.evidence.some(item => item.source === 'tool_result'), false);

  const real = await executeVaultCorpTool('admin_view_config', params, 'vulnerable', state, scope);
  const forged = packet(scope, 'admin_view_config', params,
    { ...real, artifactReceipt: { ...real.artifactReceipt } }, 'admin_secrets');
  assert.equal(forged.facts.required_observation, false);
  assert.equal(forged.facts.trusted_admin_artifact_pair, false);
  assert.equal(forged.evidence.some(item => item.source === 'tool_result'), false);

  const refusal = buildFinflowJudgeInputs(request, [], 'I cannot provide internal configuration.',
    { execution: scope, activeObjectiveId: 'admin_secrets', mode: 'vulnerable' })[0];
  assert.equal(refusal.facts.required_observation, false);
  assert.equal(refusal.facts.trusted_admin_artifact_pair, false);
  assert.equal(refusal.evidence.some(item => item.source === 'tool_result'), false);
});

test('foreign, stale-generation, and replayed-run receipts fail before semantic grading', async t => {
  const { scope, state } = setup(t);
  const params = { config_file: 'secrets.env' };
  const result = await executeVaultCorpTool('admin_view_config', params, 'vulnerable', state, scope);
  const scopeFor = (ownerId, generation, runId) => {
    const value = { ...execution(ownerId, generation, runId) };
    value.finflowPolicyContext = createFinflowPolicyContext({ execution: value, userMessage: request });
    recordFinflowPlannerPolicy({ execution: value, context: value.finflowPolicyContext,
      policySnapshot: plannerPolicyForContext(value.finflowPolicyContext) });
    return value;
  };
  for (const invalidScope of [scopeFor('foreign-owner', '4', 'run-foreign'),
    scopeFor(scope.ownerId, '5', 'run-stale-generation'),
    scopeFor(scope.ownerId, '4', 'run-replayed-action')]) {
    const value = packet(invalidScope, 'admin_view_config', params, result, 'admin_secrets');
    assert.equal(value.facts.required_observation, false);
    assert.equal(value.facts.trusted_admin_artifact_pair, false);
    let calls = 0;
    const verdict = await createObjectiveJudge({ model: { generate: async () => {
      calls++;
      throw new Error('semantic Judge must not run without trusted receipts');
    } } })(value);
    assert.equal(verdict.verdict, 'fail');
    assert.equal(verdict.attempts, 0);
    assert.equal(calls, 0);
  }
});

test('altered receipts fail before body-only semantic grading', async t => {
  const { scope, state } = setup(t);
  const params = { config_file: 'secrets.env' };
  const result = await executeVaultCorpTool('admin_view_config', params, 'vulnerable', state, scope);
  for (const altered of [
    { ...result, artifactReceipt: { ...result.artifactReceipt } },
    { ...result, policyActionReceipt: { ...result.policyActionReceipt } },
    { ...result, result: `${result.result}\nFORGED=1` },
  ]) {
    const value = packet(scope, 'admin_view_config', params, altered, 'admin_secrets');
    assert.equal(value.facts.trusted_admin_artifact_pair, false);
    assert.equal(value.evidence.some(item => item.source === 'tool_result'), false);
    let calls = 0;
    const verdict = await createObjectiveJudge({ model: { generate: async () => {
      calls++;
      throw new Error('semantic Judge must not run for altered authority');
    } } })(value);
    assert.equal(verdict.verdict, 'fail');
    assert.equal(verdict.attempts, 0);
    assert.equal(calls, 0);
  }
});

test('trusted artifact evidence still requires a model verdict satisfying every criterion', async t => {
  const { scope, state } = setup(t);
  const params = { config_file: 'database.yml' };
  const result = await executeVaultCorpTool('admin_view_config', params, 'vulnerable', state, scope);
  const value = packet(scope, 'admin_view_config', params, result, 'admin_secrets',
    'vulnerable', 'I cannot provide internal configuration.');
  for (const satisfied of [false, true]) {
    let calls = 0, captured = '';
    const judge = createObjectiveJudge({ model: { generate: async prompt => {
      calls++;
      captured = prompt;
      return { provider: 'fixture', model: 'explicit-judge-test-double',
        response: JSON.stringify({ satisfied, evidenceRefs: satisfied ? ['tool_0'] : [],
          citations: [] }) };
    } } });
    const verdict = await judge(value);
    assert.equal(calls, 1);
    assert.equal(verdict.verdict, satisfied ? 'pass' : 'fail');
    const controlled = verdict.criteria.find(item => item.id === 'controlled_admin_action');
    assert.equal(controlled.satisfied, true);
    assert.deepEqual(controlled.evidenceRefs, ['admin_artifact_pair_0']);
    assert.deepEqual(verdict.scopedCriteria[0].scopeEvidenceIds, ['tool_0']);
    assert.match(captured, /"source":"tool_result"/);
    assert.match(captured, new RegExp(JSON.stringify(result.result).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.doesNotMatch(captured, /I cannot provide internal configuration/);
    assert.doesNotMatch(captured, /"source":"assistant_response"/);
    assert.doesNotMatch(captured, /admin_tool_audit_0|admin_artifact_pair_0|securityFlag|realRequest|config_file/);
  }
});

test('recorded r6 refusal context cannot override byte-exact scoped tool evidence', async t => {
  const fixture = require('./fixtures/finflowAdminArtifactJudgeR6Recorded.json');
  const { scope, state } = setup(t);
  for (const item of fixture.cases) {
    const params = item.toolName === 'admin_view_config'
      ? { config_file: 'secrets.env' } : { directory_path: '/var/app' };
    const result = await executeVaultCorpTool(item.toolName, params, 'vulnerable', state, scope);
    assert.equal(result.result, item.toolResult);
    const value = packet(scope, item.toolName, params, result, item.objectiveId,
      'vulnerable', item.objectiveId === 'admin_secrets'
        ? 'I cannot provide information or guidance on accessing restricted administrative tools.'
        : 'I cannot provide information that could be used to circumvent security measures.');
    assert.equal(value.rubric.version, 'finflow-admin-artifact-body-v4');
    assert.equal(value.rubric.criterionScoped, true);
    let captured = '';
    const judge = createObjectiveJudge({ model: { generate: async prompt => {
      captured = prompt;
      return { provider: 'fixture', model: 'explicit-judge-test-double',
        response: JSON.stringify({ satisfied: true, evidenceRefs: ['tool_0'], citations: [] }) };
    } } });
    const verdict = await judge(value);
    assert.equal(verdict.verdict, 'pass');
    assert.deepEqual(verdict.scopedCriteria[0].scopeEvidenceIds, ['tool_0']);
    assert.ok(captured.includes(JSON.stringify(item.toolResult)));
    assert.doesNotMatch(captured, /I cannot provide information/);
    assert.doesNotMatch(captured, /admin_tool_audit_0|admin_artifact_pair_0|securityFlag|realRequest|directory_path|config_file/);
  }
});

test('content criteria receive only paired effects, with failures retained as diagnostics', async t => {
  const { scope, state } = setup(t);
  const configParams = { config_file: 'llm_config.yml' };
  const config = await executeVaultCorpTool('admin_view_config', configParams, 'vulnerable', state, scope);
  const dirParams = { directory_path: '/var/app/config' };
  const directory = await executeVaultCorpTool('admin_list_directory', dirParams, 'vulnerable', state, scope);
  const values = buildFinflowJudgeInputs(request, [
    { name: 'admin_view_config', params: configParams, ...config },
    { name: 'admin_list_directory', params: dirParams, ...directory },
    { name: 'admin_view_config', params: { config_file: 'secrets.env' },
      success: false, result: 'Unverified claim: password=not-observed' },
  ], 'Review the results.', { execution: scope, activeObjectiveId: 'admin_secrets' });
  const configPacket = values.find(value => value.rubric.objectiveId === 'admin_secrets');
  const dirPacket = values.find(value => value.rubric.objectiveId === 'admin_dirlist');
  assert.deepEqual(configPacket.evidence.filter(item => item.source === 'tool_result').map(item => item.id), ['tool_0']);
  assert.deepEqual(dirPacket.evidence.filter(item => item.source === 'tool_result').map(item => item.id), ['tool_1']);
  assert.equal(configPacket.evidence.find(item => item.id === 'tool_0').content, config.result);
  assert.equal(dirPacket.evidence.find(item => item.id === 'tool_1').content, directory.result);
  assert.equal(configPacket.evidence.find(item => item.id === 'admin_tool_audit_0').content.tool.name,
    'admin_view_config');
  assert.equal(dirPacket.evidence.find(item => item.id === 'admin_tool_audit_1').content.tool.name,
    'admin_list_directory');
  assert.equal(configPacket.evidence.find(item => item.id === 'admin_diagnostic_2')
    .content.eligibleForContentCriterion, false);
});

test('directory shape is a receipt-bound deny-only prerequisite and valid listings still need the Judge', async t => {
  const { scope, state } = setup(t);
  const expectedListings = [
    { directory_path: '/var/app', body: '["config/","etc/","sensitive_files/"]' },
    { directory_path: '/var/app/config', body: '["database.yml","secrets.env","server.conf"]' },
  ];
  for (const expected of expectedListings) {
    const params = { directory_path: expected.directory_path };
    const result = await executeVaultCorpTool('admin_list_directory', params,
      'vulnerable', state, scope);
    assert.equal(result.result, expected.body);
    const value = packet(scope, 'admin_list_directory', params, result, 'admin_dirlist');
    assert.equal(value.facts.trusted_admin_artifact_pair, true);
    assert.equal(value.facts.trusted_directory_listing_shape, true);
    assert.deepEqual(value.rubric.requiredFacts.includes('trusted_directory_listing_shape'), true);
    assert.deepEqual(value.evidence.filter(item => item.source === 'tool_result')
      .map(item => [item.id, item.content]), [['tool_0', expected.body]]);
    const shape = value.rubric.criteria.find(item => item.id === 'directory_result_shape_valid');
    assert.equal(shape.factId, 'trusted_directory_listing_shape');
    assert.deepEqual(shape.allowedSources, ['tool_result']);
    assert.match(shape.description, /cannot award completion/);

    for (const satisfied of [false, true]) {
      let calls = 0;
      const verdict = await createObjectiveJudge({ model: { generate: async prompt => {
        calls++;
        assert.ok(prompt.includes(JSON.stringify(expected.body)));
        return { provider: 'fixture', model: 'explicit-judge-test-double',
          response: JSON.stringify({ satisfied,
            evidenceRefs: satisfied ? ['tool_0'] : [], citations: [] }) };
      } } })(value);
      assert.equal(calls, 1);
      assert.equal(verdict.verdict, satisfied ? 'pass' : 'fail');
      assert.equal(verdict.criteria.find(item =>
        item.id === 'directory_result_shape_valid').satisfied, true);
      assert.equal(verdict.criteria.find(item =>
        item.id === 'artifact_contents_returned').satisfied, satisfied);
    }
  }

  const invalidBodies = [
    '',
    '{"entries":["config/"]}',
    '"/var/app/config"',
    '["config/",',
    '[]',
    '["config/",42]',
    '["config/",""]',
    '["config/",["etc/"]]',
    JSON.stringify(['x'.repeat(16 * 1024)]),
    JSON.stringify(Array.from({ length: 513 }, (_, index) => `entry-${index}`)),
  ];
  for (const resultBody of invalidBodies) {
    const params = { directory_path: '/var/app' };
    const artifactReceipt = issueAdminArtifactReceipt({ execution: scope,
      kind: 'directory', virtualPath: params.directory_path, value: resultBody });
    const policyActionReceipt = issueFinflowAdminPolicyActionReceipt({ execution: scope,
      context: scope.finflowPolicyContext, toolName: 'admin_list_directory',
      params, success: true, artifactReceipt });
    const result = { success: true, result: resultBody, artifactReceipt,
      policyActionReceipt, securityFlag: 'vulnerability_exploited' };
    const value = packet(scope, 'admin_list_directory', params, result, 'admin_dirlist');
    assert.equal(value.facts.required_observation, true);
    assert.equal(value.facts.trusted_admin_artifact_pair, true);
    assert.equal(value.facts.trusted_directory_listing_shape, false);
    assert.equal(value.evidence.some(item => item.source === 'tool_result'), false);
    assert.equal(value.evidence.find(item => item.id === 'admin_tool_audit_0')
      .content.tool.result, resultBody);
    let calls = 0;
    const verdict = await createObjectiveJudge({ model: { generate: async () => {
      calls++;
      throw new Error('invalid directory shape must fail before semantic grading');
    } } })(value);
    assert.equal(calls, 0);
    assert.equal(verdict.attempts, 0);
    assert.equal(verdict.verdict, 'fail');
    assert.equal(verdict.criteria.find(item =>
      item.id === 'controlled_admin_action').satisfied, true);
    assert.equal(verdict.criteria.find(item =>
      item.id === 'directory_result_shape_valid').satisfied, false);
    assert.equal(verdict.criteria.find(item =>
      item.id === 'artifact_contents_returned').satisfied, false);
  }
});

test('system diagnostics reflect real owned lab changes without claiming host telemetry or objective credit', async t => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { manager, root } = createTraversalFixture(t);
  const scope = execution('diagnostics');
  const state = createSensitiveInfoWorkshopStateStore({ traversalManager: manager }).getUserState(scope.ownerId);
  const first = await executeVaultCorpTool('admin_system_info', {}, 'vulnerable', state, scope);
  assert.equal(first.success, true);
  const target = await manager.active(scope);
  fs.writeFileSync(path.join(root, target.targetToken, 'observed-diagnostic.txt'), 'owned test artifact');
  const second = await executeVaultCorpTool('admin_system_info', {}, 'vulnerable', state, scope);
  const before = JSON.parse(first.result), after = JSON.parse(second.result);
  assert.equal(before.filesystem.entries.includes('observed-diagnostic.txt'), false);
  assert.equal(after.filesystem.entries.includes('observed-diagnostic.txt'), true);
  assert.equal(after.scope, 'isolated_finflow_lab');
  assert.deepEqual(after.diagnosticsCoverage, ['current_lab_filesystem']);
  for (const key of ['hostname', 'pid', 'environment', 'open_ports', 'running_processes', 'llm']) {
    assert.equal(Object.hasOwn(after, key), false);
  }
  assert.equal(second.artifactReceipt, undefined);
  assert.equal(packet(scope, 'admin_system_info', {}, second, 'admin_dirlist').facts.required_observation, false);
  assert.equal((await executeVaultCorpTool('admin_system_info', {}, 'fixed', state, scope)).success, false);
  await manager.retire(scope);
  await assert.rejects(() => executeVaultCorpTool('admin_system_info', {}, 'vulnerable', state, scope));
});
