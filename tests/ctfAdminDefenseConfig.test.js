'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');
const {
  CTF_DEFENSE_NAMES,
  ctfStageDefenseInput,
} = require('../server/middleware/ctfAttemptInput');
const { stages: canonicalStages } = require('../server/data/ctfDefaults');
const { MAX_HINT_COST } = require('../server/middleware/ctfHintConfigInput');

// Exact projection submitted by StageEditForm. Seed-only and read-only fields,
// including the inactive time bonus, are not admin-editable inputs.
function editableStageInput(stage) {
  return Object.fromEntries([
    'stage_name', 'stage_description', 'system_prompt', 'success_criteria', 'hints',
    'defense_style', 'adaptive_mode', 'level_score', 'feedback_mode',
  ].map(field => [field, stage[field]]));
}

test('mounted admin hint configuration rejects invalid fees and thresholds before persistence', async t => {
  const writes = [];
  const { router, routePath } = loadRoute({ updateConfig: async (...args) => writes.push(args) });
  const express = require('express');
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = { id: 1, role: 'admin', adminLevel: 2 }; next(); });
  app.use(router);
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); delete require.cache[routePath]; });
  const send = body => fetch(`http://127.0.0.1:${server.address().port}/admin/config`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  for (const key of ['ctf_hint_cost_1', 'ctf_hint_cost_2', 'ctf_hint_cost_3', 'ctf_hint_gating_attempts']) {
    for (const value of [-1, '-1', '1.5', '20points', '1e2', '', null, true, {}, 2147483648]) {
      assert.equal((await send({ key, value })).status, 400);
    }
  }
  assert.equal((await send({ key: 'ctf_hint_cost_1', value: MAX_HINT_COST + 1 })).status, 400);
  assert.deepEqual(writes, []);
  for (const body of [
    { key: 'ctf_hint_cost_1', value: 0 },
    { key: 'ctf_hint_cost_2', value: '25' },
    { key: 'ctf_hint_cost_3', value: MAX_HINT_COST },
    { key: 'ctf_hint_gating_attempts', value: '0' },
    { key: 'ctf_hint_gating_attempts', value: 2147483647 },
    { key: 'ctf_enabled', value: 'false' },
  ]) {
    assert.equal((await send(body)).status, 200);
    assert.deepEqual(writes.at(-1), [body.key, body.value]);
  }
});

function invokeDefenseMiddleware(body) {
  let status = 200;
  let payload;
  let next = false;
  ctfStageDefenseInput({ body }, {
    status(value) { status = value; return this; },
    json(value) { payload = value; return this; },
  }, () => { next = true; });
  return { status, payload, next };
}

function loadRoute(helpers) {
  const routePath = path.resolve(__dirname, '../server/routes/ctf.js');
  const original = Module._load;
  Module._load = function(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../agent-runtime/ctfStageJudge') return { stageDigest: () => 'unused', judgeCtfStage: async () => { throw new Error('judge forbidden'); } };
      if (request === '../agent-runtime/ctfAttemptCommit') return { commitCtfAttempt: async () => { throw new Error('commit forbidden'); } };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return { ownerWorkflowRoute: (_coordinator, _owner, handler) => handler, getOwnerExecution: () => null };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({ reset: async (_owner, work) => work(), cancel() {} }) };
      if (request === '../database/ctfDb') return { ctfDb: {}, CTFHelpers: helpers, ctfDbPath: ':forbidden:', engine: 'postgres' };
      if (request === '../services/promptInjectionCTF') return { classifyTechnique() {}, hashPayload() {}, isNearDuplicate() {}, TECHNIQUE_TAGS: { OTHER: 'other' } };
      if (request === '../services/ctfDefenseLayers') return { runDefenseLayers() {}, runOutputDefenses() {}, normalizedContains() {} };
      if (request === '../agent-runtime/ctfGuardianResult') return { requireCtfGuardianResult() {} };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../data/ctfSolutions') return { levels: [] };
      if (request === '../services/ctfLeaderboardRefreshCoordinator') return { createLeaderboardRefreshCoordinator: () => ({ requestRefresh() {}, flush: async () => {} }) };
    }
    return original.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[routePath];
    return { router: require(routePath).router, routePath };
  } finally {
    Module._load = original;
  }
}

test('defense middleware preserves JSON-text order, repeats, empty arrays, and omitted values', () => {
  assert.deepEqual([...CTF_DEFENSE_NAMES].sort(), [
    'input_blocklist', 'instruction_leak_guard', 'meta_llm_judge',
    'meta_rotation_handoff_reviewer_v1', 'meta_structured_artifact_reviewer_v1',
    'output_fuzzy_strip', 'output_regex_strip', 'persona_guard',
    'polyglot_decoder', 'transformation_guard',
  ]);
  for (const defense_style of [
    '[]',
    '["persona_guard","input_blocklist","persona_guard","meta_llm_judge"]',
  ]) {
    const body = { defense_style };
    const result = invokeDefenseMiddleware(body);
    assert.deepEqual(result, { status: 200, payload: undefined, next: true });
    assert.equal(body.defense_style, defense_style, 'validation must not normalize stored order or repeats');
  }
  assert.deepEqual(invokeDefenseMiddleware({ stage_name: 'partial update' }), {
    status: 200, payload: undefined, next: true,
  });
  assert.deepEqual(invokeDefenseMiddleware(null), {
    status: 400, payload: { error: 'Stage configuration must be an object' }, next: false,
  });
  for (const stage of canonicalStages) {
    assert.equal(invokeDefenseMiddleware({ defense_style: stage.defense_style }).next, true,
      `canonical stage ${stage.stage_number} must use registered defense handlers`);
  }
});

test('mounted admin create/update reject invalid defense JSON before persistence', async t => {
  const creates = [];
  const updates = [];
  const helpers = {
    createStage: async data => { creates.push(structuredClone(data)); return creates.length; },
    updateStage: async (id, data) => { updates.push([id, structuredClone(data)]); return true; },
  };
  const express = require('express');
  const { router, routePath } = loadRoute(helpers);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = { id: 1, role: 'admin', adminLevel: 2 }; next(); });
  app.use(router);
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    delete require.cache[routePath];
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const send = (method, route, body) => fetch(base + route, {
    method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  const invalidValues = [
    '{',
    '{}',
    null,
    '["nonexistent_defense"]',
    '["input_blocklist",17]',
    '["input_blocklist",null]',
    ['input_blocklist'],
  ];
  for (const defense_style of invalidValues) {
    const create = await send('POST', '/admin/stages', { success_criteria: 'VALID_1', defense_style });
    assert.equal(create.status, 400);
    const update = await send('PUT', '/admin/stages/17', { defense_style });
    assert.equal(update.status, 400);
  }
  assert.deepEqual(creates, []);
  assert.deepEqual(updates, []);

  const ordered = '["persona_guard","input_blocklist","persona_guard","output_fuzzy_strip"]';
  assert.equal((await send('POST', '/admin/stages', {
    success_criteria: 'VALID_OMITTED', stage_name: 'Default defenses',
  })).status, 200);
  assert.equal((await send('POST', '/admin/stages', {
    success_criteria: 'VALID_1', defense_style: '[]',
  })).status, 200);
  assert.equal((await send('POST', '/admin/stages', {
    success_criteria: 'VALID_2', defense_style: ordered,
  })).status, 200);
  assert.deepEqual(creates.map(row => row.defense_style), [undefined, '[]', ordered]);

  assert.equal((await send('PUT', '/admin/stages/17', { defense_style: ordered })).status, 200);
  assert.equal((await send('PUT', '/admin/stages/17', { defense_style: '[]' })).status, 200);
  assert.equal((await send('PUT', '/admin/stages/17', { stage_name: 'Omitted defense remains unchanged' })).status, 200);
  assert.deepEqual(updates, [
    [17, { defense_style: ordered }],
    [17, { defense_style: '[]' }],
    [17, { stage_name: 'Omitted defense remains unchanged' }],
  ]);

  const inactiveMessage = { error: 'time_bonus_seconds is a legacy inactive setting and cannot be edited' };
  for (const stage of canonicalStages) {
    const createsBefore = creates.length;
    const updatesBefore = updates.length;
    const rejectedCreate = await send('POST', '/admin/stages', stage);
    assert.equal(rejectedCreate.status, 400);
    assert.deepEqual(await rejectedCreate.json(), inactiveMessage);
    const rejectedUpdate = await send('PUT', '/admin/stages/17', stage);
    assert.equal(rejectedUpdate.status, 400);
    assert.deepEqual(await rejectedUpdate.json(), inactiveMessage);
    assert.equal(creates.length, createsBefore, 'rejected seed input must not create a stage');
    assert.equal(updates.length, updatesBefore, 'rejected seed input must not update a stage');

    const editable = editableStageInput(stage);
    assert.equal(Object.hasOwn(editable, 'time_bonus_seconds'), false);
    assert.equal((await send('POST', '/admin/stages', editable)).status, 200);
    assert.equal((await send('PUT', '/admin/stages/17', editable)).status, 200);
  }
  assert.deepEqual(creates.slice(-canonicalStages.length).map(row => row.defense_style),
    canonicalStages.map(stage => stage.defense_style));
  assert.deepEqual(updates.slice(-canonicalStages.length).map(([, row]) => row.defense_style),
    canonicalStages.map(stage => stage.defense_style));
});
