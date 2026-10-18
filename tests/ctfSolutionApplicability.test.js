'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');
const { stages: canonicalStages } = require('../server/data/ctfDefaults');
const {
  COMPARISON_POLICY,
  annotateCtfSolutionLevels,
} = require('../server/services/ctfSolutionApplicability');

test('solution applicability compares the documented runtime-relevant fields without exposing their values', () => {
  const matching = {
    ...canonicalStages[0],
    defense_style: '[  ]',
  };
  const changed = {
    ...canonicalStages[1],
    system_prompt: 'Instructor-edited guardian',
    success_criteria: 'INSTRUCTOR_EDITED_SECRET',
    defense_style: '["persona_guard","persona_guard"]',
    adaptive_mode: 'technique',
  };
  const [match, drift, missing] = annotateCtfSolutionLevels(
    [{ level: 1 }, { level: 2 }, { level: 3 }],
    [matching, changed],
    canonicalStages,
  );

  assert.deepEqual(match.configurationApplicability, {
    candidateBasis: 'canonical_default',
    appliesToDefault: true,
    currentConfiguration: 'matches_default',
    differingFields: [],
  });
  assert.deepEqual(drift.configurationApplicability, {
    candidateBasis: 'canonical_default',
    appliesToDefault: true,
    currentConfiguration: 'differs_from_default',
    differingFields: ['system_prompt', 'success_criteria', 'defense_style', 'adaptive_mode'],
  });
  assert.equal(missing.configurationApplicability.currentConfiguration, 'stage_missing');
  assert.equal(JSON.stringify(drift.configurationApplicability).includes('INSTRUCTOR_EDITED_SECRET'), false);
  assert.deepEqual(COMPARISON_POLICY.comparedFields, [
    'system_prompt', 'success_criteria', 'defense_style', 'adaptive_mode',
  ]);
});

test('defense comparison ignores JSON whitespace but preserves order and repeated layers', () => {
  const canonical = {
    ...canonicalStages[4],
    defense_style: '["persona_guard","meta_llm_judge","persona_guard"]',
  };
  const levels = [{ level: canonical.stage_number }];
  const reordered = {
    ...canonical,
    defense_style: '[ "meta_llm_judge", "persona_guard", "persona_guard" ]',
  };
  const duplicateRemoved = {
    ...canonical,
    defense_style: '["persona_guard","meta_llm_judge"]',
  };
  const spacedMatch = {
    ...canonical,
    defense_style: '[ "persona_guard", "meta_llm_judge", "persona_guard" ]',
  };

  assert.equal(annotateCtfSolutionLevels(levels, [spacedMatch], [canonical])[0]
    .configurationApplicability.currentConfiguration, 'matches_default');
  for (const current of [reordered, duplicateRemoved]) {
    assert.deepEqual(annotateCtfSolutionLevels(levels, [current], [canonical])[0]
      .configurationApplicability.differingFields, ['defense_style']);
  }
});

test('solution applicability reports missing and invalid canonical defaults without claiming applicability', () => {
  const levels = [{ level: 4 }];
  const current = [{ ...canonicalStages[3] }];
  const missing = annotateCtfSolutionLevels(levels, current, [])[0].configurationApplicability;
  assert.deepEqual(missing, {
    candidateBasis: 'canonical_default',
    appliesToDefault: false,
    currentConfiguration: 'canonical_default_missing',
    differingFields: [],
  });

  const invalidCanonical = { ...canonicalStages[3], defense_style: '{"not":"an array"}' };
  const invalid = annotateCtfSolutionLevels(levels, current, [invalidCanonical])[0]
    .configurationApplicability;
  assert.deepEqual(invalid, {
    candidateBasis: 'canonical_default',
    appliesToDefault: false,
    currentConfiguration: 'canonical_default_invalid',
    differingFields: [],
    invalidDefaultFields: ['defense_style'],
  });
});

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

test('admin solutions route reports current match, drift, and missing stages while denying learners', async t => {
  let reads = 0;
  const helpers = {
    getAllStages: async () => {
      reads += 1;
      return [
        { ...canonicalStages[0] },
        { ...canonicalStages[1], adaptive_mode: 'hybrid' },
      ];
    },
  };
  const express = require('express');
  const { router, routePath } = loadRoute(helpers);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.get('x-fixture-role') === 'admin'
      ? { id: 1, role: 'admin', adminLevel: 2 }
      : { id: 2, role: 'student', adminLevel: 0 };
    next();
  });
  app.use(router);
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    delete require.cache[routePath];
  });
  const url = `http://127.0.0.1:${server.address().port}/admin/solutions`;

  const denied = await fetch(url, { headers: { 'x-fixture-role': 'student' } });
  assert.equal(denied.status, 403);
  assert.equal(reads, 0, 'authorization must run before stage configuration lookup');

  const response = await fetch(url, { headers: { 'x-fixture-role': 'admin' } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(reads, 1);
  assert.equal(body.comparisonPolicy.version, 'ctf-solution-applicability-v1');
  assert.equal(body.levels[0].configurationApplicability.currentConfiguration, 'matches_default');
  assert.deepEqual(body.levels[1].configurationApplicability.differingFields, ['adaptive_mode']);
  assert.equal(body.levels[2].configurationApplicability.currentConfiguration, 'stage_missing');
});
