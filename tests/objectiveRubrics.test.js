'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { rubricSchema } = require('../server/agent-runtime/objectiveJudge');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
const {
  getObjectiveRubric,
  listObjectiveRubrics,
  OBJECTIVE_RUBRIC_INSPECTION_NOTES,
} = require('../server/config/objectiveRubrics');

const COVERED = {
  sql_injection_workshop: Array.from({ length: 10 }, (_, i) => `sqli_${i + 1}`),
  nosql_injection_workshop: Array.from({ length: 10 }, (_, i) => `nosqli_${i + 1}`),
  mcp_workshop: [
    'mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning',
    'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
    'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server',
  ],
  xss_workshop: [
    'xss_r1', 'xss_r2', 'xss_r3', 'xss_s1', 'xss_s2', 'xss_s3',
    'xss_g1', 'xss_g2', 'xss_g3', 'xss_e1', 'xss_e2', 'xss_e3',
  ],
};

test('registry covers 43 static canonical objectives and reports partial 179-objective coverage honestly', () => {
  const catalogIds = Object.values(WORKSHOP_OBJECTIVES).flat().map(objective => objective.id);
  assert.equal(catalogIds.length, 179);
  assert.equal(new Set(catalogIds).size, 179);

  const rubrics = listObjectiveRubrics();
  assert.equal(rubrics.length, 43);
  assert.equal(new Set(rubrics.map(item => item.objectiveId)).size, 43);
  for (const [workshopKey, objectiveIds] of Object.entries(COVERED)) {
    assert.deepEqual(WORKSHOP_OBJECTIVES[workshopKey].map(item => item.id), objectiveIds);
    for (const objectiveId of objectiveIds) {
      assert.ok(getObjectiveRubric(workshopKey, objectiveId, 'vuln'));
      assert.ok(catalogIds.includes(objectiveId));
    }
  }
});

test('every rubric is valid, outcome-specific, immutable, and excludes student claims from acceptable proof', () => {
  for (const item of listObjectiveRubrics()) {
    assert.deepEqual(rubricSchema.parse(item), {
      ...item, authoritativeVerdictFacts: item.authoritativeVerdictFacts || [],
    });
    assert.ok(Object.isFrozen(item));
    assert.ok(item.requiredFacts.length >= 3);
    assert.ok(item.requiredFacts.includes('objective_signal_detected'));
    assert.ok(item.requiredFacts.includes('vulnerable_mode'));
    assert.ok(item.criteria[0].description.length > 80);
    assert.ok(item.criteria.every(criterion => !criterion.allowedSources.includes('student_input')));
    if (item.objectiveId === 'mcp_secret_exposure') {
      // An observer's description cannot substitute for an actual returned
      // credential. The grounded disclosure criteria intentionally narrow proof.
      for (const criterion of item.criteria) {
        assert.deepEqual(criterion.allowedSources, ['tool_result']);
        assert.equal(criterion.quoteRequired, true);
      }
    } else if (item.objectiveId === 'mcp_tool_poisoning') {
      // The action receipt proves metadata influence; protected bytes must be
      // quoted from the actual tool result, never an observer's narration.
      assert.deepEqual(item.criteria.map(criterion => criterion.allowedSources),
        [['server_observation'], ['tool_result']]);
      assert.equal(item.criteria[1].quoteRequired, true);
    } else if (item.objectiveId === 'mcp_confused_deputy') {
      assert.deepEqual(item.criteria.map(criterion => criterion.allowedSources),
        [['tool_result'], ['server_observation']]);
      assert.equal(item.criteria[0].quoteRequired, true);
    } else {
      assert.ok(item.criteria.every(criterion => criterion.allowedSources.includes('server_observation')));
    }
  }
});

test('mode aliases resolve only vulnerable attack rubrics and unknown objectives remain unsupported', () => {
  assert.equal(getObjectiveRubric('sql_injection_workshop', 'sqli_1', 'vulnerable'),
    getObjectiveRubric('sql_injection_workshop', 'sqli_1', 'vuln'));
  assert.equal(getObjectiveRubric('sql_injection_workshop', 'sqli_1', 'fixed'), undefined);
  assert.equal(getObjectiveRubric('sql_injection_workshop', 'unknown', 'vuln'), undefined);
  assert.equal(getObjectiveRubric('unknown', 'sqli_1', 'vuln'), undefined);
  assert.equal(getObjectiveRubric('sql_injection_workshop', 'sqli_1'), undefined);
});

test('each covered objective has an explicit trusted-proof inspection note', () => {
  for (const [workshopKey, objectiveIds] of Object.entries(COVERED)) {
    const notes = OBJECTIVE_RUBRIC_INSPECTION_NOTES[workshopKey];
    assert.match(notes.source, /server\//);
    assert.deepEqual(Object.keys(notes.proof), objectiveIds);
    for (const objectiveId of objectiveIds) assert.ok(notes.proof[objectiveId].length > 40);
  }
});
