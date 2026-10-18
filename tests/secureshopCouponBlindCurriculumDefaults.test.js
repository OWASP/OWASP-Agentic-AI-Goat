'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const curriculum = require('../server/config/secureshopCurriculum');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');

const ID = 'ss_sqli_blind_boolean';

test('V48 has a distinct qualified but default-disabled coupon-probe curriculum entry', () => {
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_coupon_probe'), {
    id: 'ss_coupon_probe', title: 'Infer an unknown synthetic character through coupon probes', objectiveIds: [ID],
  });
  const objective = curriculum.OBJECTIVES.find(row => row.id === ID);
  assert.equal(objective?.exerciseId, 'ss_coupon_probe');
  assert.equal(objective?.qualification, 'native-browser-judge');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(ID), true);
  assert.equal(curriculum.PENDING_OBJECTIVE_IDS.includes(ID), false);
  assert.match(objective.evidence, /bound_coupon_blind.*secureshop-coupon-blind-v1/s);
  assert.match(objective.evidence, /seven bounded read-only.*distinct true and false character-equality.*private noncitable reference/s);
  assert.match(objective.evidence, /Fixed parameterized no-match.*missing contrast.*wrong discount/s);
  assert.match(objective.evidence, /one-character inference, not whole-password disclosure or authentication compromise/);
  assert.notEqual(objective.exerciseId, curriculum.OBJECTIVES.find(row => row.id === 'ss_sqli_coupon').exerciseId);
  const hints = curriculum.HINTS[ID].hints.join(' ');
  assert.match(hints, /disabled by default.*fixture-local candidate admission/s);
  assert.match(hints, /Raw SQL is the default.*Guided boolean investigation.*true and false equality/s);
  const solution = curriculum.SOLUTIONS[ID];
  assert.equal(solution.approach, objective.evidence);
  assert.match(solution.examples[0].explanation, /seven read-only SQL probes.*true inferred-character equality.*distinct false equality.*canonical Judge/s);
  assert.match(solution.examples[0].explanation, /fixture-local candidate admission only.*disabled by default/s);
});

test('V48 default reseed records managed content and preserves instructor edits', () => {
  const row = curriculum.OBJECTIVES.find(value => value.id === ID);
  for (const [fieldName, value] of [
    ['label', row.text],
    ['hint_content', curriculum.HINTS[ID]],
    ['solution_content', curriculum.SOLUTIONS[ID]],
  ]) {
    const sourceDocument = provenance.document(value);
    const applied = provenance.hashDocument(sourceDocument);
    assert.equal(provenance.decideReconciliation({
      provenance: { provenance_state: 'managed', applied_default_hash: applied },
      currentDocument: sourceDocument, sourceDocument,
    }).action, 'record');
    const edited = fieldName === 'label' ? 'Instructor-owned blind probe lesson'
      : { ...value, title: 'Instructor-owned blind probe lesson' };
    assert.equal(provenance.decideReconciliation({
      provenance: { provenance_state: 'managed', applied_default_hash: applied },
      currentDocument: provenance.document(edited), sourceDocument,
    }).action, 'mark_custom');
    assert.equal(provenance.decideReconciliation({
      provenance: { provenance_state: 'custom', applied_default_hash: applied },
      currentDocument: provenance.document(edited), sourceDocument,
    }).action, 'preserve');
  }
});
