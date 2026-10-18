'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const v10 = require('../server/agent-runtime/dpiSelectedCompactContextCandidate');
const { VERSION, SOURCE_TECHNIQUE_POLICY, createDpiSelectedSourceTechniqueCandidate } = require('../server/agent-runtime/dpiSelectedSourceTechniqueCandidate');
const { DELIMITER } = require('../server/agent-runtime/dpiDirectWitnessCandidate');

const fixed = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tests', 'release-inputs', 'dpi-selected-source-technique-four-input-v1.json')));
const expectations = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tests', 'release-inputs', 'dpi-selected-source-technique-four-expectations-v1.json')));
const sha = value => createHash('sha256').update(value).digest('hex');
const labelled = fixed.cases.map(row => ({ ...row, expected: expectations.cases.find(item => item.id === row.id)?.expected }));

function evidence(row) {
  return [{ id: 'request', source: 'student_input', content: row.request }, { id: 'response', source: 'assistant_response', content: row.response }];
}

function raw(candidate, row) {
  const source = candidate.catalog.entries.find(entry => entry.field === 'source').id;
  const response = candidate.catalog.entries.find(entry => entry.field === 'response').id;
  const yes = value => value === 'yes';
  const technique = row.objective === 'jailbreak'
    ? { overrideRequested: { value: row.expected.overrideRequested, support: yes(row.expected.overrideRequested) ? { id: source } : null } }
    : {
      personaAssigned: { value: row.expected.personaAssigned, support: yes(row.expected.personaAssigned) ? { id: source } : null },
      roleAdopted: { value: row.expected.roleAdopted, support: yes(row.expected.roleAdopted) ? { id: response } : null },
    };
  return JSON.stringify({ coverage: 'complete', selected: {
    source: { id: source }, topic: 'non_aws', technique,
    contribution: { content: 'substantive', relation: 'adopted_answer', answer: [{ id: response }] },
    context: { value: 'none_observed', defeatingContext: [] },
  } });
}

function withoutWireVersion(value) {
  const { version, wireVersion, ...rest } = value;
  return rest;
}

test('v11 changes only the source-technique instruction and binds it into its policy hash', () => {
  assert.equal(fixed.version, 'dpi-selected-source-technique-four-input-v1');
  assert.equal(expectations.version, 'dpi-selected-source-technique-four-expectations-v1');
  assert.equal(expectations.inputVersion, fixed.version);
  assert.equal(fixed.cases.length, 4);
  assert.ok(labelled.every(row => row.expected));
  for (const row of labelled) {
    const input = evidence(row);
    const base = v10.createDpiSelectedCompactContextCandidate({ objective: row.objective, evidence: input });
    const candidate = createDpiSelectedSourceTechniqueCandidate({ objective: row.objective, evidence: input });
    const baseWire = base.stages[0].messages(), wire = candidate.stages[0].messages();
    assert.equal(candidate.version, VERSION);
    assert.deepEqual(wire.format, baseWire.format);
    assert.equal(candidate.policy.schemaSha256, base.policy.schemaSha256);
    assert.match(wire.messages[0].content, /Source-technique classification is determined only by a semantic directive/);
    assert.deepEqual(JSON.parse(wire.messages[0].content.split(DELIMITER)[1]), wire.format);
    assert.doesNotMatch(wire.messages[1].content, /expected|verdict/i, 'external labels are not sent to the model');
    assert.equal(candidate.policy.instructionsSha256, sha(JSON.stringify({
      version: VERSION,
      baseVersion: base.version,
      baseInstructionsSha256: base.policy.instructionsSha256,
      schemaSha256: candidate.policy.schemaSha256,
      sourceTechniquePolicy: SOURCE_TECHNIQUE_POLICY,
    })));
    assert.notEqual(candidate.policy.instructionsSha256, base.policy.instructionsSha256);
  }
});

test('v11 preserves the v10 reducer for the fixed source-technique calibration cases', () => {
  for (const row of labelled) {
    const input = evidence(row);
    const base = v10.createDpiSelectedCompactContextCandidate({ objective: row.objective, evidence: input });
    const candidate = createDpiSelectedSourceTechniqueCandidate({ objective: row.objective, evidence: input });
    const baseResult = base.combine(base.stages[0].validate(raw(base, row)));
    const result = candidate.combine(candidate.stages[0].validate(raw(candidate, row)));
    assert.equal(result.verdict, row.expected.verdict, row.id);
    assert.deepEqual(withoutWireVersion(result), withoutWireVersion(baseResult), row.id);
  }
});
