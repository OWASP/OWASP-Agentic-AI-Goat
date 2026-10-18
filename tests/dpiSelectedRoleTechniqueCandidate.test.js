'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const v11 = require('../server/agent-runtime/dpiSelectedSourceTechniqueCandidate');
const { VERSION, ROLE_TECHNIQUE_POLICY, createDpiSelectedRoleTechniqueCandidate } = require('../server/agent-runtime/dpiSelectedRoleTechniqueCandidate');
const { DELIMITER } = require('../server/agent-runtime/dpiDirectWitnessCandidate');

const root = path.join(__dirname, '..', 'tests', 'release-inputs');
const input = JSON.parse(fs.readFileSync(path.join(root, 'dpi-selected-source-technique-four-input-v1.json')));
const expectations = JSON.parse(fs.readFileSync(path.join(root, 'dpi-selected-source-technique-four-expectations-v1.json')));
const sha = value => createHash('sha256').update(value).digest('hex');
const labelled = input.cases.map(row => ({ ...row, expected: expectations.cases.find(item => item.id === row.id)?.expected }));

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

test('v12 adds only its response-role instruction and binds it into a new policy hash', () => {
  assert.equal(input.version, expectations.inputVersion);
  assert.equal(labelled.length, 4);
  assert.ok(labelled.every(row => row.expected));
  for (const row of labelled) {
    const base = v11.createDpiSelectedSourceTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const candidate = createDpiSelectedRoleTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const baseWire = base.stages[0].messages(), wire = candidate.stages[0].messages();
    assert.equal(candidate.version, VERSION);
    assert.deepEqual(wire.format, baseWire.format);
    assert.equal(candidate.policy.schemaSha256, base.policy.schemaSha256);
    assert.match(wire.messages[0].content, /roleAdopted is no/);
    assert.deepEqual(JSON.parse(wire.messages[0].content.split(DELIMITER)[1]), wire.format);
    assert.equal(candidate.policy.instructionsSha256, sha(JSON.stringify({
      version: VERSION,
      baseVersion: base.version,
      baseInstructionsSha256: base.policy.instructionsSha256,
      schemaSha256: candidate.policy.schemaSha256,
      roleTechniquePolicy: ROLE_TECHNIQUE_POLICY,
    })));
    assert.notEqual(candidate.policy.instructionsSha256, base.policy.instructionsSha256);
  }
});

test('v12 delegates parser and reducer behavior to v11 for all four fixed cases', () => {
  for (const row of labelled) {
    const base = v11.createDpiSelectedSourceTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const candidate = createDpiSelectedRoleTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const rawValue = raw(candidate, row);
    const baseResult = base.combine(base.stages[0].validate(raw(base, row)));
    const result = candidate.combine(candidate.stages[0].validate(rawValue));
    assert.equal(result.verdict, row.expected.verdict, row.id);
    assert.deepEqual(withoutWireVersion(result), withoutWireVersion(baseResult), row.id);
    const invalid = JSON.parse(rawValue);
    invalid.selected.context.defeatingContext = [{ id: candidate.catalog.entries.find(entry => entry.field === 'response').id }];
    assert.throws(() => candidate.stages[0].validate(JSON.stringify(invalid)), row.id);
  }
});
