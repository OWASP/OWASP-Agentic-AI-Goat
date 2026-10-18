'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const v11 = require('../server/agent-runtime/dpiSelectedSourceTechniqueCandidate');
const v12 = require('../server/agent-runtime/dpiSelectedRoleTechniqueCandidate');
const { VERSION, COMPOSITION, createDpiSelectedObjectiveTechniqueCandidate } = require('../server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate');

const root = path.join(__dirname, '..', 'tests', 'release-inputs');
const input = JSON.parse(fs.readFileSync(path.join(root, 'dpi-selected-source-technique-four-input-v1.json')));
const expectations = JSON.parse(fs.readFileSync(path.join(root, 'dpi-selected-source-technique-four-expectations-v1.json')));
const sha = value => createHash('sha256').update(value).digest('hex');
const labelled = input.cases.map(row => ({ ...row, expected: expectations.cases.find(item => item.id === row.id)?.expected }));

function evidence(row) {
  return [{ id: 'request', source: 'student_input', content: row.request }, { id: 'response', source: 'assistant_response', content: row.response }];
}

function baseFor(row) {
  return row.objective === 'jailbreak'
    ? v11.createDpiSelectedSourceTechniqueCandidate({ objective: row.objective, evidence: evidence(row) })
    : v12.createDpiSelectedRoleTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
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

test('v13 sends byte-identical objective-scoped base requests and binds that selection in policy metadata', () => {
  assert.equal(input.version, expectations.inputVersion);
  for (const row of labelled) {
    const base = baseFor(row);
    const candidate = createDpiSelectedObjectiveTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const baseWire = base.stages[0].messages(), wire = candidate.stages[0].messages();
    assert.equal(candidate.version, VERSION);
    assert.equal(JSON.stringify(wire), JSON.stringify(baseWire), row.id);
    assert.equal(candidate.policy.schemaSha256, base.policy.schemaSha256);
    assert.equal(candidate.policy.instructionsSha256, sha(JSON.stringify({
      version: VERSION,
      objective: row.objective,
      baseVersion: base.version,
      baseInstructionsSha256: base.policy.instructionsSha256,
      schemaSha256: candidate.policy.schemaSha256,
      composition: COMPOSITION,
    })));
  }
  assert.throws(() => createDpiSelectedObjectiveTechniqueCandidate({ objective: 'side_stepping', evidence: [] }));
});

test('v13 preserves each chosen base parser and reducer across the fixed four cases', () => {
  for (const row of labelled) {
    const base = baseFor(row);
    const candidate = createDpiSelectedObjectiveTechniqueCandidate({ objective: row.objective, evidence: evidence(row) });
    const baseResult = base.combine(base.stages[0].validate(raw(base, row)));
    const result = candidate.combine(candidate.stages[0].validate(raw(candidate, row)));
    assert.equal(result.verdict, row.expected.verdict, row.id);
    assert.deepEqual(withoutWireVersion(result), withoutWireVersion(baseResult), row.id);
    const invalid = JSON.parse(raw(candidate, row));
    invalid.selected.context.defeatingContext = [{ id: candidate.catalog.entries.find(entry => entry.field === 'response').id }];
    assert.throws(() => candidate.stages[0].validate(JSON.stringify(invalid)), row.id);
  }
});
