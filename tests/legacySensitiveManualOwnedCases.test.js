'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createLegacySensitiveManualOwnedCases } = require('./fixtures/legacySensitiveManualOwnedCases');
const { inspect, rubricFor } = require('../server/services/legacySensitiveObjectiveGrader');

function rootFor(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'legacy-sensitive-manual-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('owned manual cases execute real tools and satisfy independently declared effects', t => {
  const root = rootFor(t);
  const cases = createLegacySensitiveManualOwnedCases({ ownedRoot: root });
  assert.equal(cases.length, 11);
  assert.equal(new Set(cases.map(row => row.name)).size, 11);
  for (const objectiveId of ['path_traversal', 'ssi_injection', 'combined_traversal_ssi']) {
    const core = cases.filter(row => row.core && row.objectiveId === objectiveId);
    assert.deepEqual(core.map(row => row.expected.completed), [true, false]);
  }
  for (const fixture of cases) {
    const result = fixture.invoke();
    const expected = fixture.expected;
    assert.equal(result.success, expected.success, fixture.name);
    for (const field of ['content', 'rendered', 'ssiSucceeded', 'commandExecution', 'code']) {
      if (Object.hasOwn(expected, field)) assert.equal(result[field], expected[field], `${fixture.name}:${field}`);
    }
    if (Object.hasOwn(expected, 'protectedPath')) assert.equal(result.boundary?.outsidePublic === true, expected.protectedPath, fixture.name);
    const observed = inspect(fixture.objectiveId, result);
    assert.equal(observed.facts.known_flag, expected.knownFlag, fixture.name);
    const required = rubricFor(fixture.objectiveId).requiredFacts;
    assert.equal(required.some(key => /model|decision|call/.test(key)), false);
    assert.equal(required.every(key => observed.facts[key]), expected.completed, fixture.name);
    assert.deepEqual(fixture.invoke(), result, `${fixture.name}: repeatable`);
  }
});

test('builder refuses implicit, occupied, workspace and symlink roots without writing', t => {
  assert.throws(() => createLegacySensitiveManualOwnedCases(), /explicit absolute/);
  assert.throws(() => createLegacySensitiveManualOwnedCases({ ownedRoot: '.' }), /explicit absolute/);
  assert.throws(() => createLegacySensitiveManualOwnedCases({ ownedRoot: path.resolve(__dirname, '..') }), /outside the workspace/);
  const root = rootFor(t);
  fs.writeFileSync(path.join(root, 'sentinel'), 'preserve');
  assert.throws(() => createLegacySensitiveManualOwnedCases({ ownedRoot: root }), /empty/);
  assert.deepEqual(fs.readdirSync(root), ['sentinel']);
  assert.equal(fs.readFileSync(path.join(root, 'sentinel'), 'utf8'), 'preserve');
  const parent = rootFor(t);
  const actual = path.join(parent, 'actual');
  const link = path.join(parent, 'link');
  fs.mkdirSync(actual);
  fs.symlinkSync(actual, link);
  assert.throws(() => createLegacySensitiveManualOwnedCases({ ownedRoot: link }), /non-symlink/);
  assert.deepEqual(fs.readdirSync(actual), []);
});
