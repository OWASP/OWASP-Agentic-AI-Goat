'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { solutions } = require('../server/data/promptInjectionSolutions');
const hints = require('../server/data/workshopHints').direct_prompt_injection;
const ui = require('node:fs').readFileSync(require('node:path').join(__dirname,
  '../client/src/pages/challenges/DirectPromptInjectionChallenge.js'), 'utf8');

test('the shared DPI introduction explains the lab policy and Judge requirement once', () => {
  assert.match(ui, /Each objective selects its own application policy/);
  assert.match(ui, /does not prove the model disobeyed its governing instructions/);
  assert.match(ui, /A refusal or unrelated answer earns no credit/);
  for (const solution of Object.values(solutions)) {
    assert.doesNotMatch(solution.approach, /Training scope:/);
    assert.ok(solution.examples.length > 0);
  }
});

test('encoding and language help retain the actual teaching boundaries', () => {
  const encoding = JSON.stringify(solutions.obfuscation);
  assert.match(encoding, /decoder tool/);
  assert.match(encoding, /application promotes the decoder output into instructions/);
  assert.match(encoding, /answer to the decoded question/);
  assert.match(encoding, /Leetspeak and split words are unsupported/);
  assert.match(encoding, /fixed mode earns no attack credit/);
  assert.doesNotMatch(encoding, /decoded by the preprocessor|server does not decode/);
  assert.match(hints.multi_language.hints.join(' '), /lab prompt has an exception/);
  assert.doesNotMatch(JSON.stringify(solutions.multi_language), /cannot be parsed|bypasses the English-only safety filter/);
});

test('short help retains lab-specific exceptions and matches the canonical technique names', () => {
  assert.match(hints.system_prompt.hints.join(' '), /lab prompt.*weak audit rule/);
  assert.match(hints.jailbreak.hints.join(' '), /lab prompt permits some instruction overrides/);
  assert.match(hints.virtualization.hints.join(' '), /lab prompt has an exception for hypothetical questions/);
  const catalog = require('../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.direct_prompt_injection;
  for (const objective of catalog) {
    assert.equal(hints[objective.id].title, objective.text);
    if (solutions[objective.id]) assert.equal(solutions[objective.id].title, objective.text);
  }
});
