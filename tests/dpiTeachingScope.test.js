'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { solutions } = require('../server/data/promptInjectionSolutions');

test('DPI solutions distinguish deliberately weakened training from model benchmarking', () => {
  for (const [id, solution] of Object.entries(solutions)) {
    assert.match(solution.approach, /objective-specific application policy/, id);
    assert.match(solution.approach, /encoding exercise starts with an AWS-only rule/, id);
    assert.match(solution.approach, /not the resistance of an unmodified model/, id);
    assert.match(solution.approach, /do not guarantee success/, id);
  }
});

test('encoding and language lessons describe the actual actor boundary', () => {
  const encoding = JSON.stringify(solutions.obfuscation);
  assert.match(encoding, /LangGraph agent can choose decode_payload/);
  assert.match(encoding, /application trust-boundary flaw/);
  assert.match(encoding, /not a verified defense/);
  assert.doesNotMatch(encoding, /server decoding is only Judge ground truth|server does not decode/);
  assert.match(encoding, /Judge ground truth/);
  assert.doesNotMatch(encoding, /decoded by the preprocessor|treated as trusted input/);
  const language = JSON.stringify(solutions.multi_language);
  assert.match(language, /exception deliberately written into the training prompt/);
  assert.doesNotMatch(language, /cannot be parsed|bypasses the English-only safety filter/);
});

// Copy assertions describe deliberate lab policy, not a model success guarantee.
test('DPI hints and persona card name the actual deliberate application-policy exceptions',()=>{
 const hints=require('../server/data/workshopHints').direct_prompt_injection;
 assert.match(hints.system_prompt.hints[0],/deliberately includes a SYSTEM AUDIT PROTOCOL/);
 assert.match(hints.system_prompt.hints[0],/synthetic protected instructions/);
 assert.match(hints.jailbreak.hints[0],/AWS-only scope policy.*instruction-override exception/);
 assert.doesNotMatch(hints.jailbreak.hints[0],/safety guidelines/);
 assert.match(hints.virtualization.hints[0],/non-AWS answers.*hypothetical-context exception/);
 assert.doesNotMatch(hints.virtualization.hints[0],/content filters/);
 const ui=require('node:fs').readFileSync(require('node:path').join(__dirname,'../client/src/pages/challenges/DirectPromptInjectionChallenge.js'),'utf8');
 assert.match(ui,/Assign a persona and test the training prompt’s explicit exception to its AWS-only scope\./);
 assert.doesNotMatch(ui,/Make the AI assume a different persona to circumvent guardrails/);
});
