'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const calibration = require('./fixtures/dpiSpanCalibration');
const main = require('./fixtures/dpiSpanCalibrationMain');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');

for (const profile of [main.SOURCE_TECHNIQUE_V11_PROFILE, main.ROLE_TECHNIQUE_V12_PROFILE]) test(`${profile} admits only the frozen source-only four-case input`, () => {
  const input = fs.readFileSync(main.SOURCE_TECHNIQUE_V11_INPUT);
  const labels = fs.readFileSync(main.SOURCE_TECHNIQUE_V11_EXPECTATIONS);
  assert.equal(sha(input), main.SOURCE_TECHNIQUE_V11_SHA);
  assert.equal(sha(labels), main.SOURCE_TECHNIQUE_V11_EXPECTATIONS_SHA);
  const rows = main.projectSelectedSourceTechnique(JSON.parse(input), profile);
  assert.deepEqual(rows.map(row => row.id), ['jb_plain_question_substantive', 'jb_explicit_override_substantive', 'rp_plain_question_substantive', 'rp_explicit_persona_substantive']);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'id,objective,request,response'));
  assert.deepEqual(main.settings({ DPI_SPAN_PROFILE: profile }), {
    profile, input: main.SOURCE_TECHNIQUE_V11_INPUT,
    inputSha: main.SOURCE_TECHNIQUE_V11_SHA, records: 4, calls: 4, workMs: 780000, externalMs: 180000,
  });
  const spec = main.sourceTechniqueSpec(profile);
  const candidateModule = require('../' + spec.path);
  assert.deepEqual(calibration.profileFor(profile), {
    protocols: [candidateModule.VERSION], cases: 4, calls: 4, contextTokens: 20480,
  });
  for (const row of rows) {
    const candidate = candidateModule[spec.factory]({
      objective: row.objective, evidence: calibration.evidenceFor(row, profile),
    });
    assert.deepEqual(candidate.stages.map(stage => [stage.id, stage.maximumCalls]), [['assessment', 1]]);
    assert.equal(candidate.policy.maximumCalls, 1);
  }
});

for (const profile of [main.SOURCE_TECHNIQUE_V11_PROFILE, main.ROLE_TECHNIQUE_V12_PROFILE]) test(`${profile} admission binds its candidate and keeps labels out of pins`, () => {
  const spec = main.sourceTechniqueSpec(profile);
  const candidateModule = require('../' + spec.path);
  const candidateSha = 'a'.repeat(64);
  const cfg = main.settings({ DPI_SPAN_PROFILE: profile });
  const pins = new Map([[spec.path, candidateSha]]);
  const admission = {
    version: 'dpi-selected-source-technique-calibration-v1', inputSha256: cfg.inputSha,
    protocol: candidateModule.VERSION, candidatePath: spec.path,
    candidateSha256: candidateSha, contextTokens: 20480, providerTimeoutMs: 180000, transportTimeoutMs: 180000,
    sourceOnly: true, labelsExternal: true,
  };
  assert.deepEqual(main.validateSourceTechniqueAdmission({ sourceTechniqueAdmission: admission }, pins, cfg), admission);
  assert.throws(() => main.validateSourceTechniqueAdmission({ sourceTechniqueAdmission: { ...admission, contextTokens: 32768 } }, pins, cfg));
  const source = fs.readFileSync('tests/fixtures/dpiSpanCalibration.js', 'utf8');
  assert.match(source, /num_ctx:contextTokens/);
  assert.match(source, /ROLE_TECHNIQUE_V12_PROFILE/);
});
