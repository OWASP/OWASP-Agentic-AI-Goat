'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Offline negative-path test only. The preload replaces every fetch operation
// with a controlled inventory failure before the native fixture imports models.
// It must never contact Ollama, and cannot qualify any actual actor or Judge.
test('actual8B fixture retains sanitized provenance failure evidence without invoking a model', t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-model-provenance-fixture-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const fixture = path.join(__dirname, 'postgres/legacyAiExperimentProductionActual8b.integration.test.js');
  for (const failure of ['wrong-digest', 'inventory-error']) {
    const directory = path.join(temporary, failure);
    fs.mkdirSync(directory, { mode: 0o700 });
    const evidence = path.join(directory, 'qualification.json');
    const preload = path.join(directory, 'offline-fetch.cjs');
    fs.writeFileSync(preload, `
      global.fetch = async function (input) {
        if (String(input) !== 'http://127.0.0.1:11434/api/tags') {
          throw new Error('No model or external network operation is allowed in this offline test');
        }
        ${failure === 'inventory-error'
          ? "throw new Error('PRIVATE-INVENTORY-ERROR');"
          : "return new Response(JSON.stringify({models:[{name:'llama3.1:8b',digest:'PRIVATE-INVENTORY-DIGEST'}]}),{status:200});"}
      };
    `, { mode: 0o600 });
    const result = spawnSync(process.execPath, ['--require', preload, '--test', '--test-reporter=tap', fixture], {
      cwd: path.dirname(__dirname), encoding: 'utf8', timeout: 10000,
      env: { PATH: process.env.PATH, HOME: directory, TMPDIR: directory, NODE_ENV: 'test',
        LEGACY_AI_EXPERIMENT_ACTUAL8B_ISOLATED: '1', LEGACY_AI_EXPERIMENT_ACTUAL8B_STAGE: 'actual8b-v1',
        OLLAMA_BASE_URL: 'http://127.0.0.1:11434', OLLAMA_MODEL: 'llama3.1:8b', JUDGE_MODEL: 'llama3.1:8b',
        LEGACY_AI_EXPERIMENT_MODEL_DIGEST: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
        LEGACY_AI_EXPERIMENT_ACTUAL8B_EVIDENCE_PATH: evidence },
    });
    assert.equal(result.error, undefined, failure);
    assert.equal(result.status, 1, failure);
    const text = fs.readFileSync(evidence, 'utf8');
    const report = JSON.parse(text);
    assert.equal(report.qualification, 'incomplete');
    assert.equal(report.modelVerifiedBefore, false);
    assert.equal(report.modelVerifiedAfter, false);
    assert.deepEqual(report.cases, []);
    assert.deepEqual(report.judgeCalibrations, []);
    assert.deepEqual(report.cancellation, { passed: false, calls: [] });
    assert.deepEqual(report.failures, ['model-provenance']);
    assert.equal((text + result.stdout + result.stderr).includes('PRIVATE-INVENTORY'), false);
  }
});
