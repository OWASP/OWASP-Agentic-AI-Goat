'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { projectCtfGuardianResult, requireCtfGuardianResult } = require('../server/agent-runtime/ctfGuardianResult');

test('durable guardian evidence binds exact raw and visible bytes without exposing protected output', () => {
  const { captureCtfGuardianEvidence } = require('../server/agent-runtime/ctfGuardianResult');
  const { createHash } = require('node:crypto');
  const raw = '  fixture secret 🐈\n';
  const evidence = captureCtfGuardianEvidence({ response: raw, provider: 'ollama', model: 'fixture:8b', mocked: false }, '[REDACTED]');
  assert.equal(evidence.provider, 'ollama'); assert.equal(evidence.model, 'fixture:8b');
  assert.equal(evidence.rawResponseSha256, createHash('sha256').update(raw).digest('hex'));
  assert.notEqual(evidence.rawResponseSha256, evidence.visibleResponseSha256);
  assert.equal(evidence.rawResponseBytes, Buffer.byteLength(raw));
  assert.doesNotMatch(JSON.stringify(evidence), /fixture secret/);
  assert.equal(captureCtfGuardianEvidence({ response: raw, provider: 'mock', model: 'fixture', mocked: true }, raw), null);
  assert.equal(captureCtfGuardianEvidence(null, raw), null);
});

test('only an explicit supported model result qualifies as a real CTF guardian response', () => {
  assert.deepEqual(projectCtfGuardianResult({ response: 'visible', provider: 'ollama',
    model: 'llama3.1:8b', mocked: false, fallback: false }), {
    text: 'visible', realModel: true, provider: 'ollama', model: 'llama3.1:8b',
  });
  assert.equal(projectCtfGuardianResult({ text: 'visible', provider: 'openai',
    model: 'gpt-4', mocked: false }).realModel, true);
});

test('unavailable guardian results stop the graph before output defenses or visible-secret grading', async () => {
  const { runCtfGuardianGraph } = require('../server/agent-runtime/ctfGuardianGraph');
  for (const result of [null,
    { response: 'FIXTURE_SECRET', provider: 'mock', model: 'fixture', mocked: true },
    { response: 'FIXTURE_SECRET', provider: 'ollama', model: 'llama3.1:8b', mocked: false, fallback: true },
  ]) {
    let defenses = 0, grades = 0;
    await assert.rejects(runCtfGuardianGraph({ success_criteria: 'FIXTURE_SECRET' }, 'fixture', {
      generate: async () => requireCtfGuardianResult(result).text,
      runOutputDefenses: async () => { defenses++; return 'FIXTURE_SECRET'; },
      normalizedContains: () => { grades++; return true; },
    }), { code: 'CTF_GUARDIAN_UNAVAILABLE' });
    assert.equal(defenses, 0);
    assert.equal(grades, 0);
  }
  assert.equal(requireCtfGuardianResult({ response: 'real reply', provider: 'ollama',
    model: 'llama3.1:8b', mocked: false }).text, 'real reply');
});

test('missing identity, mock/fallback metadata and malformed text cannot become CTF credit', () => {
  const invalid = [
    { response: 'secret', provider: 'ollama', mocked: false },
    { response: 'secret', provider: 'ollama', model: 'llama3.1:8b' },
    { response: 'secret', provider: 'fixture', model: 'fixture', mocked: false },
    { response: 'secret', provider: 'ollama', model: 'llama3.1:8b', mocked: true },
    { response: 'secret', provider: 'ollama', model: 'llama3.1:8b', mocked: false, fallback: true },
    { response: {}, provider: 'ollama', model: 'llama3.1:8b', mocked: false },
    { response: '   ', provider: 'ollama', model: 'llama3.1:8b', mocked: false },
    null,
  ];
  for (const value of invalid) assert.equal(projectCtfGuardianResult(value).realModel, false);
});

test('guardian provenance does not depend on unrelated response phrases', () => {
  const projected = projectCtfGuardianResult({
    response: 'The protected value appeared while discussing access configuration files.',
    provider: 'ollama', model: 'llama3.1:8b', mocked: false,
  });
  assert.equal(projected.realModel, true);
  assert.match(projected.text, /access configuration files/);
});
