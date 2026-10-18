'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { checkpoint, verifyCheckpoint, sha, COMPARISON } = require('../server/agent-runtime/auditJudgeStageCheckpoint');
const input = () => ({ stage: 'source', runId: '52bfe3e3-05a4-4a2d-bb65-f183cbf46c83',
  evidenceDigest: sha('evidence'), packetSha256: sha('packet'), judgeVersion: 'test-judge',
  comparisonVersion: COMPARISON, policyDigest: sha('policy'), canonicalInputSha256: sha('canonical'),
  actualRequestSha256: sha('actual'), sourceCheckpointSha256: null,
  provider: 'ollama', model: 'owned-test-model', rawResponse: '{"passages":[]}' });

test('checkpoint rejects altered saved response or binding before reuse', () => {
  const saved = checkpoint(input());
  assert(Object.isFrozen(saved));
  assert.deepEqual(verifyCheckpoint(saved, { packetSha256: saved.packetSha256 }), saved);
  for (const mutation of [{ rawResponse: '{"passages":[{}]}' }, { model: 'different-model' },
    { policyDigest: sha('changed') }, { responseSha256: sha('forged') },
    { checkpointSha256: sha('forged') }, { version: 'other' }]) {
    assert.throws(() => verifyCheckpoint({ ...saved, ...mutation }), { code: 'AUDIT_CHECKPOINT_INVALID' });
  }
  // Even a self-consistent checkpoint from another packet cannot satisfy the caller's binding.
  const foreign = checkpoint({ ...input(), packetSha256: sha('another packet') });
  assert.throws(() => verifyCheckpoint(foreign, { packetSha256: saved.packetSha256 }),
    { code: 'AUDIT_CHECKPOINT_INVALID' });
});

test('effect checkpoints bind a source digest and enforce response byte limits', () => {
  const source = checkpoint(input());
  const effect = checkpoint({ ...input(), stage: 'effect', sourceCheckpointSha256: source.checkpointSha256 });
  assert.deepEqual(verifyCheckpoint(effect, { sourceCheckpointSha256: source.checkpointSha256 }), effect);
  assert.throws(() => verifyCheckpoint(effect, { sourceCheckpointSha256: sha('other source') }),
    { code: 'AUDIT_CHECKPOINT_INVALID' });
  for (const mutation of [{ stage: 'effect' }, { stage: 'support' },
    { sourceCheckpointSha256: source.checkpointSha256 }, { rawResponse: '' },
    { rawResponse: 'é'.repeat(8193) }]) {
    assert.throws(() => checkpoint({ ...input(), ...mutation }), { code: 'AUDIT_CHECKPOINT_INVALID' });
  }
  assert.equal(Buffer.byteLength(checkpoint({ ...input(), rawResponse: 'é'.repeat(8192) }).rawResponse), 16384);
});
