'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path');
const { createHash } = require('node:crypto');
const { verifyAuditWorkerArtifacts: verify } = require('../server/services/secureshopAuditArtifactVerification');
const hash = value => createHash('sha256').update(value).digest('hex');
async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-artifact-verify-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const artifacts = {};
  for (const name of ['messages', 'traces', 'effects']) {
    const data = JSON.stringify([{ name, text: 'raw instruction' }]);
    await fs.writeFile(path.join(directory, `${name}.json`), data);
    artifacts[name] = { bytes: Buffer.byteLength(data), sha256: hash(data) };
  }
  await fs.writeFile(path.join(directory, 'log.txt'), 'raw log');
  await fs.writeFile(path.join(directory, 'sources.json'), '[]');
  return { directory, artifacts, manifest: { sourceBytes: 9, logSha256: hash('raw log'), sourcesSha256: hash('[]') }, checkCurrent: async () => {} };
}
test('verifies all fixed artifacts and sources, returning immutable references', async t => {
  const input = await fixture(t), result = await verify(input);
  assert.deepEqual(result, input.artifacts); assert.ok(Object.isFrozen(result.messages));
  input.artifacts.messages.sha256 = '0'.repeat(64);
  assert.notEqual(result.messages.sha256, input.artifacts.messages.sha256);
});
test('rejects modified source, artifact, size and extra path selections', async t => {
  const input = await fixture(t);
  await assert.rejects(verify({ ...input, artifacts: { ...input.artifacts, '../other': input.artifacts.messages } }), { code: 'AUDIT_ARTIFACT_INVALID' });
  await assert.rejects(verify({ ...input, artifacts: { ...input.artifacts, messages: { ...input.artifacts.messages, bytes: 1 } } }), { code: 'AUDIT_ARTIFACT_INVALID' });
  await fs.writeFile(path.join(input.directory, 'traces.json'), 'tampered');
  await assert.rejects(verify(input), { code: 'AUDIT_ARTIFACT_INVALID' });
  await fs.writeFile(path.join(input.directory, 'log.txt'), 'changed');
  await assert.rejects(verify(input), { code: 'AUDIT_ARTIFACT_INVALID' });
});
test('refuses symlinked files and stops immediately on authority loss', async t => {
  const input = await fixture(t);
  await fs.unlink(path.join(input.directory, 'effects.json'));
  await fs.symlink('messages.json', path.join(input.directory, 'effects.json'));
  await assert.rejects(verify(input));
  await assert.rejects(verify({ ...input, checkCurrent: async () => { throw new Error('stale'); } }), /stale/);
});
