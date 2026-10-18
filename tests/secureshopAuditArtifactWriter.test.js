'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path');
const { createHash } = require('node:crypto');
const { writeArtifacts } = require('../server/agent-runtime/workers/secureshopAuditWorker');
test('worker artifact records stream into exact JSON arrays and digest references', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-audit-writer-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const values = { messages: [{ content: 'raw\n"injection"' }, { content: 'second' }], traces: [], effects: [{ status: 'completed', workerLocal: true }] };
  const result = await writeArtifacts(root, values);
  for (const name of Object.keys(values)) {
    const body = await fs.readFile(path.join(root, `${name}.json`));
    assert.equal(body.toString(), JSON.stringify(values[name]));
    assert.equal(result[name].sha256, createHash('sha256').update(body).digest('hex'));
    assert.equal(result[name].bytes, body.length);
  }
});
test('worker rejects aggregate artifact overflow instead of returning partial references', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-audit-writer-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await assert.rejects(writeArtifacts(root, { messages: [], traces: [], effects: [] }, 5), /ARTIFACT_LIMIT/);
});
