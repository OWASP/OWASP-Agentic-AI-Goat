'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSecureShopAuditUnboundedWitnessReader,
  createSecureShopAuditUnboundedOwnedWitnessSelector } = require('../server/services/secureshopAuditUnboundedWitnessReader');

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const binding = Object.freeze({ launchId: id, scenarioId: id, generation: 1, platformOwnerId: 7,
  platformSessionId: 8, shopUserId: 7, role: 'admin' });
const hash = value => createHash('sha256').update(value).digest('hex');

function fixture() {
  const line = 'owned audit witness: unusual export event';
  const log = `ordinary event\n${line}\nordinary event two`;
  const sources = JSON.stringify([{ id: `review:${id}` }, { id: 'agents:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
    { id: 'agents:cccccccc-cccc-4ccc-8ccc-cccccccccccc' }]);
  const artifacts = { log: { bytes: Buffer.byteLength(log), sha256: hash(log) },
    sources: { bytes: Buffer.byteLength(sources), sha256: hash(sources) } };
  const evidence = { runId: id, summary: 'The unusual export was observed.', provider: 'ollama', model: 'llama3.1:8b',
    requestedCount: 101, rowCount: 101, artifacts };
  return { line, log, sources, evidence };
}

test('derives the witness only from the current owner-fenced saved log', async () => {
  const f = fixture(); let openInput; let selectedInput; let checks = 0;
  const readWitness = createSecureShopAuditUnboundedWitnessReader({
    async openAuditRun(input) {
      openInput = input;
      return { ...f.evidence, artifacts: f.evidence.artifacts,
        async *readArtifact(name) { yield Buffer.from(name === 'log' ? f.log : f.sources); } };
    },
    async selectWitness(input) {
      selectedInput = input;
      return { version: 1, line: f.line, sha256: hash(f.line) };
    },
  });
  const value = await readWitness({ binding, execution: { runId: id, async check() { checks++; } }, evidence: f.evidence });
  assert.deepEqual(value, { version: 1, line: f.line, sha256: hash(f.line) });
  assert.equal(openInput.runId, id); assert.equal(openInput.scope.shopUserId, binding.shopUserId);
  assert.deepEqual(openInput.persona, { id: binding.shopUserId, role: 'admin' });
  assert.equal(selectedInput.logText, f.log); assert.equal(selectedInput.logSha256, f.evidence.artifacts.log.sha256);
  assert.ok(checks >= 3);
});

test('rejects substituted saved artifacts and selectors that do not name one exact saved line', async () => {
  const f = fixture(); let selectorCalls = 0;
  const reader = ({ savedArtifacts = f.evidence.artifacts, selected = { version: 1, line: 'missing', sha256: hash('missing') } } = {}) =>
    createSecureShopAuditUnboundedWitnessReader({
      async openAuditRun() { return { ...f.evidence, artifacts: savedArtifacts,
        async *readArtifact(name) { yield Buffer.from(name === 'log' ? f.log : f.sources); } }; },
      async selectWitness() { selectorCalls++; return selected; },
    });
  const execution = { runId: id, async check() {} };
  await assert.rejects(reader({ savedArtifacts: { ...f.evidence.artifacts, log: { ...f.evidence.artifacts.log, sha256: '0'.repeat(64) } } })
    ({ binding, execution, evidence: f.evidence }), { code: 'AUDIT_UNBOUNDED_WITNESS_MISMATCH' });
  assert.equal(selectorCalls, 0);
  await assert.rejects(reader()({ binding, execution, evidence: f.evidence }), { code: 'AUDIT_UNBOUNDED_WITNESS_INVALID' });
  await assert.rejects(reader({ selected: { version: 1, line: f.log, sha256: hash(f.log) } })
    ({ binding, execution, evidence: f.evidence }), { code: 'AUDIT_UNBOUNDED_WITNESS_INVALID' });
});

test('server-owned selector requires one exact persisted fixture event, never a generic first line', async () => {
  const descriptor = { sourceEventId: `review:${id}`, actor: 'admin', action: 'audit_unbounded_witness', target: 'owned-v36-target',
    paramsJson: JSON.stringify({ version: 1, nonce: 'owned-v36-nonce' }) };
  const selector = createSecureShopAuditUnboundedOwnedWitnessSelector(descriptor);
  const expected = '[2026-10-13T00:00:00.000Z] actor=admin action=audit_unbounded_witness target=owned-v36-target params={"version":1,"nonce":"owned-v36-nonce"}';
  const sources = JSON.stringify([{ id: 'agents:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, { id: `review:${id}` },
    { id: 'agents:cccccccc-cccc-4ccc-8ccc-cccccccccccc' }]);
  const selected = await selector({ logText: `ordinary event\n${expected}\nother event`, sourcesText: sources });
  assert.deepEqual(selected, { version: 1, line: expected, sha256: hash(expected) });
  await assert.rejects(selector({ logText: `${expected}\n${expected}`, sourcesText: sources }), { code: 'AUDIT_UNBOUNDED_WITNESS_INVALID' });
  await assert.rejects(selector({ logText: 'ordinary event only', sourcesText: '[]' }), { code: 'AUDIT_UNBOUNDED_WITNESS_INVALID' });
  assert.throws(() => createSecureShopAuditUnboundedOwnedWitnessSelector({ ...descriptor, paramsJson: '{not-json}' }), TypeError);
});
