'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { posix } = require('node:path');
const { createHash } = require('node:crypto');
const { createSecureShopReservedFileReader } = require('../server/services/secureshopReservedFiles');

const scope = { platformSessionId: 1, platformOwnerId: 2, launchId: 'launch', generation: 3 };
function fixture({ check, provision, read, corrupt = false, wrongTarget = false, reservation = {}, wrongPath = false } = {}) {
  const events = [];
  const target = { targetId: 'target', launchId: 'launch', scenarioId: 'scenario', generation: 3, kind: 'files', ...reservation };
  let checks = 0;
  const launches = {
    async reserveFilesTarget(args) { events.push(['reserve', args]); return target; },
    async assertCurrent(args) { events.push(['authorize', args]); if (check) await check(++checks); },
  };
  const files = {
    async provisionReservedTarget(args) { events.push(['provision', args]); if (provision) await provision(); return { ...args,
      targetId: wrongTarget ? 'other-target' : args.targetId, capability: 'internal-file-secret' }; },
    async readFile(capability, requestedPath, options) {
      events.push(['read', requestedPath, options]); assert.equal(capability, 'internal-file-secret');
      if (read) await read();
      return { generation: 3, virtualPath: wrongPath ? '/wrong-file' : posix.resolve('/', options.base, requestedPath), bytes: 3,
        sha256: corrupt ? 'bad-digest' : createHash('sha256').update('lab').digest('hex'), data: Buffer.from('lab') };
    },
  };
  return { reader: createSecureShopReservedFileReader({ launches, files }), events };
}

test('reserved read records ownership first, preserves traversal, and returns no internal bearer', async () => {
  const { reader, events } = fixture();
  const result = await reader.readFile(scope, '../server/config/.env', { base: '/uploads' });
  assert.deepEqual(events.map(event => event[0]), ['reserve', 'authorize', 'provision', 'authorize', 'read', 'authorize']);
  assert.equal(events[4][1], '../server/config/.env');
  assert.equal(events[4][2].expectedGeneration, 3);
  assert.equal(result.data.toString(), 'lab');
  assert.equal(result.targetId, 'target');
  assert.ok(!JSON.stringify(result).includes('internal-file-secret'));
});

test('authority lost after provisioning prevents reading the target', async () => {
  const { reader, events } = fixture({ check: count => { if (count === 2) throw new Error('stale'); } });
  await assert.rejects(reader.readFile(scope, '/etc/passwd'), /stale/);
  assert.ok(!events.some(event => event[0] === 'read'));
});

test('revocation observed by the final authority check suppresses returned bytes', async () => {
  const { reader, events } = fixture({ check: count => { if (count === 3) throw new Error('stale'); } });
  await assert.rejects(reader.readFile(scope, '/etc/passwd'), /stale/);
  assert.ok(events.some(event => event[0] === 'read'));
});

test('asynchronous work cannot change the copied owner or generation', async () => {
  const mutable = { ...scope };
  const { reader, events } = fixture({ provision: () => { mutable.platformOwnerId = 999; mutable.generation = 100; } });
  await reader.readFile(mutable, '/etc/passwd');
  for (const event of events.filter(event => event[0] === 'authorize')) {
    assert.equal(event[1].platformOwnerId, 2);
    assert.equal(event[1].generation, 3);
  }
});

test('inconsistent file evidence is rejected before becoming a read receipt', async () => {
  const { reader } = fixture({ corrupt: true });
  await assert.rejects(reader.readFile(scope, '/etc/passwd'), { code: 'INVALID_FILE_RESULT' });
});

test('a misrouted provision result cannot select another target handle', async () => {
  const { reader, events } = fixture({ wrongTarget: true });
  await assert.rejects(reader.readFile(scope, '/etc/passwd'), { code: 'TARGET_BINDING_MISMATCH' });
  assert.ok(!events.some(event => event[0] === 'read'));
});

for (const reservation of [{ launchId: 'other-launch' }, { generation: 4 }, { kind: 'other' }]) {
  test(`misrouted reservation is rejected before provisioning: ${JSON.stringify(reservation)}`, async () => {
    const { reader, events } = fixture({ reservation });
    await assert.rejects(reader.readFile(scope, '/etc/passwd'), { code: 'RESERVATION_BINDING_MISMATCH' });
    assert.deepEqual(events.map(event => event[0]), ['reserve']);
  });
}

test('valid bytes and digest from a different virtual file are rejected', async () => {
  const { reader } = fixture({ wrongPath: true });
  await assert.rejects(reader.readFile(scope, '/etc/passwd'), { code: 'INVALID_FILE_RESULT' });
});
