'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSecureShopReservedFileWriter, MAX_UPLOAD_BYTES } = require('../server/services/secureshopReservedFileWriter');

const scope = Object.freeze({
  launchId: '123e4567-e89b-42d3-a456-426614174000',
  scenarioId: '123e4567-e89b-42d3-a456-426614174001',
  generation: 4,
  platformOwnerId: 71,
  platformSessionId: 81,
});
const targetId = '123e4567-e89b-42d3-a456-426614174002';
const operationId = '123e4567-e89b-42d3-a456-426614174003';

function input(overrides = {}) {
  return { operationId, productId: 9, bytes: Buffer.from('<script>raw teaching sink</script>'),
    filename: '../editable manual.html', mime: 'text/html', signal: undefined, ...overrides };
}

function fixture(options = {}) {
  const events = [];
  const capability = 'private-capability';
  let stored;
  let checks = 0;
  const target = { targetId, launchId: scope.launchId, scenarioId: scope.scenarioId,
    generation: scope.generation, kind: 'files', ...(options.target || {}) };
  const launches = {
    async reserveFilesTarget(value) {
      events.push(['reserve', value]);
      await options.reserve?.();
      return target;
    },
    async assertCurrent(value) {
      events.push(['current', value]);
      checks += 1;
      await options.check?.(checks);
    },
  };
  const files = {
    async provisionReservedTarget(value) {
      events.push(['provision', value]);
      await options.provision?.();
      return { ...value, ...(options.provisioned || {}), capability };
    },
    async writeFile(actualCapability, path, bytes, writeOptions) {
      events.push(['write', actualCapability, path, Buffer.from(bytes), writeOptions]);
      await options.write?.();
      stored = Buffer.from(bytes);
      return { generation: scope.generation, virtualPath: path, bytes: stored.length,
        sha256: createHash('sha256').update(stored).digest('hex'), ...(options.written || {}) };
    },
    async readFile(actualCapability, path, readOptions) {
      events.push(['read', actualCapability, path, readOptions]);
      await options.read?.();
      const data = Buffer.from(options.readBytes || stored);
      return { generation: scope.generation, virtualPath: path, bytes: data.length,
        sha256: createHash('sha256').update(data).digest('hex'), data, ...(options.readResult || {}) };
    },
  };
  return { events, writer: createSecureShopReservedFileWriter({ launches, files }) };
}

test('writes and reads exact raw bytes at a server-selected path without leaking the capability', async () => {
  const { writer, events } = fixture();
  const original = input();
  const result = await writer.writeAndReadBack(scope, original);
  const path = `/uploads/product_manuals/9/${operationId}-manual`;
  assert.deepEqual(events.map(row => row[0]), [
    'reserve', 'current', 'provision', 'current', 'current', 'write', 'current', 'current', 'read', 'current',
  ]);
  assert.deepEqual(events[0][1], { platformSessionId: 81, platformOwnerId: 71,
    launchId: scope.launchId, expectedGeneration: 4 });
  assert.deepEqual(events[2][1], { targetId, launchId: scope.launchId, scenarioId: scope.scenarioId,
    generation: 4, ownerId: '71' });
  assert.equal(events[5][2], path);
  assert.deepEqual(events[5][4], { expectedGeneration: 4, createParents: true });
  assert.equal(events[8][3].maxBytes, MAX_UPLOAD_BYTES);
  assert.equal(result.receipt.virtualPath, path);
  assert.equal(result.filename, '../editable manual.html', 'editable metadata does not select the path');
  assert.deepEqual(Object.keys(result.receipt).sort(), [
    'bytes', 'generation', 'launchId', 'platformOwnerId', 'platformSessionId',
    'scenarioId', 'sha256', 'targetId', 'virtualPath',
  ]);
  assert.equal(result.data.toString(), original.bytes.toString(), 'raw intentional content is preserved');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.receipt));
  assert.equal(JSON.stringify(result).includes('private-capability'), false);
});

test('snapshots trusted scope, metadata, and bytes before the first await', async () => {
  const mutableScope = { ...scope };
  const mutableInput = input();
  const { writer, events } = fixture({ reserve() {
    mutableScope.platformOwnerId = 999;
    mutableScope.generation = 99;
    mutableInput.filename = 'changed.txt';
    mutableInput.bytes.fill(0);
  } });
  const result = await writer.writeAndReadBack(mutableScope, mutableInput);
  assert.equal(result.filename, '../editable manual.html');
  assert.equal(result.data.toString(), '<script>raw teaching sink</script>');
  for (const row of events.filter(event => event[0] === 'current')) {
    assert.equal(row[1].platformOwnerId, 71);
    assert.equal(row[1].generation, 4);
  }
});

test('returned bytes are a copy rather than primitive-owned storage', async () => {
  let primitiveResult;
  const { writer } = fixture({ readResult: Object.freeze({}) });
  const result = await writer.writeAndReadBack(scope, input());
  primitiveResult = result.data.toString();
  result.data.fill(0);
  assert.equal(primitiveResult, '<script>raw teaching sink</script>');
  assert.equal(result.receipt.sha256, createHash('sha256').update('<script>raw teaching sink</script>').digest('hex'));
});

for (const target of [
  { scenarioId: '123e4567-e89b-42d3-a456-426614174099' },
  { launchId: '123e4567-e89b-42d3-a456-426614174099' },
  { generation: 5 },
  { kind: 'reviews' },
]) {
  test(`rejects a mismatched reservation before provisioning: ${JSON.stringify(target)}`, async () => {
    const { writer, events } = fixture({ target });
    await assert.rejects(writer.writeAndReadBack(scope, input()), { code: 'RESERVATION_BINDING_MISMATCH' });
    assert.deepEqual(events.map(row => row[0]), ['reserve']);
  });
}

test('rejects a mismatched provision result before any write', async () => {
  const { writer, events } = fixture({ provisioned: { scenarioId: '123e4567-e89b-42d3-a456-426614174099' } });
  await assert.rejects(writer.writeAndReadBack(scope, input()), { code: 'TARGET_BINDING_MISMATCH' });
  assert.equal(events.some(row => row[0] === 'write'), false);
});

for (const [name, options, code] of [
  ['write path', { written: { virtualPath: '/wrong' } }, 'INVALID_FILE_WRITE_RESULT'],
  ['write digest', { written: { sha256: '0'.repeat(64) } }, 'INVALID_FILE_WRITE_RESULT'],
  ['read bytes', { readBytes: Buffer.from('changed') }, 'INVALID_FILE_READBACK'],
  ['read path', { readResult: { virtualPath: '/wrong' } }, 'INVALID_FILE_READBACK'],
  ['read generation', { readResult: { generation: 5 } }, 'INVALID_FILE_READBACK'],
]) {
  test(`rejects inconsistent ${name} evidence`, async () => {
    const { writer } = fixture(options);
    await assert.rejects(writer.writeAndReadBack(scope, input()), { code });
  });
}

test('observed cancellation and current-authority loss suppress later effects and publication', async () => {
  const beforeWrite = new AbortController();
  const first = fixture({ provision() { beforeWrite.abort(); } });
  await assert.rejects(first.writer.writeAndReadBack(scope, input({ signal: beforeWrite.signal })), { name: 'AbortError' });
  assert.equal(first.events.some(row => row[0] === 'write'), false);

  const stale = fixture({ check(count) { if (count === 6) throw Object.assign(new Error('retired'), { code: 'LAUNCH_UNAVAILABLE' }); } });
  await assert.rejects(stale.writer.writeAndReadBack(scope, input()), { code: 'LAUNCH_UNAVAILABLE' });
  assert.equal(stale.events.some(row => row[0] === 'read'), true);
});

test('validates a closed input and public byte bound before reserving a target', async () => {
  for (const bad of [
    input({ bytes: 'not-buffer' }),
    input({ bytes: Buffer.alloc(MAX_UPLOAD_BYTES + 1) }),
    input({ productId: true }),
    input({ operationId: 'not-a-uuid' }),
    { ...input(), ownerId: 71 },
  ]) {
    const { writer, events } = fixture();
    await assert.rejects(writer.writeAndReadBack(scope, bad), { code: 'INVALID_FILE_WRITE' });
    assert.equal(events.length, 0);
  }
});

test('accessor-bearing inputs are rejected without invoking the accessor', async () => {
  let invoked = false;
  const value = input();
  Object.defineProperty(value, 'filename', { enumerable: true, get() { invoked = true; return 'x'; } });
  const { writer } = fixture();
  await assert.rejects(writer.writeAndReadBack(scope, value), { code: 'INVALID_FILE_WRITE' });
  assert.equal(invoked, false);
});
