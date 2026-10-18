'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { createSecureShopMailInlineTargetPool } = require('../server/services/secureshopMailInlineTargetPool');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const mailScene = require('../server/services/secureshopMailSceneBinding');

const hash = value => createHash('sha256').update(value).digest('hex');
const scope = Object.freeze({ launchId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  scenarioId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', generation: 1,
  platformOwnerId: 7, platformSessionId: 8 });
const raw = Object.freeze({ scope, targetId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  persona: { id: 12, role: 'merchant' },
  personaSession: { sessionId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', authorityVersion: '1' },
  mode: 'vuln', operationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' });
const selected = Object.freeze({ messageId: 25, messageSha256: hash('owned-message'), recipientId: 12 });
const IDS = ['11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333'];
function fixture(override) {
  let verified;
  const ids = [...IDS];
  const pool = createSecureShopMailInlineTargetPool({
    verifyBound: async (_raw, source) => {
      assert.deepEqual(source, selected);
      return override ? override(verified) : verified;
    },
    makeId: () => ids.shift(), makeNonce: () => ids.shift(),
  });
  return { pool, setBound: value => { verified = value; } };
}
function bound(reserved) {
  return { issuanceId: reserved.reservation.issuanceId,
    sendOperationId: raw.operationId, targetId: raw.targetId,
    ...selected, threadId: 31,
    listenerTargetId: reserved.reservation.listenerTargetId,
    nonceSha256: reserved.reservation.nonceSha256,
    path: reserved.reservation.path, resourceKind: reserved.reservation.resourceKind,
    urlSha256: reserved.reservation.urlSha256 };
}

test('pending mail URL rejects until durable verified activation and a one-shot fetch claim', async () => {
  const { pool, setBound } = fixture();
  try {
    const reserved = await pool.reserve(raw), exact = bound(reserved);
    assert.deepEqual(pool.assertPendingReservation(raw, reserved.reservation), reserved.reservation);
    assert.throws(() => pool.assertPendingReservation(raw,
      { ...reserved.reservation, nonceSha256: hash('forged') }), /unavailable/);
    assert.equal((await fetch(reserved.url)).status, 404);
    assert.throws(() => pool.assertBound(raw, exact), /unavailable/);
    setBound(exact);
    const activated = await pool.activate(raw, selected);
    assert.deepEqual(await pool.activate(raw, selected), activated,
      'saved send recovery only reads the same activated URL');
    assert.throws(() => pool.assertPendingReservation(raw, reserved.reservation), /unavailable/);
    assert.equal(activated.url, reserved.url);
    assert.deepEqual(activated.binding, exact);
    assert.equal((await fetch(reserved.url)).status, 404,
      'activation alone cannot let a page load the listener');
    assert.deepEqual(pool.assertBound(raw, exact), { url: reserved.url });
    assert.deepEqual(pool.claimFetch(raw, exact), { url: reserved.url });
    assert.throws(() => pool.claimFetch(raw, exact), /unavailable/);
    const response = await fetch(reserved.url), bytes = await response.arrayBuffer();
    assert.equal(response.status, 200);
    assert.equal((await fetch(reserved.url)).status, 404);
    const receipt = pool.readReceipt(raw, { issuanceId: exact.issuanceId });
    const { receiptSha256, ...base } = receipt;
    assert.deepEqual(Object.keys(base), ['version', 'issuanceId', 'sendOperationId',
      'targetId', 'listenerTargetId', 'nonceSha256', 'path', 'resourceKind',
      'urlSha256', 'method', 'status', 'responseSha256']);
    assert.equal(receiptSha256, hash(JSON.stringify(base)));
    assert.equal(receipt.responseSha256, hash(Buffer.from(bytes)));
    assert.equal(receipt.sendOperationId, raw.operationId);
    assert.equal(receipt.targetId, raw.targetId);
    assert.equal(receipt.urlSha256, hash(reserved.url));
    assert.deepEqual(await pool.consume(raw, { issuanceId: exact.issuanceId }), receipt);
    assert.deepEqual(await pool.activate(raw, selected), activated,
      'saved recovery after consumption never rearms the listener');
    assert.throws(() => pool.readReceipt(raw, { issuanceId: exact.issuanceId }), /unavailable/);
    assert.deepEqual(await pool.retire(raw), { ok: true, replayed: false });
    await assert.rejects(fetch(reserved.url));
  } finally { await pool.close(); }
});

test('wrong durable row and foreign scope never activate pending listener', async () => {
  const { pool, setBound } = fixture();
  try {
    const reserved = await pool.reserve(raw), exact = bound(reserved);
    assert.throws(() => pool.assertPendingReservation({ ...raw,
      scope: { ...scope, platformOwnerId: 9 } }, reserved.reservation), /unavailable/);
    assert.throws(() => pool.assertPendingReservation({ ...raw,
      operationId: 'ffffffff-ffff-4fff-8fff-ffffffffffff' }, reserved.reservation), /unavailable/);
    setBound({ ...exact, urlSha256: hash('other-url') });
    await assert.rejects(pool.activate(raw, selected), /unavailable/);
    assert.equal((await fetch(reserved.url)).status, 404);
    setBound(exact);
    await assert.rejects(pool.activate({ ...raw,
      scope: { ...scope, platformOwnerId: 9 } }, selected), /unavailable/);
    await pool.activate(raw, selected);
    const foreign = { ...raw, persona: { id: 13, role: 'merchant' } };
    assert.throws(() => pool.claimFetch(foreign, exact), /unavailable/);
    assert.throws(() => pool.claimFetch(raw, { ...exact, messageSha256: hash('other') }), /unavailable/);
    assert.equal((await fetch(reserved.url)).status, 404);
    await pool.retire(raw);
    assert.throws(() => pool.assertPendingReservation(raw, reserved.reservation), /unavailable/);
    await assert.rejects(pool.activate(raw, selected), /unavailable/);
  } finally { await pool.close(); }
});

test('an attempted fetch is not rearmed after failure and shutdown drains pending listener', async () => {
  const { pool, setBound } = fixture();
  const reserved = await pool.reserve(raw), exact = bound(reserved);
  setBound(exact);
  await pool.activate(raw, selected);
  pool.claimFetch(raw, exact);
  assert.throws(() => pool.claimFetch(raw, exact), /unavailable/);
  await pool.close();
  await assert.rejects(fetch(reserved.url));
  assert.throws(() => pool.readReceipt(raw, { issuanceId: exact.issuanceId }), /unavailable/);
});

test('failed durable save cancels only its pending listener and cannot rearm the send', async () => {
  const { pool, setBound } = fixture();
  try {
    const reserved = await pool.reserve(raw), exact = bound(reserved);
    setBound(exact);
    assert.deepEqual(await pool.cancelPending(raw, { issuanceId: exact.issuanceId }), { ok: true });
    await assert.rejects(fetch(reserved.url));
    assert.throws(() => pool.assertPendingReservation(raw, reserved.reservation), /unavailable/);
    await assert.rejects(pool.activate(raw, selected), /unavailable/);
    await assert.rejects(pool.reserve(raw), /unavailable/);
  } finally { await pool.close(); }
});

test('capacity counts pending listeners and releases only after close; reset needs durable authority', async () => {
  const cleanupId = '44444444-4444-4444-8444-444444444444';
  const cleanupScope = { ...scope, targetId: raw.targetId };
  const pool = createSecureShopMailInlineTargetPool({ verifyBound: async () => null,
    authorizeRetirement: async (_target, authority) => {
      if (authority.operationId !== cleanupId) throw Error('no durable cleanup receipt');
      return { version: 1, ...authority.scope, operationId: authority.operationId };
    } });
  try {
    const owned = [];
    for (let i = 0; i < 4; i += 1) {
      const send = { ...raw, operationId: `0000000${i}-0000-4000-8000-000000000000` };
      owned.push({ send, reserved: await pool.reserve(send) });
    }
    const next = { ...raw, operationId: '00000004-0000-4000-8000-000000000000' };
    await assert.rejects(pool.reserve(next), /unavailable/);
    await pool.cancelPending(owned[0].send, { issuanceId: owned[0].reserved.reservation.issuanceId });
    const replacement = await pool.reserve(next);
    assert.equal((await fetch(replacement.url)).status, 404);
    await assert.rejects(pool.retireTarget(raw.targetId, { scope: cleanupScope,
      operationId: '55555555-5555-4555-8555-555555555555' }), /no durable cleanup receipt/);
    const authority = { scope: cleanupScope, operationId: cleanupId };
    assert.deepEqual(await pool.retireTarget(raw.targetId, authority), { ok: true, replayed: false });
    assert.deepEqual(await pool.retireTarget(raw.targetId, authority), { ok: true, replayed: true });
    await assert.rejects(fetch(replacement.url));
    await assert.rejects(pool.reserve({ ...raw,
      operationId: '66666666-6666-4666-8666-666666666666' }), /unavailable/);
  } finally { await pool.close(); }
});

test('concurrent pending listener creations occupy the per-target capacity', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const pool = createSecureShopMailInlineTargetPool({ verifyBound: async () => null,
    createListener: async () => { await gate; return { origin: 'http://127.0.0.1:19001',
      close: async () => {} }; } });
  const operations = [0, 1, 2, 3].map(index => ({ ...raw,
    operationId: `1000000${index}-0000-4000-8000-000000000000` }));
  const creating = operations.map(input => pool.reserve(input));
  try {
    await assert.rejects(pool.reserve({ ...raw,
      operationId: '10000004-0000-4000-8000-000000000000' }), /unavailable/);
    release();
    const reserved = await Promise.all(creating);
    assert.equal(new Set(reserved.map(row => row.reservation.issuanceId)).size, 4);
  } finally { release(); await pool.close(); }
});

test('retirement and shutdown report a failed close during pending creation, then retry it', async () => {
  let release, allowClose = false, closeCalls = 0;
  const gate = new Promise(resolve => { release = resolve; });
  const authority = { scope: { ...scope, targetId: raw.targetId },
    operationId: '77777777-7777-4777-8777-777777777777' };
  const pool = createSecureShopMailInlineTargetPool({ verifyBound: async () => null,
    authorizeRetirement: async () => ({ version: 1, ...authority.scope,
      operationId: authority.operationId }),
    createListener: async () => {
      await gate;
      return { origin: 'http://127.0.0.1:19002', close: async () => {
        closeCalls += 1;
        if (!allowClose) throw Error('owned listener close failed');
      } };
    } });
  const reserving = pool.reserve(raw), retiring = pool.retireTarget(raw.targetId, authority);
  release();
  await assert.rejects(reserving, /reservation cleanup failed/);
  await assert.rejects(retiring, /retirement failed/);
  await assert.rejects(pool.close(), /shutdown failed/);
  assert.ok(closeCalls >= 3, 'each failed cleanup remained discoverable for retry');
  allowClose = true;
  assert.deepEqual(await pool.retireTarget(raw.targetId, authority), { ok: true, replayed: true });
  await pool.close();
});

test('reset uses immutable mail target birth while an admin has a newer scene execution', async () => {
  const execution = { ...scope, launchId: '88888888-8888-4888-8888-888888888888',
    platformSessionId: 29 };
  const scene = createSceneBinding({ ...scope, targetId: raw.targetId }, {
    sceneId: '99999999-9999-4999-8999-999999999999', sceneGeneration: 2,
    grantId: 'aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa', execution,
    withLease: work => work() });
  const target = mailScene.attach({ ...scope, targetId: raw.targetId }, scene);
  const current = mailScene.copy(target, { ...raw, scope: execution, target });
  const authority = { scope: { ...scope, targetId: raw.targetId },
    operationId: 'bbbbbbbb-0000-4000-8000-bbbbbbbbbbbb' };
  const pool = createSecureShopMailInlineTargetPool({ verifyBound: async () => null,
    authorizeRetirement: async () => ({ version: 1, ...authority.scope,
      operationId: authority.operationId }) });
  try {
    const reserved = await pool.reserve(current);
    assert.equal((await fetch(reserved.url)).status, 404);
    assert.deepEqual(await pool.retireTarget(raw.targetId, authority), { ok: true, replayed: false });
    await assert.rejects(fetch(reserved.url));
  } finally { await pool.close(); }
});
