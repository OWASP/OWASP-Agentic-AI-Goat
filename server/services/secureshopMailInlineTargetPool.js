'use strict';

const { createHash, randomUUID } = require('node:crypto');
const http = require('node:http');
const { isDeepStrictEqual } = require('node:util');
const mailScene = require('./secureshopMailSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const SCOPE_KEYS = Object.freeze(['launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId', 'targetId', 'personaId', 'role',
  'personaSessionId', 'authorityVersion']);
const RESOURCE_KIND = 'mail_inline_image_v1';
const MAX_LISTENERS = 32;
const MAX_PER_TARGET = 4;
const RESPONSE = Buffer.from(JSON.stringify({ kind: RESOURCE_KIND,
  message: 'Owned synthetic internal mail image target.' }), 'utf8');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const unavailable = () => Object.assign(Error('Owned mail inline target unavailable'),
  { code: 'MAIL_INLINE_TARGET_UNAVAILABLE', executionBoundary: true });
function id(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw unavailable();
  return value.toLowerCase();
}
function scopeOf(raw) {
  const s = raw?.scope;
  if (!s || !raw?.persona || !raw?.personaSession || !['merchant'].includes(raw.persona.role)
    || !['vuln', 'fixed'].includes(raw.mode)) throw unavailable();
  const scope = {
    launchId: id(s.launchId), scenarioId: id(s.scenarioId), generation: s.generation,
    platformOwnerId: s.platformOwnerId, platformSessionId: s.platformSessionId,
    targetId: id(raw.targetId), personaId: raw.persona.id, role: raw.persona.role,
    personaSessionId: id(raw.personaSession.sessionId),
    authorityVersion: raw.personaSession.authorityVersion,
  };
  if (!Number.isSafeInteger(scope.generation) || scope.generation < 1
    || !Number.isSafeInteger(scope.platformOwnerId) || scope.platformOwnerId < 1
    || !Number.isSafeInteger(scope.platformSessionId) || scope.platformSessionId < 1
    || !Number.isSafeInteger(scope.personaId) || scope.personaId < 1
    || typeof scope.authorityVersion !== 'string' || !/^[1-9]\d{0,15}$/.test(scope.authorityVersion)
    || SCOPE_KEYS.some(key => scope[key] == null)) throw unavailable();
  return Object.freeze(scope);
}
function birthOf(raw) {
  const original = mailScene.birth(raw), value = original?.scope || original;
  if (!value || id(original?.targetId || raw?.targetId) !== id(raw?.targetId)) throw unavailable();
  const birth = { targetId: id(raw.targetId), launchId: id(value.launchId),
    scenarioId: id(value.scenarioId), generation: value.generation,
    platformOwnerId: value.platformOwnerId, platformSessionId: value.platformSessionId };
  if (!Number.isSafeInteger(birth.generation) || birth.generation < 1
    || !Number.isSafeInteger(birth.platformOwnerId) || birth.platformOwnerId < 1
    || !Number.isSafeInteger(birth.platformSessionId) || birth.platformSessionId < 1) throw unavailable();
  return Object.freeze(birth);
}
function selectedOf(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join() !== 'messageId,messageSha256,recipientId'
    || !Number.isSafeInteger(value.messageId) || value.messageId < 1
    || !Number.isSafeInteger(value.recipientId) || value.recipientId < 1
    || typeof value.messageSha256 !== 'string' || !SHA.test(value.messageSha256)) throw unavailable();
  return Object.freeze({ messageId: value.messageId,
    messageSha256: value.messageSha256, recipientId: value.recipientId });
}
function reservationOf(value) {
  const keys = ['issuanceId', 'listenerTargetId', 'nonceSha256', 'path',
    'resourceKind', 'urlSha256'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join() !== keys.sort().join()
    || typeof value.nonceSha256 !== 'string' || !SHA.test(value.nonceSha256)
    || typeof value.urlSha256 !== 'string' || !SHA.test(value.urlSha256)
    || typeof value.path !== 'string' || !/^\/[A-Za-z0-9._~/-]*$/.test(value.path)
    || value.resourceKind !== RESOURCE_KIND) throw unavailable();
  return Object.freeze({ issuanceId: id(value.issuanceId),
    listenerTargetId: id(value.listenerTargetId), nonceSha256: value.nonceSha256,
    path: value.path, resourceKind: value.resourceKind, urlSha256: value.urlSha256 });
}
function boundOf(value) {
  const keys = ['issuanceId', 'sendOperationId', 'targetId', 'messageId', 'messageSha256',
    'threadId', 'recipientId', 'listenerTargetId', 'nonceSha256', 'path',
    'resourceKind', 'urlSha256'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join() !== keys.sort().join()) throw unavailable();
  const selected = selectedOf({ messageId: value.messageId,
    messageSha256: value.messageSha256, recipientId: value.recipientId });
  if (!Number.isSafeInteger(value.threadId) || value.threadId < 1
    || typeof value.path !== 'string' || !/^\/[A-Za-z0-9._~/-]*$/.test(value.path)
    || value.resourceKind !== RESOURCE_KIND || !SHA.test(value.nonceSha256)
    || !SHA.test(value.urlSha256)) throw unavailable();
  return Object.freeze({ issuanceId: id(value.issuanceId),
    sendOperationId: id(value.sendOperationId), targetId: id(value.targetId),
    ...selected, threadId: value.threadId, listenerTargetId: id(value.listenerTargetId),
    nonceSha256: value.nonceSha256, path: value.path,
    resourceKind: value.resourceKind, urlSha256: value.urlSha256 });
}

async function createMailInlineListener(entry) {
  const server = http.createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== entry.path
      || entry.phase !== 'activated' || !entry.claimed || entry.hit) {
      response.writeHead(404, { 'cache-control': 'no-store' }); response.end(); return;
    }
    entry.hit = true;
    response.once('finish', () => {
      const base = Object.freeze({ version: 1, issuanceId: entry.issuanceId,
        sendOperationId: entry.sendOperationId, targetId: entry.scope.targetId,
        listenerTargetId: entry.listenerTargetId, nonceSha256: entry.nonceSha256,
        path: entry.path, resourceKind: RESOURCE_KIND, urlSha256: entry.urlSha256,
        method: 'GET', status: 200, responseSha256: sha256(RESPONSE) });
      entry.receipt = Object.freeze({ ...base, receiptSha256: sha256(JSON.stringify(base)) });
    });
    response.writeHead(200, { 'content-type': 'application/json',
      'content-length': RESPONSE.length, 'cache-control': 'no-store' });
    response.end(RESPONSE);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  return Object.freeze({ origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) });
}

function createSecureShopMailInlineTargetPool({ verifyBound, authorizeRetirement,
  createListener = createMailInlineListener,
  makeId = randomUUID, makeNonce = randomUUID } = {}) {
  if (typeof verifyBound !== 'function' || typeof createListener !== 'function')
    throw new TypeError('Mail inline repository verifier and listener required');
  const entries = new Map(), sendKeys = new Set(), retired = new Map(), pending = new Map(), slots = new Set();
  let closed = false, closing;
  function current(raw) {
    if (closed) throw unavailable();
    const scope = scopeOf(raw), previous = retired.get(scope.targetId);
    if (previous) { if (!isDeepStrictEqual(previous, scope)) throw unavailable(); throw unavailable(); }
    return scope;
  }
  function entryFor(raw, issuanceId) {
    const scope = current(raw), entry = entries.get(id(issuanceId));
    if (!entry || !isDeepStrictEqual(entry.scope, scope)) throw unavailable();
    return entry;
  }
  function sameBound(entry, bound) {
    const value = boundOf(bound);
    if (!entry.bound || !isDeepStrictEqual(entry.bound, value)) throw unavailable();
    return value;
  }
  return Object.freeze({
    async reserve(raw) {
      const scope = current(raw), birth = birthOf(raw), sendOperationId = id(raw.operationId);
      const sendKey = `${scope.targetId}:${sendOperationId}`;
      if (sendKeys.has(sendKey) || slots.size >= MAX_LISTENERS
        || [...slots].filter(slot => slot.scope.targetId === scope.targetId).length >= MAX_PER_TARGET)
        throw unavailable();
      const issuanceId = id(makeId()), listenerTargetId = id(makeId()), nonce = id(makeNonce());
      if (entries.has(issuanceId) || issuanceId === listenerTargetId
        || listenerTargetId === scope.targetId) throw unavailable();
      const entry = { scope, birth, issuanceId, sendOperationId, listenerTargetId,
        nonceSha256: sha256(nonce), path: `/mail-inline/${listenerTargetId}/${nonce}`,
        phase: 'pending', claimed: false, hit: false, receipt: null, bound: null };
      sendKeys.add(sendKey);
      slots.add(entry);
      const creation = Promise.resolve().then(() => createListener(entry));
      let finish;
      const finished = new Promise(resolve => { finish = resolve; });
      pending.set(creation, { scope, finished });
      let listener;
      try {
        listener = await creation;
        if (typeof listener?.close !== 'function') throw unavailable();
        entry.close = () => {
          entry.closing ||= Promise.resolve().then(() => listener.close()).catch(error => {
            entry.closing = null; throw error;
          });
          return entry.closing;
        };
        if (closed || retired.has(scope.targetId) || typeof listener?.origin !== 'string')
          throw unavailable();
        const url = `${listener.origin}${entry.path}`;
        if (new URL(url).hostname !== '127.0.0.1') throw unavailable();
        entry.urlSha256 = sha256(url); entry.url = url;
        entries.set(issuanceId, entry);
        const reservation = Object.freeze({ issuanceId,
          listenerTargetId, nonceSha256: entry.nonceSha256, path: entry.path,
          resourceKind: RESOURCE_KIND, urlSha256: entry.urlSha256 });
        entry.reservation = reservation;
        return Object.freeze({ url, reservation });
      } catch (error) {
        sendKeys.delete(sendKey);
        if (entry.close) {
          try { await entry.close(); }
          catch (closeError) {
            entry.phase = 'failed'; entries.set(entry.issuanceId, entry);
            throw new AggregateError([error, closeError], 'Mail inline reservation cleanup failed');
          }
        }
        slots.delete(entry); throw error;
      }
      finally { pending.delete(creation); finish(); }
    },
    assertPendingReservation(raw, reservation) {
      const entry = entryFor(raw, reservation?.issuanceId);
      if (entry.phase !== 'pending' || entry.sendOperationId !== id(raw.operationId)
        || !isDeepStrictEqual(entry.reservation, reservationOf(reservation))) throw unavailable();
      return entry.reservation;
    },
    async activate(raw, selected) {
      const scope = current(raw), source = selectedOf(selected);
      const verified = boundOf(await verifyBound(raw, source));
      const entry = entryFor(raw, verified.issuanceId);
      if (!isDeepStrictEqual(entry.scope, scope)
        || !['pending', 'activated', 'consumed'].includes(entry.phase)
        || entry.sendOperationId !== verified.sendOperationId
        || verified.targetId !== scope.targetId
        || !isDeepStrictEqual(source, selectedOf({ messageId: verified.messageId,
          messageSha256: verified.messageSha256, recipientId: verified.recipientId }))
        || entry.listenerTargetId !== verified.listenerTargetId
        || entry.nonceSha256 !== verified.nonceSha256 || entry.path !== verified.path
        || verified.resourceKind !== RESOURCE_KIND || entry.urlSha256 !== verified.urlSha256)
        throw unavailable();
      if (entry.bound && !isDeepStrictEqual(entry.bound, verified)) throw unavailable();
      if (entry.phase === 'pending') { entry.bound = verified; entry.phase = 'activated'; }
      return Object.freeze({ url: entry.url, binding: verified });
    },
    assertBound(raw, bound) {
      const entry = entryFor(raw, bound?.issuanceId);
      sameBound(entry, bound);
      if (entry.phase !== 'activated' || entry.hit) throw unavailable();
      return Object.freeze({ url: entry.url });
    },
    claimFetch(raw, bound) {
      const entry = entryFor(raw, bound?.issuanceId);
      sameBound(entry, bound);
      if (entry.phase !== 'activated' || entry.claimed || entry.hit) throw unavailable();
      entry.claimed = true;
      return Object.freeze({ url: entry.url });
    },
    readReceipt(raw, { issuanceId } = {}) {
      const entry = entryFor(raw, issuanceId);
      if (entry.phase !== 'activated' || !entry.receipt) throw unavailable();
      return entry.receipt;
    },
    async consume(raw, { issuanceId } = {}) {
      const entry = entryFor(raw, issuanceId);
      if (entry.phase !== 'activated' || !entry.receipt) throw unavailable();
      entry.phase = 'consumed';
      await entry.close();
      slots.delete(entry);
      return entry.receipt;
    },
    async cancelPending(raw, { issuanceId } = {}) {
      const entry = entryFor(raw, issuanceId);
      if (entry.phase !== 'pending' || entry.sendOperationId !== id(raw.operationId)) throw unavailable();
      entry.phase = 'cancelled';
      await entry.close();
      entries.delete(entry.issuanceId);
      slots.delete(entry);
      return Object.freeze({ ok: true });
    },
    async retire(raw) {
      const scope = scopeOf(raw), prior = retired.get(scope.targetId);
      if (prior && !isDeepStrictEqual(prior, scope)) throw unavailable();
      const creating = [...pending.values()].filter(value => value.scope.targetId === scope.targetId);
      if (creating.some(value => !isDeepStrictEqual(value.scope, scope))) throw unavailable();
      const matched = [...entries.values()].filter(entry => entry.scope.targetId === scope.targetId);
      if (matched.some(entry => !isDeepStrictEqual(entry.scope, scope))) throw unavailable();
      if (!prior && !matched.length && !creating.length) throw unavailable();
      retired.set(scope.targetId, scope);
      await Promise.allSettled(creating.map(value => value.finished));
      const results = await Promise.allSettled(matched.map(entry => entry.close()));
      const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'Mail inline listener retirement failed');
      for (const entry of matched) { entry.phase = 'retired'; entry.receipt = null; entries.delete(entry.issuanceId); }
      for (const entry of matched) slots.delete(entry);
      return Object.freeze({ ok: true, replayed: !!prior });
    },
    async retireTarget(targetId, authority) {
      const target = id(targetId), s = authority?.scope, operationId = id(authority?.operationId);
      if (!s || id(s.targetId) !== target || !Number.isSafeInteger(s.generation)
        || !Number.isSafeInteger(s.platformOwnerId) || !Number.isSafeInteger(s.platformSessionId)
        || !UUID.test(s.launchId || '') || !UUID.test(s.scenarioId || '')
        || typeof authorizeRetirement !== 'function') throw unavailable();
      const receipt = await authorizeRetirement(target, authority);
      for (const key of ['targetId', 'launchId', 'scenarioId', 'generation',
        'platformOwnerId', 'platformSessionId']) {
        if (receipt?.[key] !== s[key]) throw unavailable();
      }
      if (receipt.operationId !== operationId || receipt.version !== 1) throw unavailable();
      const matches = [...slots].filter(entry => entry.scope.targetId === target);
      if (matches.some(entry => ['launchId', 'scenarioId', 'generation',
        'platformOwnerId', 'platformSessionId'].some(key => entry.birth[key] !== s[key]))) throw unavailable();
      const previous = retired.get(target);
      if (previous && !isDeepStrictEqual(previous, s)) throw unavailable();
      retired.set(target, Object.freeze({ ...s }));
      const creating = [...pending.values()].filter(value => value.scope.targetId === target);
      await Promise.allSettled(creating.map(value => value.finished));
      const entriesForTarget = [...entries.values()].filter(entry => entry.scope.targetId === target);
      const results = await Promise.allSettled(entriesForTarget.map(entry => entry.close()));
      const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'Mail inline target retirement failed');
      for (const entry of entriesForTarget) {
        entry.phase = 'retired'; entry.receipt = null; entries.delete(entry.issuanceId); slots.delete(entry);
      }
      return Object.freeze({ ok: true, replayed: !!previous });
    },
    close() {
      if (closing) return closing;
      closed = true;
      closing = (async () => {
        await Promise.allSettled([...pending.values()].map(value => value.finished));
        const results = await Promise.allSettled([...entries.values()].map(entry => entry.close()));
        const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (failures.length) throw new AggregateError(failures, 'Mail inline listener shutdown failed');
        slots.clear();
      })().catch(error => { closing = null; throw error; });
      return closing;
    },
  });
}

module.exports = { createSecureShopMailInlineTargetPool, MAIL_INLINE_RESOURCE_KIND: RESOURCE_KIND };
