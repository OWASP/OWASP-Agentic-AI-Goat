'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createSecureShopBoundAccountAvatar } = require('../server/services/secureshopBoundAccountAvatar');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

const id = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const scope = Object.freeze({ launchId: id(1), scenarioId: id(2), generation: 3,
  platformOwnerId: 11, platformSessionId: 12 });
const target = createSceneBinding({ ...scope, targetId: id(3) }, {
  sceneId: id(4), sceneGeneration: 5, grantId: id(6), execution: scope,
  withLease: work => work()
});

function harness(options = {}) {
  const admissions = new Map(), effects = new Map(), calls = [];
  let currentSession = id(7), currentRole = 'customer', currentMode = 'vuln',
    currentScene = target, retired = false;
  const context = (role = currentRole, requestId = id(8), overrides = {}) => ({
    scope, persona: { id: 41, role }, personaSession: {
      sessionId: currentSession, authorityVersion: '2'
    }, requestId, signal: new AbortController().signal, ...overrides
  });
  const check = role => {
    if (retired || role !== currentRole) throw Object.assign(Error('stale'), { code: 'SHOP_AUTH_INVALID' });
  };
  const repository = {
    async claim(raw) {
      const admitted = normalizeAdmission(raw), previous = admissions.get(admitted.uploadRequestId);
      if (previous) {
        if (previous.operationId !== admitted.operationId || previous.requestSha256 !== admitted.requestSha256
            || previous.bindingSha256 !== admitted.bindingSha256)
          throw Object.assign(Error('replay conflict'), { code: 'BOUND_UPLOAD_REPLAY_CONFLICT' });
        return Object.freeze({ ...previous, replayed: true });
      }
      admissions.set(admitted.uploadRequestId, admitted);
      return Object.freeze({ ...admitted, replayed: false });
    },
    async recordEffect(admitted, value) {
      const effect = normalizeEffect(value, admitted);
      if (effects.has(admitted.operationId)) throw Error('duplicate effect');
      effects.set(admitted.operationId, effect);
      options.onRecordEffect?.(effect);
      return effect;
    }
  };
  const toRow = admitted => ({
    operation_id: admitted.operationId, upload_request_id: admitted.uploadRequestId,
    storage_key: admitted.storageKey, target_id: admitted.scope.targetId,
    launch_id: admitted.scope.launchId, scenario_id: admitted.scope.scenarioId,
    generation: String(admitted.scope.generation), platform_owner_id: admitted.scope.platformOwnerId,
    platform_session_id: admitted.scope.platformSessionId, scene_id: admitted.scope.sceneId,
    scene_generation: String(admitted.scope.sceneGeneration), grant_id: admitted.scope.grantId,
    shop_user_id: admitted.scope.shopUserId, persona_session_id: admitted.scope.personaSessionId,
    persona_authority_version: admitted.scope.personaAuthorityVersion,
    mode: admitted.scope.mode, mode_generation: String(admitted.scope.modeGeneration),
    mode_stamp: Buffer.from(admitted.scope.modeStamp, 'hex'),
    kind: admitted.request.kind, scope_id: admitted.request.scopeId,
    original_filename: admitted.request.originalFilename,
    declared_mime: admitted.request.declaredMime, is_public: admitted.request.public,
    byte_count: admitted.request.byteCount,
    body_sha256: Buffer.from(admitted.request.bodySha256, 'hex'),
    binding_sha256: Buffer.from(admitted.bindingSha256, 'hex'),
    request_sha256: Buffer.from(admitted.requestSha256, 'hex')
  });
  const pool = { async query(_sql, args) {
    calls.push(['sqlRead', args]);
    const admitted = admissions.get(args[0]);
    return { rows: admitted && !retired && admitted.scope.targetId === args[1]
      && admitted.scope.personaSessionId === args[8] ? [toRow(admitted)] : [] };
  } };
  const writer = traversal => ({ async writeAndReadBack(value) {
    calls.push([traversal ? 'traversalWrite' : 'ordinaryWrite', value]);
    const digest = createHash('sha256').update(value.bytes).digest('hex');
    return { cleanedFilename: value.filename, byteCount: value.bytes.length,
      bodySha256: digest, baseVirtualPath: `operations/${value.storageKey}/avatars/41`,
      resolvedVirtualPath: `operations/${value.storageKey}/avatars/41/${value.filename}`,
      storedVirtualPath: `operations/${value.storageKey}/avatars/41/${value.filename}`,
      isTraversal: traversal };
  } });
  const service = createSecureShopBoundAccountAvatar({ pool,
    launches: { async assertCurrent() { if (retired) throw Error('retired'); } },
    resolveTarget: async () => currentScene,
    personaAuthority: { async capture(input) {
      check(input.role);
      return { binding: { ...scope, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      async assertRemoteAdmission() { check(input.role); if (input.sessionId !== currentSession) throw Error('revoked'); } };
    } },
    modeAuthority: { async capture() {
      const snapshot = { mode: currentMode, generation: 1, modeStamp: 'a'.repeat(64) };
      return { snapshot, async assertCurrent() { if (currentMode !== snapshot.mode) throw Error('mode changed'); } };
    }, assertToken: token => token },
    journal: repository, effects: { async find(admitted) { return effects.get(admitted.operationId) || null; } },
    writer: options.writer || writer(false), traversalWriter: options.traversalWriter || writer(true),
    read: options.read || (async value => { calls.push(['ordinaryReadback', value]); }),
    readTraversal: options.readTraversal || (async value => { calls.push(['traversalReadback', value]); })
  });
  return { service, context, calls, admissions, effects,
    setRole(value) { currentRole = value; }, setSession(value) { currentSession = value; },
    setMode(value) { currentMode = value; }, setScene(value) { currentScene = value; },
    retire() { retired = true; } };
}

const upload = (h, overrides = {}, role) => h.service.upload({ ...h.context(role),
  scopeId: 41, bytes: Buffer.from('avatar-body'), filename: 'chosen.svg',
  mime: 'image/svg+xml', public: true, ...overrides });

test('all-role direct avatar upload is domain separated, owner-bound and GET-only after ACK loss', async () => {
  for (const role of ['customer', 'merchant', 'admin']) {
    const h = harness(); h.setRole(role);
    const first = await upload(h, {}, role);
    assert.equal(first.status, 'completed');
    assert.equal(first.ok, true);
    assert.equal(first.mime, 'image/svg+xml');
    assert.equal(first.public, true);
    assert.equal(first.is_traversal, false);
    const admitted = [...h.admissions.values()][0];
    assert.notEqual(admitted.uploadRequestId, id(8));
    assert.notEqual(admitted.operationId, id(8));
    const graphOperationId = (() => { const digest = createHash('sha256').update(JSON.stringify([
      'bound-upload-v1', scope, 41, id(7), id(8), 'chosen.svg', 'image/svg+xml', true,
      createHash('sha256').update(Buffer.from('avatar-body')).digest('hex')
    ])).digest('hex'); return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-a${digest.slice(17, 20)}-${digest.slice(20, 32)}`; })();
    assert.notEqual(admitted.operationId, graphOperationId,
      'direct Account operation cannot alias a graph upload with the same client UUID');
    assert.equal(admitted.scope.shopUserId, 41);
    assert.equal(h.calls.filter(([kind]) => kind === 'ordinaryWrite').length, 1);
    const saved = await h.service.read(h.context(role));
    assert.equal(saved.status, 'completed');
    assert.equal(saved.operationId, first.operationId);
    assert.equal(saved.replayed, true);
    assert.equal(h.calls.filter(([kind]) => kind === 'ordinaryWrite').length, 1,
      'saved GET never replays physical write');
    await assert.rejects(() => upload(h, { bytes: Buffer.from('different') }, role),
      { code: 'BOUND_UPLOAD_REPLAY_CONFLICT' });
    assert.equal(h.calls.filter(([kind]) => kind === 'ordinaryWrite').length, 1);
  }
});

test('crafted traversal uses existing vulnerable writer and fixed mode denies before writer', async () => {
  const vulnerable = harness();
  const result = await upload(vulnerable, { filename: '....//chosen.svg' });
  assert.equal(result.is_traversal, true);
  assert.equal(vulnerable.calls.filter(([kind]) => kind === 'traversalWrite').length, 1);
  assert.equal((await vulnerable.service.read(vulnerable.context())).is_traversal, true);
  const fixed = harness(); fixed.setMode('fixed');
  const denied = await upload(fixed, { filename: '....//chosen.svg' });
  assert.equal(denied.status, 'denied');
  assert.equal(denied.denialCode, 'PATH_TRAVERSAL_DENIED');
  assert.equal(fixed.calls.filter(([kind]) => kind.endsWith('Write')).length, 0);
  const extension = harness(); extension.setMode('fixed');
  const deniedExtension = await upload(extension);
  assert.equal(deniedExtension.status, 'denied');
  assert.equal(deniedExtension.denialCode, 'EXTENSION_DENIED');
  assert.equal(extension.calls.filter(([kind]) => kind.endsWith('Write')).length, 0);
});

test('owner, session, scene, mode and reset changes fence saved GET and new effects', async () => {
  const h = harness();
  await upload(h);
  h.setRole('merchant');
  await assert.rejects(() => h.service.read(h.context('customer')), { code: 'SHOP_AUTH_INVALID' });
  h.setRole('customer');
  h.setSession(id(9));
  assert.equal((await h.service.read(h.context())).status, 'uncertain',
    'new owner session cannot recover old session operation');
  h.setSession(id(7));
  h.setMode('fixed');
  await assert.rejects(() => h.service.read(h.context()), { code: 'SHOP_AUTH_INVALID' });
  h.setMode('vuln');
  h.setScene(createSceneBinding({ ...scope, targetId: id(10) }, {
    sceneId: id(11), sceneGeneration: 1, grantId: id(12), execution: scope,
    withLease: work => work()
  }));
  assert.equal((await h.service.read(h.context())).status, 'uncertain');
  h.retire();
  await assert.rejects(() => h.service.read(h.context()));
  await assert.rejects(() => upload(h));
});

test('real legacy writers preserve chosen filenames and confine crafted traversal to the operation root', async t => {
  const directory = await fs.mkdtemp(path.join(__dirname, '../tasks/tmp/account-avatar-writer-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const environment = { SECURESHOP_UPLOAD_ROOT: directory };
  const h = harness({
    writer: require('../server/services/secureshopUploadWriter').createSecureShopUploadWriter({ environment }),
    traversalWriter: require('../server/services/secureshopV46TraversalWriter').createSecureShopV46TraversalWriter({ environment }),
    read: require('../server/services/secureshopUploadAssetReader').createSecureShopUploadAssetReader({ environment }),
    readTraversal: require('../server/services/secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader({ environment })
  });
  const ordinary = await upload(h, { filename: 'chosen.svg', bytes: Buffer.from('<svg>ordinary</svg>') });
  const ordinaryAdmission = [...h.admissions.values()][0], ordinaryEffect = h.effects.get(ordinary.operationId);
  assert.equal(ordinary.status, 'completed');
  assert.equal(ordinaryEffect.file.originalFilename, 'chosen.svg');
  assert.equal(ordinaryEffect.file.isTraversal, false);
  assert.deepEqual(await fs.readFile(path.join(directory, ordinaryEffect.file.storedVirtualPath)),
    Buffer.from('<svg>ordinary</svg>'));
  const crafted = await upload(h, { requestId: id(9), filename: '....//escape.svg',
    bytes: Buffer.from('<svg>traversal</svg>') });
  const craftedAdmission = [...h.admissions.values()].find(value => value.operationId === crafted.operationId);
  const craftedEffect = h.effects.get(crafted.operationId);
  assert.equal(crafted.status, 'completed');
  assert.equal(craftedEffect.file.isTraversal, true);
  assert.equal(craftedEffect.file.storedVirtualPath,
    `operations/${craftedAdmission.storageKey}/avatars/escape.svg`);
  assert.deepEqual(await fs.readFile(path.join(directory, craftedEffect.file.storedVirtualPath)),
    Buffer.from('<svg>traversal</svg>'));
  assert.equal((await h.service.read(h.context('customer', id(9)))).is_traversal, true);
  const operationRoot = path.join(directory, 'operations', craftedAdmission.storageKey);
  assert.ok(path.relative(operationRoot, path.join(directory, craftedEffect.file.storedVirtualPath))
    .startsWith(`avatars${path.sep}`));
  assert.equal(ordinaryAdmission.request.originalFilename, 'chosen.svg');
  await assert.rejects(() => upload(h, { requestId: id(10), filename: '....//....//escape.svg' }));
  await fs.writeFile(path.join(directory, craftedEffect.file.storedVirtualPath), Buffer.from('tampered'));
  await assert.rejects(() => h.service.read(h.context('customer', id(9))),
    'saved GET must perform actual physical digest readback');
});

test('authority loss during and after physical write never retries the sink', async () => {
  let writes = 0, h;
  const writer = { async writeAndReadBack(value) {
    writes += 1;
    h.setSession(id(9));
    return { cleanedFilename: value.filename, byteCount: value.bytes.length,
      bodySha256: createHash('sha256').update(value.bytes).digest('hex'),
      baseVirtualPath: 'operations/owned/avatars/41',
      resolvedVirtualPath: `operations/owned/avatars/41/${value.filename}`,
      storedVirtualPath: `operations/owned/avatars/41/${value.filename}`,
      isTraversal: false };
  } };
  h = harness({ writer });
  await assert.rejects(() => upload(h), { code: 'BOUND_UPLOAD_OUTCOME_UNCERTAIN' });
  assert.equal(writes, 1);
  h.setSession(id(7));
  await assert.rejects(() => upload(h), { code: 'BOUND_UPLOAD_OUTCOME_UNCERTAIN' });
  assert.equal(writes, 1, 'uncertain operation must not repeat its physical writer');
  const effect = [...h.effects.values()][0];
  assert.equal(effect.outcome, 'unresolved');
});

test('authority loss after durable effect preserves saved receipt without a second write', async () => {
  let h;
  h = harness({ onRecordEffect(effect) {
    if (effect.outcome === 'completed') h.setMode('fixed');
  } });
  await assert.rejects(() => upload(h));
  assert.equal(h.calls.filter(([kind]) => kind === 'ordinaryWrite').length, 1);
  h.setMode('vuln');
  const recovered = await h.service.read(h.context());
  assert.equal(recovered.status, 'completed');
  assert.equal(recovered.ok, true);
  assert.equal(h.calls.filter(([kind]) => kind === 'ordinaryWrite').length, 1);
});
