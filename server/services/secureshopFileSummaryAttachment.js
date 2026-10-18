'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { executionScope, withSceneLease } = require('./secureshopSceneBinding');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { canonicalDigest } = require('./mcp/protocolContext');
const MAX_BYTES = 8192;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = code => Object.assign(new Error('Owned summary attachment unavailable'), { code });
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || !equal(Reflect.ownKeys(value).sort(), [...keys].sort())
      || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) {
    throw fail('FILE_SUMMARY_INVALID');
  }
}
function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function identity(raw, upload) {
  exact(raw, ['scope', 'persona', 'personaSession', 'sessionId', 'requestId',
    ...(upload ? ['filename', 'mime', 'bytes'] : [])]);
  const binding = createConversationBinding(raw.scope, raw.persona);
  exact(raw.personaSession, ['sessionId', 'authorityVersion']);
  if (binding.role !== 'customer' || !UUID.test(raw.sessionId) || !UUID.test(raw.requestId)
      || !UUID.test(raw.personaSession.sessionId)
      || typeof raw.personaSession.authorityVersion !== 'string'
      || !/^[1-9][0-9]{0,18}$/.test(raw.personaSession.authorityVersion)) throw fail('FILE_SUMMARY_INVALID');
  const ref = { scope: createLaunchScope(binding), persona: { id: binding.shopUserId, role: 'customer' },
    personaSession: { ...raw.personaSession }, sessionId: raw.sessionId, requestId: raw.requestId };
  const h = digest(JSON.stringify(['owned-file-summary-v1', ref]));
  const operationId = h.slice(0, 8) + '-' + h.slice(8, 12) + '-5' + h.slice(13, 16)
    + '-a' + h.slice(17, 20) + '-' + h.slice(20, 32);
  const result = { ref: freeze(ref), binding, operationId };
  if (upload) {
    if (!Buffer.isBuffer(raw.bytes) || raw.bytes.length < 1 || raw.bytes.length > MAX_BYTES
        || typeof raw.filename !== 'string' || Buffer.byteLength(raw.filename) > 255
        || !/^[^/\\\x00-\x1f]+\.(txt|md)$/i.test(raw.filename)
        || !['text/plain', 'text/markdown'].includes(raw.mime)) throw fail('FILE_SUMMARY_INVALID');
    const bytes = Buffer.from(raw.bytes);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (text.includes('\0')) throw fail('FILE_SUMMARY_INVALID');
    result.bytes = bytes;
    result.attachment = freeze({ filename: raw.filename, mime: raw.mime,
      byteCount: bytes.length, bodySha256: digest(bytes) });
  }
  return result;
}
function createFileSummaryAttachment({ launches, files, personaAuthority, scenes, modeAuthority } = {}) {
  for (const [object, method] of [[launches, 'reserveFilesTarget'], [launches, 'readExistingFilesTarget'], [launches, 'assertCurrent'],
    [files, 'provisionReservedTarget'], [files, 'openExistingReservedTarget'], [files, 'writeFile'], [files, 'readFile'],
    [personaAuthority, 'capture'], [scenes, 'readExisting'], [modeAuthority, 'capture'],
    [modeAuthority, 'assertToken']]) {
    if (typeof object?.[method] !== 'function') throw new TypeError('Summary attachment dependencies required');
  }
  async function authorize(source, execution) {
    if (typeof execution?.check !== 'function' || typeof execution?.checkAtEffect !== 'function') {
      throw fail('FILE_SUMMARY_AUTHORITY');
    }
    const { ref, binding } = source;
    const abort = () => execution.signal?.throwIfAborted();
    abort();
    const expected = { ...ref.scope, personaId: ref.persona.id, role: 'customer', ...ref.personaSession };
    const fence = await personaAuthority.capture({ scope: ref.scope, personaId: ref.persona.id,
      role: 'customer', ...ref.personaSession });
    if (typeof fence?.assertRemoteAdmission !== 'function' || typeof fence.withCrossStoreEffect !== 'function'
        || !Object.keys(expected).every(key => fence.binding?.[key] === expected[key])) throw fail('FILE_SUMMARY_AUTHORITY');
    const target = await scenes.readExisting(binding);
    if (!target?.scene || !equal(createLaunchScope(executionScope(target)), ref.scope)) throw fail('FILE_SUMMARY_AUTHORITY');
    const mode = await captureFeatureMode(modeAuthority, binding, 'file_summary');
    if (mode.snapshot.featureId !== 'file_summary' || !equal(mode.snapshot.scope, ref.scope)
        || !['vuln', 'fixed'].includes(mode.snapshot.mode) || !SHA.test(mode.snapshot.modeStamp)) throw fail('FILE_SUMMARY_AUTHORITY');
    const authority = freeze({ ...ref, scene: structuredClone(target.scene), sceneTargetId: target.targetId,
      mode: structuredClone(mode.snapshot) });
    const check = async ({ effect = false } = {}) => {
      abort(); await execution[effect ? 'checkAtEffect' : 'check'](); await launches.assertCurrent(ref.scope);
      if (!effect) await fence.assertRemoteAdmission();
      await mode[effect && typeof mode.assertCurrentAtEffect === 'function'
        ? 'assertCurrentAtEffect' : 'assertCurrent']();
      const current = await scenes.readExisting(binding);
      if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
          || !equal(createLaunchScope(executionScope(current)), ref.scope)) throw fail('FILE_SUMMARY_AUTHORITY');
      await execution[effect ? 'checkAtEffect' : 'check'](); abort();
    };
    await check();
    // withCrossStoreEffect holds the persona admission locks and validates the
    // persona before and after its callback. Re-entering assertRemoteAdmission
    // from that callback would wait on those same locks through a second agents
    // connection. Keep the other authority checks live inside the effect while
    // relying on the enclosing fence for the persona admission.
    const effectCheck = () => check({ effect: true });
    return { authority, check,
      lease: work => withSceneLease(target, () => fence.withCrossStoreEffect(() => work(effectCheck))) };
  }
  function targetBinding(source, target) {
    const s = source.ref.scope;
    if (!UUID.test(target?.targetId) || target.kind !== 'files'
        || !equal(createLaunchScope({ ...target, platformOwnerId: s.platformOwnerId,
          platformSessionId: s.platformSessionId }), s)) throw fail('FILE_SUMMARY_TARGET');
    return Object.freeze({ targetId: target.targetId, launchId: s.launchId, scenarioId: s.scenarioId,
      generation: s.generation, ownerId: String(s.platformOwnerId) });
  }
  async function reserve(source, guard, existing = false) {
    await guard.check();
    const s = source.ref.scope;
    const target = existing ? await launches.readExistingFilesTarget(s)
      : await launches.reserveFilesTarget({ platformSessionId: s.platformSessionId,
        platformOwnerId: s.platformOwnerId, launchId: s.launchId, expectedGeneration: s.generation });
    await guard.check();
    return targetBinding(source, target);
  }
  async function storage(source, guard, binding, existing = false) {
    await guard.check();
    // Reservation is a launch-row mutation and happens before the scene lease.
    // Inside the lease, re-read the exact reservation without trying to upgrade
    // its FOR SHARE launch lock through another identity connection.
    const retained = targetBinding(source, await launches.readExistingFilesTarget(source.ref.scope));
    if (!equal(retained, binding)) throw fail('FILE_SUMMARY_TARGET');
    await guard.check();
    const provisioned = existing ? await files.openExistingReservedTarget(binding)
      : await files.provisionReservedTarget(binding);
    await guard.check();
    if (!Object.keys(binding).every(key => provisioned?.[key] === binding[key])
        || typeof provisioned.capability !== 'string' || !provisioned.capability) throw fail('FILE_SUMMARY_TARGET');
    return { binding, capability: provisioned.capability,
      virtualPath: '/uploads/file_summaries/' + source.operationId + '/attachment' };
  }
  async function read(file, attachment, guard) {
    await guard.check();
    const result = await files.readFile(file.capability, file.virtualPath,
      { expectedGeneration: file.binding.generation, maxBytes: MAX_BYTES });
    await guard.check();
    if (!Buffer.isBuffer(result?.data) || result.virtualPath !== file.virtualPath
        || result.generation !== file.binding.generation || result.bytes !== attachment.byteCount
        || result.data.length !== attachment.byteCount || result.sha256 !== attachment.bodySha256
        || digest(result.data) !== attachment.bodySha256) throw fail('FILE_SUMMARY_BYTES_CHANGED');
    return Buffer.from(result.data);
  }
  return Object.freeze({
    async writeAndReadBack(raw, execution) {
      const source = identity(raw, true), guard = await authorize(source, execution);
      const binding = await reserve(source, guard);
      return guard.lease(async effectCheck => {
        const effectGuard = { check: effectCheck };
        const file = await storage(source, effectGuard, binding);
        await effectCheck();
        const written = await files.writeFile(file.capability, file.virtualPath, source.bytes,
          { expectedGeneration: file.binding.generation, createParents: true, createOnly: true });
        try {
          await effectCheck();
          if (written?.publicationMode !== 'file_synced_atomic_link'
              || written.virtualPath !== file.virtualPath || written.generation !== file.binding.generation
              || written.bytes !== source.attachment.byteCount || written.sha256 !== source.attachment.bodySha256) {
            throw fail('FILE_SUMMARY_WRITE_UNCERTAIN');
          }
          const data = await read(file, source.attachment, effectGuard);
          const body = { version: 1, publicationMode: 'file_synced_atomic_link',
            operationId: source.operationId, authority: guard.authority,
            attachment: source.attachment, file: { ...file.binding, virtualPath: file.virtualPath } };
          const receipt = freeze({ ...body, receiptSha256: canonicalDigest(body) });
          await effectCheck();
          // The caller must persist this in the original completed graph turn.
          // A returned object alone is not durable evidence or objective credit.
          return Object.freeze({ receipt, data });
        } catch {
          // Publication happened, but no original completed read receipt exists.
          // Never retry the create or remove its destination here.
          throw fail('FILE_SUMMARY_WRITE_UNCERTAIN');
        }
      });
    },
    async readRetained(raw, saved, execution) {
      const source = identity(raw, false), receipt = structuredClone(saved);
      exact(receipt, ['version', 'publicationMode', 'operationId', 'authority', 'attachment', 'file', 'receiptSha256']);
      const { receiptSha256, ...body } = receipt;
      if (receipt.version !== 1 || receipt.publicationMode !== 'file_synced_atomic_link'
          || receipt.operationId !== source.operationId
          || !SHA.test(receiptSha256) || canonicalDigest(body) !== receiptSha256) throw fail('FILE_SUMMARY_RECEIPT');
      exact(receipt.attachment, ['filename', 'mime', 'byteCount', 'bodySha256']);
      if (!Number.isSafeInteger(receipt.attachment.byteCount) || receipt.attachment.byteCount < 1
          || receipt.attachment.byteCount > MAX_BYTES || !SHA.test(receipt.attachment.bodySha256)) throw fail('FILE_SUMMARY_RECEIPT');
      const guard = await authorize(source, execution);
      if (!equal(receipt.authority, guard.authority)) throw fail('FILE_SUMMARY_AUTHORITY');
      const binding = await reserve(source, guard, true);
      return guard.lease(async effectCheck => {
        const effectGuard = { check: effectCheck };
        const file = await storage(source, effectGuard, binding, true);
        if (!equal(receipt.file, { ...file.binding, virtualPath: file.virtualPath })) throw fail('FILE_SUMMARY_TARGET');
        const data = await read(file, receipt.attachment, effectGuard);
        return Object.freeze({ receipt: freeze(receipt), data });
      });
    }
  });
}
module.exports = { createFileSummaryAttachment, MAX_BYTES };
