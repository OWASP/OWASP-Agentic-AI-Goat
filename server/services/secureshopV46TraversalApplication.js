'use strict';

const fail = code => Object.assign(new Error(code), { code, executionBoundary: true });

function createSecureShopV46TraversalApplication({ effects, writer, journal } = {}) {
  if (typeof effects?.find !== 'function' || typeof writer?.writeAndReadBack !== 'function'
      || typeof journal?.recordEffect !== 'function') throw new TypeError('V46 upload application dependencies required');
  function validate(effect, admission) {
    if (effect.operationId !== admission.operationId
        || effect.file && effect.file.storageKey !== admission.storageKey) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH');
    if (effect.outcome === 'unresolved') throw fail('BOUND_UPLOAD_OUTCOME_UNCERTAIN');
    if (effect.outcome === 'completed' && effect.file?.isTraversal !== true
        || effect.outcome === 'denied' && (effect.file !== null || effect.denialCode !== 'PATH_TRAVERSAL_DENIED')) {
      throw fail('BOUND_UPLOAD_EFFECT_MISMATCH');
    }
    return Object.freeze({ effect, replayed: true });
  }
  return Object.freeze({
    async execute({ admission, file, mode, execution, effectId }) {
      await execution.check();
      const prior = await effects.find(admission);
      await execution.check();
      if (prior) return validate(prior, admission);
      // Fixed mode denies the traversal variant before the vulnerable writer is called,
      // irrespective of the selected extension.
      if (mode === 'fixed') {
        const effect = await journal.recordEffect(admission, { effectId, outcome: 'denied', file: null,
          denialCode: 'PATH_TRAVERSAL_DENIED', quarantineRequired: false });
        await execution.check();
        return Object.freeze({ effect, replayed: false });
      }
      try {
        const written = await writer.writeAndReadBack({
          operationId: admission.operationId,
          storageKey: admission.storageKey,
          shopUserId: admission.scope.shopUserId,
          bytes: file.bytes,
          filename: file.filename,
          mime: file.mime,
          signal: execution.signal
        });
        await execution.check();
        if (written.isTraversal !== true) throw fail('UPLOAD_WRITE_FAILED');
        const effect = await journal.recordEffect(admission, {
          effectId,
          outcome: 'completed',
          file: {
            storageKey: admission.storageKey,
            originalFilename: file.filename,
            cleanedFilename: written.cleanedFilename,
            declaredMime: file.mime,
            byteCount: written.byteCount,
            bodySha256: written.bodySha256,
            baseVirtualPath: written.baseVirtualPath,
            resolvedVirtualPath: written.resolvedVirtualPath,
            storedVirtualPath: written.storedVirtualPath,
            isTraversal: true
          },
          denialCode: null,
          quarantineRequired: false
        });
        await execution.check();
        return Object.freeze({ effect, replayed: false });
      } catch (cause) {
        let recovered;
        try { recovered = await effects.find(admission); } catch {}
        if (recovered) {
          await execution.check();
          return validate(recovered, admission);
        }
        try {
          await journal.recordEffect(admission, { effectId, outcome: 'unresolved', file: null,
            denialCode: null, quarantineRequired: true });
        } catch {}
        throw fail('BOUND_UPLOAD_OUTCOME_UNCERTAIN');
      }
    }
  });
}

module.exports = { createSecureShopV46TraversalApplication };
