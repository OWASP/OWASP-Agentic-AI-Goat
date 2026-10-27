import { shopStorage, flushShopStorage, SHOP_REVIEW_MODERATION_KEY } from './shopStorage.mjs';

// Only operation references cross the parent storage boundary. Review bodies,
// model prose, decision notes and client-side outcome claims never do.
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const reject = () => { throw new TypeError('Review moderation reference unavailable'); };
const exact = (value, keys) => value !== null && typeof value === 'object'
  && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const limit = value => Number.isInteger(value) && value >= 1 && value <= 100;
const pair = value => Array.isArray(value) && value.length === 2
  && UUID.test(value[0]) && limit(value[1]);

export function decodeReviewModerationReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > 8192) reject();
  let value;
  try { value = JSON.parse(raw); } catch { reject(); }
  if (!exact(value, ['version', 'actionId', 'recoveryScopeKey', 'completed', 'pending'])
    || value.version !== 1 || !UUID.test(value.actionId || '')
    || !SHA.test(value.recoveryScopeKey || '') || !Array.isArray(value.completed)
    || value.completed.length > 100 || value.completed.some(entry => !pair(entry))
    || (value.pending !== null && (!exact(value.pending, ['requestId', 'requestedLimit'])
      || !UUID.test(value.pending.requestId || '') || !limit(value.pending.requestedLimit)))
    || (value.completed.length === 0 && value.pending === null)) reject();
  const ids = value.completed.map(entry => entry[0]);
  if (value.pending) ids.push(value.pending.requestId);
  if (new Set(ids).size !== ids.length || ids.length > 100
    || (value.completed.length && value.completed[0][1] !== 100)
    || (!value.completed.length && value.pending?.requestedLimit !== 100)) reject();
  return Object.freeze({ version: 1, actionId: value.actionId,
    recoveryScopeKey: value.recoveryScopeKey,
    completed: Object.freeze(value.completed.map(entry => Object.freeze(entry.slice()))),
    pending: value.pending === null ? null : Object.freeze({ ...value.pending }) });
}

function projectedResult(result, requestedLimit) {
  if (!result || typeof result !== 'object' || Array.isArray(result)
    || !Object.keys(result).every(key => ['ok', 'processed', 'decisions', 'stopReason',
      'replayed', 'batch', 'modeCapability'].includes(key))
    || !['ok', 'processed', 'decisions', 'stopReason', 'batch'].every(key => Object.hasOwn(result, key))
    || typeof result.ok !== 'boolean' || !Number.isInteger(result.processed)
    || result.processed < 0 || !Array.isArray(result.decisions)
    || result.decisions.length !== result.processed || result.decisions.length > 5
    || typeof result.stopReason !== 'string' || !result.stopReason
    || encoder.encode(result.stopReason).byteLength > 128
    || (Object.hasOwn(result, 'replayed') && typeof result.replayed !== 'boolean')) reject();
  const batch = result.batch;
  if (!exact(batch, ['requested', 'considered', 'complete', 'continuationRequired'])
    || batch.requested !== requestedLimit || !Number.isInteger(batch.considered)
    || batch.considered < 0 || batch.considered > Math.min(5, requestedLimit)
    || result.processed > batch.considered || typeof batch.complete !== 'boolean'
    || typeof batch.continuationRequired !== 'boolean'
    || (result.ok && !batch.complete)
    || (batch.continuationRequired && (!batch.complete || batch.considered === 0))) reject();
  for (const decision of result.decisions) {
    if (!exact(decision, ['review_id', 'product_id', 'applied_decision', 'notes', 'applied'])
      || !Number.isSafeInteger(decision.review_id) || decision.review_id < 1
      || !Number.isSafeInteger(decision.product_id) || decision.product_id < 1
      || !['approve', 'reject'].includes(decision.applied_decision)
      || (decision.notes !== null && (typeof decision.notes !== 'string'
        || encoder.encode(decision.notes).byteLength > 16384))
      || !exact(decision.applied, ['ok', 'review_id']) || decision.applied.ok !== true
      || decision.applied.review_id !== decision.review_id) reject();
  }
  if (Object.hasOwn(result, 'modeCapability')) {
    const mode = result.modeCapability;
    if (!exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || mode.version !== 1 || mode.featureId !== 'review'
      || mode.policyVersion !== 'product-feedback-enforced-decision-v1'
      || !['vuln', 'fixed'].includes(mode.effectiveMode)
      || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
      || mode.scope.id !== 'review') reject();
  }
  return result;
}

export function verifyReviewModerationLookup(lookup, expected) {
  if (!exact(expected, ['requestId', 'requestedLimit'])
    && !exact(expected, ['requestId', 'requestedLimit', 'recoveryScopeKey'])) reject();
  if (!UUID.test(expected.requestId || '') || !limit(expected.requestedLimit)
    || (Object.hasOwn(expected, 'recoveryScopeKey')
      && !SHA.test(expected.recoveryScopeKey || ''))) reject();
  if (!exact(lookup, ['version', 'requestId', 'requestedLimit', 'recoveryScopeKey', 'state', 'result'])
    || lookup.version !== 1 || lookup.requestId !== expected.requestId
    || lookup.requestedLimit !== expected.requestedLimit
    || !SHA.test(lookup.recoveryScopeKey || '')
    || (Object.hasOwn(expected, 'recoveryScopeKey')
      && lookup.recoveryScopeKey !== expected.recoveryScopeKey)
    || !['not_found', 'started', 'uncertain', 'completed'].includes(lookup.state)
    || (lookup.state !== 'completed' && lookup.result !== null)) reject();
  if (lookup.state === 'completed') projectedResult(lookup.result, lookup.requestedLimit);
  return Object.freeze({ state: lookup.state, requestId: lookup.requestId,
    requestedLimit: lookup.requestedLimit, recoveryScopeKey: lookup.recoveryScopeKey,
    result: lookup.result });
}

// Recheck every retained batch after reload. Persisted counters or decisions
// would be caller-controlled claims, not evidence of the original model run.
export function verifyReviewModerationHistory(reference, lookups) {
  const admitted = decodeReviewModerationReference(JSON.stringify(reference));
  if (!Array.isArray(lookups) || lookups.length !== admitted.completed.length) reject();
  let considered = 0;
  let processed = 0;
  let canContinue = false;
  for (let index = 0; index < admitted.completed.length; index += 1) {
    const [requestId, requestedLimit] = admitted.completed[index];
    if (requestedLimit !== 100 - considered || (index > 0 && !canContinue)) reject();
    const value = verifyReviewModerationLookup(lookups[index], {
      requestId, requestedLimit, recoveryScopeKey: admitted.recoveryScopeKey,
    });
    if (value.state !== 'completed') reject();
    considered += value.result.batch.considered;
    processed += value.result.processed;
    if (considered > 100 || processed > considered) reject();
    canContinue = value.result.ok && value.result.batch.complete
      && value.result.batch.continuationRequired && value.result.batch.considered > 0
      && considered < 100;
  }
  if (admitted.pending && admitted.pending.requestedLimit !== 100 - considered) reject();
  if (admitted.pending && admitted.completed.length && !canContinue) reject();
  return Object.freeze({ considered, processed, canContinue,
    remaining: 100 - considered });
}

export function createReviewModerationReferenceStore({ storage = shopStorage,
  flush = flushShopStorage } = {}) {
  if (!storage || ['getItem', 'setItem', 'removeItem'].some(key => typeof storage[key] !== 'function')
    || typeof flush !== 'function') reject();
  const read = () => decodeReviewModerationReference(storage.getItem(SHOP_REVIEW_MODERATION_KEY));
  let busy = false;
  const current = assertCurrent => {
    if (typeof assertCurrent !== 'function') reject();
    const value = assertCurrent();
    if (value !== true) reject();
  };
  const acknowledgedWrite = async (value, assertCurrent) => {
    const raw = value === null ? null : JSON.stringify(value);
    if (raw !== null && encoder.encode(raw).byteLength > 8192) reject();
    current(assertCurrent);
    if (raw === null) storage.removeItem(SHOP_REVIEW_MODERATION_KEY);
    else storage.setItem(SHOP_REVIEW_MODERATION_KEY, raw);
    await flush();
    if (storage.getItem(SHOP_REVIEW_MODERATION_KEY) !== raw) reject();
    current(assertCurrent);
    return raw === null ? null : decodeReviewModerationReference(raw);
  };
  const exclusive = async task => {
    if (busy) reject();
    busy = true;
    try { return await task(); } finally { busy = false; }
  };
  return Object.freeze({
    read,
    reserveInitialPost({ actionId, requestId }, lookup, { assertCurrent } = {}) {
      return exclusive(async () => {
        if (read() !== null) throw new Error('Saved moderation requires GET-only recovery');
        if (!UUID.test(actionId || '') || !UUID.test(requestId || '')) reject();
        const verified = verifyReviewModerationLookup(lookup, { requestId, requestedLimit: 100 });
        if (verified.state !== 'not_found') reject();
        return acknowledgedWrite({ version: 1, actionId,
          recoveryScopeKey: verified.recoveryScopeKey, completed: [],
          pending: { requestId, requestedLimit: 100 } }, assertCurrent);
      });
    },
    observePending(lookup) {
      const reference = read();
      if (!reference?.pending) reject();
      return verifyReviewModerationLookup(lookup, {
        ...reference.pending, recoveryScopeKey: reference.recoveryScopeKey,
      });
    },
    recordCompleted(lookup, historyLookups, { assertCurrent } = {}) {
      return exclusive(async () => {
        const reference = read();
        if (!reference?.pending) reject();
        const history = verifyReviewModerationHistory(reference, historyLookups);
        const verified = verifyReviewModerationLookup(lookup, {
          ...reference.pending, recoveryScopeKey: reference.recoveryScopeKey,
        });
        if (verified.state !== 'completed'
          || verified.result.batch.considered + history.considered > 100) reject();
        const next = { ...reference,
          completed: [...reference.completed,
            [reference.pending.requestId, reference.pending.requestedLimit]], pending: null };
        const saved = await acknowledgedWrite(next, assertCurrent);
        return Object.freeze({ reference: saved, result: verified.result });
      });
    },
    reserveNextPost({ requestId, requestedLimit }, lookup, historyLookups,
      { assertCurrent } = {}) {
      return exclusive(async () => {
        const reference = read();
        if (!reference || reference.pending || !reference.completed.length
          || !UUID.test(requestId || '') || !limit(requestedLimit)
          || reference.completed.some(entry => entry[0] === requestId)) reject();
        const history = verifyReviewModerationHistory(reference, historyLookups);
        if (!history.canContinue || requestedLimit !== history.remaining) reject();
        const verified = verifyReviewModerationLookup(lookup, { requestId,
          requestedLimit, recoveryScopeKey: reference.recoveryScopeKey });
        if (verified.state !== 'not_found') reject();
        return acknowledgedWrite({ ...reference, pending: { requestId, requestedLimit } }, assertCurrent);
      });
    },
    finish(historyLookups, { assertCurrent } = {}) {
      return exclusive(async () => {
        const reference = read();
        if (!reference || reference.pending || !reference.completed.length) reject();
        const history = verifyReviewModerationHistory(reference, historyLookups);
        if (history.canContinue) reject();
        await acknowledgedWrite(null, assertCurrent);
        return history;
      });
    },
  });
}
