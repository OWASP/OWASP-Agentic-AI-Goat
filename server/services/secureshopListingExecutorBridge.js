'use strict';

const { prepareListingAdmission } = require('./secureshopListingJournalContract');
const fail = code => Object.assign(new Error('Owned listing execution unavailable'), { code, automaticRetry: false });

// Internal composition adapter. Registration is allowed only after the
// canonical journal verifies this exact persisted admission and authority.
function createListingExecutorBridge({ listingJournal, client } = {}) {
  if (typeof listingJournal?.get !== 'function' || ['withAdmission', 'execute', 'get']
    .some(name => typeof client?.[name] !== 'function')) throw TypeError('Persisted Listings admission and client required');
  async function prepare({ admission, signal, checkCurrent }) {
    if (typeof checkCurrent !== 'function') throw TypeError('Current Listings authority required');
    const captured = prepareListingAdmission({ ...admission?.binding, request: admission?.request });
    if (captured.request.action !== 'import') throw fail('LISTING_IMPORT_INVALID');
    const check = async () => { signal?.throwIfAborted(); await checkCurrent(); signal?.throwIfAborted(); };
    await check();
    const state = await listingJournal.get({ ...captured.binding, request: captured.request });
    await check();
    return { captured, state, check, signal };
  }
  return Object.freeze({
    async execute(input) {
      const { captured, state, check, signal } = await prepare(input);
      // Uncertain or previously observed operations must use GET recovery.
      if (state.state !== 'running') throw fail('LISTING_EXECUTOR_RECOVERY_REQUIRED');
      return client.withAdmission(captured,async handle=>{
      if (handle !== captured.request.operationId) throw fail('LISTING_EXECUTOR_IDENTITY');
      await check();
      let receipt;
      try { receipt = await client.execute(handle, { signal }); }
      catch { throw fail('LISTING_OUTCOME_UNCERTAIN'); }
      await check();
      if (receipt.status !== 'completed') throw fail(receipt.status === 'failed'
        ? 'LISTING_EXECUTOR_FAILED' : 'LISTING_OUTCOME_UNCERTAIN');
      return handle;
      });
    },
    async recover(input) {
      const { captured, state, check, signal } = await prepare(input);
      if (!['running', 'unknown', 'effect_received'].includes(state.state)) return Object.freeze({ state: state.state });
      return client.withAdmission(captured,async handle=>{
      if (handle !== captured.request.operationId) throw fail('LISTING_EXECUTOR_IDENTITY');
      await check();
      const receipt = await client.get(handle, { signal });
      await check();
      // No publication or inference during readback. The graph must explicitly
      // observe the stored effect before deciding whether to publish it.
      return Object.freeze({ state: receipt.status, receiptHandle: receipt.status === 'completed' ? handle : null });
      });
    },
  });
}
module.exports = { createListingExecutorBridge };
