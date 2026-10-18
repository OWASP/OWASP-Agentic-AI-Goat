'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');

// Invoke only inside the acquired conversation coordinator lease. A previous
// started claim is uncertain; it is never an invitation to rerun its graph.
function createTurnAdmission({ journal }) {
  if ([journal?.claim, journal?.complete, journal?.markUncertain].some(fn => typeof fn !== 'function')) {
    throw new TypeError('Turn journal required');
  }
  const issued = new WeakSet();
  const settled = new WeakSet();
  const prepare = async ({ sessionId, requestId, binding, message }) => {
      const trusted = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      const request = createTurnRequest({ sessionId, requestId, binding: trusted, message });
      const input = Object.freeze({ sessionId: request.sessionId, requestId: request.requestId, binding: trusted, message });
      const claim = await journal.claim(input);
      if (claim.status === 'completed') {
        return Object.freeze({ status: 'completed', outcome: Object.freeze({ result: structuredClone(claim.result), replayed: true }) });
      }
      if (claim.status !== 'claimed') {
        if (claim.status === 'started') {
          await journal.markUncertain({ ...input, claimId: claim.claimId });
        }
        throw Object.assign(new Error('Previous turn outcome requires recovery'), { code: 'TURN_RECOVERY_REQUIRED' });
      }
      const prepared = Object.freeze({ status: 'claimed', input, claimId: claim.claimId });
      issued.add(prepared);
      return prepared;
  };
  const abandon = async prepared => {
    if (!issued.has(prepared) || settled.has(prepared)) return;
    settled.add(prepared);
    try { await journal.markUncertain({ ...prepared.input, claimId: prepared.claimId }); } catch {}
  };
  const execute = async (prepared, boundary, operation, personaFence) => {
      if (!issued.has(prepared) || settled.has(prepared)) throw new TypeError('Prepared turn claim required');
      try {
        await boundary.check();
        const result = await operation();
        await boundary.check();
        // Publish the same semantic DTO that is persisted for later replay.
        const persisted = JSON.parse(JSON.stringify(result));
        const publication={ ...prepared.input, claimId: prepared.claimId, result: persisted };
        if(personaFence===undefined)await journal.complete(publication);
        else await journal.complete(publication,personaFence);
        settled.add(prepared);
        await boundary.check();
        return { result: persisted, replayed: false };
      } catch (error) {
        // A failed/uncertain write remains recoverable as a journal lookup,
        // never as automatic graph replay. Completed rows cannot be changed.
        await abandon(prepared);
        throw error;
      }
  };
  return Object.freeze({
    prepare,
    execute,
    abandon,
    async run({ sessionId, requestId, binding, message, boundary }, operation) {
      let prepared;
      try {
        await boundary.check();
        prepared = await prepare({ sessionId, requestId, binding, message });
        await boundary.check();
        if (prepared.status === 'completed') return prepared.outcome;
        return execute(prepared, boundary, operation);
      } catch (error) {
        await abandon(prepared);
        throw error;
      }
    },
  });
}
module.exports = { createTurnAdmission };
