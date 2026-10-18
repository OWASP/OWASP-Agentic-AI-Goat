'use strict';

const { randomUUID } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function canonicalOperation(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Valid reset operation required');
  return value.toLowerCase();
}

function createSensitiveInfoAggregateReset({ legacyRuns, finflowReset, cleanup, journal } = {}) {
  if (typeof legacyRuns?.reset !== 'function' || typeof finflowReset !== 'function'
      || !['apply','readReceipt'].every(name => typeof cleanup?.[name] === 'function')
      || !['begin','read','claim','nextStep','acknowledge','fail','complete'].every(name => typeof journal?.[name] === 'function')) {
    throw new TypeError('Complete Legacy Sensitive and FinFlow reset dependencies are required');
  }
  const active = new Map();
  const coordinated = async (operation, work) => {
    const ownerId=operation.ownerId;
    let result;
    let completed = false;
    const execute=()=>finflowReset(String(ownerId), async () => {
      result = await work();
      completed = true;
    });
    if(operation.planVersion===2)await execute();else await legacyRuns.reset(String(ownerId),execute);
    if (!completed) throw new Error('Sensitive Information reset coordinator did not execute cleanup');
    return result;
  };
  async function execute(operation) {
    if (operation.status === 'completed') return operation;
    const lease = await journal.claim(operation.operationId);
    if (!lease) {
      const current = await journal.read(operation.operationId);
      if (current.status === 'completed') return current;
      throw Object.assign(new Error('Sensitive Information reset is already leased'), { code: 'SENSITIVE_INFO_RESET_BUSY' });
    }
    let stepKey;
    try {
      while ((stepKey = await journal.nextStep(lease))) {
        const effectScope={operationId:lease.operationId,stepKey,ownerId:Number(lease.ownerId),
          fromGeneration:Number(lease.fromGeneration),toGeneration:Number(lease.toGeneration)};
        await cleanup.apply(effectScope);
        const proof=await cleanup.readReceipt(effectScope);
        if(!proof||Object.keys(effectScope).some(key=>proof[key]!==effectScope[key])){
          throw Object.assign(new Error('Sensitive Information cleanup receipt mismatch'),{code:'RESET_RECEIPT_MISMATCH'});
        }
        await journal.acknowledge({ ...lease, stepKey });
      }
      return await journal.complete(lease);
    } catch (error) {
      if (stepKey) {
        try { await journal.fail({ ...lease, stepKey, code: error?.code }); }
        catch (failure) { error.resetJournalError = failure; }
      }
      throw error;
    }
  }
  async function coalesce(key, work) {
    if (active.has(key)) return active.get(key);
    const pending = Promise.resolve().then(work).finally(() => active.delete(key));
    active.set(key, pending);
    return pending;
  }
  return Object.freeze({
    async reset(ownerId, { operationId } = {}) {
      const requested = operationId === undefined ? null : canonicalOperation(operationId);
      operationId = requested || randomUUID();
      if (requested) {
        let existing;
        try { existing = await journal.read(operationId); }
        catch (error) { if (error?.code !== 'SENSITIVE_INFO_RESET_UNAVAILABLE') throw error; }
        if (existing && Number(existing.ownerId) !== Number(ownerId)) {
          throw Object.assign(new Error('Sensitive Information reset scope mismatch'),
            { code: 'SENSITIVE_INFO_RESET_SCOPE_MISMATCH' });
        }
        if (existing?.status === 'completed') return existing;
      }
      const key = requested ? `${ownerId}:${operationId}` : `${ownerId}:implicit`;
      return coalesce(key, async () => {
        const operation=await journal.begin({ownerId:Number(ownerId),operationId});
        return coordinated(operation,()=>execute(operation));
      });
    },
    async recover(operationId) {
      operationId = canonicalOperation(operationId);
      const recovered = await journal.read(operationId);
      if (recovered.status === 'completed') return recovered;
      return coalesce(`${recovered.ownerId}:${recovered.operationId}`,
        () => coordinated(recovered, () => execute(recovered)));
    },
  });
}

module.exports = { createSensitiveInfoAggregateReset };
