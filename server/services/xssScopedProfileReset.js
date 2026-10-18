'use strict';

const { randomUUID } = require('node:crypto');
const { withStudentLifecycleLock } = require('../database/postgres/studentLifecycleLock');
const SCOPES = Object.freeze(['stored_user', 'stored_llm']);
const failure = (code, message) => Object.assign(new Error(message), { code });

// Inactive until origin/Judge transactions and parent/deletion recovery consume
// the same child authority. Local quiescence is not cross-process effect fencing.
function createXssScopedProfileReset({ pool, runs, ledger, journal, store, readWorkshopGeneration,
  lifecycle = withStudentLifecycleLock } = {}) {
  if (typeof pool?.connect !== 'function' || typeof runs?.withScopesQuiesced !== 'function'
      || typeof runs?.cancelScopes !== 'function'
      || typeof ledger?.withOwnerLease !== 'function'
      || typeof store?.apply !== 'function' || typeof lifecycle !== 'function'
      || !['begin', 'read', 'readNonterminalForOwner', 'claim', 'assertCurrent', 'acknowledgeStore', 'fail', 'complete']
        .every(key => typeof journal?.[key] === 'function')) {
    throw new TypeError('Complete scoped XSS reset dependencies required');
  }
  async function execute(operation, guard) {
    if (operation.status === 'completed') return operation;
    await guard.check();
    const lease = await journal.claim(operation.operationId);
    if (!lease) throw failure('XSS_PROFILE_RESET_BUSY', 'Profile reset is already leased');
    const key = Object.freeze({operationId:lease.operationId, leaseToken:lease.leaseToken});
    const check = async () => {
      await guard.check();
      await journal.assertCurrent(key);
      await guard.check();
    };
    try {
      await check();
      const receipt = await store.apply({operationId:lease.operationId, ownerId:lease.ownerId,
        graphParentGeneration:lease.graphParentGeneration, workshopGeneration:lease.workshopGeneration,
        children:lease.children});
      await check();
      await journal.acknowledgeStore({...key, receipt});
      await check();
      const result = await journal.complete(key);
      await guard.check();
      return result;
    } catch (error) {
      try { await journal.fail({...key, code:error.code}); }
      catch (journalError) { error.resetJournalError = journalError; }
      throw error;
    }
  }
  async function withAuthority(ownerId, work) {
    if (!Number.isSafeInteger(ownerId) || ownerId < 1 || ownerId > 2147483647) {
      throw new TypeError('Authenticated XSS reset owner required');
    }
    // Release a prior request's lifecycle lock before waiting for it. This
    // cancellation retains no local barrier; the established lock order below
    // remains lifecycle -> quiescence -> durable lease, including new arrivals.
    runs.cancelScopes(ownerId, SCOPES);
    return lifecycle(pool, ownerId, async (_, guard) => {
      await guard.check();
      return runs.withScopesQuiesced(ownerId, SCOPES, async () => {
        await guard.check();
        return ledger.withOwnerLease({ownerKey:JSON.stringify(['XSS', String(ownerId)])}, async lease => {
          const current = Object.freeze({check:async () => {
            await guard.check(); await lease.check(); await guard.check();
          }});
          await current.check();
          return work(lease, current);
        });
      });
    });
  }
  async function coordinate(ownerId, load) {
    return withAuthority(ownerId, async (lease, current) => {
      const operation = await load(lease, current);
      if (!operation || operation.ownerId !== ownerId) {
        throw failure('XSS_PROFILE_RESET_CONFLICT', 'Profile reset owner mismatch');
      }
      // Terminal results are immutable history; never replay their store effect.
      if (['completed', 'superseded'].includes(operation.status)) {
        await current.check();
        return operation;
      }
      if (operation.graphParentGeneration !== lease.durableGeneration) {
        throw failure('XSS_PROFILE_RESET_CONFLICT', 'Profile reset parent mismatch');
      }
      await current.check();
      return execute(operation, current);
    });
  }

  return Object.freeze({
    reset(input) {
      // Capture mutable caller input before the first await. Repository validates
      // all exact coordinates before journal mutation.
      const allowed = ['operationId', 'ownerId', 'graphParentGeneration', 'workshopGeneration'];
      if (!input || typeof input !== 'object' || Array.isArray(input)
          || Object.keys(input).some(key => !allowed.includes(key))) {
        throw new TypeError('Exact profile reset coordinates required');
      }
      const captured = Object.freeze({...input});
      return coordinate(captured.ownerId, () => journal.begin(captured));
    },
    resetCurrent(input) {
      if (!input || typeof input !== 'object' || Array.isArray(input)
          || Object.keys(input).some(key => !['ownerId', 'operationId'].includes(key))) {
        throw new TypeError('Exact reset owner and operation required');
      }
      if (typeof readWorkshopGeneration !== 'function') {
        throw new TypeError('Canonical workshop generation reader required');
      }
      const {ownerId, operationId} = input;
      return coordinate(ownerId, async (lease, current) => {
        const canonical = require('../agent-runtime/durableGeneration').canonicalDurableGeneration;
        // Read both parents inside the same lifecycle and durable owner lease.
        // HTTP callers choose neither a generation nor child transition.
        const graphParentGeneration = canonical(lease.durableGeneration);
        const workshopGeneration = canonical(await readWorkshopGeneration(ownerId));
        await current.check();
        if (operationId !== undefined) {
          const existing = await journal.read(operationId);
          await current.check();
          if (existing) return existing;
          return journal.begin({ownerId, operationId, graphParentGeneration, workshopGeneration});
        }
        const pending = await journal.readNonterminalForOwner(ownerId);
        await current.check();
        if (pending) {
          if (pending.graphParentGeneration !== graphParentGeneration
              || pending.workshopGeneration !== workshopGeneration) {
            throw failure('XSS_PROFILE_RESET_CONFLICT', 'Pending profile reset parent mismatch');
          }
          return pending;
        }
        return journal.begin({ownerId, operationId:randomUUID(), graphParentGeneration, workshopGeneration});
      });
    },
    recover({ownerId, operationId}) {
      return coordinate(ownerId, () => journal.read(operationId));
    },
    async recoverAfterParentReset(input) {
      if (!input || typeof input !== 'object' || Array.isArray(input)
          || Object.keys(input).some(key => !['ownerId', 'operationId'].includes(key))) {
        throw new TypeError('Exact recovery owner and operation required');
      }
      if (typeof readWorkshopGeneration !== 'function' || typeof store.retireOrRead !== 'function'
          || typeof journal.reconcileAfterParentReset !== 'function') {
        throw new TypeError('Parent recovery dependencies required');
      }
      const {ownerId, operationId} = input;
      return withAuthority(ownerId, async (lease, current) => {
        const operation = await journal.read(operationId);
        if (!operation || operation.ownerId !== ownerId) {
          throw failure('XSS_PROFILE_RESET_CONFLICT', 'Profile reset owner mismatch');
        }
        await current.check();
        if (['completed', 'superseded'].includes(operation.status)) return operation;
        const canonical = require('../agent-runtime/durableGeneration').canonicalDurableGeneration;
        const observedGraphParentGeneration = canonical(lease.durableGeneration);
        const observedWorkshopGeneration = canonical(await readWorkshopGeneration(ownerId));
        await current.check();
        if (observedGraphParentGeneration === operation.graphParentGeneration
            && observedWorkshopGeneration === operation.workshopGeneration) {
          throw failure('XSS_PARENT_NOT_SUPERSEDED', 'Profile reset parent is still current');
        }
        // Only the private store dependency can supply a durable retirement or
        // committed receipt. Caller-supplied outcomes/generations are rejected.
        const outcome = await store.retireOrRead({operationId:operation.operationId,
          ownerId, graphParentGeneration:operation.graphParentGeneration,
          workshopGeneration:operation.workshopGeneration, children:operation.children});
        await current.check();
        const result = await journal.reconcileAfterParentReset({operationId:operation.operationId,
          ownerId, observedGraphParentGeneration, observedWorkshopGeneration, outcome});
        await current.check();
        return result;
      });
    },
  });
}
module.exports = { createXssScopedProfileReset };
