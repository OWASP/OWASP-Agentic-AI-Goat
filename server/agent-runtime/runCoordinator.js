'use strict';
const { randomUUID } = require('node:crypto');
const traces=require('./runTraceStore');

const retained = { runs: 0, lifecycle: 0 };
const limits = Object.freeze({ runs: 1024, ownerRuns: 16, lifecycle: 256, ownerLifecycle: 4 });
function capacityError() {
  return Object.assign(new Error('GRAPH_RUN_CAPACITY_EXCEEDED'), { code: 'GRAPH_RUN_CAPACITY_EXCEEDED', statusCode: 503 });
}

function interrupted(message) {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

/** Instance-local serialization; ledger methods may add durable fencing.
 * Deadlines/cancel prevent subsequent nodes, but cannot undo an in-flight tool.
 */
function createRunCoordinator({ family, ledger, defaultTimeoutMs = 120000 }) {
  // Resolve on first run/reset so route imports do not create pools.
  // Explicit null and injected ledgers override the PostgreSQL default.
  const useDefaultLedger = ledger === undefined && process.env.PLATFORM_DATABASE_ENGINE === 'postgres';
  function resolveLedger() {
    if (useDefaultLedger && ledger === undefined) {
      ledger = require('./postgresRunLedger').configuredRunLedger({family});
      if (!ledger) throw new Error('PostgreSQL run ledger is unavailable');
    }
  }
  const owners = new Map();
  const admissionDecision = value => {
    if (!value || typeof value !== 'object' || typeof value.skip !== 'boolean') {
      throw new TypeError('Invalid pre-run admission decision');
    }
    return value;
  };
  const ownerState = userId => {
    const key = JSON.stringify([family, String(userId)]);
    if (!owners.has(key)) owners.set(key, { key, generation: 0, tail: Promise.resolve(), runs: new Set(), scopes: new Map(), retainedRuns: 0, retainedLifecycle: 0 });
    return owners.get(key);
  };
  const reserve = (userId, lane) => {
    const key = JSON.stringify([family, String(userId)]);
    const current = owners.get(key);
    const field = lane === 'runs' ? 'retainedRuns' : 'retainedLifecycle';
    const maximum = lane === 'runs' ? limits.ownerRuns : limits.ownerLifecycle;
    if (retained[lane] >= limits[lane] || (current?.[field] || 0) >= maximum) throw capacityError();
    const owner = current || ownerState(userId);
    retained[lane]++; owner[field]++;
    let released = false;
    return { owner, release() { if (!released) { released = true; retained[lane]--; owner[field]--; } } };
  };
  const captureScopes = scopeKeys => {
      if (!Array.isArray(scopeKeys) || scopeKeys.length === 0
        || scopeKeys.some(scopeKey => typeof scopeKey !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(scopeKey))
        || new Set(scopeKeys).size !== scopeKeys.length) {
        throw new TypeError('Nonempty unique scope keys required');
      }
      const frozenScopeKeys = Object.freeze([...scopeKeys]);
    return frozenScopeKeys;
  };
  return {
    async run(userId, options, execute) {
      if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Run options required');
      if (typeof execute !== 'function') throw new TypeError('Run callback required');
      if (options.admit !== undefined && typeof options.admit !== 'function') throw new TypeError('Invalid pre-run admission callback');
      if (options.idempotencyKey && (typeof options.idempotencyKey !== 'string' || options.idempotencyKey.length > 128)) throw new Error('Invalid idempotency key');
      const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300000) throw new RangeError('timeoutMs must be between 1 and 300000');
      const externalSignal = options.signal;
      if (externalSignal !== undefined && (!externalSignal || typeof externalSignal.aborted !== 'boolean' || typeof externalSignal.addEventListener !== 'function' || typeof externalSignal.removeEventListener !== 'function')) throw new TypeError('Invalid run signal');
      let scope;
      if(options.scope!==undefined){
        if(!options.scope||typeof options.scope!=='object'||Array.isArray(options.scope)
          ||!Number.isSafeInteger(options.scope.userId)||options.scope.userId<=0
          ||typeof options.scope.scopeKey!=='string'||! /^[a-z][a-z0-9_]{0,63}$/.test(options.scope.scopeKey)
          ||String(userId)!==String(options.scope.userId)
          ||Object.keys(options.scope).some(key=>!['userId','scopeKey'].includes(key))){
          throw new TypeError('Invalid graph run scope');
        }
        scope=Object.freeze({...options.scope});
      }
      if (externalSignal?.aborted) throw interrupted('Agent run cancelled');
      const reservation = reserve(userId, 'runs');
      const owner = reservation.owner;
      let controller, context, timer, release, previous, abort;
      let begun = false, queued = true, rejectCaller, cleanupFailure, primaryError;
      const caller = new Promise((_, reject) => { rejectCaller = reject; });
      // Consume early rejection even if listener setup throws before returning it.
      caller.catch(() => {});
      const cleanup = action => {
        try { action(); } catch {
          cleanupFailure ||= Object.assign(new Error('GRAPH_RUN_CLEANUP_FAILED'), { code: 'GRAPH_RUN_CLEANUP_FAILED', statusCode: 503 });
        }
      };
      const clearWaiting = () => {
        cleanup(() => clearTimeout(timer));
        cleanup(() => externalSignal?.removeEventListener('abort', abort));
      };
      const withCleanup = error => {
        if (!cleanupFailure) return error;
        if (error && typeof error === 'object' && Object.isExtensible(error)) { error.cleanupError = cleanupFailure; return error; }
        return cleanupFailure;
      };
      const rejectQueued = () => { if (queued) { execute = undefined; options = {}; clearWaiting(); rejectCaller(withCleanup(controller.signal.reason)); } };
      try {
        controller = new AbortController();
        context = { runId: randomUUID(), ownerKey: owner.key, generation: owner.generation, ...(scope ? {scope} : {}) };
        previous = owner.tail;
        owner.tail = new Promise(resolve => { release = resolve; });
        owner.runs.add(controller);
        owner.scopes.set(controller, scope?.scopeKey || null);
        controller.signal.addEventListener('abort', rejectQueued, { once: true });
        abort = () => controller.abort(interrupted('Agent run cancelled'));
        timer = setTimeout(() => controller.abort(interrupted('Agent deadline exceeded')), timeoutMs);
        externalSignal?.addEventListener('abort', abort, { once: true });
        if (externalSignal?.aborted) abort();
      } catch (error) {
        clearWaiting();
        cleanup(() => controller?.signal.removeEventListener('abort', rejectQueued));
        owner.runs.delete(controller); owner.scopes.delete(controller);
        if (release) previous.then(() => { try { release(); } finally { reservation.release(); } });
        else reservation.release();
        throw withCleanup(error);
      }
      const check = async () => {
        if (controller.signal.aborted) throw controller.signal.reason;
        if (context.generation !== owner.generation) throw interrupted('Agent reset invalidated run');
        if (begun) await ledger?.assertCurrent?.(context);
        if (controller.signal.aborted) throw controller.signal.reason;
      };
      const work = (async () => {
      try {
        await previous;
        if (controller.signal.aborted) throw controller.signal.reason;
        queued = false;
        await check();
        resolveLedger();
        if(scope&&(ledger?.supportsScopedAdmission!==true||typeof ledger.begin!=='function'
          ||typeof ledger.assertCurrent!=='function'))throw new Error('Durable ledger does not support scoped admission');
        const admit = typeof options.admit === 'function' ? async () => {
          await check();
          const decision = admissionDecision(await options.admit());
          await check();
          return decision;
        } : undefined;
        if (options.admit !== undefined && typeof options.admit !== 'function') {
          throw new TypeError('Invalid pre-run admission callback');
        }
        if (admit && ledger?.begin && ledger.supportsPreRunAdmission !== true) {
          throw new Error('Durable ledger does not support pre-run admission');
        }
        let started;
        if (ledger?.begin) {
          started = await ledger.begin(context, { signal: controller.signal,
            ...(ledger.supportsPreRunAdmission && admit ? { admit } : {}) });
        }
        if (admit && !ledger?.begin) {
          const decision = await admit();
          if (decision.skip) return decision.value;
          started = { ...started, admission: decision.value };
        }
        if (started?.skipped) { await check(); return started.value; }
        if(scope){
          context.durableGeneration=started?.durableGeneration;
          context.scopeBinding=started?.scopeBinding;
        }else Object.assign(context, started);
        begun = true;
        if(scope){
          if(!started||Object.keys(started).some(key=>!['durableGeneration','scopeBinding','admission'].includes(key))){
            throw new Error('Durable ledger returned invalid scoped admission fields');
          }
          const binding=started?.scopeBinding;
          const canonical=require('./durableGeneration').canonicalDurableGeneration;
          if(!binding||!Object.isFrozen(binding)||binding.runId!==context.runId
            ||binding.ownerKey!==context.ownerKey||binding.ownerId!==scope.userId
            ||binding.scopeKey!==scope.scopeKey
            ||canonical(binding.parentGeneration)!==canonical(started?.durableGeneration)){
            throw new Error('Durable ledger returned an invalid scope binding');
          }
          canonical(binding.childGeneration);
        }
        traces.begin(context);
        await check();
        const effectPrefix = options.idempotencyKey || context.runId;
        if (typeof effectPrefix !== 'string' || effectPrefix.length > 128) throw new Error('Invalid idempotency key');
        const effectKey = node => `${effectPrefix}:${node}`;
        const effect = async (node, callback) => {
          await check();
          return ledger?.effect ? ledger.effect(context, effectKey(node), callback) : callback();
        };
        const effectWithReceipt = async (node, callback) => {
          const key = effectKey(node);
          const value = await effect(node, callback);
          await check();
          if (typeof ledger?.readCompletedEffect !== 'function') return Object.freeze({ value, receipt: null });
          const stored = await ledger.readCompletedEffect(context, key);
          await check();
          if (!stored || stored.status !== 'completed' || stored.effectKey !== key
            || stored.runId !== context.runId || stored.ownerKey !== context.ownerKey
            || String(stored.generation) !== String(context.durableGeneration)) {
            const error = new Error('Completed effect receipt is unavailable');
            error.code = 'EFFECT_RECEIPT_INVALID';
            throw error;
          }
          return Object.freeze({ value, receipt: Object.freeze({ version: 1,
            ownerKey: stored.ownerKey, generation: String(stored.generation), runId: stored.runId,
            effectKey: stored.effectKey, status: 'completed' }) });
        };
        const result = await execute({ ...context, signal: controller.signal, check,
          trace: async event => { const safe={...event,type:({start:'node_start',end:'node_end',verdict:'decision',invalid:'error',inconclusive:'decision'})[event.type]||event.type,data:traces.traceData(event.data)};traces.append(context,safe);await ledger?.recordEvent?.(context,safe); },
          effect, effectWithReceipt,
          checkpoint: async node => { await check(); await ledger?.checkpoint?.(context, { node }); await check(); } });
        await check();
        await ledger?.finish?.(context, { status: 'completed' });
        traces.finish(context,'completed');
        return result;
      } catch (error) {
        primaryError = error;
        if (begun) {
          traces.finish(context,controller.signal.aborted||error.name==='AbortError'?'cancelled':'failed');
          try { await ledger?.finish?.(context, { status: controller.signal.aborted || error.name === 'AbortError' ? 'cancelled' : 'failed' }); }
          catch (ledgerError) { error.ledgerError = ledgerError; }
        }
        throw error;
      } finally {
        clearWaiting();
        cleanup(() => controller.signal.removeEventListener('abort', rejectQueued));
        try {
          owner.runs.delete(controller);
          owner.scopes.delete(controller);
        } finally { try { release(); } finally { reservation.release(); } }
        if (cleanupFailure) throw withCleanup(primaryError);
      }
      })();
      // This race settles only the caller. The private work task owns the tail.
      return Promise.race([caller, work]);
    },
    cancel(userId) {
      for (const controller of ownerState(userId).runs) controller.abort(interrupted('Agent run cancelled'));
    },
    cancelScopes(userId, scopeKeys) {
      const selected = new Set(captureScopes(scopeKeys));
      const owner = owners.get(JSON.stringify([family, String(userId)]));
      // Signal only the captured runs. No tail/barrier/lease is retained while
      // the caller subsequently waits for external lifecycle authority.
      const controllers = owner ? [...owner.runs].filter(c => selected.has(owner.scopes.get(c))) : [];
      for (const controller of controllers) controller.abort(interrupted('Agent scoped run cancelled'));
    },
    async withScopesQuiesced(userId, scopeKeys, callback) {
      if (typeof callback !== 'function') throw new TypeError('Quiescence callback required');
      const frozenScopeKeys = captureScopes(scopeKeys);
      const reservation = reserve(userId, 'lifecycle');
      const owner = reservation.owner;
      const selected = new Set(frozenScopeKeys);
      // Snapshot before installing the barrier, then install it before aborting:
      // abort listeners run synchronously and any run they enqueue must wait on
      // this barrier rather than entering the callback window.
      const controllers = [...owner.runs].filter(controller => selected.has(owner.scopes.get(controller)));
      const previous = owner.tail;
      let release;
      owner.tail = new Promise(resolve => { release = resolve; });
      for (const controller of controllers) controller.abort(interrupted('Agent scoped run quiesced'));
      try {
        await previous;
        return await callback(Object.freeze({ userId, scopeKeys: frozenScopeKeys }));
      } finally {
        release();
        reservation.release();
      }
    },
    async reset(userId, resetStore = async () => {}) {
      if (typeof resetStore !== 'function') throw new TypeError('Reset callback required');
      const reservation = reserve(userId, 'lifecycle');
      const owner = reservation.owner;
      owner.generation += 1;
      const generation = owner.generation;
      const priorControllers = [...owner.runs];
      const previous = owner.tail;
      let release;
      owner.tail = new Promise(resolve => { release = resolve; });
      // Abort listeners may synchronously enqueue new-generation work. Install
      // the reset barrier first and cancel only the captured prior generation.
      for (const controller of priorControllers) controller.abort(interrupted('Agent reset invalidated run'));
      let resetLease;
      let resetActive = false;
      try {
        resolveLedger();
        resetLease = await ledger?.invalidate?.({ ownerKey: owner.key, generation });
        await previous;
        if (generation !== owner.generation) throw interrupted('Agent reset authority was superseded');
        await resetLease?.acquire?.();
        resetActive = true;
        const check = async () => {
          if (!resetActive) throw interrupted('Agent reset authority is no longer active');
          if (generation !== owner.generation) throw interrupted('Agent reset authority was superseded');
          await resetLease?.assertCurrent?.();
          if (!resetActive) throw interrupted('Agent reset authority is no longer active');
          if (generation !== owner.generation) throw interrupted('Agent reset authority was superseded');
        };
        const execution = Object.freeze({ ownerKey: owner.key, generation,
          durableGeneration: resetLease?.durableGeneration == null ? null : String(resetLease.durableGeneration), check });
        await check();
        await resetStore(execution);
        await check();
      } finally { resetActive = false; try { await resetLease?.release?.(); } finally { await previous; release(); reservation.release(); } }
    },
  };
}
module.exports = { createRunCoordinator };
