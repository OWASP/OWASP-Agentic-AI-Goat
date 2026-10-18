'use strict';

const { normalizeRequest, requestDigest } = require('../../sidecars/sandbox-runner/owned-system/contract');
const { validateSystemConfigReceipt } = require('../../sidecars/sandbox-runner/owned-system/receipt');
const { isSystemConfigOutcomeUncertain, CAPABILITY } = require('./secureshopSystemConfigClient');
const { isDeepStrictEqual } = require('node:util');
const { validateSystemConfigExecution, fixedConfigPathAllowed } = require('./secureshopSystemConfigExecution');
const failure = code => Object.assign(new Error('Bound System config read unavailable'), { code });

// Unmounted application orchestration. Repository methods establish original
// launch/persona/session authority; the client owns the private isolated wire.
function createBoundSystemConfigReadService({ repository, client, modeAuthority, maxConcurrent = 2 } = {}) {
  if (['begin', 'complete', 'markUnknown', 'markNotExecuted', 'operation', 'assertCurrent', 'administration'].some(key => typeof repository?.[key] !== 'function')
      || typeof client?.read !== 'function' || !Number.isInteger(maxConcurrent)
      || maxConcurrent < 1 || maxConcurrent > 16) throw new TypeError('Bounded System dependencies required');
  if(modeAuthority!==undefined&&(typeof modeAuthority?.capture!=='function'||typeof modeAuthority?.assertToken!=='function')) throw new TypeError('Trusted System mode authority required');
  let active = 0;
  function normalize(raw) {
    const input = structuredClone(raw);
    if(Object.hasOwn(input,'execution')||Object.hasOwn(input,'modeToken'))throw failure('SYSTEM_CONFIG_MODE_INVALID');
    const request = normalizeRequest({ operationId: input.operationId, path: input.path });
    return { input, request, digest: requestDigest(request) };
  }
  function inspect(value, request, digest, states) {
    if (!value || value.operationId !== request.operationId || value.requestSha256 !== digest
        || !states.includes(value.state)) throw failure('SYSTEM_CONFIG_ADMISSION_INVALID');
    if(value.execution!==undefined)validateSystemConfigExecution(value.execution);
    if (value.state === 'completed') validateSystemConfigReceipt(request, value.receipt);
    return Object.freeze(structuredClone(value));
  }
  return Object.freeze({
    async administration(raw) {
      const value = await repository.administration(structuredClone(raw));
      if (typeof value?.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeKey)) throw failure('SYSTEM_CONFIG_ADMISSION_INVALID');
      return Object.freeze({ configReadCapability: CAPABILITY, scopeKey: value.scopeKey });
    },
    async read(raw, { signal, beforeEffect } = {}) {
      if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw new TypeError('Trusted pre-read check required');
      signal?.throwIfAborted();
      const { input, request, digest } = normalize(raw);
      // Refuse before admission, so overload cannot strand a fresh operation.
      if (active >= maxConcurrent) throw failure('SYSTEM_CONFIG_BUSY');
      active++;
      let admitted = false;
      let remoteFinished = false;
      let modeToken;
      const options = {};
      try {
        if(modeAuthority!==undefined){
          modeToken=modeAuthority.assertToken(await modeAuthority.capture(input.scope,'system_config'));
          validateSystemConfigExecution(modeToken.snapshot,input.scope);
          options.modeToken=modeToken;
          await modeToken.assertCurrent();
        }
        const admission = inspect(await repository.begin(input, options), request, digest,
          ['admitted', 'pending', 'unknown', 'not_executed', 'completed']);
        if (admission.state !== 'admitted') return admission;
        admitted = true;
        if(modeToken && !isDeepStrictEqual(admission.execution,modeToken.snapshot))throw failure('SYSTEM_CONFIG_ADMISSION_INVALID');
        signal?.throwIfAborted();
        if(modeToken?.snapshot.mode==='fixed'&&!fixedConfigPathAllowed(request.path)){
          await repository.assertCurrent(input,options);
          await beforeEffect?.();
          await modeToken.assertCurrent();
          return inspect(await repository.markNotExecuted(input,options),request,digest,['not_executed']);
        }
        const remote = await client.read(request, {
          signal, assertCurrent: async () => {
            // The client calls this after readiness and immediately before its
            // config POST, as well as after the response. Keep the chat scene
            // fence last inside that boundary, after the awaited repository
            // authority read, not merely around repository.begin.
            await repository.assertCurrent(input,options);
            await beforeEffect?.();
            await modeToken?.assertCurrent();
          },
        });
        remoteFinished = true;
        await modeToken?.assertCurrent();
        const receipt = validateSystemConfigReceipt(request, remote);
        signal?.throwIfAborted();
        return inspect(await repository.complete({ ...input, receipt },options), request, digest, ['completed']);
      } catch (error) {
        if (!admitted) throw error;
        if (!remoteFinished && !isSystemConfigOutcomeUncertain(error)) {
          // The client preserves readiness/authority failures before its POST.
          // Consume this admission without pretending a remote effect is unknown.
          try { await repository.markNotExecuted(input,options); } catch {}
          throw error;
        }
        // A lost publication reply may already be completed. The repository
        // preserves that terminal receipt; failure here never authorizes replay.
        try { await repository.markUnknown(input,options); } catch {}
        const uncertain = failure('SYSTEM_CONFIG_OUTCOME_UNCERTAIN');
        uncertain.outcome = 'unknown';
        uncertain.automaticRetry = false;
        throw uncertain;
      } finally { active--; }
    },
    operation: raw => repository.operation(structuredClone(raw)),
  });
}

module.exports = { createBoundSystemConfigReadService };
