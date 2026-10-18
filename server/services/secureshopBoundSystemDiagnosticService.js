'use strict';

const {normalizeDiagnosticRequest:normalizeRequest,diagnosticRequestDigest:requestDigest}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const {normalizeDiagnosticWire,validateBoundDiagnosticResult}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const { isSystemDiagnosticOutcomeUncertain, CAPABILITY } = require('./secureshopSystemDiagnosticClient');
const { captureFeatureMode, projectFeatureMode } = require('./secureshopFeatureModeAuthority');
const failure = code => Object.assign(new Error('Bound System diagnostic unavailable'), { code });

// Unmounted application orchestration. Repository methods establish original
// launch/persona/session authority; the client owns the private isolated wire.
function createBoundSystemDiagnosticService({ repository, client, modeAuthority, maxConcurrent = 2 } = {}) {
  if (['begin', 'complete', 'markUnknown', 'markNotExecuted', 'operation', 'assertCurrent', 'administration'].some(key => typeof repository?.[key] !== 'function')
      || typeof client?.execute !== 'function' || !Number.isInteger(maxConcurrent)
      || maxConcurrent < 1 || maxConcurrent > 16) throw new TypeError('Bounded System dependencies required');
  let active = 0;
  function normalize(raw) {
    const input = structuredClone(raw);
    const request = normalizeRequest({ operationId: input.operationId, cmd_template:input.cmd_template,args:input.args });
    return { input, request, digest: requestDigest(request) };
  }
  function inspect(value, request, digest, states) {
    if (!value || value.operationId !== request.operationId || value.requestSha256 !== digest
        || !states.includes(value.state)) throw failure('SYSTEM_DIAGNOSTIC_ADMISSION_INVALID');
    const wire=normalizeDiagnosticWire({targetId:value.targetId,request});
    if (value.state === 'completed') validateBoundDiagnosticResult(wire,value.receipt);
    return Object.freeze(structuredClone(value));
  }
  async function capture(input) {
    const token = await captureFeatureMode(modeAuthority, input.scope, 'system_diagnostic');
    await token.assertCurrent();
    return token;
  }
  function requireVulnerable(token) {
    if (token.snapshot.mode !== 'vuln') throw failure('SYSTEM_DIAGNOSTIC_FIXED_DENIED');
  }
  return Object.freeze({
    async administration(raw, { includeExecution = false } = {}) {
      const input = structuredClone(raw);
      const token = await capture(input);
      const value = await repository.administration(input);
      await token.assertCurrent();
      if (typeof value?.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeKey)) throw failure('SYSTEM_DIAGNOSTIC_ADMISSION_INVALID');
      return Object.freeze({ diagnosticCapability: CAPABILITY, scopeKey: value.scopeKey,
        modeCapability: projectFeatureMode(token),
        ...(includeExecution ? { execution: structuredClone(token.snapshot) } : {}) });
    },
    async execute(raw, { signal, beforeEffect } = {}) {
      signal?.throwIfAborted();
      const { input, request, digest } = normalize(raw);
      const token = await capture(input);
      requireVulnerable(token);
      if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw new TypeError('Trusted effect fence required');
      await beforeEffect?.();
      await token.assertCurrent();
      requireVulnerable(token);
      // Refuse before admission, so overload cannot strand a fresh operation.
      if (active >= maxConcurrent) throw failure('SYSTEM_DIAGNOSTIC_BUSY');
      active++;
      let admitted = false;
      let remoteFinished = false;
      let targetId;
      try {
        await token.assertCurrent();
        requireVulnerable(token);
        const admission = inspect(await repository.begin(input), request, digest,
          ['admitted', 'pending', 'unknown', 'not_executed', 'completed']);
        if (admission.state !== 'admitted') return admission;
        admitted = true;
        targetId=admission.targetId;
        signal?.throwIfAborted();
        await token.assertCurrent();
        requireVulnerable(token);
        await beforeEffect?.();
        const remote = await client.execute({targetId,request}, {
          signal, assertCurrent: async () => {
            await repository.assertCurrent(input,targetId);
            await token.assertCurrent();
            requireVulnerable(token);
            await beforeEffect?.();
          },
        });
        remoteFinished = true;
        const receipt = validateBoundDiagnosticResult({targetId,request},remote);
        signal?.throwIfAborted();
        await token.assertCurrent();
        requireVulnerable(token);
        await beforeEffect?.();
        return inspect(await repository.complete({ ...input, receipt }), request, digest, ['completed']);
      } catch (error) {
        if (!admitted) throw error;
        if (!remoteFinished && !isSystemDiagnosticOutcomeUncertain(error)) {
          // The client preserves readiness/authority failures before its POST.
          // Consume this admission without pretending a remote effect is unknown.
          try { await repository.markNotExecuted(input); } catch {}
          throw error;
        }
        // A lost publication reply may already be completed. The repository
        // preserves that terminal receipt; failure here never authorizes replay.
        try { await repository.markUnknown(input); } catch {}
        const uncertain = failure('SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN');
        uncertain.outcome = 'unknown';
        uncertain.automaticRetry = false;
        throw uncertain;
      } finally { active--; }
    },
    operation: raw => repository.operation(structuredClone(raw)),
  });
}

module.exports = { createBoundSystemDiagnosticService };
