'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');

// Private per-assessment execution capture. Tokens never enter public context.
function createAssessmentPersonaCapture(adapter) {
  if (adapter !== undefined && typeof adapter?.capture !== 'function') throw new TypeError('Trusted persona binding adapter required');
  const captures = new WeakMap();
  return Object.freeze({
    prepare(binding, fence) {
      if (adapter === undefined) return undefined;
      if (!fence?.binding || typeof fence.assertRemoteAdmission !== 'function') throw Object.assign(new TypeError('Assessment persona authority unavailable'),{executionBoundary:true});
      let scope, actual;try{scope=createLaunchScope(binding);actual=createLaunchScope(fence.binding);}catch(error){Object.assign(error,{executionBoundary:true});throw error;}const b=fence.binding;
      if (Object.keys(scope).some(key => scope[key] !== actual[key]) || b.personaId !== binding.shopUserId || b.role !== binding.role
          || typeof b.sessionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(b.sessionId)
          || typeof b.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(b.authorityVersion)) throw Object.assign(new TypeError('Assessment persona authority mismatch'),{executionBoundary:true});
      return Object.freeze({ fence, input: Object.freeze({ scope, personaId: b.personaId, role: b.role,
        sessionId: b.sessionId, authorityVersion: b.authorityVersion }) });
    },
    bind(execution, capture) {
      if (adapter === undefined) return;
      if (!capture || captures.has(execution)) throw Object.assign(new TypeError('Assessment persona capture unavailable'),{executionBoundary:true});
      captures.set(execution, capture);
    },
    options: adapter === undefined ? Object.freeze({}) : Object.freeze({
      ...(typeof adapter.resolveStores === 'function' ? {resolveExecutionStores: async execution => {
        const captured = captures.get(execution);
        if (!captured) throw Object.assign(new TypeError('Assessment persona capture unavailable'),{executionBoundary:true});
        await captured.fence.assertRemoteAdmission();
        const stores = await adapter.resolveStores(captured.input, execution);
        await captured.fence.assertRemoteAdmission();
        return stores;
      }} : {}), capturePersonaEvaluation: async execution => {
      const captured = captures.get(execution);
      if (!captured) throw Object.assign(new TypeError('Assessment persona capture unavailable'),{executionBoundary:true});
      await captured.fence.assertRemoteAdmission();
      const token = await adapter.capture(captured.input);
      await captured.fence.assertRemoteAdmission();
      return token;
    } }),
  });
}
module.exports = { createAssessmentPersonaCapture };
