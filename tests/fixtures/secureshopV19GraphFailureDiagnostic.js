'use strict';
const { projectSecureShopFailure } = require('../../server/services/secureshopFailureDiagnostic');

const CODE = /^[A-Z0-9_]{1,64}$/;
const NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const CONSTRAINT = /^[a-z][a-z0-9_]{0,127}$/;
function text(value, workspace, limit = 240) {
  if (typeof value !== 'string') return null;
  return value.replaceAll(workspace, '[workspace]')
    .replace(/\b[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b/gi, '[uuid]')
    .replace(/\b(?:Bearer|token|password|secret)\s*[:=]?\s*\S+/gi, '[credential]')
    .slice(0, limit);
}
function errorChain(error, workspace) {
  const chain = [];
  for (let current = error, depth = 0; current && depth < 4; current = current.cause, depth++) {
    const stack = typeof current.stack === 'string' ? current.stack.split('\n').slice(1, 11)
      .map(line => text(line, workspace)).filter(Boolean) : [];
    chain.push(Object.freeze({
      name: NAME.test(current?.name || '') ? current.name : null,
      code: CODE.test(current?.code || '') ? current.code : null,
      constraint: CONSTRAINT.test(current?.constraint || '') ? current.constraint : null,
      message: text(current?.message, workspace), stack,
      executionBoundary: current?.executionBoundary === true,
      effectCallbackCompleted: typeof current?.effectCallbackCompleted === 'boolean'
        ? current.effectCallbackCompleted : null,
    }));
  }
  return Object.freeze(chain);
}
function createV19GraphFailureDiagnostic({ graphModule, workspace, record } = {}) {
  if (!graphModule || typeof graphModule.createBoundFileSummaryGraph !== 'function'
      || typeof workspace !== 'string' || !workspace || typeof record !== 'function') {
    throw new TypeError('V19 graph diagnostic dependencies required');
  }
  const original = graphModule.createBoundFileSummaryGraph;
  let restored = false, factoryCalls = 0, failures = 0, captureFailure = null;
  graphModule.createBoundFileSummaryGraph = options => {
    if (restored || ++factoryCalls !== 1) throw new Error('V19 graph diagnostic factory unavailable');
    const graph = original(options);
    if (!graph || typeof graph.run !== 'function') throw new TypeError('V19 graph diagnostic graph required');
    return Object.freeze({ ...graph, async run(input) {
      try { return await graph.run(input); }
      catch (error) {
        if (++failures > 1) throw new Error('V19 graph diagnostic failure budget exceeded');
        try {
          record(Object.freeze({ version: 1, ...projectSecureShopFailure(error),
            chain: errorChain(error, workspace) }));
        } catch (diagnosticError) {
          captureFailure = Object.freeze({ version: 1, ...projectSecureShopFailure(diagnosticError),
            chain: errorChain(diagnosticError, workspace) });
        }
        throw error;
      }
    } });
  };
  return Object.freeze({
    restore() {
      if (!restored) { graphModule.createBoundFileSummaryGraph = original; restored = true; }
      return Object.freeze({ factoryCalls, failures, captureFailure });
    },
    state() { return Object.freeze({ restored, factoryCalls, failures, captureFailure }); },
  });
}
module.exports = { createV19GraphFailureDiagnostic, errorChain };
