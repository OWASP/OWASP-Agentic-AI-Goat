'use strict';
const SYNTHETIC = /^(mock|fixture|scripted|fallback|unavailable)$/i;

// Provider strings alone never establish provenance. Every assessment uses
// the server-captured adapter qualifier after rejecting explicit simulation.
function isQualifiedSecureShopModelTrace(row, qualify) {
  let meta;
  try { meta = JSON.parse(row?.result_json); } catch { return false; }
  const provider = typeof row?.provider === 'string' ? row.provider.trim() : '';
  const model = typeof meta?.model === 'string' ? meta.model.trim() : '';
  if (!provider || !model || SYNTHETIC.test(provider) || SYNTHETIC.test(model)
      || meta.mocked !== false || meta.fallback === true || typeof qualify !== 'function') return false;
  const identity = Object.freeze({ provider, model, mocked: false, kind: row.kind, step: row.step });
  try { return qualify(identity) === true; } catch { return false; }
}
module.exports = { isQualifiedSecureShopModelTrace };
