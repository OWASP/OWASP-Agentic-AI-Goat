'use strict';

const { createSecureShopPolicySandboxRuntime } = require('./secureshopPolicySandboxRuntime');
const FLAG = 'SS_BOUND_PROMPT_POLICIES_ENABLED';
function invalid(message) { return Object.assign(new Error(message), { code: 'INVALID_CONFIGURATION' }); }

function activationPolicy(env = process.env) {
  const flag = env[FLAG];
  if (flag !== undefined && !['true', 'false'].includes(flag)) throw invalid(`${FLAG} must be true or false`);
  if (flag !== 'true') return Object.freeze({ requested: false });
  if (env.SS_ENABLE !== 'true' || env.SS_BOUND_REVIEWS_ENABLED !== 'true'
      || env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw invalid('Bound prompt policies require enabled bound SecureShop and PostgreSQL stores');
  }
  let url;
  try { url = new URL(env.SS_POLICY_RENDERER_BASE_URL); } catch { throw invalid('Explicit policy renderer origin required'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw invalid('Policy renderer must be an HTTP origin without credentials or a path');
  }
  return Object.freeze({ requested: true, baseUrl: url.origin });
}

// Pure opt-in factory; repository readiness remains required by composition.
// A requested feature cannot silently downgrade to a legacy or host renderer.
async function preparePromptPolicyRenderer({ env = process.env, fetchImpl = fetch, timeoutMs = 3000 } = {}) {
  const policy = activationPolicy(env);
  if (!policy.requested) return undefined;
  if (typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw invalid('Bounded renderer readiness configuration required');
  try {
    const renderer = createSecureShopPolicySandboxRuntime({ baseUrl: policy.baseUrl, fetchImpl, timeoutMs });
    await renderer.checkReadiness();
    return renderer;
  } catch {
    throw Object.assign(new Error('Requested strict policy renderer is unavailable'), { code: 'POLICY_RENDER_UNAVAILABLE' });
  }
}

module.exports = { PROMPT_POLICY_FLAG: FLAG, activationPolicy, preparePromptPolicyRenderer };
