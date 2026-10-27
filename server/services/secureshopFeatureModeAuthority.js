'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');
const { createAnalyticsModeAuthority } = require('./secureshopAnalyticsModeAuthority');

// These policies name concrete effect boundaries, not a shop-wide security claim.
const POLICIES = Object.freeze({
  analytics: 'postgres-restricted-capability-v1',
  product_assist: 'bounded-product-data-and-catalog-neighbors-v1',
  coupons: 'parameterized-coupon-v1',
  product_search: 'parameterized-product-search-v1',
  order_status: 'parameterized-order-status-v1',
  mail: 'owned-mail-recipient-header-and-html-v1',
  pricing: 'owned-network-and-catalog-facts-v1',
  policy: 'owned-policy-literal-render-v1',
  system_config: 'owned-config-directory-v1',
  system_diagnostic: 'owned-system-diagnostic-shell-v1',
  system_restart: 'owned-system-restart-shell-v1',
  audit: 'raw-audit-query-disabled-v1',
  listings: 'owned-listing-import-v1',
  registered_mcp: 'registered-schema-approval-v1',
  inventory: 'merchant-product-ownership-v1',
  uploads: 'owner-bound-avatar-extension-policy-v1',
  file_summary: 'owned-attachment-untrusted-summary-data-v1',
  file_path_summary: 'owned-synthetic-file-path-summary-v1',
  review: 'product-feedback-enforced-decision-v1',
  refund: 'requested-owned-order-v1',
  support_tickets: 'owned-ticket-render-v1',
  customer_chat: 'owned-catalog-and-cart-read-v1',
  customer_consumption: 'customer-supervisor-byte-budgets-v1',
  customer_disclosure: 'original-customer-literal-normalized-copy-v1',
  customer_idor: 'reserved-synthetic-cart-and-order-ownership-v1',
  checkout_audit_jwt: 'owned-checkout-admin-audit-practice-jwt-v1',
  merchant_assistant: 'owned-merchant-read-and-confirmation-v1',
  admin_assistant: 'owned-admin-read-and-confirmation-v1',
  audit_summary: 'capped-audit-metadata-v1',
  persona_inbox: 'owned-persona-message-v1',
  controlled_ssrf: 'owned-public-destination-v1',
  mcp_rogue_registration: 'approved-connector-only-v1',
  mcp_rug_pull: 'immutable-approved-schema-v1',
});
const stale = () => Object.assign(new Error('SecureShop feature mode changed or is unavailable'), {
  code: 'SECURESHOP_FEATURE_MODE_STALE', executionBoundary: true,
});
const guardedModes = new WeakMap();

function createFeatureModeAuthority({ progress, launches }) {
  const canonical = createAnalyticsModeAuthority({ progress, launches }), tokens = new WeakSet();
  return Object.freeze({
    async capture(input, featureId) {
      if (!Object.hasOwn(POLICIES, featureId)) throw stale();
      const scope = createLaunchScope(input), current = await canonical.capture(scope);
      const snapshot = Object.freeze({ version: 1, featureId, policyVersion: POLICIES[featureId],
        mode: current.mode.mode, generation: current.mode.generation,
        modeStamp: current.mode.modeStamp, scope });
      const token = Object.freeze({ snapshot, assertCurrent: () => current.assertCurrent(), assertCurrentAtEffect: () => current.assertCurrentAtEffect() });
      tokens.add(token);
      return token;
    },
    assertToken(token) { if (!tokens.has(token)) throw stale(); return token; },
  });
}

// Undefined/null is a compatibility seam for explicitly composed legacy fixtures.
// A configured authority must succeed; its failures never fall back to vuln mode.
async function captureFeatureMode(authority, scope, featureId, fallback = 'vuln') {
  if (authority == null) {
    if (!['vuln', 'fixed'].includes(fallback) || !Object.hasOwn(POLICIES, featureId)) throw stale();
    return Object.freeze({ snapshot: Object.freeze({ version: 1, featureId,
      policyVersion: POLICIES[featureId], mode: fallback, generation: null,
      modeStamp: null, scope: createLaunchScope(scope) }), async assertCurrent() {} });
  }
  if (typeof authority.capture !== 'function' || typeof authority.assertToken !== 'function') throw stale();
  return authority.assertToken(await authority.capture(scope, featureId));
}

// Capture remains outside model state. Checks surround cross-store effects;
// never open an identity-owner transaction from inside a held effect transaction.
function guardFeatureFence(fence, token) {
  if (!fence || typeof fence.assertRemoteAdmission !== 'function') throw stale();
  const guarded = { ...fence };
  guarded.assertRemoteAdmission = async () => {
    await token.assertCurrent(); const value = await fence.assertRemoteAdmission();
    await token.assertCurrent(); return value;
  };
  for (const name of ['withPersonaEffect', 'withCrossStoreEffect']) {
    if (typeof fence[name] !== 'function') continue;
    guarded[name] = async (work,...args) => {
      await token.assertCurrent(); const value = await fence[name](async(...effectArgs)=>{
        // The persona transaction may have waited for a lock since admission.
        await (token.assertCurrentAtEffect||token.assertCurrent).call(token);
        return work(...effectArgs);
      },...args);
      try { await token.assertCurrent(); } catch (cause) {
        throw Object.assign(new Error('Feature effect requires authoritative readback'), {
          code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true, cause,
        });
      }
      return value;
    };
  }
  guardedModes.set(guarded,token);
  return Object.freeze(guarded);
}
function projectFeatureMode(token) {
  const { featureId, policyVersion, mode } = token.snapshot;
  return Object.freeze({ version: 1, featureId, policyVersion, effectiveMode: mode,
    scope: Object.freeze({ kind: 'launch_feature', id: featureId }) });
}
function featureModeForFence(fence) { const token=guardedModes.get(fence); return token?projectFeatureMode(token):null; }
module.exports = { POLICIES, createFeatureModeAuthority, captureFeatureMode, guardFeatureFence, projectFeatureMode, featureModeForFence };
