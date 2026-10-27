// Shop state only. Platform tokens and launch capabilities must never pass here.
export const SHOP_TOKEN_KEY = 'secureshop_v2_token';
export const SHOP_CART_KEY = 'ss_guest_cart';
export const SHOP_MCP_REGISTRY_KEY = 'ss_mcp_registry_pending';
export const SHOP_USER_ADMIN_KEY = 'ss_user_admin_pending';
export const SHOP_PASSWORD_RESET_KEY = 'ss_password_reset_pending';
export const SHOP_PROMPT_POLICY_KEY = 'ss_prompt_policy_pending';
export const SHOP_SYSTEM_CONFIG_KEY = 'ss_system_config_recovery';
export const SHOP_SYSTEM_DIAGNOSTIC_KEY = 'ss_system_diagnostic_recovery';
export const SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY = 'secureshop.admin-diagnostic.confirmation.v1';
export const SHOP_SYSTEM_RESTART_KEY = 'ss_system_restart_recovery';
export const SHOP_SYSTEM_REBUILD_KEY = 'ss_system_rebuild_recovery';
export const SHOP_COUPON_KEY = 'secureshop.coupon.operation.v1';
export const SHOP_CHECKOUT_KEY = 'secureshop.checkout.operation.v1';
export const SHOP_REFUND_KEY = 'secureshop.refund.operations.v1';
export const SHOP_CUSTOMER_CHAT_KEY = 'secureshop.customer-chat.pending.v1';
export const SHOP_CUSTOMER_CHAT_COMPLETED_KEY = 'secureshop.customer-chat.completed.v1';
export const SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY = 'secureshop.customer-coupon.confirmation.v1';
export const SHOP_CUSTOMER_COUPON_PROBE_KEY = 'secureshop.customer-coupon.probe.v1';
export const SHOP_CUSTOMER_PRODUCT_SEARCH_KEY = 'secureshop.customer-product-search.lesson.v1';
export const SHOP_CUSTOMER_ORDER_STATUS_KEY = 'secureshop.customer-order-status.lesson.v1';
export const SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY = 'secureshop.customer-ticket.confirmation.v1';
export const SHOP_ADMIN_TICKET_ASSESSMENT_KEY = 'secureshop.admin-ticket.assessment.v1';
export const SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY = 'secureshop.admin-mcp-manifest.assessment.v1';
export const SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY = 'secureshop.customer-search-echo.assessment.v1';
export const SHOP_CUSTOMER_IDOR_KEY = 'secureshop.customer-idor.lesson.v1';
export const SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY = 'secureshop.customer-checkout-audit.lesson.v1';
export const SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY = 'secureshop.customer-checkout-audit.assessment.v1';
export const SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY = 'secureshop.customer-avatar-traversal.lesson.v1';
export const SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY = 'secureshop.customer-avatar-traversal.assessment.v1';
export const SHOP_CUSTOMER_AVATAR_UPLOAD_KEY = 'secureshop.customer-avatar-upload.lesson.v1';
export const SHOP_ACCOUNT_AVATAR_PENDING_KEY = 'secureshop.account-avatar.pending.v1';
export const SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY = 'secureshop.customer-avatar-upload.assessment.v1';
export const SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY = 'secureshop.customer-avatar-upload.svg-assessment.v1';
export const SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY = 'secureshop.customer-avatar-upload.polyglot-preview.v1';
export const SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY = 'secureshop.customer-avatar-upload.polyglot-assessment.v1';
export const SHOP_POLICY_FINAL_HTML_KEY = 'secureshop.policy-final-html.reference.v1';
export const SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY = 'secureshop.customer-file-path-summary.lesson.v1';
export const SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY = 'secureshop.customer-file-path-summary.assessment.v1';
export const SHOP_CUSTOMER_FILE_SUMMARY_KEY = 'secureshop.customer-file-summary.lesson.v1';
export const SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY = 'secureshop.customer-file-summary.assessment.v1';
export const SHOP_PRODUCT_SUMMARY_KEY = 'secureshop.product-summary.operations.v1';
export const SHOP_PRODUCT_SIMILAR_KEY = 'secureshop.product-similar.pending.v1';
export const SHOP_PRODUCT_MANUAL_KEY = 'secureshop.product-manual.pending.v1';
export const SHOP_CHAT_CART_KEY = 'secureshop.customer-chat.cart-confirm.v1';
export const SHOP_AUDIT_JOB_KEY = 'secureshop.audit-job.pending.v1';
export const SHOP_ROLE_ASSISTANT_KEY = 'secureshop.role-assistant.pending.v1';
export const SHOP_ROLE_ASSISTANT_COMPLETED_KEY = 'secureshop.role-assistant.completed.v1';
export const SHOP_REGISTERED_ADMIN_CHAT_KEY = 'secureshop.registered-admin-chat.pending.v1';
export const SHOP_REGISTERED_ADMIN_COMPLETED_KEY = 'secureshop.registered-admin-chat.completed.v1';
export const SHOP_INVENTORY_KEY = 'secureshop.inventory.operation.v1';
export const SHOP_LISTING_EDIT_KEY = 'secureshop.listing-edit.operation.v1';
export const SHOP_LISTING_CREATE_KEY = 'secureshop.listing-create.operation.v1';
export const SHOP_PRACTICE_PAYMENT_KEY = 'secureshop.practice-payment.operation.v1';
export const SHOP_ADDRESS_SETUP_KEY = 'secureshop.address-setup.operation.v1';
export const SHOP_PROFILE_KEY = 'secureshop.profile.operation.v1';
export const SHOP_MAIL_KEY = 'secureshop.mail.operations.v1';
export const SHOP_LISTINGS_KEY = 'secureshop.listings.operations.v1';
export const SHOP_PRICING_KEY = 'ss_pricing_pending';
export const SHOP_ANALYTICS_KEY = 'ss_analytics_recovery';
export const SHOP_ACL_KEY = 'ss_acl_pending';
export const SHOP_REVIEW_DECISION_KEY = 'ss_review_decision_pending';
export const SHOP_REVIEW_MODERATION_KEY = 'secureshop.review-moderation.pending.v1';
const allowedKeys = new Set([SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_MCP_REGISTRY_KEY, SHOP_USER_ADMIN_KEY, SHOP_REVIEW_DECISION_KEY, SHOP_ACL_KEY, SHOP_PASSWORD_RESET_KEY, SHOP_PROMPT_POLICY_KEY, SHOP_SYSTEM_CONFIG_KEY, SHOP_SYSTEM_DIAGNOSTIC_KEY, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_SYSTEM_RESTART_KEY, SHOP_SYSTEM_REBUILD_KEY, SHOP_ANALYTICS_KEY, SHOP_PRICING_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_INVENTORY_KEY, SHOP_LISTING_EDIT_KEY, SHOP_LISTING_CREATE_KEY, SHOP_PRACTICE_PAYMENT_KEY, SHOP_ADDRESS_SETUP_KEY, SHOP_PROFILE_KEY, SHOP_COUPON_KEY, SHOP_CHECKOUT_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY, SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY, SHOP_CUSTOMER_PRODUCT_SEARCH_KEY, SHOP_CUSTOMER_ORDER_STATUS_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY, SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY, SHOP_POLICY_FINAL_HTML_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_IDOR_KEY, SHOP_PRODUCT_SIMILAR_KEY, SHOP_PRODUCT_SUMMARY_KEY, SHOP_CHAT_CART_KEY, SHOP_AUDIT_JOB_KEY, SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY]);

allowedKeys.add(SHOP_PRODUCT_MANUAL_KEY);
allowedKeys.add(SHOP_REVIEW_MODERATION_KEY);
allowedKeys.add(SHOP_ACCOUNT_AVATAR_PENDING_KEY);

export function createShopStorage({ getStorage = () => globalThis.localStorage } = {}) {
  if (typeof getStorage !== 'function') throw new TypeError('Shop storage provider must be a function');
  const memory = new Map();
  // A failed write/remove must override an older persisted value for this page.
  const pending = new Set();
  const check = key => {
    if (!allowedKeys.has(key)) throw new TypeError('Unsupported shop storage key');
  };
  return Object.freeze({
    getItem(key) {
      check(key);
      if (key === SHOP_PRODUCT_MANUAL_KEY || key === SHOP_REVIEW_MODERATION_KEY || key === SHOP_ACCOUNT_AVATAR_PENDING_KEY) return getStorage().getItem(key);
      if ((key === SHOP_MCP_REGISTRY_KEY || key === SHOP_USER_ADMIN_KEY || key === SHOP_REVIEW_DECISION_KEY || key === SHOP_ACL_KEY || key === SHOP_PASSWORD_RESET_KEY || key === SHOP_PROMPT_POLICY_KEY || key === SHOP_SYSTEM_CONFIG_KEY || key === SHOP_SYSTEM_DIAGNOSTIC_KEY || key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY || key === SHOP_SYSTEM_RESTART_KEY || key === SHOP_SYSTEM_REBUILD_KEY || key === SHOP_ANALYTICS_KEY || key === SHOP_PRICING_KEY || key === SHOP_LISTINGS_KEY || key === SHOP_MAIL_KEY || key === SHOP_INVENTORY_KEY || key === SHOP_LISTING_EDIT_KEY || key === SHOP_LISTING_CREATE_KEY || key === SHOP_PRACTICE_PAYMENT_KEY || key === SHOP_ADDRESS_SETUP_KEY || key === SHOP_PROFILE_KEY || key === SHOP_COUPON_KEY || key === SHOP_CHECKOUT_KEY || key === SHOP_REFUND_KEY || key === SHOP_CUSTOMER_CHAT_KEY || key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY || key === SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY || key === SHOP_CUSTOMER_COUPON_PROBE_KEY || key === SHOP_CUSTOMER_PRODUCT_SEARCH_KEY || key === SHOP_CUSTOMER_ORDER_STATUS_KEY || key === SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY || key === SHOP_ADMIN_TICKET_ASSESSMENT_KEY || key === SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY || key === SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY || key === SHOP_POLICY_FINAL_HTML_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_IDOR_KEY || key === SHOP_PRODUCT_SIMILAR_KEY || key === SHOP_PRODUCT_SUMMARY_KEY || key === SHOP_CHAT_CART_KEY || key === SHOP_AUDIT_JOB_KEY || key === SHOP_ROLE_ASSISTANT_KEY || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key === SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY)) return getStorage().getItem(key);
      if (pending.has(key)) return memory.get(key) ?? null;
      try {
        const value = getStorage().getItem(key);
        if (value === null) memory.delete(key);
        else if (typeof value === 'string') memory.set(key, value);
        else throw new TypeError('Invalid storage value');
        return value;
      } catch {
        return memory.get(key) ?? null;
      }
    },
    setItem(key, value) {
      check(key);
      if (typeof value !== 'string') throw new TypeError('Shop storage values must be strings');
      if (key === SHOP_PRODUCT_MANUAL_KEY || key === SHOP_REVIEW_MODERATION_KEY || key === SHOP_ACCOUNT_AVATAR_PENDING_KEY) { getStorage().setItem(key, value); return; }
      if ((key === SHOP_MCP_REGISTRY_KEY || key === SHOP_USER_ADMIN_KEY || key === SHOP_REVIEW_DECISION_KEY || key === SHOP_ACL_KEY || key === SHOP_PASSWORD_RESET_KEY || key === SHOP_PROMPT_POLICY_KEY || key === SHOP_SYSTEM_CONFIG_KEY || key === SHOP_SYSTEM_DIAGNOSTIC_KEY || key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY || key === SHOP_SYSTEM_RESTART_KEY || key === SHOP_SYSTEM_REBUILD_KEY || key === SHOP_ANALYTICS_KEY || key === SHOP_PRICING_KEY || key === SHOP_LISTINGS_KEY || key === SHOP_MAIL_KEY || key === SHOP_INVENTORY_KEY || key === SHOP_LISTING_EDIT_KEY || key === SHOP_LISTING_CREATE_KEY || key === SHOP_PRACTICE_PAYMENT_KEY || key === SHOP_ADDRESS_SETUP_KEY || key === SHOP_PROFILE_KEY || key === SHOP_COUPON_KEY || key === SHOP_CHECKOUT_KEY || key === SHOP_REFUND_KEY || key === SHOP_CUSTOMER_CHAT_KEY || key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY || key === SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY || key === SHOP_CUSTOMER_COUPON_PROBE_KEY || key === SHOP_CUSTOMER_PRODUCT_SEARCH_KEY || key === SHOP_CUSTOMER_ORDER_STATUS_KEY || key === SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY || key === SHOP_ADMIN_TICKET_ASSESSMENT_KEY || key === SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY || key === SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY || key === SHOP_POLICY_FINAL_HTML_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_IDOR_KEY || key === SHOP_PRODUCT_SIMILAR_KEY || key === SHOP_PRODUCT_SUMMARY_KEY || key === SHOP_CHAT_CART_KEY || key === SHOP_AUDIT_JOB_KEY || key === SHOP_ROLE_ASSISTANT_KEY || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key === SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY)) { getStorage().setItem(key, value); return; }
      memory.set(key, value);
      pending.add(key);
      try { getStorage().setItem(key, value); pending.delete(key); } catch { /* page-local state remains available */ }
    },
    removeItem(key) {
      check(key);
      if (key === SHOP_PRODUCT_MANUAL_KEY || key === SHOP_REVIEW_MODERATION_KEY || key === SHOP_ACCOUNT_AVATAR_PENDING_KEY) { getStorage().removeItem(key); return; }
      if ((key === SHOP_MCP_REGISTRY_KEY || key === SHOP_USER_ADMIN_KEY || key === SHOP_REVIEW_DECISION_KEY || key === SHOP_ACL_KEY || key === SHOP_PASSWORD_RESET_KEY || key === SHOP_PROMPT_POLICY_KEY || key === SHOP_SYSTEM_CONFIG_KEY || key === SHOP_SYSTEM_DIAGNOSTIC_KEY || key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY || key === SHOP_SYSTEM_RESTART_KEY || key === SHOP_SYSTEM_REBUILD_KEY || key === SHOP_ANALYTICS_KEY || key === SHOP_PRICING_KEY || key === SHOP_LISTINGS_KEY || key === SHOP_MAIL_KEY || key === SHOP_INVENTORY_KEY || key === SHOP_LISTING_EDIT_KEY || key === SHOP_LISTING_CREATE_KEY || key === SHOP_PRACTICE_PAYMENT_KEY || key === SHOP_ADDRESS_SETUP_KEY || key === SHOP_PROFILE_KEY || key === SHOP_COUPON_KEY || key === SHOP_CHECKOUT_KEY || key === SHOP_REFUND_KEY || key === SHOP_CUSTOMER_CHAT_KEY || key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY || key === SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY || key === SHOP_CUSTOMER_COUPON_PROBE_KEY || key === SHOP_CUSTOMER_PRODUCT_SEARCH_KEY || key === SHOP_CUSTOMER_ORDER_STATUS_KEY || key === SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY || key === SHOP_ADMIN_TICKET_ASSESSMENT_KEY || key === SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY || key === SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY || key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY || key === SHOP_POLICY_FINAL_HTML_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY || key === SHOP_CUSTOMER_IDOR_KEY || key === SHOP_PRODUCT_SIMILAR_KEY || key === SHOP_PRODUCT_SUMMARY_KEY || key === SHOP_CHAT_CART_KEY || key === SHOP_AUDIT_JOB_KEY || key === SHOP_ROLE_ASSISTANT_KEY || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key === SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY)) { getStorage().removeItem(key); return; }
      memory.delete(key);
      pending.add(key);
      try { getStorage().removeItem(key); pending.delete(key); } catch { /* do not resurrect a removed token */ }
    },
  });
}

// Attached frame state stays strict: persistence/authority errors must never
// fall back to stale local state from another launch in the same realm.
export function createShopStorageBinding({ local = createShopStorage() } = {}) {
  let active = local;let attached = false;let generation = 0;
  const disconnected = () => { throw new DOMException('Shop storage disconnected', 'AbortError'); };
  const closed = Object.freeze({getItem:disconnected,setItem:disconnected,removeItem:disconnected,flush:disconnected});
  const check = key => { if (!allowedKeys.has(key)) throw new TypeError('Unsupported shop storage key'); };
  const storage = Object.freeze({
    getItem(key) { check(key);return active.getItem(key); },
    setItem(key,value) { check(key);if(typeof value !== 'string')throw new TypeError('Shop storage values must be strings');active.setItem(key,value); },
    removeItem(key) { check(key);active.removeItem(key); },
  });
  return Object.freeze({
    storage,
    attach(adapter) {
      if(attached || !['getItem','setItem','removeItem','flush'].every(key=>typeof adapter?.[key]==='function')) throw new TypeError('Available acknowledged shop storage required');
      attached=true;active=adapter;const lease=++generation;let released=false;
      return () => { if(released)return;released=true;if(lease!==generation)return;active=closed;attached=false; };
    },
    disconnect() { const previous=active;active=closed;attached=false;generation++;previous.close?.(); },
    async flush() { if(typeof active.flush==='function')await active.flush(); },
  });
}

const binding = createShopStorageBinding();
export const shopStorage = binding.storage;
export const attachShopStorage = binding.attach;
export const flushShopStorage = binding.flush;

export const disconnectShopStorage = binding.disconnect;
