'use strict';

// Purpose is selected by a production workflow factory. It is never accepted
// from an HTTP request. `general` preserves the existing shared conversation
// used by the legacy SecureShop agent experience and its intentional memory
// teaching surfaces.
const PURPOSES = Object.freeze({
  general: 'general',
  mcpRogueRegistration: 'mcp_rogue_registration',
  mcpRugPull: 'mcp_rug_pull',
  personaInbox: 'persona_inbox',
  controlledSsrf: 'controlled_ssrf',
  reviewModeration: 'review_moderation',
  refundRequest: 'secureshop_refund_request',
  productAssist: 'secureshop_product_assist',
  productManualIngest: 'secureshop_product_manual_ingest',
  avatarUpload: 'secureshop_avatar_upload',
  fileSummary: 'secureshop_file_summary',
  filePathSummary: 'secureshop_file_path_summary',
  auditSummary: 'secureshop_audit_summary',
  auditUnbounded: 'secureshop_audit_unbounded',
  auditSql: 'secureshop_audit_sql',
  auditSqlTiming: 'secureshop_audit_sql_timing',
  analytics: 'secureshop_analytics',
  priceAdvisor: 'secureshop_price_advisor',
  pricingStrategy: 'secureshop_pricing_strategy',
  listingRewrite: 'secureshop_listing_rewrite',
  listingImport: 'secureshop_listing_import',
  listingOptimize: 'secureshop_listing_optimize',
  listingTemplate: 'secureshop_listing_template',
  mailReply: 'secureshop_mail_reply',
  mailSummary: 'secureshop_mail_summary',
  inventory: 'secureshop_inventory',
  customerChat: 'secureshop_customer_chat',
  merchantAssistant: 'secureshop_merchant_assistant',
  adminAssistant: 'secureshop_admin_assistant',
  idorLesson: 'secureshop_idor_lesson',
  checkoutAuditJwt: 'secureshop_checkout_audit_jwt',
  couponProbe: 'secureshop_coupon_probe',
  productSearchUnion: 'secureshop_product_search_union',
  orderStatusError: 'secureshop_order_status_error',
});
const ALLOWED = new Set(Object.values(PURPOSES));

function normalizeConversationPurpose(value = PURPOSES.general) {
  if (typeof value !== 'string' || !ALLOWED.has(value)) {
    throw new TypeError('Invalid conversation purpose');
  }
  return value;
}

module.exports = { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES, normalizeConversationPurpose };
