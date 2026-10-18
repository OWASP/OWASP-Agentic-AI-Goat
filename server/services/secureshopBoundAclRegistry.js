'use strict';

// This catalog maps server-declared tools; it does not admit a launch or grant authority.
const { createHash } = require('node:crypto');
const { TOOLS: legacyTools } = require('../data/secureshopAgentSeeds');
const ROLES = Object.freeze(['customer', 'merchant', 'admin']);
const definitions = [
  ['listing-import', ['merchant'], ['listing.fetch_parse', 'listing.publish']],
  ['listing-optimize', ['merchant'], ['listing.optimize_images']],
  ['price-advisor', ['customer'], ['price-advisor.price_history', 'price-advisor.find_deals', 'price-advisor.compare_competitor']],
  ['pricing-strategy', ['merchant'], ['pricing-strategy.price_history', 'pricing-strategy.compare_competitor', 'pricing-strategy.suggest_price', 'pricing-strategy.run_pricing_experiment']],
  ['review', ['merchant'], ['review-moderator.moderate_pending', 'review-moderator.approve', 'review-moderator.reject']],
  ['product-summary', ['customer'], ['summarizer.summarize_product']],
  ['product-summary-policy', ['customer'], ['summarizer.summarize_product','summarizer.search_policy']],
  ['product-similar', ['customer'], ['product-search.similar']],
  ['product-search-union', ['customer'], ['product-search.search']],
  ['manual', ['merchant'], ['uploads.upload_product_manual']],
  ['avatar-upload', ['customer'], ['uploads.upload_avatar']],
  ['avatar-polyglot-preview', ['customer'], ['uploads.preview_legacy_image']],
  ['file-summary', ['customer'], ['summarizer.summarize_file']],
  ['refund', ['customer'], ['support.order_status', 'support.refund_request']],
  ['coupon-probe', ['customer'], ['cart.apply_coupon']],
  ['coupon-probe-guided-v2', ['customer'], ['arithmetic.sum']],
  ['customer-chat', ['customer'], ['catalog.search', 'cart.view', 'catalog.details',
    'cart.add', 'cart.update', 'cart.remove', 'cart.coupon_prepare', 'support.ticket_prepare', 'orders.list', 'orders.details', 'orders.refund_setup',
    'account.addresses', 'account.address_setup', 'account.address_edit_setup', 'account.profile', 'account.profile_update_prepare', 'payment.methods', 'payment.create_method', 'checkout.prepare', 'user-management.set_role']],
  ['merchant-assistant', ['merchant'], ['merchant.catalog_search', 'merchant.manual_search', 'merchant.mail_recipients', 'merchant.mail_list', 'merchant.mail_detail', 'merchant.mail_send_prepare', 'merchant.mail_reply_prepare', 'merchant.overview', 'merchant.top_products', 'merchant.inventory_prepare',
    'merchant.pricing_suggest_prepare', 'merchant.pricing_experiment_prepare', 'merchant.pricing_compare_prepare', 'merchant.listing_edit_prepare', 'merchant.listing_create_prepare', 'merchant.listing_import_setup', 'merchant.listing_rewrite_setup', 'merchant.listing_optimize_setup', 'merchant.orders_list', 'merchant.orders_detail', 'merchant.reviews_list', 'merchant.reviews_detail', 'merchant.review_decision_prepare']],
  ['admin-assistant', ['admin'], ['admin.users_search', 'admin.user_lookup', 'admin.audit_recent', 'admin.audit_search', 'admin.audit_agent_prepare', 'admin.audit_summary_prepare', 'admin.system_health', 'admin.system_config_read', 'admin.system_restart_prepare', 'admin.system_diagnostic_prepare', 'admin.acl_list', 'admin.acl_permission_prepare', 'admin.acl_enforcement_prepare', 'admin.role_change_prepare', 'admin.ban_prepare', 'admin.password_reset_setup', 'admin.policies_search', 'admin.policy_detail', 'admin.policy_preview_prepare', 'admin.policy_create_prepare', 'admin.policy_edit_prepare', 'admin.policy_delete_prepare', 'admin.mcp_servers', 'admin.mcp_detail', 'admin.mcp_register_prepare', 'admin.mcp_import_prepare', 'admin.mcp_retire_prepare', 'admin.mcp_invocation_setup']],
  ['inventory', ['merchant'], ['inventory.stock_levels', 'inventory.reorder_suggestion', 'inventory.set_stock']],
  ['mail-reply', ROLES, ['email.read_thread', 'email.send_reply']],
  ['mail-summary', ['merchant'], ['email.summarize_thread']],
  ['inbox', ROLES, ['persona-inbox.list_messages', 'persona-inbox.read_message']],
  ['ssrf', ROLES, ['summarizer.explain_return_policy']],
  ['audit-summary', ['admin'], ['audit.summarize_anomalies']],
  ['audit-query', ['admin'], ['audit.search_by_user']],
  ['mcp-rogue', ['admin'], ['mcp-rogue.forecast_lookup']],
  ['mcp-rug-pull', ['admin'], ['mcp-rug-pull.forecast_lookup']],
];
const flags = roles => Object.freeze(Object.fromEntries(ROLES.map(role => [role, roles.includes(role)])));
const workflows = new Map();
const supported = new Map();
for (const [workflow, roles, keys] of definitions) {
  workflows.set(workflow, Object.freeze({ roles: flags(roles), keys: Object.freeze([...keys]) }));
  for (const toolKey of keys) supported.set(toolKey, Object.freeze({ toolKey, workflow,
    supported: true, roleApplicability: flags(roles), // Preserve the legacy admin default; customer applicability does not grant permission.
    defaultAllowed: flags(toolKey === 'user-management.set_role' ? ['admin'] : roles) }));
}
// The path-read lesson reuses the admitted customer file-read permission.
// Keep the published registry row and instructor overrides unchanged.
workflows.set('file-path-summary', Object.freeze({ roles: flags(['customer']),
  keys: Object.freeze(['summarizer.summarize_file']) }));
// The summary workflow reuses the existing read permission without replacing
// its all-role mail-reply registry row or altering any published policy bytes.
workflows.set('mail-summary', Object.freeze({ roles: flags(['merchant']),
  keys: Object.freeze(['email.read_thread', 'email.summarize_thread']) }));
// Reuse the existing customer permission without replacing the refund row or
// changing instructor overrides, registry bytes, or historical upgrade edges.
workflows.set('order-status-error', Object.freeze({ roles: flags(['customer']),
  keys: Object.freeze(['support.order_status']) }));
// Guided v2 reuses the admitted cart probe and adds only bounded public arithmetic.
workflows.set('coupon-probe-guided-v2', Object.freeze({ roles: flags(['customer']),
  keys: Object.freeze(['cart.apply_coupon', 'arithmetic.sum']) }));
const rows = [...supported.values()];
for (const [toolKey, defaults] of legacyTools) if (!supported.has(toolKey)) rows.push(Object.freeze({
  toolKey, workflow: null, supported: false, roleApplicability: flags([]),
  defaultAllowed: Object.freeze(Object.fromEntries(ROLES.map(role => [role, defaults[role] === true]))),
  unavailableReason: 'No supported bound execution workflow',
}));
const REGISTRY = Object.freeze(rows.sort((a, b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : 0));
const REGISTRY_VERSION = 36;
const REGISTRY_SHA256 = createHash('sha256').update(JSON.stringify({ version: REGISTRY_VERSION, rows: REGISTRY })).digest('hex');
const PREDECESSOR_REGISTRY_SHA256 = 'a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64';
const ADDED_TOOL_KEYS = Object.freeze([
  'catalog.details', 'cart.add', 'cart.update', 'cart.remove', 'orders.list',
  'orders.details', 'account.addresses', 'payment.methods', 'payment.create_method',
  'checkout.prepare', 'merchant.catalog_search', 'merchant.overview',
  'merchant.top_products', 'admin.users_search', 'admin.audit_recent',
]);


// Only these exact published catalogs may transition to this catalog. The
// original fifteen-key list stays exported for historical qualification.
const PREVIOUS_REGISTRY_SHA256 = '93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed';
const INVENTORY_PREPARE_KEY = 'merchant.inventory_prepare';
const INVENTORY_REGISTRY_SHA256 = 'a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427';
const PRICING_PREPARE_KEYS = Object.freeze(['merchant.pricing_suggest_prepare', 'merchant.pricing_experiment_prepare']);
const PRICING_COMPARE_PREPARE_KEY = 'merchant.pricing_compare_prepare';
const PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256 = 'e01641f40076b2de5a3b250ef5e62156ae9fca0752c467cfeee5e9ff846f8c83';
const MANUAL_SEARCH_KEY = 'merchant.manual_search';
const MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256 = 'ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf';
const MERCHANT_MAIL_KEYS = Object.freeze(['merchant.mail_recipients','merchant.mail_list','merchant.mail_detail']);
const MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256 = 'ea01e56229188d248e9513097b5551c2d8eb7363c8790dad66b618a781ec79d8';
const MERCHANT_MAIL_PREPARE_KEYS = Object.freeze(['merchant.mail_send_prepare','merchant.mail_reply_prepare']);
const MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256 = '45893991ebda645902f9af8d0c55dde316ce67715fec4d19ebfc63db99f3aa19';
const MERCHANT_LISTING_SETUP_KEYS = Object.freeze(['merchant.listing_import_setup','merchant.listing_rewrite_setup']);
const MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256 = '34005b3480e2dfe11e49221f812fcdd62e7d1851880d2c87bda09f4791f335ae';
const PRICING_REGISTRY_SHA256 = '640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1';
const LISTING_EDIT_PREPARE_KEY = 'merchant.listing_edit_prepare';
const LISTING_EDIT_REGISTRY_SHA256 = '4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26';
const LISTING_CREATE_PREPARE_KEY = 'merchant.listing_create_prepare';
const ADDRESS_SETUP_KEY = 'account.address_setup';
const ADDRESS_EDIT_SETUP_KEY = 'account.address_edit_setup';
const REFUND_SETUP_KEY = 'orders.refund_setup';
const MERCHANT_ORDER_KEYS = Object.freeze(['merchant.orders_list','merchant.orders_detail']);
const MERCHANT_ORDER_REGISTRY_SHA256 = '45523b86483491e9ad584814f3feb2296a33fd1eef3d1dee9649726e6e6bf04b';
const MERCHANT_REVIEW_KEYS = Object.freeze(['merchant.reviews_list','merchant.reviews_detail','merchant.review_decision_prepare']);
const PROFILE_CHAT_KEYS = Object.freeze(['account.profile','account.profile_update_prepare']);
const PROFILE_CHAT_REGISTRY_SHA256 = '11d22a92e0860da587c40c7c4b0624f30f090217283104ef8b4eecf1f624a7b3';
const REFUND_SETUP_REGISTRY_SHA256 = 'fa2ca449a16bb4cf176f298934022c3bb62ad47853d8ff53af81b82a0b2da9ea';
const ADDRESS_EDIT_REGISTRY_SHA256 = '69598fe7cd484a95fe46fb856f1240499a1381a84ba289178262d6dd86d41e96';
const ADDRESS_SETUP_REGISTRY_SHA256 = '2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0';
const LISTING_CREATE_REGISTRY_SHA256 = 'f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b';
const ADMIN_USER_PREPARE_KEYS = Object.freeze(['admin.role_change_prepare','admin.ban_prepare']);
const ADMIN_USER_REGISTRY_SHA256 = '7033c43968337d22aa51a32d7b59c8560cb5b7bff684f77880fa3ed4d5c97e70';
const PASSWORD_RESET_SETUP_KEY = 'admin.password_reset_setup';
const PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256 = '9e427b77e3c4957eef0a7d82fe66fb5ddca17c5192ae0551b89bbce67ef114ba';
const ADMIN_POLICY_KEYS = Object.freeze(['admin.policies_search','admin.policy_detail','admin.policy_preview_prepare','admin.policy_create_prepare','admin.policy_edit_prepare','admin.policy_delete_prepare']);
const ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256 = 'b304723f3db4faa9f94014e5231ad3b99289083732e0a892081187a44ead77dd';
const ADMIN_MCP_KEYS = Object.freeze(['admin.mcp_servers','admin.mcp_detail','admin.mcp_register_prepare','admin.mcp_import_prepare','admin.mcp_retire_prepare','admin.mcp_invocation_setup']);
const ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256 = '45c1d52e58c9db3e4eaefa28cb472e2d5f9b555c4b94721923a1f851b4016626';
const ADMIN_AUDIT_SYSTEM_KEYS = Object.freeze(['admin.audit_search','admin.system_health','admin.system_config_read']);
const ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256 = '4fcf0a5032fac72ff4e907909e431403fc1fa8caccf673f4937855143adb479b';
const ADMIN_MANAGEMENT_PREPARE_KEYS = Object.freeze(['admin.audit_agent_prepare','admin.audit_summary_prepare','admin.system_restart_prepare','admin.acl_list','admin.acl_permission_prepare','admin.acl_enforcement_prepare']);
const ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256 = '94a618b7985f5d674d04e660e98fb65704b798d82d5ba212e24198a5895bd0a0';
const BASE_REGISTRY_UPGRADES = Object.freeze({
  [PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([PRICING_COMPARE_PREPARE_KEY]),
  [ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADMIN_USER_REGISTRY_SHA256]: Object.freeze([...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [PROFILE_CHAT_REGISTRY_SHA256]: Object.freeze([...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [MERCHANT_ORDER_REGISTRY_SHA256]: Object.freeze([...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...ADDED_TOOL_KEYS, INVENTORY_PREPARE_KEY, ...PRICING_PREPARE_KEYS, LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [PREVIOUS_REGISTRY_SHA256]: Object.freeze([INVENTORY_PREPARE_KEY, ...PRICING_PREPARE_KEYS, LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [INVENTORY_REGISTRY_SHA256]: Object.freeze([...PRICING_PREPARE_KEYS, LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [PRICING_REGISTRY_SHA256]: Object.freeze([LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [LISTING_EDIT_REGISTRY_SHA256]: Object.freeze([LISTING_CREATE_PREPARE_KEY, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [LISTING_CREATE_REGISTRY_SHA256]: Object.freeze([ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADDRESS_SETUP_REGISTRY_SHA256]: Object.freeze([ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [REFUND_SETUP_REGISTRY_SHA256]: Object.freeze([...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
  [ADDRESS_EDIT_REGISTRY_SHA256]: Object.freeze([REFUND_SETUP_KEY, ...MERCHANT_ORDER_KEYS, ...MERCHANT_REVIEW_KEYS, ...PROFILE_CHAT_KEYS, ...ADMIN_USER_PREPARE_KEYS, PASSWORD_RESET_SETUP_KEY, ...ADMIN_POLICY_KEYS, ...ADMIN_MCP_KEYS, ...ADMIN_AUDIT_SYSTEM_KEYS, ...ADMIN_MANAGEMENT_PREPARE_KEYS, PRICING_COMPARE_PREPARE_KEY]),
});
const COUPON_PREPARE_KEY = 'cart.coupon_prepare';
const COUPON_PREDECESSOR_REGISTRY_SHA256 = 'a927f19c9101ea9ced754fe0609cddde7885169763986d004f14a55695247b01';
const PRE_COUPON_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(BASE_REGISTRY_UPGRADES)
    .map(([registrySha256, keys]) => [registrySha256, Object.freeze([...keys, MANUAL_SEARCH_KEY, ...MERCHANT_MAIL_KEYS, ...MERCHANT_MAIL_PREPARE_KEYS, ...MERCHANT_LISTING_SETUP_KEYS])])),
  [MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS]),
  [MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS]),
  [MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS]),
  [MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256]: MERCHANT_LISTING_SETUP_KEYS,
});

const PRE_TICKET_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_COUPON_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...keys, COUPON_PREPARE_KEY])])),
  [COUPON_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([COUPON_PREPARE_KEY]),
});

const TICKET_PREPARE_KEY = 'support.ticket_prepare';
const TICKET_PREDECESSOR_REGISTRY_SHA256 = '1744f9c32cc93cf6708d6512288313c833fce84ca5496515f6155c50d1a39fff';
const PRE_DIAGNOSTIC_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_TICKET_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...keys, TICKET_PREPARE_KEY])])),
  [TICKET_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([TICKET_PREPARE_KEY]),
});

const DIAGNOSTIC_PREPARE_KEY = 'admin.system_diagnostic_prepare';
const DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256 = '2df507e918c1ecba5d8ebac3a0d0ba63e88909c70f0b37d8c198082cc1baad7d';
const PRE_MAIL_SUMMARY_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_DIAGNOSTIC_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...keys, DIAGNOSTIC_PREPARE_KEY])])),
  [DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([DIAGNOSTIC_PREPARE_KEY]),
});
const COUPON_PROBE_KEY = 'cart.apply_coupon';
const COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256 = 'f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c';
const MAIL_SUMMARY_KEY = 'email.summarize_thread';
const MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256 = '5aa6284201a2d234efd7dbe2d2d31599e1e167f410d23aa8b2890f48c561ee9b';
const PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_MAIL_SUMMARY_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...keys, MAIL_SUMMARY_KEY])])),
  [MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([MAIL_SUMMARY_KEY]),
  [COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([COUPON_PROBE_KEY]),
});

const PRODUCT_SEARCH_UNION_KEY = 'product-search.search';
const PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256 = '1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72';
// The frozen v29 transition map stays separate. V30 appends one arithmetic denial
// to every predecessor without changing historical workflow definitions.
const PRE_ARITHMETIC_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...new Set([...keys, COUPON_PROBE_KEY, PRODUCT_SEARCH_UNION_KEY])])])),
  [PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([PRODUCT_SEARCH_UNION_KEY]),
});
const ARITHMETIC_SUM_KEY = 'arithmetic.sum';
const ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256 = 'bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71';
const AVATAR_UPLOAD_KEY = 'uploads.upload_avatar';
const AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256 = 'e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef';
const PRE_LISTING_OPTIMIZE_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_ARITHMETIC_REGISTRY_UPGRADES).map(([hash, keys]) =>
    [hash, Object.freeze([...keys, ARITHMETIC_SUM_KEY, AVATAR_UPLOAD_KEY])])),
  [ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([ARITHMETIC_SUM_KEY, AVATAR_UPLOAD_KEY]),
  [AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([AVATAR_UPLOAD_KEY]),
});
const LISTING_OPTIMIZE_KEYS=Object.freeze(['listing.optimize_images','merchant.listing_optimize_setup']);
const LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256='0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c';
const PRE_FILE_SUMMARY_REGISTRY_UPGRADES=Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_LISTING_OPTIMIZE_REGISTRY_UPGRADES).map(([digest,keys])=>[digest,Object.freeze([...keys,...LISTING_OPTIMIZE_KEYS])])),
  [LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256]:LISTING_OPTIMIZE_KEYS,
});
const FILE_SUMMARY_KEY = 'summarizer.summarize_file';
const FILE_SUMMARY_PREDECESSOR_REGISTRY_SHA256 = '7b61d5cd1f2dcb98585b0a4312423df33b2a2d2df54905bf394a6e6717719beb';
const PRE_USER_LOOKUP_REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_FILE_SUMMARY_REGISTRY_UPGRADES)
    .map(([hash, keys]) => [hash, Object.freeze([...keys, FILE_SUMMARY_KEY])])),
  [FILE_SUMMARY_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([FILE_SUMMARY_KEY]),
});

const USER_LOOKUP_KEY='admin.user_lookup';
const USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256='435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc';
const PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES=Object.freeze({
 ...Object.fromEntries(Object.entries(PRE_USER_LOOKUP_REGISTRY_UPGRADES).map(([hash,keys])=>[hash,Object.freeze([...keys,USER_LOOKUP_KEY])])),
 [USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256]:Object.freeze([USER_LOOKUP_KEY]),
});

const UPLOAD_PREVIEW_KEY='uploads.preview_legacy_image';
const UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256='974d64bf78037ad3de2dbba5a28f277feab87487c13477b8b81b6c11540c8ea1';
const PRE_AGENCY_ROLE_REGISTRY_UPGRADES=Object.freeze({
 ...Object.fromEntries(Object.entries(PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES).map(([hash,keys])=>[hash,Object.freeze([...keys,UPLOAD_PREVIEW_KEY])])),
 [UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256]:Object.freeze([UPLOAD_PREVIEW_KEY]),
});

const AGENCY_ROLE_KEY = 'user-management.set_role';
const AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256 = 'cd81b73f42c6de9c1bd9d975606ee29e05f53ff77212ffba68542d305626dcda';
const REGISTRY_UPGRADES = Object.freeze({
  ...Object.fromEntries(Object.entries(PRE_AGENCY_ROLE_REGISTRY_UPGRADES)
    .map(([hash, keys]) => [hash, Object.freeze([...keys, AGENCY_ROLE_KEY])])),
  [AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256]: Object.freeze([AGENCY_ROLE_KEY]),
});

function createBoundAclResolver({ workflow, declaredTools, admittedMcp } = {}) {
  const definition = workflows.get(workflow);
  if (!definition || !Array.isArray(declaredTools) || declaredTools.length !== definition.keys.length) {
    throw new TypeError('Unknown workflow or incomplete declared tools');
  }
  const dynamic = workflow === 'mcp-rogue' || workflow === 'mcp-rug-pull';
  let expected;
  if (dynamic) {
    const scenario = workflow === 'mcp-rogue' ? 'rogue_registration' : 'rug_pull';
    const schema = admittedMcp?.schema;
    if (admittedMcp?.trustScenario !== scenario || typeof admittedMcp.serverIdentity !== 'string'
      || !admittedMcp.serverIdentity || schema?.serverIdentity !== admittedMcp.serverIdentity
      || !Number.isSafeInteger(schema.version) || schema.version < 1
      || !/^[0-9a-f]{64}$/.test(schema.schemaSha256 || '')
      || !Array.isArray(schema.tools) || schema.tools.length !== 1 || schema.tools[0]?.name !== 'forecast_lookup') {
      throw new TypeError('Exact admitted MCP schema required');
    }
    const declared = declaredTools[0];
    if (declared?.isExternalMcp !== true || declared.schemaVersion !== schema.version
      || declared.schemaSha256 !== schema.schemaSha256) throw new TypeError('MCP declaration does not match admission');
    expected = [[admittedMcp.serverIdentity, 'forecast_lookup', definition.keys[0]]];
  } else {
    if (admittedMcp !== undefined) throw new TypeError('Unexpected MCP admission');
    expected = definition.keys.map(key => [...key.split('.'), key]);
  }
  const mapping = new Map();
  for (const declared of declaredTools) {
    const match = expected.find(([agent, tool]) => declared?.agent === agent && declared?.tool === tool);
    if (!match || mapping.has(JSON.stringify([match[0], match[1]]))) throw new TypeError('Unknown or duplicate declared tool');
    mapping.set(JSON.stringify([match[0], match[1]]), supported.get(match[2]));
  }
  return Object.freeze({ workflow, registrySha256: REGISTRY_SHA256,
    resolve(agent, tool) {
      if (typeof agent !== 'string' || typeof tool !== 'string') return null;
      return mapping.get(JSON.stringify([agent, tool])) || null;
    },
    isRoleApplicable(role) { return ROLES.includes(role) && definition.roles[role]; },
  });
}
module.exports = { AGENCY_ROLE_KEY, AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256, PRE_AGENCY_ROLE_REGISTRY_UPGRADES, UPLOAD_PREVIEW_KEY, UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256, PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES, USER_LOOKUP_KEY, USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256, PRE_USER_LOOKUP_REGISTRY_UPGRADES, FILE_SUMMARY_KEY, FILE_SUMMARY_PREDECESSOR_REGISTRY_SHA256, PRE_FILE_SUMMARY_REGISTRY_UPGRADES, LISTING_OPTIMIZE_KEYS, LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256, PRE_LISTING_OPTIMIZE_REGISTRY_UPGRADES, AVATAR_UPLOAD_KEY, AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256, ARITHMETIC_SUM_KEY, ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256, PRE_ARITHMETIC_REGISTRY_UPGRADES, PRODUCT_SEARCH_UNION_KEY, PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256, PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES, COUPON_PROBE_KEY, COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256, MAIL_SUMMARY_KEY, MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256, DIAGNOSTIC_PREPARE_KEY, DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256, TICKET_PREPARE_KEY, TICKET_PREDECESSOR_REGISTRY_SHA256, COUPON_PREPARE_KEY, COUPON_PREDECESSOR_REGISTRY_SHA256, MERCHANT_MAIL_KEYS, MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256, MERCHANT_MAIL_PREPARE_KEYS, MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256, MERCHANT_LISTING_SETUP_KEYS, MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256, MANUAL_SEARCH_KEY, MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256, PRICING_COMPARE_PREPARE_KEY, PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256, ADMIN_MANAGEMENT_PREPARE_KEYS, ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256, ADMIN_AUDIT_SYSTEM_KEYS, ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256, ADMIN_MCP_KEYS, ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256, ADMIN_POLICY_KEYS, ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256, PASSWORD_RESET_SETUP_KEY, PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256, ADMIN_USER_PREPARE_KEYS, ADMIN_USER_REGISTRY_SHA256, REGISTRY_VERSION, REGISTRY_SHA256, PREDECESSOR_REGISTRY_SHA256,
  PREVIOUS_REGISTRY_SHA256, INVENTORY_REGISTRY_SHA256, PRICING_REGISTRY_SHA256, INVENTORY_PREPARE_KEY, PRICING_PREPARE_KEYS, LISTING_EDIT_PREPARE_KEY, LISTING_EDIT_REGISTRY_SHA256, LISTING_CREATE_PREPARE_KEY, REGISTRY_UPGRADES,
  LISTING_CREATE_REGISTRY_SHA256, BASE_REGISTRY_UPGRADES, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, ADDRESS_SETUP_REGISTRY_SHA256,
  ADDRESS_EDIT_REGISTRY_SHA256, REFUND_SETUP_KEY, REFUND_SETUP_REGISTRY_SHA256, MERCHANT_ORDER_KEYS, MERCHANT_ORDER_REGISTRY_SHA256, MERCHANT_REVIEW_KEYS, PROFILE_CHAT_KEYS, PROFILE_CHAT_REGISTRY_SHA256, ADDED_TOOL_KEYS, REGISTRY, ROLES, createBoundAclResolver };
