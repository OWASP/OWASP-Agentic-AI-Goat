'use strict';
// Pure ACL catalog; no database or tool initialization on import.
const TOOLS = [
  // product-search
  ['product-search.search',            { customer: true,  merchant: true,  admin: true }],
  ['product-search.similar',           { customer: true,  merchant: true,  admin: true }],
  ['product-search.personalized_feed', { customer: true,  merchant: false, admin: true }],
  // summarizer
  ['summarizer.summarize_product',      { customer: true,  merchant: true,  admin: true }],
  ['summarizer.summarize_reviews',      { customer: true,  merchant: true,  admin: true }],
  ['summarizer.explain_return_policy',  { customer: true,  merchant: false, admin: true }],
  ['summarizer.summarize_file',         { customer: true,  merchant: true,  admin: true }],
  // price-advisor
  ['price-advisor.price_history',       { customer: true,  merchant: true,  admin: true }],
  ['price-advisor.find_deals',          { customer: true,  merchant: false, admin: true }],
  ['price-advisor.compare_competitor',  { customer: false, merchant: true,  admin: true }],
  // cart
  ['cart.add',                          { customer: true,  merchant: false, admin: true }],
  ['cart.remove',                       { customer: true,  merchant: false, admin: true }],
  ['cart.view',                         { customer: true,  merchant: false, admin: true }],
  ['cart.apply_coupon',                 { customer: true,  merchant: false, admin: true }],
  // support
  ['support.order_status',              { customer: true,  merchant: false, admin: true }],
  ['support.open_ticket',               { customer: true,  merchant: false, admin: true }],
  ['support.refund_request',            { customer: true,  merchant: false, admin: true }],
  // listing (merchant-only)
  ['listing.create',        { customer: false, merchant: true, admin: true }],
  ['listing.update',        { customer: false, merchant: true, admin: true }],
  ['listing.import_bulk',   { customer: false, merchant: true, admin: true }],
  ['listing.optimize_images', { customer: false, merchant: true, admin: true }],
  // inventory (merchant-only)
  ['inventory.stock_levels', { customer: false, merchant: true, admin: true }],
  ['inventory.set_stock',    { customer: false, merchant: true, admin: true }],
  ['inventory.reorder',      { customer: false, merchant: true, admin: true }],
  // pricing-strategy (merchant-only)
  ['pricing-strategy.suggest_price',           { customer: false, merchant: true, admin: true }],
  ['pricing-strategy.run_pricing_experiment',  { customer: false, merchant: true, admin: true }],
  // review-moderator (merchant-only)
  ['review-moderator.moderate_pending', { customer: false, merchant: true, admin: true }],
  ['review-moderator.approve',          { customer: false, merchant: true, admin: true }],
  ['review-moderator.reject',           { customer: false, merchant: true, admin: true }],
  // analytics (merchant + admin)
  ['analytics.nl_query',         { customer: false, merchant: true, admin: true }],
  ['analytics.top_products',     { customer: false, merchant: true, admin: true }],
  ['analytics.revenue_breakdown',{ customer: false, merchant: true, admin: true }],
  // user-management (admin-only)
  // NOTE: set_role is deliberately denied for customer/merchant. The LLM06
  // teaching sink is that when enforce_tool_acl='false' the supervisor
  // dispatches anyway; Layer C (the tool implementation) also skips the
  // check. See @intentional-vulnerability above.
  ['user-management.lookup',         { customer: false, merchant: false, admin: true }],
  ['user-management.set_role',       { customer: false, merchant: false, admin: true }],
  ['user-management.reset_password', { customer: false, merchant: false, admin: true }],
  ['user-management.ban',            { customer: false, merchant: false, admin: true }],
  // audit (admin-only)
  ['audit.recent_events',        { customer: false, merchant: false, admin: true }],
  ['audit.search_by_user',       { customer: false, merchant: false, admin: true }],
  ['audit.summarize_anomalies',  { customer: false, merchant: false, admin: true }],
  // system (admin-only)
  ['system.health_check',       { customer: false, merchant: false, admin: true }],
  ['system.run_diagnostic',     { customer: false, merchant: false, admin: true }],
  ['system.restart_service',    { customer: false, merchant: false, admin: true }],
  ['system.read_config',        { customer: false, merchant: false, admin: true }],
  // policy (admin-only)
  ['policy.list_policies',      { customer: false, merchant: false, admin: true }],
  ['policy.get_policy',         { customer: false, merchant: false, admin: true }],
  ['policy.update_policy',      { customer: false, merchant: false, admin: true }],
  // mcp-registry (admin-only)
  ['mcp-registry.list_servers',        { customer: false, merchant: false, admin: true }],
  ['mcp-registry.describe_tools',      { customer: false, merchant: false, admin: true }],
  ['mcp-registry.register',            { customer: false, merchant: false, admin: true }],
  ['mcp-registry.remove',              { customer: false, merchant: false, admin: true }],
  ['mcp-registry.import_manifest',     { customer: false, merchant: false, admin: true }],
  ['mcp-registry.get_schema_history',  { customer: false, merchant: false, admin: true }],
  // uploads (mixed)
  ['uploads.upload_avatar',        { customer: true,  merchant: true,  admin: true }],
  ['uploads.upload_product_image', { customer: false, merchant: true,  admin: true }],
  ['uploads.upload_product_manual',{ customer: false, merchant: true,  admin: true }],
  // email (mixed — customers read own inbox; merchants get full send/read)
  ['email.read_inbox',           { customer: true,  merchant: true,  admin: true }],
  ['email.send',                 { customer: false, merchant: true,  admin: true }],
  ['email.render_template',      { customer: false, merchant: true,  admin: true }],
];
module.exports={TOOLS};
