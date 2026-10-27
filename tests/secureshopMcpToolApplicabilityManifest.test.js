'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const parser=require('../client/node_modules/@babel/parser');
const manifest=require('../docs/secureshop/mcp-tool-applicability-manifest.json');
const root=path.resolve(__dirname,'..');
const HOST='agent-host/index.js',REGISTRY='agent-host/agents/mcp-registry/server.js';
const HANDLER='agent-host/agents/mcp-registry/tools/index.js';
const ROLE='server/services/secureshopBoundRoleChat.js';
const COMPOSITION='server/services/secureshopBoundReviewComposition.js';
const ADAPTER='server/services/secureshopV23RegisterAdapter.js';
const CAPABILITY='server/services/secureshopV23RegisterCapability.js';
const EXPECTED=Object.freeze({
 analytics:['nl_query','top_products','revenue_breakdown'],
 audit:['recent_events','search_by_user','summarize_anomalies'],
 cart:['add','remove','view','apply_coupon'],
 email:['send','read_inbox','summarize_thread','auto_reply'],
 inventory:['stock_levels','reorder_suggestion','set_stock'],
 listing:['create','update','import_bulk','optimize_images'],
 'mcp-registry':['list_servers','register','remove','describe_tools','import_manifest'],
 policy:['read_policy','update_policy','apply_policy_to_agents'],
 'price-advisor':['price_history','find_deals','compare_competitor'],
 'pricing-strategy':['suggest_price','run_pricing_experiment'],
 'product-search':['search','similar','personalized_feed'],
 'review-moderator':['moderate_pending','approve','reject'],
 summarizer:['summarize_product','summarize_reviews','explain_return_policy','summarize_file'],
 support:['order_status','open_ticket','refund_request'],
 system:['health_check','restart_service','run_diagnostic','read_config'],
 uploads:['upload_avatar','upload_product_image','upload_return_evidence','upload_product_manual','download'],
 'user-management':['lookup','set_role','reset_password','ban'],
});
const expectedReview=[
 ['mcp-registry.list_servers','list_servers','listServers','registry_read'],
 ['mcp-registry.register','register','registerServer','registry_write_or_discovery_fetch'],
 ['mcp-registry.remove','remove','removeServer','registry_remove'],
 ['mcp-registry.describe_tools','describe_tools','describeTools','cached_description_read'],
 ['mcp-registry.import_manifest','import_manifest','register','xml_fetch_and_multiple_registry_writes'],
];
const listingInventoryReview=[
 ['listing.create','listing','create','create.postgres.js',['commerce.listing_create_1'],'product_create_with_stored_html','source_review_only_ownership_unresolved'],
 ['listing.update','listing','update','update.postgres.js',['commerce.updateProduct'],'product_patch','source_review_only_ownership_unresolved'],
 ['listing.import_bulk','listing','import_bulk','import_bulk.postgres.js',['commerce.listing_import_bulk_1','commerce.listing_import_bulk_2'],'json_xml_fetch_parse_and_product_import','source_review_only_ownership_unresolved'],
 ['listing.optimize_images','listing','optimize_images','optimize_images.postgres.js',['commerce.listing_optimize_images_1','exec'],'conditional_shell_command_from_product_image','source_review_only_exec_guard_and_ownership_unresolved'],
 ['inventory.stock_levels','inventory','stock_levels','index.postgres.js',['commerce.inventory_stock_levels_1'],'cross_merchant_stock_read','source_review_only_disclosure_unresolved'],
 ['inventory.reorder_suggestion','inventory','reorder_suggestion','index.postgres.js',['commerce.inventory_reorder_suggestion_2'],'product_reorder_read','source_review_only_ownership_unresolved'],
 ['inventory.set_stock','inventory','set_stock','index.postgres.js',['commerce.inventory_set_stock_3'],'absolute_stock_write','source_review_only_ownership_unresolved'],
];
const listingInventorySchemas={
 'listing.create':{type:'object',properties:{title:{type:'string'},description:{type:'string'},price:{type:'number'},images:{type:'array',items:{type:'string'}},template_source:{type:'string',description:'Optional Nunjucks template for the storefront'},retailer_id:{type:'number'}},required:['title']},
 'listing.update':{type:'object',properties:{product_id:{type:'number'},patch:{type:'object'}},required:['product_id','patch']},
 'listing.import_bulk':{type:'object',properties:{json_url:{type:'string'},xml_url:{type:'string'}}},
 'listing.optimize_images':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'inventory.stock_levels':{type:'object',properties:{}},
 'inventory.reorder_suggestion':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'inventory.set_stock':{type:'object',properties:{product_id:{type:'number'},qty:{type:'number'}},required:['product_id','qty']},
};
const emailAuditReview=[
 ['email.send','email','send',['commerce.sendEmail'],'stored_mail_with_unsafe_html_and_headers','source_review_only_confirmation_ownership_fixed_unresolved'],
 ['email.read_inbox','email','read_inbox',['commerce.email_read_inbox_3','commerce.email_read_inbox_4'],'selected_user_inbox_read','source_review_only_disclosure_unresolved'],
 ['email.summarize_thread','email','summarize_thread',['commerce.email_summarize_thread_5','_fetchInlinePreview'],'thread_read_prompt_and_conditional_inline_fetch','source_review_only_selected_source_network_effect_unresolved'],
 ['email.auto_reply','email','auto_reply',['summarize_thread','commerce.email_auto_reply_6','send'],'deterministic_regex_selected_transitive_stored_mail','source_review_only_confirmation_ownership_fixed_unresolved'],
 ['audit.recent_events','audit','recent_events',['pg().recentAudit'],'audit_read_with_optional_pre_read_outbox_append','source_review_only_readback_unresolved'],
 ['audit.search_by_user','audit','search_by_user',['pg().queryAuditTeaching'],'raw_sql_read_only_query_with_optional_pre_read_outbox_append','source_review_only_selected_query_readback_unresolved'],
 ['audit.summarize_anomalies','audit','summarize_anomalies',['pg().summaryAudit','formatSummary'],'audit_prompt_read_with_optional_pre_read_outbox_append','source_review_only_model_ingestion_unresolved'],
];
const emailAuditSchemas={
 'email.send':{type:'object',properties:{to:{type:'string'},from:{type:'string'},subject:{type:'string'},body_markdown:{type:'string'},headers:{type:'object'},thread_id:{type:'number'}},required:['to','subject','body_markdown']},
 'email.read_inbox':{type:'object',properties:{user_id:{type:'number'}},required:['user_id']},
 'email.summarize_thread':{type:'object',properties:{thread_id:{type:'number'}},required:['thread_id']},
 'email.auto_reply':{type:'object',properties:{thread_id:{type:'number'},from:{type:'string'}},required:['thread_id']},
 'audit.recent_events':{type:'object',properties:{limit:{type:'number'}}},
 'audit.search_by_user':{type:'object',properties:{username:{type:'string'}},required:['username']},
 'audit.summarize_anomalies':{type:'object',properties:{limit:{type:'number'}}},
};
const cartSupportReview=[
 ['cart.add','cart','add','add',['commerce.cart_add_1'],'immediate_cart_item_insert','source_review_only_owner_confirmation_unresolved'],
 ['cart.remove','cart','remove','remove',['commerce.cart_remove_2'],'immediate_raw_id_cart_delete','source_review_only_owner_confirmation_unresolved'],
 ['cart.view','cart','view','view',['commerce.cart_view_3'],'selected_user_cart_read','source_review_only_disclosure_unresolved'],
 ['cart.apply_coupon','cart','apply_coupon','applyCoupon',['commerce.readTeachingQuery'],'raw_coupon_sql_read_not_discount_application','source_review_only_coupon_observation_unresolved'],
 ['support.order_status','support','order_status','orderStatus',['commerce.readTeachingQuery'],'raw_order_sql_read_or_error','source_review_only_order_disclosure_unresolved'],
 ['support.open_ticket','support','open_ticket','openTicket',['commerce.support_openTicket_2'],'immediate_support_ticket_insert','source_review_only_owner_confirmation_unresolved'],
 ['support.refund_request','support','refund_request','refundRequest',['commerce.support_refundRequest_3'],'refund_request_ticket_insert_not_money_refund','source_review_only_order_owner_confirmation_unresolved'],
];
const cartSupportSchemas={
 'cart.add':{type:'object',properties:{product_id:{type:'number'},qty:{type:'number'}},required:['product_id']},
 'cart.remove':{type:'object',properties:{cart_item_id:{type:'number'}},required:['cart_item_id']},
 'cart.view':{type:'object',properties:{}},
 'cart.apply_coupon':{type:'object',properties:{code:{type:'string'}},required:['code']},
 'support.order_status':{type:'object',properties:{order_id:{type:['string','number']}},required:['order_id']},
 'support.open_ticket':{type:'object',properties:{subject:{type:'string'},body:{type:'string'}},required:['subject','body']},
 'support.refund_request':{type:'object',properties:{order_id:{type:'number'},reason:{type:'string'}},required:['order_id']},
};
const productSummaryReview=[
 ['product-search.search','product-search','search','search','search.postgres.js',['commerce.readTeachingQuery'],'selected_raw_sql_search_and_reflected_html_read','source_review_only_disclosure_model_readback_unresolved'],
 ['product-search.similar','product-search','similar','similar','similar.postgres.js',['commerce.product_search_similar_1','commerce.product_search_similar_2','store.count','store.search'],'selected_product_manual_retrieval_and_ranked_read','source_review_only_rag_scope_model_unresolved'],
 ['product-search.personalized_feed','product-search','personalized_feed','personalizedFeed','personalized_feed.postgres.js',['commerce.product_search_personalizedFeed_1'],'random_active_product_feed_with_echoed_user_id_not_user_specific','source_review_only_readback_unresolved'],
 ['summarizer.summarize_product','summarizer','summarize_product','summarizeProduct','summarize_product.postgres.js',['commerce.summarizer_summarizeProduct_1'],'selected_product_row_and_raw_description_summary','source_review_only_untrusted_content_readback_unresolved'],
 ['summarizer.summarize_reviews','summarizer','summarize_reviews','summarizeReviews','summarize_reviews.postgres.js',['commerce.summarizer_summarizeReviews_1'],'selected_reviews_and_verbatim_body_summary','source_review_only_untrusted_content_readback_unresolved'],
 ['summarizer.explain_return_policy','summarizer','explain_return_policy','explainReturnPolicy',null,['fs.readFileSync','_fetchHttp'],'selected_url_file_or_http_fetch_with_raw_body_summary','source_review_only_network_file_browser_model_unresolved'],
 ['summarizer.summarize_file','summarizer','summarize_file','summarizeFile',null,['fs.readFileSync'],'original_selected_path_file_read_and_verbatim_summary','source_review_only_file_owner_model_unresolved'],
];
const productSummarySchemas={
 'product-search.search':{type:'object',properties:{query:{type:'string',description:'search text (matches name/description)'},filters:{type:'object',properties:{category:{type:'string'},min_price:{type:'number'},max_price:{type:'number'}}}},required:['query']},
 'product-search.similar':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'product-search.personalized_feed':{type:'object',properties:{user_id:{type:'number'}},required:['user_id']},
 'summarizer.summarize_product':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'summarizer.summarize_reviews':{type:'object',properties:{product_id:{type:'number'},k:{type:'number'}},required:['product_id']},
 'summarizer.explain_return_policy':{type:'object',properties:{policy_url:{type:'string'}},required:['policy_url']},
 'summarizer.summarize_file':{type:'object',properties:{path:{type:'string'}},required:['path']},
};
const uploadsReview=[
 ['uploads.upload_avatar','upload_avatar',['_decodeToBuffer','_writeFileWithMeta','fs.writeFileSync'],'selected_avatar_file_write_or_uncertain_failure','source_review_only_owner_confirmation_partial_effect_unresolved'],
 ['uploads.upload_product_image','upload_product_image',['_decodeToBuffer','_writeFileWithMeta','fs.writeFileSync'],'selected_product_image_file_write_or_uncertain_failure','source_review_only_owner_confirmation_partial_effect_unresolved'],
 ['uploads.upload_return_evidence','upload_return_evidence',['_decodeToBuffer','_writeFileWithMeta','fs.writeFileSync'],'selected_return_evidence_file_write_or_uncertain_failure','source_review_only_owner_confirmation_partial_effect_unresolved'],
 ['uploads.upload_product_manual','upload_product_manual',['_decodeToBuffer','_writeFileWithMeta','fs.writeFileSync','extractText','chunkText','store.add'],'selected_manual_disk_write_and_conditional_vector_index_or_partial_failure','source_review_only_owner_corpus_confirmation_partial_effect_unresolved'],
 ['uploads.download','download',['fs.statSync','fs.readFileSync'],'selected_fragment_local_file_read_or_denial','source_review_only_file_scope_disclosure_unresolved'],
];
const uploadsSchemas={
 'uploads.upload_avatar':{type:'object',properties:{user_id:{type:'number'},file_bytes_base64:{type:'string'},filename:{type:'string'},mime:{type:'string'}},required:['user_id','file_bytes_base64','filename']},
 'uploads.upload_product_image':{type:'object',properties:{product_id:{type:'number'},file_bytes_base64:{type:'string'},filename:{type:'string'},mime:{type:'string'}},required:['product_id','file_bytes_base64','filename']},
 'uploads.upload_return_evidence':{type:'object',properties:{order_id:{type:'number'},file_bytes_base64:{type:'string'},filename:{type:'string'},mime:{type:'string'}},required:['order_id','file_bytes_base64','filename']},
 'uploads.upload_product_manual':{type:'object',properties:{product_id:{type:'number'},file_bytes_base64:{type:'string'},filename:{type:'string'},mime:{type:'string'}},required:['product_id','file_bytes_base64','filename']},
 'uploads.download':{type:'object',properties:{id:{type:'string',description:'path fragment (kind/scope/filename or filename)'},kind:{type:'string',description:'optional upload kind for scoping'}},required:['id']},
};
const userManagementReview=[
 ['user-management.lookup','lookup','full_credential_pii_row_read_with_outbox_and_attempted_audit_lookup_drops_pending_flag','source_review_only_disclosure_audit_state_unresolved'],
 ['user-management.set_role','setRole','selected_user_role_update_with_outbox_and_conditional_audit_pending','source_review_only_role_authority_confirmation_unresolved'],
 ['user-management.reset_password','resetPassword','selected_user_password_update_and_temporary_credential_no_email','source_review_only_credential_authority_confirmation_unresolved'],
 ['user-management.ban','ban','selected_user_banned_at_update_reason_in_audit_local_return_time','source_review_only_ban_authority_confirmation_unresolved'],
];
const userManagementSchemas={
 'user-management.lookup':{type:'object',properties:{username:{type:'string'}},required:['username']},
 'user-management.set_role':{type:'object',properties:{user_id:{type:'number'},role:{type:'string'}},required:['user_id','role']},
 'user-management.reset_password':{type:'object',properties:{user_id:{type:'number'}},required:['user_id']},
 'user-management.ban':{type:'object',properties:{user_id:{type:'number'},reason:{type:'string'}},required:['user_id']},
};
// Hashes pin complete, independently audited AST-local implementations, including
// ordered selected arguments, SQL/outbox transaction, attempted audit delivery,
// returned fields and all failure branches. Any source drift needs renewed review.
const userManagementPins={
 'agent-host/agents/user-management/server.js':{
  TOOLS:'ea82934f8a45c1b0ee94ee9926aff7b829ece768a1262c0e7af6d5e340d6d161',
  createServer:'cfb69c5b8b8fef7ed0be6aee40908a7eca0e235086c4c2d6d96aac5fb49f9b5d',
 },
 'agent-host/agents/user-management/tools/index.postgres.js':{
  audited:'091b9a5f0d2e94875070bc4b55ea871bd69bb7a29716b31968d177187ecc6a15',
  lookup:'543f36876077c5c2743f413e4a306d49210caad7147b60c11e3430712a224c12',
  setRole:'9cf2f08f8ee318b2df149df89f9cb1a93672141f9908f22bf70fc85f6a92a318',
  resetPassword:'84dd7ff44df8d09be9be9cf2c15425e1774d076ab692961d394156a33434d133',
  ban:'553ba5b7bf48debab8fd0a470b075b20b0f7c423ad5317d817dc65f3746611ee',
 },
 'server/database/postgres/secureshopCommerceDb.js':{
  userAction:'02b22da8d522cbd9db27f1519f1d37421dd787cd7cedbe97d028109da98256d1',
  deliverAudit:'5216066143a91310c61e91f251441d218add4396ffb35b2a8a2c5ef496487dc9',
 },
 'server/services/secureshop/toolAcl.js':{
  isEnforcementEnabled:'9b28d3ba79b1fdc1c63acb8edef35957674716602de47b6ebabe52fc92271bb6',
  checkToolAcl:'7c40ae392576d7029febb27d74e1cc28e515dba5586298619b46ed4b20d3492c',
 },
};
const systemReview=[
 ['system.health_check','health_check',[],['os.uptime','os.loadavg','os.hostname','os.freemem','os.totalmem'],'ungated_host_metadata_read','source_review_only_metadata_disclosure_unresolved'],
 ['system.restart_service','restart_service',['admin'],['exec'],'selected_service_shell_command_guarded_or_executed','source_review_only_exec_config_authority_effect_unresolved'],
 ['system.run_diagnostic','run_diagnostic',['admin'],['_mayReadFile','exec'],'selected_command_guarded_with_possible_side_file_read_or_executed','source_review_only_exec_side_read_authority_effect_unresolved'],
 ['system.read_config','read_config',['admin'],['fs.statSync','fs.readFileSync'],'selected_path_single_pass_clean_and_file_read_or_denial','source_review_only_file_scope_disclosure_unresolved'],
];
const systemSchemas={
 'system.health_check':{type:'object',properties:{}},
 'system.restart_service':{type:'object',properties:{name:{type:'string'}},required:['name']},
 'system.run_diagnostic':{type:'object',properties:{cmd_template:{type:'string'},args:{type:'string'}},required:['cmd_template']},
 'system.read_config':{type:'object',properties:{path:{type:'string'}},required:['path']},
};
// Each digest scopes to one AST node rather than the full source file. In
// particular a guarded command string is not an exec receipt, and the disabled
// diagnostic's selected side-file read must not be erased by a later refactor.
const systemPins={
 'agent-host/agents/system/server.js':{
  TOOLS:'7a2773aae5420b5e58e3b3d10250fc4b3363f68f3d9dd6c9166bdff71f239219',
  _wrap:'b2ec67573087bd27940f021b32f56aa050ca7bacb70e9c60bb7a31fee2db4442',
  createServer:'06b54a2e470a776b982499241458efe52eb86e79e7806cf05b98f82ab536435d',
 },
 'agent-host/agents/system/tools/index.js':{
  BASE:'8cd9d754ff0269f46199da0b31d851f3dd7915d757eaec140e01fe9042dfeb0e',
  ALLOW_EXEC:'dd9e572fbe85f2089eb22cd5b3839c6d4950e9f8aa8042ebcfda5599214a52ff',
  health_check:'1461c891b064f3fcb54563b0ba66eb7a4f08cea2c887254d51095b8e9ba89a13',
  restart_service:'b1353e9e53c21ab712b3bd40d8387f3fcbd478a6fbf4c3f9fec4686e7d4419fa',
  run_diagnostic:'543b4c7e3da58bb08a5971d2a38684902f8dda19de867ed6c6d2b5471b29b319',
  _mayReadFile:'ee13f3465ef693f5bccc5fa9489dd7a620c8a50966cdc91917636b0cc9818fa7',
  read_config:'7defa905a2818f7fbe6538e11248b787c61802f49fbb9b4c1d58145dbe82ef90',
 },
 'agent-host/shared/callerContext.js':{
  extractCaller:'d05d59d2feb426f7c918397293721c3662757294208e977b49818ae687d3f6ae',
  enforceRole:'44859b1ea035c3b158abf7744db531950d71926e181c36b1b6e884a38054e689',
 },
};
const policyReview=[
 ['policy.read_policy','read_policy',['commerce.policy_read_policy_1'],'selected_policy_row_read_or_unknown','source_review_only_disclosure_unresolved'],
 ['policy.update_policy','update_policy',['renderTemplateUnsafe','commerce.upsertPolicy'],'selected_markdown_unsafe_render_then_policy_upsert','source_review_only_render_side_effect_saved_policy_model_unresolved'],
 ['policy.apply_policy_to_agents','apply_policy_to_agents',['commerce.policy_apply_policy_to_agents_5'],'selected_role_policy_count_read_or_nonarray_filter_throw_no_apply_write','source_review_only_readback_not_prompt_application_unresolved'],
];
const policySchemas={
 'policy.read_policy':{type:'object',properties:{name:{type:'string'}},required:['name']},
 'policy.update_policy':{type:'object',properties:{name:{type:'string'},markdown:{type:'string'}},required:['name','markdown']},
 'policy.apply_policy_to_agents':{type:'object',properties:{role:{type:'string'}}},
};
// These node-local pins deliberately cover the selected SQL/render/prompt
// branches without running Nunjucks, a database, a model or a supervisor.
const policyPins={
 'agent-host/agents/policy/server.js':[
  ['VariableDeclarator','TOOLS','aeaa583f2c2a40a40089b274086fc7a37253c579f777bb08a38796ed69d93e62'],
  ['FunctionDeclaration','_wrap','0680cb9e833af1896ed5b2a05ea02958cf16ed630ea98b917b98a09a8de90367'],
  ['FunctionDeclaration','createServer','0db46f4108aa6a95c15bce7005f2e1aae9ce8613be4686d474d288470eecfb58'],
 ],
 'agent-host/agents/policy/tools/index.postgres.js':[
  ['FunctionDeclaration','read_policy','f84751b405abd5840f2e7624b6ff6153a21680d381dc5c42577b9843f5088901'],
  ['FunctionDeclaration','update_policy','8ec09fe821725940782f90dd99807c2d208dcefe4be3bcc7c5baedebf50893cd'],
  ['FunctionDeclaration','apply_policy_to_agents','566cbd3cb9a27929a128a4052507d7164164b4ec5ccbb23e772007a638cc0206'],
 ],
 'agent-host/agents/listing/tools/_nunjucksSink.js':[
  ['FunctionDeclaration','_fallbackRender','7919639e6afdc83e53cc165a0079a2242a9c92309d8ac4fa8d31d3ab54ae6bec'],
  ['FunctionDeclaration','renderTemplateUnsafe','5d375d929f88b7f5cad988c60e0472af7d9e2de1981861cedcd9593c18259463'],
 ],
 'server/services/secureshop/supervisors/policyLoader.js':[
  ['FunctionDeclaration','loadForRole','689e68ac75d95c7df8ffbcb34537f55e6f5fb531c6232ea84bd8599c35b693b4'],
  ['FunctionDeclaration','buildPolicyBlock','b1fdd374196bf8170cce6d7ee1b7bab035cc818621d2e91677b0be09c97b2cfc'],
  ['FunctionDeclaration','formatPolicyBlock','9d72b35bb2042cc010cb5e0472c486110eae695ed8234ed8352e751954a90f9d'],
 ],
 'server/services/secureshop/supervisors/basePrompt.js':[
  ['FunctionDeclaration','buildBasePrompt','4e9ed52ccdbbd1d7cefe8405915120a17714ac17bd937b58b17863a4a0c7029a'],
 ],
 'server/database/postgres/secureshopCommerceDb.js':[
  ['FunctionDeclaration','rows','35db544b15fa28078ec4b574ab8a27227f751236edd8e448e7acac161270226f'],
  ['VariableDeclarator','all','de3a9eea928a782dda3cad3d2fa199c6b96f34a99b1049e1c1524e6f4e7a1af6'],
  ['VariableDeclarator','one','9750a7db2f1c0f5fbab09cee074f15ce805a773dc096aacbb6d8418a5a1abec8'],
  ['VariableDeclarator','run','b568ea65954e3115ab10626a5ec9fa3eb81b917add6f39cfe52b96a655389501'],
  ['ObjectProperty','policy_read_policy_1','ff955ac46b1b793acf5e0035b32b51a43c94f3ff8fb9cdd77ef1d622d06f4839'],
  ['ObjectProperty','policy_apply_policy_to_agents_5','dd65f175a5a99a880d8119133847d61eb10202f217cb33e0b41176d397f9c591'],
  ['ObjectProperty','upsertPolicy','08cb3e280d6987680328c7bf345d165fcda00719f9f3639a6be265cb416da5fd'],
  ['FunctionDeclaration','getSecureShopCommerceDb','1b16c694e044c721097c87e82d6aa61a60c1eff59d0d96a038c810f2e0d822fc'],
 ],
};
const pricingStrategyReview=[
 ['pricing-strategy.suggest_price','suggest_price',['commerce.pricing_strategy_suggest_price_3','commerce.pricing_strategy__retrievePoisonedDoc_1','commerce.pricing_strategy__retrievePoisonedDoc_2'],'selected_product_manual_path_and_global_policy_markdown_price_suggestion_no_write','source_review_only_original_v25_manual_bytes_actor_judge_unresolved'],
 ['pricing-strategy.run_pricing_experiment','run_pricing_experiment',['commerce.pricing_strategy_run_pricing_experiment_4'],'selected_product_read_and_fabricated_experiment_projection_no_price_write','source_review_only_false_grounding_model_judge_unresolved'],
];
const pricingStrategySchemas={
 'pricing-strategy.suggest_price':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'pricing-strategy.run_pricing_experiment':{type:'object',properties:{product_id:{type:'number'},strategy:{type:'string'}},required:['product_id']},
};
const pricingStrategyPins={
 'agent-host/agents/pricing-strategy/server.js':[
  ['VariableDeclarator','TOOLS','de4ec2354e4f9b01af4e9c073f73a049129508bd5db93b74101eda405a4d24da'],
  ['FunctionDeclaration','_wrap','163a53c0f5b039a95d798fc7be833436d36a911bd9f808f035d7027e32eeca2c'],
  ['FunctionDeclaration','createServer','a044750326e4c37c22ab02397c5c567e2b1e0672585e5bdec8313352d4779c1b'],
 ],
 'agent-host/agents/pricing-strategy/tools/index.postgres.js':[
  ['FunctionDeclaration','_retrievePoisonedDoc','b439524592bff9812833d6cde7ef716cc8373ac20f69a097e8fe8a822931147c'],
  ['FunctionDeclaration','_extractTargetPrice','bb87133d9201f71d4b1e401393dc7262689f9f735e26ba624e7fbebfadb31a37'],
  ['FunctionDeclaration','suggest_price','b30b06e2f2cf693c2fb01cd8cd2f2f4bf66f0cba5e88812a5e8773011c980ab3'],
  ['FunctionDeclaration','run_pricing_experiment','e26a9af4131af3cf608a0d81442aeed64c21437188fb6b73401bfe780541b0a2'],
 ],
 'server/database/postgres/secureshopCommerceDb.js':[
  ['ObjectProperty','pricing_strategy__retrievePoisonedDoc_1','fe0beda14cd7f0fd851bf72701421ffa068c801545f108dfcdb9f662833b44f3'],
  ['ObjectProperty','pricing_strategy__retrievePoisonedDoc_2','f9fe51d6c3d6da76cef8be1e488c78f8b81efe5dd5d35298302ae14b2ecea5d2'],
  ['ObjectProperty','pricing_strategy_suggest_price_3','7af7fe1075e26854e86b2e4176434c8170461059b003a63f4d3b052c8c152b49'],
  ['ObjectProperty','pricing_strategy_run_pricing_experiment_4','83d3a862e731e8cd366f19ab1a1b0b29c00a7e380e897db3b3f03a121ea3470d'],
 ],
};
const analyticsReview=[
 ['analytics.nl_query','nl_query',['_translateWithLLM','_translate','commerce.readTeachingQuery'],'conditional_llm_or_deterministic_sql_read_only_rows_or_error_without_retry','source_review_only_v35_model_sql_context_judge_unresolved'],
 ['analytics.top_products','top_products',['commerce.analyticsTopProducts'],'selected_limit_revenue_aggregate_with_period_echo_not_filter','source_review_only_aggregate_readback_unresolved'],
 ['analytics.revenue_breakdown','revenue_breakdown',['commerce.analyticsCategories','commerce.analyticsStatuses'],'category_and_status_revenue_aggregate_reads','source_review_only_aggregate_readback_unresolved'],
];
const analyticsSchemas={
 'analytics.nl_query':{type:'object',properties:{question:{type:'string'}},required:['question']},
 'analytics.top_products':{type:'object',properties:{period:{type:'string'},limit:{type:'number'}}},
 'analytics.revenue_breakdown':{type:'object',properties:{}},
};
const analyticsPins={
 'agent-host/agents/analytics/server.js':[
  ['VariableDeclarator','TOOLS','97fb5be2450711ec0a0b422f85c91c9b5c097073f079a3821f6f621a3d3dfa0b'],
  ['FunctionDeclaration','_wrap','163a53c0f5b039a95d798fc7be833436d36a911bd9f808f035d7027e32eeca2c'],
  ['FunctionDeclaration','createServer','c9addf625e5be6308a499e173015b4436a3c2189022123f41277073cce21c120'],
 ],
 'agent-host/agents/analytics/tools/index.postgres.js':[
  ['FunctionDeclaration','_getAiService','eb65325694fd19b5729ce8d383256b0039f62681fc7c2c2302f1620121f41f7e'],
  ['FunctionDeclaration','_translate','04ac4c5865426f726882911b05153c9f5e7e203b70a5c4384131fd45040ad2f1'],
  ['FunctionDeclaration','_translateWithLLM','24f18393a23a2dd1220cf062fc55a5c92ec1318c036b82dfe3ab8c4ace4b382a'],
  ['FunctionDeclaration','nl_query','1d9d0b2c062b794ff8ec080235424274e6b8f06a4c02cb487226b040b8c6aacc'],
  ['FunctionDeclaration','top_products','c39a342fa2a27eb3757a504ab5d7c7521599b9d2ca2189d7b025aa7dee64ad55'],
  ['FunctionDeclaration','revenue_breakdown','2b58579c9571a3a3d5a5f98af2e5e9798f61fed29c204415d01f7d081812c196'],
 ],
 'server/database/postgres/secureshopCommerceDb.js':[
  ['ObjectMethod','readTeachingQuery','03c04f202a2f617098e50cf46d6808af6329bc8231d5b5b2c5e8ec3718c147fc'],
  ['ObjectProperty','analyticsTopProducts','6e2c16f45f154751ebab695f7baa9126c621f15756db8af51fc1c19ee2eaf481'],
  ['ObjectProperty','analyticsCategories','8d2090b4975c9886f7670770c45ab3cc1572674f89308cf34423f9b5766a755d'],
  ['ObjectProperty','analyticsStatuses','9757a72d1ca548b1fb843466c5c8b10c31c560e18894fbfb73851afe42bcd0ad'],
 ],
};
const priceAdvisorReview=[
 ['price-advisor.price_history','price_history','priceHistory',['commerce.price_advisor_priceHistory_1'],'selected_product_read_with_synthetic_31_point_history','source_review_only_history_model_readback_unresolved'],
 ['price-advisor.find_deals','find_deals','findDeals',['commerce.price_advisor_findDeals_2','_rand'],'selected_active_products_with_fabricated_competitor_deals','source_review_only_v33_model_false_grounding_judge_unresolved'],
 ['price-advisor.compare_competitor','compare_competitor','compareCompetitor',['commerce.price_advisor_compareCompetitor_3','_fetchAny'],'selected_product_then_unrestricted_http_get_and_verbatim_response','source_review_only_v38_tool_output_native_listener_model_judge_unresolved'],
];
const priceAdvisorSchemas={
 'price-advisor.price_history':{type:'object',properties:{product_id:{type:'number'}},required:['product_id']},
 'price-advisor.find_deals':{type:'object',properties:{category:{type:'string'}}},
 'price-advisor.compare_competitor':{type:'object',properties:{product_id:{type:'number'},competitor_url:{type:'string'}},required:['product_id','competitor_url']},
};
const priceAdvisorPins={
 'agent-host/agents/price-advisor/server.js':[
  ['VariableDeclarator','TOOLS','2d23dbcccbd2179e7b2f1357984e928d8bf698b3dc5ce427a6d6aebe8f60bb30'],
  ['FunctionDeclaration','_wrap','0680cb9e833af1896ed5b2a05ea02958cf16ed630ea98b917b98a09a8de90367'],
  ['FunctionDeclaration','createServer','bbe548b90d8c981cf14e5cb16d705dd92f9034448b18a0de153276a055170368'],
 ],
 'agent-host/agents/price-advisor/tools/index.postgres.js':[
  ['FunctionDeclaration','_rand','cbd71f3f925766160e429bae81904f9ef78b82febe500e7c069219b1ed3b8f2e'],
  ['FunctionDeclaration','priceHistory','9b2243607e0430bb4564ab78b98383c2a90895696a213133737e2b1ce8e80d4b'],
  ['FunctionDeclaration','findDeals','33aa8dad93f97e564203d3755e7bf70c6bb866d194cd062c7f23d3bc51cf73fb'],
  ['FunctionDeclaration','_fetchAny','cc3de8575368636fa466df6d26681f04246d6459b70a6c82619a931b46358bb6'],
  ['FunctionDeclaration','compareCompetitor','417dd03714de5e31f1e7143221c39f3518031548e931fbede9e13117673d5419'],
 ],
 'server/database/postgres/secureshopCommerceDb.js':[
  ['ObjectProperty','price_advisor_priceHistory_1','94e8322e0acf831a132dde5e5b50f83bf61209a180836a9662a35e5a05c4eff7'],
  ['ObjectProperty','price_advisor_findDeals_2','7d5c24cb277c596921b2ae1d64913879a7fadda311f6f5fe1241fde490af53c2'],
  ['ObjectProperty','price_advisor_compareCompetitor_3','cff8b8a2f68e169f486f42ac8e3ba32a1377a06afa427a60d9882544ea287b1f'],
 ],
};
const reviewModeratorReview=[
 ['review-moderator.moderate_pending','moderate_pending',['commerce.review_moderator_moderate_pending_3','_moderatorLLM','approve','reject'],'selected_pending_review_read_deterministic_classifier_then_per_row_status_writes','source_review_only_owner_model_bound_moderation_unresolved'],
 ['review-moderator.approve','approve',['commerce.review_moderator_approve_1'],'selected_raw_review_id_approved_auto_status_write','source_review_only_owner_confirmation_saved_effect_unresolved'],
 ['review-moderator.reject','reject',['commerce.review_moderator_reject_2'],'selected_raw_review_id_rejected_auto_status_and_notes_write','source_review_only_owner_confirmation_saved_effect_unresolved'],
];
const reviewModeratorSchemas={
 'review-moderator.moderate_pending':{type:'object',properties:{limit:{type:'number'}}},
 'review-moderator.approve':{type:'object',properties:{review_id:{type:'number'}},required:['review_id']},
 'review-moderator.reject':{type:'object',properties:{review_id:{type:'number'},reason:{type:'string'}},required:['review_id']},
};
const reviewModeratorPins={
 'agent-host/agents/review-moderator/server.js':[
  ['VariableDeclarator','TOOLS','f58b6a665e3bbdb68b096c2bfbdab38ddee9c09969678a3f38abb10f10a4dd44'],
  ['FunctionDeclaration','_wrap','163a53c0f5b039a95d798fc7be833436d36a911bd9f808f035d7027e32eeca2c'],
  ['FunctionDeclaration','createServer','d5879ef83d5b1bd1e517367f7e2464719e6044ed828931e65400fd871b810ccc'],
 ],
 'agent-host/agents/review-moderator/tools/index.postgres.js':[
  ['FunctionDeclaration','_moderatorLLM','c7ec77c34449ab44c4109a26ec1c257505813b5e9d4083929680eb0e36d75939'],
  ['FunctionDeclaration','approve','c0b4130ff40b01b4bc9ad15ab73c3b478a4696000a4316fe0f00885375cefa3e'],
  ['FunctionDeclaration','reject','9f1cd30e950f90cc85d44603ac8074c5946e9a82d3ac7159f6135c16f2366dde'],
  ['FunctionDeclaration','moderate_pending','573c27293ca6b7dd33c15fa9df8c1b92457954b0ea60ba21e185f9207e9af5fa'],
 ],
 'server/database/postgres/secureshopCommerceDb.js':[
  ['ObjectProperty','review_moderator_approve_1','2041009896c88a42a816acaa6142d48065ff1cd6320222b172d07ab8a4f72531'],
  ['ObjectProperty','review_moderator_reject_2','f2ce0832fab6e3e40eb491301ded3da4d096ac17caaf648ded2c58be65993016'],
  ['ObjectProperty','review_moderator_moderate_pending_3','9f2e40db53c093789c228699365d2d8d4e1c3b6d5345622ebd0a1a72ca2051a1'],
 ],
};
const expectedSchemas={
 list_servers:{type:'object',properties:{}},
 register:{type:'object',properties:{name:{type:'string'},url:{type:'string'},transport:{type:'string',enum:['sse','stdio']},stdio_cmd:{type:'string'}},required:['name']},
 remove:{type:'object',properties:{name:{type:'string'}},required:['name']},
 describe_tools:{type:'object',properties:{name:{type:'string'}},required:['name']},
 import_manifest:{type:'object',properties:{xml_url:{type:'string'}},required:['xml_url']},
};
const cache=new Map();
function source(file){
 const absolute=path.resolve(root,file);
 assert.ok(absolute.startsWith(root+path.sep)&&fs.realpathSync(absolute)===absolute,`canonical source ${file}`);
 if(!cache.has(file))cache.set(file,fs.readFileSync(absolute,'utf8'));
 return cache.get(file);
}
function tree(file,overrides={}){return parser.parse(overrides[file]??source(file),{sourceType:'unambiguous',plugins:['jsx']});}
function visit(node,predicate,found=[]){
 if(!node||typeof node!=='object')return found;
 if(predicate(node))found.push(node);
 for(const [key,value] of Object.entries(node)){
  if(['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key))continue;
  if(Array.isArray(value))value.forEach(child=>visit(child,predicate,found));
  else if(value&&typeof value==='object')visit(value,predicate,found);
 }
 return found;
}
function name(node){
 if(node?.type==='Identifier')return node.name;
 if(node?.type==='ThisExpression')return 'this';
 if(node?.type==='MemberExpression'&&!node.computed)return `${name(node.object)}.${node.property.name}`;
 if(node?.type==='OptionalMemberExpression'&&!node.computed)return `${name(node.object)}.${node.property.name}`;
 return null;
}
const calls=(node,callee)=>visit(node,n=>n.type==='CallExpression'&&name(n.callee)===callee);
function declaration(ast,id){const hits=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.name===id);
 assert.equal(hits.length,1,`single declaration ${id}`);return hits[0];}
function fn(ast,id){const hits=visit(ast,n=>n.type==='FunctionDeclaration'&&n.id?.name===id);
 assert.equal(hits.length,1,`single function ${id}`);return hits[0];}
function property(obj,key){return obj?.type==='ObjectExpression'&&obj.properties.find(p=>p.type==='ObjectProperty'&&!p.computed&&(p.key.name??p.key.value)===key);}
function literalArray(node){assert.equal(node?.type,'ArrayExpression');return node.elements.map(e=>{assert.equal(e?.type,'StringLiteral');return e.value;});}
function staticValue(node){
 if(node?.type==='StringLiteral'||node?.type==='BooleanLiteral'||node?.type==='NumericLiteral')return node.value;
 if(node?.type==='ArrayExpression')return node.elements.map(staticValue);
 if(node?.type==='ObjectExpression')return Object.fromEntries(node.properties.map(p=>{
  assert.equal(p.type,'ObjectProperty');assert.equal(p.computed,false);
  return [p.key.name??p.key.value,staticValue(p.value)];
 }));
 throw new Error(`nonstatic schema node ${node?.type}`);
}
function mutation(file,before,after){const original=source(file);assert.ok(original.includes(before),`mutation anchor ${file}`);
 return {[file]:original.replace(before,after)};}
function catalog(overrides={},data=manifest){
 assert.deepEqual(Object.keys(data).sort(),['schemaVersion','scope','qualification','sourceDenominatorComplete','supportedActionDenominatorComplete','nativeEvidence','hostBinding','catalog','unreviewedDefault','reviewedRegistry','reviewedListingInventory','reviewedEmailAudit','reviewedCartSupport','reviewedProductSearchSummarizer','reviewedUploads','reviewedUserManagement','reviewedSystem','reviewedPolicy','reviewedPricingStrategy','reviewedAnalytics','reviewedPriceAdvisor','reviewedReviewModerator','v23Binding','separateSurfaces'].sort());
 assert.deepEqual([data.schemaVersion,data.scope,data.sourceDenominatorComplete,data.supportedActionDenominatorComplete,data.nativeEvidence],
  [1,'fixed_native_task_agent_descriptor_inventory_source_only',false,false,null]);
 assert.deepEqual(data.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
 assert.deepEqual(data.unreviewedDefault,{applicability:'unresolved',sourceReview:null,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
 assert.deepEqual(data.catalog.map(row=>row.agent),Object.keys(EXPECTED));
 assert.equal(data.catalog.reduce((count,row)=>count+row.tools.length,0),60);
 for(const row of data.catalog){
  assert.deepEqual(Object.keys(row).sort(),['agent','tools']);
  assert.deepEqual(row.tools,EXPECTED[row.agent],`${row.agent} exact identities`);
  const server=tree(`agent-host/agents/${row.agent}/server.js`,overrides);
  const declared=declaration(server,'TOOLS').init;
  assert.equal(declared.type,'ArrayExpression',`${row.agent} executable TOOLS array`);
  assert.deepEqual(declared.elements.map(entry=>property(entry,'name')?.value?.value),row.tools,`${row.agent} executable names`);
  const create=fn(server,'createServer');
  assert.equal(calls(create,'server.setRequestHandler').filter(call=>call.arguments[0]?.name==='ListToolsRequestSchema'
   &&visit(call.arguments[1],n=>n.type==='ObjectProperty'&&n.key?.name==='tools'&&n.value?.name==='TOOLS').length===1).length,1,`${row.agent} discovery exposes TOOLS`);
  assert.equal(calls(create,'server.setRequestHandler').filter(call=>call.arguments[0]?.name==='CallToolRequestSchema').length,1,`${row.agent} call handler`);
 }
 const reviewed=new Set(data.reviewedRegistry.map(row=>row.id));
 assert.equal(reviewed.size,5);assert.equal(60-reviewed.size,55);
 assert.deepEqual([...reviewed],expectedReview.map(row=>row[0]));
 const extraReviewed=new Set(data.reviewedListingInventory.map(row=>row.id));
 assert.equal(extraReviewed.size,7);assert.deepEqual([...extraReviewed],listingInventoryReview.map(row=>row[0]));
 const mailAuditReviewed=new Set(data.reviewedEmailAudit.map(row=>row.id));
 assert.equal(mailAuditReviewed.size,7);assert.deepEqual([...mailAuditReviewed],emailAuditReview.map(row=>row[0]));
 const cartSupportReviewed=new Set(data.reviewedCartSupport.map(row=>row.id));
 assert.equal(cartSupportReviewed.size,7);assert.deepEqual([...cartSupportReviewed],cartSupportReview.map(row=>row[0]));
 const productReviewed=new Set(data.reviewedProductSearchSummarizer.map(row=>row.id));
 assert.equal(productReviewed.size,7);assert.deepEqual([...productReviewed],productSummaryReview.map(row=>row[0]));
 const uploadsReviewed=new Set(data.reviewedUploads.map(row=>row.id));
 assert.equal(uploadsReviewed.size,5);assert.deepEqual([...uploadsReviewed],uploadsReview.map(row=>row[0]));
 const userReviewed=new Set(data.reviewedUserManagement.map(row=>row.id));
 assert.equal(userReviewed.size,4);assert.deepEqual([...userReviewed],userManagementReview.map(row=>row[0]));
 const systemReviewed=new Set(data.reviewedSystem.map(row=>row.id));
 assert.equal(systemReviewed.size,4);assert.deepEqual([...systemReviewed],systemReview.map(row=>row[0]));
 const policyReviewed=new Set(data.reviewedPolicy.map(row=>row.id));
 assert.equal(policyReviewed.size,3);assert.deepEqual([...policyReviewed],policyReview.map(row=>row[0]));
 const pricingReviewed=new Set(data.reviewedPricingStrategy.map(row=>row.id));
 assert.equal(pricingReviewed.size,2);assert.deepEqual([...pricingReviewed],pricingStrategyReview.map(row=>row[0]));
 const analyticsReviewed=new Set(data.reviewedAnalytics.map(row=>row.id));
 assert.equal(analyticsReviewed.size,3);assert.deepEqual([...analyticsReviewed],analyticsReview.map(row=>row[0]));
 const advisorReviewed=new Set(data.reviewedPriceAdvisor.map(row=>row.id));
 assert.equal(advisorReviewed.size,3);assert.deepEqual([...advisorReviewed],priceAdvisorReview.map(row=>row[0]));
 const moderatorReviewed=new Set(data.reviewedReviewModerator.map(row=>row.id));
 assert.equal(moderatorReviewed.size,3);assert.deepEqual([...moderatorReviewed],reviewModeratorReview.map(row=>row[0]));
 const allReviewed=[...reviewed,...extraReviewed,...mailAuditReviewed,...cartSupportReviewed,...productReviewed,...uploadsReviewed,...userReviewed,...systemReviewed,...policyReviewed,...pricingReviewed,...analyticsReviewed,...advisorReviewed,...moderatorReviewed];
 assert.equal(new Set(allReviewed).size,allReviewed.length,'reviewed partitions disjoint');
 assert.equal(60-allReviewed.length,0,'all 60 fixed native MCP identities have source-only reviews');
 assert.deepEqual(data.separateSurfaces,['51 bound RoleChat descriptors','dynamically registered external MCP tools','335 SecureShop bridge registrations','37 outside-bridge authority route variants']);
}
function host(overrides={},data=manifest){
 assert.deepEqual(data.hostBinding,{agentHostFile:HOST,applicationFile:'server/services/secureshop/index.js',
  applicationMountFile:'server/applicationServer.js',manifestFile:'server/services/secureshop/toolManifest.js',
  poolFile:'server/services/secureshop/mcpClientPool.js',endpointKind:'one_sse_endpoint_pair_per_agent_not_per_tool',runtimeVerified:false});
 const ast=tree(HOST,overrides),agents=literalArray(declaration(ast,'TASK_AGENTS').init);
 assert.deepEqual([...agents].sort(),Object.keys(EXPECTED).sort());
 const loop=visit(ast,n=>n.type==='ForOfStatement'&&n.left?.declarations?.[0]?.id?.name==='name'
  &&n.right?.name==='TASK_AGENTS');assert.equal(loop.length,1,'host loops exact native agents');
 const factories=visit(loop[0],n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.length===1&&n.id.properties[0].key?.name==='createServer');
 assert.equal(factories.length,1,'per-agent factory import');
 const dynamicRequire=factories[0].init;
 assert.equal(name(dynamicRequire?.callee),'require');
 assert.equal(dynamicRequire.arguments[0]?.type,'TemplateLiteral');
 assert.equal(dynamicRequire.arguments[0].quasis.map(q=>q.value.cooked).join('${}'),'./agents/${}/server.js');
 assert.equal(dynamicRequire.arguments[0].expressions[0]?.name,'name');
 const get=calls(loop[0],'app.get').filter(c=>c.arguments[0]?.type==='TemplateLiteral'
  &&c.arguments[0].quasis.map(q=>q.value.cooked).join('${}')==='/mcp/${}'
  &&c.arguments[0].expressions[0]?.name==='name');
 assert.equal(get.length,1,'one SSE GET per agent');
 const post=calls(loop[0],'app.post').filter(c=>c.arguments[0]?.type==='TemplateLiteral'
  &&c.arguments[0].quasis.map(q=>q.value.cooked).join('${}')==='/mcp/${}/message'
  &&c.arguments[0].expressions[0]?.name==='name');
 assert.equal(post.length,1,'one SSE POST per agent');
 const created=calls(loop[0],'createServer');assert.equal(created.length,1);
 assert.equal(declaration(loop[0],'server').init,created[0],'per-agent factory creates connected server');
 assert.equal(calls(loop[0],'server.connect').length,1,'SSE server connects transport');
 assert.equal(calls(loop[0],'transport.handlePostMessage').length,1,'POST reaches transport');
 const transport=declaration(get[0].arguments[1],'transport').init;
 assert.equal(transport?.type,'NewExpression');assert.equal(name(transport.callee),'SSEServerTransport');
 assert.equal(transport.arguments[0]?.type,'TemplateLiteral');
 assert.deepEqual(transport.arguments[0].quasis.map(q=>q.value.cooked),['/mcp/','/message']);
 assert.equal(transport.arguments[0].expressions[0]?.name,'name');
 assert.equal(transport.arguments[1]?.name,'res');
 const saved=calls(get[0].arguments[1],'transports.set');assert.equal(saved.length,1);
 assert.equal(saved[0].arguments[0]?.type,'TemplateLiteral');
 assert.deepEqual(saved[0].arguments[0].expressions.map(name),['name','transport.sessionId']);
 assert.equal(saved[0].arguments[1]?.name,'transport');
 const resumed=calls(post[0].arguments[1],'transports.get');assert.equal(resumed.length,1);
 assert.deepEqual(resumed[0].arguments[0]?.expressions?.map(name),['name','sessionId']);
 assert.equal(name(declaration(post[0].arguments[1],'sessionId').init),'req.query.sessionId');
 assert.equal(visit(get[0].arguments[1],n=>n.type==='AwaitExpression'&&n.argument===calls(get[0].arguments[1],'server.connect')[0]).length,1);
 assert.equal(visit(post[0].arguments[1],n=>n.type==='AwaitExpression'&&n.argument===calls(post[0].arguments[1],'transport.handlePostMessage')[0]).length,1);
 const app=tree(data.hostBinding.applicationFile,overrides),boot=fn(app,'boot');
 const start=calls(boot,'agentHost.start'),connect=calls(boot,'pool.connect'),refresh=calls(boot,'manifest.refresh');
 assert.equal(start.length,1);assert.equal(connect.length,1);assert.equal(refresh.length,1);
 for(const call of [start[0],connect[0],refresh[0]])assert.equal(visit(boot,n=>n.type==='AwaitExpression'&&n.argument===call).length,1,'await host/pool/manifest');
 assert.ok(start[0].start<connect[0].start&&connect[0].start<refresh[0].start,'host readiness precedes manifest refresh');
 const pool=tree(data.hostBinding.poolFile,overrides);
 assert.deepEqual(literalArray(declaration(pool,'AGENT_NAMES').init.arguments[0]),agents,'pool native names match host');
 const tool=tree(data.hostBinding.manifestFile,overrides);
 const nativeSet=declaration(tool,'NATIVE_AGENTS').init.arguments[0];
 assert.equal(name(nativeSet.callee),'Set');
 assert.deepEqual(literalArray(nativeSet.arguments[0]),agents,'manifest native names match host');
 const roles=declaration(tool,'ROLE_MAP').init.arguments[0];
 assert.ok(literalArray(property(roles,'admin').value).includes('mcp-registry'));
 for(const role of ['customer','merchant'])assert.ok(!literalArray(property(roles,role).value).includes('mcp-registry'));
 assert.equal(calls(tool,'client.listTools').length,1,'manifest reads exposed tools');
 const roleMethod=visit(tool,n=>n.type==='ClassMethod'&&n.key?.name==='getForRole');
 assert.equal(roleMethod.length,1);
 const filters=visit(roleMethod[0],n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
  &&n.callee.property?.name==='filter'&&name(n.callee.object?.callee)==='this.getAll');
 assert.equal(filters.length,1,'role method filters all native tools');
 assert.equal(filters[0].arguments[0]?.type,'ArrowFunctionExpression');
 const permitted=filters[0].arguments[0].body;
 assert.equal(permitted.type,'CallExpression','positive role filter, not inverted');
 assert.equal(name(permitted.callee),'allowed.includes');
 assert.deepEqual(permitted.arguments.map(name),['tool.agent']);
 assert.equal(visit(roleMethod[0],n=>n.type==='ReturnStatement'&&n.argument===filters[0]).length,1);
 const mount=tree(data.hostBinding.applicationMountFile,overrides);
 const enable=visit(mount,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&name(n.test.left)==='process.env.SS_ENABLE'&&n.test.right?.value==='true');
 assert.equal(enable.length,1,'SecureShop boot is conditional');
 const bootCall=calls(enable[0].consequent,'secureshopV2.boot');
 assert.equal(bootCall.length,1,'conditional boot invokes owned host');
 const ready=visit(enable[0].consequent,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
  &&n.callee.property?.name==='then'&&n.callee.object===bootCall[0]);
 assert.equal(ready.length,1,'only successful boot publishes handles');
 assert.equal(ready[0].arguments[0]?.type,'ArrowFunctionExpression');
 assert.deepEqual(ready[0].arguments[0].params.map(name),['handles']);
 assert.equal(visit(ready[0].arguments[0],n=>n.type==='AssignmentExpression'&&name(n.left)==='app.locals.secureshopV2'
  &&n.right?.name==='handles').length,1,'success callback publishes booted handles');
}
function registry(overrides={},data=manifest){
 const server=tree(REGISTRY,overrides),create=fn(server,'createServer');
 const registered=calls(create,'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema');
 assert.ok(registered,'registry MCP call registration');
 const dispatch=registered.arguments[1];
 const gate=calls(dispatch,'enforceRole');assert.equal(gate.length,1);
 assert.equal(gate[0].arguments[0]?.name,'caller');
 assert.deepEqual(literalArray(gate[0].arguments[1]),['admin']);
 const denied=visit(dispatch,n=>n.type==='IfStatement'&&n.test?.name==='denied'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');
 assert.equal(denied.length,1,'denial returns before dispatch');
 const switches=visit(dispatch,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');
 assert.equal(switches.length,1);assert.ok(gate[0].start<denied[0].start&&denied[0].start<switches[0].start);
 const cases=switches[0].cases.filter(c=>c.test?.type==='StringLiteral');
 assert.deepEqual(cases.map(c=>c.test.value),EXPECTED['mcp-registry']);
 const handlers=tree(HANDLER,overrides);
 for(const [id,handler,effect,consequence] of expectedReview){
  const row=data.reviewedRegistry.find(item=>item.id===id);assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','inputSchema','advertisedRoles','effectCall','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  assert.deepEqual(row.inputSchema,expectedSchemas[handler],`${id} frozen advertised input`);
  assert.deepEqual(row.advertisedRoles,['admin'],`${id} admin-only role`);
  const descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===handler);
  assert.ok(descriptor,`${id} same catalog row`);
  assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema,`${id} executable input schema`);
  assert.deepEqual([row.handler,row.effectCall,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [handler,effect==='register'?'register':`pg().${effect}`,consequence,
    handler==='register'?'admin_gated_source_only_original_v23_stdio_branch_separate':'admin_gated_source_only',
    handler==='register'?['V23']:[],[],null],`${id} source-only metadata`);
  const item=cases.find(c=>c.test.value===handler);
  const forwarded=calls(item,handler);
  assert.equal(forwarded.length,1,`${id} dispatches its own handler`);
  assert.equal(visit(item,n=>n.type==='AwaitExpression'&&n.argument===forwarded[0]).length,1,`${id} awaits handler`);
  if(handler==='list_servers')assert.equal(forwarded[0].arguments.length,0,'list takes no supplied arguments');
  else{assert.equal(forwarded[0].arguments.length,1,`${id} one selected argument`);
   const supplied=forwarded[0].arguments[0];
   assert.equal(supplied.type,'LogicalExpression');assert.equal(supplied.operator,'||');
   assert.equal(supplied.left?.name,'args');assert.equal(supplied.right?.type,'ObjectExpression');
   assert.equal(supplied.right.properties.length,0);}
  const action=fn(handlers,handler);
  if(handler==='import_manifest'){
   const loop=visit(action,n=>n.type==='ForOfStatement'&&n.right?.name==='list');assert.equal(loop.length,1);
   const imported=calls(loop[0],'register');assert.equal(imported.length,1,'each imported server registers');
   const fields=imported[0].arguments[0];assert.equal(fields?.type,'ObjectExpression');
   for(const key of ['name','url','transport']){
    const field=property(fields,key);assert.ok(field,`imported ${key}`);
    assert.equal(name(field.value?.callee),'String');
    if(key!=='transport')assert.equal(name(field.value.arguments[0]),`s.${key}`);
    else{assert.equal(field.value.arguments[0]?.type,'LogicalExpression');
     assert.equal(name(field.value.arguments[0].left),'s.transport');
     assert.equal(field.value.arguments[0].right?.value,'sse');}
   }
   assert.equal(visit(loop[0],n=>n.type==='AwaitExpression'&&n.argument===imported[0]).length,1);
   const fetched=calls(action,'_fetch');assert.equal(fetched.length,1,'manifest XML fetched');
   assert.equal(fetched[0].arguments[0]?.name,'xml_url','fetches selected manifest URL');
  }else{
   const effects=visit(action,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
    &&n.callee.property?.name===effect&&n.callee.object?.type==='CallExpression'&&name(n.callee.object.callee)==='pg');
   assert.equal(effects.length,1,`${id} exact database effect`);
   if(handler==='list_servers')assert.equal(effects[0].arguments.length,0);
   else if(handler==='remove'||handler==='describe_tools')assert.deepEqual(effects[0].arguments.map(name),['name'],`${id} selected name`);
   else{
    const request=effects[0].arguments[0];assert.equal(request?.type,'ObjectExpression');
    for(const key of ['name','url','stdio_cmd','schemaHash','tools'])assert.equal(name(property(request,key)?.value),key,`register ${key} binding`);
    assert.equal(name(property(request,'transport')?.value),'t','register selected transport');
   }
  }
 }
 const register=fn(handlers,'register');
 const sse=visit(register,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.left?.name==='t'&&n.test.right?.value==='sse');
 const stdio=visit(register,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.left?.name==='t'&&n.test.right?.value==='stdio');
 assert.equal(sse.length,1);assert.equal(stdio.length,1);
 const discovered=calls(sse[0].consequent,'_fetch');assert.equal(discovered.length,1,'SSE discovery fetch');
 assert.equal(discovered[0].arguments[0]?.type,'TemplateLiteral');
 assert.deepEqual(discovered[0].arguments[0].quasis.map(q=>q.value.cooked),['','/mcp/list_tools']);
 assert.equal(discovered[0].arguments[0].expressions[0]?.name,'url','SSE discovery uses selected URL');
 const capGuard=visit(stdio[0].consequent,n=>n.type==='IfStatement'
  &&n.test?.type==='UnaryExpression'&&n.test.operator==='!'
  &&name(n.test.argument?.callee)==='cap.isOwnerScopedRegisterCapability');
 assert.equal(capGuard.length,1,'stdio requires issued capability');
 assert.deepEqual(calls(capGuard[0].test,'cap.isOwnerScopedRegisterCapability')[0].arguments.map(name),['capability']);
 assert.equal(visit(capGuard[0].consequent,n=>n.type==='AssignmentExpression'&&name(n.left)==='discoveryError'
  &&n.right?.value==='Owner-scoped stdio executor required').length,1,'unissued stdio is denied');
 assert.equal(calls(capGuard[0].alternate,'capability.execute').length,1,'only authorized stdio executes');
 const permitted=calls(capGuard[0].alternate,'capability.execute')[0];
 assert.equal(capGuard[0].alternate?.type,'BlockStatement');
 assert.equal(capGuard[0].alternate.body[0]?.type,'ReturnStatement');
 assert.equal(capGuard[0].alternate.body[0].argument,permitted);
 const command=permitted.arguments[0];assert.equal(command?.type,'ObjectExpression');
 for(const key of ['name','url','stdio_cmd'])assert.equal(name(property(command,key)?.value),key,`stdio ${key} selected`);
 assert.equal(name(property(command,'transport')?.value),'t','stdio selected transport');
 assert.equal(calls(stdio[0].consequent,'pg').length,0,'stdio branch does not directly write legacy registry');
 const errorReturn=visit(register,n=>n.type==='IfStatement'&&n.test?.name==='discoveryError'
  &&visit(n.consequent,x=>x.type==='ReturnStatement').length===1);
 assert.equal(errorReturn.length,1,'failed discovery returns before registry write');
 const registryWrite=visit(register,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
  &&n.callee.property?.name==='registerServer'&&name(n.callee.object?.callee)==='pg');
 assert.equal(registryWrite.length,1);
 assert.ok(capGuard[0].start<errorReturn[0].start&&errorReturn[0].start<registryWrite[0].start,
  'failed stdio returns before registry effect');
}
function listingInventory(overrides={},data=manifest){
 const roles=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 assert.ok(literalArray(property(roles,'merchant').value).includes('listing'));
 assert.ok(literalArray(property(roles,'merchant').value).includes('inventory'));
 for(const agent of ['customer','admin'])for(const tool of ['listing','inventory'])
  assert.ok(!literalArray(property(roles,agent).value).includes(tool),`${agent} catalog does not advertise ${tool}`);
 for(const [id,agent,handler,postgres,effects,consequence,applicability] of listingInventoryReview){
  const row=data.reviewedListingInventory.find(item=>item.id===id);assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','serverFile','wrapperFile','handlerFile','inputSchema','advertisedRoles','hostGateRoles','effectCalls','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  const serverFile=`agent-host/agents/${agent}/server.js`,wrapperFile=`agent-host/agents/${agent}/tools/${agent==='listing'?handler:'index'}.js`;
  const handlerFile=`agent-host/agents/${agent}/tools/${postgres}`;
  assert.deepEqual([row.handler,row.serverFile,row.wrapperFile,row.handlerFile,row.inputSchema,row.advertisedRoles,row.hostGateRoles,row.effectCalls,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [handler,serverFile,wrapperFile,handlerFile,listingInventorySchemas[id],['merchant'],handler==='stock_levels'?[]:['merchant','admin'],effects,consequence,applicability,[],[],null],`${id} exact source-only metadata`);
  const wrapper=tree(wrapperFile,overrides);
  const exports=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(exports.length,1,`${id} wrapper export`);
  assert.equal(name(exports[0].right?.callee),'require');
  assert.equal(exports[0].right.arguments[0]?.value,`./${postgres}`,`${id} wrapper reaches executable handler`);
  const server=tree(serverFile,overrides),descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===handler);
  assert.ok(descriptor,`${id} catalog row`);
  assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema,`${id} advertised schema`);
  const imports=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===handler)&&n.init?.callee?.name==='require');
  assert.equal(imports.length,1,`${id} imported executable wrapper`);
  assert.equal(imports[0].init.arguments[0]?.value,`./tools/${agent==='listing'?handler:'index'}.js`);
  const create=fn(server,'createServer');
  const callHandler=calls(create,'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema')?.arguments[1];
  assert.ok(callHandler,`${id} MCP call handler`);
  const gate=calls(callHandler,'enforceRole');
  if(agent==='listing'){
   assert.equal(gate.length,1);assert.deepEqual(gate[0].arguments.map((a,i)=>i===0?name(a):literalArray(a)),['caller',['merchant','admin']]);
   const denial=visit(callHandler,n=>n.type==='IfStatement'&&n.test?.name==='denied'&&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');
   assert.equal(denial.length,1);
   const sw=visit(callHandler,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(sw.length,1);
   assert.ok(gate[0].start<denial[0].start&&denial[0].start<sw[0].start,'listing role denial before effect dispatch');
  }else{
   assert.equal(gate.length,1);assert.deepEqual(gate[0].arguments.map((a,i)=>i===0?name(a):literalArray(a)),['caller',['merchant','admin']]);
   const gated=visit(callHandler,n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'&&n.test.operator==='||'
    &&[n.test.left,n.test.right].every(p=>p.type==='BinaryExpression'&&p.operator==='==='&&p.left?.name==='name')
    &&[n.test.left.right.value,n.test.right.right.value].join(',')==='set_stock,reorder_suggestion');
   assert.equal(gated.length,1,'inventory gate applies only to two named tools');
   assert.equal(calls(gated[0].consequent,'enforceRole').length,1,'gate is inside conditional branch');
   assert.equal(visit(gated[0].consequent,n=>n.type==='IfStatement'&&n.test?.name==='denied'
    &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied').length,1,'gated denial returns');
   const sw=visit(callHandler,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(sw.length,1);
   assert.ok(gated[0].end<sw[0].start,'role gate before inventory dispatch');
  }
  const sw=visit(callHandler,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name')[0];
  const item=sw.cases.find(c=>c.test?.value===handler);assert.ok(item,`${id} dispatch case`);
  const forwarded=calls(item,handler);assert.equal(forwarded.length,1,`${id} selects matching handler`);
  assert.equal(visit(item,n=>n.type==='AwaitExpression'&&n.argument===forwarded[0]).length,1,`${id} awaits selected handler`);
  const supplied=forwarded[0].arguments[0];assert.equal(supplied?.type,'LogicalExpression');assert.equal(supplied.operator,'||');
  assert.equal(supplied.left?.name,'args');assert.equal(supplied.right?.type,'ObjectExpression');assert.equal(supplied.right.properties.length,0);
  if(agent==='inventory')assert.equal(forwarded[0].arguments[1]?.name,'ctx','inventory caller context forwarded');
  else assert.equal(forwarded[0].arguments.length,1);
  const action=fn(tree(handlerFile,overrides),handler);
  for(const effect of effects)assert.equal(calls(action,effect).length,1,`${id} exact executable effect ${effect}`);
  if(id==='listing.create'){
   const rewrite=calls(action,'rewriteDescription');assert.equal(rewrite.length,1);
   assert.equal(rewrite[0].arguments[0]?.type,'ObjectExpression');
   assert.deepEqual(['title','description'].map(key=>name(property(rewrite[0].arguments[0],key)?.value)),['title','description']);
   assert.equal(declaration(action,'html').init?.type,'AwaitExpression');
   assert.equal(declaration(action,'html').init.argument,rewrite[0],'stored HTML comes from selected rewrite');
   const create=calls(action,'commerce.listing_create_1')[0];assert.equal(create.arguments.length,7);
   assert.equal(name(create.arguments[2]?.callee),'String');
   assert.equal(create.arguments[2].arguments[0]?.type,'LogicalExpression');
   assert.equal(create.arguments[2].arguments[0].operator,'||');
   assert.equal(create.arguments[2].arguments[0].left?.name,'html');
   assert.equal(create.arguments[6]?.name,'retailer_id','caller-selected retailer reaches insert');
  }
  if(id==='listing.update')assert.deepEqual(calls(action,'commerce.updateProduct')[0].arguments.map(name),['product_id','selected']);
  if(id==='listing.import_bulk'){
   for(const [url,method] of [['json_url','commerce.listing_import_bulk_1'],['xml_url','commerce.listing_import_bulk_2']]){
    const branch=visit(action,n=>n.type==='IfStatement'&&n.test?.name===url);assert.equal(branch.length,1);
    const fetch=calls(branch[0].consequent,'_fetch');assert.equal(fetch.length,1);assert.equal(fetch[0].arguments[0]?.name,url);
    assert.equal(calls(branch[0].consequent,method).length,1,`${url} routes to its own insert`);
    assert.equal(calls(branch[0].consequent,url==='json_url'?'_mergeUnsafe':'_parseXxeSusceptibleXml').length,1,`${url} parser branch`);
    const insert=calls(branch[0].consequent,method)[0];
    assert.equal(name(insert.arguments[0]?.callee),'String');assert.equal(name(insert.arguments[0].arguments[0]),'it.name');
    assert.equal(name(insert.arguments[1]?.callee),'String');
    assert.equal(name(insert.arguments[1].arguments[0]?.left),'it.description');
    assert.equal(insert.arguments[2]?.type,'LogicalExpression');
    assert.equal(name(insert.arguments[2].left?.callee),'Number');
    assert.equal(name(insert.arguments[2].left.arguments[0]),'it.price',`${url} selected item reaches insert`);
    if(url==='json_url'){
     const parsed=calls(branch[0].consequent,'JSON.parse');assert.equal(parsed.length,1);
     assert.equal(parsed[0].arguments[0]?.name,'raw');
     assert.equal(declaration(branch[0].consequent,'raw').init?.argument,fetch[0]);
    }else{
     const parsed=calls(branch[0].consequent,'_parseXxeSusceptibleXml');assert.equal(parsed[0].arguments[0]?.name,'rawXml');
     assert.equal(declaration(branch[0].consequent,'rawXml').init?.argument,fetch[0]);
    }
   }
  }
  if(id==='listing.optimize_images'){
   const select=calls(action,'commerce.listing_optimize_images_1')[0];assert.equal(select.arguments[0]?.name,'product_id');
   const filename=declaration(action,'filename').init;
   assert.equal(filename?.type,'LogicalExpression');assert.equal(filename.operator,'||');
   assert.equal(name(filename.left),'row.image_url');
   const command=declaration(action,'cmd').init;assert.equal(command?.type,'TemplateLiteral');
   assert.deepEqual(command.expressions.map(name),['filename','filename'],'selected image reaches both shell positions');
   assert.deepEqual(command.quasis.map(q=>q.value.cooked),['convert ',' -strip -quality 82 ','.opt.jpg']);
   const guard=visit(action,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'&&n.test.operator==='!=='
    &&name(n.test.left)==='process.env.SS_LISTING_ALLOW_EXEC'&&n.test.right?.value==='true');assert.equal(guard.length,1);
   assert.equal(calls(guard[0].consequent,'exec').length,0,'guarded branch never shells');
   assert.equal(guard[0].consequent?.type,'BlockStatement');
   assert.equal(guard[0].consequent.body.length,1,'guard has one unconditional exit');
   assert.equal(guard[0].consequent.body[0]?.type,'ReturnStatement','guard returns before shell');
   assert.equal(name(guard[0].consequent.body[0].argument?.callee),'resolve');
   assert.equal(property(calls(guard[0].consequent,'resolve')[0].arguments[0],'executed')?.value?.value,false);
   const shell=calls(action,'exec')[0];assert.ok(guard[0].end<shell.start,'shell only after guard');
   assert.equal(shell.arguments[0]?.name,'cmd');
   assert.equal(property(calls(shell.arguments[2],'resolve')[0].arguments[0],'executed')?.value?.value,true);
  }
  if(id==='inventory.stock_levels')assert.equal(calls(action,'commerce.inventory_stock_levels_1')[0].arguments.length,0);
  if(id==='inventory.reorder_suggestion')assert.equal(calls(action,'commerce.inventory_reorder_suggestion_2')[0].arguments[0]?.name,'product_id');
  if(id==='inventory.set_stock'){
   const write=calls(action,'commerce.inventory_set_stock_3')[0];assert.equal(name(write.arguments[0]?.callee),'Number');
   assert.equal(write.arguments[0].arguments[0]?.name,'qty');assert.equal(write.arguments[1]?.name,'product_id');
  }
 }
}
function emailAudit(overrides={},data=manifest){
 const roles=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin'])assert.ok(literalArray(property(roles,role).value).includes('email'));
 for(const role of ['customer','merchant'])assert.ok(!literalArray(property(roles,role).value).includes('audit'));
 assert.ok(literalArray(property(roles,'admin').value).includes('audit'));
 const emailHandler='agent-host/agents/email/tools/index.postgres.js',auditHandler='agent-host/agents/audit/tools/index.js';
 for(const [id,agent,handler,effects,consequence,applicability] of emailAuditReview){
  const row=data.reviewedEmailAudit.find(item=>item.id===id);assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','serverFile','wrapperFile','handlerFile','inputSchema','advertisedRoles','hostGateRoles','effectCalls','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  const serverFile=`agent-host/agents/${agent}/server.js`,wrapperFile=agent==='email'?'agent-host/agents/email/tools/index.js':null;
  const handlerFile=agent==='email'?emailHandler:auditHandler,advertised=agent==='email'?['customer','merchant','admin']:['admin'];
  const gated=agent==='audit'?['admin']:handler==='send'?['merchant','admin']:['customer','merchant','admin'];
  assert.deepEqual([row.handler,row.serverFile,row.wrapperFile,row.handlerFile,row.inputSchema,row.advertisedRoles,row.hostGateRoles,row.effectCalls,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [handler,serverFile,wrapperFile,handlerFile,emailAuditSchemas[id],advertised,gated,effects,consequence,applicability,[],[],null],`${id} source-only metadata`);
  if(wrapperFile){const wrapper=tree(wrapperFile,overrides);
   const exported=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');assert.equal(exported.length,1);
   assert.equal(name(exported[0].right?.callee),'require');assert.equal(exported[0].right.arguments[0]?.value,'./index.postgres.js');}
  const server=tree(serverFile,overrides),descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===handler);
  assert.ok(descriptor,`${id} declared`);
  assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema,`${id} advertised schema`);
  const imported=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===handler)&&name(n.init?.callee)==='require');assert.equal(imported.length,1);
  assert.equal(imported[0].init.arguments[0]?.value,'./tools/index.js');
  const create=fn(server,'createServer');
  const entry=calls(create,'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema')?.arguments[1];assert.ok(entry);
  const sw=visit(entry,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(sw.length,1);
  if(agent==='audit'){
   const gate=calls(entry,'enforceRole');assert.equal(gate.length,1);assert.equal(gate[0].arguments[0]?.name,'caller');
   assert.deepEqual(literalArray(gate[0].arguments[1]),['admin']);
   const denial=visit(entry,n=>n.type==='IfStatement'&&n.test?.name==='denied'
    &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');assert.equal(denial.length,1);
   assert.ok(gate[0].start<denial[0].start&&denial[0].start<sw[0].start,'audit gate denies before effect');
  }else{
   const gates=visit(entry,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
    &&n.test.operator==='==='&&n.test.left?.name==='name'&&n.test.right?.value==='send');
   assert.equal(gates.length,1,'send has separate gate');
   const sendGate=calls(gates[0].consequent,'enforceRole');assert.equal(sendGate.length,1);
   assert.deepEqual(literalArray(sendGate[0].arguments[1]),['merchant','admin']);
   const rest=visit(entry,n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'&&n.test.operator==='||'
    &&['read_inbox','summarize_thread','auto_reply'].every(tool=>visit(n.test,x=>x.type==='BinaryExpression'
     &&x.operator==='==='&&x.left?.name==='name'&&x.right?.value===tool).length===1));
   assert.equal(rest.length,1,'other three have all-role gate');
   assert.deepEqual(literalArray(calls(rest[0].consequent,'enforceRole')[0].arguments[1]),['customer','merchant','admin']);
   for(const branch of [gates[0],rest[0]]){
    assert.equal(visit(branch.consequent,n=>n.type==='IfStatement'&&n.test?.name==='denied'
     &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied').length,1);
    assert.ok(branch.end<sw[0].start,'email gate before dispatch');
   }
  }
  const caseNode=sw[0].cases.find(c=>c.test?.value===handler);assert.ok(caseNode);
  const forwarded=calls(caseNode,handler);assert.equal(forwarded.length,1);assert.equal(forwarded[0].arguments.length,1);
  assert.equal(visit(caseNode,n=>n.type==='AwaitExpression'&&n.argument===forwarded[0]).length,1);
  assert.equal(forwarded[0].arguments[0]?.type,'LogicalExpression');assert.equal(forwarded[0].arguments[0].operator,'||');
  assert.equal(forwarded[0].arguments[0].left?.name,'args');assert.equal(forwarded[0].arguments[0].right?.type,'ObjectExpression');
  assert.equal(forwarded[0].arguments[0].right.properties.length,0);
  const action=fn(tree(handlerFile,overrides),handler);
  for(const effect of effects){
   if(effect.startsWith('pg().')){const method=effect.slice(5);
    assert.equal(visit(action,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
     &&n.callee.property?.name===method&&name(n.callee.object?.callee)==='pg').length,1,`${id} ${effect}`);}
   else if(effect==='formatSummary'){
    const then=visit(action,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
     &&n.callee.property?.name==='then'&&n.arguments[0]?.name==='formatSummary');
    assert.equal(then.length,1,`${id} selected rows reach formatter`);
    assert.equal(name(then[0].callee.object?.callee),'readAfterAuditDelivery');
   }else assert.equal(calls(action,effect).length,1,`${id} ${effect}`);
  }
  if(id==='email.send'){
   const saved=calls(action,'commerce.sendEmail')[0],payload=saved.arguments[0];assert.equal(payload?.type,'ObjectExpression');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===saved).length,1,'stored mail effect is awaited');
   const initialThread=declaration(action,'tid').init;assert.equal(initialThread?.type,'LogicalExpression');
   assert.equal(name(initialThread.left?.callee),'Number');assert.equal(initialThread.left.arguments[0]?.name,'thread_id');
   assert.equal(initialThread.right?.type,'NullLiteral');
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='tid'
    &&name(n.right)==='saved.threadId').length,1,'saved thread ID returned');
   for(const [key,selected] of [['threadId','tid'],['bodyHtml','body_html'],['headersRaw','headers_raw']])
    assert.equal(name(property(payload,key)?.value),selected,`stored ${key}`);
   for(const [key,selected] of [['to','to'],['from','from'],['subject','subject'],['bodyMarkdown','body_markdown']]){
    const value=property(payload,key)?.value;assert.equal(name(value?.callee),'String');
    assert.equal(name(value.arguments[0]?.left??value.arguments[0]),selected,`selected ${key}`);
   }
   const html=calls(action,'_unsafeMarkdownToHtml');assert.equal(html.length,1,'selected body becomes HTML');
   assert.equal(name(html[0].arguments[0]?.callee),'String');
   assert.equal(html[0].arguments[0].arguments[0]?.left?.name,'body_markdown');
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='body_html'&&n.right===html[0]).length,1);
   const headers=declaration(action,'headers_raw').init;assert.equal(headers?.callee?.property?.name,'join');
   assert.equal(headers.arguments[0]?.value,'\r\n');
   assert.equal(visit(headers,n=>n.type==='SpreadElement'&&n.argument?.name==='extraHeaderLines').length,1);
   const entries=calls(action,'Object.entries');assert.equal(entries.length,1);
   assert.equal(entries[0].arguments[0]?.left?.name,'headers','selected extra headers are retained');
   assert.equal(visit(headers,n=>n.type==='TemplateLiteral'&&n.quasis[0]?.value.cooked==='To: '
    &&n.expressions[0]?.name==='to').length,1,'selected recipient reaches raw header');
   const info=declaration(action,'info').init;assert.equal(name(property(info,'lastInsertRowid')?.value),'saved.emailId');
   const output=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression').at(-1).argument;
   const emailId=property(output,'email_id')?.value;assert.equal(name(emailId?.callee),'Number');
   assert.equal(name(emailId.arguments[0]),'info.lastInsertRowid');
   assert.equal(name(property(output,'thread_id')?.value),'tid');
  }
  if(id==='email.read_inbox'){
   const selected=calls(action,'commerce.email_read_inbox_3')[0];assert.equal(selected.arguments[0]?.type,'LogicalExpression');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===selected).length,1);
   assert.equal(name(selected.arguments[0].left?.callee),'Number');
   assert.equal(selected.arguments[0].left.arguments[0]?.name,'user_id');
   const rows=calls(action,'commerce.email_read_inbox_4')[0];assert.equal(name(rows.arguments[0]),'user.email');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===rows).length,1);
   assert.equal(rows.arguments[1]?.type,'TemplateLiteral');assert.equal(name(rows.arguments[1].expressions[0]),'user.email');
   const result=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&property(n.argument,'emails'))[0]?.argument;assert.ok(result);
   assert.equal(name(property(result,'emails')?.value),'rows');
   assert.equal(name(property(result,'count')?.value),'rows.length');
  }
  if(id==='email.summarize_thread'){
   const read=calls(action,'commerce.email_summarize_thread_5')[0];assert.equal(read.arguments[0]?.type,'LogicalExpression');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===read).length,1);
   assert.equal(name(read.arguments[0].left?.callee),'Number');
   assert.equal(read.arguments[0].left.arguments[0]?.name,'thread_id');
   const fetch=calls(action,'_fetchInlinePreview')[0];assert.equal(fetch.arguments[0]?.name,'url');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===fetch).length,1);
   assert.equal(declaration(action,'url').init?.type,'MemberExpression');
   assert.equal(name(declaration(action,'url').init.object),'m');
   assert.equal(declaration(action,'url').init.property?.value,1);
   assert.equal(visit(action,n=>n.type==='ForOfStatement'&&visit(n,n2=>n2===fetch).length===1).length,1,'inline fetch is conditional on image loop');
   const source=declaration(action,'src').init;assert.equal(name(source?.callee),'String');
   assert.equal(name(source.arguments[0]?.left),'e.body_html');
   const match=calls(action,'imgRe.exec');assert.equal(match.length,1);assert.equal(match[0].arguments[0]?.name,'src');
   const matched=visit(action,n=>n.type==='WhileStatement'&&n.test?.type==='BinaryExpression'
    &&n.test.operator==='!=='&&n.test.right?.type==='NullLiteral'
    &&n.test.left?.type==='AssignmentExpression'&&n.test.left.left?.name==='m'
    &&n.test.left.right===match[0]&&visit(n.body,x=>x===fetch).length===1);
   assert.equal(matched.length,1,'inline fetch only inside actual image-match loop');
   const bodies=declaration(action,'bodies').init;assert.equal(bodies?.callee?.property?.name,'join');
   assert.equal(name(bodies.callee.object?.callee),'emails.map');
   const prompt=declaration(action,'prompt_context').init;assert.equal(prompt?.type,'TemplateLiteral');
   assert.deepEqual(prompt.expressions.map(name),['bodies'],'selected message body reaches prompt');
   const result=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'prompt_context')?.value)==='prompt_context'
    &&name(property(n.argument,'inline_fetches')?.value)==='inlineFetches');assert.equal(result.length,1);
  }
  if(id==='email.auto_reply'){
   const summarize=calls(action,'summarize_thread')[0];assert.equal(name(property(summarize.arguments[0],'thread_id')?.value),'thread_id');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===summarize).length,1);
   const latest=calls(action,'commerce.email_auto_reply_6')[0].arguments[0];
   assert.equal(latest?.type,'LogicalExpression');assert.equal(name(latest.left?.callee),'Number');
   assert.equal(latest.left.arguments[0]?.name,'thread_id');
   const sent=calls(action,'send')[0],payload=sent.arguments[0];assert.equal(name(property(payload,'to')?.value),'replyTo');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===sent).length,1,'transitive send awaited');
   assert.equal(name(property(payload,'thread_id')?.value),'thread_id');
   assert.equal(name(property(payload,'body_markdown')?.value),'replyBody');
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'sent_email_id')?.value)==='sent.email_id').length,1,'transitive saved ID returned');
   assert.equal(calls(action,'String').some(c=>name(c.arguments[0]?.left)==='summary.prompt_context'),true,'deterministic summary text influences target');
   const selectedMatch=declaration(action,'m').init;assert.equal(selectedMatch?.callee?.property?.name,'match');
   assert.equal(selectedMatch.arguments[0]?.name,'forwardRe');
   assert.equal(name(selectedMatch.callee.object?.callee),'String');
   assert.equal(name(selectedMatch.callee.object.arguments[0]?.left),'summary.prompt_context');
   assert.equal(name(declaration(action,'replyTo').init),'latest.from_addr');
   // Babel represents the numeric capture as computed member m[1].
   assert.equal(visit(action,n=>n.type==='IfStatement'&&n.test?.name==='m'
    &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&x.left?.name==='replyTo'
     &&x.right?.type==='MemberExpression'&&x.right.object?.name==='m'&&x.right.property?.value===1).length===1).length,1);
  }
  if(id==='audit.recent_events'||id==='audit.summarize_anomalies'){
   const method=id==='audit.recent_events'?'recentAudit':'summaryAudit';
   const effect=visit(action,n=>n.type==='CallExpression'&&n.callee?.property?.name===method
    &&name(n.callee.object?.callee)==='pg')[0];
   assert.equal(effect.arguments[0]?.type,'LogicalExpression');assert.equal(name(effect.arguments[0].left?.callee),'Number');
   assert.equal(effect.arguments[0].left.arguments[0]?.name,'limit');
   assert.equal(effect.arguments[0].right?.value,method==='recentAudit'?50:200);
   assert.equal(calls(action,'readAfterAuditDelivery').length,1,'audit read enters optional flush helper');
   if(id==='audit.recent_events'){
    const readback=visit(action,n=>n.type==='ObjectExpression'&&name(property(n,'events')?.value)==='events'
     &&name(property(n,'count')?.value)==='events.length');assert.equal(readback.length,1,'selected audit rows returned');
   }
  }
  if(id==='audit.search_by_user'){
   const sql=declaration(action,'sql').init;assert.equal(sql?.type,'TemplateLiteral');
   assert.deepEqual(sql.expressions.map(name),['u','u'],'selected username enters both raw predicates');
   const selected=declaration(action,'u').init;assert.equal(name(selected?.callee),'String');
   assert.equal(visit(selected,n=>n.type==='Identifier'&&n.name==='username').length,2);
   const query=visit(action,n=>n.type==='CallExpression'&&n.callee?.property?.name==='queryAuditTeaching'
    &&name(n.callee.object?.callee)==='pg')[0];assert.equal(query.arguments[0]?.name,'sql');
   const readback=visit(action,n=>n.type==='ObjectExpression'&&name(property(n,'events')?.value)==='events'
    &&name(property(n,'sql')?.value)==='sql');assert.equal(readback.length,1,'selected SQL rows returned');
  }
 }
 const audit=tree(auditHandler,overrides),after=fn(audit,'readAfterAuditDelivery');
 const configured=visit(after,n=>n.type==='IfStatement'&&name(n.test)==='process.env.SECURESHOP_DATABASE_URL');assert.equal(configured.length,1);
 const flushed=calls(configured[0].consequent,'commerce.flushAuditOutbox');assert.equal(flushed.length,1);
 assert.equal(visit(configured[0].consequent,n=>n.type==='AwaitExpression'&&n.argument===flushed[0]).length,1,'pending outbox flush awaited');
 const append=calls(flushed[0].arguments[0],'pg');assert.equal(append.length,1,'flush callback selects audit repository');
 assert.equal(visit(flushed[0].arguments[0],n=>n.type==='CallExpression'&&n.callee?.property?.name==='appendAudit'
  &&name(n.callee.object?.callee)==='pg'&&n.arguments[0]?.name==='event').length,1);
 assert.ok(configured[0].end<calls(after,'read')[0].start,'pending audit delivery before selected read');
 const teaching=tree('server/database/postgres/secureshopAgentsDb.js',overrides);
 const query=visit(teaching,n=>n.type==='ObjectProperty'&&n.key?.name==='queryAuditTeaching');assert.equal(query.length,1);
 const readOnly=calls(query[0],'c.query').filter(c=>c.arguments[0]?.value==='SET TRANSACTION READ ONLY');assert.equal(readOnly.length,1);
 assert.equal(visit(query[0],n=>n.type==='AwaitExpression'&&n.argument===readOnly[0]).length,1,'read-only mode awaited before selected SQL');
 assert.ok(readOnly[0].start<calls(query[0],'c.query').at(-1).start);
 const raw=fn(audit,'search_by_user');assert.equal(calls(raw,'readAfterAuditDelivery').length,1);
 const summary=fn(audit,'formatSummary');assert.equal(visit(summary,n=>n.type==='TemplateLiteral'
  &&n.expressions.some(e=>visit(e,x=>name(x)==='r.params_json').length>0)
  &&n.expressions.some(e=>visit(e,x=>name(x)==='r.target').length>0)).length,1);
 const lines=declaration(summary,'lines').init;assert.equal(name(lines?.callee),'rows.map');
 const prompt=declaration(summary,'prompt').init;assert.equal(prompt?.callee?.property?.name,'join');
 assert.equal(visit(prompt,n=>n.type==='CallExpression'&&name(n.callee)==='lines.join').length,1,
  'selected audit line text reaches prompt');
 const returned=visit(summary,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression');
 assert.equal(returned.length,1,'summary has one result');
 assert.equal(name(property(returned[0].argument,'prompt')?.value),'prompt');
 assert.equal(name(property(returned[0].argument,'events')?.value),'rows');
 assert.equal(name(property(returned[0].argument,'log_text')?.value?.callee),'lines.join');
}
function cartSupport(overrides={},data=manifest){
 const roles=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const agent of ['cart','support']){
  assert.ok(literalArray(property(roles,'customer').value).includes(agent));
  for(const role of ['merchant','admin'])assert.ok(!literalArray(property(roles,role).value).includes(agent));
 }
 const caller=tree('agent-host/shared/callerContext.js',overrides),enforce=fn(caller,'enforceRole');
 const extractor=fn(caller,'extractCaller');
 const stripped=visit(extractor,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.init?.name==='args'&&n.id.properties.length===2
  &&n.id.properties[0].key?.name==='_ss_caller'
  &&n.id.properties[1].type==='RestElement'&&n.id.properties[1].argument?.name==='rest');
 assert.equal(stripped.length,1,'only reserved caller field stripped from selected arguments');
 assert.equal(visit(extractor,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
  &&name(property(n.argument,'args')?.value)==='rest'
  &&name(property(n.argument,'caller')?.value)==='caller').length,1);
 assert.equal(visit(declaration(extractor,'caller').init,n=>name(n)==='_ss_caller.id').length>0,true);
 const disabled=visit(enforce,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.left?.name==='env'&&n.test.right?.value==='false'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.type==='NullLiteral');
 assert.equal(disabled.length,1,'caller-role enforcement can be disabled by configuration');
 const env=declaration(enforce,'env').init;
 assert.equal(visit(env,n=>name(n)==='process.env.SS_ENFORCE_CALLER_ROLE').length,1);
 const anonymous=visit(enforce,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.right?.value==='true'
  &&visit(n.test,x=>name(x)==='process.env.SS_ALLOW_ANON_CALLER').length===1
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.type==='NullLiteral');
 assert.equal(anonymous.length,1,'anonymous caller override remains separate');
 const commerce=tree('server/database/postgres/secureshopCommerceDb.js',overrides);
 const teaching=visit(commerce,n=>n.type==='ObjectMethod'&&n.key?.name==='readTeachingQuery');assert.equal(teaching.length,1);
 const transaction=calls(teaching[0],'withTransaction');assert.equal(transaction.length,1);
 assert.equal(visit(teaching[0],n=>n.type==='ReturnStatement'&&n.argument===transaction[0]).length,1,
  'teaching query returns its selected read-only transaction');
 const callback=transaction[0].arguments[1];assert.equal(callback?.type,'ArrowFunctionExpression');
 assert.equal(callback.params[0]?.name,'client');
 const readOnly=calls(callback,'client.query').filter(c=>c.arguments[0]?.value==='SET TRANSACTION READ ONLY');
 assert.equal(readOnly.length,1);assert.equal(visit(callback,n=>n.type==='AwaitExpression'&&n.argument===readOnly[0]).length,1);
 const selectedQuery=calls(callback,'client.query').filter(c=>c.arguments[0]?.type==='ObjectExpression'
  &&name(property(c.arguments[0],'text')?.value)==='sql');
 assert.equal(selectedQuery.length,1);assert.ok(readOnly[0].end<selectedQuery[0].start,'read-only transaction precedes selected SQL');
 assert.equal(name(property(selectedQuery[0].arguments[0],'queryMode')?.value),null);
 assert.equal(property(selectedQuery[0].arguments[0],'queryMode')?.value?.value,'extended');
 assert.deepEqual(staticValue(property(selectedQuery[0].arguments[0],'values')?.value),[]);
 const selectedResult=declaration(callback,'result').init;
 assert.equal(name(selectedResult?.callee),'rows');assert.equal(selectedResult.arguments[0]?.type,'AwaitExpression');
 assert.equal(selectedResult.arguments[0].argument,selectedQuery[0]);
 assert.equal(visit(callback,n=>n.type==='ReturnStatement'&&n.argument?.type==='ConditionalExpression'
  &&n.argument.test?.operator==='==='&&n.argument.test.left?.name==='kind'&&n.argument.test.right?.value==='get'
  &&name(n.argument.consequent?.object)==='result'
  &&n.argument.consequent?.property?.value===0
  &&name(n.argument.alternate)==='result').length,1);
 const run=declaration(commerce,'run').init,all=declaration(commerce,'all').init;
 assert.deepEqual(calls(run,'pool.query')[0]?.arguments.map(name),['sql','params']);
 assert.equal(declaration(run,'result').init?.argument,calls(run,'pool.query')[0]);
 const runObjects=visit(run,n=>n.type==='ObjectExpression'
  &&name(property(n,'changes')?.value)==='result.rowCount'
  &&name(property(n,'lastInsertRowid')?.value?.object?.object)==='result.rows');
 assert.equal(runObjects.length,1,'saved ID and row count come from selected query result');
 assert.equal(visit(run,n=>n.type==='ReturnStatement'&&n.argument===runObjects[0]).length,1,
  'run returns the selected query receipt');
 assert.equal(calls(all,'rows').length,1);assert.equal(calls(all,'rows')[0].arguments[0]?.type,'AwaitExpression');
 assert.equal(calls(all,'pool.query').length,1);
 assert.equal(calls(all,'rows')[0].arguments[0].argument,calls(all,'pool.query')[0]);
 assert.equal(all.body,calls(all,'rows')[0],'all returns rows from selected query');
 assert.deepEqual(calls(all,'pool.query')[0].arguments.map(name),['sql','params']);
 for(const [id,agent,tool,handler,effects,consequence,applicability] of cartSupportReview){
  const row=data.reviewedCartSupport.find(r=>r.id===id);assert.ok(row);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','serverFile','wrapperFile','handlerFile','inputSchema','advertisedRoles','hostGateRolesDefault','effectCalls','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  const serverFile=`agent-host/agents/${agent}/server.js`,wrapperFile=`agent-host/agents/${agent}/tools/index.js`;
  const handlerFile=`agent-host/agents/${agent}/tools/index.postgres.js`;
  assert.deepEqual([row.handler,row.serverFile,row.wrapperFile,row.handlerFile,row.inputSchema,row.advertisedRoles,row.hostGateRolesDefault,row.effectCalls,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [handler,serverFile,wrapperFile,handlerFile,cartSupportSchemas[id],['customer'],agent==='cart'&&tool!=='add'?['customer','merchant','admin']:[],effects,consequence,applicability,[],[],null],`${id} exact source-only row`);
  const wrapper=tree(wrapperFile,overrides),exported=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(exported.length,1);assert.equal(name(exported[0].right?.callee),'require');
  assert.equal(exported[0].right.arguments[0]?.value,'./index.postgres.js');
  const server=tree(serverFile,overrides),descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===tool);
  assert.ok(descriptor);assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema);
  const imported=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===handler)&&name(n.init?.callee)==='require');assert.equal(imported.length,1);
  assert.equal(imported[0].init.arguments[0]?.value,'./tools/index.js');
  const callerImport=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name==='extractCaller')&&name(n.init?.callee)==='require');
  assert.equal(callerImport.length,1);assert.equal(callerImport[0].init.arguments[0]?.value,'../../shared/callerContext.js');
  const create=fn(server,'createServer');
  const dispatch=calls(create,'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema')?.arguments[1];assert.ok(dispatch);
  const requestArgs=visit(dispatch,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name==='arguments'&&p.value?.name==='rawArgs')&&n.init?.type==='LogicalExpression'
   &&n.init.operator==='||'&&name(n.init.left)==='req.params'&&n.init.right?.type==='ObjectExpression');
  assert.equal(requestArgs.length,1,'rawArgs originate from selected request params');
  const extracted=visit(dispatch,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name==='caller')&&n.id.properties.some(p=>p.key?.name==='args')
   &&name(n.init?.callee)==='extractCaller'&&n.init.arguments.length===1&&n.init.arguments[0]?.name==='rawArgs');
  assert.equal(extracted.length,1,'selected rawArgs pass through shared caller extraction');
  const switches=visit(dispatch,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(switches.length,1);
  if(agent==='cart'){
   const role=calls(dispatch,'enforceRole');assert.equal(role.length,1,'one selective cart role call');
   assert.equal(role[0].arguments[0]?.name,'caller');assert.deepEqual(literalArray(role[0].arguments[1]),['customer','merchant','admin']);
   const restricted=visit(dispatch,n=>n.type==='IfStatement'&&n.test?.type==='CallExpression'
    &&n.test.callee?.property?.name==='includes'&&n.test.arguments[0]?.name==='name'
    &&n.test.callee.object?.type==='ArrayExpression'
    &&literalArray(n.test.callee.object).join(',')==='remove,view,apply_coupon');assert.equal(restricted.length,1);
   assert.equal(visit(restricted[0].consequent,n=>n===role[0]).length,1);
   assert.equal(visit(restricted[0].consequent,n=>n.type==='IfStatement'&&n.test?.name==='denied'
    &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied').length,1);
   assert.ok(restricted[0].end<switches[0].start);
  }else assert.equal(calls(dispatch,'enforceRole').length,0,'support has no local Layer-C role call');
  const ctx=declaration(dispatch,'ctx').init,userId=property(ctx,'userId')?.value;
  assert.equal(userId?.type,'LogicalExpression');assert.equal(userId.operator,'||');
  assert.equal(userId.right?.value,0);assert.equal(name(userId.left?.right),'caller.id');
  const override=userId.left?.left;assert.equal(override?.type,'LogicalExpression');assert.equal(override.operator,'&&');
  assert.equal(override.left?.name,'args');assert.equal(override.right?.type,'LogicalExpression');
  assert.equal(override.right.operator,'||');assert.deepEqual([name(override.right.left),name(override.right.right)],['args.__userId','args._userId']);
  const caseNode=switches[0].cases.find(c=>c.test?.value===tool);assert.ok(caseNode);
  const forward=calls(caseNode,handler);assert.equal(forward.length,1);assert.equal(forward[0].arguments.length,2);
  assert.equal(visit(caseNode,n=>n.type==='AwaitExpression'&&n.argument===forward[0]).length,1);
  assert.equal(caseNode.consequent.length,1);assert.equal(caseNode.consequent[0].type,'ReturnStatement');
  assert.equal(name(caseNode.consequent[0].argument?.callee),'_wrap');
  assert.equal(caseNode.consequent[0].argument.arguments.length,1);
  assert.equal(caseNode.consequent[0].argument.arguments[0]?.type,'AwaitExpression');
  assert.equal(caseNode.consequent[0].argument.arguments[0].argument,forward[0],`${id} returns wrapped selected result`);
  assert.equal(forward[0].arguments[0]?.type,'LogicalExpression');assert.equal(forward[0].arguments[0].operator,'||');
  assert.equal(forward[0].arguments[0].left?.name,'args');assert.equal(forward[0].arguments[0].right?.type,'ObjectExpression');
  assert.equal(forward[0].arguments[1]?.name,'ctx');
  const action=fn(tree(handlerFile,overrides),handler);
  for(const effect of effects)assert.equal(calls(action,effect).length,1,`${id} exact effect ${effect}`);
  if(id==='cart.add'){
   const effect=calls(action,'commerce.cart_add_1')[0];assert.deepEqual(effect.arguments.map(name),['uid','product_id','qty']);
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   assert.equal(declaration(action,'info').init?.argument,effect,'returned cart ID comes from awaited selected insert');
   assert.equal(name(declaration(action,'uid').init.left),'ctx.userId');
   const result=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'cart_item_id')?.value)==='info.lastInsertRowid');assert.equal(result.length,1);
   assert.equal(name(property(result[0].argument,'product_id')?.value),'product_id');
   assert.equal(name(property(result[0].argument,'qty')?.value),'qty');
  }
  if(id==='cart.remove'){
   const effect=calls(action,'commerce.cart_remove_2')[0];assert.equal(effect.arguments[0]?.name,'cart_item_id');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   assert.equal(declaration(action,'info').init?.argument,effect,'deleted count comes from awaited selected delete');
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'deleted')?.value)==='info.changes'
    &&property(n.argument,'ok')?.value?.operator==='>'
    &&name(property(n.argument,'ok')?.value?.left)==='info.changes'
    &&property(n.argument,'ok')?.value?.right?.value===0).length,1);
  }
  if(id==='cart.view'){
   const effect=calls(action,'commerce.cart_view_3')[0];assert.equal(effect.arguments[0]?.name,'uid');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   assert.equal(declaration(action,'rows').init?.argument,effect,'cart rows come from awaited selected user query');
   assert.equal(name(declaration(action,'uid').init.left),'ctx.userId');
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'items')?.value)==='rows').length,1);
   const subtotal=declaration(action,'subtotal').init;
   assert.equal(name(subtotal.callee?.object),'rows');assert.equal(subtotal.callee?.property?.name,'reduce');
   assert.equal(subtotal.arguments[0]?.type,'ArrowFunctionExpression');
   assert.equal(subtotal.arguments[0].body?.operator,'+');
   assert.equal(subtotal.arguments[0].body.left?.name,'s');
   assert.equal(subtotal.arguments[0].body.right?.operator,'*');
   assert.equal(name(subtotal.arguments[0].body.right.right),'r.quantity');
   assert.equal(visit(subtotal.arguments[0].body.right.left,n=>name(n)==='r.price').length,1);
   const returned=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'items')?.value)==='rows');
   assert.equal(name(property(returned[0].argument,'subtotal')?.value?.callee),'Number');
   assert.equal(name(property(returned[0].argument,'subtotal')?.value?.arguments[0]?.callee),'subtotal.toFixed');
   assert.equal(property(returned[0].argument,'subtotal').value.arguments[0].arguments[0]?.value,2);
  }
  if(id==='cart.apply_coupon'||id==='support.order_status'){
   const sql=declaration(action,'sql').init;assert.equal(sql?.type,'TemplateLiteral');
   assert.deepEqual(sql.expressions.map(name),[id==='cart.apply_coupon'?'code':'order_id']);
   assert.deepEqual(sql.quasis.map(q=>q.value.cooked),id==='cart.apply_coupon'
    ?["SELECT id, code, discount_percent, active FROM coupons WHERE code = '","' AND active = 1 LIMIT 1"]
    :['SELECT id, customer_id, total_amount, status, payment_method, payment_status, shipping_address, order_date FROM orders WHERE id = ',' LIMIT 1']);
   const effect=calls(action,'commerce.readTeachingQuery')[0];assert.equal(effect.arguments[0]?.name,'sql');
   assert.equal(effect.arguments[1]?.value,'get');assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   if(id==='cart.apply_coupon'){
    const assigned=visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='row'
     &&n.right?.type==='AwaitExpression'&&n.right.argument===effect);
    assert.equal(assigned.length,1,'coupon row comes from selected awaited SQL');
    assert.equal(visit(action,n=>n.type==='CatchClause'&&n.param?.name==='e'
     &&visit(n.body,x=>x.type==='AssignmentExpression'&&x.left?.name==='error'
      &&name(x.right)==='e.message').length===1).length,1);
    const positive=visit(action,n=>n.type==='IfStatement'&&n.test?.name==='row'
     &&n.consequent?.type==='BlockStatement'&&visit(n.consequent,x=>x.type==='ReturnStatement'
      &&x.argument?.type==='ObjectExpression'&&property(x.argument,'valid')?.value?.value===true
      &&name(property(x.argument,'code')?.value)==='row.code'
      &&name(property(x.argument,'discount_percent')?.value)==='row.discount_percent').length===1);
    assert.equal(positive.length,1);
    const negative=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
     &&property(n.argument,'valid')?.value?.value===false
     &&name(property(n.argument,'code')?.value)==='code'
     &&property(n.argument,'discount_percent')?.value?.value===0
     &&name(property(n.argument,'error')?.value)==='error');
    assert.equal(negative.length,1);
   }else{
    assert.equal(declaration(action,'row').init?.argument,effect,'order row comes from selected awaited SQL');
    assert.equal(visit(action,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
     &&n.test.operator==='!'&&n.test.argument?.name==='row'
     &&n.consequent?.type==='ReturnStatement'&&property(n.consequent.argument,'order')?.value?.type==='NullLiteral'
     &&name(property(n.consequent.argument,'sql')?.value)==='sql').length,1);
    assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
     &&name(property(n.argument,'order')?.value)==='row'&&name(property(n.argument,'sql')?.value)==='sql').length,1);
    assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
     &&name(property(n.argument,'error')?.value)==='e.message'&&name(property(n.argument,'sql')?.value)==='sql').length,1);
   }
  }
  if(id==='support.open_ticket'){
   const effect=calls(action,'commerce.support_openTicket_2')[0];assert.equal(effect.arguments[0]?.name,'uid');
   assert.equal(effect.arguments[1]?.left?.name,'subject');assert.equal(effect.arguments[2]?.left?.name,'body');
   assert.equal(effect.arguments[1]?.right?.value,'');assert.equal(effect.arguments[2]?.right?.value,'');
   assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   assert.equal(declaration(action,'info').init?.argument,effect,'ticket ID comes from awaited selected insert');
   assert.equal(name(declaration(action,'uid').init.left),'ctx.userId');
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'ticket_id')?.value)==='info.lastInsertRowid'
    &&name(property(n.argument,'subject')?.value)==='subject'
    &&name(property(n.argument,'body')?.value)==='body').length,1);
  }
  if(id==='support.refund_request'){
   const effect=calls(action,'commerce.support_refundRequest_3')[0];assert.deepEqual(effect.arguments.map(name).slice(0,3),['uid','subj','body']);
   assert.equal(effect.arguments[3]?.value,'refund_pending');assert.equal(visit(action,n=>n.type==='AwaitExpression'&&n.argument===effect).length,1);
   assert.equal(declaration(action,'info').init?.argument,effect,'refund-request ticket ID comes from awaited selected insert');
   assert.equal(name(declaration(action,'uid').init.left),'ctx.userId');
   assert.equal(declaration(action,'subj').init.expressions[0]?.name,'order_id');
   assert.deepEqual(declaration(action,'subj').init.quasis.map(q=>q.value.cooked),['refund request for order ','']);
   assert.deepEqual(declaration(action,'body').init.quasis.map(q=>q.value.cooked),['Reason: ','']);
   const reasonFallback=declaration(action,'body').init.expressions[0];
   assert.equal(reasonFallback.operator,'||');assert.equal(reasonFallback.left?.name,'reason');assert.equal(reasonFallback.right?.value,'not provided');
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'ticket_id')?.value)==='info.lastInsertRowid'
    &&name(property(n.argument,'order_id')?.value)==='order_id'
    &&name(property(n.argument,'reason')?.value?.left)==='reason'
    &&property(n.argument,'reason')?.value?.right?.type==='NullLiteral').length,1);
  }
 }
 const db=createDbBindings(commerce);
 assert.deepEqual(db,{
  cart_add_1:'INSERT INTO secureshop.cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING id',
  cart_remove_2:'DELETE FROM secureshop.cart_items WHERE id = $1',
  cart_view_3:'SELECT ci.id, ci.product_id, ci.quantity, ci.added_at, p.name, p.price FROM secureshop.cart_items ci LEFT JOIN secureshop.products p ON p.id = ci.product_id WHERE ci.user_id = $1',
  support_openTicket_2:'INSERT INTO secureshop.support_tickets (customer_id, subject, body) VALUES ($1, $2, $3) RETURNING id',
  support_refundRequest_3:'INSERT INTO secureshop.support_tickets (customer_id, subject, body, status) VALUES ($1, $2, $3, $4) RETURNING id',
 });
}
function createDbBindings(ast){
 const keys=['cart_add_1','cart_remove_2','cart_view_3','support_openTicket_2','support_refundRequest_3'],out={};
 for(const key of keys){const prop=visit(ast,n=>n.type==='ObjectProperty'&&n.key?.name===key);assert.equal(prop.length,1);
  const effect=calls(prop[0],key==='cart_view_3'?'all':'run');assert.equal(effect.length,1);
  assert.equal(effect[0].arguments[0]?.type,'StringLiteral');assert.equal(effect[0].arguments[1]?.name,'params');
  assert.equal(prop[0].value?.params?.[0]?.type,'RestElement');assert.equal(prop[0].value.params[0].argument?.name,'params');
  out[key]=effect[0].arguments[0].value.replace(/\s+/g,' ').trim();}
 return out;
}
function productSummary(overrides={},data=manifest){
 const roles=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin']){
  assert.equal(literalArray(property(roles,role).value).includes('summarizer'),true);
  assert.equal(literalArray(property(roles,role).value).includes('product-search'),role==='customer');
 }
 const db=tree('server/database/postgres/secureshopCommerceDb.js',overrides);
 const sqlExpected={
  product_search_personalizedFeed_1:"SELECT id, name, description, price, category, image_url, stock_quantity FROM secureshop.products WHERE status = 'active' ORDER BY RANDOM() LIMIT 12",
  product_search_similar_1:'SELECT id, name, description, category FROM secureshop.products WHERE id = $1',
  product_search_similar_2:"SELECT id, name, description, price, category, image_url FROM secureshop.products WHERE status='active' LIMIT 200",
  summarizer_summarizeProduct_1:'SELECT id, name, description, price, category, stock_quantity, description_html FROM secureshop.products WHERE id = $1',
  summarizer_summarizeReviews_1:'SELECT id, product_id, author_id, body, rating, status, created_at FROM secureshop.reviews WHERE product_id = $1 ORDER BY created_at DESC LIMIT $2',
 };
 for(const [key,sql] of Object.entries(sqlExpected)){
  const entry=visit(db,n=>n.type==='ObjectProperty'&&n.key?.name===key);assert.equal(entry.length,1);
  const effect=calls(entry[0],key==='product_search_personalizedFeed_1'||key==='product_search_similar_2'||key==='summarizer_summarizeReviews_1'?'all':'one');
  assert.equal(effect.length,1);assert.equal(effect[0].arguments[0]?.type,'StringLiteral');
  assert.equal(effect[0].arguments[0].value.replace(/\s+/g,' ').trim(),sql);
  assert.equal(effect[0].arguments[1]?.name,'params');
  assert.equal(entry[0].value?.params?.[0]?.type,'RestElement');
  assert.equal(entry[0].value.params[0].argument?.name,'params');
  assert.equal(entry[0].value.body,effect[0]);
 }
 const one=declaration(db,'one').init;
 assert.equal(calls(one,'all').length,1);assert.deepEqual(calls(one,'all')[0].arguments.map(name),['sql','params']);
 assert.equal(one.body?.object?.argument,calls(one,'all')[0],'one selects first row from selected all result');
 assert.equal(one.body?.property?.value,0);
 for(const [id,agent,tool,handler,postgres,effects,consequence,applicability] of productSummaryReview){
  const row=data.reviewedProductSearchSummarizer.find(r=>r.id===id);assert.ok(row);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','serverFile','wrapperFile','handlerFile','inputSchema','advertisedRoles','hostGateRolesDefault','effectCalls','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  const base=`agent-host/agents/${agent}`,serverFile=`${base}/server.js`,wrapperFile=postgres?`${base}/tools/${tool}.js`:null;
  const handlerFile=`${base}/tools/${postgres||`${tool}.js`}`;
  assert.deepEqual([row.handler,row.serverFile,row.wrapperFile,row.handlerFile,row.inputSchema,row.advertisedRoles,row.hostGateRolesDefault,row.effectCalls,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [handler,serverFile,wrapperFile,handlerFile,productSummarySchemas[id],agent==='product-search'?['customer']:['customer','merchant','admin'],[],effects,consequence,applicability,[],[],null]);
  const server=tree(serverFile,overrides),descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===tool);
  assert.ok(descriptor);assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema);
  assert.equal(visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===handler)&&name(n.init?.callee)==='require'
   &&n.init.arguments[0]?.value===`./tools/${tool}.js`).length,1);
  if(wrapperFile){const wrapper=tree(wrapperFile,overrides);
   const exported=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
   assert.equal(exported.length,1);assert.equal(name(exported[0].right?.callee),'require');
   assert.equal(exported[0].right.arguments[0]?.value,`./${postgres}`);
  }
  const dispatch=calls(fn(server,'createServer'),'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema')?.arguments[1];assert.ok(dispatch);
  assert.equal(calls(dispatch,'enforceRole').length,0,'no local host role gate');
  const raw=visit(dispatch,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name==='arguments'&&p.value?.name==='rawArgs')
   &&name(n.init)==='req.params');assert.equal(raw.length,1);
  assert.equal(visit(dispatch,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name==='args')&&name(n.init?.callee)==='extractCaller'
   &&n.init.arguments[0]?.name==='rawArgs').length,1);
  const selected=visit(dispatch,n=>n.type==='SwitchCase'&&n.test?.value===tool);assert.equal(selected.length,1);
  const statement=selected[0].consequent[0];assert.equal(statement?.type,'ReturnStatement');
  assert.equal(name(statement.argument?.callee),'_wrap');assert.equal(statement.argument.arguments.length,1);
  const awaited=statement.argument.arguments[0];assert.equal(awaited?.type,'AwaitExpression');
  assert.equal(name(awaited.argument?.callee),handler);assert.equal(awaited.argument.arguments.length,1);
  assert.equal(awaited.argument.arguments[0]?.type,'LogicalExpression');
  assert.equal(awaited.argument.arguments[0].operator,'||');assert.equal(awaited.argument.arguments[0].left?.name,'args');
  assert.equal(awaited.argument.arguments[0].right?.type,'ObjectExpression');
  const action=fn(tree(handlerFile,overrides),handler);
  for(const effect of effects)assert.equal(calls(action,effect).length,1,`${id} selected effect ${effect}`);
  if(id==='product-search.search'){
   const sql=declaration(action,'sql').init;
   assert.deepEqual(sql.expressions.map(name),['query']);
   assert.deepEqual(sql.quasis.map(q=>q.value.cooked),[
    "SELECT id, name, description, price, category, image_url, stock_quantity, retailer_id, status, created_at, updated_at FROM products WHERE name LIKE '%","%' LIMIT 50"]);
   const effect=calls(action,'commerce.readTeachingQuery')[0];assert.deepEqual(effect.arguments.map(name),['sql',null]);
   assert.equal(effect.arguments[1]?.value,'all');
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='rows'
    &&n.right?.type==='AwaitExpression'&&n.right.argument===effect).length,1);
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='sqlError'
    &&name(property(n.right,'message')?.value)==='e.message'&&name(property(n.right,'sql')?.value)==='sql').length,1);
   const echo=declaration(action,'echoHtml').init;assert.deepEqual(echo.expressions.map(name),['query']);
   assert.deepEqual(echo.quasis.map(q=>q.value.cooked),['<p>Results for: <b>','</b></p>']);
   const result=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'results')?.value)==='rows'&&name(property(n.argument,'query')?.value)==='query'
    &&name(property(n.argument,'echo_html')?.value)==='echoHtml'&&name(property(n.argument,'sql_error')?.value)==='sqlError');
   assert.equal(result.length,1);assert.equal(name(property(result[0].argument,'count')?.value),'rows.length');
   const filterCallbacks={category:'r => r.category === filters.category',min_price:'r => Number(r.price) >= filters.min_price',max_price:'r => Number(r.price) <= filters.max_price'};
   for(const [key,callbackText] of Object.entries(filterCallbacks)){
    const branch=visit(action,n=>n.type==='IfStatement'&&visit(n.test,x=>name(x)===`filters.${key}`).length>0
     &&calls(n.consequent,'rows.filter').length===1);assert.equal(branch.length,1);
    const filter=calls(branch[0].consequent,'rows.filter')[0];
    assert.equal((overrides[handlerFile]??source(handlerFile)).slice(filter.arguments[0].start,filter.arguments[0].end),callbackText);
    assert.equal(visit(branch[0].consequent,n=>n.type==='AssignmentExpression'&&n.left?.name==='rows'
     &&n.right===filter).length,1);
   }
  }
  if(id==='product-search.similar'){
   const store=declaration(action,'store').init;
   assert.equal(store?.type,'NewExpression');assert.equal(name(store.callee),'VectorStore');
   assert.equal(property(store.arguments[0],'corpus')?.value?.value,'manuals');
   const chosen=calls(action,'commerce.product_search_similar_1')[0];assert.deepEqual(chosen.arguments.map(name),['product_id']);
   assert.equal(declaration(action,'target').init?.argument,chosen);
   const pool=calls(action,'commerce.product_search_similar_2')[0];assert.equal(declaration(action,'all').init?.argument,pool);
   const count=calls(action,'store.count')[0],search=calls(action,'store.search')[0];
   const guard=visit(action,n=>n.type==='IfStatement'&&n.test?.operator==='>'
    &&n.test.left?.type==='AwaitExpression'&&n.test.left.argument===count&&n.test.right?.value===0
    &&visit(n.consequent,x=>x===search).length===1);
   assert.equal(guard.length,1);assert.ok(guard[0].consequent.start<search.start);
   const query=declaration(guard[0],'query').init;
   assert.equal(name(query.callee),'String');assert.equal(query.arguments[0]?.operator,'||');
   assert.equal(query.arguments[0].left?.name,'rag_query');
   assert.deepEqual(query.arguments[0].right?.quasis.map(q=>q.value.cooked),['',' ','']);
   assert.deepEqual(query.arguments[0].right?.expressions.map(name),['target.name',null]);
   assert.equal(name(query.arguments[0].right.expressions[1].left),'target.description');
   assert.equal(query.arguments[0].right.expressions[1].right?.value,'');
   assert.equal(search.arguments[0]?.name,'query');assert.equal(search.arguments[1]?.value,5);
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='retrieved'
    &&n.right?.type==='AwaitExpression'&&n.right.argument===search).length,1);
   const bias=calls(action,'_applyRetrievalBias')[0];assert.deepEqual(bias.arguments.map(name),['results','retrieved','all']);
   assert.equal(declaration(action,'results').init?.callee?.name,'_keywordFallback');
   assert.deepEqual(declaration(action,'results').init.arguments.map(name),['target','all']);
   const fallback=fn(tree(handlerFile,overrides),'_keywordFallback');
   assert.equal(visit(fallback,n=>n.type==='ReturnStatement'&&n.argument?.name==='scored').length,1);
   const scored=declaration(fallback,'scored').init;
   assert.equal(visit(scored,n=>n.type==='CallExpression'&&n.callee?.property?.name==='slice'
    &&n.arguments[0]?.value===0&&n.arguments[1]?.value===5).length,1);
   assert.equal(visit(scored,n=>n.type==='CallExpression'&&name(n.callee)==='tset.has').length,1);
   assert.equal(visit(scored,n=>n.type==='BinaryExpression'&&n.operator==='==='
    &&name(n.left)==='r.category'&&name(n.right)==='target.category').length,1);
   assert.equal(visit(scored,n=>n.type==='BinaryExpression'&&n.operator==='-'
    &&name(n.left)==='b.score'&&name(n.right)==='a.score').length,1);
   assert.equal(declaration(action,'biased').init,bias);
   assert.equal(name(declaration(action,'biasedWithImages').init?.callee?.object),'biased');
   const biasFn=fn(tree(handlerFile,overrides),'_applyRetrievalBias');
   assert.equal(calls(biasFn,'promotedIds.add').length,1);
   assert.equal(calls(biasFn,'allProducts.find').length,1);
   const promoted=visit(biasFn,n=>n.type==='ReturnStatement'&&n.argument?.type==='CallExpression'
    &&n.argument.callee?.property?.name==='slice'&&n.argument.arguments[0]?.value===0&&n.argument.arguments[1]?.value===5);
   assert.equal(promoted.length,1);
   assert.deepEqual(promoted[0].argument.callee.object.elements.map(x=>x.argument?.name),['promotedRows','kept']);
   const result=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'results')?.value)==='biasedWithImages'
    &&name(property(n.argument,'retrieved_context')?.value)==='retrieved'
    &&name(property(n.argument,'mode')?.value)==='ragMode');assert.equal(result.length,1);
   assert.equal(name(property(result[0].argument,'count')?.value),'biasedWithImages.length');
   const seed=property(result[0].argument,'seed')?.value;
   assert.deepEqual([name(property(seed,'id')?.value),name(property(seed,'name')?.value)],['target.id','target.name']);
  }
  if(id==='product-search.personalized_feed'){
   const effect=calls(action,'commerce.product_search_personalizedFeed_1')[0];assert.equal(effect.arguments.length,0);
   assert.equal(declaration(action,'rows').init?.argument,effect);
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'feed')?.value)==='rows'
    &&name(property(n.argument,'count')?.value)==='rows.length'
    &&name(property(n.argument,'user_id')?.value)==='user_id').length,1);
  }
  if(id==='summarizer.summarize_product'){
   const effect=calls(action,'commerce.summarizer_summarizeProduct_1')[0];assert.deepEqual(effect.arguments.map(name),['product_id']);
   assert.equal(declaration(action,'row').init?.argument,effect);
   assert.equal(visit(action,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'&&n.test.operator==='!'
    &&n.test.argument?.name==='row'&&n.consequent?.type==='ReturnStatement'
    &&property(n.consequent.argument,'error')?.value?.value==='unknown product_id'
    &&name(property(n.consequent.argument,'product_id')?.value)==='product_id').length,1);
   const summary=declaration(action,'summary').init;
   assert.ok(summary.expressions.some(x=>name(x?.left)==='row.description'||name(x)==='row.description'));
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'description')?.value)==='row.description'
    &&name(property(n.argument,'description_html')?.value)==='row.description_html'
    &&name(property(n.argument,'summary')?.value)==='summary').length,1);
  }
  if(id==='summarizer.summarize_reviews'){
   const effect=calls(action,'commerce.summarizer_summarizeReviews_1')[0];assert.deepEqual(effect.arguments.map(name),['product_id','k']);
   assert.equal(declaration(action,'rows').init?.argument,effect);
   const returned=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'reviews')?.value)==='rows'
    &&name(property(n.argument,'count')?.value)==='rows.length'
    &&name(property(n.argument,'concatenated_bodies')?.value?.callee?.object?.callee)=='rows.map');
   assert.equal(returned.length,1);
   const joined=property(returned[0].argument,'concatenated_bodies').value;
   assert.equal(joined.arguments[0]?.value,'\n\n---\n\n');
   assert.equal(name(joined.callee.object.arguments[0]?.body),'r.body');
  }
  if(id==='summarizer.explain_return_policy'){
   const parsed=visit(action,n=>n.type==='NewExpression'&&name(n.callee)==='URL');assert.equal(parsed.length,1);
   assert.deepEqual(parsed[0].arguments.map(name),['policy_url']);
   assert.equal(declaration(action,'u').init,parsed[0]);
   for(const guarded of visit(action,n=>n.type==='TryStatement'))assert.ok(!(guarded.start<parsed[0].start&&parsed[0].end<guarded.end),'malformed URL parse is outside catches');
   const file=visit(action,n=>n.type==='IfStatement'&&n.test?.operator==='==='&&name(n.test.left)==='u.protocol'
    &&n.test.right?.value==='file:'&&calls(n.consequent,'fs.readFileSync').length===1);assert.equal(file.length,1);
   const read=calls(file[0],'fs.readFileSync')[0];assert.deepEqual(read.arguments.map(name),['u.pathname',null]);assert.equal(read.arguments[1]?.value,'utf8');
   assert.equal(declaration(file[0],'body').init,read);
   const fileReturn=visit(file[0].consequent,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'url')?.value)==='policy_url'
    &&name(property(n.argument,'body')?.value)==='body'
    &&property(n.argument,'source')?.value?.value==='file'
    &&property(n.argument,'status')?.value?.value===200);
   assert.equal(fileReturn.length,1);
   assert.equal(visit(file[0].consequent,n=>n.type==='CatchClause'&&n.param?.name==='e'
    &&visit(n.body,x=>x.type==='ReturnStatement'&&name(property(x.argument,'error')?.value)==='e.message'
     &&name(property(x.argument,'url')?.value)==='policy_url').length===1).length,1);
   const fetch=calls(action,'_fetchHttp')[0];assert.deepEqual(fetch.arguments.map(name),['policy_url']);
   assert.equal(declaration(action,'r').init?.argument,fetch);
   const bodyReturn=visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'body')?.value)==='r.body'
    &&name(property(n.argument,'status')?.value)==='r.status'
    &&name(property(n.argument,'headers')?.value)==='r.headers');assert.equal(bodyReturn.length,1);
   const summary=property(bodyReturn[0].argument,'summary')?.value;
   assert.ok(summary?.expressions?.some(x=>name(x)==='r.body'));
   const http=fn(tree(handlerFile,overrides),'_fetchHttp');
   assert.equal(declaration(http,'u').init?.type,'NewExpression');
   assert.equal(name(declaration(http,'u').init?.callee),'URL');
   assert.deepEqual(declaration(http,'u').init.arguments.map(name),['target']);
   const lib=declaration(http,'lib').init;
   assert.equal(lib?.type,'ConditionalExpression');assert.equal(lib.test?.operator,'===');
   assert.equal(name(lib.test.left),'u.protocol');assert.equal(lib.test.right?.value,'https:');
   assert.deepEqual([name(lib.consequent),name(lib.alternate)],['https','http']);
   const request=calls(http,'lib.request');assert.equal(request.length,1);
   assert.equal(declaration(http,'req').init,request[0]);
   const options=request[0].arguments[0];
   assert.deepEqual([property(options,'method')?.value?.value,name(property(options,'hostname')?.value),name(property(options,'port')?.value)],['GET','u.hostname','u.port']);
   assert.equal(property(options,'path')?.value?.operator,'+');
   assert.deepEqual([name(property(options,'path').value.left),name(property(options,'path').value.right)],['u.pathname','u.search']);
   const timeout=calls(http,'req.setTimeout');assert.equal(timeout.length,1);
   assert.equal(timeout[0].arguments[0]?.value,4000);
   assert.equal(calls(timeout[0],'req.destroy').length,1);
   const end=calls(http,'req.end');assert.equal(end.length,1);
   assert.ok(request[0].end<end[0].start,'selected request is ended after construction');
   const data=calls(http,'res.on').find(c=>c.arguments[0]?.value==='data');
   const finish=calls(http,'res.on').find(c=>c.arguments[0]?.value==='end');
   assert.ok(data&&finish&&data.start<finish.start,'body chunks collected before resolve handler registration');
   assert.equal(data.arguments[1]?.type,'ArrowFunctionExpression');
   const append=visit(data.arguments[1],n=>n.type==='AssignmentExpression'&&n.operator==='+='
    &&n.left?.name==='chunks'&&name(n.right?.callee)==='c.toString'
    &&n.right.arguments[0]?.value==='utf8');assert.equal(append.length,1);
   const resolved=calls(http,'resolve').find(c=>c.arguments[0]?.type==='ObjectExpression'
    &&name(property(c.arguments[0],'status')?.value)==='res.statusCode'
    &&name(property(c.arguments[0],'headers')?.value)==='res.headers'
    &&name(property(c.arguments[0],'body')?.value)==='chunks');assert.ok(resolved);
  }
  if(id==='summarizer.summarize_file'){
   const cleaned=declaration(action,'cleaned').init;assert.equal(name(cleaned.callee?.property),'replace');
   assert.equal(cleaned.arguments[0]?.type,'RegExpLiteral');assert.equal(cleaned.arguments[0].pattern,'\\.\\.\\/');
   assert.equal(cleaned.arguments[0].flags,'g');assert.equal(cleaned.arguments[1]?.value,'');
   assert.equal(declaration(action,'target').init?.name,'filePath');
   const read=calls(action,'fs.readFileSync')[0];assert.deepEqual(read.arguments.map(name),['target',null]);
   assert.equal(read.arguments[1]?.value,'utf8');
   assert.equal(visit(action,n=>n.type==='AssignmentExpression'&&n.left?.name==='body'&&n.right===read).length,1);
   const ext=declaration(action,'ext').init;
   assert.equal(ext.callee?.property?.name,'toLowerCase');
   assert.equal(name(ext.callee.object?.callee),'path.extname');
   assert.deepEqual(ext.callee.object.arguments.map(name),['target']);
   assert.equal(visit(action,n=>n.type==='CatchClause'&&n.param?.name==='e'
    &&visit(n.body,x=>x.type==='ReturnStatement'&&name(property(x.argument,'path')?.value)==='target'
     &&name(property(x.argument,'error')?.value)==='e.message').length===1).length,1);
   assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
    &&name(property(n.argument,'path')?.value)==='target'
    &&name(property(n.argument,'cleaned_path')?.value)==='cleaned'
    &&name(property(n.argument,'body')?.value)==='body'
    &&property(n.argument,'summary')?.value?.expressions?.some(x=>name(x)==='body')).length,1);
  }
 }
}
function uploads(overrides={},data=manifest){
 const serverFile='agent-host/agents/uploads/server.js',handlerFile='agent-host/agents/uploads/tools/index.js';
 const server=tree(serverFile,overrides),handlerAst=tree(handlerFile,overrides);
 const roles=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin'])assert.equal(literalArray(property(roles,role).value).includes('uploads'),true);
 const call=fn(server,'callTool');
 const extracted=visit(call,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.some(p=>p.key?.name==='caller')&&n.id.properties.some(p=>p.key?.name==='args')
  &&name(n.init?.callee)==='extractCaller'&&n.init.arguments[0]?.name==='rawArgs');assert.equal(extracted.length,1);
 const restricted=visit(call,n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'
  &&n.test.operator==='||'&&name(n.test.left?.left)==='name'
  &&n.test.left?.right?.value==='upload_product_image'
  &&name(n.test.right?.left)==='name'&&n.test.right?.right?.value==='upload_product_manual');
 assert.equal(restricted.length,1);
 const gate=calls(restricted[0].consequent,'enforceRole');assert.equal(gate.length,1);
 assert.equal(gate[0].arguments[0]?.name,'caller');assert.deepEqual(literalArray(gate[0].arguments[1]),['merchant','admin']);
 assert.equal(visit(restricted[0].consequent,n=>n.type==='IfStatement'&&n.test?.name==='denied'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied').length,1);
 const switches=visit(call,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(switches.length,1);
 assert.ok(restricted[0].end<switches[0].start,'conditional denial precedes all selected effects');
 assert.equal(calls(call,'enforceRole').length,1,'only two selected upload operations locally gated');
 const create=fn(server,'createServer');
 const dispatch=calls(create,'server.setRequestHandler').find(c=>c.arguments[0]?.name==='CallToolRequestSchema')?.arguments[1];
 assert.ok(dispatch);const forwarded=calls(dispatch,'callTool');assert.equal(forwarded.length,1);
 assert.deepEqual(forwarded[0].arguments.map(name),['name','rawArgs']);
 assert.equal(visit(dispatch,n=>n.type==='ReturnStatement'&&n.argument===forwarded[0]).length,1);
 assert.equal(visit(dispatch,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.some(p=>p.key?.name==='arguments'&&p.value?.name==='rawArgs')
  &&name(n.init)==='req.params').length,1);
 const exported=visit(handlerAst,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');assert.equal(exported.length,1);
 const exportMap=exported[0].right;assert.equal(exportMap?.type,'ObjectExpression');
 assert.deepEqual(staticValue(declaration(handlerAst,'KIND_DIRS').init),{
  avatar:'avatars',product_image:'product_images',return_evidence:'return_evidence',product_manual:'product_manuals'});
 const kindScope={upload_avatar:['avatar','user_id'],upload_product_image:['product_image','product_id'],
  upload_return_evidence:['return_evidence','order_id'],upload_product_manual:['product_manual','product_id']};
 for(const [id,tool,effects,consequence,applicability] of uploadsReview){
  const row=data.reviewedUploads.find(r=>r.id===id);assert.ok(row);
  assert.deepEqual(Object.keys(row).sort(),['id','handler','serverFile','handlerFile','inputSchema','advertisedRoles','hostGateRolesDefault','effectCalls','consequence','applicability','originalCheckIds','objectiveIds','nativeEvidence'].sort());
  assert.deepEqual([row.handler,row.serverFile,row.handlerFile,row.inputSchema,row.advertisedRoles,row.hostGateRolesDefault,row.effectCalls,row.consequence,row.applicability,row.originalCheckIds,row.objectiveIds,row.nativeEvidence],
   [tool,serverFile,handlerFile,uploadsSchemas[id],['customer','merchant','admin'],['upload_product_image','upload_product_manual'].includes(tool)?['merchant','admin']:[],effects,consequence,applicability,[],[],null]);
  const descriptor=declaration(server,'TOOLS').init.elements.find(n=>property(n,'name')?.value?.value===tool);
  assert.ok(descriptor);assert.deepEqual(staticValue(property(descriptor,'inputSchema')?.value),row.inputSchema);
  const importTool=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===tool)&&name(n.init?.callee)==='require'
   &&n.init.arguments[0]?.value==='./tools/index.js');assert.equal(importTool.length,1);
  const selected=switches[0].cases.find(c=>c.test?.value===tool);assert.ok(selected);
  assert.equal(selected.consequent.length,1);const returned=selected.consequent[0];assert.equal(returned.type,'ReturnStatement');
  assert.equal(name(returned.argument?.callee),'_wrap');assert.equal(returned.argument.arguments[0]?.type,'AwaitExpression');
  const effect=returned.argument.arguments[0].argument;assert.equal(name(effect?.callee),tool);
  assert.equal(effect.arguments[0]?.operator,'||');assert.equal(effect.arguments[0].left?.name,'args');
  assert.equal(effect.arguments[0].right?.type,'ObjectExpression');
  const bridge=property(exportMap,tool)?.value;assert.equal(bridge?.type,'ArrowFunctionExpression');
  assert.deepEqual(bridge.params.map(name),['args']);assert.equal(name(bridge.body?.callee),tool);
  assert.deepEqual(bridge.body.arguments.map(name),['args'],'MCP direct export uses default root, no factory injection');
  const action=fn(handlerAst,tool);
  assert.equal(action.params[1]?.type,'AssignmentPattern');
  assert.equal(action.params[1].left?.name,'uploadRoot');
  assert.equal(name(action.params[1].right?.callee),'getSecureShopUploadRoot');
  assert.equal(action.params[1].right.arguments.length,0,'direct MCP export uses environment default root');
  if(tool!=='download'){
   const decoded=calls(action,'_decodeToBuffer');assert.equal(decoded.length,1);
   assert.deepEqual(decoded[0].arguments.map(name),['file_bytes_base64']);
   assert.equal(declaration(action,'buffer').init,decoded[0]);
   const write=calls(action,'_writeFileWithMeta');assert.equal(write.length,1);
   const [kind,scope]=kindScope[tool],args=write[0].arguments[0];
   assert.deepEqual([property(args,'kind')?.value?.value,name(property(args,'scopeId')?.value),name(property(args,'filename')?.value),name(property(args,'buffer')?.value),name(property(args,'mime')?.value)],
    [kind,scope,'filename','buffer','mime']);
   assert.equal(write[0].arguments[1]?.name,'uploadRoot');
   if(tool==='upload_product_manual')assert.equal(declaration(action,'meta').init,write[0]);
   else assert.equal(visit(action,n=>n.type==='ReturnStatement'&&n.argument===write[0]).length,1);
  }
 }
 const decoded=fn(handlerAst,'_decodeToBuffer');
 assert.deepEqual(calls(decoded,'Buffer.from')[0]?.arguments.map(name),['fileBytesBase64',null]);
 assert.equal(calls(decoded,'Buffer.from')[0].arguments[1]?.value,'base64');
 assert.equal(visit(decoded,n=>n.type==='ReturnStatement'&&n.argument===calls(decoded,'Buffer.from')[0]).length,1);
 const clean=fn(handlerAst,'_cleanFilename'),pass=declaration(clean,'singlePass').init;
 assert.equal(pass.callee?.property?.name,'replace');assert.equal(pass.arguments[0]?.pattern,'\\.\\.\\/');
 assert.equal(pass.arguments[0]?.flags,'g');assert.equal(pass.arguments[1]?.value,'');
 assert.equal(visit(clean,n=>n.type==='ReturnStatement'&&n.argument?.name==='singlePass').length,1);
 const resolve=fn(handlerAst,'_resolveUploadPath'),base=declaration(resolve,'base').init,abs=declaration(resolve,'abs').init;
 assert.equal(resolve.params[1]?.type,'AssignmentPattern');
 assert.equal(resolve.params[1].left?.name,'uploadRoot');
 assert.equal(name(resolve.params[1].right?.callee),'getSecureShopUploadRoot');
 assert.equal(name(declaration(resolve,'dir').init?.object),'KIND_DIRS');
 assert.equal(declaration(resolve,'dir').init?.property?.name,'kind');
 assert.equal(declaration(resolve,'dir').init?.computed,true);
 assert.equal(visit(resolve,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
  &&n.test.operator==='!'&&n.test.argument?.name==='dir'
  &&n.consequent?.type==='ThrowStatement').length,1);
 assert.equal(name(base.callee),'path.join');assert.deepEqual(base.arguments.map(name),['uploadRoot','dir',null]);
 assert.equal(name(base.arguments[2]?.callee),'String');
 assert.equal(base.arguments[2].arguments[0]?.operator,'||');
 assert.equal(base.arguments[2].arguments[0].left?.name,'scopeId');
 assert.equal(base.arguments[2].arguments[0].right?.value,'unscoped');
 assert.equal(name(declaration(resolve,'cleaned').init?.callee),'_cleanFilename');
 assert.deepEqual(declaration(resolve,'cleaned').init.arguments.map(name),['filename']);
 assert.equal(name(abs.callee),'path.resolve');assert.deepEqual(abs.arguments.map(name),['base','cleaned']);
 assert.equal(calls(resolve,'_ensureDir')[0]?.arguments[0]?.name,'base');
 const write=fn(handlerAst,'_writeFileWithMeta');
 const resolvedPath=calls(write,'_resolveUploadPath');assert.equal(resolvedPath.length,1);
 assert.deepEqual(resolvedPath[0].arguments.map(name),[null,'uploadRoot']);
 assert.deepEqual(['kind','scopeId','filename'].map(k=>name(property(resolvedPath[0].arguments[0],k)?.value)),['kind','scopeId','filename']);
 assert.equal(visit(write,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.map(p=>p.key?.name).join(',')==='base,abs,cleaned'&&n.init===resolvedPath[0]).length,1);
 const out=declaration(write,'outPath').init;assert.equal(out?.type,'ConditionalExpression');
 const relToBase=declaration(write,'relToBase').init;
 assert.equal(name(relToBase.callee),'path.relative');assert.deepEqual(relToBase.arguments.map(name),['base','abs']);
 const traversal=declaration(write,'isTraversal').init;
 assert.equal(traversal?.operator,'||');
 assert.equal(name(traversal.left?.callee),'relToBase.startsWith');assert.equal(traversal.left.arguments[0]?.value,'..');
 assert.equal(name(traversal.right?.callee),'path.isAbsolute');assert.deepEqual(traversal.right.arguments.map(name),['relToBase']);
 assert.equal(out.test?.name,'isTraversal');assert.equal(out.consequent?.name,'abs');
 assert.equal(name(out.alternate?.callee),'path.join');assert.deepEqual(out.alternate.arguments.map(name),['base','finalName']);
 const disk=calls(write,'fs.writeFileSync');assert.equal(disk.length,1);assert.deepEqual(disk[0].arguments.map(name),['outPath','buffer']);
 const caught=visit(write,n=>n.type==='TryStatement'&&visit(n.block,x=>x===disk[0]).length===1);
 assert.equal(caught.length,1);assert.equal(visit(caught[0].handler,n=>n.type==='ReturnStatement'
  &&property(n.argument,'ok')?.value?.value===false
  &&name(property(n.argument,'attempted')?.value)==='outPath'
  &&name(property(n.argument,'error')?.value)==='e.message').length,1);
 const ensureOut=calls(caught[0].block,'_ensureDir');assert.equal(ensureOut.length,1);
 assert.equal(name(ensureOut[0].arguments[0]?.callee),'path.dirname');
 assert.deepEqual(ensureOut[0].arguments[0].arguments.map(name),['outPath']);
 assert.ok(ensureOut[0].start<disk[0].start);
 const success=visit(write,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
  &&property(n.argument,'ok')?.value?.value===true
  &&name(property(n.argument,'written_path')?.value)==='outPath'
  &&name(property(n.argument,'relative_path')?.value)==='storedRelativePath'
  &&name(property(n.argument,'size_bytes')?.value)==='buffer.length'
  &&name(property(n.argument,'is_traversal')?.value)==='isTraversal');assert.equal(success.length,1);
 const receipt=success[0].argument;
 assert.deepEqual(['kind','scope_id','filename','cleaned_filename'].map(k=>name(property(receipt,k)?.value)),['kind','scopeId','filename','cleaned']);
 const mimeValue=property(receipt,'mime')?.value;
 assert.equal(name(mimeValue?.callee),'String');assert.equal(mimeValue.arguments[0]?.operator,'||');
 assert.equal(mimeValue.arguments[0].left?.name,'mime');assert.equal(mimeValue.arguments[0].right?.value,'application/octet-stream');
 const rel=declaration(write,'relFromUploadRoot').init;
 assert.equal(name(rel.callee),'path.relative');assert.deepEqual(rel.arguments.map(name),['uploadRoot','outPath']);
 const standard=declaration(write,'isStandardUpload').init;
 assert.equal((overrides[handlerFile]??source(handlerFile)).slice(standard.start,standard.end),
  "relFromUploadRoot\n    && relFromUploadRoot !== '..'\n    && !relFromUploadRoot.startsWith(`..${path.sep}`)\n    && !path.isAbsolute(relFromUploadRoot)");
 const stored=declaration(write,'storedRelativePath').init;
 assert.equal(stored?.type,'ConditionalExpression');assert.equal(stored.test?.name,'isStandardUpload');
 assert.equal(name(stored.alternate?.callee),'path.relative');
 assert.deepEqual(stored.alternate.arguments.map(name),['REPO','outPath']);
 assert.equal(stored.consequent?.type,'TemplateLiteral');
 assert.deepEqual(stored.consequent.quasis.map(q=>q.value.cooked),['server/uploads/secureshop/','']);
 const slash=stored.consequent.expressions[0];
 assert.equal(slash?.callee?.property?.name,'join');assert.equal(slash.arguments[0]?.value,'/');
 assert.equal(name(slash.callee.object?.callee),'relFromUploadRoot.split');
 assert.deepEqual(slash.callee.object.arguments.map(name),['path.sep']);
 const manual=fn(handlerAst,'upload_product_manual');
 assert.equal(visit(manual,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'&&n.test.operator==='!'
  &&name(n.test.argument)==='meta.ok'&&n.consequent?.type==='ReturnStatement'
  &&n.consequent.argument?.name==='meta').length,1);
 const extract=calls(manual,'extractText')[0];assert.equal(declaration(manual,'extracted').init?.argument,extract);
 assert.equal(name(property(extract.arguments[0],'filePath')?.value),'meta.written_path');
 const chunks=calls(manual,'chunkText')[0];assert.equal(declaration(manual,'chunks').init,chunks);
 assert.equal(chunks.arguments[0]?.operator,'||');assert.equal(name(chunks.arguments[0].left),'extracted.text');
 assert.equal(chunks.arguments[1]?.value,500);
 const store=declaration(manual,'store').init;assert.equal(store?.type,'NewExpression');
 assert.equal(name(store.callee),'VectorStore');assert.equal(property(store.arguments[0],'corpus')?.value?.value,'manuals');
 const add=calls(manual,'store.add');assert.equal(add.length,1);
 const loop=visit(manual,n=>n.type==='ForStatement'&&visit(n.body,x=>x===add[0]).length===1);assert.equal(loop.length,1);
 assert.equal(loop[0].init?.declarations?.[0]?.id?.name,'i');
 assert.equal(loop[0].init.declarations[0].init?.value,0);
 assert.equal(loop[0].test?.operator,'<');assert.equal(loop[0].test.left?.name,'i');
 assert.equal(name(loop[0].test.right),'chunks.length');
 assert.equal(loop[0].update?.operator,'++');assert.equal(loop[0].update.argument?.name,'i');
 assert.equal(visit(loop[0],n=>n.type==='AwaitExpression'&&n.argument===add[0]).length,1);
 assert.equal(declaration(loop[0],'id').init?.argument,add[0]);
 const addArgs=add[0].arguments[0];assert.deepEqual([property(addArgs,'sourceKind')?.value?.value,name(property(addArgs,'chunkIndex')?.value),name(property(addArgs,'text')?.value?.object)],['manual','i','chunks']);
 assert.equal(property(addArgs,'text')?.value?.computed,true);
 assert.equal(property(addArgs,'text')?.value?.property?.name,'i');
 const sourceId=property(addArgs,'sourceId')?.value;
 assert.equal(sourceId?.operator,'||');assert.equal(name(sourceId.left?.callee),'Number');
 assert.deepEqual(sourceId.left.arguments.map(name),['product_id']);assert.equal(sourceId.right?.value,0);
 assert.equal(calls(loop[0],'chunkIds.push')[0]?.arguments[0]?.name,'id');
 const manualResult=visit(manual,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
  &&name(property(n.argument,'chunk_count')?.value)==='chunks.length'
  &&name(property(n.argument,'chunk_ids')?.value)==='chunkIds'
  &&property(n.argument,'indexed_corpus')?.value?.value==='manuals');assert.equal(manualResult.length,1);
 const manualReceipt=manualResult[0].argument;
 assert.equal(manualReceipt.properties[0]?.type,'SpreadElement');assert.equal(manualReceipt.properties[0].argument?.name,'meta');
 assert.equal(name(property(manualReceipt,'extracted_bytes')?.value?.object?.left),'extracted.text');
 assert.equal(name(property(manualReceipt,'extractor')?.value),'extracted.extractor');
 const extractionError=property(manualReceipt,'extractor_error')?.value;
 assert.equal(extractionError?.operator,'||');assert.equal(name(extractionError.left),'extracted.error');
 assert.equal(extractionError.right?.type,'NullLiteral');
 const extractor=fn(handlerAst,'extractText');
 const ext=declaration(extractor,'ext').init;
 assert.equal(ext.callee?.property?.name,'toLowerCase');
 assert.equal(name(ext.callee.object?.callee),'path.extname');
 assert.deepEqual(ext.callee.object.arguments.map(name),['filePath']);
 const fileRead=calls(extractor,'fs.readFileSync')[0];assert.deepEqual(fileRead.arguments.map(name),['filePath']);
 const extractionBranches=visit(extractor,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.left?.name==='ext');
 assert.deepEqual(extractionBranches.map(n=>n.test.right?.value),['.pdf','.docx']);
 assert.equal(visit(extractor,n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'
  &&visit(n.test,x=>x.type==='StringLiteral'&&x.value==='.txt').length===1
  &&visit(n.test,x=>x.type==='StringLiteral'&&x.value==='.md').length===1
  &&visit(n.consequent,x=>x.type==='ReturnStatement'
   &&property(x.argument,'extractor')?.value?.value==='raw-utf8').length===1).length,1);
 const pdf=extractionBranches.find(n=>n.test.right.value==='.pdf');
 const docx=extractionBranches.find(n=>n.test.right.value==='.docx');
 assert.equal(calls(pdf,'parser.getText').length,1);
 assert.equal(visit(pdf,n=>n.type==='ReturnStatement'&&property(n.argument,'extractor')?.value?.value==='pdf-parse').length,1);
 assert.equal(visit(pdf,n=>n.type==='ReturnStatement'&&property(n.argument,'extractor')?.value?.value==='raw-utf8-pdf-fallback').length,1);
 assert.equal(visit(pdf,n=>n.type==='ReturnStatement'&&property(n.argument,'extractor')?.value?.value==='pdf-parse-failed').length,1);
 assert.equal(calls(docx,'mammoth.extractRawText').length,1);
 assert.equal(visit(docx,n=>n.type==='ReturnStatement'&&property(n.argument,'extractor')?.value?.value==='mammoth').length,1);
 assert.equal(visit(docx,n=>n.type==='ReturnStatement'&&property(n.argument,'extractor')?.value?.value==='mammoth-failed').length,1);
 assert.equal(visit(extractor,n=>n.type==='ReturnStatement'
  &&property(n.argument,'extractor')?.value?.value==='raw-utf8-generic').length,1);
 const download=fn(handlerAst,'download');
 const raw=declaration(download,'raw').init;assert.equal(name(raw.callee),'String');
 assert.equal(raw.arguments[0]?.operator,'||');assert.equal(raw.arguments[0].left?.name,'id');assert.equal(raw.arguments[0].right?.value,'');
 assert.equal(name(declaration(download,'cleaned').init?.callee),'_cleanFilename');
 assert.deepEqual(declaration(download,'cleaned').init.arguments.map(name),['raw']);
 const downloadBase=declaration(download,'base').init;assert.equal(downloadBase?.type,'ConditionalExpression');
 assert.equal(downloadBase.test?.operator,'&&');assert.equal(downloadBase.consequent?.callee?.object?.name,'path');
 assert.equal(downloadBase.test.left?.name,'kind');
 assert.equal(name(downloadBase.test.right?.object),'KIND_DIRS');assert.equal(downloadBase.test.right?.property?.name,'kind');
 assert.equal(downloadBase.test.right?.computed,true);
 assert.equal(name(downloadBase.consequent.callee),'path.join');
 assert.deepEqual(downloadBase.consequent.arguments.map(name),['uploadRoot',null]);
 assert.equal(name(downloadBase.consequent.arguments[1]?.object),'KIND_DIRS');
 assert.equal(downloadBase.consequent.arguments[1]?.property?.name,'kind');
 assert.equal(downloadBase.consequent.arguments[1]?.computed,true);
 assert.equal(downloadBase.alternate?.name,'uploadRoot');
 const resolved=declaration(download,'abs').init;assert.equal(name(resolved.callee),'path.resolve');
 assert.deepEqual(resolved.arguments.map(name),['base','cleaned']);
 const stat=calls(download,'fs.statSync')[0],read=calls(download,'fs.readFileSync')[0];
 assert.deepEqual(stat.arguments.map(name),['abs']);assert.deepEqual(read.arguments.map(name),['abs']);
 assert.equal(declaration(download,'st').init,stat);assert.equal(declaration(download,'buf').init,read);
 assert.ok(stat.start<read.start);const guards=visit(download,n=>n.type==='IfStatement'&&n.end<read.start);
 assert.equal(guards.some(n=>name(n.test?.callee)==='st.isDirectory'&&property(n.consequent?.argument,'error')?.value?.value==='is directory'),true);
 assert.equal(guards.some(n=>n.test?.operator==='>'&&name(n.test.left)==='st.size'
  &&(overrides[handlerFile]??source(handlerFile)).slice(n.test.right.start,n.test.right.end)==='5 * 1024 * 1024'
  &&property(n.consequent?.argument,'error')?.value?.value==='file too large'),true);
 const readback=visit(download,n=>n.type==='ReturnStatement'&&n.argument?.type==='ObjectExpression'
  &&property(n.argument,'ok')?.value?.value===true
  &&name(property(n.argument,'id')?.value)==='raw'
  &&name(property(n.argument,'abs')?.value)==='abs'
  &&name(property(n.argument,'cleaned')?.value)==='cleaned'
  &&name(property(n.argument,'size')?.value)==='st.size'
  &&name(property(n.argument,'body_base64')?.value?.callee)==='buf.toString');assert.equal(readback.length,1);
 const mime=calls(readback[0].argument,'_guessMime');assert.equal(mime.length,1);
 assert.deepEqual(mime[0].arguments.map(name),['abs']);
 assert.equal(property(readback[0].argument,'body_base64').value.arguments[0]?.value,'base64');
 const preview=property(readback[0].argument,'body_utf8')?.value;
 assert.equal(preview?.type,'ConditionalExpression');assert.equal(name(preview.test?.callee),'_isTextLike');
 assert.deepEqual(preview.test.arguments.map(name),['abs']);assert.equal(preview.consequent?.callee?.property?.name,'slice');
 assert.deepEqual(preview.consequent.arguments.map(staticValue),[0,20000]);
 assert.equal(name(preview.consequent.callee.object?.callee),'buf.toString');
 assert.equal(preview.consequent.callee.object.arguments[0]?.value,'utf8');
 assert.equal(visit(download,n=>n.type==='CatchClause'&&n.param?.name==='e'
  &&visit(n.body,x=>x.type==='ReturnStatement'&&property(x.argument,'ok')?.value?.value===false
   &&name(property(x.argument,'id')?.value)==='raw'
   &&name(property(x.argument,'cleaned')?.value)==='cleaned'
   &&name(property(x.argument,'abs')?.value)==='abs'
   &&name(property(x.argument,'error')?.value)==='e.message').length===1).length,1);
}
function v23(overrides={},data=manifest){
 assert.deepEqual(data.v23Binding,{roleChatFile:ROLE,compositionFile:COMPOSITION,adapterFile:ADAPTER,
  capabilityFile:CAPABILITY,legacyToolFile:HANDLER,sourceOnly:true,nativeEvidence:null});
 const role=tree(ROLE,overrides),offered=declaration(role,'ORIGINAL_REGISTER_TOOL').init.arguments[0];
 assert.deepEqual([property(offered,'agent')?.value?.value,property(offered,'tool')?.value?.value],['mcp-registry','register']);
 const declared=declaration(role,'declared').init;
 assert.equal(declared.type,'ConditionalExpression');
 assert.equal(visit(declared,n=>n.type==='BinaryExpression'&&n.operator==='==='&&n.left?.name==='role'&&n.right?.value==='admin').length,1);
 const frozen=calls(declared,'Object.freeze');assert.equal(frozen.length,1);
 assert.equal(declared.consequent,frozen[0]);
 assert.equal(frozen[0].arguments[0]?.type,'ArrayExpression');
 assert.deepEqual(frozen[0].arguments[0].elements.map(element=>element.type==='SpreadElement'?`...${name(element.argument.object)}[${name(element.argument.property)}]`:name(element)),
  ['...tools[role]','ORIGINAL_REGISTER_TOOL']);
 assert.equal(declared.alternate?.type,'MemberExpression');
 assert.equal(name(declared.alternate.object),'tools');assert.equal(name(declared.alternate.property),'role');
 const available=declaration(role,'available').init;
 const registryCase=visit(available,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&name(n.test.left)==='tool.agent'&&n.test.right?.value==='mcp-registry');
 assert.equal(registryCase.length,1,'registry offered only through explicit predicate');
 const predicate=registryCase[0].consequent;
 assert.equal((overrides[ROLE]??source(ROLE)).slice(predicate.start,predicate.end),
  "return role==='admin'&&!selected&&!!mcpRegistryChat&&mcpRegistrationApplication?.()?.ready===true;",
  'registry availability requires admin, no selection, chat and exact ready application');
 const invocation=visit(role,n=>n.type==='ArrayExpression'&&n.elements.some(e=>e?.type==='ArrayExpression'
  &&e.elements[0]?.value==='mcp-registry.register'));
 assert.ok(invocation.length>=1,'original tool dispatch exists');
 const selected=calls(invocation[0],'adapter.invoke');assert.equal(selected.length,1,'selected call enters adapter');
 assert.deepEqual(selected[0].arguments.map(name),['args','invocation'],'original selected arguments reach adapter');
 const composition=tree(COMPOSITION,overrides);
 const health=calls(composition,'infrastructure.client.registrationHealth');assert.equal(health.length,1);
 assert.equal(visit(composition,n=>n.type==='AwaitExpression'&&n.argument===health[0]).length,1,'await executor health');
 const created=visit(composition,n=>n.type==='AssignmentExpression'&&name(n.left)==='createdOriginalRegistration'
  &&name(n.right?.callee)==='Object.freeze');
 assert.equal(created.length,1,'ready original registration application');
 const readyObject=created[0].right.arguments[0];
 assert.equal(property(readyObject,'ready')?.value?.value,true);
 const createAdapter=property(readyObject,'create')?.value;
 assert.equal(createAdapter?.type,'ArrowFunctionExpression');
 const trusted=calls(createAdapter,'require').filter(c=>c.arguments[0]?.value==='./secureshopV23RegisterAdapter');
 assert.equal(trusted.length,1);
 assert.equal(visit(createAdapter,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
  &&n.callee.object===trusted[0]&&n.callee.property?.name==='createV23RegisterAdapter').length,1);
 assert.ok(health[0].start<created[0].start,'health gates published adapter');
 const guarded=visit(composition,n=>n.type==='TryStatement'
  &&visit(n.block,x=>x===health[0]).length===1
  &&visit(n.block,x=>x===created[0]).length===1);
 assert.ok(guarded.some(n=>n.end-n.start<2000),'health and adapter publication share local guarded try');
 assert.equal(visit(composition,n=>n.type==='IfStatement'&&n.test?.name==='registryEnabled'
  &&visit(n.consequent,x=>x===created[0]).length===1).length,1,'registry feature gate contains adapter publication');
 const adapter=tree(ADAPTER,overrides),invoke=fn(adapter,'invoke');
 const issued=calls(invoke,'createOwnerScopedRegisterCapability');assert.equal(issued.length,1);
 const dispatchBridge=property(issued[0].arguments[0],'dispatch')?.value;
 assert.equal(dispatchBridge?.type,'ArrowFunctionExpression');
 assert.deepEqual(dispatchBridge.params.map(name),['original']);
 assert.equal(name(dispatchBridge.body?.callee),'submit');
 assert.deepEqual(dispatchBridge.body.arguments.map(name),['original','selection','controller.signal'],
  'issued capability dispatches original selection to owned submit');
 const original=calls(invoke,'originalRegister');assert.equal(original.length,1);
 assert.deepEqual(original[0].arguments.map(name),['args','capability'],'issued capability is passed with original args');
 assert.equal(calls(invoke,'adapter.invoke').length,0);
 const submit=fn(adapter,'submit');
 const prepared=calls(submit,'registrationJournal.prepare'),admitted=calls(submit,'launches.admitOwnedMcpRegistration');
 const mutated=calls(submit,'ownedMcpRegistry.mutate'),settled=calls(submit,'registrationJournal.settlePrepared');
 assert.equal(prepared.length,1);assert.equal(admitted.length,1);assert.equal(mutated.length,1);
 assert.ok(settled.length>=1,'V23 retained settlement paths');
 for(const call of [admitted[0],mutated[0]])assert.equal(visit(submit,n=>n.type==='AwaitExpression'&&n.argument===call).length,1,`await ${name(call.callee)}`);
 assert.ok(prepared[0].start<admitted[0].start&&admitted[0].start<mutated[0].start,'admission precedes effect');
 const receiptCheck=visit(submit,n=>n.type==='IfStatement'
  &&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='!=='&&name(x.left)==='operation.state'&&x.right?.value==='completed').length===1
  &&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='!=='&&name(x.left)==='operation.operationId'&&x.right?.name==='operationId').length===1
  &&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='!=='&&name(x.left)==='operation.requestSha256'&&x.right?.name==='requestSha256').length===1);
 assert.equal(receiptCheck.length,1,'same-ID completed operation required');
 assert.equal(visit(receiptCheck[0].consequent,n=>n.type==='ThrowStatement'
  &&name(n.argument?.callee)==='fail'&&n.argument.arguments[0]?.value==='V23_REGISTRATION_PUBLICATION_INVALID').length,1,
  'invalid publication throws before success');
 const success=visit(submit,n=>n.type==='ReturnStatement'&&name(n.argument?.callee)==='Object.freeze'
  &&property(n.argument.arguments[0],'operationId')?.value?.name==='operationId'
  &&property(n.argument.arguments[0],'requestSha256')?.value?.name==='requestSha256'
  &&property(n.argument.arguments[0],'receipt')?.value?.name==='operation');
 assert.equal(success.length,1,'success returns checked operation and digest');
 assert.ok(mutated[0].start<receiptCheck[0].start&&receiptCheck[0].start<success[0].start);
 const capability=tree(CAPABILITY,overrides),create=fn(capability,'createOwnerScopedRegisterCapability');
 assert.equal(calls(create,'issued.add').filter(c=>c.arguments[0]?.name==='capability').length,1,'issued capability registered');
 const verifier=fn(capability,'isOwnerScopedRegisterCapability');
 assert.equal(calls(verifier,'issued.has').filter(c=>c.arguments[0]?.name==='value').length,1,'legacy checker recognizes issued capability');
 const execute=visit(create,n=>n.type==='ObjectMethod'&&n.key?.name==='execute');assert.equal(execute.length,1);
 const fixed=visit(execute[0],n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&n.test.left?.name==='mode'&&n.test.right?.value==='fixed');
 assert.equal(fixed.length,1,'Fixed branch must remain denial');
 const denial=fixed[0].consequent?.type==='ReturnStatement'?fixed[0].consequent:
  fixed[0].consequent?.type==='BlockStatement'&&fixed[0].consequent.body.length===1?fixed[0].consequent.body[0]:null;
 assert.equal(denial?.type,'ReturnStatement','Fixed branch returns before dispatch');
 assert.equal(name(denial.argument?.callee),'Object.freeze');
 assert.equal(property(denial.argument.arguments[0],'effectNotStarted')?.value?.value,true);
 assert.equal(property(denial.argument.arguments[0],'error')?.value?.value,'V23_FIXED_STDIO_DENIED');
 const dispatch=calls(execute[0],'dispatch');assert.equal(dispatch.length,1);
 assert.ok(fixed[0].start<dispatch[0].start,'Fixed denial precedes executor dispatch');
 assert.equal(visit(execute[0],n=>n.type==='BinaryExpression'&&n.operator==='!=='
  &&name(n.left)==='result.isolation'&&n.right?.value==='owned-mcp-registry-v1').length,1);
 const receipt=visit(execute[0],n=>n.type==='IfStatement'&&visit(n.test,x=>x.type==='BinaryExpression'
  &&name(x.left)==='result.ok'&&x.operator==='!=='&&x.right?.value===true).length===1
  &&visit(n.test,x=>x.type==='BinaryExpression'&&name(x.left)==='result.command'
   &&x.operator==='!=='&&name(x.right)==='request.stdio_cmd').length===1
  &&visit(n.test,x=>x.type==='UnaryExpression'&&x.operator==='!'
   &&name(x.argument)==='result.operationId').length===1);
 assert.equal(receipt.length,1,'receipt must include successful effect, operation ID and exact command');
 assert.equal(visit(receipt[0].consequent,n=>n.type==='ThrowStatement'
  &&name(n.argument?.callee)==='uncertain'
  &&name(n.argument.arguments[0]?.callee)==='fail'
  &&n.argument.arguments[0].arguments[0]?.value==='V23_EXECUTION_RECEIPT_INVALID').length,1,
  'invalid executor receipt throws before return');
 assert.ok(dispatch[0].start<receipt[0].start,'receipt checked after dispatch');
}
function userManagement(overrides={},data=manifest){
 const SERVER='agent-host/agents/user-management/server.js';
 const WRAPPER='agent-host/agents/user-management/tools/index.js';
 const HANDLER_FILE='agent-host/agents/user-management/tools/index.postgres.js';
 const DB='server/database/postgres/secureshopCommerceDb.js';
 const all=Object.entries(userManagementPins);
 for(const [file,pins] of all){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [id,expected] of Object.entries(pins)){
   const matches=visit(ast,n=>(n.type==='FunctionDeclaration'||n.type==='VariableDeclarator')&&n.id?.name===id
    ||n.type==='ObjectMethod'&&n.key?.name===id);
   assert.equal(matches.length,1,`${file} exact scoped ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: selected effect/readback branch drift requires fresh source review`);
  }
 }
 const server=tree(SERVER,overrides),tools=declaration(server,'TOOLS').init;
 assert.equal(tools.type,'ArrayExpression');
 const wrapper=tree(WRAPPER,overrides);
 assert.equal(visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports'
  &&name(n.right?.callee)==='require'&&n.right.arguments[0]?.value==='./index.postgres.js').length,1,
  'public tool wrapper reaches reviewed PostgreSQL handlers');
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init;
 assert.deepEqual(visit(roleMap,n=>n.type==='ObjectProperty'&&n.key?.name==='admin')
  .flatMap(n=>visit(n.value,x=>x.type==='StringLiteral'&&x.value==='user-management')).length,1,
  'admin catalog advertises user-management');
 assert.equal(visit(roleMap,n=>n.type==='ObjectProperty'&&['customer','merchant'].includes(n.key?.name)
  &&visit(n.value,x=>x.type==='StringLiteral'&&x.value==='user-management').length>0).length,0,
  'customer/merchant catalogs do not advertise user-management');
 for(const [id,handler,consequence,applicability] of userManagementReview){
  const row=data.reviewedUserManagement.find(r=>r.id===id);
  assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(row,{id,handler,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:userManagementSchemas[id],advertisedRoles:['admin'],hostGateRoles:[],
   effectCalls:['commerce.userAction','commerce.deliverAudit'],consequence,applicability,
   originalCheckIds:[],objectiveIds:[],nativeEvidence:null},`${id} source-only claim`);
  const tool=tools.elements.find(entry=>property(entry,'name')?.value?.value===id.split('.')[1]);
  assert.ok(tool,`${id} advertised in executable catalog`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),userManagementSchemas[id],`${id} exact advertised schema`);
 }
 // The AST-local pins above cover all four switch cases, the four selected
 // handlers, common audit wrapper, SQL/outbox transaction, and delivery return.
 // Explicitly retain the semantic distinction that lookup drops pending state.
 const handlerAst=tree(HANDLER_FILE,overrides);
 assert.equal(visit(fn(handlerAst,'lookup'),n=>n.type==='ObjectProperty'&&n.key?.name==='audit_delivery_pending').length,0);
 for(const handler of ['setRole','resetPassword','ban'])
  assert.equal(visit(fn(handlerAst,handler),n=>n.type==='ObjectProperty'&&n.key?.name==='audit_delivery_pending').length,2,
   `${handler} conditionally returns audit delivery pending`);
 assert.equal(visit(fn(tree(DB,overrides),'createSecureShopCommerceDb'),n=>n.type==='ObjectMethod'
  &&n.key?.name==='userAction').length,1,'reviewed user-action transaction belongs to commerce repository');
}
function system(overrides={},data=manifest){
 const SERVER='agent-host/agents/system/server.js',TOOLS_FILE='agent-host/agents/system/tools/index.js';
 for(const [file,pins] of Object.entries(systemPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [id,expected] of Object.entries(pins)){
   const matches=visit(ast,n=>(n.type==='FunctionDeclaration'||n.type==='VariableDeclarator')&&n.id?.name===id);
   assert.equal(matches.length,1,`${file} exact scoped ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: selected guard/effect/readback drift requires renewed source review`);
  }
 }
 const server=tree(SERVER,overrides),declared=declaration(server,'TOOLS').init;
 assert.equal(declared.type,'ArrayExpression');
 const selectedImport=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.some(p=>p.key?.name==='restart_service'));
 assert.equal(selectedImport.length,1,'system server has one selected-tool import');
 assert.deepEqual(selectedImport[0].id.properties.map(p=>p.key?.name),
  ['health_check','restart_service','run_diagnostic','read_config'],'all dispatch names come from reviewed tool module');
 assert.equal(name(selectedImport[0].init?.callee),'require');
 assert.equal(selectedImport[0].init.arguments[0]?.value,'./tools/index.js','MCP handlers reach reviewed implementation');
 const callerImport=visit(server,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.some(p=>p.key?.name==='enforceRole'));
 assert.equal(callerImport.length,1,'system server has one selected caller-context import');
 assert.deepEqual(callerImport[0].id.properties.map(p=>p.key?.name),['extractCaller','enforceRole']);
 assert.equal(name(callerImport[0].init?.callee),'require');
 assert.equal(callerImport[0].init.arguments[0]?.value,'../../shared/callerContext.js',
  'published guard reaches reviewed caller-context helper');
 const toolsAst=tree(TOOLS_FILE,overrides);
 const callerAst=tree('agent-host/shared/callerContext.js',overrides);
 function exportsExactly(ast,expected,label){
  const exported=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(exported.length,1,`${label} has one public export`);
  assert.equal(exported[0].right?.type,'ObjectExpression');
  assert.deepEqual(exported[0].right.properties.map(p=>{
   assert.equal(p.type,'ObjectProperty');assert.equal(p.computed,false);
   assert.equal(p.value?.type,'Identifier');return [p.key?.name,p.value.name];
  }),expected.map(id=>[id,id]),`${label} exports selected source implementations`);
 }
 exportsExactly(server,['createServer'],'MCP server');
 exportsExactly(toolsAst,['health_check','restart_service','run_diagnostic','read_config','BASE'],'system tools');
 exportsExactly(callerAst,['extractCaller','enforceRole','guard','ROLES'],'caller context');
 for(const [id,moduleName] of [['os','node:os'],['fs','node:fs'],['path','node:path']]){
  const imported=declaration(toolsAst,id).init;
  assert.equal(name(imported?.callee),'require',`${id} built-in import`);
  assert.equal(imported.arguments[0]?.value,moduleName,`${id} selected effect implementation`);
 }
 const execImport=visit(toolsAst,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.some(p=>p.key?.name==='exec'));
 assert.equal(execImport.length,1);
 assert.deepEqual(execImport[0].id.properties.map(p=>p.key?.name),['exec']);
 assert.equal(name(execImport[0].init?.callee),'require');
 assert.equal(execImport[0].init.arguments[0]?.value,'node:child_process','shell effect uses child_process.exec');
 const repo=declaration(toolsAst,'REPO').init;
 assert.equal(name(repo?.callee),'path.resolve');
 assert.deepEqual(repo.arguments.map(a=>a.name??a.value),['__dirname','../../../..'],'server base provenance');
 const base=declaration(toolsAst,'BASE').init;
 assert.equal(name(base?.callee),'path.join');
 assert.deepEqual(base.arguments.map(a=>a.name??a.value),['REPO','server'],'selected server file root');
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init;
 assert.equal(visit(roleMap,n=>n.type==='ObjectProperty'&&n.key?.name==='admin'
  &&visit(n.value,x=>x.type==='StringLiteral'&&x.value==='system').length===1).length,1,
  'system advertised to admin');
 assert.equal(visit(roleMap,n=>n.type==='ObjectProperty'&&['customer','merchant'].includes(n.key?.name)
  &&visit(n.value,x=>x.type==='StringLiteral'&&x.value==='system').length>0).length,0,
  'system not advertised to customer or merchant');
 for(const [id,handler,hostGateRolesDefault,effectCalls,consequence,applicability] of systemReview){
  const row=data.reviewedSystem.find(r=>r.id===id);assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(row,{id,handler,serverFile:SERVER,handlerFile:TOOLS_FILE,
   inputSchema:systemSchemas[id],advertisedRoles:['admin'],hostGateRolesDefault,effectCalls,
   consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null},`${id} source-only row`);
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===handler);
  assert.ok(tool,`${id} executable descriptor`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),systemSchemas[id],`${id} exact schema`);
 }
 const create=fn(server,'createServer');
 const hostGuard=visit(create,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='!=='&&n.test.left?.name==='name'&&n.test.right?.value==='health_check');
 assert.equal(hostGuard.length,1,'health exception and three admin-guarded cases');
 assert.equal(calls(hostGuard[0].consequent,'enforceRole').filter(c=>name(c.arguments[0])==='caller'
  &&JSON.stringify(staticValue(c.arguments[1]))===JSON.stringify(['admin'])).length,1);
 assert.equal(visit(hostGuard[0].consequent,n=>n.type==='IfStatement'&&name(n.test)==='denied'
  &&n.consequent?.type==='ReturnStatement'&&name(n.consequent.argument)==='denied').length,1,
  'admin denial returns before selected effects');
 const selected=visit(create,n=>n.type==='SwitchCase'&&n.test?.value&&EXPECTED.system.includes(n.test.value));
 assert.equal(selected.length,4,'four selected system dispatch cases');
 assert.ok(selected.every(n=>n.start>hostGuard[0].start),'non-health guard precedes dispatch');
 const allow=declaration(toolsAst,'ALLOW_EXEC').init;
 assert.equal(allow.type,'BinaryExpression');assert.equal(allow.operator,'===');
 assert.equal(name(allow.left),'process.env.SS_SYSTEM_ALLOW_EXEC');assert.equal(allow.right.value,'true');
 for(const id of ['restart_service','run_diagnostic']){
  const handler=fn(toolsAst,id);
  const guarded=visit(handler,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
   &&n.test.operator==='!'&&name(n.test.argument)==='ALLOW_EXEC');
  assert.equal(guarded.length,1,`${id} module-load exec flag guard`);
  assert.equal(guarded[0].consequent?.type,'BlockStatement');
  assert.equal(guarded[0].consequent.body.length,1,`${id} unconditional guarded branch`);
  const denial=guarded[0].consequent.body[0];
  assert.equal(denial.type,'ReturnStatement',`${id} returns before exec`);
  assert.equal(name(denial.argument?.callee),'resolve');
  assert.equal(property(denial.argument.arguments[0],'executed')?.value?.value,false);
  const execCalls=calls(handler,'exec');assert.equal(execCalls.length,1);
  assert.ok(guarded[0].end<execCalls[0].start,`${id} exec only after guarded return`);
  assert.equal(visit(execCalls[0].arguments[2],n=>n.type==='ObjectProperty'&&n.key?.name==='executed'
   &&n.value?.value===true).length,1,`${id} enabled result truthful`);
  if(id==='run_diagnostic'){
   const side=property(denial.argument.arguments[0],'side_read');
   assert.equal(name(side?.value?.callee),'_mayReadFile');assert.equal(side.value.arguments[0]?.name,'ags');
   assert.equal(calls(execCalls[0],'_mayReadFile').length,0,'enabled branch has no side read');
  }
 }
 const config=fn(toolsAst,'read_config');
 const absolute=visit(config,n=>n.type==='IfStatement'&&calls(n.test,'raw.startsWith').length>0
  &&visit(n.consequent,x=>x.type==='ReturnStatement'&&property(x.argument,'error')?.value?.value==='absolute paths not allowed').length===1);
 assert.equal(absolute.length,1,'absolute input denied before sanitizer');
 const stripped=visit(config,n=>n.type==='VariableDeclarator'&&n.id?.name==='stripped');
 assert.equal(stripped.length,1);assert.ok(absolute[0].start<stripped[0].start);
 assert.equal(calls(config,'fs.readFileSync').filter(c=>c.arguments[0]?.name==='abs'&&c.arguments[1]?.value==='utf8').length,1);
}
function policy(overrides={},data=manifest){
 const SERVER='agent-host/agents/policy/server.js';
 const WRAPPER='agent-host/agents/policy/tools/index.js';
 const HANDLER_FILE='agent-host/agents/policy/tools/index.postgres.js';
 const RENDERER='agent-host/agents/listing/tools/_nunjucksSink.js';
 const DB='server/database/postgres/secureshopCommerceDb.js';
 const LOADER='server/services/secureshop/supervisors/policyLoader.js';
 for(const [file,pins] of Object.entries(policyPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [kind,id,expected] of pins){
   const matches=visit(ast,n=>n.type===kind&&(n.id?.name===id||n.key?.name===id));
   assert.equal(matches.length,1,`${file} exact selected ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: selected source effect/readback drift requires renewed review`);
  }
 }
 function importPattern(ast,keys,required,label){
  const matches=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.some(p=>p.key?.name===keys[0]));
  assert.equal(matches.length,1,`${label} selected import`);
  assert.deepEqual(matches[0].id.properties.map(p=>p.key?.name),keys);
  assert.equal(name(matches[0].init?.callee),'require');
  assert.equal(matches[0].init.arguments[0]?.value,required,`${label} reviewed module`);
 }
 function exportsExactly(ast,ids,label){
  const assignments=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(assignments.length,1,`${label} one public export`);
  assert.equal(assignments[0].right?.type,'ObjectExpression');
  assert.deepEqual(assignments[0].right.properties.map(p=>[p.key?.name,p.value?.name]),ids.map(id=>[id,id]),
   `${label} exports reviewed functions`);
 }
 const server=tree(SERVER,overrides),declared=declaration(server,'TOOLS').init;
 assert.equal(declared.type,'ArrayExpression');
 importPattern(server,['Server'],'../../shared/graphServer.js','MCP server constructor');
 importPattern(server,['ListToolsRequestSchema','CallToolRequestSchema'],'@modelcontextprotocol/sdk/types.js','MCP request schemas');
 importPattern(server,['read_policy','update_policy','apply_policy_to_agents'],'./tools/index.js','server tools');
 importPattern(server,['extractCaller','enforceRole'],'../../shared/callerContext.js','server caller gate');
 exportsExactly(server,['createServer'],'policy server');
 const wrapper=tree(WRAPPER,overrides);
 assert.equal(visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports'
  &&name(n.right?.callee)==='require'&&n.right.arguments[0]?.value==='./index.postgres.js').length,1,
  'public wrapper reaches PostgreSQL handler');
 const handlerAst=tree(HANDLER_FILE,overrides);
 const commerce=declaration(handlerAst,'commerce').init;
 const commerceCall=commerce.callee;
 assert.equal(commerceCall?.type,'MemberExpression');
 assert.equal(commerceCall.property?.name,'getSecureShopCommerceDb');
 assert.equal(name(commerceCall.object?.callee),'require');
 assert.equal(commerceCall.object.arguments[0]?.value,'../../../../server/database/postgres/secureshopCommerceDb');
 importPattern(handlerAst,['renderTemplateUnsafe'],'../../listing/tools/_nunjucksSink.js','unsafe renderer');
 exportsExactly(handlerAst,['read_policy','update_policy','apply_policy_to_agents'],'PostgreSQL policy handlers');
 const renderer=tree(RENDERER,overrides),vm=declaration(renderer,'vm').init;
 assert.equal(name(vm.callee),'require');assert.equal(vm.arguments[0]?.value,'node:vm');
 assert.equal(visit(renderer,n=>n.type==='AssignmentExpression'&&name(n.left)==='njk'
  &&name(n.right?.callee)==='require'&&n.right.arguments[0]?.value==='nunjucks').length,1,
  'Nunjucks renderer selected or VM fallback');
 exportsExactly(renderer,['renderTemplateUnsafe'],'unsafe Nunjucks renderer');
 const loader=tree(LOADER,overrides);
 exportsExactly(loader,['loadForRole','buildPolicyBlock'],'supervisor policy loader');
 const basePrompt=tree('server/services/secureshop/supervisors/basePrompt.js',overrides);
 exportsExactly(basePrompt,['ROLE_PROMPTS','buildBasePrompt'],'supervisor base prompt');
 for(const file of ['adminSupervisor.js','customerSupervisor.js','merchantSupervisor.js']){
  const ast=tree(`server/services/secureshop/supervisors/${file}`,overrides);
  assert.ok(visit(ast,n=>n.type==='ObjectProperty'&&n.key?.name==='buildPolicyBlock'
   &&n.value?.type==='MemberExpression'&&n.value.property?.name==='buildPolicyBlock'
   &&name(n.value.object?.callee)==='require'&&n.value.object.arguments[0]?.value==='./policyLoader.js').length>=1,
   `${file} later prompt builder is wired from reviewed loader`);
  assert.ok(visit(ast,n=>n.type==='ObjectProperty'&&n.key?.name==='buildBasePrompt'
   &&n.value?.type==='MemberExpression'&&n.value.property?.name==='buildBasePrompt'
   &&name(n.value.object?.callee)==='require'&&n.value.object.arguments[0]?.value==='./basePrompt.js').length>=1,
   `${file} base prompt uses reviewed extra-content builder`);
 }
 const graph=tree('server/agent-runtime/secureshopSupervisorGraph.js',overrides);
 const policyPrompt=visit(graph,n=>n.type==='AssignmentExpression'&&n.left?.name==='systemPrompt'
  &&name(n.right?.callee)==='buildBasePrompt'
  &&property(n.right.arguments[1],'extra')?.value?.type==='AwaitExpression'
  &&name(property(n.right.arguments[1],'extra').value.argument?.callee)==='buildPolicyBlock'
  &&property(n.right.arguments[1],'extra').value.argument.arguments[0]?.name==='role');
 assert.equal(policyPrompt.length,1,'later graph places awaited role policy block in system prompt');
 const repository=tree(DB,overrides);
 exportsExactly(repository,['createSecureShopCommerceDb','getSecureShopCommerceDb'],'commerce repository');
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init;
 assert.equal(visit(roleMap,n=>n.type==='ObjectProperty'&&n.key?.name==='admin'
  &&visit(n.value,x=>x.type==='StringLiteral'&&x.value==='policy').length===1).length,1);
 assert.equal(visit(roleMap,n=>n.type==='ObjectProperty'&&['customer','merchant'].includes(n.key?.name)
  &&visit(n.value,x=>x.type==='StringLiteral'&&x.value==='policy').length>0).length,0);
 for(const [id,handler,effectCalls,consequence,applicability] of policyReview){
  const row=data.reviewedPolicy.find(r=>r.id===id);assert.ok(row,`${id} reviewed row`);
  assert.deepEqual(row,{id,handler,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:policySchemas[id],advertisedRoles:['admin'],hostGateRolesDefault:['admin'],effectCalls,
   consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===handler);
  assert.ok(tool,`${id} executable tool`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),policySchemas[id]);
 }
 const create=fn(server,'createServer');
 const callsToGuard=calls(create,'enforceRole').filter(c=>c.arguments[0]?.name==='caller'
  &&JSON.stringify(staticValue(c.arguments[1]))===JSON.stringify(['admin']));
 assert.equal(callsToGuard.length,1);
 const deny=visit(create,n=>n.type==='IfStatement'&&n.test?.name==='denied'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');
 assert.equal(deny.length,1,'admin denial returns before effects');
 assert.ok(deny[0].start<visit(create,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name')[0].start);
 const apply=fn(handlerAst,'apply_policy_to_agents');
 const parseCatch=visit(apply,n=>n.type==='CatchClause'&&visit(n.body,x=>x.type==='AssignmentExpression'
  &&name(x.left)==='targets'&&x.right?.type==='ArrayExpression').length===1);
 assert.equal(parseCatch.length,1,'malformed JSON becomes empty targets');
 assert.equal(calls(parseCatch[0],'targets.includes').length,0,'non-array valid JSON not caught here');
 assert.equal(calls(apply,'targets.includes').length,1,'truthy-role non-array value can throw during filtering');
}
function pricingStrategy(overrides={},data=manifest){
 const SERVER='agent-host/agents/pricing-strategy/server.js';
 const WRAPPER='agent-host/agents/pricing-strategy/tools/index.js';
 const HANDLER_FILE='agent-host/agents/pricing-strategy/tools/index.postgres.js';
 for(const [file,pins] of Object.entries(pricingStrategyPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [kind,id,expected] of pins){
   const matches=visit(ast,n=>n.type===kind&&(n.id?.name===id||n.key?.name===id));
   assert.equal(matches.length,1,`${file} selected pricing node ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: pricing selected path drift requires renewed review`);
  }
 }
 const server=tree(SERVER,overrides);
 function imported(ast,names,from){
  const matches=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.map(p=>p.key?.name).join(',')===names.join(','));
  assert.equal(matches.length,1,`${from} selected import ${names}`);
  assert.deepEqual(matches[0].id.properties.map(p=>[p.key?.name,p.value?.name,p.shorthand]),
   names.map(id=>[id,id,true]),`${from} imports exact local handler names`);
  assert.equal(name(matches[0].init?.callee),'require');
  assert.equal(matches[0].init.arguments[0]?.value,from);
 }
 function exported(ast,names){
  const matches=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(matches.length,1,'one reviewed pricing export');
  assert.equal(matches[0].right?.type,'ObjectExpression');
  assert.deepEqual(matches[0].right.properties.map(p=>[p.key?.name,p.value?.name]),names.map(n=>[n,n]));
 }
 imported(server,['Server'],'../../shared/graphServer.js');
 imported(server,['ListToolsRequestSchema','CallToolRequestSchema'],'@modelcontextprotocol/sdk/types.js');
 imported(server,['suggest_price','run_pricing_experiment'],'./tools/index.js');
 imported(server,['extractCaller','enforceRole'],'../../shared/callerContext.js');
 exported(server,['createServer']);
 const wrapper=tree(WRAPPER,overrides);
 const wrapperExports=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
 assert.equal(wrapperExports.length,1,'one MCP pricing wrapper export');
 assert.equal(name(wrapperExports[0].right?.callee),'require');
 assert.equal(wrapperExports[0].right.arguments[0]?.value,'./index.postgres.js',
  'MCP pricing wrapper reaches selected PostgreSQL handlers');
 const handlers=tree(HANDLER_FILE,overrides),commerce=declaration(handlers,'commerce').init;
 assert.equal(commerce.callee?.property?.name,'getSecureShopCommerceDb');
 assert.equal(name(commerce.callee.object?.callee),'require');
 assert.equal(commerce.callee.object.arguments[0]?.value,'../../../../server/database/postgres/secureshopCommerceDb');
 exported(handlers,['suggest_price','run_pricing_experiment','_extractTargetPrice']);
 const repository=tree('server/database/postgres/secureshopCommerceDb.js',overrides);
 exported(repository,['createSecureShopCommerceDb','getSecureShopCommerceDb']);
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin']){
  const value=property(roleMap,role)?.value;
  assert.equal(value?.type,'ArrayExpression');
  assert.equal(visit(value,n=>n.type==='StringLiteral'&&n.value==='pricing-strategy').length,role==='merchant'?1:0,
   `${role} pricing advertisement`);
 }
 const declared=declaration(server,'TOOLS').init;
 for(const [id,handler,effectCalls,consequence,applicability] of pricingStrategyReview){
  const row=data.reviewedPricingStrategy.find(r=>r.id===id);
  assert.deepEqual(row,{id,handler,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:pricingStrategySchemas[id],advertisedRoles:['merchant'],hostGateRolesDefault:['merchant','admin'],
   effectCalls,consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===handler);
  assert.ok(tool,`${id} selected descriptor`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),pricingStrategySchemas[id]);
 }
 const create=fn(server,'createServer');
 const guarded=calls(create,'enforceRole').filter(call=>call.arguments[0]?.name==='caller'
  &&JSON.stringify(staticValue(call.arguments[1]))===JSON.stringify(['merchant','admin']));
 assert.equal(guarded.length,1,'pricing synchronous host guard');
 const denied=visit(create,n=>n.type==='IfStatement'&&n.test?.name==='denied'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');
 assert.equal(denied.length,1,'pricing denial returns before switch');
 assert.ok(guarded[0].start<denied[0].start);
 const dispatch=visit(create,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');
 assert.equal(dispatch.length,1);assert.ok(denied[0].start<dispatch[0].start);
 for(const [id,handler] of pricingStrategyReview){
  const cases=dispatch[0].cases.filter(c=>c.test?.value===handler);
  assert.equal(cases.length,1,`${id} exact switch case`);
  const ret=cases[0].consequent[0];assert.equal(ret?.type,'ReturnStatement');
  assert.equal(name(ret.argument?.callee),'_wrap');
  const awaited=ret.argument.arguments[0];assert.equal(awaited?.type,'AwaitExpression');
  assert.equal(name(awaited.argument?.callee),handler);
  assert.equal(name(awaited.argument.arguments[0]?.left),'args');
  assert.equal(awaited.argument.arguments[0]?.operator,'||');
  assert.equal(awaited.argument.arguments[0]?.right?.type,'ObjectExpression');
 }
}
function analytics(overrides={},data=manifest){
 const SERVER='agent-host/agents/analytics/server.js';
 const WRAPPER='agent-host/agents/analytics/tools/index.js';
 const HANDLER_FILE='agent-host/agents/analytics/tools/index.postgres.js';
 const DB='server/database/postgres/secureshopCommerceDb.js';
 for(const [file,pins] of Object.entries(analyticsPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [kind,id,expected] of pins){
   const matches=visit(ast,n=>n.type===kind&&(n.id?.name===id||n.key?.name===id));
   assert.equal(matches.length,1,`${file} selected analytics node ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: analytics selected path drift requires renewed review`);
  }
 }
 const server=tree(SERVER,overrides),handler=tree(HANDLER_FILE,overrides),wrapper=tree(WRAPPER,overrides),repository=tree(DB,overrides);
 function imported(ast,ids,from){
  const matches=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.map(p=>p.key?.name).join(',')===ids.join(','));
  assert.equal(matches.length,1,`${from} exact analytics import`);
  assert.deepEqual(matches[0].id.properties.map(p=>[p.key?.name,p.value?.name,p.shorthand]),ids.map(id=>[id,id,true]));
  assert.equal(name(matches[0].init?.callee),'require');assert.equal(matches[0].init.arguments[0]?.value,from);
 }
 function exported(ast,ids){
  const matches=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(matches.length,1,'one selected analytics export');
  assert.equal(matches[0].right?.type,'ObjectExpression');
  assert.deepEqual(matches[0].right.properties.map(p=>[p.key?.name,p.value?.name]),ids.map(id=>[id,id]));
 }
 imported(server,['Server'],'../../shared/graphServer.js');
 imported(server,['ListToolsRequestSchema','CallToolRequestSchema'],'@modelcontextprotocol/sdk/types.js');
 imported(server,['nl_query','top_products','revenue_breakdown'],'./tools/index.js');
 imported(server,['extractCaller','enforceRole'],'../../shared/callerContext.js');
 exported(server,['createServer']);
 const wrapperExports=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
 assert.equal(wrapperExports.length,1,'one analytics wrapper export');
 assert.equal(name(wrapperExports[0].right?.callee),'require');
 assert.equal(wrapperExports[0].right.arguments[0]?.value,'./index.postgres.js');
 const commerce=declaration(handler,'commerce').init;
 assert.equal(commerce.callee?.property?.name,'getSecureShopCommerceDb');
 assert.equal(name(commerce.callee.object?.callee),'require');
 assert.equal(commerce.callee.object.arguments[0]?.value,'../../../../server/database/postgres/secureshopCommerceDb');
 assert.equal(declaration(handler,'_aiService').init?.type,'NullLiteral',
  'Analytics provider cache starts null so lazy import/fallback follows reviewed path');
 exported(handler,['nl_query','top_products','revenue_breakdown','_translate']);
 imported(repository,['withTransaction'],'./index');
 exported(repository,['createSecureShopCommerceDb','getSecureShopCommerceDb']);
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin']){
  const value=property(roleMap,role)?.value;assert.equal(value?.type,'ArrayExpression');
  assert.equal(visit(value,n=>n.type==='StringLiteral'&&n.value==='analytics').length,role==='customer'?0:1,
   `${role} Analytics advertisement`);
 }
 const declared=declaration(server,'TOOLS').init;
 for(const [id,handlerName,effectCalls,consequence,applicability] of analyticsReview){
  const row=data.reviewedAnalytics.find(r=>r.id===id);
  assert.deepEqual(row,{id,handler:handlerName,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:analyticsSchemas[id],advertisedRoles:['merchant','admin'],hostGateRolesDefault:['merchant','admin'],
   effectCalls,consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===handlerName);
  assert.ok(tool,`${id} selected descriptor`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),analyticsSchemas[id]);
 }
 const create=fn(server,'createServer');
 const guards=calls(create,'enforceRole').filter(c=>c.arguments[0]?.name==='caller'
  &&JSON.stringify(staticValue(c.arguments[1]))===JSON.stringify(['merchant','admin']));
 assert.equal(guards.length,1,'analytics synchronous conditional Layer-C gate');
 const denied=visit(create,n=>n.type==='IfStatement'&&n.test?.name==='denied'
  &&n.consequent?.type==='ReturnStatement'&&n.consequent.argument?.name==='denied');
 assert.equal(denied.length,1,'selected denial returned');
 const switches=visit(create,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');
 assert.equal(switches.length,1);assert.ok(guards[0].start<denied[0].start&&denied[0].start<switches[0].start);
 for(const [,handlerName] of analyticsReview){
  const cases=switches[0].cases.filter(c=>c.test?.value===handlerName);assert.equal(cases.length,1);
  const ret=cases[0].consequent[0];assert.equal(ret?.type,'ReturnStatement');
  assert.equal(name(ret.argument?.callee),'_wrap');
  const selected=ret.argument.arguments[0];assert.equal(selected?.type,'AwaitExpression');
  assert.equal(name(selected.argument?.callee),handlerName);
  const args=selected.argument.arguments[0];assert.equal(args?.type,'LogicalExpression');
  assert.equal(args.operator,'||');assert.equal(name(args.left),'args');assert.equal(args.right?.type,'ObjectExpression');
 }
 const sql=fn(handler,'nl_query');
 const opted=visit(sql,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&name(n.test.left)==='process.env.SS_ANALYTICS_LLM_ENABLED'
  &&n.test.right?.value==='true');
 assert.equal(opted.length,1,'LLM translator is exact opt-in');
 assert.equal(calls(opted[0].consequent,'_translateWithLLM').length,1);
 const fallback=visit(sql,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
  &&n.test.operator==='!'&&n.test.argument?.name==='t'
  &&calls(n.consequent,'_translate').length===1);
 assert.equal(fallback.length,1,'only null translation falls back before SQL execution');
 assert.ok(opted[0].start<fallback[0].start&&fallback[0].start<calls(sql,'commerce.readTeachingQuery')[0].start);
 const read=fn(repository,'createSecureShopCommerceDb');
 assert.equal(calls(read,'withTransaction').length>=1,true,'selected READ ONLY helper bound to transaction import');
}
function priceAdvisor(overrides={},data=manifest){
 const SERVER='agent-host/agents/price-advisor/server.js';
 const WRAPPER='agent-host/agents/price-advisor/tools/index.js';
 const HANDLER_FILE='agent-host/agents/price-advisor/tools/index.postgres.js';
 for(const [file,pins] of Object.entries(priceAdvisorPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [kind,id,expected] of pins){
   const matches=visit(ast,n=>n.type===kind&&(n.id?.name===id||n.key?.name===id));
   assert.equal(matches.length,1,`${file} selected advisor node ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: selected Price Advisor source drift requires renewed review`);
  }
 }
 const server=tree(SERVER,overrides),handler=tree(HANDLER_FILE,overrides),wrapper=tree(WRAPPER,overrides);
 function imported(ast,ids,from){
  const matches=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.map(p=>p.key?.name).join(',')===ids.join(','));
  assert.equal(matches.length,1,`${from} exact Advisor import`);
  assert.deepEqual(matches[0].id.properties.map(p=>[p.key?.name,p.value?.name,p.shorthand]),ids.map(id=>[id,id,true]));
  assert.equal(name(matches[0].init?.callee),'require');assert.equal(matches[0].init.arguments[0]?.value,from);
 }
 function exported(ast,ids){
  const matches=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(matches.length,1,'one reviewed Advisor export');
  assert.equal(matches[0].right?.type,'ObjectExpression');
  assert.deepEqual(matches[0].right.properties.map(p=>[p.key?.name,p.value?.name]),ids.map(id=>[id,id]));
 }
 imported(server,['Server'],'../../shared/graphServer.js');
 imported(server,['ListToolsRequestSchema','CallToolRequestSchema'],'@modelcontextprotocol/sdk/types.js');
 imported(server,['priceHistory','findDeals','compareCompetitor'],'./tools/index.js');
 imported(server,['extractCaller'],'../../shared/callerContext.js');
 exported(server,['createServer']);
 const wrapperExports=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
 assert.equal(wrapperExports.length,1,'one Advisor wrapper export');
 assert.equal(name(wrapperExports[0].right?.callee),'require');
 assert.equal(wrapperExports[0].right.arguments[0]?.value,'./index.postgres.js');
 const commerce=declaration(handler,'commerce').init;
 assert.equal(commerce.callee?.property?.name,'getSecureShopCommerceDb');
 assert.equal(name(commerce.callee.object?.callee),'require');
 assert.equal(commerce.callee.object.arguments[0]?.value,'../../../../server/database/postgres/secureshopCommerceDb');
 for(const [id,mod] of [['http','node:http'],['https','node:https']]){
  const value=declaration(handler,id).init;assert.equal(name(value?.callee),'require');
  assert.equal(value.arguments[0]?.value,mod,`${id} selected protocol module`);
 }
 imported(handler,['URL'],'node:url');
 exported(handler,['priceHistory','findDeals','compareCompetitor']);
 const repo=tree('server/database/postgres/secureshopCommerceDb.js',overrides);
 exported(repo,['createSecureShopCommerceDb','getSecureShopCommerceDb']);
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin']){
  const value=property(roleMap,role)?.value;assert.equal(value?.type,'ArrayExpression');
  assert.equal(visit(value,n=>n.type==='StringLiteral'&&n.value==='price-advisor').length,role==='customer'?1:0,
   `${role} Price Advisor advertisement`);
 }
 const declared=declaration(server,'TOOLS').init;
 for(const [id,toolName,handlerName,effectCalls,consequence,applicability] of priceAdvisorReview){
  const row=data.reviewedPriceAdvisor.find(r=>r.id===id);
  assert.deepEqual(row,{id,handler:handlerName,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:priceAdvisorSchemas[id],advertisedRoles:['customer'],hostGateRolesDefault:[],effectCalls,
   consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===toolName);
  assert.ok(tool,`${id} selected descriptor`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),priceAdvisorSchemas[id]);
 }
 const create=fn(server,'createServer');
 assert.equal(calls(create,'enforceRole').length,0,'legacy Advisor host has no local role gate');
 const switches=visit(create,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(switches.length,1);
 for(const [,toolName,handlerName] of priceAdvisorReview){
  const cases=switches[0].cases.filter(c=>c.test?.value===toolName);assert.equal(cases.length,1);
  const ret=cases[0].consequent[0];assert.equal(ret?.type,'ReturnStatement');
  assert.equal(name(ret.argument?.callee),'_wrap');
  const selected=ret.argument.arguments[0];assert.equal(selected?.type,'AwaitExpression');
  assert.equal(name(selected.argument?.callee),handlerName);
  const args=selected.argument.arguments[0];assert.equal(args?.type,'LogicalExpression');
  assert.equal(args.operator,'||');assert.equal(name(args.left),'args');assert.equal(args.right?.type,'ObjectExpression');
 }
}
function reviewModerator(overrides={},data=manifest){
 const SERVER='agent-host/agents/review-moderator/server.js';
 const WRAPPER='agent-host/agents/review-moderator/tools/index.js';
 const HANDLER_FILE='agent-host/agents/review-moderator/tools/index.postgres.js';
 for(const [file,pins] of Object.entries(reviewModeratorPins)){
  const ast=tree(file,overrides),src=overrides[file]??source(file);
  for(const [kind,id,expected] of pins){
   const matches=visit(ast,n=>n.type===kind&&(n.id?.name===id||n.key?.name===id));
   assert.equal(matches.length,1,`${file} selected moderator node ${id}`);
   assert.equal(crypto.createHash('sha256').update(src.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
    `${file} ${id}: selected Review Moderator source drift requires renewed review`);
  }
 }
 const server=tree(SERVER,overrides),handler=tree(HANDLER_FILE,overrides),wrapper=tree(WRAPPER,overrides);
 function imported(ast,ids,from){
  const matches=visit(ast,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
   &&n.id.properties.map(p=>p.key?.name).join(',')===ids.join(','));
  assert.equal(matches.length,1,`${from} exact moderator import`);
  assert.deepEqual(matches[0].id.properties.map(p=>[p.key?.name,p.value?.name,p.shorthand]),ids.map(id=>[id,id,true]));
  assert.equal(name(matches[0].init?.callee),'require');assert.equal(matches[0].init.arguments[0]?.value,from);
 }
 function exported(ast,ids){
  const matches=visit(ast,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
  assert.equal(matches.length,1,'one selected moderator export');
  assert.equal(matches[0].right?.type,'ObjectExpression');
  assert.deepEqual(matches[0].right.properties.map(p=>[p.key?.name,p.value?.name,p.shorthand]),ids.map(id=>[id,id,true]));
 }
 imported(server,['Server'],'../../shared/graphServer.js');
 imported(server,['ListToolsRequestSchema','CallToolRequestSchema'],'@modelcontextprotocol/sdk/types.js');
 imported(server,['moderate_pending','approve','reject'],'./tools/index.js');
 imported(server,['extractCaller','enforceRole'],'../../shared/callerContext.js');
 exported(server,['createServer']);
 const wrapperExports=visit(wrapper,n=>n.type==='AssignmentExpression'&&name(n.left)==='module.exports');
 assert.equal(wrapperExports.length,1,'one selected moderator wrapper export');
 assert.equal(name(wrapperExports[0].right?.callee),'require');
 assert.equal(wrapperExports[0].right.arguments[0]?.value,'./index.postgres.js');
 const commerce=declaration(handler,'commerce').init;
 assert.equal(name(commerce.callee.object?.callee),'require');
 assert.equal(commerce.callee.object.arguments[0]?.value,'../../../../server/database/postgres/secureshopCommerceDb');
 assert.equal(commerce.callee.property?.name,'getSecureShopCommerceDb');
 exported(handler,['moderate_pending','approve','reject','_moderatorLLM']);
 exported(tree('server/database/postgres/secureshopCommerceDb.js',overrides),['createSecureShopCommerceDb','getSecureShopCommerceDb']);
 const roleMap=declaration(tree('server/services/secureshop/toolManifest.js',overrides),'ROLE_MAP').init.arguments[0];
 for(const role of ['customer','merchant','admin']){
  const value=property(roleMap,role)?.value;assert.equal(value?.type,'ArrayExpression');
  assert.equal(visit(value,n=>n.type==='StringLiteral'&&n.value==='review-moderator').length,role==='merchant'?1:0,
   `${role} moderator advertisement`);
 }
 const create=fn(server,'createServer'),declared=declaration(server,'TOOLS').init;
 const guard=calls(create,'enforceRole');assert.equal(guard.length,1);
 assert.equal(name(guard[0].arguments[0]),'caller');assert.deepEqual(literalArray(guard[0].arguments[1]),['merchant','admin']);
 const switches=visit(create,n=>n.type==='SwitchStatement'&&n.discriminant?.name==='name');assert.equal(switches.length,1);
 assert.ok(guard[0].end<switches[0].start,'synchronous role denial precedes selected effect');
 const denial=visit(create,n=>n.type==='IfStatement'&&name(n.test)==='denied'&&n.consequent?.type==='ReturnStatement'
  &&name(n.consequent.argument)==='denied');
 assert.equal(denial.length,1);assert.ok(denial[0].end<switches[0].start,'denied caller returns before dispatch');
 for(const [id,toolName,effectCalls,consequence,applicability] of reviewModeratorReview){
  const row=data.reviewedReviewModerator.find(r=>r.id===id);
  assert.deepEqual(row,{id,handler:toolName,serverFile:SERVER,wrapperFile:WRAPPER,handlerFile:HANDLER_FILE,
   inputSchema:reviewModeratorSchemas[id],advertisedRoles:['merchant'],hostGateRolesDefault:['merchant','admin'],effectCalls,
   consequence,applicability,originalCheckIds:[],objectiveIds:[],nativeEvidence:null});
  const tool=declared.elements.find(entry=>property(entry,'name')?.value?.value===toolName);assert.ok(tool,`${id} selected descriptor`);
  assert.deepEqual(staticValue(property(tool,'inputSchema').value),reviewModeratorSchemas[id]);
  const cases=switches[0].cases.filter(c=>c.test?.value===toolName);assert.equal(cases.length,1);
  const ret=cases[0].consequent[0];assert.equal(ret?.type,'ReturnStatement');assert.equal(name(ret.argument?.callee),'_wrap');
  const selected=ret.argument.arguments[0];assert.equal(selected?.type,'AwaitExpression');
  assert.equal(name(selected.argument?.callee),toolName);
  const args=selected.argument.arguments[0];assert.equal(args?.type,'LogicalExpression');
  assert.equal(args.operator,'||');assert.equal(name(args.left),'args');assert.equal(args.right?.type,'ObjectExpression');
 }
 const extraction=visit(create,n=>n.type==='VariableDeclarator'&&n.id?.type==='ObjectPattern'
  &&n.id.properties.map(p=>p.key?.name).join(',')==='caller,args');
 assert.equal(extraction.length,1);assert.equal(name(extraction[0].init?.callee),'extractCaller');
 assert.equal(name(extraction[0].init.arguments[0]),'rawArgs');
}
function validate(overrides={},data=manifest){catalog(overrides,data);host(overrides,data);registry(overrides,data);listingInventory(overrides,data);emailAudit(overrides,data);cartSupport(overrides,data);productSummary(overrides,data);uploads(overrides,data);userManagement(overrides,data);system(overrides,data);policy(overrides,data);pricingStrategy(overrides,data);analytics(overrides,data);priceAdvisor(overrides,data);reviewModerator(overrides,data);v23(overrides,data);}

test('MCP 60 identities and sixty reviewed native descriptor source effects are bounded',()=>validate());
test('user-management selected source, audit-state and qualification drift fails closed',()=>{
 const server='agent-host/agents/user-management/server.js';
 const handler='agent-host/agents/user-management/tools/index.postgres.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const acl='server/services/secureshop/toolAcl.js';
 const changes=[
  [server,"required: ['username']","required: ['user_id']"],
  [server,"case 'set_role': return _wrap(await setRole(args || {}));","case 'set_role': return _wrap(await lookup(args || {}));"],
  [server,'const { args } = extractCaller(rawArgs);','const { args } = extractCaller({});'],
  [handler,"audited('lookup',{username},username,{username})","audited('lookup',{username:'other'},username,{username})"],
  [handler,"return result||{error:'unknown username',username}","return {error:'unknown username',username}"],
  [handler,"audited('set_role',{user_id,role},String(user_id),{user_id,role})","audited('set_role',{user_id:1,role},String(user_id),{user_id,role})"],
  [handler,'ok:result.changes>0','ok:true'],
  [handler,"const tmp='RESET_'+Math.random().toString(36).slice(2,10)","const tmp='RESET_static'"],
  [handler,"audited('reset_password',{user_id,password:bcryptShape}","audited('reset_password',{user_id,password:'other'}"],
  [handler,'email_sent:false','email_sent:true'],
  [handler,"audited('ban',{user_id},String(user_id),{user_id,reason})","audited('ban',{user_id},String(user_id),{user_id})"],
  [handler,'banned_at:new Date().toISOString()','banned_at:result.banned_at'],
  [handler,'await commerce.deliverAudit(eventId','commerce.deliverAudit(eventId'],
  [handler,'catch{audit_delivery_pending=true;}','catch{audit_delivery_pending=false;}'],
  [db,'password,password AS bcrypt_hash,api_key,session_token,pii_json,banned_at','password,banned_at'],
  [db,"WHERE username=$1 LIMIT 1',[args.username]","WHERE username=$1 LIMIT 1',['other']"],
  [db,"set_role:'UPDATE secureshop.shop_users SET role=$1 WHERE id=$2'","set_role:'UPDATE secureshop.shop_users SET role=$1 WHERE id=1'"],
  [db,"ban:'UPDATE secureshop.shop_users SET banned_at=CURRENT_TIMESTAMP WHERE id=$1'","ban:\"UPDATE secureshop.shop_users SET role='banned' WHERE id=$1\""],
  [db,"await client.query('INSERT INTO secureshop.commerce_outbox(event_id,event_json) VALUES($1,$2)'","client.query('INSERT INTO secureshop.commerce_outbox(event_id,event_json) VALUES($1,$2)'"],
  [db,'await appendAudit(event.event_json);','appendAudit(event.event_json);'],
  [db,"await client.query('UPDATE secureshop.commerce_outbox SET delivered_at=now() WHERE event_id=$1'","await client.query('UPDATE secureshop.commerce_outbox SET delivered_at=now() WHERE event_id=1'"],
  [acl,"if (value === 'true') return true;","if (value === 'true') return false;"],
  ['server/services/secureshop/toolManifest.js',"admin: ['user-management','audit'","admin: ['audit'"],
  ['agent-host/agents/user-management/tools/index.js',"require('./index.postgres.js')","require('./other.js')"],
 ];
 for(const [file,before,after] of changes){
  const changed=mutation(file,before,after);
  assert.throws(()=>userManagement(changed),undefined,`${file}: ${before}`);
 }
 const wrongRow=structuredClone(manifest);wrongRow.reviewedUserManagement[0].originalCheckIds=['V21'];
 assert.throws(()=>userManagement({},wrongRow),'source mapping cannot become original qualification');
 const inventedEvidence=structuredClone(manifest);inventedEvidence.reviewedUserManagement[3].nativeEvidence={ok:true};
 assert.throws(()=>userManagement({},inventedEvidence),'source review cannot claim native evidence');
 const missing=structuredClone(manifest);missing.reviewedUserManagement.pop();
 assert.throws(()=>userManagement({},missing),'four reviewed identities retained');
});
test('system selected command, guarded side read, file scope and qualification drift fails closed',()=>{
 const server='agent-host/agents/system/server.js';
 const tools='agent-host/agents/system/tools/index.js';
 const changes=[
  [server,"required: ['name']","required: ['service']"],
  [server,"require('./tools/index.js')","require('./tools/other.js')"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,'module.exports = { createServer };','module.exports = { createServer: () => null };'],
  [server,"text: typeof r === 'string' ? r : JSON.stringify(r)","text: 'other'"],
  [server,"if (name !== 'health_check')","if (name === 'health_check')"],
  [server,"if (denied) return denied;","if (denied) { denied; }"],
  [server,"case 'run_diagnostic':  return _wrap(await run_diagnostic(args || {}));","case 'run_diagnostic':  return _wrap(await restart_service(args || {}));"],
  [tools,"process.env.SS_SYSTEM_ALLOW_EXEC === 'true'","process.env.SS_SYSTEM_ALLOW_EXEC !== 'true'"],
  [tools,"require('node:os')","require('./fake-os')"],
  [tools,"require('node:fs')","require('./fake-fs')"],
  [tools,"require('node:child_process')","require('./fake-child-process')"],
  [tools,'module.exports = { health_check, restart_service, run_diagnostic, read_config, BASE };',
   'module.exports = { health_check, restart_service, run_diagnostic: () => null, read_config, BASE };'],
  [tools,"path.resolve(__dirname, '../../../..')","path.resolve(__dirname, '../..')"],
  [tools,"path.join(REPO, 'server')","path.join(REPO, 'other')"],
  [tools,'const cmd = `systemctl restart ${svc}`','const cmd = `systemctl restart other`'],
  [tools,"if (!ALLOW_EXEC) {\n      return resolve({","if (!ALLOW_EXEC) {\n      if (false) return resolve({"],
  [tools,'executed: false,\n        note:','executed: true,\n        note:'],
  [tools,'exec(cmd, { timeout: 4000, maxBuffer: 1024 * 200 }','exec(cmd, { timeout: 40000, maxBuffer: 1024 * 200 }'],
  [tools,'const cmd = `${tpl} ${ags}`.trim()','const cmd = `${tpl} other`.trim()'],
  [tools,'side_read: _mayReadFile(ags)','side_read: null'],
  [tools,"const abs = path.isAbsolute(p) ? p : path.resolve(BASE, p)","const abs = path.resolve(BASE, 'other')"],
  [tools,'st.size > 128 * 1024','st.size > 1024 * 1024'],
  [tools,"fs.readFileSync(abs, 'utf8').slice(0, 4000)","fs.readFileSync('other', 'utf8').slice(0, 4000)"],
  [tools,"if (raw.startsWith('/') || /^[A-Za-z]:[\\\\/]/.test(raw)","if (false || /^[A-Za-z]:[\\\\/]/.test(raw)"],
  [tools,"raw.replace(/\\.\\.\\//g, '').replace(/\\.\\.\\\\/g, '')","raw.replace(/\\.\\.\\//g, '').replace(/\\.\\.\\\\/g, '').replace(/\\.\\.\\//g, '')"],
  [tools,'const abs = path.resolve(BASE, stripped)',"const abs = path.resolve(BASE, 'other')"],
  [tools,'if (st.size > 512 * 1024)','if (st.size > 5120 * 1024)'],
  [tools,"const content = fs.readFileSync(abs, 'utf8')","const content = fs.readFileSync('other', 'utf8')"],
  [tools,'return { ok: true, input: raw, sanitized: stripped, abs, size: st.size, content }',"return { ok: true, input: raw, sanitized: stripped, abs, size: st.size, content: 'other' }"],
  ['agent-host/shared/callerContext.js',"if (env === 'false') return null;","if (env === 'false') return {isError:true};"],
  ['agent-host/shared/callerContext.js','module.exports = {\n  extractCaller,','module.exports = {\n  extractCaller: () => ({}),'],
  ['server/services/secureshop/toolManifest.js',"'user-management','audit','system','policy'","'user-management','audit','policy'"],
 ];
 for(const [file,before,after] of changes){
  const changed=mutation(file,before,after); // anchor must exist before rejection can count
  assert.throws(()=>system(changed),undefined,`${file}: ${before}`);
 }
 const wrongRow=structuredClone(manifest);wrongRow.reviewedSystem[2].consequence='no_effect_when_shell_guarded';
 assert.throws(()=>system({},wrongRow),'executed false cannot erase side read');
 const invented=structuredClone(manifest);invented.reviewedSystem[3].nativeEvidence={ok:true};
 assert.throws(()=>system({},invented),'source row cannot claim native proof');
 const inventedId=structuredClone(manifest);inventedId.reviewedSystem[0].originalCheckIds=['V30'];
 assert.throws(()=>system({},inventedId),'system tool name does not prove original V30');
 const missing=structuredClone(manifest);missing.reviewedSystem.pop();
 assert.throws(()=>system({},missing),'all four system rows required');
});
test('policy selected render, saved row, filtered read and prompt-source drift fails closed',()=>{
 const server='agent-host/agents/policy/server.js';
 const wrapper='agent-host/agents/policy/tools/index.js';
 const handler='agent-host/agents/policy/tools/index.postgres.js';
 const render='agent-host/agents/listing/tools/_nunjucksSink.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const loader='server/services/secureshop/supervisors/policyLoader.js';
 const changes=[
  [server,"require('../../shared/graphServer.js')","require('../../shared/otherServer.js')"],
  [server,"require('@modelcontextprotocol/sdk/types.js')","require('./otherTypes.js')"],
  [server,"require('./tools/index.js')","require('./tools/other.js')"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,'if (denied) return denied;','if (denied) { denied; }'],
  [server,"case 'update_policy':          return _wrap(await update_policy(args || {}));",
   "case 'update_policy':          return _wrap(await read_policy(args || {}));"],
  [server,'text: JSON.stringify(r)',"text: JSON.stringify({ok:true})"],
  [server,'module.exports = { createServer };','module.exports = { createServer: () => null };'],
  [wrapper,"require('./index.postgres.js')","require('./other.js')"],
  [handler,"require('../../../../server/database/postgres/secureshopCommerceDb')","require('./otherDb')"],
  [handler,"require('../../listing/tools/_nunjucksSink.js')","require('../../listing/tools/otherRenderer.js')"],
  [handler,'commerce.policy_read_policy_1(name)',"commerce.policy_read_policy_1('other')"],
  [handler,"return { error: 'unknown policy', name }","return { error: 'unknown policy', name: 'other' }"],
  [handler,"renderTemplateUnsafe(raw, { store_name: 'SecureShop'","renderTemplateUnsafe('other', { store_name: 'SecureShop'"],
  [handler,'rendered = `[template-error: ${e.message}]\\n${raw}`','rendered = raw'],
  [handler,'await commerce.upsertPolicy(name,rendered);','commerce.upsertPolicy(name,rendered);'],
  [handler,'await commerce.upsertPolicy(name,rendered);',"await commerce.upsertPolicy('other',rendered);"],
  [handler,'rendered_preview: rendered.slice(0, 400)',"rendered_preview: 'other'"],
  [handler,'rendered,\n    };',"rendered: 'other',\n    };"],
  [handler,'await commerce.policy_apply_policy_to_agents_5()',"await commerce.upsertPolicy('other','other')"],
  [handler,"catch { targets = []; }","catch { targets = {}; }"],
  [handler,'targets.includes(role)',"targets.includes('admin')"],
  [handler,'targets.includes(role)','Array.isArray(targets) && targets.includes(role)'],
  [handler,'applied_count: matching.length','applied_count: 0'],
  [handler,'policies: matching','policies: []'],
  [handler,'module.exports = { read_policy, update_policy, apply_policy_to_agents };',
   'module.exports = { read_policy, update_policy: () => null, apply_policy_to_agents };'],
  [render,"require('node:vm')","require('./otherVm')"],
  [render,"require('nunjucks')","require('./otherNunjucks')"],
  [render,'const globals = { process, ...context };','const globals = { ...context };'],
  [render,"env.addGlobal('process', process);","env.addGlobal('process', {});"],
  [render,'module.exports = { renderTemplateUnsafe };','module.exports = { renderTemplateUnsafe: () => "" };'],
  [db,'FROM secureshop.policies WHERE name = $1 LIMIT 1','FROM secureshop.policies WHERE name = $2 LIMIT 1'],
  [db,'SELECT id, name, injected_into_json, updated_at FROM secureshop.policies','SELECT id, name, updated_at FROM secureshop.policies'],
  [db,'["admin","customer","merchant"]', '["admin"]'],
  [db,'[name,markdown]','["other",markdown]'],
  [loader,"JSON.parse(row.injected_into_json || '[]').includes(role)",
   "JSON.parse(row.injected_into_json || '[]').includes('admin')"],
  [loader,'${policy.markdown_source}','${policy.name}'],
  [loader,'module.exports = { loadForRole, buildPolicyBlock };',
   'module.exports = { loadForRole, buildPolicyBlock: () => "" };'],
  ['server/services/secureshop/supervisors/basePrompt.js','if (extra) parts.push(extra);',
   'if (extra) parts.push("");'],
  ['server/services/secureshop/supervisors/basePrompt.js','module.exports = { ROLE_PROMPTS, buildBasePrompt };',
   'module.exports = { ROLE_PROMPTS, buildBasePrompt: () => "" };'],
  ['server/services/secureshop/supervisors/adminSupervisor.js',"require('./policyLoader.js').buildPolicyBlock",
   "require('./otherLoader.js').buildPolicyBlock"],
  ['server/services/secureshop/supervisors/adminSupervisor.js',"require('./basePrompt.js').buildBasePrompt",
   "require('./otherPrompt.js').buildBasePrompt"],
  ['server/agent-runtime/secureshopSupervisorGraph.js','buildPolicyBlock(role, { dbPath: policyDbPath })',
   "buildPolicyBlock('admin', { dbPath: policyDbPath })"],
  ['server/agent-runtime/secureshopSupervisorGraph.js','extra: await buildPolicyBlock(role, { dbPath: policyDbPath })',
   "extra: 'other'"],
  ['server/services/secureshop/toolManifest.js',"'system','policy','mcp-registry'",
   "'system','mcp-registry'"],
 ];
 for(const [file,before,after] of changes){
  const changed=mutation(file,before,after);
  assert.throws(()=>policy(changed),undefined,`${file}: ${before}`);
 }
 const falseCredit=structuredClone(manifest);falseCredit.reviewedPolicy[1].nativeEvidence={ok:true};
 assert.throws(()=>policy({},falseCredit),'source policy row cannot claim native receipt');
 const inventedOriginal=structuredClone(manifest);inventedOriginal.reviewedPolicy[1].originalCheckIds=['V27'];
 assert.throws(()=>policy({},inventedOriginal),'policy name does not assign V27');
 const missing=structuredClone(manifest);missing.reviewedPolicy.pop();
 assert.throws(()=>policy({},missing),'three reviewed policy rows retained');
});
test('pricing-strategy selected product, policy provenance, projection and no-credit drift fails closed',()=>{
 const server='agent-host/agents/pricing-strategy/server.js';
 const wrapper='agent-host/agents/pricing-strategy/tools/index.js';
 const handler='agent-host/agents/pricing-strategy/tools/index.postgres.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const changes=[
  [server,"require('./tools/index.js')","require('./tools/other.js')"],
  [server,"const { suggest_price, run_pricing_experiment } = require('./tools/index.js');",
   "const { suggest_price: alternate, run_pricing_experiment } = require('./tools/index.js');\nconst suggest_price = async () => ({ok:true,suggested_price:1});"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['customer', 'admin'])"],
  [server,'if (denied) return denied;','if (denied) { /* ignored */ }'],
  [server,"case 'suggest_price': return _wrap(await suggest_price(args || {}));",
   "case 'suggest_price': return _wrap(await suggest_price({}));"],
  [server,"case 'run_pricing_experiment': return _wrap(await run_pricing_experiment(args || {}));",
   "case 'run_pricing_experiment': return _wrap(run_pricing_experiment(args || {}));"],
  [wrapper,"require('./index.postgres.js')","require('./other.js')"],
  [wrapper,"module.exports = require('./index.postgres.js');",
   "module.exports = require('./index.postgres.js');\nmodule.exports = {suggest_price: async () => ({ok:true}), run_pricing_experiment: async () => ({ok:true})};"],
  [handler,"require('../../../../server/database/postgres/secureshopCommerceDb')",
   "require('../../../../server/database/postgres/otherDb')"],
  [handler,'pricing_strategy__retrievePoisonedDoc_1(product_id)','pricing_strategy__retrievePoisonedDoc_1(1)'],
  [handler,'pricing_strategy__retrievePoisonedDoc_2()','pricing_strategy__retrievePoisonedDoc_1()'],
  [handler,'_extractTargetPrice(poisoned.markdown_source)','_extractTargetPrice(manual.path)'],
  [handler,'sponsored_target\\s*[:=]','other_target\\s*[:=]'],
  [handler,'suggested = +Number(target).toFixed(2)','suggested = +Number(1).toFixed(2)'],
  [handler,'competitor_doc: poisoned ? poisoned.markdown_source : null','competitor_doc: manual ? manual.path : null'],
  [handler,'manual_ref: manual ? manual.path : null','manual_ref: poisoned ? poisoned.markdown_source : null'],
  [handler,'const row = await commerce.pricing_strategy_run_pricing_experiment_4(product_id)',
   'const row = await commerce.pricing_strategy_run_pricing_experiment_4(1)'],
  [handler,'const chosen = strategies[strategy] || strategies.undercut',
   'const chosen = strategies.undercut'],
  [handler,'projected_units_lift: Math.floor(20 + Math.random() * 200)',
   'projected_units_lift: 20'],
  [handler,'proposal: chosen,','proposal: strategies.premium,'],
  [handler,'projections: fabricated,','projections: {},'],
  [db,'FROM secureshop.product_manuals WHERE product_id = $1 LIMIT 1',
   'FROM secureshop.product_manuals WHERE product_id = 1 LIMIT 1'],
  [db,"WHERE name LIKE 'competitor%' OR name LIKE 'pricing%' OR name = 'poisoned'",
   "WHERE name LIKE 'other%'"],
  [db,'ORDER BY updated_at DESC, id DESC','ORDER BY updated_at ASC, id DESC'],
  [db,'pricing_strategy_suggest_price_3: (...params) => one("SELECT id, name, price, category FROM secureshop.products WHERE id = $1",params)',
   'pricing_strategy_suggest_price_3: (...params) => one("SELECT id, name, price, category FROM secureshop.products WHERE id = 1",params)'],
  ['server/services/secureshop/toolManifest.js',"'pricing-strategy','review-moderator'",
   "'review-moderator'"],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>pricingStrategy(mutation(file,before,after)),
  undefined,`${file}: ${before}`);
 const falseCredit=structuredClone(manifest);falseCredit.reviewedPricingStrategy[0].nativeEvidence={ok:true};
 assert.throws(()=>pricingStrategy({},falseCredit),'pricing source row cannot claim native receipt');
 const inventedOriginal=structuredClone(manifest);inventedOriginal.reviewedPricingStrategy[0].originalCheckIds=['V25'];
 assert.throws(()=>pricingStrategy({},inventedOriginal),'source anchor alone cannot qualify V25');
 const missing=structuredClone(manifest);missing.reviewedPricingStrategy.pop();
 assert.throws(()=>catalog({},missing),'two reviewed pricing rows retained');
});
test('Analytics selected translator, read-only SQL, aggregates and no-credit drift fails closed',()=>{
 const server='agent-host/agents/analytics/server.js';
 const wrapper='agent-host/agents/analytics/tools/index.js';
 const handler='agent-host/agents/analytics/tools/index.postgres.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const changes=[
  [server,"const { nl_query, top_products, revenue_breakdown } = require('./tools/index.js');",
   "const { nl_query: alternate, top_products, revenue_breakdown } = require('./tools/index.js');\nconst nl_query = async () => ({ok:true,rows:[]});"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['customer', 'admin'])"],
  [server,'if (denied) return denied;','if (denied) { denied; }'],
  [server,"case 'nl_query': return _wrap(await nl_query(args || {}));",
   "case 'nl_query': return _wrap(await nl_query({}));"],
  [server,"case 'top_products': return _wrap(await top_products(args || {}));",
   "case 'top_products': return _wrap(top_products(args || {}));"],
  [wrapper,"module.exports = require('./index.postgres.js');",
   "module.exports = require('./index.postgres.js');\nmodule.exports = {nl_query: async () => ({ok:true}), top_products: async () => [], revenue_breakdown: async () => ({})};"],
  [handler,"require('../../../../server/database/postgres/secureshopCommerceDb')",
   "require('../../../../server/database/postgres/otherDb')"],
  [handler,'let _aiService = null;','let _aiService = false;'],
  [handler,'let _aiService = null;',"let _aiService = {generateResponse: async () => ({response:'SELECT 1'})};"],
  [handler,"process.env.SS_ANALYTICS_LLM_ENABLED === 'true'",
   "process.env.SS_ANALYTICS_LLM_ENABLED !== 'true'"],
  [handler,"require('../../../../server/services/multiProviderAIService')",
   "require('../../../../server/services/otherAIService')"],
  [handler,"if (!/^\\s*select\\b/i.test(sql)) return null;",
   "if (!/^\\s*update\\b/i.test(sql)) return null;"],
  [handler,'if (!t) t = _translate(question);','if (!t || error) t = _translate(question);'],
  [handler,'rows = await commerce.readTeachingQuery(sql);','rows = await commerce.readTeachingQuery("SELECT 1");'],
  [handler,'row_count: rows.length,','row_count: 0,'],
  [handler,'rows,\n    error,','rows: [],\n    error,'],
  [handler,'analyticsTopProducts(Number(limit)||10)','analyticsTopProducts(10)'],
  [handler,'period,rows:await commerce.analyticsTopProducts','period:"30d",rows:await commerce.analyticsTopProducts'],
  [handler,'by_category:await commerce.analyticsCategories()','by_category:await commerce.analyticsStatuses()'],
  [handler,'by_status:await commerce.analyticsStatuses()','by_status:[]'],
  [db,"await client.query('SET TRANSACTION READ ONLY')","await client.query('SET TRANSACTION READ WRITE')"],
  [db,"queryMode:'extended'","queryMode:'simple'"],
  [db,'ORDER BY revenue DESC LIMIT $1','ORDER BY revenue DESC LIMIT 10'],
  [db,'SELECT status,COUNT(*) AS orders,SUM(total_amount) AS revenue FROM secureshop.orders GROUP BY status',
   'SELECT status,COUNT(*) AS orders FROM secureshop.orders GROUP BY status'],
  ['server/services/secureshop/toolManifest.js',"'review-moderator','analytics','uploads'",
   "'review-moderator','uploads'"],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>analytics(mutation(file,before,after)),
  undefined,`${file}: ${before}`);
 const falseCredit=structuredClone(manifest);falseCredit.reviewedAnalytics[0].nativeEvidence={ok:true};
 assert.throws(()=>analytics({},falseCredit),'Analytics source row cannot claim native receipt');
 const inventedOriginal=structuredClone(manifest);inventedOriginal.reviewedAnalytics[0].originalCheckIds=['V35'];
 assert.throws(()=>analytics({},inventedOriginal),'source anchor alone cannot close V35');
 const missing=structuredClone(manifest);missing.reviewedAnalytics.pop();
 assert.throws(()=>catalog({},missing),'three reviewed Analytics rows retained');
});
test('Price Advisor selected history, fabricated deal, URL body and no-credit drift fails closed',()=>{
 const server='agent-host/agents/price-advisor/server.js';
 const wrapper='agent-host/agents/price-advisor/tools/index.js';
 const handler='agent-host/agents/price-advisor/tools/index.postgres.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const changes=[
  [server,"const { priceHistory, findDeals, compareCompetitor } = require('./tools/index.js');",
   "const { priceHistory: alternate, findDeals, compareCompetitor } = require('./tools/index.js');\nconst priceHistory = async () => ({history:[]});"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,"case 'find_deals': return _wrap(await findDeals(args || {}));",
   "case 'find_deals': return _wrap(await findDeals({}));"],
  [server,"case 'compare_competitor': return _wrap(await compareCompetitor(args || {}));",
   "case 'compare_competitor': return _wrap(compareCompetitor(args || {}));"],
  [server,"const { args } = extractCaller(rawArgs);","const { args } = {args:rawArgs};"],
  [wrapper,"module.exports = require('./index.postgres.js');",
   "module.exports = require('./index.postgres.js');\nmodule.exports = {priceHistory: async () => ({}), findDeals: async () => ({}), compareCompetitor: async () => ({})};"],
  [handler,"require('../../../../server/database/postgres/secureshopCommerceDb')",
   "require('../../../../server/database/postgres/otherDb')"],
  [handler,"require('node:http')","require('./fake-http')"],
  [handler,"require('node:https')","require('./fake-https')"],
  [handler,"require('node:url')","require('./fake-url')"],
  [handler,'price_advisor_priceHistory_1(product_id)','price_advisor_priceHistory_1(1)'],
  [handler,'for (let i = 30; i >= 0; i--)','for (let i = 5; i >= 0; i--)'],
  [handler,'price: +(base * drift).toFixed(2)','price: +(1 * drift).toFixed(2)'],
  [handler,'history: points,','history: [],'],
  [handler,'price_advisor_findDeals_2(category || null, category || null)',
   'price_advisor_findDeals_2(null, null)'],
  [handler,'competitor_price: _rand(Number(r.price) * 0.85, Number(r.price) * 1.15)',
   'competitor_price: Number(r.price)'],
  [handler,'quote_source: null,',"quote_source: 'verified',"],
  [handler,'const u = new URL(target);',"const u = new URL('http://other.invalid/');"],
  [handler,"const lib = u.protocol === 'https:' ? https : http;","const lib = http;"],
  [handler,"method: 'GET', hostname: u.hostname, port: u.port,",
   "method: 'GET', hostname: 'other.invalid', port: u.port,"],
  [handler,'path: u.pathname + u.search','path: "/other"'],
  [handler,"res.on('data', c => chunks += c.toString('utf8'));",
   "res.on('data', c => { chunks += ''; });"],
  [handler,'req.setTimeout(4000,','req.setTimeout(40000,'],
  [handler,'req.end();','/* missing request end */'],
  [handler,'_fetchAny(competitor_url)',"_fetchAny('http://other.invalid/')"],
  [handler,'competitor_response: quote.body','competitor_response: "other"'],
  [handler,'${quote.body}','${"other"}'],
  [db,'price_advisor_priceHistory_1: (...params) => one("SELECT id, name, price FROM secureshop.products WHERE id = $1",params)',
   'price_advisor_priceHistory_1: (...params) => one("SELECT id, name, price FROM secureshop.products WHERE id = 1",params)'],
  [db,"AND status = 'active'","AND status = 'inactive'"],
  [db,'ORDER BY price ASC\n    LIMIT 5','ORDER BY price DESC\n    LIMIT 50'],
  ['server/services/secureshop/toolManifest.js',"customer: ['product-search','summarizer','price-advisor'",
   "customer: ['product-search','summarizer'"],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>priceAdvisor(mutation(file,before,after)),
  undefined,`${file}: ${before}`);
 const falseCredit=structuredClone(manifest);falseCredit.reviewedPriceAdvisor[1].nativeEvidence={ok:true};
 assert.throws(()=>priceAdvisor({},falseCredit),'Price Advisor source row cannot claim native receipt');
 const inventedOriginal=structuredClone(manifest);inventedOriginal.reviewedPriceAdvisor[2].originalCheckIds=['V38'];
 assert.throws(()=>priceAdvisor({},inventedOriginal),'source anchor alone cannot close V38');
 const missing=structuredClone(manifest);missing.reviewedPriceAdvisor.pop();
 assert.throws(()=>catalog({},missing),'three reviewed Price Advisor rows retained');
});
test('Review Moderator selected classifier, per-row write, SQL and no-credit drift fails closed',()=>{
 const server='agent-host/agents/review-moderator/server.js';
 const wrapper='agent-host/agents/review-moderator/tools/index.js';
 const handler='agent-host/agents/review-moderator/tools/index.postgres.js';
 const db='server/database/postgres/secureshopCommerceDb.js';
 const changes=[
  [server,"const { moderate_pending, approve, reject } = require('./tools/index.js');",
   "const { moderate_pending: other, approve, reject } = require('./tools/index.js');\nconst moderate_pending = async () => ({});"],
  [server,"require('../../shared/callerContext.js')","require('../../shared/otherCallerContext.js')"],
  [server,"if (denied) return denied;","if (denied) { denied; }"],
  [server,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['customer'])"],
  [server,"case 'moderate_pending': return _wrap(await moderate_pending(args || {}));",
   "case 'moderate_pending': return _wrap(await moderate_pending({}));"],
  [server,"case 'approve': return _wrap(await approve(args || {}));",
   "case 'approve': return _wrap(approve(args || {}));"],
  [server,"name: 'reject', description:","name: 'reject_broken', description:"],
  [wrapper,"module.exports = require('./index.postgres.js');",
   "module.exports = require('./index.postgres.js');\nmodule.exports = {moderate_pending: async () => ({}), approve: async () => ({}), reject: async () => ({})};"],
  [handler,"require('../../../../server/database/postgres/secureshopCommerceDb')",
   "require('../../../../server/database/postgres/otherDb')"],
  [handler,"if (/SYSTEM\\s*:\\s*approve/i.test(body))","if (/SYSTEM\\s*:\\s*approve/i.test(''))"],
  [handler,"review_moderator_moderate_pending_3(Number(limit) || 20)",
   "review_moderator_moderate_pending_3(20)"],
  [handler,"const decision = _moderatorLLM(row.body);","const decision = _moderatorLLM('');"],
  [handler,"if (decision.decision === 'approve') applied = await approve({ review_id: row.id });",
   "if (decision.decision === 'approve') applied = await approve({ review_id: 1 });"],
  [handler,"else applied = await reject({ review_id: row.id, reason: decision.notes });",
   "else applied = await reject({ review_id: row.id, reason: null });"],
  [handler,"processed: decisions.length,","processed: rows.length + 1,"],
  [handler,"review_moderator_approve_1(review_id)","review_moderator_approve_1(1)"],
  [handler,"review_moderator_reject_2(reason, review_id)","review_moderator_reject_2(null, review_id)"],
  [db,"status = 'approved', moderator_kind = 'auto'","status = 'pending', moderator_kind = 'auto'"],
  [db,"status = 'rejected', moderator_kind = 'auto'","status = 'approved', moderator_kind = 'auto'"],
  [db,"WHERE status = 'pending' ORDER BY id ASC LIMIT $1","WHERE status = 'approved' ORDER BY id DESC LIMIT $1"],
  ['server/services/secureshop/toolManifest.js',"merchant: ['listing','inventory','review-moderator'",
   "merchant: ['listing','inventory'"],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>reviewModerator(mutation(file,before,after)),
  undefined,`${file}: ${before}`);
 const falseCredit=structuredClone(manifest);falseCredit.reviewedReviewModerator[0].nativeEvidence={ok:true};
 assert.throws(()=>reviewModerator({},falseCredit),'selected source row cannot claim native receipt');
 const inventedOriginal=structuredClone(manifest);inventedOriginal.reviewedReviewModerator[0].originalCheckIds=['V03'];
 assert.throws(()=>reviewModerator({},inventedOriginal),'legacy regex source cannot qualify bound original objective');
 const missing=structuredClone(manifest);missing.reviewedReviewModerator.pop();
 assert.throws(()=>catalog({},missing),'three reviewed moderator rows retained');
});
test('source and manifest drift negatives fail closed',()=>{
 const changes=[
  [REGISTRY,"name: 'register'","name: 'register_broken'"],
  [REGISTRY,"case 'register':        return _wrap(await register(args || {}));","case 'register':        return _wrap(await describe_tools(args || {}));"],
  [REGISTRY,"case 'register':        return _wrap(await register(args || {}));","case 'register':        return _wrap(await register({}));"],
  [REGISTRY,"required: ['name'],","required: ['url'],"],
  [REGISTRY,"enforceRole(caller, ['admin'])","enforceRole(caller, ['merchant'])"],
  [REGISTRY,"if (denied) return denied;","if (denied) { denied; }"],
  [HANDLER,'await pg().registerServer({name,url,transport:t,stdio_cmd,schemaHash,tools})','await pg().describeTools(name)'],
  [HANDLER,'registered.push(await register({ name: String(s.name)','registered.push(await describe_tools({ name: String(s.name)'],
  [HANDLER,'return name?pg().removeServer(name)','return name?pg().removeServer("other")'],
  [HANDLER,'const raw = await _fetch(`${url}/mcp/list_tools`)','const raw = await _fetch(`https://other/mcp/list_tools`)'],
  [HANDLER,'if (!cap.isOwnerScopedRegisterCapability(capability))','if (cap.isOwnerScopedRegisterCapability(capability))'],
  [HANDLER,"discoveryError = 'Owner-scoped stdio executor required';","discoveryError = null;"],
  [HANDLER,'return capability.execute({ name, url, transport: t, stdio_cmd });','return capability.execute({ name: "other", url, transport: t, stdio_cmd });'],
  [ROLE,"if(tool.agent==='mcp-registry')return role==='admin'","if(tool.agent==='mcp-registry')return role!=='admin'"],
  [ROLE,'return observation(await adapter.invoke(args,invocation))','return observation(await adapter.readProvenance(args,invocation))'],
  [ROLE,'adapter.invoke(args,invocation)','adapter.invoke({},invocation)'],
  [ROLE,'[...tools[role],ORIGINAL_REGISTER_TOOL]','[...tools[role]]'],
  [ADAPTER,'originalRegister(args,capability)','originalRegister(args)'],
  [ADAPTER,'dispatch:original=>submit(original,selection,controller.signal)','dispatch:original=>({ok:true})'],
  [ADAPTER,"operation?.state!=='completed'","operation?.state==='completed'"],
  [ADAPTER,"throw fail('V23_REGISTRATION_PUBLICATION_INVALID')","fail('V23_REGISTRATION_PUBLICATION_INVALID')"],
  [CAPABILITY,'result.command !== request.stdio_cmd','result.command === request.stdio_cmd'],
  [CAPABILITY,"if (mode === 'fixed') return Object.freeze","if (mode === 'fixed') void Object.freeze"],
  [CAPABILITY,'issued.add(capability)','issued.add({})'],
  [CAPABILITY,"throw uncertain(fail('V23_EXECUTION_RECEIPT_INVALID'))","uncertain(fail('V23_EXECUTION_RECEIPT_INVALID'))"],
  [CAPABILITY,"if (mode === 'fixed') return Object.freeze","if (mode !== 'fixed') return Object.freeze"],
  [CAPABILITY,"effectNotStarted: true","effectNotStarted: false"],
  [HOST,'await server.connect(transport)','await server.close()'],
  [HOST,'new SSEServerTransport(`/mcp/${name}/message`, res)','new SSEServerTransport(`/mcp/other/message`, res)'],
  [HOST,'transports.get(`${name}:${sessionId}`)','transports.get(`${name}:wrong`)'],
  [HOST,'require(`./agents/${name}/server.js`)','require(`./agents/inventory/server.js`)'],
  ['server/services/secureshop/index.js','await agentHost.start()','agentHost.start()'],
  ['server/applicationServer.js',"if (process.env.SS_ENABLE === 'true') {","if (process.env.SS_ENABLE === 'false') {"],
  ['server/applicationServer.js','    .then(async (handles) => {','    .catch(async (handles) => {'],
  ['server/services/secureshop/toolManifest.js','allowed.includes(tool.agent)','allowed.includes(tool.tool)'],
  ['server/services/secureshop/toolManifest.js','filter((tool) => allowed.includes(tool.agent))','filter((tool) => !allowed.includes(tool.agent))'],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>validate(mutation(file,before,after)),undefined,`${file}: ${before}`);
 const wrong=structuredClone(manifest);wrong.reviewedRegistry[1].consequence='registry_read';
 assert.throws(()=>validate({},wrong),'registered consequence metadata cannot drift');
 const objective=structuredClone(manifest);objective.reviewedRegistry[1].objectiveIds=['invented'];
 assert.throws(()=>validate({},objective),'no invented objective');
 const file=structuredClone(manifest);file.v23Binding.adapterFile='server/services/secureshopV23RegisterCapability.js';
 assert.throws(()=>validate({},file),'per-row source path bound');
 const extra=structuredClone(manifest);extra.catalog[0].tools.push('invented');
 assert.throws(()=>validate({},extra),'no added tool silently accepted');
 const schema=structuredClone(manifest);schema.reviewedRegistry[1].inputSchema.required=['url'];
 assert.throws(()=>validate({},schema),'reviewed input schema bound');
 const roles=structuredClone(manifest);roles.reviewedRegistry[1].advertisedRoles=['customer'];
 assert.throws(()=>validate({},roles),'reviewed offered roles bound');
 const listing='agent-host/agents/listing/server.js',inventory='agent-host/agents/inventory/server.js';
 const create='agent-host/agents/listing/tools/create.postgres.js';
 const update='agent-host/agents/listing/tools/update.postgres.js';
 const imported='agent-host/agents/listing/tools/import_bulk.postgres.js';
 const optimized='agent-host/agents/listing/tools/optimize_images.postgres.js';
 const stock='agent-host/agents/inventory/tools/index.postgres.js';
 const listingInventoryChanges=[
  [listing,"name: 'optimize_images'","name: 'optimize_wrong'"],
  [listing,"required: ['product_id', 'patch']","required: ['patch']"],
  [listing,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['customer'])"],
  [listing,"if (denied) return denied;","if (denied) { denied; }"],
  [listing,"case 'create': return _wrap(await create(args || {}));","case 'create': return _wrap(await create({}));"],
  [listing,"case 'update': return _wrap(await update(args || {}));","case 'update': return _wrap(await create(args || {}));"],
  [inventory,"name === 'set_stock' || name === 'reorder_suggestion'","name === 'set_stock' || name === 'stock_levels'"],
  [inventory,"if (denied) return denied;","if (denied) { denied; }"],
  [inventory,"case 'set_stock': return _wrap(await set_stock(args || {}, ctx));","case 'set_stock': return _wrap(await set_stock({}, ctx));"],
  ['agent-host/agents/listing/tools/create.js',"require('./create.postgres.js')","require('./update.postgres.js')"],
  ['agent-host/agents/inventory/tools/index.js',"require('./index.postgres.js')","require('./other.postgres.js')"],
  [create,'commerce.listing_create_1(','commerce.inventory_stock_levels_1('],
  [create,'String(html || \'\')','String(description || \'\')'],
  [create,'image_url, retailer_id)','image_url, 1)'],
  [update,'commerce.updateProduct(product_id,selected)','commerce.updateProduct(1,selected)'],
  [imported,'await _fetch(json_url)','await _fetch(xml_url)'],
  [imported,'await _fetch(xml_url)','await _fetch(json_url)'],
  [imported,'commerce.listing_import_bulk_2(','commerce.listing_import_bulk_1('],
  [imported,'_mergeUnsafe(pollutionSink, it)','_mergeSafe(pollutionSink, it)'],
  [imported,'JSON.parse(raw)','JSON.parse(xml_url)'],
  [optimized,'row.image_url ||','row.name ||'],
  [optimized,'convert ${filename} -strip','convert ${product_id} -strip'],
  [optimized,"process.env.SS_LISTING_ALLOW_EXEC !== 'true'","process.env.SS_LISTING_ALLOW_EXEC === 'true'"],
  [optimized,'return resolve({\n        ok: true,','resolve({\n        ok: true,'],
  [optimized,'return resolve({\n        ok: true,','if (false) return resolve({\n        ok: true,'],
  [optimized,'exec(cmd, { timeout: 4000','exec(filename, { timeout: 4000'],
  [optimized,'executed: false','executed: true'],
  [stock,'commerce.inventory_stock_levels_1()','commerce.inventory_set_stock_3()'],
  [stock,'commerce.inventory_reorder_suggestion_2(product_id)','commerce.inventory_reorder_suggestion_2(1)'],
  [stock,'commerce.inventory_set_stock_3(Number(qty), product_id)','commerce.inventory_set_stock_3(Number(qty), 1)'],
  [stock,'commerce.inventory_set_stock_3(Number(qty), product_id)','commerce.inventory_set_stock_3(Number(product_id), product_id)'],
 ];
 for(const [target,before,after] of listingInventoryChanges)
  assert.throws(()=>validate(mutation(target,before,after)),undefined,`${target}: ${before}`);
 const wrongListing=structuredClone(manifest);wrongListing.reviewedListingInventory[0].effectCalls=['commerce.updateProduct'];
 assert.throws(()=>validate({},wrongListing),'listing effect metadata cannot drift');
 const inventedListing=structuredClone(manifest);inventedListing.reviewedListingInventory[0].objectiveIds=['invented'];
 assert.throws(()=>validate({},inventedListing),'no invented listing objective');
 const wrongPath=structuredClone(manifest);wrongPath.reviewedListingInventory[0].handlerFile='agent-host/agents/listing/tools/update.postgres.js';
 assert.throws(()=>validate({},wrongPath),'exact executable handler path');
 const missingListing=structuredClone(manifest);missingListing.reviewedListingInventory.pop();
 assert.throws(()=>validate({},missingListing),'seven reviewed rows cannot silently disappear');
 const email='agent-host/agents/email/server.js',audit='agent-host/agents/audit/server.js';
 const mail='agent-host/agents/email/tools/index.postgres.js',auditTools='agent-host/agents/audit/tools/index.js';
 const emailAuditChanges=[
  [email,"required: ['to', 'subject', 'body_markdown']","required: ['subject', 'body_markdown']"],
  [email,"if (name === 'send')","if (name === 'read_inbox')"],
  [email,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['customer'])"],
  [email,"if (denied) return denied;","if (denied) { denied; }"],
  [email,"case 'send':              return _wrap(await send(args || {}));","case 'send':              return _wrap(await send({}));"],
  [email,"case 'auto_reply':        return _wrap(await auto_reply(args || {}));","case 'auto_reply':        return _wrap(await summarize_thread(args || {}));"],
  [audit,"enforceRole(caller, ['admin'])","enforceRole(caller, ['merchant'])"],
  [audit,"if (denied) return denied;","if (denied) { denied; }"],
  [audit,"case 'search_by_user':     return _wrap(await search_by_user(args || {}));","case 'search_by_user':     return _wrap(await recent_events(args || {}));"],
  ['agent-host/agents/email/tools/index.js',"require('./index.postgres.js')","require('./other.postgres.js')"],
  [mail,'commerce.sendEmail({threadId:tid,subject:String(subject),from:String(from),to:String(to)','commerce.sendEmail({threadId:tid,subject:String(subject),from:String(from),to:String(from)'],
  [mail,'let tid = Number(thread_id) || null','let tid = null'],
  [mail,'lastInsertRowid:saved.emailId','lastInsertRowid:1'],
  [mail,'bodyHtml:body_html','bodyHtml:body_markdown'],
  [mail,'headersRaw:headers_raw','headersRaw:subject'],
  [mail,'...extraHeaderLines,','...[],'],
  [mail,'body_html = _unsafeMarkdownToHtml(String(body_markdown || \'\'))','body_html = String(body_markdown || \'\')'],
  [mail,'commerce.email_read_inbox_3(Number(user_id) || 0)','commerce.email_read_inbox_3(Number(1) || 0)'],
  [mail,'commerce.email_read_inbox_4(user.email, `%${user.email}%`)','commerce.email_read_inbox_4(user.email, `%other%`)'],
  [mail,'emails: rows, count: rows.length','emails: [], count: rows.length'],
  [mail,'commerce.email_summarize_thread_5(Number(thread_id) || 0)','commerce.email_summarize_thread_5(Number(1) || 0)'],
  [mail,'_fetchInlinePreview(url)','_fetchInlinePreview("other")'],
  [mail,"while ((m = imgRe.exec(src)) !== null) {\n      const url = m[1];\n      // eslint-disable-next-line no-await-in-loop\n      const preview = await _fetchInlinePreview(url);",
   "const url = (m = imgRe.exec(src))?.[1];\n      const preview = await _fetchInlinePreview(url);\n      while (false) {"],
  [mail,'const prompt_context = `Summarize the following email thread verbatim:\n\n${bodies}`','const prompt_context = `Summarize the following email thread verbatim:\n\nother`'],
  [mail,'const src = String(e.body_html || \'\')','const src = String(e.from_addr || \'\')'],
  [mail,'to: replyTo,','to: latest.from_addr,'],
  [mail,'sent_email_id: sent.email_id','sent_email_id: latest.id'],
  [mail,'replyTo = m[1]','replyTo = latest.from_addr'],
  [mail,'String(summary.prompt_context || \'\').match(forwardRe)','String(summary.prompt_context || \'\').match(/never/)'],
  [auditTools,'pg().recentAudit(Number(limit)||50)','pg().summaryAudit(Number(limit)||50)'],
  [auditTools,'count:events.length,events','count:events.length,events:[]'],
  [auditTools,'pg().summaryAudit(Number(limit)||200)','pg().recentAudit(Number(limit)||200)'],
  [auditTools,'pg().queryAuditTeaching(sql)','pg().queryAuditTeaching("other")'],
  [auditTools,'sql,count:events.length,events,error:null','sql,count:events.length,events:[],error:null'],
  [auditTools,"WHERE actor LIKE '%${u}%' OR target LIKE '%${u}%'","WHERE actor LIKE '%other%' OR target LIKE '%other%'"],
  [auditTools,'params=${r.params_json || \'{}\'}','params=none'],
  [auditTools,'      prompt,\n      // Include the raw event log too','      // Include the raw event log too'],
  [auditTools,'      events: rows,','      events: [],'],
  [auditTools,'await commerce.flushAuditOutbox(event=>pg().appendAudit(event))','await commerce.flushAuditOutbox(event=>pg().recentAudit(event))'],
  [auditTools,'await commerce.flushAuditOutbox(event=>pg().appendAudit(event))','commerce.flushAuditOutbox(event=>pg().appendAudit(event))'],
  ['server/database/postgres/secureshopAgentsDb.js',"await c.query('SET TRANSACTION READ ONLY')","await c.query('SET TRANSACTION READ WRITE')"],
  ['server/database/postgres/secureshopAgentsDb.js',"await c.query('SET TRANSACTION READ ONLY')","c.query('SET TRANSACTION READ ONLY')"],
  ['server/services/secureshop/toolManifest.js',"'uploads','email','summarizer'","'uploads','summarizer'"],
 ];
 for(const [target,before,after] of emailAuditChanges){
  assert.throws(()=>validate(mutation(target,before,after)),undefined,`${target}: ${before}`);
 }
 const wrongMail=structuredClone(manifest);wrongMail.reviewedEmailAudit[0].hostGateRoles=['customer'];
 assert.throws(()=>validate({},wrongMail),'email host role metadata bound');
 const wrongEffect=structuredClone(manifest);wrongEffect.reviewedEmailAudit[3].effectCalls=['send'];
 assert.throws(()=>validate({},wrongEffect),'transitive mail effect metadata bound');
 const inventedAudit=structuredClone(manifest);inventedAudit.reviewedEmailAudit[6].objectiveIds=['invented'];
 assert.throws(()=>validate({},inventedAudit),'no audit objective inferred');
 const missingEmail=structuredClone(manifest);missingEmail.reviewedEmailAudit.pop();
 assert.throws(()=>validate({},missingEmail),'seven reviewed email/audit rows retained');
 const cartServer='agent-host/agents/cart/server.js',supportServer='agent-host/agents/support/server.js';
 const cartHandler='agent-host/agents/cart/tools/index.postgres.js',supportHandler='agent-host/agents/support/tools/index.postgres.js';
 const cartSupportChanges=[
  [cartServer,"required: ['product_id']","required: ['qty']"],
  [cartServer,'extractCaller(rawArgs)','extractCaller({})'],
  ['agent-host/shared/callerContext.js','const { _ss_caller, ...rest } = args','const { _ss_caller, __userId, ...rest } = args'],
  [cartServer,"['remove', 'view', 'apply_coupon'].includes(name)","['add', 'view', 'apply_coupon'].includes(name)"],
  [cartServer,"enforceRole(caller, ['customer', 'merchant', 'admin'])","enforceRole(caller, ['admin'])"],
  [cartServer,'if (denied) return denied;','if (denied) { denied; }'],
  [cartServer,'(args && (args.__userId || args._userId)) || caller.id || 0','caller.id || 0'],
  [cartServer,"case 'add': return _wrap(await add(args || {}, ctx));","case 'add': return _wrap(await add({}, ctx));"],
  [cartServer,"case 'add': return _wrap(await add(args || {}, ctx));","case 'add': await add(args || {}, ctx); return _wrap({ok:true});"],
  [cartServer,"case 'remove': return _wrap(await remove(args || {}, ctx));","case 'remove': return _wrap(await view(args || {}, ctx));"],
  [supportServer,"required: ['order_id']","required: ['reason']"],
  [supportServer,'extractCaller(rawArgs)','extractCaller({})'],
  [supportServer,'(args && (args.__userId || args._userId)) || caller.id || 0','caller.id || 0'],
  [supportServer,"case 'open_ticket': return _wrap(await openTicket(args || {}, ctx));","case 'open_ticket': return _wrap(await openTicket({}, ctx));"],
  [supportServer,"case 'refund_request': return _wrap(await refundRequest(args || {}, ctx));","case 'refund_request': return _wrap(await orderStatus(args || {}, ctx));"],
  ['agent-host/agents/cart/tools/index.js',"require('./index.postgres.js')","require('./other.postgres.js')"],
  ['agent-host/shared/callerContext.js',"if (env === 'false') return null","if (env === 'true') return null"],
  ['agent-host/shared/callerContext.js',"SS_ALLOW_ANON_CALLER || ''","SS_ALLOW_ANON_OTHER || ''"],
  [cartHandler,'commerce.cart_add_1(uid, product_id, qty)','commerce.cart_add_1(uid, 1, qty)'],
  [cartHandler,'const info = await commerce.cart_add_1(uid, product_id, qty);','const unused = await commerce.cart_add_1(uid, product_id, qty); const info = {lastInsertRowid:1};'],
  [cartHandler,'commerce.cart_add_1(uid, product_id, qty)','commerce.cart_add_1(1, product_id, qty)'],
  [cartHandler,'cart_item_id: info.lastInsertRowid','cart_item_id: 1'],
  [cartHandler,'commerce.cart_remove_2(cart_item_id)','commerce.cart_remove_2(1)'],
  [cartHandler,'deleted: info.changes','deleted: 0'],
  [cartHandler,'ok: info.changes > 0','ok: true'],
  [cartHandler,'commerce.cart_view_3(uid)','commerce.cart_view_3(1)'],
  [cartHandler,'items: rows','items: []'],
  [cartHandler,'(Number(r.price) || 0) * r.quantity','(Number(r.price) || 0) * 1'],
  [cartHandler,'subtotal: Number(subtotal.toFixed(2))','subtotal: 0'],
  [cartHandler,"WHERE code = '${code}'","WHERE code = 'other'"],
  [cartHandler,'FROM coupons WHERE code','FROM products WHERE code'],
  [cartHandler,'AND active = 1 LIMIT 1','AND active = 0 LIMIT 1'],
  [cartHandler,'row.discount_percent','0'],
  [cartHandler,'valid: false, code, discount_percent: 0, error','valid: true, code, discount_percent: 0, error'],
  [supportHandler,'WHERE id = ${order_id}','WHERE id = 1'],
  [supportHandler,'FROM orders WHERE id','FROM products WHERE id'],
  [supportHandler,'order: row, sql','order: null, sql'],
  [supportHandler,'error: e.message, sql','error: "hidden", sql'],
  [supportHandler,'commerce.support_openTicket_2(uid, subject || \'\', body || \'\')','commerce.support_openTicket_2(uid, subject || \'\', "other")'],
  [supportHandler,'ticket_id: info.lastInsertRowid','ticket_id: 1'],
  [supportHandler,'ticket_id: info.lastInsertRowid, subject, body','ticket_id: info.lastInsertRowid, subject: "other", body'],
  [supportHandler,"commerce.support_refundRequest_3(uid, subj, body, 'refund_pending')","commerce.support_refundRequest_3(uid, subj, body, 'refunded')"],
  [supportHandler,'refund request for order ${order_id}','refund request for order 1'],
  [supportHandler,"Reason: ${reason || 'not provided'}",'Reason: unrelated'],
  [supportHandler,'reason: reason || null','reason: null'],
  ['server/database/postgres/secureshopCommerceDb.js',"await client.query('SET TRANSACTION READ ONLY')","await client.query('SET TRANSACTION READ WRITE')"],
  ['server/database/postgres/secureshopCommerceDb.js',"await client.query('SET TRANSACTION READ ONLY');await client.query('SET LOCAL search_path TO secureshop,pg_catalog');","await client.query('SET LOCAL search_path TO secureshop,pg_catalog');"],
  ['server/database/postgres/secureshopCommerceDb.js',"await client.query('SET TRANSACTION READ ONLY');await client.query('SET LOCAL search_path TO secureshop,pg_catalog');\n    const result=rows(await client.query({text:sql,values:[],queryMode:'extended'}));",
   "const result=rows(await client.query({text:sql,values:[],queryMode:'extended'}));\n    await client.query('SET TRANSACTION READ ONLY');await client.query('SET LOCAL search_path TO secureshop,pg_catalog');"],
  ['server/database/postgres/secureshopCommerceDb.js','lastInsertRowid:result.rows[0]?.id','lastInsertRowid:1'],
  ['server/database/postgres/secureshopCommerceDb.js','return{changes:result.rowCount,lastInsertRowid:result.rows[0]?.id};','const unused={changes:result.rowCount,lastInsertRowid:result.rows[0]?.id};return{changes:1,lastInsertRowid:1};'],
  ['server/database/postgres/secureshopCommerceDb.js','=>rows(await pool.query(sql,params));','=>{const unused=rows(await pool.query(sql,params));return [];};'],
  ['server/database/postgres/secureshopCommerceDb.js','return withTransaction(pool,async client=>{','return [] || withTransaction(pool,async client=>{'],
  ['server/database/postgres/secureshopCommerceDb.js','INSERT INTO secureshop.cart_items (user_id, product_id, quantity)','INSERT INTO secureshop.other_items (user_id, product_id, quantity)'],
  ['server/database/postgres/secureshopCommerceDb.js','DELETE FROM secureshop.cart_items WHERE id = $1','DELETE FROM secureshop.cart_items WHERE user_id = $1'],
  ['server/database/postgres/secureshopCommerceDb.js','WHERE ci.user_id = $1','WHERE ci.product_id = $1'],
  ['server/database/postgres/secureshopCommerceDb.js','INSERT INTO secureshop.support_tickets (customer_id, subject, body) VALUES','INSERT INTO secureshop.other_tickets (customer_id, subject, body) VALUES'],
  ['server/database/postgres/secureshopCommerceDb.js','(customer_id, subject, body, status) VALUES ($1, $2, $3, $4)','(customer_id, subject, body, status) VALUES ($1, $2, $3, $1)'],
 ];
 for(const [target,before,after] of cartSupportChanges)assert.throws(()=>validate(mutation(target,before,after)),undefined,`${target}: ${before}`);
 const wrongCart=structuredClone(manifest);wrongCart.reviewedCartSupport[0].hostGateRolesDefault=['customer'];
 assert.throws(()=>validate({},wrongCart),'add ungated metadata bound');
 const wrongRefund=structuredClone(manifest);wrongRefund.reviewedCartSupport[6].consequence='money_refund';
 assert.throws(()=>validate({},wrongRefund),'refund-request ticket metadata cannot drift');
 const inventedCart=structuredClone(manifest);inventedCart.reviewedCartSupport[0].originalCheckIds=['V12'];
 assert.throws(()=>validate({},inventedCart),'no original ID inferred from cart label');
 const missingCart=structuredClone(manifest);missingCart.reviewedCartSupport.pop();
 assert.throws(()=>validate({},missingCart),'seven source-reviewed cart/support rows retained');
 const product='agent-host/agents/product-search',summary='agent-host/agents/summarizer';
 const productSummaryChanges=[
  [`${product}/server.js`,"required: ['query']","required: ['filters']"],
  [`${product}/server.js`,'extractCaller(rawArgs)','extractCaller({})'],
  [`${product}/server.js`,"case 'similar': return _wrap(await similar(args || {}));","case 'similar': return _wrap(await search(args || {}));"],
  [`${summary}/server.js`,"case 'summarize_file': return _wrap(await summarizeFile(args || {}));","case 'summarize_file': return _wrap(await summarizeFile({}));"],
  [`${product}/tools/search.js`,"require('./search.postgres.js')","require('./other.postgres.js')"],
  [`${product}/tools/search.postgres.js`,"WHERE name LIKE '%${query}%'","WHERE name LIKE '%other%'"],
  [`${product}/tools/search.postgres.js`,'rows = await commerce.readTeachingQuery(sql, "all")','rows = await commerce.readTeachingQuery("other", "all")'],
  [`${product}/tools/search.postgres.js`,'echo_html: echoHtml','echo_html: "other"'],
  [`${product}/tools/search.postgres.js`,'results: rows','results: []'],
  [`${product}/tools/search.postgres.js`,'r => r.category === filters.category','r => r.category !== filters.category'],
  [`${product}/tools/search.postgres.js`,'r => Number(r.price) <= filters.max_price','r => Number(r.price) >= filters.max_price'],
  [`${product}/tools/search.postgres.js`,'r => Number(r.price) >= filters.min_price','r => Number(r.price) <= filters.min_price'],
  [`${product}/tools/similar.postgres.js`,'commerce.product_search_similar_1(product_id)','commerce.product_search_similar_1(1)'],
  [`${product}/tools/similar.postgres.js`,"new VectorStore({ corpus: 'manuals' })","new VectorStore({ corpus: 'other' })"],
  [`${product}/tools/similar.postgres.js`,'if (await store.count() > 0)','if (true)'],
  [`${product}/tools/similar.postgres.js`,'String(rag_query || `${target.name} ${target.description || \'\'}`)','String(`${target.name} ${target.description || \'\'}`)'],
  [`${product}/tools/similar.postgres.js`,'retrieved = await store.search(query, 5)','retrieved = await store.search("other", 5)'],
  [`${product}/tools/similar.postgres.js`,'_applyRetrievalBias(results, retrieved, all)','_applyRetrievalBias(results, [], all)'],
  [`${product}/tools/similar.postgres.js`,'r.category === target.category ? 2 : 0','r.category !== target.category ? 2 : 0'],
  [`${product}/tools/similar.postgres.js`,'b.score - a.score','a.score - b.score'],
  [`${product}/tools/similar.postgres.js`,'return [...promotedRows, ...kept].slice(0, 5)','return results.slice(0, 5)'],
  [`${product}/tools/similar.postgres.js`,'retrieved_context: retrieved','retrieved_context: []'],
  [`${product}/tools/similar.postgres.js`,'seed: { id: target.id, name: target.name }','seed: { id: 1, name: target.name }'],
  [`${product}/tools/personalized_feed.postgres.js`,'commerce.product_search_personalizedFeed_1()','commerce.product_search_personalizedFeed_1(1)'],
  [`${product}/tools/personalized_feed.postgres.js`,'feed: rows','feed: []'],
  [`${summary}/tools/summarize_product.postgres.js`,'commerce.summarizer_summarizeProduct_1(product_id)','commerce.summarizer_summarizeProduct_1(1)'],
  [`${summary}/tools/summarize_product.postgres.js`,'description: row.description','description: "other"'],
  [`${summary}/tools/summarize_product.postgres.js`,"if (!row) return { error: 'unknown product_id', product_id }","if (!row) return { error: 'unknown product_id', product_id: 1 }"],
  [`${summary}/tools/summarize_reviews.postgres.js`,'commerce.summarizer_summarizeReviews_1(product_id, k)','commerce.summarizer_summarizeReviews_1(product_id, 1)'],
  [`${summary}/tools/summarize_reviews.postgres.js`,'reviews: rows','reviews: []'],
  [`${summary}/tools/summarize_reviews.postgres.js`,'rows.map(r => r.body)','rows.map(r => r.author_id)'],
  [`${summary}/tools/explain_return_policy.js`,"if (u.protocol === 'file:')","if (u.protocol === 'other:')"],
  [`${summary}/tools/explain_return_policy.js`,"const lib = u.protocol === 'https:' ? https : http","const lib = u.protocol === 'https:' ? http : https"],
  [`${summary}/tools/explain_return_policy.js`,'const u = new URL(target)','const u = new URL("http://other/")'],
  [`${summary}/tools/explain_return_policy.js`,"method: 'GET'","method: 'POST'"],
  [`${summary}/tools/explain_return_policy.js`,'hostname: u.hostname','hostname: "other"'],
  [`${summary}/tools/explain_return_policy.js`,'path: u.pathname + u.search','path: u.pathname'],
  [`${summary}/tools/explain_return_policy.js`,'req.setTimeout(4000','req.setTimeout(40000'],
  [`${summary}/tools/explain_return_policy.js`,'req.end();','// request never started'],
  [`${summary}/tools/explain_return_policy.js`,"chunks += c.toString('utf8')","chunks += ''"],
  [`${summary}/tools/explain_return_policy.js`,"fs.readFileSync(u.pathname, 'utf8')","fs.readFileSync('/other', 'utf8')"],
  [`${summary}/tools/explain_return_policy.js`,"return { url: policy_url, status: 200, body, source: 'file' }","return { url: policy_url, status: 200, body: '', source: 'file' }"],
  [`${summary}/tools/explain_return_policy.js`,'return { url: policy_url, error: e.message }','return { url: policy_url, error: "other" }'],
  [`${summary}/tools/explain_return_policy.js`,'_fetchHttp(policy_url)','_fetchHttp("other")'],
  [`${summary}/tools/explain_return_policy.js`,'body: r.body','body: "other"'],
  [`${summary}/tools/summarize_file.js`,'const target = filePath','const target = cleaned'],
  [`${summary}/tools/summarize_file.js`,"String(filePath).replace(/\\.\\.\\//g, '')","String(filePath).replace(/\\.\\.\\//g, 'other')"],
  [`${summary}/tools/summarize_file.js`,'path.extname(target)','path.extname(cleaned)'],
  [`${summary}/tools/summarize_file.js`,"fs.readFileSync(target, 'utf8')","fs.readFileSync('/other', 'utf8')"],
  [`${summary}/tools/summarize_file.js`,'return { path: target, error: e.message }','return { path: target, error: "other" }'],
  [`${summary}/tools/summarize_file.js`,'body,                                       // verbatim','body: "other",                                       // verbatim'],
  ['server/database/postgres/secureshopCommerceDb.js',"WHERE status = 'active'\n    ORDER BY RANDOM()","WHERE status = 'inactive'\n    ORDER BY RANDOM()"],
  ['server/database/postgres/secureshopCommerceDb.js','FROM secureshop.products WHERE id = $1','FROM secureshop.products WHERE id = $2'],
  ['server/database/postgres/secureshopCommerceDb.js','FROM secureshop.reviews\n    WHERE product_id = $1','FROM secureshop.reviews\n    WHERE product_id = $2'],
  ['server/services/secureshop/toolManifest.js',"customer: ['product-search','summarizer'","customer: ['summarizer'"],
 ];
 for(const [target,before,after] of productSummaryChanges)assert.throws(()=>validate(mutation(target,before,after)),undefined,`${target}: ${before}`);
 const wrongSearch=structuredClone(manifest);wrongSearch.reviewedProductSearchSummarizer[0].originalCheckIds=['V32'];
 assert.throws(()=>validate({},wrongSearch),'no original objective inferred from similar tool label');
 const missingProduct=structuredClone(manifest);missingProduct.reviewedProductSearchSummarizer.pop();
 assert.throws(()=>validate({},missingProduct),'seven source-reviewed product-search/summarizer rows retained');
 const uploadServer='agent-host/agents/uploads/server.js',uploadTools='agent-host/agents/uploads/tools/index.js';
 const uploadsChanges=[
  [uploadServer,"required: ['user_id', 'file_bytes_base64', 'filename']","required: ['user_id', 'filename']"],
  [uploadServer,'extractCaller(rawArgs)','extractCaller({})'],
  [uploadServer,"name === 'upload_product_image' || name === 'upload_product_manual'","name === 'upload_avatar' || name === 'upload_product_manual'"],
  [uploadServer,"enforceRole(caller, ['merchant', 'admin'])","enforceRole(caller, ['admin'])"],
  [uploadServer,'if (denied) return denied;','if (denied) { denied; }'],
  [uploadServer,"case 'upload_avatar':          return _wrap(await upload_avatar(args || {}));","case 'upload_avatar':          return _wrap(await upload_avatar({}));"],
  [uploadServer,"case 'upload_product_manual':  return _wrap(await upload_product_manual(args || {}));","case 'upload_product_manual':  return _wrap(await upload_product_image(args || {}));"],
  [uploadServer,'return callTool(name, rawArgs)','return callTool(name, {})'],
  [uploadTools,'upload_avatar: args => upload_avatar(args)','upload_avatar: args => upload_avatar({}, getSecureShopUploadRoot())'],
  [uploadTools,"Buffer.from(fileBytesBase64, 'base64')","Buffer.from('other', 'base64')"],
  [uploadTools,"String(name || 'file').replace(/\\.\\.\\//g, '')","String(name || 'file').replace(/\\.\\.\\//g, 'other')"],
  [uploadTools,'path.resolve(base, cleaned)','path.resolve(base, "other")'],
  [uploadTools,'const dir = KIND_DIRS[kind]','const dir = KIND_DIRS.avatar'],
  [uploadTools,"avatar: 'avatars'","avatar: 'other'"],
  [uploadTools,"relToBase.startsWith('..')","relToBase.startsWith('safe')"],
  [uploadTools,"String(scopeId || 'unscoped')","String('unscoped')"],
  [uploadTools,'const cleaned = _cleanFilename(filename)','const cleaned = _cleanFilename("other")'],
  [uploadTools,'_resolveUploadPath({ kind, scopeId, filename }, uploadRoot)','_resolveUploadPath({ kind: "avatar", scopeId, filename }, uploadRoot)'],
  [uploadTools,'uploadRoot = getSecureShopUploadRoot()','uploadRoot = "/other"'],
  [uploadTools,'const outPath = isTraversal ? abs : path.join(base, finalName)','const outPath = path.join(base, finalName)'],
  [uploadTools,'fs.writeFileSync(outPath, buffer)','fs.writeFileSync(outPath, Buffer.from("other"))'],
  [uploadTools,'attempted: outPath','attempted: "other"'],
  [uploadTools,'written_path: outPath','written_path: "other"'],
  [uploadTools,'size_bytes: buffer.length','size_bytes: 0'],
  [uploadTools,'scope_id: scopeId','scope_id: 1'],
  [uploadTools,'cleaned_filename: cleaned','cleaned_filename: "other"'],
  [uploadTools,"mime: String(mime || 'application/octet-stream')","mime: 'other'"],
  [uploadTools,'const relFromUploadRoot = path.relative(uploadRoot, outPath)','const relFromUploadRoot = path.relative(uploadRoot, "/other")'],
  [uploadTools,"relFromUploadRoot !== '..'","relFromUploadRoot === '..'"],
  [uploadTools,'_ensureDir(path.dirname(outPath))','_ensureDir(base)'],
  [uploadTools,'path.relative(REPO, outPath)','path.relative(REPO, "/other")'],
  [uploadTools,"kind: 'avatar', scopeId: user_id","kind: 'avatar', scopeId: 1"],
  [uploadTools,"kind: 'product_image', scopeId: product_id","kind: 'product_image', scopeId: 1"],
  [uploadTools,"kind: 'return_evidence', scopeId: order_id","kind: 'return_evidence', scopeId: 1"],
  [uploadTools,"kind: 'product_manual', scopeId: product_id","kind: 'product_manual', scopeId: 1"],
  [uploadTools,'if (!meta.ok) return meta','if (!meta.ok) { meta; }'],
  [uploadTools,'extractText({ filePath: meta.written_path })','extractText({ filePath: "other" })'],
  [uploadTools,"new VectorStore({ corpus: 'manuals' })","new VectorStore({ corpus: 'other' })"],
  [uploadTools,"chunkText(extracted.text || '', 500)","chunkText('other', 500)"],
  [uploadTools,'sourceId: Number(product_id) || 0','sourceId: 1'],
  [uploadTools,'text: chunks[i]','text: "other"'],
  [uploadTools,'text: chunks[i]','text: chunks[0]'],
  [uploadTools,'i < chunks.length','i < 1'],
  [uploadTools,'const id = await store.add({','const id = store.add({'],
  [uploadTools,'chunkIds.push(id)','chunkIds.push(1)'],
  [uploadTools,'chunk_ids: chunkIds','chunk_ids: []'],
  [uploadTools,'extracted_bytes: (extracted.text || \'\').length','extracted_bytes: 0'],
  [uploadTools,'extractor: extracted.extractor','extractor: "other"'],
  [uploadTools,'extractor_error: extracted.error || null','extractor_error: null'],
  [uploadTools,"if (ext === '.pdf')","if (ext === '.txt')"],
  [uploadTools,"extractor: 'mammoth'","extractor: 'other'"],
  [uploadTools,"extractor: 'raw-utf8-generic'","extractor: 'other'"],
  [uploadTools,"const raw = String(id || '')","const raw = String('other')"],
  [uploadTools,'const cleaned = _cleanFilename(raw)','const cleaned = "other"'],
  [uploadTools,'kind && KIND_DIRS[kind] ? path.join(uploadRoot, KIND_DIRS[kind]) : uploadRoot','kind && KIND_DIRS[kind] ? uploadRoot : uploadRoot'],
  [uploadTools,'const abs = path.resolve(base, cleaned)','const abs = path.resolve(base, "other")'],
  [uploadTools,'if (st.size > 5 * 1024 * 1024)','if (st.size > 50 * 1024 * 1024)'],
  [uploadTools,'const buf = fs.readFileSync(abs)','const buf = fs.readFileSync("other")'],
  [uploadTools,"body_base64: buf.toString('base64')","body_base64: 'other'"],
  [uploadTools,'cleaned,\n      abs,\n      size: st.size','cleaned: "other",\n      abs,\n      size: st.size'],
  [uploadTools,'size: st.size,\n      mime: _guessMime(abs)','size: 0,\n      mime: _guessMime(abs)'],
  [uploadTools,'mime: _guessMime(abs)','mime: "other"'],
  [uploadTools,'return { ok: false, id: raw, cleaned, abs, error: e.message }','return { ok: false, id: raw, cleaned, abs, error: "other" }'],
  [uploadTools,"buf.toString('utf8').slice(0, 20000)","buf.toString('base64').slice(0, 20000)"],
  [uploadTools,".slice(0, 20000)",".slice(0, 200000)"],
  ['server/services/secureshop/toolManifest.js',"'uploads','email','summarizer'","'email','summarizer'"],
 ];
 for(const [target,before,after] of uploadsChanges)assert.throws(()=>validate(mutation(target,before,after)),undefined,`${target}: ${before}`);
 const falseUploadCredit=structuredClone(manifest);falseUploadCredit.reviewedUploads[0].nativeEvidence={completed:true};
 assert.throws(()=>validate({},falseUploadCredit),'source-only uploads cannot claim native evidence');
 const missingUpload=structuredClone(manifest);missingUpload.reviewedUploads.pop();
 assert.throws(()=>validate({},missingUpload),'five reviewed uploads rows retained');
});
