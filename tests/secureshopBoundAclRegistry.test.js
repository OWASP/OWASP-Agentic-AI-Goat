'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DIAGNOSTIC_PREPARE_KEY, DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256, TICKET_PREPARE_KEY, TICKET_PREDECESSOR_REGISTRY_SHA256, COUPON_PREPARE_KEY, COUPON_PREDECESSOR_REGISTRY_SHA256, PRICING_COMPARE_PREPARE_KEY, PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256, ADMIN_MANAGEMENT_PREPARE_KEYS, ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256, ADMIN_AUDIT_SYSTEM_KEYS, ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256, ADMIN_MCP_KEYS, ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256, ADMIN_POLICY_KEYS, ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256, PASSWORD_RESET_SETUP_KEY, PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256, ADMIN_USER_PREPARE_KEYS, ADMIN_USER_REGISTRY_SHA256, MERCHANT_ORDER_KEYS, MERCHANT_ORDER_REGISTRY_SHA256, MERCHANT_REVIEW_KEYS, PROFILE_CHAT_KEYS, PROFILE_CHAT_REGISTRY_SHA256, REFUND_SETUP_REGISTRY_SHA256, REGISTRY, REGISTRY_SHA256, PREDECESSOR_REGISTRY_SHA256, ADDED_TOOL_KEYS,
  PREVIOUS_REGISTRY_SHA256, INVENTORY_REGISTRY_SHA256, PRICING_REGISTRY_SHA256, LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, LISTING_EDIT_REGISTRY_SHA256, LISTING_CREATE_REGISTRY_SHA256, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ADDRESS_EDIT_REGISTRY_SHA256, ADDRESS_SETUP_REGISTRY_SHA256, INVENTORY_PREPARE_KEY, PRICING_PREPARE_KEYS, MAIL_SUMMARY_KEY, MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256, COUPON_PROBE_KEY, COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256, PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES: V27_REGISTRY_UPGRADES, BASE_REGISTRY_UPGRADES, MANUAL_SEARCH_KEY, MERCHANT_MAIL_KEYS, MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256, MERCHANT_MAIL_PREPARE_KEYS, MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256, MERCHANT_LISTING_SETUP_KEYS, MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256, REGISTRY_VERSION, createBoundAclResolver } = require('../server/services/secureshopBoundAclRegistry');
const V26_REGISTRY_UPGRADES=Object.fromEntries(Object.entries(V27_REGISTRY_UPGRADES).filter(([hash])=>hash!==MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256&&hash!==COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256).map(([hash,keys])=>[hash,keys.filter(key=>key!==MAIL_SUMMARY_KEY)]));
const LATEST_REGISTRY_UPGRADES = Object.fromEntries(Object.entries(V26_REGISTRY_UPGRADES).filter(([hash])=>hash!==DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256).map(([hash,keys])=>[hash,keys.filter(key=>key!==DIAGNOSTIC_PREPARE_KEY)]));
const CURRENT_REGISTRY_UPGRADES = Object.fromEntries(Object.entries(LATEST_REGISTRY_UPGRADES).filter(([hash])=>hash!==TICKET_PREDECESSOR_REGISTRY_SHA256).map(([hash,keys])=>[hash,keys.filter(key=>key!==TICKET_PREPARE_KEY)]));
const LEGACY_COUPON_ROW = Object.freeze({toolKey:COUPON_PROBE_KEY,workflow:null,supported:false,roleApplicability:{customer:false,merchant:false,admin:false},defaultAllowed:{customer:true,merchant:false,admin:true},unavailableReason:'No supported bound execution workflow'});
const LEGACY_SEARCH_ROW = Object.freeze({toolKey:'product-search.search',workflow:null,supported:false,roleApplicability:{customer:false,merchant:false,admin:false},defaultAllowed:{customer:true,merchant:true,admin:true},unavailableReason:'No supported bound execution workflow'});
const V35_REGISTRY = require('./helpers/secureshopHistoricalRegistry').registryV35Rows(REGISTRY);
const V29_REGISTRY = require('./helpers/secureshopHistoricalRegistry').registryV29Rows(REGISTRY);
const HISTORICAL_REGISTRY = V29_REGISTRY.map(row=>row.toolKey===COUPON_PROBE_KEY?LEGACY_COUPON_ROW:row.toolKey==='product-search.search'?LEGACY_SEARCH_ROW:row);
const V24_REGISTRY = HISTORICAL_REGISTRY.filter(row=>row.toolKey!==MAIL_SUMMARY_KEY&&row.toolKey!==TICKET_PREPARE_KEY&&row.toolKey!==DIAGNOSTIC_PREPARE_KEY);
const V23_REGISTRY = V24_REGISTRY.filter(row=>row.toolKey!==COUPON_PREPARE_KEY);
const V21_REGISTRY = V23_REGISTRY.filter(row=>!MERCHANT_MAIL_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_LISTING_SETUP_KEYS.includes(row.toolKey));
const V20_REGISTRY = V21_REGISTRY.filter(row=>!MERCHANT_MAIL_KEYS.includes(row.toolKey));
const V19_REGISTRY = V20_REGISTRY.filter(row=>row.toolKey!==MANUAL_SEARCH_KEY);
const V18_REGISTRY = V19_REGISTRY.filter(row=>row.toolKey!==PRICING_COMPARE_PREPARE_KEY);
const V17_REGISTRY = V18_REGISTRY.filter(row=>!ADMIN_MANAGEMENT_PREPARE_KEYS.includes(row.toolKey));
const V16_REGISTRY = V17_REGISTRY.filter(row=>!ADMIN_AUDIT_SYSTEM_KEYS.includes(row.toolKey));
const V15_REGISTRY = V16_REGISTRY.filter(row=>!ADMIN_MCP_KEYS.includes(row.toolKey));
const REGISTRY_UPGRADES = Object.fromEntries(Object.entries(BASE_REGISTRY_UPGRADES)
  .filter(([sha])=>sha!==PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256)
  .map(([sha,keys])=>[sha,keys.filter(key=>key!==PRICING_COMPARE_PREPARE_KEY)]));
const withoutManagement = keys => keys.filter(key=>!ADMIN_MANAGEMENT_PREPARE_KEYS.includes(key));
const beforeMcp = keys => withoutManagement(keys).filter(key=>!ADMIN_MCP_KEYS.includes(key)&&!ADMIN_AUDIT_SYSTEM_KEYS.includes(key));
const cases = [
  ['review', 'Review', 'merchant'], ['manual', 'Manual', 'merchant'], ['inbox', 'PersonaInbox', 'customer'],
  ['ssrf', 'Ssrf', 'customer'], ['audit-summary', 'Audit', 'admin'],
];
for (const [workflow, name, role] of cases) test(`${workflow} agrees with real execution manifest and role admission`, async () => {
  const config = require(`../server/services/secureshop${name}ExecutionConfig`)[`createSecureShop${name}ExecutionConfig`]();
  const tools = config.manifest.getForRole(role);
  const resolver = createBoundAclResolver({ workflow, declaredTools: tools });
  for (const r of ['customer', 'merchant', 'admin']) {
    assert.equal(resolver.isRoleApplicable(r), config.manifest.getForRole(r).length > 0);
    for (const tool of tools) assert.equal(resolver.resolve(tool.agent, tool.tool).defaultAllowed[r], (await config.checkToolAcl(r, tool.agent, tool.tool)).allowed);
  }
});
for (const operation of ['summary', 'similar']) test(`product ${operation} exact operation inventory`, () => {
  const config = require('../server/services/secureshopProductExecutionConfig').createSecureShopProductExecutionConfig(operation);
  const resolver = createBoundAclResolver({ workflow: `product-${operation}`, declaredTools: config.manifest.getForRole('customer') });
  assert.equal(resolver.isRoleApplicable('admin'), false);
});
test('exact declared sets; no arbitrary names, duplicates or cross-workflow aliases', () => {
  for (const declaredTools of [[], [{agent:'support',tool:'refund_request'}], [{agent:'support',tool:'refund_request'},{agent:'support',tool:'refund_request'}]]) {
    assert.throws(() => createBoundAclResolver({workflow:'refund', declaredTools}), TypeError);
  }
  const tools = [{agent:'support',tool:'order_status'},{agent:'support',tool:'refund_request'}];
  const resolver = createBoundAclResolver({workflow:'refund',declaredTools:tools});
  tools[0].agent='evil';
  assert.ok(resolver.resolve('support','order_status'));
  assert.equal(resolver.resolve('evil','order_status'),null);
  assert.equal(resolver.resolve('user-management','set_role'),null);
});
test('MCP aliases require exact admitted identity, scenario and schema; mappings snapshot inputs', () => {
  for (const [workflow, trustScenario] of [['mcp-rogue','rogue_registration'],['mcp-rug-pull','rug_pull']]) {
    const admittedMcp={serverIdentity:'owned-connector-123',trustScenario,schema:{serverIdentity:'owned-connector-123',version:2,schemaSha256:'a'.repeat(64),tools:[{name:'forecast_lookup'}]}};
    const config=require('../server/services/secureshopMcpTrustExecutionConfig').createSecureShopMcpTrustExecutionConfig(admittedMcp);
    const declaredTools=config.manifest.getForRole('admin');
    const resolver=createBoundAclResolver({workflow,declaredTools,admittedMcp});
    assert.equal(resolver.resolve('owned-connector-123','forecast_lookup').toolKey,`${workflow}.forecast_lookup`);
    assert.equal(resolver.resolve('another-connector','forecast_lookup'),null);
    assert.throws(()=>createBoundAclResolver({workflow,declaredTools,admittedMcp:{...admittedMcp,serverIdentity:'foreign'}}));
    admittedMcp.serverIdentity='changed';
    assert.ok(resolver.resolve('owned-connector-123','forecast_lookup'));
  }
});
test('immutable stable registry keeps unavailable legacy matrix rows without granting execution', () => {
  assert.match(REGISTRY_SHA256,/^[0-9a-f]{64}$/);
  assert.equal(new Set(REGISTRY.map(r=>r.toolKey)).size,REGISTRY.length);
  for(const row of REGISTRY) { assert.match(row.toolKey,/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/); assert.ok(Object.isFrozen(row)); assert.ok(Object.isFrozen(row.defaultAllowed)); }
  const legacy=REGISTRY.find(r=>r.toolKey==='user-management.set_role');
  assert.equal(legacy.supported,true); assert.equal(legacy.defaultAllowed.customer,false);
  assert.throws(()=>{legacy.defaultAllowed.customer=true;},TypeError);
});

test('mail read and reply use the exact closed declaration for all synthetic personas',()=>{const declaredTools=require('../server/services/secureshopBoundMailGraph').tools;const resolver=createBoundAclResolver({workflow:'mail-reply',declaredTools});for(const role of ['customer','merchant','admin']){assert.equal(resolver.isRoleApplicable(role),true);for(const tool of declaredTools)assert.equal(resolver.resolve(tool.agent,tool.tool).defaultAllowed[role],true);}assert.equal(resolver.resolve('email','send_external'),null);});

test('inventory declares only its three owned tools for merchants',()=>{const declaredTools=require('../server/services/secureshopBoundInventoryGraph').tools;const resolver=createBoundAclResolver({workflow:'inventory',declaredTools});assert.equal(resolver.isRoleApplicable('merchant'),true);for(const role of ['customer','admin'])assert.equal(resolver.isRoleApplicable(role),false);assert.equal(resolver.resolve('inventory','arbitrary_sql'),null);});
test('pricing comparison successor preserves 56 prior capabilities and adds one merchant-only preparation',()=>{
 assert.equal(PREDECESSOR_REGISTRY_SHA256,'a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64');
 assert.equal(PREVIOUS_REGISTRY_SHA256,'93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed');
 assert.equal(LISTING_CREATE_REGISTRY_SHA256,'f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b');
 assert.equal(ADDRESS_SETUP_REGISTRY_SHA256,'2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0');
 assert.equal(PROFILE_CHAT_REGISTRY_SHA256,'11d22a92e0860da587c40c7c4b0624f30f090217283104ef8b4eecf1f624a7b3');
 assert.equal(PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256,'9e427b77e3c4957eef0a7d82fe66fb5ddca17c5192ae0551b89bbce67ef114ba');
 assert.equal(ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256,'b304723f3db4faa9f94014e5231ad3b99289083732e0a892081187a44ead77dd');
 assert.equal(ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256,'45c1d52e58c9db3e4eaefa28cb472e2d5f9b555c4b94721923a1f851b4016626');
 assert.equal(ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256,'4fcf0a5032fac72ff4e907909e431403fc1fa8caccf673f4937855143adb479b');
 assert.equal(ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256,'94a618b7985f5d674d04e660e98fb65704b798d82d5ba212e24198a5895bd0a0');
 assert.equal(PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,'e01641f40076b2de5a3b250ef5e62156ae9fca0752c467cfeee5e9ff846f8c83');
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:18,rows:V18_REGISTRY})).digest('hex'),PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:19,rows:V19_REGISTRY})).digest('hex'),'ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf');
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:20,rows:V20_REGISTRY})).digest('hex'),MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:29,rows:V29_REGISTRY})).digest('hex'),'bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71');
 assert.equal(REGISTRY_VERSION,39);assert.equal(REGISTRY_SHA256,'e16a47c5c7a57a9ee60b4982795e4eb7592cf311fb4e9ee52bbbde6d73cd605f');
 const couponProbe=REGISTRY.find(row=>row.toolKey===COUPON_PROBE_KEY); assert.equal(couponProbe.workflow,'coupon-probe'); assert.deepEqual(couponProbe.defaultAllowed,{customer:true,merchant:false,admin:false}); assert.deepEqual(V27_REGISTRY_UPGRADES[COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256],[COUPON_PROBE_KEY]);
 const couponResolver=createBoundAclResolver({workflow:'coupon-probe',declaredTools:[{agent:'cart',tool:'apply_coupon'}]}); assert.equal(couponResolver.isRoleApplicable('customer'),true); assert.equal(couponResolver.isRoleApplicable('merchant'),false); assert.equal(couponResolver.resolve('cart','apply_coupon').toolKey,COUPON_PROBE_KEY);
 const byRole=[['customer-chat','customer',['user-management.set_role','catalog.search','cart.view',TICKET_PREPARE_KEY,COUPON_PREPARE_KEY,...ADDED_TOOL_KEYS.slice(0,10),ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...PROFILE_CHAT_KEYS]],
  ['merchant-assistant','merchant',[...ADDED_TOOL_KEYS.slice(10,11),MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,'merchant.listing_optimize_setup',...ADDED_TOOL_KEYS.slice(11,13),INVENTORY_PREPARE_KEY,...PRICING_PREPARE_KEYS,PRICING_COMPARE_PREPARE_KEY,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS]],
  ['admin-assistant','admin',['admin.user_lookup',...ADDED_TOOL_KEYS.slice(13),...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...ADMIN_AUDIT_SYSTEM_KEYS,...ADMIN_MANAGEMENT_PREPARE_KEYS,DIAGNOSTIC_PREPARE_KEY]]];
 assert.equal(byRole.reduce((sum,[,,keys])=>sum+keys.length,0),71);
 for(const [workflow,role,keys] of byRole){
  const declaredTools=keys.map(key=>{const [agent,tool]=key.split('.');return {agent,tool};});
  const resolver=createBoundAclResolver({workflow,declaredTools});
  assert.equal(resolver.isRoleApplicable(role),true);
  for(const key of keys){const [agent,tool]=key.split('.');assert.equal(resolver.resolve(agent,tool).toolKey,key);}
  assert.throws(()=>createBoundAclResolver({workflow,declaredTools:declaredTools.slice(1)}));
 }
});

test('merchant mail preparations preserve the v21 catalog and default-deny only populated merchant heads',()=>{
 const {createHash}=require('node:crypto');
 assert.equal(createHash('sha256').update(JSON.stringify({version:21,rows:V21_REGISTRY})).digest('hex'),MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(CURRENT_REGISTRY_UPGRADES[MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256].filter(key=>!MERCHANT_LISTING_SETUP_KEYS.includes(key)&&key!==COUPON_PREPARE_KEY),MERCHANT_MAIL_PREPARE_KEYS);
 for(const key of MERCHANT_MAIL_PREPARE_KEYS){
  const row=REGISTRY.find(value=>value.toolKey===key);
  assert.deepEqual(row,{toolKey:key,workflow:'merchant-assistant',supported:true,
   roleApplicability:{customer:false,merchant:true,admin:false},defaultAllowed:{customer:false,merchant:true,admin:false}});
 }
 for(const [predecessor,keys] of Object.entries(CURRENT_REGISTRY_UPGRADES).filter(([hash])=>hash!==MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256&&hash!==COUPON_PREDECESSOR_REGISTRY_SHA256))assert.deepEqual(keys.filter(key=>MERCHANT_MAIL_PREPARE_KEYS.includes(key)),MERCHANT_MAIL_PREPARE_KEYS);
});

test('all pinned predecessor transitions are recognized and old definitions remain byte-identical',()=>{
 const {createHash}=require('node:crypto');
 const previous=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY&&row.toolKey!==ADDRESS_SETUP_KEY&&row.toolKey!==LISTING_CREATE_PREPARE_KEY&&row.toolKey!==LISTING_EDIT_PREPARE_KEY&&row.toolKey!==INVENTORY_PREPARE_KEY&&!PRICING_PREPARE_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:2,rows:previous})).digest('hex'),PREVIOUS_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[PREVIOUS_REGISTRY_SHA256]),[INVENTORY_PREPARE_KEY,...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[PREDECESSOR_REGISTRY_SHA256]),[...ADDED_TOOL_KEYS,INVENTORY_PREPARE_KEY,...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 assert.equal(Object.keys(REGISTRY_UPGRADES).length,17);
 assert.equal(Object.keys(CURRENT_REGISTRY_UPGRADES).length,23);
 const added=REGISTRY.find(row=>row.toolKey===INVENTORY_PREPARE_KEY);
 assert.deepEqual(added.defaultAllowed,{customer:false,merchant:true,admin:false});
 assert.deepEqual(added.roleApplicability,added.defaultAllowed);
 assert.equal(added.workflow,'merchant-assistant');
});

test('pricing-only successor preserves the exact v3 catalog and fresh merchant-only defaults',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY&&row.toolKey!==ADDRESS_SETUP_KEY&&row.toolKey!==LISTING_CREATE_PREPARE_KEY&&row.toolKey!==LISTING_EDIT_PREPARE_KEY&&!PRICING_PREPARE_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:3,rows:prior})).digest('hex'),INVENTORY_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[INVENTORY_REGISTRY_SHA256]),[...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 for(const key of PRICING_PREPARE_KEYS){const row=REGISTRY.find(row=>row.toolKey===key);
  assert.equal(row.workflow,'merchant-assistant');assert.deepEqual(row.defaultAllowed,{customer:false,merchant:true,admin:false});
  assert.deepEqual(row.roleApplicability,row.defaultAllowed);
 }
});

test('listing successor preserves exact v4 catalog and has one merchant-only preparation',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY&&row.toolKey!==ADDRESS_SETUP_KEY&&row.toolKey!==LISTING_CREATE_PREPARE_KEY&&row.toolKey!==LISTING_EDIT_PREPARE_KEY);
 assert.equal(createHash('sha256').update(JSON.stringify({version:4,rows:prior})).digest('hex'),PRICING_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[PRICING_REGISTRY_SHA256]),[LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 const row=REGISTRY.find(row=>row.toolKey===LISTING_EDIT_PREPARE_KEY);
 assert.equal(row.workflow,'merchant-assistant');assert.deepEqual(row.defaultAllowed,{customer:false,merchant:true,admin:false});
});

test('creation successor pins v5 and grants only fresh merchants',()=>{
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY&&row.toolKey!==ADDRESS_SETUP_KEY&&row.toolKey!==LISTING_CREATE_PREPARE_KEY);
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:5,rows:prior})).digest('hex'),LISTING_EDIT_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[LISTING_EDIT_REGISTRY_SHA256]),[LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 assert.deepEqual(REGISTRY.find(row=>row.toolKey===LISTING_CREATE_PREPARE_KEY).defaultAllowed,{customer:false,merchant:true,admin:false});
});

test('address successor pins v6 and grants fresh customer-only no-effect preparation',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY&&row.toolKey!==ADDRESS_SETUP_KEY);
 assert.equal(createHash('sha256').update(JSON.stringify({version:6,rows:prior})).digest('hex'),LISTING_CREATE_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[LISTING_CREATE_REGISTRY_SHA256]),[ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 const row=REGISTRY.find(row=>row.toolKey===ADDRESS_SETUP_KEY);
 assert.equal(row.workflow,'customer-chat');
 assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
});

test('edit successor pins v7 and fresh customer-only selected handoff',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY&&row.toolKey!==ADDRESS_EDIT_SETUP_KEY);
 assert.equal(createHash('sha256').update(JSON.stringify({version:7,rows:prior})).digest('hex'),ADDRESS_SETUP_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[ADDRESS_SETUP_REGISTRY_SHA256]),[ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 const row=REGISTRY.find(row=>row.toolKey===ADDRESS_EDIT_SETUP_KEY);
 assert.equal(row.workflow,'customer-chat');
 assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
});

test('refund handoff adds only its fresh customer permission and preserves exact v8 catalog',()=>{
 const previous=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey)&&row.toolKey!==REFUND_SETUP_KEY);
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:8,rows:previous})).digest('hex'),ADDRESS_EDIT_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[ADDRESS_EDIT_REGISTRY_SHA256]),[REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 const row=REGISTRY.find(row=>row.toolKey===REFUND_SETUP_KEY);
 assert.equal(row.workflow,'customer-chat');assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
});

test('merchant orders preserve exact v9 catalog and expose only merchant defaults',()=>{
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_ORDER_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey));
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:9,rows:prior})).digest('hex'),REFUND_SETUP_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[REFUND_SETUP_REGISTRY_SHA256]),[...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 for(const key of MERCHANT_ORDER_KEYS)assert.deepEqual(REGISTRY.find(row=>row.toolKey===key).defaultAllowed,{customer:false,merchant:true,admin:false});
});


test('merchant review successor is merchant-only and retains the exact v10 predecessor',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:10,rows:prior})).digest('hex'),MERCHANT_ORDER_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[MERCHANT_ORDER_REGISTRY_SHA256]),[...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 for(const key of MERCHANT_REVIEW_KEYS){const row=REGISTRY.find(row=>row.toolKey===key);assert.equal(row.workflow,'merchant-assistant');assert.deepEqual(row.defaultAllowed,{customer:false,merchant:true,admin:false});}
});


test('profile successor pins v11 and grants only fresh customer profile capabilities',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey)&&!PROFILE_CHAT_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:11,rows:prior})).digest('hex'),PROFILE_CHAT_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[PROFILE_CHAT_REGISTRY_SHA256]),[...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 for(const key of PROFILE_CHAT_KEYS){
  const row=REGISTRY.find(row=>row.toolKey===key);
  assert.equal(row.workflow,'customer-chat');
  assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
  assert.deepEqual(row.roleApplicability,row.defaultAllowed);
 }
});


test('admin preparation successor retains exact v12 and adds only admin capabilities',()=>{
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(row.toolKey));
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:12,rows:prior})).digest('hex'),ADMIN_USER_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[ADMIN_USER_REGISTRY_SHA256]),[...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS]);
 for(const key of ADMIN_USER_PREPARE_KEYS){const row=REGISTRY.find(row=>row.toolKey===key);assert.equal(row.workflow,'admin-assistant');assert.deepEqual(row.defaultAllowed,{customer:false,merchant:false,admin:true});assert.deepEqual(row.roleApplicability,row.defaultAllowed);}
});


test('password reset setup adds one admin-only v14 denial without changing v13 rows',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>row.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:13,rows:prior})).digest('hex'),PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(withoutManagement(REGISTRY_UPGRADES[PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256]).filter(key=>!ADMIN_POLICY_KEYS.includes(key)&&!ADMIN_MCP_KEYS.includes(key)&&!ADMIN_AUDIT_SYSTEM_KEYS.includes(key)),[PASSWORD_RESET_SETUP_KEY]);
 const row=REGISTRY.find(value=>value.toolKey===PASSWORD_RESET_SETUP_KEY);
 assert.equal(row.workflow,'admin-assistant');
 assert.deepEqual(row.roleApplicability,{customer:false,merchant:false,admin:true});
 assert.deepEqual(row.defaultAllowed,row.roleApplicability);
 assert.equal(V15_REGISTRY.length,prior.length+1+ADMIN_POLICY_KEYS.length);
});

test('policy successor retains exact v14 and adds only six admin-assistant keys',()=>{
 const {createHash}=require('node:crypto');
 const prior=V15_REGISTRY.filter(row=>!ADMIN_POLICY_KEYS.includes(row.toolKey));
 assert.equal(createHash('sha256').update(JSON.stringify({version:14,rows:prior})).digest('hex'),ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(beforeMcp(REGISTRY_UPGRADES[ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256]),ADMIN_POLICY_KEYS);
 assert.equal(V15_REGISTRY.length,prior.length+ADMIN_POLICY_KEYS.length);
 for(const key of ADMIN_POLICY_KEYS){const row=REGISTRY.find(value=>value.toolKey===key);assert.equal(row.workflow,'admin-assistant');assert.deepEqual(row.roleApplicability,{customer:false,merchant:false,admin:true});assert.deepEqual(row.defaultAllowed,row.roleApplicability);}
 const declaredTools=[...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...ADMIN_AUDIT_SYSTEM_KEYS,...ADMIN_MANAGEMENT_PREPARE_KEYS,DIAGNOSTIC_PREPARE_KEY].map(key=>{const [agent,tool]=key.split('.');return{agent,tool};});
 const existing=['admin.users_search','admin.user_lookup','admin.audit_recent','admin.role_change_prepare','admin.ban_prepare',PASSWORD_RESET_SETUP_KEY].map(key=>{const [agent,tool]=key.split('.');return{agent,tool};});
 const resolver=createBoundAclResolver({workflow:'admin-assistant',declaredTools:[...existing,...declaredTools]});
 assert.equal(resolver.isRoleApplicable('admin'),true);assert.equal(resolver.isRoleApplicable('merchant'),false);
 for(const tool of declaredTools)assert.equal(resolver.resolve(tool.agent,tool.tool).toolKey,`${tool.agent}.${tool.tool}`);
 assert.throws(()=>createBoundAclResolver({workflow:'admin-assistant',declaredTools:[...existing,...declaredTools.slice(1)]}));
});

test('owned MCP successor retains exact v15 and adds only six admin-assistant keys',()=>{
 const {createHash}=require('node:crypto');
 assert.equal(createHash('sha256').update(JSON.stringify({version:15,rows:V15_REGISTRY})).digest('hex'),ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(withoutManagement(REGISTRY_UPGRADES[ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256]).filter(key=>!ADMIN_AUDIT_SYSTEM_KEYS.includes(key)),ADMIN_MCP_KEYS);
 assert.equal(V16_REGISTRY.length,V15_REGISTRY.length+ADMIN_MCP_KEYS.length);
 for(const key of ADMIN_MCP_KEYS){const row=REGISTRY.find(value=>value.toolKey===key);assert.equal(row.workflow,'admin-assistant');assert.deepEqual(row.roleApplicability,{customer:false,merchant:false,admin:true});assert.deepEqual(row.defaultAllowed,row.roleApplicability);}
 const existing=['admin.users_search','admin.user_lookup','admin.audit_recent','admin.role_change_prepare','admin.ban_prepare',PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_AUDIT_SYSTEM_KEYS,...ADMIN_MANAGEMENT_PREPARE_KEYS,DIAGNOSTIC_PREPARE_KEY];
 const declaredTools=[...existing,...ADMIN_MCP_KEYS].map(key=>{const [agent,tool]=key.split('.');return{agent,tool};});
 const resolver=createBoundAclResolver({workflow:'admin-assistant',declaredTools});
 for(const key of ADMIN_MCP_KEYS){const [agent,tool]=key.split('.');assert.equal(resolver.resolve(agent,tool).toolKey,key);}
 assert.throws(()=>createBoundAclResolver({workflow:'admin-assistant',declaredTools:declaredTools.slice(1)}));
});


test('admin audit and system read successor retains v16 and adds only three fresh admin defaults',()=>{
 const {createHash}=require('node:crypto');
 assert.equal(createHash('sha256').update(JSON.stringify({version:16,rows:V16_REGISTRY})).digest('hex'),ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(withoutManagement(REGISTRY_UPGRADES[ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256]),ADMIN_AUDIT_SYSTEM_KEYS);
 assert.equal(V17_REGISTRY.length,V16_REGISTRY.length+ADMIN_AUDIT_SYSTEM_KEYS.length);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='admin-assistant').map(row=>{const [agent,tool]=row.toolKey.split('.');return {agent,tool};});
 const resolver=createBoundAclResolver({workflow:'admin-assistant',declaredTools});
 for(const key of ADMIN_AUDIT_SYSTEM_KEYS){const row=REGISTRY.find(value=>value.toolKey===key);assert.deepEqual(row.defaultAllowed,{customer:false,merchant:false,admin:true});const [agent,tool]=key.split('.');assert.equal(resolver.resolve(agent,tool).toolKey,key);}
});


test('coupon preparation is customer-only and preserves the entire v23 policy catalog',()=>{
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:23,rows:V23_REGISTRY})).digest('hex'),COUPON_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(CURRENT_REGISTRY_UPGRADES[COUPON_PREDECESSOR_REGISTRY_SHA256],[COUPON_PREPARE_KEY]);
 const row=REGISTRY.find(value=>value.toolKey===COUPON_PREPARE_KEY);
 assert.equal(row.workflow,'customer-chat');
 assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
 for(const keys of Object.values(CURRENT_REGISTRY_UPGRADES))assert.equal(keys.filter(key=>key===COUPON_PREPARE_KEY).length,1);
});

test('ticket preparation adds exactly one customer-only proposal without changing v24 rows',()=>{
 assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify({version:24,rows:V24_REGISTRY})).digest('hex'),TICKET_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(LATEST_REGISTRY_UPGRADES[TICKET_PREDECESSOR_REGISTRY_SHA256],[TICKET_PREPARE_KEY]);
 const row=REGISTRY.find(value=>value.toolKey===TICKET_PREPARE_KEY);
 assert.deepEqual(row.roleApplicability,{customer:true,merchant:false,admin:false});
 assert.deepEqual(row.defaultAllowed,{customer:true,merchant:false,admin:false});
 assert.equal(row.workflow,'customer-chat');
 for(const keys of Object.values(LATEST_REGISTRY_UPGRADES))assert.equal(keys.filter(key=>key===TICKET_PREPARE_KEY).length,1);
});

test('file path summary reuses existing customer read authority without replacing registry history', () => {
 const declaration = [{agent:'summarizer',tool:'summarize_file'}];
 const resolver = createBoundAclResolver({workflow:'file-path-summary',declaredTools:declaration});
 assert.equal(resolver.isRoleApplicable('customer'),true);
 assert.equal(resolver.isRoleApplicable('merchant'),false);
 assert.equal(resolver.isRoleApplicable('admin'),false);
 assert.equal(resolver.resolve('summarizer','summarize_file').defaultAllowed.customer,true);
 assert.equal(resolver.resolve('system','read_config'),null);
 assert.equal(require('../server/services/secureshopBoundAclRegistry').USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256,'435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc');
});

test('v34 adds only distinct admin lookup, preserves exact v33 bytes and appends one administrator denial to every predecessor',()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
 const oldRows=V35_REGISTRY.filter(row=>![R.USER_LOOKUP_KEY,R.UPLOAD_PREVIEW_KEY].includes(row.toolKey));
 assert.equal(hash(JSON.stringify({version:33,rows:oldRows})),R.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(hash(JSON.stringify({version:34,rows:V35_REGISTRY.filter(row=>row.toolKey!==R.UPLOAD_PREVIEW_KEY)})),R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256);
 const lookup=R.REGISTRY.find(row=>row.toolKey===R.USER_LOOKUP_KEY);assert.deepEqual(lookup,{toolKey:'admin.user_lookup',workflow:'admin-assistant',supported:true,roleApplicability:{customer:false,merchant:false,admin:true},defaultAllowed:{customer:false,merchant:false,admin:true}});
 assert.deepEqual(R.REGISTRY.find(row=>row.toolKey==='admin.users_search'),oldRows.find(row=>row.toolKey==='admin.users_search'));
 for(const [prior,keys]of Object.entries(R.PRE_USER_LOOKUP_REGISTRY_UPGRADES))assert.deepEqual(R.PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES[prior],[...keys,R.USER_LOOKUP_KEY]);
 assert.deepEqual(R.PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES[R.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256],[R.USER_LOOKUP_KEY]);
});

test('0111 reconstructs exact prior guard, retains historical branches and extends only exact legal edges/default denials',()=>{
 const fs=require('node:fs'),path=require('node:path'),hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex'),R=require('../server/services/secureshopBoundAclRegistry');
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents'),read=name=>fs.readFileSync(path.join(base,name),'utf8');
 function literals(sql){const values={};
  for(const match of sql.matchAll(/(\w+) (?:constant )?text := (E)?'((?:''|[^'])*)';/g)){let text=match[3].replaceAll("''", "'");if(match[2])text=text.replace(/\\([nrt\\])/g,(_,c)=>({n:'\n',r:'\r',t:'\t','\\':'\\'})[c]);values[match[1]]=text;}
  for(const match of sql.matchAll(/(\w+) (?:constant )?text := \$(\w+)\$([\s\S]*?)\$\2\$;/g))values[match[1]]=match[3];return values;
 }
 let body=read('0082_merchant_mail_reads_registry_successor.sql').match(/AS \$\$([\s\S]*?)\$\$;/)[1];
 for(const prefix of ['0084','0085','0087','0088','0089','0092','0096','0098','0100','0103','0104','0106','0108']){
  const sql=read(fs.readdirSync(base).find(file=>file.startsWith(prefix+'_'))),v=literals(sql);assert.equal(hash(body),v.old_guard_sha256||v.old_guard_hash,prefix);
  if(prefix==='0096'){const anchor=` IF encode(NEW.successor_sha256,'hex')='${v.old_hash}' THEN`;body=body.replaceAll(anchor,v.branch+anchor);}
  else if(prefix==='0104')body=body.replaceAll(v.broken_anchor,v.repaired_anchor);
  else{const b=sql.match(/guard_source:=replace\(guard_source,(v\d+_branch),(v\d+_branch)\|\|/);body=body.replaceAll(v.old_edge,v.old_edge+'\n'+v.new_edges).replaceAll(v[b[1]],v[b[2]]+v[b[1]]);if(['0098','0100','0103','0106','0108'].includes(prefix))body=body.replaceAll(v.denial_anchor,'\n END IF;'+v.denial_anchor);}
  if(v.upgraded_guard_sha256||v.repaired_guard_sha256)assert.equal(hash(body),v.upgraded_guard_sha256||v.repaired_guard_sha256,prefix);
 }
 const sql=read('0111_admin_user_lookup_registry_successor.sql'),v=literals(sql);assert.equal(hash(body),v.old_guard_sha256);
 for(const anchor of [v.old_edge,v.v33_branch,v.denial_anchor])assert.equal(body.split(anchor).length,2);
 const next=body.replace(v.old_edge,v.old_edge+'\n'+v.new_edges).replace(v.v33_branch,v.v34_branch+v.v33_branch).replace(v.denial_anchor,'\n END IF;'+v.denial_anchor);
 assert.equal(hash(next),v.upgraded_guard_sha256);assert.equal(next.replace(v.old_edge+'\n'+v.new_edges,v.old_edge).replace(v.v34_branch+v.v33_branch,v.v33_branch).replace('\n END IF;'+v.denial_anchor,v.denial_anchor),body);
 assert(v.v34_branch.endsWith('\n ELSE\n'));assert.doesNotMatch(v.v34_branch,/RETURN NEW/);
 for(const [prior,keys]of Object.entries(R.PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES)){
  const denials=keys.flatMap(toolKey=>R.ROLES.filter(role=>R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability[role]).map(role=>({toolKey,role})));
  assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256}')`));
  assert(v.v34_branch.includes(`WHEN '${prior}' THEN '${JSON.stringify(denials)}'::jsonb`));
  assert(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
 }
 assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
 const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');assert(read('0112_upload_preview_registry_successor.sql').includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
});

test('v35 preview has its own customer-only declaration and exact unchanged v34 predecessor',()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
 assert.equal(hash(JSON.stringify({version:34,rows:V35_REGISTRY.filter(r=>r.toolKey!==R.UPLOAD_PREVIEW_KEY)})),R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256);
 const tool={agent:'uploads',tool:'preview_legacy_image'};
 const resolver=R.createBoundAclResolver({workflow:'avatar-polyglot-preview',declaredTools:[tool]});
 assert.deepEqual(resolver.resolve(tool.agent,tool.tool).roleApplicability,{customer:true,merchant:false,admin:false});
 assert.equal(resolver.isRoleApplicable('customer'),true);
 for(const role of ['merchant','admin'])assert.equal(resolver.isRoleApplicable(role),false);
 assert.equal(resolver.resolve('uploads','upload_avatar'),null);
 assert.throws(()=>R.createBoundAclResolver({workflow:'avatar-upload',declaredTools:[tool]}));
 for(const [prior,keys]of Object.entries(R.PRE_UPLOAD_PREVIEW_REGISTRY_UPGRADES))assert.deepEqual(R.PRE_AGENCY_ROLE_REGISTRY_UPGRADES[prior],[...keys,R.UPLOAD_PREVIEW_KEY]);
 assert.deepEqual(R.PRE_AGENCY_ROLE_REGISTRY_UPGRADES[R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256],[R.UPLOAD_PREVIEW_KEY]);
});

test('0112 exact trigger successor preserves historical guards and adds only complete preview denial edges',()=>{
 const fs=require('node:fs'),path=require('node:path'),H=require('./helpers/secureshopRegistryGuard'),R=require('../server/services/secureshopBoundAclRegistry');
 const dir=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');let body=H.reconstruct();
 for(const name of ['0108_file_summary_registry_successor.sql','0111_admin_user_lookup_registry_successor.sql','0112_upload_preview_registry_successor.sql']){
  const sql=fs.readFileSync(path.join(dir,name),'utf8'),v=H.constants(sql);assert.equal(H.hash(body),v.old_guard_sha256);
  const before=body;
  for(const m of sql.matchAll(/guard_source\s*:=\s*replace\(guard_source,\s*(E?'(?:[^']|'')*'|[a-zA-Z_]\w*),\s*([\s\S]*?)\);/g)){
   const a=H.evaluate(m[1],v),b=H.evaluate(m[2],v);assert.equal(body.split(a).length,2);body=body.replace(a,b);
  }
  assert.equal(H.hash(body),v.upgraded_guard_sha256);
  if(name.startsWith('0112')){
   assert.equal(body.replace(v.old_edge+'\n'+v.new_edges,v.old_edge).replace(v.v35_branch+v.v34_branch,v.v34_branch).replace('\n END IF;'+v.denial_anchor,v.denial_anchor),before);
   for(const [prior,keys]of Object.entries(R.PRE_AGENCY_ROLE_REGISTRY_UPGRADES)){
    const denials=keys.flatMap(toolKey=>R.ROLES.filter(role=>R.REGISTRY.find(x=>x.toolKey===toolKey).roleApplicability[role]).map(role=>({toolKey,role})));
    assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256}')`));
    assert(v.v35_branch.includes(`WHEN '${prior}' THEN '${JSON.stringify(denials)}'::jsonb`));
    assert(v.constraint_additions.includes(`jsonb_array_length(added_denials)=${denials.length}`));
   }
   assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
   const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');assert(fs.readFileSync(path.join(dir,'0114_customer_agency_role_registry_successor.sql'),'utf8').includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
  }
 }
});

test('v36 promotes only customer teaching role applicability, retaining legacy defaults and secure admin preparation',()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),H=require('./helpers/secureshopRegistryGuard');
 assert.equal(H.hash(JSON.stringify({version:35,rows:V35_REGISTRY})),R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(require('./helpers/secureshopHistoricalRegistry').registryV36Rows(R.REGISTRY).filter(row=>row.toolKey!==R.AGENCY_ROLE_KEY),V35_REGISTRY.filter(row=>row.toolKey!==R.AGENCY_ROLE_KEY));
 const row=R.REGISTRY.find(row=>row.toolKey===R.AGENCY_ROLE_KEY);
 assert.deepEqual(row,{toolKey:'user-management.set_role',workflow:'customer-chat',supported:true,roleApplicability:{customer:true,merchant:false,admin:false},defaultAllowed:{customer:false,merchant:false,admin:true}});
 const declaredTools=R.REGISTRY.filter(row=>row.workflow==='customer-chat').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const resolver=R.createBoundAclResolver({workflow:'customer-chat',declaredTools});
 assert.equal(resolver.resolve('user-management','set_role'),row);assert.equal(resolver.isRoleApplicable('customer'),true);
 for(const role of ['merchant','admin'])assert.equal(resolver.isRoleApplicable(role),false);
 assert.equal(resolver.resolve('admin','role_change_prepare'),null);
 for(const [prior,keys]of Object.entries(R.PRE_AGENCY_ROLE_REGISTRY_UPGRADES))assert.deepEqual(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES[prior],[...keys,R.AGENCY_ROLE_KEY]);
 assert.deepEqual(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES[R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256],[R.AGENCY_ROLE_KEY]);
});

test('0114 reconstructs exact v36 guard, preserving every old edge and admitting only canonical new denials',()=>{
 const fs=require('node:fs'),path=require('node:path'),H=require('./helpers/secureshopRegistryGuard'),R=require('../server/services/secureshopBoundAclRegistry');
 const dir=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');let body=H.reconstruct();
 for(const name of ['0108_file_summary_registry_successor.sql','0111_admin_user_lookup_registry_successor.sql','0112_upload_preview_registry_successor.sql','0114_customer_agency_role_registry_successor.sql']){
  const sql=fs.readFileSync(path.join(dir,name),'utf8'),v=H.constants(sql),before=body;
  assert.equal(H.hash(body),v.old_guard_sha256);
  for(const m of sql.matchAll(/guard_source\s*:=\s*replace\(guard_source,\s*(E?'(?:[^']|'')*'|[a-zA-Z_]\w*),\s*([\s\S]*?)\);/g)){
   const a=H.evaluate(m[1],v),b=H.evaluate(m[2],v);assert.equal(body.split(a).length,2);body=body.replace(a,b);
  }
  assert.equal(H.hash(body),v.upgraded_guard_sha256);
  if(!name.startsWith('0114'))continue;
  assert.equal(body.replace(v.old_edge+'\n'+v.new_edges,v.old_edge).replace(v.v36_branch+v.v35_branch,v.v35_branch).replace('\n END IF;'+v.denial_anchor,v.denial_anchor),before);
  assert.equal(Object.keys(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES).length,35);
  for(const [prior,keys]of Object.entries(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES)){
   const denials=R.REGISTRY.filter(row=>keys.includes(row.toolKey)).flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
   assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.MCP_REGISTRATION_PREDECESSOR_REGISTRY_SHA256}')`));
   assert(v.v36_branch.includes(`WHEN '${prior}' THEN '${JSON.stringify(denials)}'::jsonb`));
   assert(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.MCP_REGISTRATION_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
   assert.deepEqual(denials.filter(row=>row.toolKey===R.AGENCY_ROLE_KEY),[{toolKey:R.AGENCY_ROLE_KEY,role:'customer'}]);
  }
  assert.match(sql,/constraint_def:=regexp_replace\(constraint_def/);
  assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
  assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
  const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
  assert(fs.readFileSync(path.join(dir,'0116_mcp_registration_registry_successor.sql'),'utf8').includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
  const oldSql=fs.readFileSync(path.join(dir,'0112_upload_preview_registry_successor.sql'),'utf8');
  const lengths=text=>text.match(/added_denials\) IN \(([^)]+)\)/)[1].split(',').map(Number);
  const expected=[...new Set([...lengths(oldSql),...Object.values(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES).map(keys=>keys.length)])].sort((a,b)=>a-b);
  assert.deepEqual(lengths(sql),expected);assert(readiness.includes('Object.freeze(['+[...expected,78,79,80].join(',')+'])'));
 }
});
