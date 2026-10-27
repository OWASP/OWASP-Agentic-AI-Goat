'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSecureShopBoundAclRepository } = require('../server/database/postgres/secureshopBoundAclRepository');
const { ADMIN_MCP_KEYS, ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256, ADMIN_POLICY_KEYS, PASSWORD_RESET_SETUP_KEY, ADMIN_USER_PREPARE_KEYS, ADMIN_USER_REGISTRY_SHA256, MERCHANT_REVIEW_KEYS, PROFILE_CHAT_KEYS, MERCHANT_ORDER_KEYS, REFUND_SETUP_REGISTRY_SHA256, REGISTRY_SHA256, PREDECESSOR_REGISTRY_SHA256, ADDED_TOOL_KEYS, REGISTRY, PREVIOUS_REGISTRY_SHA256, INVENTORY_PREPARE_KEY, INVENTORY_REGISTRY_SHA256, PRICING_REGISTRY_SHA256, LISTING_EDIT_PREPARE_KEY, LISTING_CREATE_PREPARE_KEY, LISTING_EDIT_REGISTRY_SHA256, LISTING_CREATE_REGISTRY_SHA256, ADDRESS_SETUP_KEY, ADDRESS_EDIT_SETUP_KEY, REFUND_SETUP_KEY, ADDRESS_EDIT_REGISTRY_SHA256, ADDRESS_SETUP_REGISTRY_SHA256, PRICING_PREPARE_KEYS, REGISTRY_UPGRADES } = require('../server/services/secureshopBoundAclRegistry');
const denialsFor = predecessorSha256 => (REGISTRY_UPGRADES[predecessorSha256] || []).flatMap(toolKey => Object.entries(REGISTRY.find(row => row.toolKey === toolKey).roleApplicability).filter(([, allowed]) => allowed).map(([role]) => ({ toolKey, role }))).sort((a, b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : a.role < b.role ? -1 : a.role > b.role ? 1 : 0);
const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 };
function input(role = 'admin') {
  return { scope, persona: { id: role === 'admin' ? 3 : 1, role }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
}
function fixture() {
  let state = { head: null, operations: [], admissions: [], overrides: [], upgrades: [], audits: [] };
  const controls = { revoked: false, mismatch: false, failAudit: false, afterCapture: null, afterCommit: null };
  const queries = [];
  const client = { async query(sql, v = []) {
    queries.push(sql);
    if (sql.startsWith('SET LOCAL')) return { rows: [] };
    if (sql.startsWith('INSERT INTO secureshop_agents.bound_tool_policy_heads')) {
      state.head ||= { policy_version: '1', enforcement_enabled: false, registry_sha256: REGISTRY_SHA256 }; return { rows: [] };
    }
    if (sql.includes('FROM secureshop_agents.bound_tool_policy_heads')) return { rows: [state.head] };
    if (sql.startsWith('UPDATE secureshop_agents.bound_tool_policy_heads')) {
      state.head.policy_version = String(BigInt(state.head.policy_version) + 1n);
      if (sql.includes('registry_sha256=')) state.head.registry_sha256 = v[5];
      else state.head.enforcement_enabled = v[5];
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO secureshop_agents.bound_tool_registry_upgrades')) {
      state.upgrades.push({ predecessorVersion: v[5], successorVersion: v[6], predecessorSha256: v[7],
        successorSha256: v[8], enforcement: v[9], overridesBefore: JSON.parse(v[10]), addedDenials: JSON.parse(v[11]) });
      return { rows: [] };
    }
    if (sql.startsWith('SELECT') && sql.includes('bound_tool_policy_operations')) return { rows: state.operations.filter(row => row.operation_id === v[5]) };
    if (sql.startsWith('INSERT') && sql.includes('bound_tool_policy_operations')) {
      state.operations.push({ operation_id: v[5], persona_id: v[6], persona_session_id: v[7], persona_role: v[8], authority_version: v[9], request_digest: v[12], receipt_json: JSON.parse(v[13]) }); return { rows: [] };
    }
    if (sql.startsWith('SELECT') && sql.includes('bound_tool_policy_overrides')) return { rows: state.overrides.filter(row => !v[5] || row.tool_key === v[5] && row.role === v[6]) };
    if (sql.startsWith('INSERT') && sql.includes('bound_tool_policy_overrides')) {
      state.overrides = state.overrides.filter(row => row.tool_key !== v[5] || row.role !== v[6]); state.overrides.push({ tool_key: v[5], role: v[6], allowed: sql.includes(',false)') ? false : v[7] }); return { rows: [] };
    }
    if (sql.startsWith('SELECT') && sql.includes('bound_tool_admissions')) return { rows: state.admissions.filter(row => row.run_id === v[5] && row.invocation_id === v[6]) };
    if (sql.startsWith('INSERT') && sql.includes('bound_tool_admissions')) {
      state.admissions.push({ admission_id: v[5], run_id: v[6], invocation_id: v[7], persona_id: v[8], persona_session_id: v[9], persona_role: v[10], authority_version: v[11], tool_key: v[12], args_digest: v[13], registry_sha256: v[14], policy_version: v[15], enforcement_enabled: v[16], allowed: v[17], action: v[18], policy_violation: v[19] }); return { rows: [] };
    }
    throw Error('Unhandled SQL: ' + sql);
  } };
  const personaAuthority = { async capture(value) {
    const binding = { ...value.scope, personaId: value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion };
    if (controls.mismatch) binding.sessionId = randomUUID();
    await controls.afterCapture?.();
    return { binding, async withPersonaEffect(work) {
      if (controls.revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' });
      const before = structuredClone(state);
      try { const result = await work(client); controls.afterCommit?.(); return result; }
      catch (e) { state = before; throw e; }
    }, async assertRemoteAdmission() { if (controls.revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); } };
  } };
  const audit = { async append(c, event) { assert.equal(c, client); if (controls.failAudit) throw Error('audit unavailable'); state.audits.push(event); } };
  return { repo: createSecureShopBoundAclRepository({ personaAuthority, audit }), controls, queries, state: () => state };
}
const permission = { kind: 'permission', toolKey: 'audit.search_by_user', role: 'admin', allowed: false };
function mutation(actor, expectedVersion = '1', change = permission) { return { ...actor, operationId: randomUUID(), expectedVersion, change: structuredClone(change) }; }
function admission(actor) { return { ...actor, workflow: 'audit-query', declaredTools: [{ agent: 'audit', tool: 'search_by_user' }], agent: 'audit', tool: 'search_by_user', runId: randomUUID(), invocationId: 'call-1', args: { username: 'synthetic' } }; }

test('owned policy defaults advisory, with all rows and explicit unavailable readOnly entries', async () => {
  const f = fixture(); const policy = await f.repo.readPolicy(input());
  assert.equal(policy.enforcement, false); assert.equal(policy.version, '1'); assert.equal(policy.registrySha256, REGISTRY_SHA256);
  assert.equal(new Set(policy.rows.map(row => row.toolKey)).size, REGISTRY.length);
  assert.deepEqual(policy.rows, REGISTRY.map(row => ({ ...row, readOnly: !row.supported, allowed: { ...row.defaultAllowed } }))); 
  assert.equal(policy.rows.find(r => r.toolKey === 'user-management.set_role').readOnly, false);
  assert.ok(f.queries.some(sql => sql.endsWith('FOR UPDATE')));
  assert.equal(f.queries.some(sql => /^(BEGIN|COMMIT)/.test(sql)), false);
});
test('known predecessor upgrades once with immutable old override snapshot and conservative new denials',async()=>{
 const f=fixture(),actor=input();
 await f.repo.readPolicy(actor);
 f.state().head.registry_sha256=PREDECESSOR_REGISTRY_SHA256;
 f.state().head.policy_version='4';f.state().head.enforcement_enabled=true;
 f.state().overrides.push({tool_key:'audit.search_by_user',role:'admin',allowed:false});
 const oldOperation={operation_id:randomUUID(),persona_id:actor.persona.id,request_digest:'old',receipt_json:{version:'2'}};
 f.state().operations.push(oldOperation);
 const policy=await f.repo.readPolicy(actor);
 assert.equal(policy.version,'5');assert.equal(policy.enforcement,true);assert.equal(policy.registrySha256,REGISTRY_SHA256);
 assert.equal(policy.rows.find(row=>row.toolKey==='audit.search_by_user').allowed.admin,false);
 const upgrade=f.state().upgrades[0];
 assert.equal(f.state().upgrades.length,1);assert.equal(upgrade.predecessorSha256,PREDECESSOR_REGISTRY_SHA256);
 assert.equal(upgrade.successorSha256,REGISTRY_SHA256);assert.equal(upgrade.predecessorVersion,'4');
 assert.deepEqual(upgrade.overridesBefore,[{toolKey:'audit.search_by_user',role:'admin',allowed:false}]);
 assert.deepEqual(upgrade.addedDenials,denialsFor(PREDECESSOR_REGISTRY_SHA256));
 for(const key of [...ADDED_TOOL_KEYS,INVENTORY_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY]){
  const row=policy.rows.find(item=>item.toolKey===key),role=Object.keys(row.roleApplicability).find(value=>row.roleApplicability[value]);
  assert.equal(row.allowed[role],false,key);
 }
 assert.deepEqual(f.state().operations,[oldOperation]);assert.equal(f.state().audits.length,0);
 assert.equal((await f.repo.readPolicy(actor)).version,'5');assert.equal(f.state().upgrades.length,1);
});
test('unknown registry and old override on a newly supported key fail without relabeling policy',async()=>{
 for(const hash of ['f'.repeat(64),PREDECESSOR_REGISTRY_SHA256]){
  const f=fixture(),actor=input();await f.repo.readPolicy(actor);
  f.state().head.registry_sha256=hash;
  if(hash===PREDECESSOR_REGISTRY_SHA256)
   f.state().overrides.push({tool_key:'cart.add',role:'customer',allowed:true});
  await assert.rejects(f.repo.readPolicy(actor),{code:'ACL_REGISTRY_MISMATCH'});
  assert.equal(f.state().head.registry_sha256,hash);assert.equal(f.state().upgrades.length,0);
 }
});
test('mutation, same actor fresh-session replay and readback are immutable and audited once', async () => {
  const f = fixture(), actor = input(), request = mutation(actor);
  const receipt = await f.repo.mutate(request);
  assert.equal(receipt.version, '2');
  const refreshed = { ...request, personaSession: { sessionId: randomUUID(), authorityVersion: '2' } };
  assert.deepEqual(await f.repo.mutate(refreshed), receipt);
  assert.deepEqual(await f.repo.readOperation(refreshed), receipt);
  assert.equal(f.state().audits.length, 1); assert.equal(f.state().operations.length, 1);
  await assert.rejects(f.repo.mutate({ ...request, change: { ...permission, allowed: true } }), { code: 'ACL_OPERATION_CONFLICT' });
  await assert.rejects(f.repo.mutate(mutation(actor)), { code: 'ACL_VERSION_CONFLICT' });
  await assert.rejects(f.repo.readOperation({ ...request, persona: { id: 99, role: 'admin' } }), { code: 'ACL_OPERATION_UNAVAILABLE' });
});
test('same-client audit failure rolls back policy and receipt', async () => {
  const f = fixture(); f.controls.failAudit = true;
  await assert.rejects(f.repo.mutate(mutation(input())), /audit unavailable/);
  assert.equal(f.state().head, null); assert.equal(f.state().operations.length, 0);
});
test('revoked or mismatched original credential cannot reach SQL; caller mutation cannot change captured request', async () => {
  const f = fixture(), request = mutation(input());
  f.controls.mismatch = true;
  await assert.rejects(f.repo.mutate(request), { code: 'SHOP_AUTH_INVALID' }); assert.equal(f.queries.length, 0);
  f.controls.mismatch = false; f.controls.revoked = true;
  await assert.rejects(f.repo.mutate(request), { code: 'SHOP_AUTH_INVALID' }); assert.equal(f.queries.length, 0);
  f.controls.revoked = false; f.controls.afterCapture = () => { request.change.allowed = true; request.persona.id = 99; };
  const result = await f.repo.mutate(request); assert.equal(result.change.allowed, false); assert.equal(f.state().operations[0].persona_id, 3);
});
test('advisory denial dispatches; enforced denial blocks; exact admission replay does not duplicate audit', async () => {
  const f = fixture(), actor = input(); await f.repo.mutate(mutation(actor));
  const request = admission(actor), denied = await f.repo.admitTool(request);
  assert.equal(denied.allowed, false); assert.equal(denied.action, 'dispatch'); assert.equal(denied.policyViolation, 'denied-by-acl');
  assert.deepEqual(await f.repo.admitTool(request), denied); assert.equal(f.state().admissions.length, 1);
  await assert.rejects(f.repo.admitTool({ ...request, args: { username: 'changed' } }), { code: 'ACL_ADMISSION_CONFLICT' });
  await f.repo.mutate(mutation(actor, '2', { kind: 'enforcement', enabled: true }));
  await assert.rejects(f.repo.admitTool(request), { code: 'ACL_ADMISSION_STALE' });
  assert.equal((await f.repo.admitTool(admission(actor))).action, 'block');
  assert.equal(f.state().audits.length, 4);
});
test('unknown tools, unavailable rows and wrong workflow roles never become permissions', async () => {
  const f = fixture();
  await assert.rejects(f.repo.mutate(mutation(input(), '1', { ...permission, toolKey: 'user-management.set_role' })), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.repo.admitTool(admission(input('customer'))), { code: 'ACL_TOOL_UNAVAILABLE' });
  await assert.rejects(f.repo.admitTool({ ...admission(input()), tool: 'invented' }), { code: 'ACL_TOOL_UNAVAILABLE' });
  assert.equal(f.queries.length, 0);
});
test('postcommit revocation reports uncertainty and preserves original receipt for authorized recovery', async () => {
  const f = fixture(), request = mutation(input());
  f.controls.afterCommit = () => { f.controls.revoked = true; };
  await assert.rejects(f.repo.mutate(request), e => e.code === 'ACL_RECEIPT_OUTCOME_UNCERTAIN' && e.cause.code === 'SHOP_AUTH_INVALID' && !Object.keys(e).includes('cause'));
  assert.equal(f.state().operations.length, 1);
  f.controls.afterCommit = null; f.controls.revoked = false;
  assert.equal((await f.repo.readOperation(request)).version, '2');
});

test('bounded canonical arguments reject cycles and excess depth before SQL', async () => {
  const f = fixture(); const cycle = {}; cycle.self = cycle;
  let nested = {}; for (let i = 0; i < 30; i++) nested = { child: nested };
  for (const args of [cycle, nested]) await assert.rejects(f.repo.admitTool({ ...admission(input()), args }), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.repo.mutate(mutation(input(), '1', { ...permission, role: 'customer' })), { code: 'INVALID_ARGUMENT' });
  assert.equal(f.queries.length, 0);
});

for(const enforcement of [true,false])test(`v2 stock capability upgrade preserves old receipt and overrides with enforcement ${enforcement}`,async()=>{
 const f=fixture(),actor=input();await f.repo.readPolicy(actor);
 f.state().head={policy_version:'8',enforcement_enabled:enforcement,registry_sha256:PREVIOUS_REGISTRY_SHA256};
 const retained={predecessorSha256:PREDECESSOR_REGISTRY_SHA256,successorSha256:PREVIOUS_REGISTRY_SHA256,successorVersion:'3'};
 f.state().upgrades.push(retained);
 const prior=[{tool_key:'merchant.catalog_search',role:'merchant',allowed:true},{tool_key:'cart.add',role:'customer',allowed:false}];
 f.state().overrides.push(...prior);
 const policy=await f.repo.readPolicy(actor);
 assert.equal(policy.version,'9');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(r=>r.toolKey===INVENTORY_PREPARE_KEY).allowed.merchant,false);
 assert.equal(policy.rows.find(r=>r.toolKey==='merchant.catalog_search').allowed.merchant,true);
 assert.equal(policy.rows.find(r=>r.toolKey==='cart.add').allowed.customer,false);
 assert.deepEqual(f.state().upgrades[0],retained);assert.equal(f.state().upgrades.length,2);
 assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(PREVIOUS_REGISTRY_SHA256));
 assert.equal(f.state().upgrades[1].predecessorSha256,PREVIOUS_REGISTRY_SHA256);
 assert.equal(f.state().upgrades[1].successorSha256,REGISTRY_SHA256);
 assert.deepEqual(f.state().overrides.slice(0,2),prior);
 await f.repo.readPolicy(actor);assert.equal(f.state().upgrades.length,2);
});
test('preexisting unsupported stock override fails closed without rewriting the retained head',async()=>{
 for(const hash of [PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256]){
  const f=fixture(),actor=input();await f.repo.readPolicy(actor);f.state().head.registry_sha256=hash;
  f.state().overrides.push({tool_key:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true});
  await assert.rejects(f.repo.readPolicy(actor),{code:'ACL_REGISTRY_MISMATCH'});
  assert.equal(f.state().head.registry_sha256,hash);assert.equal(f.state().upgrades.length,0);
 }
});

test('stock prepare is merchant-only, fresh allowed, retained enforced denied until versioned instructor change',async()=>{
 const f=fixture(),merchant=input('merchant'),admin=input('admin');
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{
  const [agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=()=>({...merchant,workflow:'merchant-assistant',declaredTools,agent:'merchant',tool:'inventory_prepare',
  runId:randomUUID(),invocationId:'prepare-1',args:{choiceId:randomUUID(),quantity:0}});
 assert.equal((await f.repo.admitTool(request())).allowed,true);
 f.state().head.registry_sha256=PREVIOUS_REGISTRY_SHA256;f.state().head.enforcement_enabled=true;
 const denied=await f.repo.admitTool(request());assert.equal(denied.allowed,false);assert.equal(denied.action,'block');
 assert.equal(denied.registrySha256,REGISTRY_SHA256);
 await assert.rejects(f.repo.mutate(mutation(admin,'1',{kind:'permission',toolKey:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true})),{code:'ACL_VERSION_CONFLICT'});
 const policy=await f.repo.readPolicy(admin);
 await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true}));
 const enabled=await f.repo.admitTool(request());assert.equal(enabled.allowed,true);assert.equal(enabled.action,'dispatch');
 await assert.rejects(f.repo.admitTool({...request(),...admin}),{code:'ACL_TOOL_UNAVAILABLE'});
});
test('retained advisory enforcement is preserved without relabeling a denied stock capability as allowed',async()=>{
 const f=fixture(),merchant=input('merchant');await f.repo.readPolicy(merchant);
 f.state().head.registry_sha256=PREVIOUS_REGISTRY_SHA256;
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const receipt=await f.repo.admitTool({...merchant,workflow:'merchant-assistant',declaredTools,agent:'merchant',tool:'inventory_prepare',runId:randomUUID(),invocationId:'p',args:{choiceId:randomUUID(),quantity:1}});
 assert.equal(receipt.enforcement,false);assert.equal(receipt.allowed,false);assert.equal(receipt.action,'dispatch');assert.equal(receipt.policyViolation,'denied-by-acl');
});

for(const enforcement of [true,false])test(`v3 pricing upgrade preserves inventory permission and historical receipts with enforcement ${enforcement}`,async()=>{
 const f=fixture(),merchant=input('merchant'),admin=input('admin');await f.repo.readPolicy(merchant);
 f.state().head={policy_version:'9',enforcement_enabled:enforcement,registry_sha256:INVENTORY_REGISTRY_SHA256};
 const retained=[{successorSha256:PREVIOUS_REGISTRY_SHA256,successorVersion:'3'},
  {successorSha256:INVENTORY_REGISTRY_SHA256,successorVersion:'7'}];
 f.state().upgrades.push(...retained);
 f.state().overrides.push({tool_key:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true});
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 for(const toolKey of PRICING_PREPARE_KEYS){const request=()=>({...merchant,workflow:'merchant-assistant',declaredTools,
   agent:'merchant',tool:toolKey.split('.')[1],runId:randomUUID(),invocationId:'prepare',args:{choiceId:randomUUID()}});
  const denied=await f.repo.admitTool(request());assert.equal(denied.allowed,false);
  assert.equal(denied.enforcement,enforcement);assert.equal(denied.action,enforcement?'block':'dispatch');
  assert.equal(denied.policyViolation,'denied-by-acl');
  const policy=await f.repo.readPolicy(admin);
  await assert.rejects(f.repo.mutate(mutation(admin,'9',{kind:'permission',toolKey,role:'merchant',allowed:true})),{code:'ACL_VERSION_CONFLICT'});
  await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey,role:'merchant',allowed:true}));
  const allowed=await f.repo.admitTool(request());assert.equal(allowed.allowed,true);assert.equal(allowed.action,'dispatch');
  await assert.rejects(f.repo.admitTool({...request(),...admin}),{code:'ACL_TOOL_UNAVAILABLE'});
 }
 assert.deepEqual(f.state().upgrades.slice(0,2),retained);assert.equal(f.state().upgrades.length,3);
 assert.deepEqual(f.state().upgrades[2].addedDenials,denialsFor(INVENTORY_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key===INVENTORY_PREPARE_KEY).allowed,true);
 await f.repo.readPolicy(admin);assert.equal(f.state().upgrades.length,3);
});
test('unknown or prematurely present Pricing override never silently transitions',async()=>{
 for(const predecessor of [PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256,INVENTORY_REGISTRY_SHA256])for(const tool_key of PRICING_PREPARE_KEYS){
  const f=fixture(),actor=input();await f.repo.readPolicy(actor);f.state().head.registry_sha256=predecessor;
  f.state().overrides.push({tool_key,role:'merchant',allowed:false});
  await assert.rejects(f.repo.readPolicy(actor),{code:'ACL_REGISTRY_MISMATCH'});
  assert.equal(f.state().head.registry_sha256,predecessor);assert.equal(f.state().upgrades.length,0);
 }
});

test('fresh Pricing preparations admit only the merchant role with the complete current manifest',async()=>{
 const f=fixture(),merchant=input('merchant');
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 for(const toolKey of PRICING_PREPARE_KEYS){const request={...merchant,workflow:'merchant-assistant',declaredTools,
   agent:'merchant',tool:toolKey.split('.')[1],runId:randomUUID(),invocationId:'prepare',args:{choiceId:randomUUID()}};
  const admitted=await f.repo.admitTool(request);assert.equal(admitted.allowed,true);assert.equal(admitted.action,'dispatch');
  for(const role of ['customer','admin'])await assert.rejects(f.repo.admitTool({...request,...input(role),runId:randomUUID()}),{code:'ACL_TOOL_UNAVAILABLE'});
 }
 assert.equal(f.state().upgrades.length,0);
});

for(const enforcement of [true,false])test(`v4 listing upgrade preserves Pricing override and advisory semantics ${enforcement}`,async()=>{
 const f=fixture(),merchant=input('merchant'),admin=input('admin');await f.repo.readPolicy(merchant);
 f.state().head={policy_version:'12',enforcement_enabled:enforcement,registry_sha256:PRICING_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:PRICING_PREPARE_KEYS[0],role:'merchant',allowed:true});
 const historical={successorSha256:PRICING_REGISTRY_SHA256,successorVersion:'10'};f.state().upgrades.push(historical);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=()=>({...merchant,workflow:'merchant-assistant',declaredTools,agent:'merchant',tool:'listing_edit_prepare',runId:randomUUID(),invocationId:'prepare',args:{choiceId:randomUUID(),patch:{name:'Changed'}}});
 const denied=await f.repo.admitTool(request());assert.equal(denied.allowed,false);assert.equal(denied.action,enforcement?'block':'dispatch');
 assert.equal(denied.policyViolation,'denied-by-acl');assert.equal(denied.enforcement,enforcement);
 assert.deepEqual(f.state().upgrades[0],historical);assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(PRICING_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key===PRICING_PREPARE_KEYS[0]).allowed,true);
 const policy=await f.repo.readPolicy(admin);await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:LISTING_EDIT_PREPARE_KEY,role:'merchant',allowed:true}));
 assert.equal((await f.repo.admitTool(request())).allowed,true);
 await f.repo.readPolicy(admin);assert.equal(f.state().upgrades.length,2);
 for(const role of ['customer','admin'])await assert.rejects(f.repo.admitTool({...request(),...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
});
test('preexisting unsupported listing override rejects every pinned upgrade',async()=>{
 for(const registry_sha256 of [PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256,INVENTORY_REGISTRY_SHA256,PRICING_REGISTRY_SHA256]){
  const f=fixture(),actor=input();await f.repo.readPolicy(actor);f.state().head.registry_sha256=registry_sha256;
  f.state().overrides.push({tool_key:LISTING_EDIT_PREPARE_KEY,role:'merchant',allowed:false});
  await assert.rejects(f.repo.readPolicy(actor),{code:'ACL_REGISTRY_MISMATCH'});assert.equal(f.state().upgrades.length,0);
 }
});

for(const enforcement of [true,false])test(`v5 creation upgrade preserves listing override and enforcement ${enforcement}`,async()=>{
 const f=fixture(),merchant=input('merchant'),admin=input('admin');await f.repo.readPolicy(merchant);
 f.state().head={policy_version:'14',enforcement_enabled:enforcement,registry_sha256:LISTING_EDIT_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:LISTING_EDIT_PREPARE_KEY,role:'merchant',allowed:true});
 const prior={successorSha256:LISTING_EDIT_REGISTRY_SHA256,successorVersion:'13'};f.state().upgrades.push(prior);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=()=>({...merchant,workflow:'merchant-assistant',declaredTools,agent:'merchant',tool:'listing_create_prepare',
  runId:randomUUID(),invocationId:'prepare',args:{listing:{name:'Notebook',description:'Paper',category:'Office',price:5}}});
 const denied=await f.repo.admitTool(request());assert.equal(denied.allowed,false);assert.equal(denied.action,enforcement?'block':'dispatch');
 assert.equal(denied.enforcement,enforcement);assert.equal(denied.policyViolation,'denied-by-acl');
 assert.deepEqual(f.state().upgrades[0],prior);assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(LISTING_EDIT_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key===LISTING_EDIT_PREPARE_KEY).allowed,true);
 const policy=await f.repo.readPolicy(admin);await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:LISTING_CREATE_PREPARE_KEY,role:'merchant',allowed:true}));
 assert.equal((await f.repo.admitTool(request())).allowed,true);await f.repo.readPolicy(admin);assert.equal(f.state().upgrades.length,2);
});
test('premature creation overrides reject all published predecessors',async()=>{
 for(const registry_sha256 of [PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256,INVENTORY_REGISTRY_SHA256,PRICING_REGISTRY_SHA256,LISTING_EDIT_REGISTRY_SHA256]){
  const f=fixture(),actor=input();await f.repo.readPolicy(actor);f.state().head.registry_sha256=registry_sha256;
  f.state().overrides.push({tool_key:LISTING_CREATE_PREPARE_KEY,role:'merchant',allowed:false});
  await assert.rejects(f.repo.readPolicy(actor),{code:'ACL_REGISTRY_MISMATCH'});assert.equal(f.state().upgrades.length,0);
 }
});

test('retained v6 address setup is denied until instructor admits it, preserving overrides',async()=>{
 const f=fixture(),actor=input('customer'),admin=input('admin');await f.repo.readPolicy(actor);
 f.state().head={policy_version:'16',enforcement_enabled:true,registry_sha256:LISTING_CREATE_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:'cart.view',role:'customer',allowed:false});
 const policy=await f.repo.readPolicy(actor);
 assert.equal(policy.registrySha256,REGISTRY_SHA256);
 assert.deepEqual(f.state().upgrades[0].addedDenials,denialsFor(LISTING_CREATE_REGISTRY_SHA256));
 assert.equal(policy.rows.find(row=>row.toolKey===ADDRESS_SETUP_KEY).allowed.customer,false);
 assert.equal(policy.rows.find(row=>row.toolKey==='cart.view').allowed.customer,false);
 const changed=await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:ADDRESS_SETUP_KEY,role:'customer',allowed:true}));
 assert.ok(changed);assert.equal((await f.repo.readPolicy(actor)).rows.find(row=>row.toolKey===ADDRESS_SETUP_KEY).allowed.customer,true);
});

test('retained v7 selected address edit is denied until an instructor admits only that key',async()=>{
 const f=fixture(),actor=input('customer'),admin=input('admin');await f.repo.readPolicy(actor);
 f.state().head={policy_version:'18',enforcement_enabled:true,registry_sha256:ADDRESS_SETUP_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:ADDRESS_SETUP_KEY,role:'customer',allowed:true});
 const policy=await f.repo.readPolicy(actor);
 assert.deepEqual(f.state().upgrades[0].addedDenials,denialsFor(ADDRESS_SETUP_REGISTRY_SHA256));
 assert.equal(policy.rows.find(row=>row.toolKey===ADDRESS_SETUP_KEY).allowed.customer,true);
 assert.equal(policy.rows.find(row=>row.toolKey===ADDRESS_EDIT_SETUP_KEY).allowed.customer,false);
 const changed=await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:ADDRESS_EDIT_SETUP_KEY,role:'customer',allowed:true}));
 assert.ok(changed);assert.equal((await f.repo.readPolicy(actor)).rows.find(row=>row.toolKey===ADDRESS_EDIT_SETUP_KEY).allowed.customer,true);
});

for(const enforcement of [true,false])test(`v8 refund handoff preserves old policy and exact admission with enforcement ${enforcement}`,async()=>{
 const f=fixture(),actor=input('customer'),admin=input('admin');await f.repo.readPolicy(actor);
 f.state().head={policy_version:'20',enforcement_enabled:enforcement,registry_sha256:ADDRESS_EDIT_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:ADDRESS_EDIT_SETUP_KEY,role:'customer',allowed:true});
 const historical={successorSha256:ADDRESS_EDIT_REGISTRY_SHA256,successorVersion:'19'};f.state().upgrades.push(historical);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='customer-chat').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=()=>({...actor,workflow:'customer-chat',declaredTools,agent:'orders',tool:'refund_setup',runId:randomUUID(),invocationId:'handoff',args:{choiceId:randomUUID()}});
 const denied=await f.repo.admitTool(request());assert.equal(denied.allowed,false);assert.equal(denied.action,enforcement?'block':'dispatch');
 assert.equal(denied.enforcement,enforcement);assert.equal(denied.policyViolation,'denied-by-acl');
 assert.deepEqual(f.state().upgrades[0],historical);assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(ADDRESS_EDIT_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key===ADDRESS_EDIT_SETUP_KEY).allowed,true);
 const policy=await f.repo.readPolicy(admin);await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:REFUND_SETUP_KEY,role:'customer',allowed:true}));
 assert.equal((await f.repo.admitTool(request())).allowed,true);
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.admitTool({...request(),...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
});

for(const enforcement of [true,false])test(`v9 merchant order upgrade preserves overrides with enforcement ${enforcement}`,async()=>{
 const f=fixture(),actor=input('merchant'),admin=input('admin');await f.repo.readPolicy(actor);
 f.state().head={policy_version:'22',enforcement_enabled:enforcement,registry_sha256:REFUND_SETUP_REGISTRY_SHA256};
 f.state().overrides.push({tool_key:'merchant.catalog_search',role:'merchant',allowed:false});
 const old={successorSha256:REFUND_SETUP_REGISTRY_SHA256,successorVersion:'21'};f.state().upgrades.push(old);
 const declaredTools=require('../server/services/secureshopBoundRoleChat').TOOLS.merchant;
 const request=toolKey=>({...actor,workflow:'merchant-assistant',declaredTools,agent:'merchant',tool:toolKey.split('.')[1],
  runId:randomUUID(),invocationId:'read',args:toolKey.endsWith('detail')?{choiceId:randomUUID()}:{}});
 for(const toolKey of MERCHANT_ORDER_KEYS){
  const denied=await f.repo.admitTool(request(toolKey));assert.equal(denied.allowed,false);assert.equal(denied.action,enforcement?'block':'dispatch');
  const p=await f.repo.readPolicy(admin);await f.repo.mutate(mutation(admin,p.version,{kind:'permission',toolKey,role:'merchant',allowed:true}));
  assert.equal((await f.repo.admitTool(request(toolKey))).allowed,true);
  for(const role of ['customer','admin'])await assert.rejects(f.repo.admitTool({...request(toolKey),...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 }
 assert.deepEqual(f.state().upgrades[0],old);assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(REFUND_SETUP_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key==='merchant.catalog_search').allowed,false);
 assert.equal(f.state().upgrades.length,2);
});

for(const enforcement of [true,false])test(`v12 admin preparations retain receipts and explicit permission with enforcement ${enforcement}`,async()=>{
 const f=fixture(),admin=input('admin');await f.repo.readPolicy(admin);
 f.state().head={policy_version:'30',enforcement_enabled:enforcement,registry_sha256:ADMIN_USER_REGISTRY_SHA256};
 const old={successorSha256:ADMIN_USER_REGISTRY_SHA256,successorVersion:'29'};f.state().upgrades.push(old);
 f.state().overrides.push({tool_key:'admin.users_search',role:'admin',allowed:false});
 const declaredTools=REGISTRY.filter(row=>row.workflow==='admin-assistant').map(row=>{const [agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=key=>({...admin,workflow:'admin-assistant',declaredTools,agent:'admin',tool:key.split('.')[1],runId:randomUUID(),invocationId:'prepare',args:{choiceId:randomUUID()}});
 for(const key of ADMIN_USER_PREPARE_KEYS){
  const denied=await f.repo.admitTool(request(key));assert.equal(denied.allowed,false);assert.equal(denied.action,enforcement?'block':'dispatch');assert.equal(denied.policyViolation,'denied-by-acl');
  const policy=await f.repo.readPolicy(admin);await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:key,role:'admin',allowed:true}));
  assert.equal((await f.repo.admitTool(request(key))).allowed,true);
  for(const role of ['customer','merchant'])await assert.rejects(f.repo.admitTool({...request(key),...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 }
 assert.deepEqual(f.state().upgrades[0],old);
 assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(ADMIN_USER_REGISTRY_SHA256));
 assert.equal(f.state().overrides.find(row=>row.tool_key==='admin.users_search').allowed,false);
 await f.repo.readPolicy(admin);assert.equal(f.state().upgrades.length,2);
});

test('v15 owned MCP successor adds only six admin denials and preserves prior receipts',async()=>{
 const f=fixture(),actor=input();await f.repo.readPolicy(actor);
 f.state().head={policy_version:'7',enforcement_enabled:true,registry_sha256:ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256};
 const retained={operation_id:randomUUID(),persona_id:actor.persona.id,request_digest:'retained',receipt_json:{version:'2'}};
 f.state().operations.push(retained);
 const policy=await f.repo.readPolicy(actor);
 assert.equal(policy.version,'8');assert.equal(policy.registrySha256,REGISTRY_SHA256);assert.equal(policy.enforcement,true);
 assert.equal(f.state().upgrades.length,1);
 assert.equal(f.state().upgrades[0].predecessorSha256,ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(f.state().upgrades[0].addedDenials,denialsFor(ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256));
 for(const key of ADMIN_MCP_KEYS)assert.equal(policy.rows.find(row=>row.toolKey===key).allowed.admin,false);
 assert.deepEqual(f.state().operations,[retained]);assert.equal((await f.repo.readPolicy(actor)).version,'8');assert.equal(f.state().upgrades.length,1);
});

for(const enforcement of [true,false])test(`current ticket preparation preserves populated v24 policy with enforcement ${enforcement}`,async()=>{
 const {TICKET_PREPARE_KEY,TICKET_PREDECESSOR_REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');
 const f=fixture(),admin=input('admin');await f.repo.readPolicy(admin);
 f.state().head={policy_version:'24',enforcement_enabled:enforcement,registry_sha256:TICKET_PREDECESSOR_REGISTRY_SHA256};
 const retained={successorSha256:TICKET_PREDECESSOR_REGISTRY_SHA256,successorVersion:'24'};
 f.state().upgrades.push(retained);
 const overrides=[{tool_key:'cart.coupon_prepare',role:'customer',allowed:true},{tool_key:'merchant.manual_search',role:'merchant',allowed:false}];
 f.state().overrides.push(...structuredClone(overrides));
 const policy=await f.repo.readPolicy(admin);
 assert.equal(policy.version,'25');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(row=>row.toolKey===TICKET_PREPARE_KEY).allowed.customer,false);
 assert.equal(policy.rows.find(row=>row.toolKey==='cart.coupon_prepare').allowed.customer,true);
 assert.equal(policy.rows.find(row=>row.toolKey==='merchant.manual_search').allowed.merchant,false);
 assert.deepEqual(f.state().upgrades[0],retained);
 assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(TICKET_PREDECESSOR_REGISTRY_SHA256));
 assert.deepEqual(f.state().overrides.filter(row=>!denialsFor(TICKET_PREDECESSOR_REGISTRY_SHA256).some(item=>item.toolKey===row.tool_key)),overrides);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='customer-chat').map(row=>{const [agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request={...input('customer'),workflow:'customer-chat',declaredTools,agent:'support',tool:'ticket_prepare',runId:randomUUID(),invocationId:'prepare',args:{}};
 const admission=await f.repo.admitTool(request);
 assert.equal(admission.allowed,false);assert.equal(admission.action,enforcement?'block':'dispatch');
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.admitTool({...request,...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,2);
 const fresh=fixture();assert.deepEqual((await fresh.repo.readPolicy(admin)).rows.find(row=>row.toolKey===TICKET_PREPARE_KEY).allowed,{customer:true,merchant:false,admin:false});
});

for(const enforcement of [true,false])test(`v26 diagnostic preparation preserves populated v25 policy with enforcement ${enforcement}`,async()=>{
 const {DIAGNOSTIC_PREPARE_KEY,DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');
 const f=fixture(),admin=input('admin');await f.repo.readPolicy(admin);
 f.state().head={policy_version:'25',enforcement_enabled:enforcement,registry_sha256:DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256};
 const retained={successorSha256:DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,successorVersion:'25'};
 f.state().upgrades.push(retained);
 const overrides=[{tool_key:'cart.coupon_prepare',role:'customer',allowed:true},{tool_key:'merchant.manual_search',role:'merchant',allowed:false}];
 f.state().overrides.push(...structuredClone(overrides));
 const policy=await f.repo.readPolicy(admin);
 assert.equal(policy.version,'26');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(row=>row.toolKey===DIAGNOSTIC_PREPARE_KEY).allowed.admin,false);
 assert.equal(policy.rows.find(row=>row.toolKey==='cart.coupon_prepare').allowed.customer,true);
 assert.equal(policy.rows.find(row=>row.toolKey==='merchant.manual_search').allowed.merchant,false);
 assert.deepEqual(f.state().upgrades[0],retained);
 assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256));
 assert.deepEqual(f.state().overrides.filter(row=>!denialsFor(DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256).some(item=>item.toolKey===row.tool_key)),overrides);
 const declaredTools=REGISTRY.filter(row=>row.workflow==='admin-assistant').map(row=>{const [agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request={...input('admin'),workflow:'admin-assistant',declaredTools,agent:'admin',tool:'system_diagnostic_prepare',runId:randomUUID(),invocationId:'prepare',args:{}};
 const admission=await f.repo.admitTool(request);
 assert.equal(admission.allowed,false);assert.equal(admission.action,enforcement?'block':'dispatch');
 for(const role of ['merchant','customer'])await assert.rejects(f.repo.admitTool({...request,...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,2);
 const fresh=fixture();assert.deepEqual((await fresh.repo.readPolicy(admin)).rows.find(row=>row.toolKey===DIAGNOSTIC_PREPARE_KEY).allowed,{customer:false,merchant:false,admin:true});
});

for (const enforcement of [true, false]) test(`current registry preserves populated v26 policy and reply with enforcement ${enforcement}`, async () => {
 const { MAIL_SUMMARY_KEY, MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256 } = require('../server/services/secureshopBoundAclRegistry');
 const f = fixture(), admin = input('admin'), merchant = input('merchant');
 await f.repo.readPolicy(admin);
 f.state().head = { policy_version: '26', enforcement_enabled: enforcement,
  registry_sha256: MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256 };
 const historical = { successorSha256: MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256, successorVersion: '26' };
 f.state().upgrades.push(historical);
 const retained = [{ tool_key: 'email.read_thread', role: 'merchant', allowed: true },
  { tool_key: 'email.send_reply', role: 'merchant', allowed: false }];
 f.state().overrides.push(...structuredClone(retained));
 const upgraded = await f.repo.readPolicy(admin);
 assert.equal(upgraded.version, '27'); assert.equal(upgraded.enforcement, enforcement);
 assert.equal(upgraded.rows.find(row => row.toolKey === MAIL_SUMMARY_KEY).allowed.merchant, false);
 assert.equal(upgraded.rows.find(row => row.toolKey === 'email.read_thread').allowed.merchant, true);
 assert.equal(upgraded.rows.find(row => row.toolKey === 'email.send_reply').allowed.merchant, false);
 assert.deepEqual(f.state().upgrades[0], historical);
 assert.deepEqual(f.state().upgrades[1].addedDenials, denialsFor(MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256));
 assert.deepEqual(f.state().overrides.filter(row => !denialsFor(MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256).some(denied=>denied.toolKey===row.tool_key)), retained);
 const declaredTools = [{ agent: 'email', tool: 'read_thread' }, { agent: 'email', tool: 'summarize_thread' }];
 const request = { ...merchant, workflow: 'mail-summary', declaredTools,
  agent: 'email', tool: 'summarize_thread', runId: randomUUID(), invocationId: 'summary', args: {} };
 const admission = await f.repo.admitTool(request);
 assert.equal(admission.allowed, false); assert.equal(admission.action, enforcement ? 'block' : 'dispatch');
 assert.deepEqual(await f.repo.admitTool(request), admission);
 assert.equal(f.state().admissions.length, 1);
 for (const role of ['customer', 'admin']) await assert.rejects(f.repo.admitTool({ ...request, ...input(role) }), { code: 'ACL_TOOL_UNAVAILABLE' });
 assert.deepEqual(await f.repo.readPolicy(admin), upgraded); assert.equal(f.state().upgrades.length, 2);
 const fresh = fixture();
 assert.equal((await fresh.repo.admitTool(request)).allowed, true);
 assert.deepEqual((await fresh.repo.readPolicy(admin)).rows.find(row => row.toolKey === MAIL_SUMMARY_KEY).allowed,
  { customer: false, merchant: true, admin: false });
});

for(const enforcement of [true,false])test(`v29 union upgrade preserves all predecessor overrides and enforcement ${enforcement}`,async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry');
 for(const predecessor of Object.keys(R.PRE_ARITHMETIC_REGISTRY_UPGRADES)){
  const f=fixture(),admin=input('admin');await f.repo.readPolicy(admin);
  f.state().head={policy_version:'80',enforcement_enabled:enforcement,registry_sha256:predecessor};
  const history={successorSha256:predecessor,successorVersion:'80'};f.state().upgrades.push(history);
  const overrides=[{tool_key:'email.read_thread',role:'merchant',allowed:true},{tool_key:'email.send_reply',role:'merchant',allowed:false}];
  f.state().overrides.push(...structuredClone(overrides));
  const policy=await f.repo.readPolicy(admin);
  assert.equal(policy.version,'81');assert.equal(policy.enforcement,enforcement);
  assert.deepEqual(f.state().upgrades[0],history);
  assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(predecessor));
  assert.equal(policy.rows.find(row=>row.toolKey===R.PRODUCT_SEARCH_UNION_KEY).allowed.customer,false);
  assert.deepEqual(f.state().overrides.filter(row=>!R.REGISTRY_UPGRADES[predecessor].includes(row.tool_key)),overrides);
  const request={...input('customer'),workflow:'product-search-union',declaredTools:[{agent:'product-search',tool:'search'}],agent:'product-search',tool:'search',runId:randomUUID(),invocationId:'search',args:{query:'owned'}};
  const admission=await f.repo.admitTool(request);
  assert.equal(admission.allowed,false);assert.equal(admission.action,enforcement?'block':'dispatch');
  for(const role of ['merchant','admin'])await assert.rejects(f.repo.admitTool({...request,...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
  assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,2);
 }
});
test('fresh union capability is customer-only and does not activate legacy merchant/admin grants',async()=>{
 const f=fixture(),policy=await f.repo.readPolicy(input('admin'));
 assert.deepEqual(policy.rows.find(row=>row.toolKey==='product-search.search').allowed,{customer:true,merchant:false,admin:false});
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.mutate({...input('admin'),operationId:randomUUID(),expectedVersion:policy.version,change:{kind:'permission',toolKey:'product-search.search',role,allowed:true}}),{code:'INVALID_ARGUMENT'});
 assert.equal(f.state().operations.length,0);
});

for(const enforcement of [true,false])test(`v39 list-read upgrade denies one new admin permission and retains v38 choices with enforcement ${enforcement}`,async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),f=fixture(),admin=input('admin');
 await f.repo.readPolicy(admin);
 f.state().head={policy_version:'8',enforcement_enabled:enforcement,registry_sha256:R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256};
 const prior={tool_key:R.MCP_DESCRIBE_KEY,role:'admin',allowed:false};
 f.state().overrides.push(prior);
 const history={operation_id:randomUUID(),receipt_json:{version:'7'}};
 f.state().operations.push(history);
 const policy=await f.repo.readPolicy(admin);
 assert.equal(policy.version,'9');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(row=>row.toolKey===R.MCP_LIST_KEY).allowed.admin,false);
 assert.equal(policy.rows.find(row=>row.toolKey===R.MCP_DESCRIBE_KEY).allowed.admin,false);
 assert.deepEqual(f.state().upgrades[0].overridesBefore,[{toolKey:R.MCP_DESCRIBE_KEY,role:'admin',allowed:false}]);
 assert.deepEqual(f.state().upgrades[0].addedDenials,[{toolKey:R.MCP_LIST_KEY,role:'admin'}]);
 assert.deepEqual(f.state().operations,[history]);
 assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,1);
 const declaredTools=R.REGISTRY.filter(row=>row.workflow==='admin-assistant')
  .map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 declaredTools.push({agent:'mcp-registry',tool:'register'},{agent:'mcp-registry',tool:'describe_tools'},
  {agent:'mcp-registry',tool:'list_servers'});
 const admitted=await f.repo.admitTool({...admin,workflow:'admin-registration-assistant',declaredTools,
  agent:'mcp-registry',tool:'list_servers',runId:randomUUID(),invocationId:'list',args:{}});
 assert.equal(admitted.allowed,false);assert.equal(admitted.action,enforcement?'block':'dispatch');
 assert.equal(admitted.policyViolation,'denied-by-acl');
 for(const role of ['customer','merchant'])await assert.rejects(f.repo.admitTool({...admin,...input(role),
  workflow:'admin-registration-assistant',declaredTools,agent:'mcp-registry',tool:'list_servers',
  runId:randomUUID(),invocationId:'list',args:{}}),{code:'ACL_TOOL_UNAVAILABLE'});
});
test('v39 refuses a forged v38 override for the not-yet-supported list permission',async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),f=fixture(),admin=input('admin');
 await f.repo.readPolicy(admin);
 f.state().head.registry_sha256=R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256;
 f.state().overrides.push({tool_key:R.MCP_LIST_KEY,role:'admin',allowed:true});
 await assert.rejects(f.repo.readPolicy(admin),{code:'ACL_REGISTRY_MISMATCH'});
 assert.equal(f.state().upgrades.length,0);
 assert.equal(f.state().head.registry_sha256,R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256);
});

for(const enforcement of [true,false])test(`current lookup/preview/role upgrade preserves exact populated v33 policy with enforcement ${enforcement}`,async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),f=fixture(),admin=input('admin');
 await f.repo.readPolicy(admin);
 f.state().head={policy_version:'33',enforcement_enabled:enforcement,registry_sha256:R.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256};
 const retained=[{tool_key:'admin.users_search',role:'admin',allowed:false}];
 f.state().overrides.push(...structuredClone(retained));
 const historical={operation_id:randomUUID(),receipt_json:{version:'32'}};
 f.state().operations.push(historical);
 const policy=await f.repo.readPolicy(admin);
 assert.equal(policy.version,'34');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(row=>row.toolKey===R.USER_LOOKUP_KEY).allowed.admin,false);
 assert.equal(policy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,false);
 assert.deepEqual(f.state().upgrades[0].overridesBefore,[{toolKey:'admin.users_search',role:'admin',allowed:false}]);
 assert.deepEqual(f.state().upgrades[0].addedDenials,denialsFor(R.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256));
 assert.deepEqual(f.state().upgrades[0].addedDenials.filter(row=>row.toolKey===R.MCP_DESCRIBE_KEY),[{toolKey:R.MCP_DESCRIBE_KEY,role:'admin'}]);
 assert.deepEqual(f.state().operations,[historical]);
 assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,1);
 const changed=await f.repo.mutate(mutation(admin,'34',{kind:'permission',toolKey:R.USER_LOOKUP_KEY,role:'admin',allowed:true}));
 assert.equal(changed.version,'35');
 assert.equal((await f.repo.readPolicy(admin)).rows.find(row=>row.toolKey===R.USER_LOOKUP_KEY).allowed.admin,true);
 assert.equal((await f.repo.readPolicy(admin)).rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,false);
});

test('order-status error alias preserves v29 rows, upgrade edges and exact refund declaration',()=>{
 const R=require('../server/services/secureshopBoundAclRegistry');
 const hash=value=>require('node:crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex');
 const historicalRows=require('./helpers/secureshopHistoricalRegistry').registryV29Rows(R.REGISTRY);
 assert.equal(R.ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256,'bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71');
 assert.equal(hash(historicalRows),'76c82909f5b5e5f4c5187c8b53396900a3f3aec6489769442dba64e1a82d3d6d');
 assert.equal(hash(R.PRE_ARITHMETIC_REGISTRY_UPGRADES),'5ed3b318fd36d9103eccb1d462d12bd5e403fc70bca99a57aca6b274fd6b77f4');
 const status={agent:'support',tool:'order_status'},refund={agent:'support',tool:'refund_request'};
 const alias=R.createBoundAclResolver({workflow:'order-status-error',declaredTools:[status]});
 const original=R.createBoundAclResolver({workflow:'refund',declaredTools:[status,refund]});
 assert.strictEqual(alias.resolve('support','order_status'),original.resolve('support','order_status'));
 assert.equal(alias.resolve('support','order_status').workflow,'refund');
 assert.equal(alias.resolve('support','refund_request'),null);
 assert.equal(alias.isRoleApplicable('customer'),true);
 for(const role of ['merchant','admin'])assert.equal(alias.isRoleApplicable(role),false);
 for(const declaredTools of [[],[refund],[status,refund],[status,status]])
  assert.throws(()=>R.createBoundAclResolver({workflow:'order-status-error',declaredTools}));
 assert.throws(()=>R.createBoundAclResolver({workflow:'refund',declaredTools:[status]}));
});

test('order-status alias shares existing refund permission overrides without policy migration',async()=>{
 for(const enforcement of [false,true])for(const allowed of [false,true]){
  const f=fixture(),admin=input(),customer=input('customer');
  await f.repo.readPolicy(admin);
  await f.repo.mutate(mutation(admin,'1',{kind:'enforcement',enabled:enforcement}));
  await f.repo.mutate(mutation(admin,'2',{kind:'permission',toolKey:'support.order_status',role:'customer',allowed}));
  const before=await f.repo.readPolicy(admin);
  for(const workflow of ['order-status-error','refund']){
   const request={...customer,workflow,declaredTools:[{agent:'support',tool:'order_status'},
    ...(workflow==='refund'?[{agent:'support',tool:'refund_request'}]:[])],
    agent:'support',tool:'order_status',runId:randomUUID(),invocationId:'status',args:{order_id:'1'}};
   const receipt=await f.repo.admitTool(request);
   assert.equal(receipt.allowed,allowed);assert.equal(receipt.action,allowed||!enforcement?'dispatch':'block');
   assert.equal(receipt.policyViolation,allowed?null:'denied-by-acl');
   assert.deepEqual(await f.repo.admitTool(request),receipt);
  }
  assert.deepEqual(await f.repo.readPolicy(admin),before);
  assert.equal(f.state().admissions.length,2);assert.equal(f.state().upgrades.length,0);
 }
});

test('order-status alias rejects foreign roles and cross-workflow admission replay',async()=>{
 const f=fixture(),customer=input('customer');
 const request={...customer,workflow:'order-status-error',declaredTools:[{agent:'support',tool:'order_status'}],
  agent:'support',tool:'order_status',runId:randomUUID(),invocationId:'status',args:{order_id:'1'}};
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.admitTool({...request,...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 assert.equal(f.queries.length,0);
 const original=await f.repo.admitTool(request);assert.equal(original.allowed,true);
 await assert.rejects(f.repo.admitTool({...request,workflow:'refund',declaredTools:[...request.declaredTools,{agent:'support',tool:'refund_request'}]}),{code:'ACL_ADMISSION_CONFLICT'});
 assert.deepEqual(await f.repo.admitTool(request),original);
 assert.equal(f.state().admissions.length,1);
});

for(const enforcement of [true,false])test(`current preview/role upgrade preserves populated v34 overrides/history and no-op with enforcement ${enforcement}`,async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),f=fixture(),admin=input('admin');await f.repo.readPolicy(admin);
 f.state().head={policy_version:'34',enforcement_enabled:enforcement,registry_sha256:R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256};
 const overrides=[{tool_key:'uploads.upload_avatar',role:'customer',allowed:false},{tool_key:R.USER_LOOKUP_KEY,role:'admin',allowed:true}];
 f.state().overrides.push(...structuredClone(overrides));const history={operation_id:randomUUID(),receipt_json:{version:'33'}};f.state().operations.push(history);
 const policy=await f.repo.readPolicy(admin);assert.equal(policy.version,'35');assert.equal(policy.enforcement,enforcement);
 assert.equal(policy.rows.find(x=>x.toolKey===R.UPLOAD_PREVIEW_KEY).allowed.customer,false);
 assert.equal(policy.rows.find(x=>x.toolKey==='uploads.upload_avatar').allowed.customer,false);
 assert.equal(policy.rows.find(x=>x.toolKey===R.USER_LOOKUP_KEY).allowed.admin,true);
 assert.deepEqual(f.state().upgrades[0].addedDenials,denialsFor(R.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256));assert.deepEqual(f.state().operations,[history]);
 assert.deepEqual(await f.repo.readPolicy(admin),policy);assert.equal(f.state().upgrades.length,1);
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.mutate(mutation(admin,'35',{kind:'permission',toolKey:R.UPLOAD_PREVIEW_KEY,role,allowed:true})),{code:'INVALID_ARGUMENT'});
 await f.repo.mutate(mutation(admin,'35',{kind:'permission',toolKey:R.UPLOAD_PREVIEW_KEY,role:'customer',allowed:true}));
 assert.equal((await f.repo.readPolicy(admin)).rows.find(x=>x.toolKey===R.UPLOAD_PREVIEW_KEY).allowed.customer,true);
});

for(const enforcement of [false,true])test(`v36 customer role denial preserves v35 overrides and receipts with enforcement ${enforcement}`,async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),f=fixture(),actor=input('customer');await f.repo.readPolicy(actor);
 f.state().head.registry_sha256=R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256;f.state().head.enforcement_enabled=enforcement;
 const override={tool_key:'admin.role_change_prepare',role:'admin',allowed:false},historical={successorSha256:R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256,successorVersion:'1'};
 f.state().overrides.push(override);f.state().upgrades.push(historical);
 const declaredTools=R.REGISTRY.filter(row=>row.workflow==='customer-chat').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const request=()=>({...actor,workflow:'customer-chat',declaredTools,agent:'user-management',tool:'set_role',runId:randomUUID(),invocationId:'role',args:{role:'admin'}});
 const receipt=await f.repo.admitTool(request());
 assert.equal(receipt.allowed,false);assert.equal(receipt.action,enforcement?'block':'dispatch');assert.equal(receipt.policyViolation,'denied-by-acl');
 assert.deepEqual(f.state().upgrades[0],historical);assert.deepEqual(f.state().overrides[0],override);
 assert.deepEqual(f.state().upgrades[1].addedDenials,denialsFor(R.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256));
 assert.deepEqual(f.state().upgrades[1].overridesBefore,[{toolKey:override.tool_key,role:override.role,allowed:false}]);
 const policy=await f.repo.readPolicy(actor),row=policy.rows.find(row=>row.toolKey===R.AGENCY_ROLE_KEY);
 assert.deepEqual(row.allowed,{customer:false,merchant:false,admin:true});assert.equal(f.state().upgrades.length,2);
 for(const role of ['merchant','admin'])await assert.rejects(f.repo.admitTool({...request(),...input(role)}),{code:'ACL_TOOL_UNAVAILABLE'});
 const admin=input();await f.repo.mutate(mutation(admin,policy.version,{kind:'permission',toolKey:R.AGENCY_ROLE_KEY,role:'customer',allowed:true}));
 assert.equal((await f.repo.admitTool(request())).allowed,true);
 assert.equal((await f.repo.readPolicy(admin)).rows.find(row=>row.toolKey==='admin.role_change_prepare').allowed.admin,false);
});
