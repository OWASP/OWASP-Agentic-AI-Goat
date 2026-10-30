'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { createSecureShopPersonaInboxTools } = require('../server/services/secureshopPersonaInboxTools');
const { createSecureShopPersonaInboxApplication } = require('../server/services/secureshopPersonaInboxApplication');
const { createSecureShopSsrfTargetPool } = require('../server/services/secureshopSsrfTargetPool');
const { createSecureShopSsrfExternalAdapter, SSRF_EGRESS_POLICY_SHA256 } = require('../server/services/secureshopSsrfExternalAdapter');
const { createSecureShopMcpTrustExternalAdapter } = require('../server/services/secureshopMcpTrustExternalAdapter');
const { CONTROLLED_MCP_SCENARIOS } = require('../server/services/secureshopMcpControlledServer');
const { createSecureShopMcpTrustCoordinator } = require('../server/services/secureshopMcpTrustProduction');
const { digestMcpValue } = require('../server/services/secureshopMcpTrustTools');
const { guardFeatureFence, POLICIES } = require('../server/services/secureshopFeatureModeAuthority');

const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 11, platformSessionId: 21 });
const owner = Object.freeze({ ...scope, shopUserId: 31, role: 'customer' });
const targetId = randomUUID(), requestId = randomUUID(), runId = randomUUID(), sessionId = randomUUID();
const parsed = result => JSON.parse(result.content[0].text);
const execution = () => ({ runId, ownerKey: 'owner', durableGeneration: 1,
  signal: new AbortController().signal, async check() {} });
function fixedFence(binding, featureId) {
  const raw = { binding: { ...scope, personaId: binding.shopUserId, role: binding.role },
    async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); },
    async withCrossStoreEffect(work) { return work(); } };
  const token = { snapshot: { version: 1, featureId, policyVersion: POLICIES[featureId], mode: 'fixed' },
    async assertCurrent() {} };
  return guardFeatureFence(raw, token);
}

test('fixed persona tools filter the index and deny a cross-persona read before repository.read', async () => {
  const calls = [];
  const rows = [
    { messageId: 1, ownerShopUserId: owner.shopUserId, ownerShopRole: owner.role, subject: 'Owned' },
    { messageId: 2, ownerShopUserId: 99, ownerShopRole: 'merchant', subject: 'Other' },
    { messageId: 3, ownerShopUserId: 100, ownerShopRole: 'admin', subject: 'Admin' },
  ];
  const tools = createSecureShopPersonaInboxTools({ repository: {
    async list() { return rows; }, async read() { calls.push('read'); throw Error('must not read'); },
  }, trustedScope: { ...scope, targetId }, trustedPersona: { id: owner.shopUserId, role: owner.role },
  mode: 'fixed', allowedMessageId: 2, authorizedTargetId: targetId,
  checkCurrent: async () => {}, resolveTarget: async value => ({ ...value, targetId }) });
  const index = parsed(await tools['persona-inbox.list_messages']({}));
  assert.equal(index.count, 1); assert.equal(index.messages[0].owner_persona_id, owner.shopUserId);
  const denied = parsed(await tools['persona-inbox.read_message']({ message_id: 2 }));
  assert.equal(denied.code, 'PERSONA_INBOX_ACCESS_DENIED'); assert.deepEqual(calls, []);
});

test('fixed persona status filters other subjects using canonical launch mode', async () => {
  const rows = [
    { messageId: 1, ownerShopUserId: owner.shopUserId, ownerShopRole: owner.role, subject: 'Owned' },
    { messageId: 2, ownerShopUserId: 99, ownerShopRole: 'merchant', subject: 'Other' },
    { messageId: 3, ownerShopUserId: 100, ownerShopRole: 'admin', subject: 'Admin' },
  ];
  let mode = 'fixed';
  const application = createSecureShopPersonaInboxApplication({
    launches: { async assertCurrent() {}, async reservePersonaInboxTarget() { return { targetId }; } },
    repository: { async provision() {}, async list() { return rows; }, async readAcl() { return { mode: 'advisory' }; },
      async advanceAcl() {} },
    conversations: { async create() { return { id: sessionId }; } }, runner: { async run() {} },
    fixtures: [{ owner: { id: owner.shopUserId } }, {}, {}], authorizeAclTransition: async () => {},
    requestAuthority: { issue() {} }, availability: { async read() { return { visible: true,
      enabled: new Set(['ss_cross_persona_effect', 'ss_acl_advisory_effect']) }; }, async assertObjectives() {} },
    personaAuthority: { async capture() { return { async assertRemoteAdmission() {} }; } },
    modeAuthority: { async capture() { return { snapshot: { mode }, async assertCurrent() {} }; }, assertToken(value) { return value; } },
  });
  const input = { scope, persona: { id: owner.shopUserId, role: owner.role } };
  const fixed = await application.status(input);
  assert.equal(fixed.messages.length, 1); assert.equal(fixed.messages[0].subject, 'Owned');
  mode = 'vuln';
  const vulnerable = await application.status(input);
  assert.equal(vulnerable.messages.length, 3);
});

test('fixed SSRF destination authority binds the live owner, exact issued URL, request and public kind', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-fixed-ssrf-'));
  const pool = createSecureShopSsrfTargetPool({ root });
  t.after(async () => { await pool.close(); await fs.rm(root, { recursive: true, force: true }); });
  const binding = { ...scope, targetId };
  const issued = await pool.issue(binding, { requestId, resourceKind: 'public-policy' });
  const input = { nonce: issued.nonce, requestId, resourceKind: 'public-policy', url: issued.url };
  assert.equal(pool.assertIssuedPublicRequest(binding, input).url, issued.url);
  assert.throws(() => pool.assertIssuedPublicRequest({ ...binding, platformOwnerId: 12 }, input), /scope mismatch/);
  assert.throws(() => pool.assertIssuedPublicRequest(binding, { ...input, url: issued.url + '/redirect' }), /destination unavailable/);
  assert.throws(() => pool.assertIssuedPublicRequest(binding, { ...input, requestId: randomUUID() }), /destination unavailable/);
  assert.throws(() => pool.assertIssuedPublicRequest(binding, { ...input, resourceKind: 'private-policy' }), /destination unavailable/);
  const response = await fetch(issued.url, { redirect: 'manual' });
  assert.equal(response.status, 200); assert.equal((await response.json()).classification, 'public');
  assert.throws(() => pool.assertIssuedPublicRequest(binding, input), /destination unavailable/);
  await pool.retire(binding);
  assert.throws(() => pool.assertIssuedPublicRequest(binding, input), /unavailable/);
});

test('fixed SSRF blocks private egress and rejects a redirect response without a second request', async () => {
  const binding = { ...owner, targetId };
  const fence = fixedFence(owner, 'controlled_ssrf');
  let calls = 0, admissions = 0;
  const value = kind => ({ ...binding, targetId, requestId, nonce: randomUUID(), operationId: randomUUID(),
    resourceKind: kind, policyDecision: kind === 'public-policy' ? 'allowed' : 'denied',
    egressPolicySha256: SSRF_EGRESS_POLICY_SHA256, url: `http://127.0.0.1:12345/policy/${kind}/nonce` });
  let selected = value('private-policy');
  const adapter = createSecureShopSsrfExternalAdapter({ resolveRequest: async () => selected,
    targetPool: { consume() {}, readReceipt() {}, assertIssuedPublicRequest() { admissions++; } },
    upstreamPool: { async callTool() { calls++; return { content: [{ type: 'text', text: JSON.stringify({ status: 302 }) }] }; } },
    recordInvocation: async () => {}, checkCurrent: async () => {} });
  const context = { execution: execution(), requestId, sessionId };
  const privatePool = await adapter.createToolPool(binding, context, fence);
  await assert.rejects(privatePool.callTool('summarizer', 'explain_return_policy', { policy_url: selected.url }, { callId: 'call-1' }),
    { code: 'BOUND_SSRF_UNAVAILABLE' });
  assert.equal(calls, 0); assert.equal(admissions, 0);
  selected = value('public-policy');
  const publicPool = await adapter.createToolPool(binding, context, fence);
  await assert.rejects(publicPool.callTool('summarizer', 'explain_return_policy', { policy_url: selected.url }, { callId: 'call-2' }),
    { code: 'BOUND_SSRF_UNAVAILABLE' });
  assert.equal(admissions, 1); assert.equal(calls, 1);
});

test('fixed SSRF admits an exact owned public baseline through the external tool', async () => {
  const binding = { ...owner, targetId }, fence = fixedFence(owner, 'controlled_ssrf');
  const request = { ...binding, targetId, requestId, nonce: randomUUID(), operationId: randomUUID(),
    resourceKind: 'public-policy', policyDecision: 'allowed', egressPolicySha256: SSRF_EGRESS_POLICY_SHA256,
    url: 'http://127.0.0.1:12345/policy/public-policy/exact' };
  let admissions = 0, remoteCalls = 0;
  const body = '{"classification":"public"}';
  const adapter = createSecureShopSsrfExternalAdapter({ resolveRequest: async () => request,
    targetPool: { consume() {}, assertIssuedPublicRequest() { admissions++; },
      readReceipt() { return { status: 200, operationId: request.operationId, resourceKind: 'public-policy',
        responseSha256: createHash('sha256').update(body).digest('hex') }; } },
    upstreamPool: { async callTool() { remoteCalls++; return { content: [{ type: 'text',
      text: JSON.stringify({ url: request.url, status: 200, body }) }] }; } },
    recordInvocation: async () => {}, checkCurrent: async () => {} });
  const pool = await adapter.createToolPool(binding, { execution: execution(), requestId, sessionId }, fence);
  const result = await pool.callTool('summarizer', 'explain_return_policy', { policy_url: request.url }, { callId: 'call-3' });
  assert.equal(parsed(result).body, body); assert.equal(admissions, 1); assert.equal(remoteCalls, 1);
});

test('fixed MCP pins approved v1 and refuses a changed schema before remote invocation', async () => {
  const admin = { ...owner, role: 'admin' }, fence = fixedFence(admin, 'mcp_rug_pull');
  const approved = CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[0];
  const digest = digestMcpValue(approved);
  let current = { serverIdentity: 'secureshop-weather-lab', version: 1, schemaSha256: digest, tools: approved };
  let remoteCalls = 0;
  const adapter = createSecureShopMcpTrustExternalAdapter({
    application: { async target() { return { ...admin, targetId, trustScenario: 'rug_pull', serverIdentity: 'secureshop-weather-lab' }; } },
    repository: { async currentSchema() { return current; }, async recordInvocation() { throw Error('must not record'); } },
    transport: { async callTool() { remoteCalls++; throw Error('must not call'); } },
    checkCurrent: async () => {}, serverIdentity: 'secureshop-weather-lab', trustScenario: 'rug_pull', expectedSchemaSha256: digest,
  });
  const pool = await adapter.createToolPool(admin, { execution: execution(), requestId, sessionId }, fence);
  current = { ...current, version: 2, schemaSha256: digestMcpValue(CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[1]),
    tools: CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[1] };
  await assert.rejects(pool.callTool('secureshop-weather-lab', 'forecast_lookup', { city: 'Seattle' }, { callId: 'call-1' }),
    /schema changed before invocation/);
  assert.equal(remoteCalls, 0);
});

test('fixed MCP coordinator blocks rogue discovery and changed rug schema before model admission', async () => {
  const admin = { ...owner, role: 'admin' };
  const approved = CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[0];
  let current = { serverIdentity: 'secureshop-weather-lab', version: 1,
    schemaSha256: digestMcpValue(approved), tools: approved };
  let discoveries = 0, conversations = 0, runs = 0;
  const coordinator = createSecureShopMcpTrustCoordinator({
    launches: { async assertCurrent() {} },
    conversations: { async create() { conversations++; return { id: sessionId }; } },
    availability: { async read() { return { visible: true, enabled: { rogue_registration: true, rug_pull: true } }; },
      async assertScenario() {} },
    features: {
      rogue_registration: { ready: true, application: { async initialize() { discoveries++; throw Error('rogue touched'); } } },
      rug_pull: { ready: true, application: { async initialize() { discoveries++; return current; },
        async rotate() { current = { ...current, version: 2,
          schemaSha256: digestMcpValue(CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[1]),
          tools: CONTROLLED_MCP_SCENARIOS.rug_pull.schemas[1] }; return current; } } },
    },
    createRunner: () => ({ async run() { runs++; return { text: 'public forecast', stopReason: 'end_turn' }; } }),
    checkCurrent: async () => {},
    capturePersonaAuthority: async ({ trustScenario }) => fixedFence(admin,
      trustScenario === 'rogue_registration' ? 'mcp_rogue_registration' : 'mcp_rug_pull'),
  });
  await assert.rejects(coordinator.discover({ scope, persona: { id: admin.shopUserId, role: 'admin' },
    trustScenario: 'rogue_registration' }), /Unapproved connector/);
  assert.equal(discoveries, 0);
  const v1 = await coordinator.run({ scope, persona: { id: admin.shopUserId, role: 'admin' },
    trustScenario: 'rug_pull', requestId });
  assert.equal(v1.ok, true); assert.equal(runs, 1);
  await coordinator.rotate({ scope, persona: { id: admin.shopUserId, role: 'admin' } });
  await assert.rejects(coordinator.run({ scope, persona: { id: admin.shopUserId, role: 'admin' },
    trustScenario: 'rug_pull', requestId: randomUUID() }), /Changed MCP schema/);
  assert.equal(conversations, 1); assert.equal(runs, 1);
});
