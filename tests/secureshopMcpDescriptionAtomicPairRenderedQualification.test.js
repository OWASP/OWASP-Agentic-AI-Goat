'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SCOPE, assertPhysicalArm, assertCapturedArm, assertPairCaptured,
  finalizePairReceipt, assertPairReceipt } = require('./fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification');
const { VERSION } = require('./fixtures/secureshopMcpDescriptionAtomicPair');
const { resetAfterControlRelayRetirement } = require('./fixtures/secureshopMcpDescriptionRenderedQualification');
const hash = value => createHash('sha256').update(value).digest('hex');
const H = 'a'.repeat(64);
test('actual candidate admission block initializes both atomic receipts and preserves legacy receipt', async () => {
  const native = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const source = readFileSync(path.join(__dirname, 'postgres/secureshopOwnedMcpRegistryRendered.native.js'), 'utf8');
  const block = source.slice(source.indexOf('        let v42Admission, v39Admission'), source.indexOf('        if (V66_ENABLED) {', source.indexOf('        let v42Admission, v39Admission')));
  for (const pair of [true, false]) for (const bad of [false, true]) {
    const objective = { objectiveId: 'ss_mcp_description_instruction_adoption', qualification: 'pending', enabled: false, revision: 1 };
    const legacy = pair ? null : {};
    let writes = 0, enabled = false;
    const context = { assert, Q05_HANDOFF_ENABLED: false, V42_ENABLED: false, V39_ENABLED: true, V39_PAIR_ENABLED: pair,
      objective, ownerBase: {}, v39Receipt: legacy, v39Contract: require('./fixtures/secureshopMcpDescriptionRenderedQualification'),
      retainV39Admission: native.retainV39Admission, initializeV39Receipt: native.initializeV39Receipt,
      require: require('node:module').createRequire(path.join(__dirname, 'postgres/secureshopOwnedMcpRegistryRendered.native.js')),
      pools: { IDENTITY_MIGRATION: { query: async () => { writes++; return { rowCount: bad ? 0 : 1,
        rows: [{ objective_id: objective.objectiveId, qualification: 'native-model', is_enabled: false }] }; } } },
      catalog: { set: async () => { if (!writes) throw Object.assign(Error('pending'), { code: 'SHOP_OBJECTIVE_UNQUALIFIED' }); enabled = true; return { enabled }; },
        list: async () => ({ objectives: [{ ...objective, qualification: 'native-model' }] }) } };
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const run = new AsyncFunction(...Object.keys(context), block + ';return [initializeV39Receipt(v39Contract,v39Admission),initializeV39Receipt(v39Contract,v39Admission)];')(...Object.values(context));
    if (bad) { await assert.rejects(run); assert.equal(enabled, false); }
    else { const receipts = await run; assert.notEqual(receipts[0], receipts[1]);
      for (const r of receipts) assert.equal(r.fixtureLocalCandidateAdmission && r.canonicalObjectiveEnabled, true);
      if (!pair) assert.deepEqual(legacy, { fixtureLocalCandidateAdmission: true, canonicalObjectiveEnabled: true }); }
  }
  assert.throws(() => native.initializeV39Receipt({ createReceipt: () => ({}) }, { fixtureLocalCandidateAdmission: true, canonicalObjectiveEnabled: true }));
  assert.match(source, /const controlReceipt = V39_PAIR_ENABLED \? await initializeObservedV39Receipt/);
  assert.match(source, /scope: nextScope, actor: nextActor, issued: nextIssued/);
});
test('real receipt flags retain observed eight-store and fresh admin scope checks for each arm', async () => {
  const native = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const contract = require('./fixtures/secureshopMcpDescriptionRenderedQualification');
  const { createDisposableAssessmentReleaseAdmission } = require('../server/services/secureshopAssessmentReleaseAdmission');
  const scope = { launchId: '00000000-0000-4000-8000-000000000001', scenarioId: '00000000-0000-4000-8000-000000000002', generation: 3, platformOwnerId: 11, platformSessionId: 12 };
  const stores = {}, pools = {}, rows = []; let generation = 3, reads = 0;
  for (const [key, store] of Object.entries({ identity: 'identity', agents: 'secureshop_agents', review: 'secureshop_review', commerce: 'secureshop' })) {
    const entry = stores[key] = {};
    for (const role of ['runtime', 'migration']) {
      const database = `dvaia_test_agent_host_012345abcdef_${store}`, username = `dvaia_${store}_${role}`;
      const url = `postgresql://${username}@127.0.0.1:54321/${database}`;
      const row = { database, role: username, session_role: username, server_address: '172.20.0.2', server_port: 5432, server_started: '2026-10-19 00:00:00+00' }; rows.push(row);
      entry[`${role}Url`] = url;
      entry[`${role}Pool`] = { options: { connectionString: url }, connect() {}, async query(sql, params) {
        if (sql.includes('current_database()')) { reads++; return { rows: [{ ...row }] }; }
        return { rows: JSON.stringify(params) === JSON.stringify([12, 11, scope.launchId, scope.scenarioId, generation]) ? [{ launch_id: scope.launchId }] : [] };
      } };
    }
    pools[`${key.toUpperCase()}_RUNTIME`] = entry.runtimePool;
  }
  const objectiveId = 'ss_mcp_description_instruction_adoption';
  const admission = await createDisposableAssessmentReleaseAdmission({ stores, objectiveIds: [objectiveId] });
  const witness = native.retainV39Admission({ objectiveId, qualification: 'pending', enabled: false },
    { rowCount: 1, rows: [{ objective_id: objectiveId, qualification: 'native-model', is_enabled: false }] }, 'native-model', { enabled: true });
  const input = { contract, witness, admission, pools, scope, actor: { user: { role: 'admin' }, sessionId: 'control', authorityVersion: 1 }, issued: { persona: { user: { username: 'student_admin' } } } };
  const setupFlags = new Set(['isolatedStores', 'registeredAdminAuthority', 'fixtureLocalCandidateAdmission', 'canonicalObjectiveEnabled']);
  const before = reads;
  const control = await native.initializeObservedV39Receipt(input);
  generation = 4;
  await assert.rejects(native.initializeObservedV39Receipt(input), 'old control scope cannot initialize treatment');
  const treatmentInput = { ...input, scope: { ...scope, generation }, actor: { ...input.actor, sessionId: 'treatment', authorityVersion: 2 } };
  const treatment = await native.initializeObservedV39Receipt(treatmentInput);
  assert.notEqual(control, treatment); assert.ok(reads >= before + 24);
  for (const receipt of [control, treatment]) for (const flag of contract.FLAGS) assert.equal(receipt[flag], setupFlags.has(flag), flag);
  await assert.rejects(native.initializeObservedV39Receipt({ ...treatmentInput, actor: { ...input.actor, user: { role: 'customer' } } }));
  await assert.rejects(native.initializeObservedV39Receipt({ ...treatmentInput, admission: {} }));
  rows[7].database = 'application';
  await assert.rejects(native.initializeObservedV39Receipt(treatmentInput), 'actual store drift cannot be projected as isolated');
});
test('actual standalone client and compiled bridge calls match four exact additional routes', async () => {
  const { createStandaloneShopClient } = await import('../client/src/pages/secureshop/standaloneClient.mjs');
  const { compileOperation } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const { createV39AtomicBrowserAudit, v39AtomicBrowserRequestAllowed: allowed } = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const origin = 'http://127.0.0.1:41111', calls = [], audit = createV39AtomicBrowserAudit({ origin });
  const observe = (address, method) => {
    calls.push([method, address]);
    audit.intercept({ url: () => origin + address, method: () => method,
      continue: async () => {}, abort: async () => assert.fail('actual client request denied') });
  };
  const client = createStandaloneShopClient({ fetchImpl: async (address, options) => {
    observe(address, options.method);
    assert.equal(options.credentials, 'include'); assert.equal(options.redirect, 'error');
    return { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () =>
      address.includes('learners') ? { learners: [], nextCursor: null } : {
        available: true, scope: 'shared_practice', launchId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        generation: 1, scene: { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', label: 'Practice' } } };
  } });
  await client.getPracticeResetReadiness(); await client.getAdminProgressLearners();
  for (const [name, body] of [['agent.admin.session', {}], ['agent.admin.assistant.mcpConfirm', {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }]]) {
    const operation = compileOperation(name, { body }); observe(operation.path, operation.method);
  }
  assert.deepEqual(calls, [['GET', '/api/secureshop/auth/reset-readiness'], ['GET', '/api/secureshop/auth/admin/progress/learners?limit=25'],
    ['POST', '/api/secureshop/agents/admin/session'], ['POST', '/api/secureshop/agents/admin/assistant/mcp/confirm']]);
  assert.equal((await audit.finish()).denied.length, 0);
  for (const [method, address] of calls) {
    for (const wrong of ['GET', 'POST', 'PUT', 'DELETE'].filter(value => value !== method))
      assert.equal(allowed({ origin, method: wrong, url: origin + address }), false);
    for (const url of [origin + address + '#x', origin + address + '&extra=1', origin.replace('41111', '41112') + address,
      origin + address.replace('/api/', '/api/extra/'), origin + address.replace('/api/', '/%61pi/')])
      assert.equal(allowed({ origin, method, url }), false, url);
  }
  const learners = origin + '/api/secureshop/auth/admin/progress/learners';
  for (const query of ['', '?limit=025', '?limit=25.0', '?limit=+25', '?limit=%32%35', '?limit=24', '?limit=26',
    '?limit=25&limit=25', '?cursor=0&limit=25', '?limit=25&cursor=0', '?limit=25&', '?LIMIT=25'])
    assert.equal(allowed({ origin, method: 'GET', url: learners + query }), false, query);
  for (const [method, address] of calls.filter(([, address]) => !address.includes('?')))
    assert.equal(allowed({ origin, method, url: origin + address + '?limit=25' }), false);
});
test('mounted admin availability admits four literal GETs without mutation or query authority', () => {
  const { v39AtomicBrowserRequestAllowed: allowed } = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const origin = 'http://127.0.0.1:41111';
  for (const route of ['/api/secureshop/admin/policies', '/api/secureshop/admin/system/restart',
    '/api/secureshop/admin/system/diagnostic', '/api/secureshop/admin/access-control']) {
    assert.equal(allowed({ origin, method: 'GET', url: origin + route }), true);
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'])
      assert.equal(allowed({ origin, method, url: origin + route }), false);
    for (const url of [origin + route + '?limit=25', origin + route + '?x=1&x=1', origin + route + '/',
      origin + route + '/operations', origin + route + '#x', origin.replace('41111', '41112') + route,
      origin.replace('http://', 'http://user@') + route, origin + route.replace('/api/', '/%61pi/')])
      assert.equal(allowed({ origin, method: 'GET', url }), false, url);
  }
});
test('actual browser audit admits only exact same-origin GET whoami', async () => {
  const { createV39AtomicBrowserAudit, v39AtomicBrowserRequestAllowed: allowed } = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const origin = 'http://127.0.0.1:41111', route = '/api/secureshop/v2/auth/whoami';
  assert.equal(hash(route), '0135d20dce9904ca40f80c9190f246f8d919bc4e95a89c5089aebecdbe1da1b8');
  const audit = createV39AtomicBrowserAudit({ origin }); let continued = 0;
  audit.intercept({ url: () => origin + route, method: () => 'GET', continue: async () => { continued++; }, abort: () => assert.fail() });
  assert.equal((await audit.finish()).denied.length, 0); assert.equal(continued, 1);
  for (const url of [origin + route + '?x=1', origin + route + '/extra', 'http://127.0.0.1:41112' + route, origin + route + '#x'])
    assert.equal(allowed({ origin, method: 'GET', url }), false);
  for (const method of ['POST', 'PUT', 'DELETE']) assert.equal(allowed({ origin, method, url: origin + route }), false);
});
function arm(arm, launchId, sessionId, runId, credit, launchGeneration = '1') {
  return { actorCalls: 7, judgeCalls: 1, physicalCalls: 8,
    launchId, launchGeneration, platformOwnerId: 101, platformSessionId: 102,
    sessionId, runId, sourceSha256: H, offeredSchemaSha256: H,
    resultSha256: H, trustedTaskSha256: H, selectedArgsSha256: H,
    canonicalCredit: credit };
}
const receipt = () => ({ version: 2, scope: SCOPE, pairVersion: VERSION,
  control: arm('control', 'control-launch', 'control-session', 'control-run', 0),
  treatment: arm('treatment', 'treatment-launch', 'treatment-session', 'treatment-run', 1),
  physicalCalls: 16, sameTaskCatalogSchemaResult: true,
  controlNoCredit: true, treatmentCanonicalCredit: true,
  fixedAndLifecycle: true, cleanupComplete: true, relayRetired: true,
  browserApi: { total: 11, apiRequests: 7, denied: [], interceptionErrors: 0 }, errors: [] });
function wire(armName, index, kind) {
  const request = '{}', response = '{"message":{"content":"ok"}}';
  return { arm: armName, index, kind, status: 200, responseComplete: true,
    responseCaptureTruncated: false, request, requestSha256: hash(request),
    response, responseSha256: hash(response) };
}

test('pair receipt is distinct, exact, two-arm and never promotes control credit (structural only)', () => {
  assert.equal(assertPairReceipt(receipt()).scope, SCOPE);
  for (const changed of [
    { ...receipt(), control: { ...receipt().control, canonicalCredit: 1 } },
    { ...receipt(), physicalCalls: 15 },
    { ...receipt(), treatment: { ...receipt().treatment, runId: 'control-run' } },
    { ...receipt(), treatment: { ...receipt().treatment, launchId: 'control-launch' } },
    { ...receipt(), treatment: { ...receipt().treatment, resultSha256: 'b'.repeat(64) } },
    { ...receipt(), control: { ...receipt().control, judgeCalls: 0, physicalCalls: 7 }, physicalCalls: 15 },
    { ...receipt(), treatmentCanonicalCredit: false },
    { ...receipt(), cleanupComplete: false },
    { ...receipt(), relayRetired: false },
    { ...receipt(), browserApi: { ...receipt().browserApi, denied: [{ method: 'POST', path: '/api/foreign' }] } },
    { ...receipt(), errors: ['failed'] },
    { ...receipt(), oldV39Credit: true },
  ]) assert.throws(() => assertPairReceipt(changed));
  const sameLaunchAfterReset = receipt();
  sameLaunchAfterReset.treatment.launchId = sameLaunchAfterReset.control.launchId;
  sameLaunchAfterReset.treatment.launchGeneration = '2';
  assert.equal(assertPairReceipt(sameLaunchAfterReset).treatment.launchGeneration, '2');
  const { cleanupComplete, relayRetired, browserApi, ...captured } = receipt();
  assert.equal(finalizePairReceipt(captured, { cleanupComplete, relayRetired, browserApi }).version, 2);
  assert.throws(() => assertPairReceipt(captured), 'pre-cleanup pair evidence cannot qualify');
});

test('arm wire requires actual completed POST records with exact arm, digest and budget', () => {
  const calls = [...Array(7)].map((_, i) => wire('control', i + 1, 'actor'));
  calls.push(wire('control', 8, 'judge'));
  assert.deepEqual(assertPhysicalArm('control', calls),
    { actorCalls: 7, judgeCalls: 1, physicalCalls: 8 });
  for (const changed of [
    calls.map((row, i) => i === 0 ? { ...row, arm: 'treatment' } : row),
    calls.map((row, i) => i === 0 ? { ...row, index: 2 } : row),
    calls.map((row, i) => i === 0 ? { ...row, responseComplete: false } : row),
    calls.map((row, i) => i === 0 ? { ...row, requestSha256: 'b'.repeat(64) } : row),
    [...calls, wire('control', 9, 'unknown')],
  ]) assert.throws(() => assertPhysicalArm('control', changed));
});

test('source-backed admission rejects caller-supplied summaries without persisted original proof', () => {
  assert.throws(() => assertCapturedArm('control', {}, [], () => true));
  assert.throws(() => assertPairCaptured({ control: {}, treatment: {},
    controlCalls: [], treatmentCalls: [], qualifyModelTrace: () => true }));
  assert.throws(() => assertPairCaptured({ control: {}, treatment: {},
    controlCalls: [], treatmentCalls: [], qualifyModelTrace: null }));
});

test('legacy rendered default remains closed while the atomic control is a separate early-return branch', () => {
  const source = readFileSync(require.resolve('./fixtures/secureshopMcpDescriptionRenderedQualification'), 'utf8');
  assert.match(source, /atomicArm = null/);
  assert.match(source, /atomicArm === 'control'/);
  assert.match(source, /buildMcpDescriptionDiagnosticCandidate/);
  assert.match(source, /isMcpDescriptionJudgeInputValid\(diagnosticInput/);
  assert.match(source, /return captured;\s*}\s*const beforeAssessment/);
});

test('physical control retirement completes before canonical reset, and retirement failure prevents reset', async () => {
  const events = [];
  const scope = { launchId: 'owned-control', generation: 4 };
  const reset = { launchResetCoordinator: { reset: async input => {
    events.push('reset');
    assert.equal(input.launchId, scope.launchId);
    assert.equal(input.expectedGeneration, scope.generation);
    assert.match(input.idempotencyKey, /^[0-9a-f-]{36}$/);
    return { resetId: 'real-reset' };
  } } };
  assert.deepEqual(await resetAfterControlRelayRetirement({
    retirePhysicalArm: async () => { events.push('retired'); }, reset, scope,
  }), { resetId: 'real-reset' });
  assert.deepEqual(events, ['retired', 'reset']);
  events.length = 0;
  await assert.rejects(resetAfterControlRelayRetirement({
    retirePhysicalArm: async () => { events.push('retirement-failed');
      throw new Error('owned listener not retired'); }, reset, scope,
  }), /owned listener not retired/);
  assert.deepEqual(events, ['retirement-failed'], 'a failed listener retirement cannot reset or start treatment');
  await assert.rejects(resetAfterControlRelayRetirement({ reset, scope }), /physical relay retirement/);
  assert.deepEqual(events, ['retirement-failed']);
});

test('native pair admission retains the genuine provider class and switches only after retired control', () => {
  const source = readFileSync(require.resolve('./postgres/secureshopOwnedMcpRegistryRendered.native'), 'utf8');
  assert.match(source, /MCP_DESCRIPTION_V39_ATOMIC_PAIR_NATIVE === '1'/);
  assert.match(source, /await v39PairArm\.finish\(\);[\s\S]*beginArm\('treatment'/);
  assert.match(source, /retirePhysicalArm: atomicArm === 'control'[\s\S]*await v39PairArm\.finish\(\)/);
  assert.match(source, /assertV43ResetCheckpoint\(control\.fences\.reset, scope, resetRows\[0\]\)/);
  assert.match(source, /assertPairCaptured\(\{ control, treatment, controlCalls, treatmentCalls/);
  const { switchV39AtomicProvider } = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
  const { createSecureShopModelQualifier } = require('../server/services/secureshopModelQualification');
  const instance = (port, label) => Object.assign(Object.create(OllamaProvider.prototype), {
    model: 'llama3.1:8b', baseUrl: `http://127.0.0.1:${port}`,
    transport: { label }, chat: () => label, finalResponse: () => label,
    routeWorkflow: () => label, isReachable: () => true,
  });
  const control = instance(41101, 'control'), treatment = instance(41102, 'treatment');
  assert.equal(switchV39AtomicProvider(control, treatment), control);
  assert.equal(control.chat(), 'treatment');
  assert.equal(control.baseUrl, treatment.baseUrl);
  assert.equal(createSecureShopModelQualifier(control)({ provider: 'ollama',
    model: 'llama3.1:8b', mocked: false, fallback: false }), true);
  assert.throws(() => switchV39AtomicProvider(instance(41103, 'control'),
    { ...treatment, baseUrl: 'http://127.0.0.1:41104' }));
  assert.throws(() => switchV39AtomicProvider(instance(41105, 'control'), instance(41105, 'same')));
});

test('atomic browser admits only exact local rendered assets and original V39 API operations', async () => {
  const { v39AtomicBrowserRequestAllowed, createV39AtomicBrowserAudit } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const origin = 'http://127.0.0.1:41111';
  const build = fs.mkdtempSync(path.join(os.tmpdir(), 'v39-atomic-browser-'));
  try {
    fs.mkdirSync(path.join(build, 'assets'));
    fs.writeFileSync(path.join(build, 'assets', 'app-1.js'), 'controlled asset');
    const allowed = (method, address) => v39AtomicBrowserRequestAllowed({ origin, build,
      method, url: `${origin}${address}` });
    const id = '123e4567-e89b-42d3-a456-426614174000';
    for (const [method, address] of [
      ['GET', '/secureshop/login'], ['GET', '/secureshop/admin/mcp'],
      ['GET', '/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp'],
      ['GET', `/secureshop-frame.html?entry=%2Fsecureshop%2Fadmin%2Fmcp&standalone=1#${'a'.repeat(64)}`],
      ['GET', '/assets/app-1.js'], ['POST', '/api/secureshop/auth/login'],
      ['POST', '/api/secureshop/auth/bootstrap'], ['GET', '/api/secureshop/auth/session'],
      ['GET', '/api/secureshop/v2/mcp-trust/readiness'], ['GET', '/api/secureshop/auth/reset-recovery'],
      ['GET', '/api/secureshop/admin/mcp/servers'],
      ['POST', '/api/secureshop/agents/admin/chat'],
      ['GET', `/api/secureshop/agents/admin/chat/description-assessment/${id}/${id}`],
    ]) assert.equal(allowed(method, address), true, `${method} ${address}`);
    for (const [method, address] of [
      ['POST', '/api/secureshop/auth/reset'], ['POST', '/api/secureshop/admin/mcp/register'],
      ['POST', '/api/secureshop/auth/session'], ['GET', '/api/secureshop/auth/session?all=1'],
      ['POST', '/api/secureshop/auth/reset-recovery'], ['GET', '/api/secureshop/auth/reset-recovery?all=1'],
      ['GET', '/secureshop/admin'], ['GET', '/secureshop/admin/users'],
      ['GET', '/secureshop/login?next=%2Fsecureshop%2Fadmin'],
      ['GET', '/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp&next=%2Fsecureshop%2Fadmin%2Fmcp'],
      ['GET', '/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp&prefill=student_admin'],
      ['POST', '/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp'],
      ['POST', '/api/secureshop/v2/mcp-trust/readiness'],
      ['GET', '/api/secureshop/v2/mcp-trust/readiness?scope=all'],
      ['GET', '/api/secureshop/auth/admin/users'], ['GET', '/api/secureshop/admin/mcp/servers?scope=all'],
      ['GET', '/assets/absent.js'], ['GET', '/other-workshop'],
      ['POST', '/secureshop/admin/mcp'],
    ]) assert.equal(allowed(method, address), false, `${method} ${address}`);
    assert.equal(v39AtomicBrowserRequestAllowed({ origin, build, method: 'GET',
      url: 'http://127.0.0.1:41112/api/secureshop/admin/mcp/servers' }), false);
    const audit = createV39AtomicBrowserAudit({ origin, build, maximumRequests: 2 });
    let sent = 0, stopped = 0;
    const request = (url, method = 'GET') => ({ url: () => `${origin}${url}`, method: () => method,
      continue: async () => { sent += 1; }, abort: async () => { stopped += 1; } });
    audit.intercept(request('/api/secureshop/admin/mcp/servers'));
    audit.intercept(request('/api/secureshop/admin/mcp/servers'));
    assert.deepEqual(await audit.finish(), { total: 2, apiRequests: 2, denied: [], interceptionErrors: 0 });
    audit.intercept(request('/api/secureshop/admin/mcp/servers'));
    await assert.rejects(audit.finish(), /unowned route or exceeded its cap/);
    assert.equal(sent, 2); assert.equal(stopped, 1);
  } finally { fs.rmSync(build, { recursive: true, force: true }); }
});

test('pair physical login uses the original safe destination and legacy login is unchanged', async () => {
  const { registryBrowserLoginUrl, v39AtomicBrowserRequestAllowed } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const { safeLoginDestination } = await import('../client/src/pages/secureshop/utils/loginDestination.mjs');
  const origin = 'http://127.0.0.1:41111';
  const actual = new URL(registryBrowserLoginUrl(origin, true));
  assert.equal(actual.search, '?next=%2Fsecureshop%2Fadmin%2Fmcp');
  assert.equal(safeLoginDestination(actual.searchParams.get('next'), { role: 'admin' }), '/secureshop/admin/mcp');
  assert.equal(safeLoginDestination('/secureshop/home', { role: 'admin' }), '/secureshop/admin');
  assert.equal(registryBrowserLoginUrl(origin, false), `${origin}/secureshop/login`);
  assert.equal(v39AtomicBrowserRequestAllowed({ origin, method: 'GET', url: actual.href }), true);
  assert.equal(v39AtomicBrowserRequestAllowed({ origin, method: 'GET', url: `${origin}/secureshop/admin` }), false);
  const source = readFileSync(require.resolve('./postgres/secureshopOwnedMcpRegistryRendered.native'), 'utf8');
  assert.ok(source.includes('page.goto(registryBrowserLoginUrl(origin, V39_PAIR_ENABLED))'));
});

test('actual standalone admin controller performs admitted reset-recovery GET before bootstrap', async () => {
  const { createSecureShopStandaloneController } = await import('../client/src/pages/secureshop/SecureShopStandaloneController.mjs');
  const { createStandaloneShopClient } = await import('../client/src/pages/secureshop/standaloneClient.mjs');
  const { v39AtomicBrowserRequestAllowed } = require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const origin = 'http://127.0.0.1:41111';
  for (const denied of [false, true]) {
    const calls = [], states = [];
    const client = createStandaloneShopClient({ fetchImpl: async (address, options) => {
      calls.push(`${options.method} ${address}`);
      assert.equal(v39AtomicBrowserRequestAllowed({ origin, url: origin + address, method: options.method }), true);
      assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'include');
      assert.equal(options.body, undefined); assert.equal(options.signal.aborted, false);
      return { ok: !denied, status: denied ? 403 : 200, headers: { get: () => 'application/json' },
        json: async () => denied ? { error: 'controlled recovery denied' } : { pending: null } };
    } });
    const controller = createSecureShopStandaloneController({ origin, shopRole: 'admin',
      storage: { getItem: () => null }, documentRef: { createElement: () => assert.fail('unexpected mount') },
      client: { ...client, bootstrap: async () => { calls.push('bootstrap'); return { bearer: 'a'.repeat(43) }; },
        scenes: async () => { calls.push('scenes'); return [{ id: 'one' }, { id: 'two' }]; } },
      onState: state => states.push(state.status) });
    try {
      const operation = controller.start({ replaceChildren() {} });
      if (denied) await assert.rejects(operation, /controlled recovery denied/); else await operation;
      assert.deepEqual(calls, ['GET /api/secureshop/auth/reset-recovery', ...(denied ? [] : ['bootstrap', 'scenes'])]);
      assert.equal(states.at(-1), denied ? 'error' : 'choose-scene');
    } finally { controller.close(); }
  }
});

test('bounded sanitized browser audit is retained before failure assertion and excludes private URL content', async () => {
  const { createV39AtomicBrowserAudit, createV39PrivateWriter } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v39-audit-retention-')); fs.chmodSync(directory, 0o700);
  const writer = createV39PrivateWriter(directory, { atomicPair: true });
  const audit = createV39AtomicBrowserAudit({ origin: 'http://127.0.0.1:41111', maximumRequests: 2 });
  let closed = 0;
  const request = (url, method = 'GET') => ({ method: () => method, url: () => url,
    continue: () => assert.fail('denied route continued'), abort: async () => { closed++; } });
  try {
    audit.intercept(request('http://127.0.0.1:41111/secureshop/admin?token=SECRET_QUERY'));
    for (let i = 0; i < 20; i++) audit.intercept(request(
      'https://SECRET_USER:SECRET_PASSWORD@other.invalid/SECRET_PATH' + 'x'.repeat(100000)
        + '?body=SECRET_BODY#SECRET_HASH', i === 0 ? 'SECRET_METHOD'.repeat(1000) : 'GET'));
    let saved;
    await assert.rejects(audit.finish(async snapshot => {
      saved = snapshot;
      writer.write('candidate-result.json', JSON.stringify({ status: 'failed', browserApi: snapshot }));
    }), /unowned route or exceeded its cap/);
    assert.equal(closed, 21); assert.equal(saved.total, 21); assert.equal(saved.denied.length, 16);
    assert.equal(saved.denied[0].path, '/secureshop/admin');
    assert.equal(saved.denied[1].path, '[unrecognized-path]');
    assert.equal(saved.denied[1].method, 'OTHER');
    assert.ok(saved.denied.every(row => row.method.length <= 7 && row.path.length <= 100
      && /^[a-f0-9]{64}$/.test(row.pathSha256)));
    const bytes = fs.readFileSync(path.join(directory, 'candidate-result.json'), 'utf8');
    assert.doesNotMatch(bytes, /SECRET_|https?:|other\.invalid/);
    assert.ok(Buffer.byteLength(bytes) < 4096);
    assert.deepEqual(JSON.parse(bytes).browserApi, audit.snapshot());
  } finally { writer.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('atomic pair final receipt exists only after closed cleanup and is exclusive private output', () => {
  const { publishV39AtomicFinalReceipt } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'v39-atomic-receipt-')));
  const filename = path.join(directory, 'mcp-description-atomic-pair-receipt.json');
  try {
    assert.throws(() => publishV39AtomicFinalReceipt(directory,
      { ...receipt(), cleanupComplete: false }));
    assert.equal(fs.existsSync(filename), false);
    publishV39AtomicFinalReceipt(directory, receipt());
    assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(fs.readFileSync(filename)), receipt());
    assert.throws(() => publishV39AtomicFinalReceipt(directory, receipt()), /EEXIST/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('receipt publication failure never leaves the final success name behind', () => {
  const { publishV39AtomicFinalReceipt } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  for (const failAt of ['file', 'directory']) {
    const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'v39-receipt-failure-')));
    const original = fs.fsyncSync;
    try {
      fs.fsyncSync = descriptor => {
        if (fs.fstatSync(descriptor).isDirectory() === (failAt === 'directory')) {
          const error = new Error(`forced ${failAt} fsync failure`); error.code = 'EIO'; throw error;
        }
        return original(descriptor);
      };
      assert.throws(() => publishV39AtomicFinalReceipt(directory, receipt()), /forced .* fsync failure/);
      assert.equal(fs.existsSync(path.join(directory, 'mcp-description-atomic-pair-receipt.json')), false);
      assert.deepEqual(fs.readdirSync(directory), []);
    } finally { fs.fsyncSync = original; fs.rmSync(directory, { recursive: true, force: true }); }
  }
});

test('early receipt fsync failure retains a replaced candidate and reports cleanup debt', () => {
  const { publishV39AtomicFinalReceipt } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'v39-receipt-replaced-')));
  const original = fs.fsyncSync;
  try {
    fs.fsyncSync = descriptor => {
      if (!fs.fstatSync(descriptor).isDirectory()) {
        const name = fs.readdirSync(directory).find(value => value.endsWith('.tmp'));
        assert.ok(name);
        fs.renameSync(path.join(directory, name), path.join(directory, 'original-retained'));
        fs.writeFileSync(path.join(directory, name), 'replacement', { mode: 0o600 });
        const error = new Error('forced candidate fsync failure'); error.code = 'EIO'; throw error;
      }
      return original(descriptor);
    };
    assert.throws(() => publishV39AtomicFinalReceipt(directory, receipt()),
      /publication failed with cleanup debt/);
    assert.equal(fs.existsSync(path.join(directory, 'mcp-description-atomic-pair-receipt.json')), false);
    assert.ok(fs.readdirSync(directory).some(value => value.endsWith('.tmp')),
      'replaced path must not be unlinked as if it were the original owned inode');
    assert.ok(fs.existsSync(path.join(directory, 'original-retained')));
  } finally { fs.fsyncSync = original; fs.rmSync(directory, { recursive: true, force: true }); }
});

test('unreadable candidate inode is retained as publication debt, never blindly unlinked', () => {
  const { publishV39AtomicFinalReceipt } =
    require('./postgres/secureshopOwnedMcpRegistryRendered.native');
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'v39-receipt-no-inode-')));
  const original = fs.fstatSync;
  try {
    fs.fstatSync = descriptor => {
      const error = new Error('forced inode read failure'); error.code = 'EIO'; throw error;
    };
    assert.throws(() => publishV39AtomicFinalReceipt(directory, receipt()),
      /publication failed with cleanup debt/);
    assert.equal(fs.existsSync(path.join(directory, 'mcp-description-atomic-pair-receipt.json')), false);
    assert.equal(fs.readdirSync(directory).filter(value => value.endsWith('.tmp')).length, 1);
  } finally { fs.fstatSync = original; fs.rmSync(directory, { recursive: true, force: true }); }
});
