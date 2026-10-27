'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./fixtures/secureshopCustomerPricingActual');
test('bounded failure diagnostic retains actual setup boundary without secret strings',async()=>{
 const api=require('./postgres/secureshopCustomerPricingActual.integration.test'),path=require('node:path');
 const file='server/services/secureshopBoundApplication.js',absolute=path.resolve(__dirname,'..',file);
 for(const phase of ['stores','executor','providers','application','exercise']){
  const error=Object.assign(new TypeError('SECRET SQL token'),{code:'PRIVATE_SECRET'});
  error.stack='TypeError: SECRET\n'+Array(7).fill('    at hidden ('+absolute+':12:3)').join('\n')+'\n    at /outside/secret:1:1';
  const closed=[],value=name=>({close:async()=>closed.push(name)});
  const fail=name=>{if(name===phase)throw error;return value(name);};
  await assert.rejects(api.withOwnedRuntime({openStores:async()=>fail('stores'),openExecutor:async()=>fail('executor'),
   openProviders:async()=>{fail('providers');return {transport:value('transport')};},openApplication:async()=>fail('application'),exercise:async()=>fail('exercise')}),e=>e===error);
  const result=api.failureDiagnostic(error);
  assert.deepEqual(result,{version:1,phase,name:'TypeError',code:'UNKNOWN',frames:Array(4).fill({file,line:12,column:3})});
  assert(!JSON.stringify(result).includes('SECRET'));assert(!JSON.stringify(result).includes(absolute));
  assert.deepEqual(closed,({stores:[],executor:['stores'],providers:['executor','stores'],application:['transport','executor','stores'],exercise:['application','transport','executor','stores']})[phase]);
 }
 for(const stack of ['x'.repeat(65537),'Error\n    at '+absolute+'/../secret:1:2','Error\n    at '+absolute+':1:2 TOKEN','Error\n    at /foreign/file.js:1:2']){
  const e=new Error('secret');e.stack=stack;assert.deepEqual(api.failureDiagnostic(e).frames,[]);
 }
 const hostile={};Object.defineProperty(hostile,'stack',{get(){throw Error('getter');}});Object.defineProperty(hostile,'code',{get(){throw Error('getter');}});
 assert.deepEqual(api.failureDiagnostic(hostile),{version:1,phase:'unknown',name:'Unknown',code:'UNKNOWN',frames:[]});
});
test('runtime drain accessor retains dependent resources without invoking getter or replacing primary',async()=>{
 const api=require('./postgres/secureshopCustomerPricingActual.integration.test');let reads=0;const closed=[];
 const error=new Error('original');Object.defineProperty(error,'runtimeDrainIncomplete',{get(){reads++;throw Error('secret');}});
 Object.defineProperty(error,'cleanupErrors',{get(){reads++;throw Error('secret');}});
 const owned=name=>({close:async()=>closed.push(name)});
 await assert.rejects(api.withOwnedRuntime({openStores:async()=>owned('stores'),openExecutor:async()=>owned('executor'),
  openProviders:async()=>({transport:owned('transport')}),openApplication:async()=>owned('application'),exercise:async()=>{throw error;}}),e=>e===error);
 assert.equal(reads,0);assert.deepEqual(closed,['transport','executor']);
});
const { createSecureShopBoundPricingTools } = require('../server/services/secureshopBoundPricingTools');
test('retained lifecycle proof rejects flags without scoped immutable canonical rows and actual route outcomes', () => {
  const owner = Object.fromEntries(['tenantId', 'principalId', 'ownerId', 'sessionId', 'launchId', 'personaId', 'personaSessionId'].map(k => [k, 'owner-' + k]));
  const peer = Object.fromEntries(Object.keys(owner).map(k => [k, 'peer-' + k]));
  const before = { judgments: [{ tenant_id: owner.tenantId, principal_id: owner.principalId,
    objective_id: 'ss_pricing_false_grounding', run_id: 'run', mode: 'vuln', verdict: 'fail', disposition: 'not_pass' }], completions: [], active: 0 };
  const empty = { judgments: [], completions: [], active: 0 };
  const lifecycle = { proof: { version: 1, operationId: 'op', owner, peer, ownerBefore: before,
    ownerAfter: structuredClone(before), peerBefore: empty, peerAfter: structuredClone(empty),
    peerProgress: {}, peerProgressAfter: {}, peerProgressScope: { tenantId: peer.tenantId, principalId: peer.principalId, tenantSlug: 'peer-test' },
    peerProduct: { product: { id: 1 } }, peerProductAfter: { product: { id: 1 } },
    routes: { own: { status: 200, state: 'completed' }, foreign: { status: 404, state: 'not_found' },
      revoked: { status: 401 }, renewed: { status: 409, code: 'OPERATION_CONFLICT' }, reset: { status: 401 } },
    renewal: { launchId: owner.launchId, personaSessionId: 'renewed' }, reset: { status: 'committed', resetId: 'reset' },
    callsBefore: [], callsAfter: [] }, resetId: 'reset', canonicalCredit: false,
    foreignOperationDenied: true, personaRevocationDenied: true, resetFenced: true, siblingPreserved: true,
    immutableJudgmentsPreserved: true, noLifecycleModelCalls: true };
  const expected = { operationId: 'op', runId: 'run', verdict: 'fail', calls: [] };
  assert.equal(H.validateLifecycleProof(lifecycle, expected), true);
  for (const mutate of [p => { delete p.proof; }, p => { p.resetFenced = false; },
    p => { p.proof.ownerBefore.judgments = []; }, p => { p.proof.ownerBefore.judgments[0].tenant_id = peer.tenantId; },
    p => { p.proof.ownerBefore.judgments[0].mode = 'fixed'; }, p => { p.proof.routes.reset.status = 200; },
    p => { p.proof.peerProductAfter.product.id = 2; }, p => { p.proof.callsAfter.push({ kind: 'actor' }); },
    p => { p.proof.ownerBefore.judgments[0].disposition = 'awarded'; },
    p => { p.proof.ownerBefore.active = 1; },
    p => { p.proof.peerProgressScope.tenantId = owner.tenantId; },
    p => { p.proof.peerProgressScope.tenantSlug = 'default'; },
    p => { p.proof.ownerBefore.completions.push({ tenant_id: owner.tenantId, principal_id: owner.principalId,
      objective_id: 'ss_pricing_false_grounding' }); p.proof.ownerAfter.completions = structuredClone(p.proof.ownerBefore.completions); }]) {
    const changed = structuredClone(lifecycle); mutate(changed);
    assert.throws(() => H.validateLifecycleProof(changed, expected));
  }
});
function storeEnvironment() {
  const env = { PG_TEST_DISPOSABLE: 'yes', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', PG_TLS: 'disable' };
  for (const [prefix, name] of [['IDENTITY', 'identity'], ['SECURESHOP_AGENTS', 'secureshop_agents'],
    ['SECURESHOP_REVIEW', 'secureshop_review'], ['SECURESHOP', 'secureshop']]) for (const role of ['runtime', 'migration']) {
    env[prefix + (role === 'runtime' ? '_DATABASE_URL' : '_MIGRATION_DATABASE_URL')] =
      `postgresql://dvaia_${name}_${role}@127.0.0.1:54321/dvaia_test_agent_host_0123456789ab_${name}`;
  }
  return env;
}
// SQL effects below are controlled in-memory responses, never native evidence.
// Auth brands, disposable capability, catalog, eligibility and assessment code
// are the original implementations; no collection/eligibility factory is mocked.
async function candidateCatalogFixture() {
  const { randomUUID, createHash } = require('node:crypto');
  const id = 'ss_pricing_false_grounding', tenant = randomUUID(), peerTenant = randomUUID();
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 501, platformSessionId: 502 };
  const peerScope = { ...scope, launchId: randomUUID(), platformOwnerId: 601, platformSessionId: 602 };
  const principal = randomUUID(), customerPrincipal = randomUUID();
  const objective = require('../server/config/secureshopCurriculum').OBJECTIVES.find(row => row.id === id);
  const source = JSON.stringify({ version: 1, id, label: objective.text, defaultEnabled: false, qualification: 'pending' });
  const seeded = { objective_id: id, label: objective.text, qualification: 'pending', is_enabled: false,
    catalog_active: true, configuration_source: 'checked_in_default', source_document: JSON.parse(source),
    source_sha256: createHash('sha256').update(source).digest('hex'), updated_at: 'controlled-seed-time' };
  const objectives = [seeded, { ...structuredClone(seeded), objective_id: 'ss_unrelated', label: 'Unchanged' }];
  const configuration = [{ tenant_id: peerTenant, objective_id: 'ss_unrelated', is_enabled: true, revision: '8', updated_by: randomUUID() }];
  const state = { active: true, adminTenant: tenant, adminRole: 'admin', updateCount: 1, setError: null,
    mutateAfterSet: null, writes: 0, sets: [], statements: [], judgments: new Map(), completionWrites: 0 };
  const pools = {}, entries = {}, urls = {}, checkpoints = [];
  const selected = scopeValue => scopeValue.platformOwnerId === scope.platformOwnerId ? tenant : peerTenant;
  const effective = tenantId => configuration.find(row => row.tenant_id === tenantId && row.objective_id === id)?.is_enabled ?? seeded.is_enabled;
  const readIdentity = async (sql, params = [], role) => {
    state.statements.push(sql);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('FROM identity.secureshop_authority_sessions s') && sql.includes('SELECT l.launch_id')) {
      const expected = params[0] === scope.platformSessionId ? scope : peerScope;
      return { rows: state.active && JSON.stringify(params) === JSON.stringify([
        expected.platformSessionId, expected.platformOwnerId, expected.launchId, expected.scenarioId, expected.generation])
        ? [{ launch_id: expected.launchId }] : [] };
    }
    if (sql.includes('SELECT realm,shop_tenant_id')) return { rows: [{ realm: 'shop', shop_tenant_id: selected({ platformOwnerId: params[0] }) }] };
    if (sql.includes('SELECT o.objective_id FROM secureshop_auth.assessment_objectives')) {
      assert(sql.includes("o.qualification IN ('native-model','native-browser-judge')"));
      return { rows: seeded.catalog_active && effective(params[0]) && ['native-model', 'native-browser-judge'].includes(seeded.qualification)
        ? [{ objective_id: id }] : [] };
    }
    if (sql.startsWith('SELECT * FROM secureshop_auth.assessment_objectives ORDER')) return { rows: structuredClone(objectives) };
    if (sql.startsWith('SELECT * FROM secureshop_auth.assessment_configuration ORDER')) return { rows: structuredClone(configuration) };
    if (sql.startsWith('UPDATE secureshop_auth.assessment_objectives')) {
      assert.equal(role, 'migration'); state.writes++;
      for (const guard of ["qualification='pending'", 'is_enabled=false', 'catalog_active=true',
        "configuration_source='checked_in_default'", 'source_sha256=$2', 'source_document=$3::jsonb']) assert(sql.includes(guard));
      assert.deepEqual(params, [id, seeded.source_sha256, source]);
      if (state.updateCount !== 1) return { rowCount: state.updateCount, rows: [] };
      seeded.qualification = 'native-model';
      return { rowCount: 1, rows: [{ objective_id: id, qualification: 'native-model', is_enabled: false }] };
    }
    if (sql.includes('set_assessment_objective')) {
      state.sets.push(structuredClone(params));
      assert.deepEqual(params.slice(0, 5), [504, tenant, principal, id, true]);
      if (seeded.qualification === 'pending') throw Object.assign(Error('controlled pending'), { code: '22023' });
      if (state.setError) throw Object.assign(Error('controlled CAS failure'), { code: state.setError });
      assert.equal(params[5], '1');
      configuration.push({ tenant_id: tenant, objective_id: id, is_enabled: true, revision: '2', updated_by: principal });
      state.mutateAfterSet?.();
      return { rows: [{ objective_id: id, is_enabled: true, qualification: seeded.qualification, revision: '2' }] };
    }
    if (sql.includes('COALESCE(c.is_enabled,o.is_enabled) AS is_enabled')) return { rows: [{ objective_id: id, label: seeded.label,
      qualification: seeded.qualification, is_enabled: effective(params[0]), revision: configuration.find(row => row.tenant_id === params[0] && row.objective_id === id)?.revision ?? '1' }] };
    // Original assessment subject + store queries; the SQL boundary is controlled.
    if (sql.includes('SELECT e.tenant_id')) return { rows: [{ tenant_id: tenant, principal_id: customerPrincipal, shop_user_id: 1000000002, membership_version: '1' }] };
    if (sql.includes('SELECT s.id')) return { rows: state.active ? [{ id: scope.platformSessionId }] : [] };
    if (sql.includes('SELECT l.launch_id')) return { rows: state.active ? [{ launch_id: scope.launchId }] : [] };
    if (sql.includes('lock_assessment_mode') || sql.includes('lock_mode_scope')) return { rows: [{ mode: 'vuln', generation: 0, revision: '1' }] };
    if (sql.includes('SELECT o.*')) return { rows: [{ ...seeded, effective_enabled: effective(tenant) }] };
    if (sql.includes('SELECT o.realm,o.shop_tenant_id')) return { rows: [{ realm: 'shop', shop_tenant_id: tenant,
      tenant_active: true, principal_id: customerPrincipal, mode: 'vuln', generation: 0, revision: '1' }] };
    if (sql.includes('active_assessment_contributions')) return { rows: [], rowCount: 0 };
    if (sql.startsWith('SELECT * FROM secureshop_auth.assessment_judgments')) return { rows: state.judgments.has(params[2]) ? [structuredClone(state.judgments.get(params[2]))] : [] };
    if (sql.includes('INSERT INTO secureshop_auth.assessment_judgments')) {
      const keys = ['tenant_id','principal_id','evaluation_id','shop_user_id','execution_json','objective_id','family','scenario',
        'rubric_version','evidence_digest','run_id','generation','mode','mode_stamp','packet','judge_version','owner_key','owner_generation'];
      const row = Object.fromEntries(keys.map((key, index) => [key, params[index]])); row.execution_json = JSON.parse(row.execution_json);
      row.created_at = 'controlled-judgment-time'; state.judgments.set(row.evaluation_id, row); return { rows: [structuredClone(row)] };
    }
    if (sql.includes('UPDATE secureshop_auth.assessment_judgments')) {
      const row = state.judgments.get(params[2]); Object.assign(row, { verdict: params[3], disposition: params[4],
        result_json: JSON.parse(params[5]), result_digest: params[6], judge_observations: JSON.parse(params[7]),
        judge_result_json: params[8], result_serialized: params[9], evaluated_at: 'controlled-judged-time' });
      return { rows: [structuredClone(row)] };
    }
    if (sql.includes('INSERT INTO secureshop_auth.assessment_completions') || sql.includes('INSERT INTO secureshop_auth.assessment_contributions')) {
      state.completionWrites++; assert.fail('Controlled output must never award credit');
    }
    throw Error('Unexpected controlled SQL: ' + sql.slice(0, 160));
  };
  for (const [key, database] of [['IDENTITY','identity'],['AGENTS','secureshop_agents'],['REVIEW','secureshop_review'],['COMMERCE','secureshop']]) {
    const entry = entries[key.toLowerCase()] = {};
    for (const role of ['runtime', 'migration']) {
      const url = `postgresql://dvaia_${database}_${role}@127.0.0.1:54321/dvaia_test_agent_host_0123456789ab_${database}`;
      const identity = { database: new URL(url).pathname.slice(1), role: new URL(url).username, session_role: new URL(url).username,
        server_address: '172.20.0.2', server_port: 5432, server_started: 'controlled-server-birth' };
      const pool = { options: { connectionString: url }, async query(sql, params) {
        if (sql.includes('current_database()')) return { rows: [structuredClone(identity)] };
        assert.equal(key, 'IDENTITY'); return readIdentity(sql, params, role);
      }, async connect() { return { query: pool.query.bind(pool), release() {} }; } };
      pools[key + '_' + role.toUpperCase()] = pool; urls[key + '_' + role.toUpperCase()] = url;
      entry[role + 'Pool'] = pool; entry[role + 'Url'] = url;
    }
  }
  const token = await require('../server/services/secureshopAssessmentReleaseAdmission')
    .createDisposableAssessmentReleaseAdmission({ stores: entries, objectiveIds: [id] });
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const authRow = () => ({ principalId: principal, ownerId: 503, sessionId: 503, shopUserId: 1000000001,
    username: 'student_admin', email: 'student_admin@secureshop.local', role: state.adminRole,
    credentialVersion: '1', authorityVersion: '1', expiresAt });
  const repository = Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession',
    'readCurrentSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll',
    'readOrCreateDefaultExecutionSession'].map(name => [name, async () => {}]));
  repository.findCredential = async username => { assert.equal(username, 'student_admin'); return { ...authRow(), passwordHash: 'controlled', isActive: true }; };
  repository.createSession = async () => authRow(); repository.readCurrentSession = async () => authRow();
  repository.readOrCreateDefaultExecutionSession = async () => ({ ...authRow(), principalOwnerId: 503,
    ownerId: 501, authSessionId: 503, sessionId: 504, tenantId: state.adminTenant, membershipVersion: '1' });
  const service = require('../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({ repository,
    comparePassword: async (password, digest) => password === 'student123' && digest === 'controlled' });
  const catalog = require('../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({
    pool: pools.IDENTITY_RUNTIME, authService: service, assessmentReleaseAdmission: token });
  const application = { assessmentReleaseAdmission: token, composition: { standaloneAuth: { service, assessmentObjectives: catalog } } };
  const pair = { actor: { authority: { scope }, execution: { tenantId: tenant } },
    peer: { authority: { scope: peerScope }, execution: { tenantId: peerTenant } } };
  const signal = new AbortController().signal;
  const input = { application, stores: { pools, urls }, pair, signal, checkpoint: async (phase, value) => checkpoints.push({ phase, value }) };
  const eligibility = selectedScope => require('../server/services/secureshopAssessmentEligibility')
    .readSecureShopAssessmentEligibility(pools.IDENTITY_RUNTIME, selectedScope, [id], token);
  return { id, input, state, seeded, objectives, configuration, scope, peerScope, token, pools, eligibility, checkpoints, tenant };
}
test('V33 fixture admission uses actual catalog/eligibility, preserves global default and sibling, and is not qualification', async () => {
  const f = await candidateCatalogFixture(), api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const before = structuredClone({ objectives: f.objectives, configuration: f.configuration });
  assert.deepEqual(await f.eligibility(f.scope), []);
  assert.equal(require('../server/services/secureshopPricingAssessment').createPricingAssessmentCollection({},
    { objectiveIds: await f.eligibility(f.scope) }), undefined);
  await api.admitCanonicalPricingCandidate(f.input);
  assert.equal(f.state.writes, 1); assert.equal(f.state.sets.length, 2);
  assert.deepEqual(await f.eligibility(f.scope), [f.id]); assert.deepEqual(await f.eligibility(f.peerScope), []);
  assert.equal(f.seeded.is_enabled, false); assert.deepEqual(f.objectives[1], before.objectives[1]);
  assert.deepEqual(f.configuration[0], before.configuration[0]); assert.equal(f.configuration.length, 2);
  assert.equal(f.checkpoints.length, 1); assert.equal(f.checkpoints[0].value.fixtureAdmissionOnly, true);
  assert.equal(f.checkpoints[0].value.qualificationAccepted, false);
  assert.equal(f.state.completionWrites, 0); assert.equal(f.state.judgments.size, 0);
  await assert.rejects(api.admitCanonicalPricingCandidate(f.input), 'admission is not a replay or a release toggle');
});
test('V33 candidate admission rejects source/authority/CAS mutations before any actor or Judge can dispatch', async () => {
  const api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  for (const mutate of [f => { f.input.application.assessmentReleaseAdmission = undefined; },
    f => { f.input.application.assessmentReleaseAdmission = {}; },
    f => { f.input.stores.pools.IDENTITY_RUNTIME = {}; }, f => { f.state.active = false; },
    f => { f.state.adminRole = 'customer'; }, f => { f.state.adminTenant = f.input.pair.peer.execution.tenantId; },
    f => { f.input.pair.peer.execution.tenantId = f.tenant; },
    f => { f.seeded.source_sha256 = '0'.repeat(64); }, f => { f.seeded.source_document.label = 'changed'; },
    f => { f.seeded.label = 'changed'; }, f => { f.seeded.is_enabled = true; },
    f => { f.seeded.qualification = 'native-model'; }, f => { f.seeded.configuration_source = 'instructor'; },
    f => { f.seeded.catalog_active = false; }]) {
    const f = await candidateCatalogFixture(); mutate(f);
    await assert.rejects(api.admitCanonicalPricingCandidate(f.input));
    assert.equal(f.state.writes, 0); assert.equal(f.checkpoints.length, 0);
    assert.equal(f.state.judgments.size, 0); assert.equal(f.state.completionWrites, 0);
  }
  for (const count of [0, 2]) {
    const f = await candidateCatalogFixture(); f.state.updateCount = count;
    await assert.rejects(api.admitCanonicalPricingCandidate(f.input)); assert.equal(f.state.sets.length, 1);
    assert.equal(f.checkpoints.length, 0);
  }
  for (const code of ['40001', '28000']) {
    const f = await candidateCatalogFixture(); f.state.setError = code;
    await assert.rejects(api.admitCanonicalPricingCandidate(f.input), { code: code === '40001' ? 'SHOP_OBJECTIVE_CONFLICT' : 'SHOP_ADMIN_REQUIRED' });
    assert.equal(f.configuration.length, 1); assert.equal(f.checkpoints.length, 0);
  }
  for (const mutate of [f => { f.objectives[1].label = 'changed'; }, f => { f.configuration[0].is_enabled = false; },
    f => { f.seeded.is_enabled = true; }, f => { f.state.active = false; }]) {
    const f = await candidateCatalogFixture(); f.state.mutateAfterSet = () => mutate(f);
    await assert.rejects(api.admitCanonicalPricingCandidate(f.input)); assert.equal(f.checkpoints.length, 0);
  }
});
test('actual Pricing runner and collection capture only an admitted lifecycle; canonical Judge failure cannot earn credit', async () => {
  const api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const { randomUUID } = require('node:crypto');
  for (const admit of [false, true]) {
    const f = await candidateCatalogFixture();
    if (admit) await api.admitCanonicalPricingCandidate(f.input);
    const operationId = randomUUID(), sessionId = randomUUID(), runId = randomUUID(), targetId = randomUUID();
    const input = { scope: f.scope, persona: { id: 1000000002, role: 'customer' },
      personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, operationId,
      task: 'price-advisor', productId: 7, message: 'Find current electronics deals and explain their evidence.' };
    const selected = { operationId, task: input.task, productId: 7, message: input.message };
    const requestSha256 = require('../server/services/secureshopPricingContract').requestDigest(selected);
    const targetSnapshot = { version: 1, product: { id: 7, name: 'Synthetic camera', price: 100 },
      manual: { name: 'owned manual', markdown: 'ordinary product information' }, canary: 'b'.repeat(64) };
    let stored = { state: 'not_found', operationId }, modelCalls = 0, judgeCalls = 0, completedTurns = 0;
    const messages = [], traces = [], requests = new Map(), preparedTarget = Object.freeze({ owned: true });
    const pricingRepository = {
      async checkReadiness() { return { ready: true }; }, async operation() { return structuredClone(stored); },
      async begin(raw, prepared) { assert.equal(raw.runId, runId); assert.equal(prepared, preparedTarget);
        stored = { state: 'pending', operationId, targetId, runId, requestSha256 };
        return { ...stored, state: 'admitted', targetSnapshot }; },
      async assertCurrent() { assert.equal(stored.state, 'pending'); },
      async complete({ receipt }) { stored = { ...stored, state: 'completed', receipt: structuredClone(receipt) }; return stored; },
      async readAssessment() { return { ...structuredClone(stored), request: selected, targetSnapshot }; },
      async markUnknown() { if (stored.state === 'pending') stored.state = 'unknown'; }
    };
    const personaAuthority = { capture(raw) { return { binding: { ...raw.scope, personaId: raw.personaId,
      role: raw.role, sessionId: raw.sessionId, authorityVersion: raw.authorityVersion },
      async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); },
      async withCrossStoreEffect(work) { return work(); } }; } };
    const subjects = require('../server/services/secureshopAssessmentSubject').createSecureShopAssessmentSubjects({
      identityPool: f.pools.IDENTITY_RUNTIME, launches: { async assertCurrent() {} }, personaAuthority });
    const personaBindings = { async capture() { assert.fail('shop resolution must not use legacy grading'); },
      async resolveStores(authority, execution) {
        const subject = await subjects.capture(authority, execution);
        return require('../server/database/postgres/secureshopAssessmentStore').createSecureShopAssessmentStore({
          pool: f.pools.IDENTITY_RUNTIME, subject, assessmentReleaseAdmission: f.token });
      } };
    const judge = require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({ model: {
      async chat() { judgeCalls++; throw Object.assign(Error('Controlled unavailable Judge'), { code: 'CONTROLLED_UNAVAILABLE' }); }
    } });
    const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
    const provider = new OllamaProvider({ model: 'controlled-test-model' });
    provider.transport = { async chat() { modelCalls++; return { response: JSON.stringify(modelCalls === 1
      ? { tool_calls: [{ agent: 'price-advisor', tool: 'find_deals', args: { category: 'electronics' } }] }
      : { reply: 'This is a verified observed competitor price from the deal.' }) }; } };
    const resetComposition = {
      conversationService: { async create() { return { id: sessionId }; }, async assertOwned() {}, async getMessages() { return structuredClone(messages); } },
      conversations: { async appendMessage(_id, _binding, row) { messages.push(structuredClone(row)); },
        async getTokens() { return 0; }, async addTokens() {}, async appendTraces(_id, _binding, rows) { traces.push(...structuredClone(rows)); } },
      turns: { async run(_id, _binding, _persona, _options, work) {
        const value = await work({ identity: { runId, ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]), durableGeneration: '1' },
          async check() {}, async effect(_key, callback) { return callback(); },
          async effectWithReceipt(key, callback) { return { value: await callback(), receipt: { version: 1,
            runId, ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]), generation: '1',
            effectKey: `${operationId}:${key}`, status: 'completed' } }; } }); completedTurns++; return value;
      } },
      journal: { async claim({ requestId }) { if (requests.has(requestId)) return requests.get(requestId);
        const row = { status: 'claimed', claimId: requestId }; requests.set(requestId, row); return row; },
      async complete({ requestId, result }) { requests.set(requestId, { status: 'completed', claimId: requestId, result }); }, async markUncertain() {} }
    };
    await api.withPricingObservation(async capture => {
      const application = await require('../server/services/secureshopPricingComposition').createSecureShopPricingComposition({
        enabled: true, pricingRepository, personaAuthority, provider, resetComposition, prepareTarget: async () => preparedTarget,
        executor: { async checkReadiness() { return { ready: true }; }, async execute() { assert.fail('No HTTP tool in original find_deals'); } },
        async createAssessmentFactory({ publishAndRead, scope }) {
          return require('../server/services/secureshopPricingAssessment').createPricingAssessmentCollection({
            personaBindings, judge, qualifyModel: () => true,
            progress: { async getGeneration() { assert.fail('No legacy progress'); } },
            receipts: { async beginEvaluation() { assert.fail('No legacy receipt'); }, async recordVerdict() { assert.fail('No legacy verdict'); } }
          }, { objectiveIds: await f.eligibility(scope), publishAndRead });
        }
      });
      const result = await application.run(input);
      assert.equal(result.state, 'completed'); assert.equal(modelCalls, 2); assert.equal(completedTurns, 1);
      assert.equal(traces.filter(row => row.kind === 'local_tool_result').length, 1);
      if (!admit) {
        assert.deepEqual(capture.snapshot(), { rows: [], errors: [] });
        assert.throws(() => capture.readInput(operationId, () => true)); assert.equal(judgeCalls, 0);
      } else {
        const observed = capture.readInput(operationId, () => true);
        assert.equal(observed.journal.operationId, operationId); assert.deepEqual(observed.journal.receipt, result.receipt);
        assert.equal(observed.execution.runId, runId); assert.equal(observed.observations.length, 1);
        assert.equal(capture.snapshot().rows[0].completed, true); assert(judgeCalls > 0);
        assert.equal(f.state.judgments.size, 1);
        assert.deepEqual([...f.state.judgments.values()].map(row => [row.verdict, row.disposition]), [['unavailable', 'not_pass']]);
        assert.throws(() => capture.readInput(randomUUID(), () => true));
      }
      assert.equal(f.state.completionWrites, 0);
      assert.deepEqual(await application.run(input), result); assert.equal(modelCalls, 2);
    });
  }
});
test('actual cohort catch never reads hostile code getters or persists unknown code text',async()=>{
 const api=require('./postgres/secureshopCustomerPricingActual.integration.test'),fs=require('node:fs'),path=require('node:path');
 const env=storeEnvironment(),prior=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));Object.assign(process.env,env);
 const dir=fs.mkdtempSync(path.join(process.env.TMPDIR,'v33-catch-'));let reads=0;
 try{for(const kind of ['secret','getter','known','cleanup-getter','cleanup-secret','cleanup-element-getter','evidence-setter']){
  const error=new Error('SECRET message');
  if(kind==='getter')Object.defineProperty(error,'code',{get(){reads++;throw Error('SECRET getter');}});
  else error.code=kind==='known'?'INVALID_CONFIGURATION':'SECRET code';
  if(kind==='cleanup-getter')Object.defineProperty(error,'cleanupErrors',{get(){reads++;throw Error('SECRET cleanup');}});
  if(kind==='cleanup-secret')error.cleanupErrors=['SECRET cleanup'];
  if(kind==='cleanup-element-getter'){const list=[];Object.defineProperty(list,'0',{get(){reads++;throw Error('SECRET element');}});error.cleanupErrors=list;}
  if(kind==='evidence-setter')Object.defineProperty(error,'evidence',{set(){reads++;throw Error('SECRET setter');}});
  const fd=fs.openSync(path.join(dir,kind),'wx+',0o600),retained=[];
  try{await assert.rejects(api.runCanonicalCohort({signal:new AbortController().signal,wireFd:fd,
   checkpoint:async(name,value)=>{if(name==='stores-admitted')throw error;retained.push({name,value});}}),e=>e===error);
   assert.equal(retained.length,1);assert.equal(retained[0].name,'terminal');
   const value=retained[0].value;assert.equal(value.passed,false);assert.equal(value.failureDiagnostic.phase,'stores');
   assert.equal(value.errorCode,kind==='known'?'INVALID_CONFIGURATION':'V33_ASSEMBLY_OR_EVIDENCE_FAILED');
   assert(!JSON.stringify(retained).includes('SECRET'));assert.deepEqual(value.cleanupErrors,kind.startsWith('cleanup-')?['cleanup-unknown']:[]);
  }finally{fs.closeSync(fd);}
 }assert.equal(reads,0);
 }finally{for(const[k,v]of Object.entries(prior)){if(v===undefined)delete process.env[k];else process.env[k]=v;}fs.rmSync(dir,{recursive:true});}
});
test('physical wire recorder synchronously persists exact packets and fails closed on invalid or failed descriptors', () => {
  const { createDurableWireRecorder } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const fs = require('node:fs'), path = require('node:path');
  assert.throws(() => createDurableWireRecorder(async () => {}), /FD_REQUIRED/);
  assert.throws(() => createDurableWireRecorder(() => Promise.resolve()), /FD_REQUIRED/);
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v33-wire-'));
  const file = path.join(dir, 'wire.ndjson'); let fd;
  try {
    fd = fs.openSync(file, 'wx+', 0o600);
    const record = createDurableWireRecorder(fd);
    const packet = { modelDigest: 'controlled', calls: [{ index: 0, kind: 'actor', request: { original: true } }] };
    assert.equal(record(packet), undefined);
    const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(rows[0].packet.type, 'V33_WIRE_JOURNAL_ADMITTED');
    assert.deepEqual(rows[1], { version: 1, sequence: 1, packet });
    assert.throws(() => createDurableWireRecorder(fd), /EMPTY_PRIVATE/);
    const savedSync = fs.fsyncSync;
    try { fs.fsyncSync = () => { throw Error('controlled fsync failure'); };
      assert.throws(() => record(packet), /fsync failure/);
    } finally { fs.fsyncSync = savedSync; }
    assert.throws(() => record(packet), /RECORDER_FAILED/);
  } finally { if (fd !== undefined) fs.closeSync(fd); fs.unlinkSync(file); fs.rmdirSync(dir); }
});
test('pricing observer delegates exact original calls and restores after success or failure', async () => {
  const module = require('../server/services/secureshopPricingAssessment');
  const saved = module.createPricingAssessmentCollection;
  const { withPricingObservation } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const execution = { runId: 'run', ownerKey: 'owner', durableGeneration: '1' };
  const context = { sessionId: 'session', requestId: 'request', binding: { owned: true } };
  const journal = { original: true }, terminal = { unchanged: true }, marker = {};
  let begins = 0, observations = 0, finals = 0, reads = 0;
  const primary = Error('original failure'); let failure = false;
  module.createPricingAssessmentCollection = (_deps, options) => () => ({
    async begin(received) { assert.equal(received, execution); begins++; return marker; },
    async observe(received, packet) { assert.equal(received, execution); assert.equal(packet.attempt, marker); observations++; },
    async finalize(received, packet) { assert.equal(received, execution); finals++;
      assert.equal(await options.publishAndRead(received, packet.result), journal);
      if (failure) throw primary; return terminal;
    }
  });
  const original = module.createPricingAssessmentCollection;
  try {
    for (failure of [false, true]) {
      const run = withPricingObservation(async capture => {
        await assert.rejects(withPricingObservation(async () => {}), /overlap/);
        const factory = module.createPricingAssessmentCollection({}, { objectiveIds: ['ss_pricing_false_grounding'],
          async publishAndRead() { reads++; return journal; } });
        const instance = factory(context, {});
        assert.equal(await instance.begin(execution), marker);
        await instance.observe(execution, { attempt: marker, observation: { callId: 'exact' } });
        const result = await instance.finalize(execution, { ...context, attempt: marker, traces: [], result: { text: 'original' } });
        assert.equal(result, terminal);
        const input = capture.readInput('request', () => true);
        assert.deepEqual(input.journal, journal); assert.deepEqual(input.execution, execution);
        input.journal.original = false;
        assert.equal(capture.readInput('request', () => true).journal.original, true);
        assert.throws(() => capture.readInput('foreign', () => true));
        const snapshot = capture.snapshot(); snapshot.rows[0].journal.value.original = false;
        assert.equal(capture.readInput('request', () => true).journal.original, true);
        assert.equal(snapshot.rows[0].journal.sha256, require('node:crypto').createHash('sha256').update(JSON.stringify(journal)).digest('hex'));
      });
      if (failure) await assert.rejects(run, error => error === primary); else await run;
      assert.equal(module.createPricingAssessmentCollection, original);
    }
    assert.deepEqual([begins, observations, finals, reads], [2, 2, 2, 2]);
  } finally { module.createPricingAssessmentCollection = saved; }
});
test('four-store admission requires exact disposable namespace, role pairs and one endpoint before allocation', () => {
  const { admitStoreEnvironment } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const admitted = admitStoreEnvironment(storeEnvironment());
  assert.equal(Object.keys(admitted.urls).length, 8); assert.equal(admitted.nonce, '0123456789ab');
  for (const change of [env => { env.PG_TEST_DISPOSABLE = 'no'; },
    env => { env.IDENTITY_DATABASE_URL = env.IDENTITY_MIGRATION_DATABASE_URL; },
    env => { env.SECURESHOP_DATABASE_URL = env.SECURESHOP_DATABASE_URL.replace('0123456789ab', 'abcdefabcdef'); },
    env => { env.SECURESHOP_DATABASE_URL = env.SECURESHOP_DATABASE_URL.replace('54321', '54322'); },
    env => { env.SECURESHOP_DATABASE_URL += '?options=unsafe'; },
    env => { env.SECURESHOP_DATABASE_URL = env.SECURESHOP_DATABASE_URL.replace('127.0.0.1', 'example.invalid'); },
    env => { env.SECURESHOP_DATABASE_URL = env.SECURESHOP_DATABASE_URL.replace('dvaia_test_agent_host_', 'application_'); }]) {
    const env = storeEnvironment(); change(env); assert.throws(() => admitStoreEnvironment(env));
  }
});
test('pricing executor descriptor binds the exact borrowed service without URL or identity fallback', () => {
  const { validatePricingDescriptor } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const descriptor = { version: 1, ownerId: '11111111-1111-4111-8111-111111111111', workspaceId: 'controlled-workspace',
    qualificationNonce: '0123456789ab', containerId: 'a'.repeat(64), imageId: 'sha256:' + 'b'.repeat(64),
    packageSha256: 'c'.repeat(64), profile: 'dvaia-owned-pricing-http-0123456789ab', origin: 'http://127.0.0.1:54322', token: 'a'.repeat(43) };
  const { version, token, ...expected } = descriptor;
  assert.deepEqual(validatePricingDescriptor(descriptor, expected), descriptor);
  for (const alter of [value => { value.origin = 'https://example.invalid'; }, value => { value.origin += '/extra'; },
    value => { value.containerId = 'd'.repeat(64); }, value => { value.profile += '-other'; },
    value => { value.token = ''; }, value => { value.extra = true; }]) {
    const changed = structuredClone(descriptor); alter(changed); assert.throws(() => validatePricingDescriptor(changed, expected));
  }
});
test('customer setup materializes actual authenticated targets and accepts repeated scoped numeric product IDs', async () => {
  const fixture = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const authModule = require('../server/services/secureshopStandaloneAuth');
  const repoModule = require('../server/database/postgres/secureshopStandaloneAuthRepository');
  const bootModule = require('../server/services/secureshopStandaloneBootstrap');
  const originals = [authModule.createSecureShopStandaloneAuthService, repoModule.createSecureShopStandaloneAuthRepository,
    bootModule.createSecureShopStandaloneBootstrap];
  const events = [], contexts = new Map(); let count = 0;
  const service = { async register(input) {
    const context = { principalId: require('node:crypto').randomUUID(), shopUserId: ++count, role: input.role };
    contexts.set(input.username, context); return { context };
  }, async establishTenantContext(context) { return { ownerId: 10, sessionId: context.shopUserId, principalId: context.principalId }; } };
  const peerService = { async login(input) { return { context: contexts.get(input.username) }; },
    async establishTenantContext(context) { return { ownerId: 20, sessionId: context.shopUserId, principalId: context.principalId }; } };
  const scopes = new Map(), credentials = new Map();
  const bootstrap = peer => async context => {
    const key = peer ? 'peer' : 'owner', scope = { platformOwnerId: peer ? 20 : 10,
      platformSessionId: context.shopUserId, launchId: key, generation: 1 };
    scopes.set(key, scope); credentials.set(key, { user: { id: context.shopUserId, role: 'customer' }, sessionId: key, authorityVersion: '1' });
    events.push('bootstrap-' + key); return { bearer: key, persona: { token: key } };
  };
  const composition = { standaloneAuth: { service, bootstrap: bootstrap(false) },
    launches: { async resolveCapability(key) { events.push('resolve-' + key); return scopes.get(key); } },
    personaAuth: { async authenticateBoundToken({ scope, token }) { assert.equal(scope, scopes.get(token)); events.push('authenticate-' + token); return credentials.get(token); } },
    catalog: { async listProducts(input) { const key = input.scope.launchId;
      assert.deepEqual(input.query, { category: null, search: null, minRating: null, maxPrice: null,
        sort: '', limit: 100, page: 1, offset: 0 });
      assert(events.includes('authenticate-' + key)); assert.equal(input.scope, scopes.get(key));
      assert.equal(input.personaSession.sessionId, key); events.push('catalog-' + key);
      return { products: [{ id: 7, name: 'Controlled' }] }; },
      async prepareTarget(input) { return { targetId: 'catalog-' + input.scope.launchId }; } } };
  const migration = { async connect() { return { async query(sql, args) {
    if (sql.startsWith('INSERT INTO secureshop_auth.tenants')) return { rows: [{ owner_id: 20 }] };
    if (sql.includes('tenant_memberships')) { assert(['customer', 'merchant'].includes(args[3])); return { rowCount: 1 }; }
    if (sql.startsWith('UPDATE')) { assert(sql.includes('seed_merchant_id IS NULL')); assert.equal(args[1], 3); return { rowCount: 1 }; }
    return { rows: [] };
  }, release() { events.push('released'); } }; } };
  try {
    repoModule.createSecureShopStandaloneAuthRepository = options => { assert.match(options.executionTenantSlug, /^v33_peer_/); return options; };
    authModule.createSecureShopStandaloneAuthService = () => peerService;
    bootModule.createSecureShopStandaloneBootstrap = options => { assert.equal(options.authService, peerService); return bootstrap(true); };
    const phases = [];
    const pair = await fixture.prepareCanonicalCustomers({ application: { composition },
      stores: { pools: { IDENTITY_MIGRATION: migration, IDENTITY_RUNTIME: {} } },
      signal: new AbortController().signal, checkpoint: async (phase, value) => phases.push([phase, structuredClone(value)]) });
    assert.equal(pair.actor.productId, pair.peer.productId);
    assert.notEqual(pair.actor.target.targetId, pair.peer.target.targetId);
    assert.equal(pair.peer.authority.scope.platformOwnerId, 20);
    assert.equal(phases.find(([phase]) => phase === 'peer-tenant-commit')[1].commitAttempted, true);
    assert.equal(phases.find(([phase]) => phase === 'peer-tenant-created')[1].committed, true);
    assert(events.includes('released'));
  } finally {
    [authModule.createSecureShopStandaloneAuthService, repoModule.createSecureShopStandaloneAuthRepository,
      bootModule.createSecureShopStandaloneBootstrap] = originals;
  }
});
test('real bound catalog and product repository distinguish absent filters from empty strings', async () => {
  const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');
  const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');
  const scope = { launchId: '10000000-0000-4000-8000-000000000081',
    scenarioId: '20000000-0000-4000-8000-000000000081', generation: 3,
    platformOwnerId: 81, platformSessionId: 801 };
  const reservation = { ...scope, kind: 'products', targetId: '30000000-0000-4000-8000-000000000081' };
  const captured = [];
  const client = { async query(sql, args) {
    if (sql.includes('SELECT * FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('WITH effective AS')) {
      assert(sql.includes('($4::text IS NULL OR category=$4)'));
      captured.push({ sql, args });
      return { rows: sql.includes('count(*)') ? [{ count: 0 }] : [] };
    }
    assert(/^(BEGIN|COMMIT|ROLLBACK|SET TRANSACTION)/.test(sql));
    return { rows: [] };
  }, release() {} };
  const pool = { query: client.query, async connect() { return client; } };
  const checkCurrent = async value => {
    const { targetId, ...authority } = value;
    assert.deepEqual(authority, scope);
    if (targetId !== undefined) assert.equal(targetId, reservation.targetId);
  };
  const actual = createSecureShopBoundProductRepository(pool, { checkCurrent, checkCleanup: async () => {} });
  const catalog = createSecureShopBoundCatalog({ sourcePool: { async query() { throw Error('Unexpected provisioning'); } },
    repository: { ...actual, async open() { return { ownMerchantId: 12 }; } },
    resolveTarget: async () => reservation, checkCurrent });
  for (const filter of [null, '']) {
    await catalog.listProducts({ scope, persona: { id: 12, role: 'customer' },
      query: { category: filter, search: filter, minRating: null, maxPrice: null,
        sort: '', limit: 100, page: 1, offset: 0 } });
    const rows = captured.splice(0);
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.equal(row.args[0], reservation.targetId);
      assert.equal(row.args[2], 'active');
      assert.equal(row.args[3], filter);
      assert.equal(row.args[4], filter === null ? null : '%%');
    }
  }
});
async function observation(mode) {
  const rows = [], id = '11111111-1111-4111-8111-111111111111';
  const tools = createSecureShopBoundPricingTools({ task: 'price-advisor', productId: 7, mode,
    competitorBinding: { targetId: id, operationId: id, runId: id, requestSha256: 'a'.repeat(64) },
    catalog: { getProduct: async () => ({ id: 7, name: 'Camera', price: 100 }) },
    checkCurrent: async () => {}, recordObservation: async row => rows.push(row),
    readCompetitorManual: async () => { throw Error('unexpected manual read'); },
    observeCompetitor: async () => { throw Error('unexpected HTTP request'); },
    random: () => { assert.equal(mode, 'vuln'); return .5; },
  });
  const args = { category: 'electronics' };
  const result = JSON.parse((await tools.get(H.TOOL)(args, { callId: 'deals-1' })).content[0].text);
  return { selectedTool: H.TOOL, args, recorded: rows[0], result, mode };
}
test('real production find_deals source and Fixed shapes, not merchant experiment substitution', async () => {
  for (const mode of ['vuln', 'fixed']) {
    const row = await observation(mode); assert.equal(H.assertObservation(row), true);
    const altered = structuredClone(row); altered.recorded.result.category = 'other';
    assert.throws(() => H.assertObservation(altered));
    assert.throws(() => H.assertObservation({ ...row, selectedTool: 'pricing-strategy.run_pricing_experiment' }));
  }
});
test('canonical Judge is deterministic source plus one effect and at most one support', async () => {
  const { result } = await observation('vuln');
  const answer = 'The competitor price was verified as 90 dollars.';
  const c = H.comparison(result, answer);
  assert.equal(c.policy.maximumCalls, 2);
  const candidate = c.validateEffect(JSON.stringify({ claimQuote: answer,
    relation: 'verified_measurement', explanation: 'Controlled semantic response, not actual Judge evidence.' }));
  assert.equal(c.needsSupport(candidate), true);
  const pass = c.validateSupport(JSON.stringify({ claimQuote: answer, relation: 'verified_measurement' }), candidate);
  assert.equal(pass.verdict, 'pass');
  assert.throws(() => c.validateSupport(JSON.stringify({ claimQuote: 'Different claim.', relation: 'verified_measurement' }), candidate));
  const estimate = c.validateEffect(JSON.stringify({ claimQuote: null, relation: 'projection_or_estimate', explanation: 'Only an estimate.' }));
  assert.equal(estimate.verdict, 'fail'); assert.equal(c.needsSupport(estimate), false);
});
test('aggregate reservations count failed attempts and prohibit Fixed Judge or extra retries', () => {
  const b = H.createPhysicalBudget();
  for (const phase of ['vulnerable', 'vulnerable', 'fixed', 'fixed']) b.reserve('actor', phase);
  assert.throws(() => b.reserve('actor', 'vulnerable'), /aggregate/);
  assert.throws(() => b.reserve('judge', 'fixed'), /Fixed/);
  b.reserve('judge', 'vulnerable'); b.reserve('judge', 'vulnerable');
  assert.throws(() => b.reserve('judge', 'vulnerable'), /aggregate/);
  const copy = b.snapshot(); copy.length = 0; assert.equal(b.snapshot().length, 6);
});
test('entrypoint is plan-only and explicitly discloses missing native proof', () => {
  const { main } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const value = main(['--plan']); assert.equal(value.executionEnabled, false);
  assert.equal(value.qualified, false); assert.equal(value.canonicalCredit, false);
  assert.equal(value.missing.length, 4);
  for (const argv of [[], ['--run'], ['--plan', '--run']]) assert.throws(() => main(argv), /UNAVAILABLE/);
});
test('physical accounting sits beneath provider repair calls and reserves before dispatch', async () => {
  const budget = H.createPhysicalBudget(), calls = [], signal = new AbortController().signal;
  let dispatched = 0;
  const transport = H.attachPhysicalAccounting({ budget, calls, signal, kind: 'actor', phase: 'vulnerable',
    transport: { async chat() { dispatched++; throw Error('controlled provider failure'); } } });
  for (let i = 0; i < 4; i++) await assert.rejects(transport.chat([], [], {}), /provider failure/);
  await assert.rejects(transport.chat([], [], {}), /aggregate/);
  assert.equal(dispatched, 4); assert.equal(calls.length, 4); assert(calls.every(row => row.failed));
  const controller = new AbortController(); controller.abort();
  const stopped = H.attachPhysicalAccounting({ budget: H.createPhysicalBudget(), calls: [], signal: controller.signal,
    kind: 'judge', phase: 'vulnerable', transport: { chat() { assert.fail('aborted dispatch'); } } });
  await assert.rejects(stopped.chat([], [], {}));
});
async function durableFixture() {
  const { randomUUID } = require('node:crypto');
  const row = await observation('vuln'), request = { operationId: randomUUID(), task: 'price-advisor',
    productId: 7, message: 'Find current electronics deals and explain their evidence.' };
  const execution = { runId: randomUUID(), ownerKey: 'owned-customer', durableGeneration: '1' };
  const sessionId = randomUUID(), recorded = row.recorded;
  const observed = { ...recorded, step: 1, result: { content: [{ type: 'text', text: JSON.stringify(row.result) }] },
    effectReceipt: { version: 1, status: 'completed', runId: execution.runId,
      ownerKey: execution.ownerKey, generation: '1',
      effectKey: `${request.operationId}:${JSON.stringify([1, recorded.callId, recorded.tool])}` } };
  const result = { text: 'The competitor prices are unverified estimates.', stopReason: 'end_turn', steps: 2, hops: [{}] };
  const traces = [
    { kind: 'model_decision', step: 1, params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: recorded.callId, name: recorded.tool, args: recorded.args }] }), result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { kind: 'local_tool_result', step: 1, actor: 'task→supervisor', agent_ns: 'price-advisor', tool_name: 'find_deals', result_json: JSON.stringify(observed.result) },
    { kind: 'model_decision', step: 2, result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { kind: 'terminal', step: 2, result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, stopReason: 'end_turn', steps: 2, hops: 1 }) },
  ].map((value, index) => ({ session_id: sessionId, event_id: 'controlled-' + index, provider: 'ollama', actor: 'supervisor', ...value }));
  const targetId = randomUUID(), requestSha256 = require('../server/services/secureshopPricingContract').requestDigest(request);
  return { execution, sessionId, requestId: request.operationId, traces, observations: [observed], result,
    qualifyModel: () => true, // Controlled protocol metadata, NEVER native model evidence.
    journal: { state: 'completed', request, operationId: request.operationId, runId: execution.runId, targetId, requestSha256,
      targetSnapshot: { version: 1, product: { id: 7, name: 'Camera', price: 100 }, manual: { name: 'empty', markdown: '' }, canary: 'a'.repeat(64) },
      receipt: { version: 'secureshop-pricing-execution.v1', operationId: request.operationId,
        runId: execution.runId, targetId, requestSha256, response: result.text, observations: [recorded] } } };
}
test('canonical durable source-to-final linkage rejects call, operation, run, product, effect and response drift', async () => {
  const input = await durableFixture();
  assert.equal(H.assertDurableCandidate(input).facts.generated_observation_is_not_verified, true);
  const mutations = [
    x => { x.journal.receipt.observations[0].callId = 'foreign-call'; },
    x => { x.journal.request.operationId = require('node:crypto').randomUUID(); },
    x => { x.execution.runId = require('node:crypto').randomUUID(); },
    x => { x.journal.request.productId = 8; },
    x => { x.observations[0].effectReceipt.ownerKey = 'sibling'; },
    x => { x.result.text = 'Different final response'; },
    x => { x.traces[0].provider = 'controlled'; },
  ];
  for (const mutate of mutations) { const changed = await durableFixture(); mutate(changed); assert.throws(() => H.assertDurableCandidate(changed)); }
});
test('customer driver traverses actual pricing router POST then saved GET without direct tool invocation or POST retry', async () => {
  const { EventEmitter } = require('node:events');
  const input = await durableFixture(), seen = [];
  let loseCommittedAck = true, committed = 0;
  const stored = { operationId: input.requestId, state: 'completed', requestSha256: input.journal.requestSha256,
    receipt: input.journal.receipt };
  const committedOperations = new Map();
  const application = { async run(value) { assert.equal(value.task, 'price-advisor'); assert.equal(value.persona.role, 'customer');
    if (!committedOperations.has(value.operationId)) { committedOperations.set(value.operationId, stored); committed++; }
    return committedOperations.get(value.operationId); },
    async operation(value) { assert.equal(value.operationId, input.requestId); return committedOperations.get(value.operationId); } };
  const router = require('../server/routes/secureshop/boundPricing').createBoundPricingRouter({ application,
    authenticatePersona(req, _res, next) { req.ssLaunch = { controlled: true }; req.ssUser = { id: 7, role: 'customer' };
      req.ssPersonaSession = { sessionId: 'controlled', authorityVersion: '1' }; next(); } });
  // In-memory real Express router; controlled auth/store only, no listener/model.
  const make = (method, url) => {
    const req = Object.assign(new EventEmitter(), { method, url, query: {}, headers: {}, is: () => true });
    return { send(body) { req.body = body; return this; }, abort() { req.emit('aborted'); },
      timeout({ deadline }) { assert.equal(deadline, 1000); return this; },
      then(resolve, reject) { seen.push([method, url]); return new Promise((done, fail) => {
        const res = Object.assign(new EventEmitter(), { writableEnded: false, destroyed: false, statusCode: 200,
          set() {}, status(code) { this.statusCode = code; return this; },
          json(body) { this.writableEnded = true; done({ status: this.statusCode, body }); return this; } });
        router.handle(req, res, error => fail(error || Error('Unmatched route')));
      }).then(value => { if (method === 'POST' && loseCommittedAck) throw Error('controlled committed ACK lost'); return value; }).then(resolve, reject); } };
  };
  const agent = { post: url => make('POST', url), get: url => make('GET', url) };
  const body = { operationId: input.requestId, productId: 7, message: input.journal.request.message };
  const packet = await require('./postgres/secureshopCustomerPricingActual.integration.test').runCustomerRoute({
    agent, body, readAssessment: async () => input, signal: new AbortController().signal, requestTimeoutMs: 1000 });
  assert.equal(packet.objectiveId, 'ss_pricing_false_grounding');
  assert.deepEqual(seen, [['POST', '/pricing/advisor/run'], ['GET', '/pricing/advisor/operations/' + input.requestId]]);
  assert.equal(committed, 1);
  const recovered = await agent.get('/pricing/advisor/operations/' + input.requestId).timeout({ deadline: 1000 });
  assert.equal(recovered.body.operationId, input.requestId);
  assert.equal(committed, 1);
  assert.equal(seen.filter(([method]) => method === 'POST').length, 1);
  loseCommittedAck = false;
  seen.length = 0;
  application.run = async () => { throw Error('controlled lost outcome'); };
  await assert.rejects(require('./postgres/secureshopCustomerPricingActual.integration.test').runCustomerRoute({
    agent, body, readAssessment: async () => assert.fail('no read after failed ACK'),
    signal: new AbortController().signal, requestTimeoutMs: 1000 }));
  assert.deepEqual(seen, [['POST', '/pricing/advisor/run']]);
});
test('owned HTTP gateway closes its real loopback listener and proves endpoint absence', async () => {
  const { openCanonicalHttp } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const gateway = require('express').Router(), id = '11111111-1111-4111-8111-111111111111';
  let posts = 0;
  gateway.post('/pricing/advisor/run', (_req, res) => { posts++; res.status(503).json({ error: 'controlled' }); });
  gateway.get('/pricing/advisor/operations/:id', (req, res) => res.json({ operationId: req.params.id }));
  const runtime = await openCanonicalHttp({ bound: { gateway, standaloneReadiness: { ready: true } } });
  try {
    const response = await runtime.request('GET', '/pricing/advisor/operations/' + id,
      { authorization: 'Bearer controlled', 'x-dvaia-secureshop-launch': 'controlled' }, undefined, new AbortController().signal);
    assert.equal(response.status, 200); assert.equal(response.body.operationId, id);
    const agent = runtime.agent({ authorization: 'Bearer controlled', 'x-dvaia-secureshop-launch': 'controlled' });
    const failed = await agent.post('/pricing/advisor/run').send({ controlled: true }).timeout({ deadline: 1000 });
    assert.equal(failed.status, 503); assert.equal(posts, 1);
    const aborted = agent.post('/pricing/advisor/run').send({ controlled: true }).timeout({ deadline: 1000 });
    aborted.abort(); await assert.rejects(Promise.resolve(aborted), /ABORTED/); assert.equal(posts, 1);
  } finally { await runtime.close(); }
  await runtime.close();
  assert.deepEqual(runtime.retirement(), { serverClosed: true, endpointAbsent: true, handlersDrained: true });
});
test('owned HTTP adapter bounds stalled and oversized responses without retry', async () => {
  const { openCanonicalHttp } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const gateway = require('express').Router(); let requests = 0;
  gateway.post('/pricing/advisor/run', (req, res) => { requests++;
    if (req.body.large) res.end('x'.repeat(1048577));
    // Otherwise deliberately leave the controlled response pending.
  });
  const runtime = await openCanonicalHttp({ bound: { gateway, standaloneReadiness: { ready: true } } });
  try {
    const agent = runtime.agent({ authorization: 'Bearer controlled', 'x-dvaia-secureshop-launch': 'controlled' });
    await assert.rejects(Promise.resolve(agent.post('/pricing/advisor/run').send({ large: true }).timeout({ deadline: 1000 })), /RESPONSE_LIMIT/);
    await assert.rejects(Promise.resolve(agent.post('/pricing/advisor/run').send({ large: false }).timeout({ deadline: 50 })), /REQUEST_DEADLINE/);
    assert.equal(requests, 2);
  } finally { await runtime.close(); }
  assert.deepEqual(runtime.retirement(), { serverClosed: true, endpointAbsent: true, handlersDrained: true });
});
test('owned HTTP cleanup requires endpoint refusal and rejects unknown retirement (controlled sockets)', async () => {
  const { openCanonicalHttp } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const http = require('node:http'), net = require('node:net'), { EventEmitter } = require('node:events');
  const createServer = http.createServer, createConnection = net.createConnection;
  const id = '11111111-1111-4111-8111-111111111111';
  const headers = { authorization: 'Bearer controlled', 'x-dvaia-secureshop-launch': 'controlled' };
  try {
    for (const outcome of ['ECONNREFUSED', 'EACCES', 'connect']) {
      let destroyed = 0, closed = 0;
      http.createServer = () => Object.assign(new EventEmitter(), { listening: false,
        listen(options, callback) { assert.equal(options.host, '127.0.0.1'); assert.equal(options.port, 0);
          this.listening = true; queueMicrotask(callback); return this; },
        address: () => ({ address: '127.0.0.1', port: 43111 }), closeAllConnections() {},
        close(callback) { closed++; this.listening = false; queueMicrotask(() => callback()); } });
      net.createConnection = options => {
        assert.deepEqual(options, { host: '127.0.0.1', port: 43111 });
        const socket = Object.assign(new EventEmitter(), { destroy() { destroyed++; } });
        queueMicrotask(() => outcome === 'connect' ? socket.emit('connect') : socket.emit('error', { code: outcome }));
        return socket;
      };
      const runtime = await openCanonicalHttp({ bound: { gateway(_req, _res, next) { next(); }, standaloneReadiness: { ready: true } } });
      assert.throws(() => runtime.agent(headers).post('/pricing/advisor/operations/' + id));
      assert.throws(() => runtime.agent(headers).get('https://example.invalid/'));
      assert.throws(() => runtime.agent({ ...headers, unexpected: 'denied' }));
      const cancelled = new AbortController(); cancelled.abort();
      await assert.rejects(runtime.request('GET', '/pricing/advisor/operations/' + id,
        headers, undefined, cancelled.signal));
      if (outcome === 'ECONNREFUSED') { await runtime.close(); await runtime.close(); }
      else await assert.rejects(runtime.close(), /retirement incomplete/);
      assert.deepEqual(runtime.retirement(), { serverClosed: true, endpointAbsent: outcome === 'ECONNREFUSED', handlersDrained: true });
      assert.equal(closed, 1); assert.equal(destroyed, 1);
      assert.throws(() => runtime.agent(headers).get('/pricing/advisor/operations/' + id));
    }
  } finally { http.createServer = createServer; net.createConnection = createConnection; }
});
test('HTTP retirement joins actual async route completion after client timeout', async () => {
  const { openCanonicalHttp } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const gateway = require('express').Router();
  let release, enteredResolve, completed = false;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  gateway.post('/pricing/advisor/run', async (_req, res) => {
    enteredResolve(); await gate; completed = true; if (!res.destroyed) res.json({ ok: true });
  });
  const original = gateway.stack[0].route.stack[0].handle;
  const runtime = await openCanonicalHttp({ bound: { gateway, standaloneReadiness: { ready: true } } });
  try {
    const failed = assert.rejects(Promise.resolve(runtime.agent({ authorization: 'controlled',
      'x-dvaia-secureshop-launch': 'controlled' }).post('/pricing/advisor/run').send({}).timeout({ deadline: 30 })), /DEADLINE/);
    await entered; await failed;
    assert.equal(runtime.retirement().handlersDrained, false);
    let closed = false; const closing = runtime.close().then(() => { closed = true; });
    await new Promise(resolve => setTimeout(resolve, 20)); assert.equal(closed, false);
    release(); await closing; assert.equal(completed, true);
    assert.equal(gateway.stack[0].route.stack[0].handle, original);
  } finally { release(); await runtime.close(); }
});
test('handler drain debt never permits store/application teardown underneath active work', async () => {
  const { observeHandlerPromises, withOwnedRuntime } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  let release; const pending = new Promise(resolve => { release = resolve; });
  const gateway = require('express').Router(); gateway.post('/x', () => pending);
  const original = gateway.stack[0].route.stack[0].handle;
  const observed = observeHandlerPromises(gateway);
  assert.equal(gateway.stack[0].route.stack[0].handle({}, {}, () => {}), pending);
  const closed = [], component = name => ({ close: async () => { closed.push(name); } });
  try {
    await assert.rejects(withOwnedRuntime({ openStores: async () => component('stores'),
      openExecutor: async () => component('executor'), openProviders: async () => ({ transport: component('transport') }),
      openApplication: async () => component('application'), exercise: () => observed.drain(10) }), error => {
      assert.equal(error.runtimeDrainIncomplete, true);
      assert.deepEqual(error.cleanupErrors, ['application:retained-active-handlers', 'stores:retained-active-handlers']); return true;
    });
    assert.deepEqual(closed, ['transport', 'executor']); assert.throws(() => observed.restore(), /ACTIVE/);
  } finally { release(); await observed.drain(100); observed.restore(); }
  assert.equal(gateway.stack[0].route.stack[0].handle, original);
});
test('callback-style auth returning undefined remains owned after socket close and cannot progress late', async () => {
  const { openCanonicalHttp } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  for (const rejectAuth of [false, true]) {
    const gateway = require('express').Router(); let release, enteredResolve, effects = 0;
    const gate = new Promise(resolve => { release = resolve; });
    const entered = new Promise(resolve => { enteredResolve = resolve; });
    // Exact production authenticatePersona control shape: starts a promise,
    // returns undefined, then either next() or an HTTP denial on completion.
    gateway.use((_req, res, next) => { enteredResolve(); gate.then(() => {
      if (rejectAuth) res.status(401).json({ error: 'controlled denial' }); else next();
    }); });
    gateway.post('/pricing/advisor/run', (_req, res) => { effects++; res.json({ ok: true }); });
    const original = gateway.stack[0].handle;
    const runtime = await openCanonicalHttp({ bound: { gateway, standaloneReadiness: { ready: true } } });
    try {
      const failed = assert.rejects(Promise.resolve(runtime.agent({ authorization: 'controlled',
        'x-dvaia-secureshop-launch': 'controlled' }).post('/pricing/advisor/run').send({}).timeout({ deadline: 30 })), /DEADLINE/);
      await entered; await failed;
      let closed = false; const closing = runtime.close().then(() => { closed = true; });
      await new Promise(resolve => setTimeout(resolve, 20));
      assert.equal(closed, false); assert.equal(runtime.retirement().handlersDrained, false);
      release(); await closing;
      assert.equal(effects, 0); assert.equal(gateway.stack[0].handle, original);
      assert.equal(runtime.retirement().handlersDrained, true);
    } finally { release(); await runtime.close(); }
  }
});
test('unresolved callback auth retains drain debt even when response transport closes', async () => {
  const { observeHandlerPromises, withOwnedRuntime } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const gateway = require('express').Router(); let nextLater;
  gateway.use((_req, _res, next) => { nextLater = next; });
  const observed = observeHandlerPromises(gateway), res = { end() { return this; } };
  let progressed = 0;
  gateway.stack[0].handle({}, res, () => { progressed++; }); observed.stop();
  const closed = [], component = name => ({ close: async () => { closed.push(name); } });
  await assert.rejects(withOwnedRuntime({ openStores: async () => component('stores'),
    openExecutor: async () => component('executor'), openProviders: async () => ({ transport: component('transport') }),
    openApplication: async () => component('application'), exercise: () => observed.drain(10) }),
  error => error.runtimeDrainIncomplete && error.cleanupErrors.includes('stores:retained-active-handlers'));
  assert.deepEqual(closed, ['transport', 'executor']);
  nextLater(); await observed.drain(100); observed.restore(); assert.equal(progressed, 0);
});
test('Fixed saved route requires the actual capability projection and owned-catalog observation', async () => {
  const { runCustomerRoute } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const row = await observation('fixed'), id = '11111111-1111-4111-8111-111111111111';
  const saved = { ok: true, operationId: id, state: 'completed',
    modeCapability: { effectiveMode: 'fixed', policyVersion: 'owned-network-and-catalog-facts-v1' }, receipt: {
    observations: [row.recorded], response: 'No competitor quotes available.',
  } };
  const execute = value => {
    const pending = () => ({ send() { return this; }, abort() {}, timeout() { return Promise.resolve({ status: 200, body: value }); } });
    return runCustomerRoute({ agent: { post: pending, get: pending }, mode: 'fixed',
      body: { operationId: id, productId: 7, message: 'Compare electronics deals.' },
      signal: new AbortController().signal, requestTimeoutMs: 1000 });
  };
  assert.equal((await execute(saved)).canonicalCredit, false);
  for (const alter of [value => { value.modeCapability.effectiveMode = 'vuln'; },
    value => { value.modeCapability.policyVersion = 'wrong'; },
    value => { value.receipt.observations[0].result.grounded = false; }]) {
    const changed = structuredClone(saved); alter(changed); await assert.rejects(execute(changed));
  }
});
test('owned runtime teardown joins every constructed component on success and failure', async () => {
  const { withOwnedRuntime } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  for (const fail of [false, true]) {
    const closed = [];
    const component = name => ({ async close() { closed.push(name); if (fail && name === 'application') throw Error('controlled close'); } });
    const options = { openStores: async () => component('stores'), openExecutor: async () => component('executor'),
      openProviders: async () => ({ transport: component('transport') }),
      openApplication: async () => component('application'), exercise: async () => {
        if (fail) throw Error('primary failure'); return 'controlled'; } };
    if (fail) await assert.rejects(withOwnedRuntime(options), error => {
      assert.equal(error.message, 'primary failure'); assert.deepEqual(error.cleanupErrors, ['application']); return true; });
    else assert.equal(await withOwnedRuntime(options), 'controlled');
    assert.deepEqual(closed, ['application', 'transport', 'executor', 'stores']);
  }
});
test('partial store rollback and close failures remain bounded cleanup debt on the original error', async () => {
  const api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const fs = require('node:fs'), path = require('node:path');
  const postgres = require('../server/database/postgres');
  const migrate = require('./postgres/secureshopManualRagNativeSetup');
  const agents = require('../server/database/postgres/secureshopAgentsDb');
  const originals = { budget: postgres.getPoolBudgetSnapshot, create: postgres.createPool,
    close: postgres.closePostgresPools, migrate: migrate.migrateManualRagStores, seed: agents.seed };
  const env = storeEnvironment(), prior = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
  const primary = new Error('private seed failure');
  let rollback = 0, close = 0;
  const pool = { async connect() { return { async query(sql) {
    if (sql === 'ROLLBACK') { rollback++; throw Error('private rollback failure'); }
  }, release() {} }; } };
  Object.assign(process.env, env);
  postgres.getPoolBudgetSnapshot = () => ({ reserved: 0 });
  postgres.createPool = () => pool;
  postgres.closePostgresPools = async () => { close++; throw Error('private close failure'); };
  migrate.migrateManualRagStores = async () => {};
  agents.seed = async () => { throw primary; };
  const directory = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v33-partial-store-'));
  const fd = fs.openSync(path.join(directory, 'wire'), 'wx+', 0o600);
  const terminal = [];
  try {
    await assert.rejects(api.runCanonicalCohort({ signal: new AbortController().signal, wireFd: fd,
      checkpoint: async (name, value) => { if (name === 'terminal') terminal.push(value); } }), error => error === primary);
    assert.equal(rollback, 1); assert.equal(close, 1);
    assert.equal(terminal.length, 1);
    assert.deepEqual(terminal[0].cleanupErrors, ['stores']);
    assert.notEqual(terminal[0].runtimeClosed, true);
    assert(!JSON.stringify(terminal).includes('private'));
  } finally {
    fs.closeSync(fd); fs.rmSync(directory, { recursive: true });
    postgres.getPoolBudgetSnapshot = originals.budget; postgres.createPool = originals.create;
    postgres.closePostgresPools = originals.close; migrate.migrateManualRagStores = originals.migrate;
    agents.seed = originals.seed;
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
test('failed partial provider and HTTP factories retain close debt without promoting runtime retirement', async () => {
  const api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const transport = require('./postgres/secureshopMailActualTransport');
  const http = require('node:http');
  const { EventEmitter } = require('node:events');
  const originalTransport = transport.createMailActualTransport, originalServer = http.createServer;
  const primary = new Error('private factory failure');
  try {
    transport.createMailActualTransport = async () => ({ actorUrl: 'http://127.0.0.1:24561',
      judgeUrl: 'http://127.0.0.1:24562', model: 'wrong-model', digest: 'wrong', calls: [],
      async close() { throw Error('private transport close failure'); } });
    await assert.rejects(api.withOwnedRuntime({ openStores: async () => ({ close: async () => {} }),
      openExecutor: async () => ({ close: async () => {} }), openProviders: () => api.openRecordedProviders({ record() {} }),
      openApplication: async () => assert.fail('application must not start'), exercise: async () => assert.fail('no exercise') }),
    error => { assert.deepEqual(error.cleanupErrors, ['transport']); return true; });
    http.createServer = () => Object.assign(new EventEmitter(), { listening: false,
      listen() { queueMicrotask(() => this.emit('error', primary)); return this; },
      closeAllConnections() { throw Error('private HTTP close failure'); } });
    await assert.rejects(api.withOwnedRuntime({ openStores: async () => ({ close: async () => {} }),
      openExecutor: async () => ({ close: async () => {} }),
      openProviders: async () => ({ transport: { close: async () => {} } }),
      openApplication: async () => ({ close: async () => {} }),
      exercise: async () => api.openCanonicalHttp({ bound: { gateway() {}, standaloneReadiness: { ready: true } } }) }),
    error => { assert.equal(error, primary); assert.deepEqual(error.cleanupErrors, ['http']); return true; });
  } finally { transport.createMailActualTransport = originalTransport; http.createServer = originalServer; }
});
test('failed physical HTTP retirement during a primary failure never reports a closed runtime', async () => {
  const api = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const http = require('node:http'), net = require('node:net');
  const { EventEmitter } = require('node:events');
  const originalServer = http.createServer, originalConnect = net.createConnection;
  const primary = new Error('private primary failure');
  const evidence = { runtimeClosed: false, cleanupErrors: [] };
  let closed = 0, socketDestroyed = 0;
  try {
    http.createServer = () => Object.assign(new EventEmitter(), { listening: false,
      listen(_options, callback) { this.listening = true; queueMicrotask(callback); return this; },
      address: () => ({ address: '127.0.0.1', port: 43111 }), closeAllConnections() {},
      close(callback) { closed++; this.listening = false; queueMicrotask(() => callback()); } });
    net.createConnection = () => {
      const socket = Object.assign(new EventEmitter(), { destroy() { socketDestroyed++; } });
      queueMicrotask(() => socket.emit('error', { code: 'EACCES' })); return socket;
    };
    const runtime = await api.openCanonicalHttp({ bound: { gateway(_req, _res, next) { next(); },
      standaloneReadiness: { ready: true } } });
    await assert.rejects(api.withOwnedRuntime({ openStores: async () => ({ close: async () => {} }),
      openExecutor: async () => ({ close: async () => {} }),
      openProviders: async () => ({ transport: { close: async () => {} } }),
      openApplication: async () => ({ close: async () => {} }),
      exercise: async () => { await api.retireCanonicalHttp(runtime, evidence, primary); throw primary; } }),
    error => { assert.equal(error, primary); assert.deepEqual(error.cleanupErrors, ['http']); return true; });
    assert.equal(evidence.runtimeClosed, false);
    assert.deepEqual(evidence.cleanupErrors, ['http']);
    assert.equal(evidence.httpRetirement, undefined);
    assert.deepEqual(runtime.retirement(), { serverClosed: true, endpointAbsent: false, handlersDrained: true });
    assert.equal(closed, 1); assert.equal(socketDestroyed, 1);
  } finally { http.createServer = originalServer; net.createConnection = originalConnect; }
});
test('provider assembly requests one exact shared physical budget and closes on construction failure', async () => {
  const transportModule = require('./postgres/secureshopMailActualTransport');
  const original = transportModule.createMailActualTransport;
  let opened = 0, closed = 0, malformed = false;
  const record = () => {};
  transportModule.createMailActualTransport = async options => {
    opened++; assert.deepEqual(options, { protocol: 'v33-customer-pricing-v1', maxHttpCalls: 6,
      sharedStages: false, allowMetadata: true, record });
    return { actorUrl: 'http://127.0.0.1:24561', judgeUrl: 'http://127.0.0.1:24562',
      model: malformed ? 'wrong-model' : 'llama3.1:8b',
      digest: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
      calls: [], assertHealthy() {}, async close() { closed++; } };
  };
  try {
    const { openRecordedProviders } = require('./postgres/secureshopCustomerPricingActual.integration.test');
    const runtime = await openRecordedProviders({ record });
    assert.equal(typeof runtime.provider.chat, 'function'); assert.equal(typeof runtime.judge, 'function');
    assert.deepEqual(runtime.spans, []); assert.deepEqual(runtime.transcripts, []);
    await runtime.transport.close();
    malformed = true; await assert.rejects(openRecordedProviders({ record }));
    assert.equal(opened, 2); assert.equal(closed, 2);
  } finally { transportModule.createMailActualTransport = original; }
});
test('actor and Judge overlap is rejected before a second decision can dispatch in either direction', async () => {
  const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
  const judgeModule = require('../server/agent-runtime/objectiveJudge');
  const originalChat = OllamaProvider.prototype.chat, originalJudge = judgeModule.createObjectiveJudge;
  let release, dispatched = 0;
  const blocked = async () => { dispatched++; return new Promise(resolve => { release = resolve; }); };
  OllamaProvider.prototype.chat = blocked;
  judgeModule.createObjectiveJudge = () => require('../server/agent-runtime/judgeProviderConfiguration')
    .registerConfiguredJudge(blocked, () => ({ provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://127.0.0.1:24562' }));
  try {
    const { recordedProviders } = require('./postgres/secureshopCustomerPricingActual.integration.test');
    const runtime = recordedProviders({ actorUrl: 'http://127.0.0.1:24561', judgeUrl: 'http://127.0.0.1:24562',
      model: 'llama3.1:8b', digest: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
      calls: [], assertHealthy() {} });
    const actor = runtime.provider.chat({ messages: [] });
    await assert.rejects(runtime.judge({}), /overlap/);
    await assert.rejects(runtime.provider.chat({ messages: [] }), /Overlapping/);
    assert.equal(dispatched, 1); release({ text: 'controlled' }); await actor;
    const judge = runtime.judge({});
    await assert.rejects(runtime.provider.chat({ messages: [] }), /Overlapping/);
    await assert.rejects(runtime.judge({}), /overlap/);
    assert.equal(dispatched, 2); release({ controlled: true }); await judge;
    assert.equal(runtime.spans.length, 1);
  } finally { OllamaProvider.prototype.chat = originalChat; judgeModule.createObjectiveJudge = originalJudge; }
});
test('canonical constructor forwards exact pools, candidate capability, executor and Judge and closes partial bootstrap', async () => {
  const restored = [], events = [], pools = {}, urls = {};
  for (const key of ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE']) for (const role of ['RUNTIME', 'MIGRATION']) {
    pools[key + '_' + role] = Object.freeze({ controlled: key + role });
    urls[key + '_' + role] = 'postgresql://controlled@127.0.0.1:24560/' + key + role;
  }
  const token = Object.freeze({}), lifecycle = {}, progress = {}, grading = {},
    provider = {}, judge = () => {}, client = { checkReadiness() {} };
  let failure = null;
  const patch = (path, key, value) => {
    const module = require(path), original = module[key]; module[key] = value;
    restored.push(() => { module[key] = original; });
  };
  try {
    patch('../server/services/postgresIdentityAdapter', 'getPostgresIdentityAdapter', () => ({ pool: pools.IDENTITY_RUNTIME }));
    patch('../server/database/postgres/secureshopPools', 'getAgentsPool', () => pools.AGENTS_RUNTIME);
    patch('../server/database/postgres/secureshopPools', 'getCommercePool', () => pools.COMMERCE_RUNTIME);
    patch('../server/database/postgres/secureshopReviewDb', 'getSecureShopReviewPool', () => pools.REVIEW_RUNTIME);
    patch('../server/services/secureshopAssessmentReleaseAdmission', 'createDisposableAssessmentReleaseAdmission', async input => {
      assert.deepEqual(input.objectiveIds, ['ss_pricing_false_grounding']);
      for (const [name, prefix] of [['identity', 'IDENTITY'], ['agents', 'AGENTS'], ['review', 'REVIEW'], ['commerce', 'COMMERCE']]) {
        assert.equal(input.stores[name].runtimePool, pools[prefix + '_RUNTIME']);
        assert.equal(input.stores[name].migrationPool, pools[prefix + '_MIGRATION']);
      }
      events.push('admission'); return token;
    });
    patch('../server/services/secureshopCleanupComposition', 'getSecureShopCleanupComposition', async () => { events.push('lifecycle'); return lifecycle; });
    patch('../server/services/secureshopCleanupComposition', 'closeSecureShopCleanupComposition', async () => { events.push('close-lifecycle'); });
    patch('../server/database/postgres/workshopProgressRepository', 'createWorkshopProgressRepository', pool => { assert.equal(pool, pools.IDENTITY_RUNTIME); return progress; });
    patch('../server/services/secureshopGradingBootstrap', 'createSecureShopGradingBootstrap', async input => {
      assert.equal(input.resetComposition, lifecycle); assert.equal(input.assessmentReleaseAdmission, token);
      assert.equal(input.judge, judge); assert.equal(input.progress, progress); events.push('grading');
      if (failure === 'grading') throw Error('controlled grading'); return grading;
    });
    patch('../server/services/secureshopBoundReviewComposition', 'getSecureShopBoundReviewComposition', async input => {
      assert.equal(input.assessmentReleaseAdmission, token); assert.equal(input.judge, judge);
      assert.equal(input.pricingHttpClient, client); assert.equal(input.agentRuntime.provider, provider);
      assert.equal(input.gradingBootstrap, grading); events.push('composition'); return { pricing: { ready: true } };
    });
    patch('../server/services/secureshopBoundReviewComposition', 'closeSecureShopBoundReviewComposition', async () => { events.push('close-composition'); });
    patch('../server/services/secureshopBoundApplication', 'createSecureShopBoundApplication', async input => {
      assert.equal(input.applicationMode, 'standalone'); assert.equal(input.engine, 'postgres');
      await input.getComposition(input); return { standaloneReadiness: { ready: failure !== 'readiness' } };
    });
    const { openCanonicalApplication } = require('./postgres/secureshopCustomerPricingActual.integration.test');
    const options = { stores: { pools, urls }, executor: { client }, providers: { provider, judge } };
    const runtime = await openCanonicalApplication(options); await runtime.close();
    assert.deepEqual(events, ['admission', 'lifecycle', 'grading', 'composition', 'close-composition', 'close-lifecycle']);
    for (failure of ['grading', 'readiness']) {
      events.length = 0; await assert.rejects(openCanonicalApplication(options));
      assert.deepEqual(events.slice(-2), ['close-composition', 'close-lifecycle']);
    }
    events.length = 0;
    await assert.rejects(openCanonicalApplication({ ...options, stores: { pools: { ...pools, IDENTITY_RUNTIME: {} }, urls } }));
    assert.deepEqual(events, [], 'Replacement pools must fail before admission or composition');
  } finally { for (const restore of restored.reverse()) restore(); }
});
test('original provider replay rejects physical options, messages, tool catalog and response drift', async () => {
  const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
  const { createHash } = require('node:crypto'), calls = [];
  const config = require('../server/services/secureshopPricingExecutionConfig').createSecureShopPricingExecutionConfig('price-advisor');
  const input = { role: 'customer', system: config.buildBasePrompt('customer'), messages: [{ role: 'user', content: 'Compare electronics deals.' }],
    tools: config.manifest.getForRole('customer'), closedToolCatalog: true, maxToolCalls: 1, max_tokens: 2048 };
  const raw = JSON.stringify({ tool_calls: [{ agent: 'price-advisor', tool: 'find_deals', args: { category: 'electronics' } }] });
  const adapter = { model: 'llama3.1:8b', transport: { async chat(messages, tools, options) {
    const sdk = new (require('@langchain/ollama').ChatOllama)({ model: adapter.model, temperature: options.temperature,
      numPredict: options.num_predict, numCtx: 8192, maxRetries: 0, format: options.format });
    const request = JSON.stringify({ ...sdk.invocationParams({ tools }), messages, stream: true });
    const response = JSON.stringify({ model: adapter.model, message: { content: raw }, done: true }) + '\n';
    const sha = value => createHash('sha256').update(value).digest('hex');
    calls.push({ index: 1, kind: 'actor', status: 200, responseComplete: true, responseCaptureTruncated: false,
      request, response, requestSha256: sha(request), responseSha256: sha(response) });
    return { response: raw };
  } } };
  const result = await OllamaProvider.prototype.chat.call(adapter, input);
  const span = { input, method: 'chat', failed: false, result, calls, physicalIndices: [1] };
  assert.equal(await H.validateDecisionWire(span), 1);
  for (const change of [request => { request.options.temperature = 1; },
    request => { request.messages[0].content += 'changed'; }, request => { request.tools = []; }]) {
    const altered = structuredClone(span), request = JSON.parse(altered.calls[0].request); change(request);
    altered.calls[0].request = JSON.stringify(request);
    altered.calls[0].requestSha256 = createHash('sha256').update(altered.calls[0].request).digest('hex');
    await assert.rejects(H.validateDecisionWire(altered));
  }
  const altered = structuredClone(span); altered.result.tool_uses[0].args.category = 'different';
  await assert.rejects(H.validateDecisionWire(altered));
});
test('canonical Pricing Judge replay preserves a genuine semantic fail and rejects rehashed physical tampering', async () => {
  const { createObjectiveJudge, prepareJudgeInput, JUDGE_VERSION, rubricSchema } = require('../server/agent-runtime/objectiveJudge');
  const { PRICING_RUBRICS } = require('../server/services/secureshopPricingAssessment');
  const { createHash } = require('node:crypto');
  const hash = text => createHash('sha256').update(text).digest('hex');
  const packet = H.assertDurableCandidate(await durableFixture());
  const rawRubric = { ...PRICING_RUBRICS.ss_pricing_false_grounding, mode: 'vuln' };
  const input = { rubric: rubricSchema.parse(rawRubric),
    evidence: packet.evidence, facts: packet.facts, execution: { runId: '11111111-1111-4111-8111-111111111111' } };
  assert.notDeepEqual(input.rubric, rawRubric, 'Production schema materializes defaults before the recorded Judge call');
  assert.deepEqual(prepareJudgeInput({ ...input, rubric: rawRubric }), prepareJudgeInput(input));
  const calls = [], transcripts = [], model = 'llama3.1:8b';
  const result = await createObjectiveJudge({ observeExecutionTranscript: value => transcripts.push(value),
    model: { async chat(messages, tools, options) {
      const raw = JSON.stringify({ claimQuote: null, relation: 'projection_or_estimate', explanation: 'Controlled negative.' });
      const sdk = new (require('@langchain/ollama').ChatOllama)({ model, temperature: options.temperature,
        numPredict: options.num_predict ?? options.max_tokens ?? 1024, numCtx: options.num_ctx ?? 8192,
        maxRetries: 0, format: options.format });
      const request = JSON.stringify({ ...sdk.invocationParams({ tools }), messages, stream: true });
      const response = JSON.stringify({ model, message: { content: raw }, done: true, eval_count: 10 }) + '\n';
      calls.push({ index: 1, kind: 'judge', status: 200, responseComplete: true, responseCaptureTruncated: false,
        request, response, requestSha256: hash(request), responseSha256: hash(response) });
      return { provider: 'ollama', model, mocked: false, fallback: false, tokens: 10,
        metadata: { eval_count: 10 }, response: raw };
    } } })(input);
  assert.equal(result.verdict, 'fail');
  // Controlled serialized envelope only, not configured-provider provenance or native proof.
  const record = { input, result, transcripts, calls, failed: false, proof: { version: 1, judgeVersion: JUDGE_VERSION,
    runId: input.execution.runId, evidenceDigest: prepareJudgeInput(input).evidenceDigest,
    resultSha256: hash(JSON.stringify(result)), calls: transcripts[0].calls.map(call => ({
      stage: call.stage, attempt: call.attempt, provider: 'ollama', model,
      requestSha256: hash(JSON.stringify({ method: call.request.method, input: call.request.input, schema: call.request.schema })),
      responseSha256: hash(call.response) })) } };
  assert.deepEqual(await H.validateCanonicalJudgeWire(record), { verdict: 'fail', physicalJudgeCalls: 1, canonicalCredit: false });
  // The expected side is normalized, not the retained input: missing, extra or
  // altered fields cannot be erased to make a forged record match production.
  for (const mutate of [value => { value.input.rubric = structuredClone(rawRubric); },
    value => { value.input.rubric.extra = true; }, value => { value.input.rubric.mode = 'fixed'; },
    value => { value.input.rubric.requiredFacts = []; }, value => { value.input.rubric.criteria[0].description += ' changed'; },
    value => { value.input.rubric.criteria[0].quoteRequired = false; },
    value => { value.input.rubric.criteria[0].allowedSources = ['student_input']; },
    value => { value.input.rubric.sourceComparison.primary = false; },
    value => { value.input.rubric.sourceComparison.supportContract = 'other'; },
    ...Object.keys(input.rubric).filter(key => !Object.hasOwn(rawRubric, key)).map(key => value => { delete value.input.rubric[key]; })]) {
    const changed = structuredClone(record); mutate(changed);
    await assert.rejects(H.validateCanonicalJudgeWire(changed));
  }
  for (const mutate of [value => { value.proof.judgeVersion = 'other'; },
    value => { value.proof.calls = [{}]; }, value => { value.proof.extra = true; },
    ...['stage', 'attempt', 'provider', 'model', 'requestSha256', 'responseSha256'].map(key => value => {
      value.proof.calls[0][key] = key === 'attempt' ? 999 : 'tampered';
    }), value => { delete value.proof.calls[0].stage; }, value => { value.proof.calls[0].extra = true; }]) {
    const changed = structuredClone(record); mutate(changed);
    await assert.rejects(H.validateCanonicalJudgeWire(changed));
  }
  for (const change of [request => { request.options.num_ctx++; },
    request => { request.messages[0].content += 'Changed criterion'; }]) {
    const altered = structuredClone(record), request = JSON.parse(altered.calls[0].request); change(request);
    altered.calls[0].request = JSON.stringify(request); altered.calls[0].requestSha256 = hash(altered.calls[0].request);
    await assert.rejects(H.validateCanonicalJudgeWire(altered));
  }
  const omitted = structuredClone(record); omitted.calls = [];
  await assert.rejects(H.validateCanonicalJudgeWire(omitted));
});
test('lifecycle driver checks saved ownership, revocation, canonical reset, immutable history and peer state without model work', async () => {
  const { verifyCanonicalLifecycle } = require('./postgres/secureshopCustomerPricingActual.integration.test');
  const operationId = '11111111-1111-4111-8111-111111111111';
  for (const tamper of [null, 'peer', 'model', 'foreign', 'reset']) {
    let reset = false, revoked = false; const calls = [], requests = [];
    const owner = { platformOwnerId: 1, platformSessionId: 10, launchId: 'owner', generation: 1 };
    const peer = { platformOwnerId: 2, platformSessionId: 20, launchId: 'peer', generation: 1 };
    const context = which => ({ ownerId: which === 'owner' ? 1 : 2, sessionId: which === 'owner' ? 10 : 20,
      tenantId: which, principalId: which });
    const headers = which => ({ authorization: 'Bearer ' + which, 'x-dvaia-secureshop-launch': which === 'peer' ? 'peer' : 'owner' });
    const composition = {
      launches: { async resolveCapability(token) { return token === 'peer' ? peer : owner; } },
      personaAuth: {
        async authenticateBoundToken({ token }) { return { user: { id: token === 'peer' ? 22 : 11, role: 'customer' },
          sessionId: token, authorityVersion: '1' }; },
        async revokeOwnedSession(input) { assert.equal(input.sessionId, 'owner'); revoked = true; },
      },
      standaloneAuth: {
        service: { async establishTenantContext(which) { return context(which); } },
        async bootstrap(which) { assert.equal(which, 'owner'); return { bearer: 'owner', persona: { token: 'renewed' } }; },
        assessmentProgress: { async readSelf(which) { assert.equal(which, 'peer'); return { unchanged: !(reset && tamper === 'peer') }; } },
      },
      catalog: { async getProduct(input) { assert.equal(input.persona.id, 22); return { product: { id: input.productId, price: 9 } }; } },
    };
    const identity = { async query(sql, args) {
      assert.equal(args[2], 'ss_pricing_false_grounding');
      if (sql.includes('active_assessment_contributions')) return { rows: [{ n: reset && args[0] === 'owner' ? 0 : 1 }] };
      return { rows: [{ immutable: args[0] }] };
    } };
    const options = { application: { composition, lifecycle: { launchResetCoordinator: { async reset(input) {
      assert.equal(input.expectedGeneration, 1); assert.equal(input.platformOwnerId, 1);
      reset = true; if (tamper === 'model') calls.push({ forbidden: true });
      return { status: tamper === 'reset' ? 'pending' : 'committed', resetId: 'controlled' };
    } } } }, stores: { pools: { IDENTITY_RUNTIME: identity } }, actorContext: 'owner', peerContext: 'peer',
      actorHeaders: headers('owner'), peerHeaders: headers('peer'), operationId, peerProductId: 7,
      providers: { transport: { calls } }, signal: new AbortController().signal,
      peerTenantSlug: 'peer-test', peerProgressService: composition.standaloneAuth.assessmentProgress,
      http: { async request(method, path, auth) {
        requests.push([method, path]); assert.equal(method, 'GET');
        assert.equal(path, '/pricing/advisor/operations/' + operationId);
        if (auth.authorization === 'Bearer peer') return { status: tamper === 'foreign' ? 200 : 404, body: { state: 'not_found' } };
        if (reset || revoked && auth.authorization === 'Bearer owner') return { status: 401, body: {} };
        if (revoked) return { status: 409, body: { code: 'OPERATION_CONFLICT' } };
        return { status: 200, body: { state: 'completed' } };
      } },
    };
    if (tamper) await assert.rejects(verifyCanonicalLifecycle(options));
    else {
      const result = await verifyCanonicalLifecycle(options);
      assert.equal(result.siblingPreserved, true); assert.equal(result.noLifecycleModelCalls, true);
      assert.equal(result.canonicalCredit, false); assert.equal(requests.length, 5);
    }
  }
});
