'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { readMigrations, migrate, executionSql } = require('../../db/postgres/migrate');
const { withTransaction, verifyServer } = require('../../server/database/postgres');
const { assertBoundToolPolicyReadiness } = require('../../server/database/postgres/secureshopBoundToolPolicyReadiness');
const { createListingJournalRepository } = require('../../server/database/postgres/secureshopListingJournalRepository');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createSecureShopBoundUploadGraph } = require('../../server/services/secureshopBoundUploadGraph');
const { prepareListingAdmission } = require('../../server/services/secureshopListingJournalContract');
const { createListingOptimizeExecutor } = require('../../server/services/secureshopListingOptimizeExecutor');
const { createSceneBinding, authorizeSceneMerchant } = require('../../server/services/secureshopSceneBinding');
const { REGISTRY_VERSION, REGISTRY_SHA256 } = require('../../server/services/secureshopBoundAclRegistry');
const { bindDiagnosticResult, diagnosticHostname } = require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const { VERSION: DIAGNOSTIC_VERSION, diagnosticRequestDigest, diagnosticCommand } = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.SECURESHOP_V03_OPTIMIZE_NATIVE === '1';
const PREFIX = 'PG_SECURESHOP_V03_OPTIMIZE_';
const AGENTS_DIRECTORY = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents');
const REVIEW_DIRECTORY = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const AGENTS_SUCCESSORS = ['0105_listing_optimize_conversation_purpose.sql', '0106_listing_optimize_registry_successor.sql'];
const REVIEW_SUCCESSOR = '0054_owned_listing_image_optimize.sql';
const V30 = 'e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef';
const V31 = '0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c';
const V32 = '7b61d5cd1f2dcb98585b0a4312423df33b2a2d2df54905bf394a6e6717719beb';
const V32_GUARD = '32a77ee440bdcc16e8e5b8606d5458a47eacae659dfa06aba1e1bf404ca55530';
const V39 = 'e16a47c5c7a57a9ee60b4982795e4eb7592cf311fb4e9ee52bbbde6d73cd605f';
const V39_GUARD = '445e8716ed8920be8666c95e7aaa04f662c61a1726172f6d93ac9fbff20f43d6';
const REVIEW_GUARD = 'dd34dd8956071640c4af36f8489afbcb22b40dbe3d17d3d6c3f24fb1845bb426';
const digest = value => createHash('sha256').update(value).digest('hex');

function id(value) {
  const text = String(value);
  return `${text.padStart(8, '0')}-0000-4000-8000-${text.padStart(12, '0')}`;
}

function pools(store, roleBase) {
  const value = {};
  for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${PREFIX}${store}_${role}_URL`;
    assert.ok(process.env[key], `${key} required`);
    const parsed = new URL(process.env[key]);
    assert.equal(parsed.protocol, 'postgresql:');
    assert.equal(parsed.hostname, '127.0.0.1');
    assert.equal(parsed.username, `dvaia_secureshop_${roleBase}_${role.toLowerCase()}`);
    assert.match(parsed.pathname, /^\/owasp_ai_goat_test_v03_optimize_[a-f0-9]{12}_[a-z_]+$/);
    value[role.toLowerCase()] = new Pool({ connectionString: process.env[key], max: role === 'RUNTIME' ? 8 : 4 });
  }
  return value;
}

async function preparePrefix(pool, directory, successor) {
  const migrations = await readMigrations(directory);
  const prefix = migrations.filter(migration => migration.name < successor);
  assert.ok(prefix.length > 0);
  return withTransaction(pool, async client => {
    await verifyServer(client);
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
    await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    assert.equal((await client.query('SELECT name FROM dvaia_migrations.ledger')).rowCount, 0);
    for (const migration of prefix) {
      await client.query(executionSql(migration));
      await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',
        [migration.name, migration.checksum]);
    }
    return prefix.map(migration => migration.name);
  });
}

function exactHistory(migrations, targets) {
  const names = migrations.map(row => row.name);
  assert.deepEqual(names, [...new Set(names)].sort());
  const at = names.indexOf(targets[0]);
  assert.ok(at >= 0, 'original target migration required');
  assert.deepEqual(names.slice(at, at + targets.length), targets);
  return { names, rows: migrations.map(({ name, checksum }) => ({ name, checksum })) };
}

// The populated prefix stops at0104. Prove its exact original successor pair
// before applying the current production tail; no source copy or altered SQL.
async function applyOptimizeSuccessors(pool, migrations) {
  const history = exactHistory(migrations, AGENTS_SUCCESSORS);
  const at = history.names.indexOf(AGENTS_SUCCESSORS[0]);
  return withTransaction(pool, async client => {
    await verifyServer(client);
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    assert.deepEqual((await client.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
    history.rows.slice(0, at));
    const applied = [];
    for (const migration of migrations.slice(at, at + AGENTS_SUCCESSORS.length)) {
      await client.query(executionSql(migration));
      await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',
        [migration.name, migration.checksum]);
      applied.push(migration.name);
    }
    return applied;
  });
}

async function ledger(pool) {
  return (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}

function coordinates(seed) {
  return Object.freeze({ launchId: id(1000 + seed), scenarioId: id(2000 + seed), generation: 3,
    platformOwnerId: 100 + seed, platformSessionId: 200 + seed });
}

async function insertPurpose(pool, purpose, seed) {
  const scope = coordinates(seed);
  return pool.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,$2,'merchant','launch_bound','pending',$3,$4,$5,$6,$7,$8)
    RETURNING id,conversation_purpose`,
  [id(3000 + seed), 400 + seed, scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId, purpose]);
}

async function qualifyAvatarSessionAfterCustomerChat(pool) {
  const scope = coordinates(70);
  const persona = Object.freeze({ id: 1000000070, role: 'customer' });
  const repository = createBoundConversationsRepository({ pool,
    queue: async (_sessionId, operation) => operation() });
  let currentChecks = 0;
  const launches = Object.freeze({ async assertCurrent(value) {
    assert.deepEqual(value, scope); currentChecks += 1; return scope;
  } });
  const conversations = createBoundConversationService({ conversations: repository, launches });
  const prior = await conversations.create(scope, persona, 'secureshop_customer_chat');
  const unavailable = async () => { throw new Error('Unexpected upload execution dependency'); };
  const graph = createSecureShopBoundUploadGraph({
    launches, conversationRepository: repository, journal: {},
    coordinator: { run: unavailable }, provider: { chat: unavailable, finalResponse: unavailable },
    uploadApplication: { execute: unavailable }, uploadJournal: { claim: unavailable },
    personaAuthority: { capture: unavailable },
    modeAuthority: { capture: unavailable, assertToken: unavailable },
    toolPolicyRepository: { admitTool: unavailable }, promptPolicyRepository: {},
    assetOrigin: 'http://[::1]:65534', assetCapability: { mint: unavailable },
    resolveTarget: unavailable, assertUploadCurrent: unavailable, verifyEffect: unavailable,
  });
  const created = await graph.createSession({ scope, persona,
    personaSession: { sessionId: id(7070), authorityVersion: '1' } });
  assert.match(prior.id, /^[a-f0-9-]{36}$/); assert.match(created.id, /^[a-f0-9-]{36}$/);
  assert.notEqual(created.id, prior.id);
  assert.ok(currentChecks >= 6, 'launch authority brackets both real session admissions');
  const rows = (await pool.query(`SELECT id,binding_state,conversation_purpose,user_id,role
    FROM secureshop_agents.agent_sessions WHERE platform_launch_id=$1
    ORDER BY conversation_purpose`, [scope.launchId])).rows;
  assert.deepEqual(rows, [
    { id: created.id, binding_state: 'active', conversation_purpose: 'secureshop_avatar_upload',
      user_id: persona.id, role: 'customer' },
    { id: prior.id, binding_state: 'active', conversation_purpose: 'secureshop_customer_chat',
      user_id: persona.id, role: 'customer' },
  ]);
  assert.deepEqual(await graph.createSession({ scope, persona }), created,
    'exact retry reuses the durable avatar-upload session');
}

async function runtimeRegistryProof(pool, { historical = false } = {}) {
  await assert.rejects(pool.query('CREATE TABLE secureshop_agents.v03_forbidden(value integer)'),
    error => error.code === '42501');
  if (!historical) assert.deepEqual(await assertBoundToolPolicyReadiness(pool), { ready: true });
  const row = (await pool.query(`SELECT
    encode(sha256(convert_to(prosrc,'UTF8')),'hex') AS guard_sha,
    EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
      AND conname=$1 AND contype='c' AND convalidated) AS successor,
    has_function_privilege(current_user,'secureshop_agents.guard_bound_tool_registry_upgrade()','EXECUTE') AS runtime_execute
    FROM pg_proc WHERE oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure`,
    [`bound_tool_registry_successor_v${historical ? 32 : 39}`])).rows[0];
  assert.deepEqual(row, { guard_sha: historical ? V32_GUARD : V39_GUARD,
    successor: true, runtime_execute: false });
}

async function upgradeRegistry(pool, scope, { wrong = false } = {}) {
  const values = [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId];
  const overrides = JSON.stringify([{ toolKey: 'audit.search_by_user', role: 'admin', allowed: true }]);
  const denials = wrong
    ? JSON.stringify([{ toolKey: 'listing.optimize_images', role: 'merchant' },
      { toolKey: 'merchant.listing_optimize_setup', role: 'customer' }])
    : JSON.stringify([{ toolKey: 'listing.optimize_images', role: 'merchant' },
      { toolKey: 'merchant.listing_optimize_setup', role: 'merchant' }]);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
      (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
       original_platform_session_id,predecessor_version,successor_version,predecessor_sha256,
       successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
      VALUES($1,$2,$3,$4,$5,31,32,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
       sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`, [...values, V31, V32, overrides, denials]);
    if (!wrong) {
      await client.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,tool_key,role,allowed)
        VALUES($1,$2,$3,$4,$5,'listing.optimize_images','merchant',false),
              ($1,$2,$3,$4,$5,'merchant.listing_optimize_setup','merchant',false)`, values);
      await client.query(`UPDATE secureshop_agents.bound_tool_policy_heads
        SET policy_version=32,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,
      [scope.launchId, V32]);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

test('0105-0106 qualify exact production migration history, v31 registry transition and runtime privileges',
  { skip: !enabled, timeout: 120000 }, async () => {
    const fresh = pools('AGENTS_FRESH', 'agents');
    const populated = pools('AGENTS_POPULATED', 'agents');
    try {
      const migrations = await readMigrations(AGENTS_DIRECTORY);
      const history = exactHistory(migrations, AGENTS_SUCCESSORS);
      const freshApplied = await migrate(fresh.migration, AGENTS_DIRECTORY);
      assert.deepEqual(freshApplied, history.names);
      assert.deepEqual(await ledger(fresh.migration), history.rows);
      assert.deepEqual(await migrate(fresh.migration, AGENTS_DIRECTORY), []);
      assert.equal((await insertPurpose(fresh.runtime, 'secureshop_listing_optimize', 1)).rows[0].conversation_purpose,
        'secureshop_listing_optimize');
      await assert.rejects(insertPurpose(fresh.runtime, 'secureshop_listing_optimize_unknown', 2),
        error => error.code === '23514');
      await assert.rejects(fresh.runtime.query(`INSERT INTO secureshop_agents.agent_sessions
        (id,user_id,role,conversation_purpose) VALUES($1,403,'merchant','secureshop_listing_optimize')`, [id(3003)]),
      error => error.code === '23514');
      await qualifyAvatarSessionAfterCustomerChat(fresh.runtime);
      await runtimeRegistryProof(fresh.runtime);

      const prefix = await preparePrefix(populated.migration, AGENTS_DIRECTORY, AGENTS_SUCCESSORS[0]);
      assert.equal(prefix.at(-1), '0104_avatar_upload_registry_guard_repair.sql');
      const prefixLedger = await ledger(populated.migration);
      const retained = (await insertPurpose(populated.runtime, 'secureshop_avatar_upload', 10)).rows[0];
      const scope = coordinates(20);
      const values = [scope.launchId, scope.scenarioId, scope.generation,
        scope.platformOwnerId, scope.platformSessionId];
      await populated.runtime.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,policy_version,enforcement_enabled,registry_sha256)
        VALUES($1,$2,$3,$4,$5,31,true,decode($6,'hex'))`, [...values, V31]);
      await populated.runtime.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,tool_key,role,allowed)
        VALUES($1,$2,$3,$4,$5,'audit.search_by_user','admin',true)`, values);
      const before = {
        session: (await populated.runtime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1', [retained.id])).rows,
        head: (await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1', [scope.launchId])).rows,
        overrides: (await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1', [scope.launchId])).rows,
      };
      assert.deepEqual(await applyOptimizeSuccessors(populated.migration, migrations), AGENTS_SUCCESSORS);
      await runtimeRegistryProof(populated.runtime, { historical: true });
      const afterOriginal = history.names.indexOf(AGENTS_SUCCESSORS[1]) + 1;
      assert.deepEqual(await ledger(populated.migration), history.rows.slice(0, afterOriginal));
      assert.deepEqual(await migrate(populated.migration, AGENTS_DIRECTORY), history.names.slice(afterOriginal));
      assert.deepEqual(await ledger(populated.migration), history.rows);
      assert.deepEqual((await ledger(populated.migration)).slice(0, prefixLedger.length), prefixLedger);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1', [retained.id])).rows, before.session);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1', [scope.launchId])).rows, before.head);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1', [scope.launchId])).rows, before.overrides);
      assert.equal((await insertPurpose(populated.runtime, 'secureshop_listing_optimize', 11)).rows[0].conversation_purpose,
        'secureshop_listing_optimize');
      await assert.rejects(upgradeRegistry(populated.runtime, scope, { wrong: true }), error => error.code === '55000');
      assert.equal((await populated.runtime.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1', [scope.launchId])).rows[0].n, 0);
      await upgradeRegistry(populated.runtime, scope);
      const head = (await populated.runtime.query(`SELECT policy_version,encode(registry_sha256,'hex') AS registry
        FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1`, [scope.launchId])).rows[0];
      assert.deepEqual(head, { policy_version: '32', registry: V32 });
      assert.equal(REGISTRY_VERSION, 39);
      assert.equal(REGISTRY_SHA256, V39);
      assert.deepEqual((await populated.runtime.query(`SELECT tool_key,role,allowed
        FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,
      [scope.launchId])).rows, [
        { tool_key: 'audit.search_by_user', role: 'admin', allowed: true },
        { tool_key: 'listing.optimize_images', role: 'merchant', allowed: false },
        { tool_key: 'merchant.listing_optimize_setup', role: 'merchant', allowed: false },
      ]);
      const receipt = (await populated.runtime.query(`SELECT predecessor_version,successor_version,
        encode(predecessor_sha256,'hex') AS predecessor,encode(successor_sha256,'hex') AS successor,
        overrides_before,added_denials FROM secureshop_agents.bound_tool_registry_upgrades
        WHERE platform_launch_id=$1`, [scope.launchId])).rows[0];
      assert.deepEqual(receipt, { predecessor_version: '31', successor_version: '32', predecessor: V31,
        successor: V32, overrides_before: JSON.parse(JSON.stringify([{ toolKey: 'audit.search_by_user', role: 'admin', allowed: true }])),
        added_denials: [{ toolKey: 'listing.optimize_images', role: 'merchant' },
          { toolKey: 'merchant.listing_optimize_setup', role: 'merchant' }] });
      assert.deepEqual(await migrate(populated.migration, AGENTS_DIRECTORY), []);
      await runtimeRegistryProof(populated.runtime);
    } finally {
      await Promise.allSettled([fresh.runtime.end(), fresh.migration.end(), populated.runtime.end(), populated.migration.end()]);
    }
  });

function execution(seed) {
  return Object.freeze({ launchId: id(4000 + seed), scenarioId: id(4100 + seed), generation: 7,
    platformOwnerId: 700 + seed, platformSessionId: 800 + seed });
}

function listingTarget(seed, mode = 'vuln') {
  const scope = execution(seed);
  const merchantId = 1000000000 + seed;
  const targetId = id(4200 + seed);
  const storage = Object.freeze({ targetId, launchId: id(4300 + seed), scenarioId: id(4400 + seed),
    generation: 2, platformOwnerId: scope.platformOwnerId, platformSessionId: 900 + seed });
  const sceneId = id(4500 + seed), grantId = id(4600 + seed);
  const target = authorizeSceneMerchant(createSceneBinding(storage, { sceneId, sceneGeneration: 4,
    grantId, execution: scope, withLease: work => work() }), merchantId);
  return Object.freeze({ scope, storage, target, targetId, merchantId, sceneId, grantId, sceneGeneration: 4,
    productId: 100 + seed, imageUrl: `https://owned.invalid/${seed}.jpg; /usr/bin/uname -n; #`, mode });
}

async function seedTarget(pool, value) {
  const s = value.storage;
  await pool.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,decode($8,'hex'))`,
  [s.targetId, s.launchId, s.scenarioId, s.generation, s.platformOwnerId,
    s.platformSessionId, value.merchantId, String(value.productId).padStart(64, '0').slice(-64)]);
  await pool.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,
     price,image_url,images,stock_quantity,status)
    VALUES($1,$2,$3,$3,decode($4,'hex'),$5,'native sibling/reset evidence',9.99,$6,$7::jsonb,1,'active')`,
  [s.targetId, value.productId, value.merchantId, '2'.repeat(64), `Product ${value.productId}`,
    value.imageUrl, JSON.stringify([value.imageUrl])]);
  await pool.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [value.grantId, value.sceneId, value.sceneGeneration, value.targetId, value.scope.launchId,
    value.scope.scenarioId, value.scope.generation, value.scope.platformOwnerId, value.scope.platformSessionId]);
}

function optimizeRaw(value, seed, mode = value.mode) {
  return Object.freeze({ scope: value.scope, persona: Object.freeze({ id: value.merchantId, role: 'merchant' }),
    personaSession: Object.freeze({ sessionId: id(4700 + seed), authorityVersion: '1' }),
    targetId: value.targetId, mode, catalogRevision: '0', request: Object.freeze({
      version: 1, action: 'optimize', operationId: id(4800 + seed), productId: value.productId,
      imageUrl: value.imageUrl, imageUrlSha256: digest(value.imageUrl), sceneId: value.sceneId,
      sceneGeneration: value.sceneGeneration, grantId: value.grantId,
    }) });
}

function authority() {
  return Object.freeze({ capture(input) {
    return Object.freeze({ binding: Object.freeze({ ...input.scope, personaId: input.personaId,
      role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion }),
    assertRemoteAdmission: async () => {}, withCrossStoreEffect: async work => work() });
  } });
}

function optimizeExecutor() {
  return createListingOptimizeExecutor({ client: Object.freeze({ async execute(wire, { assertCurrent }) {
    await assertCurrent();
    const stdout = Buffer.from(`${diagnosticHostname(wire.targetId)}\n`);
    const stderr = Buffer.from('convert unavailable\n');
    return bindDiagnosticResult(wire, { version: DIAGNOSTIC_VERSION,
      isolation: 'bwrap-system-diagnostic-v1', operationId: wire.request.operationId,
      requestSha256: diagnosticRequestDigest(wire.request), command: diagnosticCommand(wire.request),
      executed: true, exitCode: 127, signal: null, drained: true,
      stdout: stdout.toString('base64'), stderr: stderr.toString('base64'), encoding: 'base64',
      stdoutBytes: stdout.length, stderrBytes: stderr.length, stdoutSha256: digest(stdout),
      stderrSha256: digest(stderr), timedOut: false, truncated: false } );
  } }) });
}

async function completeOptimize(repository, raw) {
  const admission = prepareListingAdmission(raw);
  const receipt = await optimizeExecutor().execute({ admission, checkCurrent: async () => {} });
  const runningOptions = { eventId: randomUUID(), expectedSequence: 0, state: 'running', receipt: null };
  await repository.admit(raw);
  await repository.transition(raw, runningOptions);
  const effectOptions = { eventId: randomUUID(), expectedSequence: 1, state: 'effect_received', receipt };
  const effect = await repository.transition(raw, effectOptions);
  assert.deepEqual(await repository.transition(raw, effectOptions), effect);
  const completed = await repository.transition(raw,
    { eventId: randomUUID(), expectedSequence: 2, state: 'completed', receipt });
  assert.equal(completed.state, 'completed');
  assert.equal(completed.receipt.command, `convert ${raw.request.imageUrl} -strip -quality 82 ${raw.request.imageUrl}.opt.jpg`);
  assert.equal(completed.receipt.remoteReceipt.result.exitCode, 127);
  return completed;
}

async function snapshotOperation(pool, operationId) {
  return {
    admission: (await pool.query(`SELECT operation_id,target_id,binding_sha256,request_sha256,action,request_json,redacted_at
      FROM secureshop_review.owned_listing_admissions WHERE operation_id=$1`, [operationId])).rows,
    events: (await pool.query(`SELECT operation_id,event_id,sequence,state,payload_sha256,payload_json,redacted_at
      FROM secureshop_review.owned_listing_events WHERE operation_id=$1 ORDER BY sequence`, [operationId])).rows,
  };
}

function repository(pool, targets) {
  return createListingJournalRepository({ pool, personaAuthority: authority(), capabilityKey: Buffer.alloc(32, 7),
    resolveTarget: async binding => targets.get(binding.targetId) });
}

test('0054 qualifies fresh/populated/no-op and real optimize, fixed denial, sibling and lifecycle-reset journal behavior',
  { skip: !enabled, timeout: 120000 }, async () => {
    const fresh = pools('REVIEW_FRESH', 'review');
    const populated = pools('REVIEW_POPULATED', 'review');
    try {
      const history = exactHistory(await readMigrations(REVIEW_DIRECTORY), [REVIEW_SUCCESSOR]);
      const freshApplied = await migrate(fresh.migration, REVIEW_DIRECTORY);
      assert.deepEqual(freshApplied, history.names);
      assert.deepEqual(await ledger(fresh.migration), history.rows);
      assert.deepEqual(await migrate(fresh.migration, REVIEW_DIRECTORY), []);
      const freshGuard = (await fresh.runtime.query(`SELECT
        encode(sha256(convert_to(prosrc,'UTF8')),'hex') AS guard_sha,
        has_function_privilege(current_user,'secureshop_review.guard_owned_listing_journal()','EXECUTE') AS runtime_execute
        FROM pg_proc WHERE oid='secureshop_review.guard_owned_listing_journal()'::regprocedure`)).rows[0];
      assert.deepEqual(freshGuard, { guard_sha: REVIEW_GUARD, runtime_execute: false });
      await assert.rejects(fresh.runtime.query('CREATE TABLE secureshop_review.v03_forbidden(value integer)'),
        error => error.code === '42501');
      await assert.rejects(fresh.runtime.query(`INSERT INTO secureshop_review.owned_listing_events
        (operation_id,event_id,sequence,state) VALUES($1,$2,1,'running')`, [randomUUID(), randomUUID()]),
      error => error.code === '42501');

      const prefix = await preparePrefix(populated.migration, REVIEW_DIRECTORY, REVIEW_SUCCESSOR);
      assert.equal(prefix.at(-1), '0053_bound_upload_reconciliation_aliases.sql');
      const prefixLedger = await ledger(populated.migration);
      const legacy = listingTarget(1);
      await seedTarget(populated.runtime, legacy);
      const legacyTargets = new Map([[legacy.targetId, legacy.target]]);
      const legacyRepo = repository(populated.runtime, legacyTargets);
      const historicalRaw = Object.freeze({ scope: legacy.scope,
        persona: Object.freeze({ id: legacy.merchantId, role: 'merchant' }),
        personaSession: Object.freeze({ sessionId: id(4901), authorityVersion: '1' }),
        targetId: legacy.targetId, mode: 'vuln', catalogRevision: '0', request: Object.freeze({
          version: 1, action: 'rewrite', operationId: id(4902), title: 'Historical title', description: 'preserve me',
        }) });
      await legacyRepo.admit(historicalRaw);
      await legacyRepo.transition(historicalRaw,
        { eventId: id(4903), expectedSequence: 0, state: 'failed', receipt: { code: 'MODEL_UNAVAILABLE' } });
      const historicalBefore = await snapshotOperation(populated.runtime, historicalRaw.request.operationId);
      assert.deepEqual(await migrate(populated.migration, REVIEW_DIRECTORY),
        history.names.slice(history.names.indexOf(REVIEW_SUCCESSOR)));
      assert.deepEqual(await ledger(populated.migration), history.rows);
      assert.deepEqual((await ledger(populated.migration)).slice(0, prefixLedger.length), prefixLedger);
      assert.deepEqual(await snapshotOperation(populated.runtime, historicalRaw.request.operationId), historicalBefore);
      assert.equal((await legacyRepo.get(historicalRaw)).state, 'failed');

      const owned = listingTarget(2), sibling = listingTarget(3);
      await seedTarget(populated.runtime, owned);
      await seedTarget(populated.runtime, sibling);
      const targets = new Map([[owned.targetId, owned.target], [sibling.targetId, sibling.target]]);
      const journal = repository(populated.runtime, targets);
      const completedRaw = optimizeRaw(owned, 2);
      const deniedRaw = optimizeRaw(owned, 12, 'fixed');
      const siblingRaw = optimizeRaw(sibling, 3);
      const completed = await completeOptimize(journal, completedRaw);
      const siblingCompleted = await completeOptimize(journal, siblingRaw);
      await journal.admit(deniedRaw);
      const denial = { version: 1, operationId: deniedRaw.request.operationId,
        productId: deniedRaw.request.productId, imageUrlSha256: deniedRaw.request.imageUrlSha256,
        mode: 'fixed', code: 'LISTING_OPTIMIZE_FIXED_DENIED', dispatched: false };
      const deniedOptions = { eventId: randomUUID(), expectedSequence: 0, state: 'denied', receipt: denial };
      const denied = await journal.transition(deniedRaw, deniedOptions);
      assert.equal(denied.state, 'denied');
      assert.deepEqual(await journal.transition(deniedRaw, deniedOptions), denied);
      await assert.rejects(journal.transition(deniedRaw,
        { ...deniedOptions, state: 'running', receipt: null }), error => error.code === 'LISTING_OPERATION_CONFLICT');
      await assert.rejects(populated.runtime.query(`SELECT secureshop_review.append_owned_listing_event
        ($1,$2,4,'completed',$3,$4,$5)`, [completedRaw.request.operationId, randomUUID(),
        JSON.stringify(completed.receipt), digest(JSON.stringify(completed.receipt)), '0'.repeat(64)]),
      error => error.code === '42501');

      const siblingBefore = await snapshotOperation(populated.runtime, siblingRaw.request.operationId);
      await populated.migration.query(`UPDATE secureshop_review.product_targets
        SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=$1`, [owned.targetId]);
      const ownedRows = (await populated.runtime.query(`SELECT
        (SELECT bool_and(request_json IS NULL AND redacted_at IS NOT NULL)
          FROM secureshop_review.owned_listing_admissions WHERE target_id=$1) AS admissions_redacted,
        (SELECT bool_and(e.payload_json IS NULL AND e.redacted_at IS NOT NULL)
          FROM secureshop_review.owned_listing_events e JOIN secureshop_review.owned_listing_admissions a USING(operation_id)
          WHERE a.target_id=$1) AS events_redacted`, [owned.targetId])).rows[0];
      assert.deepEqual(ownedRows, { admissions_redacted: true, events_redacted: true });
      const cleanup = (await populated.runtime.query(`SELECT target_id,original_platform_owner_id,
        operation_count,event_count,evidence_sha256 FROM secureshop_review.owned_listing_cleanup_receipts WHERE target_id=$1`,
      [owned.targetId])).rows[0];
      assert.equal(cleanup.target_id, owned.targetId);
      assert.equal(cleanup.original_platform_owner_id, owned.scope.platformOwnerId);
      assert.equal(cleanup.operation_count, 2);
      assert.equal(cleanup.event_count, 4);
      assert.match(cleanup.evidence_sha256, /^[a-f0-9]{64}$/);
      await assert.rejects(journal.get(completedRaw), error => error.code === 'SHOP_SCENE_STALE');
      assert.deepEqual(await snapshotOperation(populated.runtime, siblingRaw.request.operationId), siblingBefore);
      assert.deepEqual(await journal.get(siblingRaw), siblingCompleted);
      assert.equal((await populated.runtime.query(`SELECT request_json IS NOT NULL AS active
        FROM secureshop_review.owned_listing_admissions WHERE operation_id=$1`, [siblingRaw.request.operationId])).rows[0].active, true);
      assert.deepEqual(await migrate(populated.migration, REVIEW_DIRECTORY), []);
    } finally {
      await Promise.allSettled([fresh.runtime.end(), fresh.migration.end(), populated.runtime.end(), populated.migration.end()]);
    }
  });
