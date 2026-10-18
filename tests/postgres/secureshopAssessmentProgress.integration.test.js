'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedSecureShopAssessmentDefaults } = require('../../server/database/postgres/secureshopAssessmentSeed');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopAssessmentCatalog } = require('../../server/services/secureshopAssessmentCatalog');
const { createSecureShopAssessmentProgressRepository } = require('../../server/database/postgres/secureshopAssessmentProgressRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopRealmProgressCleanupCheckpointRepository } = require('../../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository');

const PREFIX = 'PG_SECURESHOP_ASSESSMENT_PROGRESS_';
const ENABLED = process.env.SECURESHOP_ASSESSMENT_PROGRESS_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}RUNTIME_URL`] && process.env[`${PREFIX}MIGRATION_URL`];
const OBJECTIVE = 'ss_loop_observation';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function disposableUrl(key) {
  const url = new URL(process.env[`${PREFIX}${key}`]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.password, '');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url;
}

test('native shop progress reads current same-tenant awards and reset-retired contributions',
  { skip: !ENABLED, timeout: 180000 }, async t => {
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const runtimeUrl = disposableUrl('RUNTIME_URL');
    const migrationUrl = disposableUrl('MIGRATION_URL');
    assert.equal(runtimeUrl.pathname, migrationUrl.pathname);
    assert.notEqual(runtimeUrl.username, migrationUrl.username);
    const runtime = new Pool({ connectionString: runtimeUrl.href, max: 5 });
    const migration = new Pool({ connectionString: migrationUrl.href, max: 2 });
    t.after(async () => {
      const settled = await Promise.allSettled([runtime, migration].map(pool => pool.end()));
      assert.equal(settled.filter(item => item.status === 'rejected').length, 0);
    });

    await migrate(migration, path.resolve(__dirname, '../../db/postgres/identity-migrations'));
    assert.deepEqual(await migrate(migration,
      path.resolve(__dirname, '../../db/postgres/identity-migrations')), []);
    await seedSecureShopAssessmentDefaults(migration);
    await seedSecureShopStandaloneDefaults(migration, { hashPassword: value => bcrypt.hash(value, 4) });

    const auth = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: runtime }),
      hashPassword: value => bcrypt.hash(value, 4),
    });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const suffix = randomUUID().slice(0, 8);
    const customer = await auth.register({ username: `progress_${suffix}`,
      email: `progress_${suffix}@example.invalid`, password: 'owned-progress-password', role: 'customer' });
    const sibling = await auth.register({ username: `sibling_${suffix}`,
      email: `sibling_${suffix}@example.invalid`, password: 'owned-progress-password', role: 'customer' });
    const customerExecution = await auth.establishTenantContext(customer.context);
    const siblingExecution = await auth.establishTenantContext(sibling.context);
    assert.equal(customerExecution.tenantId, siblingExecution.tenantId);
    const progress = createSecureShopAssessmentProgressRepository({ pool: runtime });
    const catalog = createSecureShopAssessmentCatalog({ pool: runtime, authService: auth });

    const initial = await progress.readSelf({ base: customer.context });
    assert.equal(initial.principalId, customer.context.principalId);
    assert.equal(initial.completedObjectives, 0);
    assert.equal(initial.objectives.some(row => row.objectiveId === OBJECTIVE), false);
    const enabled = await catalog.set(admin.context,
      { objectiveId: OBJECTIVE, enabled: true, expectedRevision: '1' });
    assert.equal(enabled.enabled, true);
    const empty = await progress.readSelf({ base: customer.context });
    assert.deepEqual(empty.objectives.filter(row => row.objectiveId === OBJECTIVE),
      [{ objectiveId: OBJECTIVE, label: 'Observe a real model selecting a tool, reading its result, and deciding what to do next', completed: false }]);
    assert.equal(empty.totalObjectives, initial.totalObjectives + 1);
    assert.equal(empty.completedObjectives, 0);
    assert.deepEqual(await progress.readLearner({ base: admin.context,
      targetPrincipalId: customer.context.principalId }), empty);

    // This is a migration/read-model fixture, not an agent or Judge run. Its
    // explicitly marked rows exercise the canonical accepted-contribution view
    // without claiming genuine model provenance or learner objective credit.
    const launches = createSecureShopLaunchRepository(runtime);
    async function issue(execution) {
      const launched = await launches.issueOrRenew({ platformOwnerId: execution.ownerId,
        platformSessionId: execution.sessionId,
        expiresAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(), shopPrincipal: execution });
      assert.ok(UUID.test(launched.binding.launchId));
      return launched.binding;
    }
    const firstLaunch = await issue(customerExecution);
    const siblingLaunch = await issue(siblingExecution);
    async function controlledContribution(identity, launch) {
      const evaluationId = randomUUID();
      const mode = (await migration.query(`SELECT generation,mode
        FROM secureshop_auth.tenant_modes WHERE tenant_id=$1 AND principal_id=$2`,
      [identity.tenantId, identity.principalId])).rows[0];
      assert.ok(mode);
      const result = JSON.stringify({ verdict: 'pass', provenance: 'controlled-native-progress-fixture',
        actualModel: false, actualJudge: false });
      await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
        (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,
         family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
         judge_version,owner_key,owner_generation,verdict,disposition,result_json,
         result_digest,evaluated_at)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','native-progress-fixture','fixture-only-v1',
          $7,$8,$9,$10,'controlled-fixture-mode','fixture-only',
          'controlled-native-progress-fixture',0,'pass','awarded',$11::jsonb,$12,clock_timestamp())`,
      [identity.tenantId, identity.principalId, evaluationId, identity.shopUserId,
        JSON.stringify({ fixture: 'controlled-native-progress-only',
          scope: { launchId: launch.launchId, generation: launch.generation } }),
        OBJECTIVE, 'a'.repeat(64), randomUUID(), mode.generation, mode.mode, result,
        createHash('sha256').update(result).digest('hex')]);
      await migration.query(`INSERT INTO secureshop_auth.assessment_completions
        (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,$4,$5)`,
      [identity.tenantId, identity.principalId, OBJECTIVE, mode.generation, evaluationId]);
      await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
        (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
      [identity.tenantId, identity.principalId, evaluationId]);
      return evaluationId;
    }
    const primaryEvaluation = await controlledContribution(customerExecution, firstLaunch);
    const siblingEvaluation = await controlledContribution(siblingExecution, siblingLaunch);
    const awarded = await progress.readSelf({ base: customer.context });
    assert.equal(awarded.completedObjectives, 1);
    assert.equal(awarded.objectives.find(row => row.objectiveId === OBJECTIVE).completed, true);
    assert.deepEqual(await progress.readLearner({ base: admin.context,
      targetPrincipalId: customer.context.principalId }), awarded);
    assert.equal((await progress.readSelf({ base: sibling.context })).completedObjectives, 1);

    const page = await progress.listLearners({ base: admin.context, limit: 2 });
    assert.equal(page.learners.length, 2);
    assert.ok(page.nextCursor !== null);
    const pageIds = new Set(page.learners.map(row => row.principalId));
    let cursor = page.nextCursor;
    let pages = 1;
    while (cursor !== null) {
      assert.ok(++pages <= 8, 'bounded pagination must terminate');
      const next = await progress.listLearners({ base: admin.context, limit: 2, cursor });
      for (const learner of next.learners) {
        assert.equal(pageIds.has(learner.principalId), false);
        pageIds.add(learner.principalId);
      }
      if (next.nextCursor !== null) assert.ok(next.nextCursor > cursor);
      cursor = next.nextCursor;
    }
    assert.ok(pageIds.has(customer.context.principalId));
    assert.ok(pageIds.has(sibling.context.principalId));
    await assert.rejects(progress.readLearner({ base: customer.context,
      targetPrincipalId: sibling.context.principalId }), { code: 'SHOP_ADMIN_REQUIRED' });

    const peerSlug = `progress_peer_${suffix}`;
    const peerId = randomUUID();
    const peerTenant = randomUUID();
    const peerUsername = `peer_${suffix}`;
    const peerPassword = 'owned-peer-password';
    const peerPrincipal = (await migration.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
      RETURNING shop_user_id`, [peerId, peerUsername, `${peerUsername}@example.invalid`,
      await bcrypt.hash(peerPassword, 4)])).rows[0];
    await migration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)`,
      [peerTenant, peerSlug]);
    await migration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [peerTenant, peerId, peerPrincipal.shop_user_id]);
    const peerAuth = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: runtime,
        executionTenantSlug: peerSlug }),
      hashPassword: value => bcrypt.hash(value, 4),
    });
    const peer = await peerAuth.login({ username: peerUsername, password: peerPassword });
    assert.equal((await createSecureShopAssessmentProgressRepository({ pool: runtime,
      executionTenantSlug: peerSlug }).readSelf({ base: peer.context })).completedObjectives, 0);
    await assert.rejects(progress.readLearner({ base: admin.context,
      targetPrincipalId: peer.context.principalId }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });

    const reset = await launches.beginReset({ launchId: firstLaunch.launchId,
      platformOwnerId: customerExecution.ownerId,
      platformSessionId: customerExecution.sessionId,
      expectedGeneration: firstLaunch.generation, idempotencyKey: randomUUID() });
    const checkpoint = await createSecureShopRealmProgressCleanupCheckpointRepository(runtime)
      .finalize(reset.resetId);
    assert.equal(checkpoint.realm, 'shop');
    assert.equal(checkpoint.checkpoint.retired_contribution_count, 1);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
    [primaryEvaluation])).rows[0].n, 0);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
    [siblingEvaluation])).rows[0].n, 1);
    const retired = await progress.readSelf({ base: customer.context });
    assert.equal(retired.completedObjectives, 0);
    assert.equal(retired.objectives.find(row => row.objectiveId === OBJECTIVE).completed, false);
    assert.equal((await progress.readSelf({ base: sibling.context })).completedObjectives, 1);
    assert.deepEqual(await progress.readLearner({ base: admin.context,
      targetPrincipalId: customer.context.principalId }), retired);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.assessment_contributions WHERE evaluation_id=$1`,
    [primaryEvaluation])).rows[0].n, 1, 'retired contribution remains immutable');

    assert.equal(await auth.logout(customer.token), true);
    await assert.rejects(progress.readSelf({ base: customer.context }), { code: 'SHOP_AUTH_INVALID' });
    await assert.rejects(progress.readLearner({ base: admin.context,
      targetPrincipalId: randomUUID() }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
    assert.equal((await progress.readSelf({ base: sibling.context })).completedObjectives, 1);
    t.diagnostic('Controlled native progress projection only; no model/Judge/browser qualification.');
  });
