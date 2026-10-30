'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require(
  '../../server/database/postgres/secureshopLaunchRepository');
const { createObjectiveJudgmentRepository } = require(
  '../../server/database/postgres/objectiveJudgmentRepository');

const PREFIX = 'PG_SECURESHOP_INSTANCE_CONTRIBUTION_TEST';
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'moderate_review';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}_MIGRATION_URL`] && process.env[`${PREFIX}_RUNTIME_URL`];
const sha = value => createHash('sha256').update(value).digest('hex');

function judgment(userId, binding, overrides = {}) {
  return { userId, evaluationId: randomUUID(), workshopKey: WORKSHOP,
    objectiveId: OBJECTIVE, family: 'SecureShop', scenario: 'review-moderation',
    rubricVersion: 'instance-v1', evidenceDigest: 'a'.repeat(64), runId: randomUUID(),
    mode: null, instanceScope: binding, ...overrides };
}
function verdict(input, verdictValue = 'pass') {
  return { family: input.family, scenario: input.scenario, objectiveId: input.objectiveId,
    rubricVersion: input.rubricVersion, evidenceDigest: input.evidenceDigest,
    runId: input.runId, mode: input.mode, verdict: verdictValue,
    criteria: verdictValue === 'pass'
      ? [{ id: 'observed', satisfied: true, evidenceRefs: ['tool-result'] }] : [],
    explanation: 'Fixture verifies the persistence boundary.', provider: 'fixture',
    model: 'fixture', usage: null };
}

test('native SecureShop judgments bind immutable instance contributions', {
  skip: !enabled, timeout: 30000,
}, async () => {
  const migrationUrl = new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
  const runtimeUrl = new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
  for (const url of [migrationUrl, runtimeUrl]) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);
  const migration = new Pool({ connectionString: migrationUrl.href, max: 3 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 8 });
  try {
    await initializeIdentityRepository(runtime, migration);
    await migration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal,catalog_active)
      VALUES($1,'secureshop-agent-security','SecureShop Agent Security',900,true)`, [WORKSHOP]);
    await migration.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled)
      VALUES($1,$2,'Moderate an observed review',1,true,true)`, [WORKSHOP,OBJECTIVE]);
    const draft = await fs.readFile(path.join(__dirname,
      '../../docs/modernization/drafts/secureshop-instance-objective-contributions.sql'), 'utf8');
    const preexistingHash = await bcrypt.hash('preexisting-fixture',4);
    const preexisting = (await migration.query(`INSERT INTO identity.users
      (username,email,password) VALUES($1,$2,$3) RETURNING id`,
    [`preexisting-${randomUUID().slice(0,8)}`,`${randomUUID()}@instance.invalid`,preexistingHash])).rows[0];
    await migration.query(`INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id) VALUES($1,$2,$3)`, [preexisting.id,WORKSHOP,OBJECTIVE]);
    await assert.rejects(migration.query(draft), /progress already exists without instance provenance/);
    await migration.query('DELETE FROM workshop_platform.completions WHERE user_id=$1', [preexisting.id]);
    await migration.query(draft);

    const identities = createIdentityRepository(runtime);
    const launches = createSecureShopLaunchRepository(runtime);
    const receipts = createObjectiveJudgmentRepository(runtime);
    const passwordHash = await bcrypt.hash('instance-fixture', 4);
    const makeUser = async label => identities.createUser({ username: `${label}-${randomUUID().slice(0,8)}`,
      email: `${randomUUID()}@instance.invalid`, passwordHash });
    const owner = await makeUser('instance-owner');
    const other = await makeUser('instance-other');
    const makeLaunch = async user => {
      const session = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(), expectedPasswordHash: passwordHash });
      const issued = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt: new Date(Date.now() + 3600000).toISOString() });
      return { ...issued.binding, platformOwnerId: user.id, platformSessionId: session.id };
    };
    const instanceA = await makeLaunch(owner);
    const instanceB = await makeLaunch(owner);
    const foreign = await makeLaunch(other);

    const first = judgment(owner.id, instanceA);
    await receipts.beginEvaluation(first);
    assert.equal((await receipts.recordVerdict({ userId: owner.id, evaluationId: first.evaluationId,
      result: verdict(first) })).disposition, 'awarded');
    const second = judgment(owner.id, instanceB);
    await receipts.beginEvaluation(second);
    assert.equal((await receipts.recordVerdict({ userId: owner.id, evaluationId: second.evaluationId,
      result: verdict(second) })).disposition, 'already_complete');
    const contributions = (await runtime.query(`SELECT evaluation_id,platform_launch_id,
      platform_scenario_id,platform_launch_generation FROM workshop_platform.objective_contributions
      WHERE user_id=$1 ORDER BY evaluation_id`, [owner.id])).rows;
    assert.equal(contributions.length, 2);
    assert.deepEqual(new Set(contributions.map(row => row.platform_launch_id)),
      new Set([instanceA.launchId,instanceB.launchId]));
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`, [owner.id,WORKSHOP,OBJECTIVE])).rows[0].n, 1);
    await assert.rejects(runtime.query(`INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id) VALUES($1,$2,$3)`,[other.id,WORKSHOP,OBJECTIVE]),
    {code:'42501'});
    assert.equal((await runtime.query(`UPDATE workshop_platform.completions SET completed_at=clock_timestamp()
      WHERE user_id=$1 AND workshop_key=$2`,[owner.id,WORKSHOP])).rowCount,0);
    assert.equal((await runtime.query(`DELETE FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2`,[owner.id,WORKSHOP])).rowCount,0);
    await assert.rejects(runtime.query(`INSERT INTO workshop_platform.objective_contributions
      (user_id,evaluation_id,workshop_key,objective_id,platform_launch_id,platform_scenario_id,
       platform_launch_generation,workshop_generation) SELECT user_id,evaluation_id,workshop_key,
       objective_id,platform_launch_id,platform_scenario_id,platform_launch_generation,generation
       FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2`,
    [owner.id,first.evaluationId]),{code:'42501'});
    await assert.rejects(runtime.query(
      'SELECT workshop_platform.accept_secureshop_objective_contribution($1,$2)',
      [owner.id,randomUUID()]),/authoritative passing judgment/);

    assert.equal((await receipts.recordVerdict({ userId: owner.id, evaluationId: first.evaluationId,
      result: verdict(first) })).disposition, 'awarded');
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_contributions WHERE user_id=$1', [owner.id])).rows[0].n, 2,
      'exact verdict replay cannot create a second contribution');
    await assert.rejects(receipts.beginEvaluation({ ...first, instanceScope: instanceB }),
      { code: 'IDEMPOTENCY_CONFLICT' });

    for (const outcome of ['fail','unavailable']) {
      const negative = judgment(owner.id, instanceA);
      await receipts.beginEvaluation(negative);
      const result = verdict(negative,outcome);
      if (outcome === 'unavailable') result.errorCode = 'JUDGE_TRANSPORT';
      assert.equal((await receipts.recordVerdict({ userId: owner.id,
        evaluationId: negative.evaluationId, result })).disposition, 'not_pass');
      assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_contributions WHERE user_id=$1 AND evaluation_id=$2', [owner.id,negative.evaluationId])).rows[0].n, 0);
    }

    assert.throws(() => receipts.beginEvaluation(judgment(owner.id, foreign)),
      { code: 'JUDGMENT_SCOPE_MISMATCH' });
    await assert.rejects(receipts.beginEvaluation(judgment(owner.id,
      { ...instanceA, generation: instanceA.generation + 1 })), { code: 'STALE_GENERATION' });
    await assert.rejects(receipts.beginEvaluation(judgment(owner.id,
      { ...instanceA, scenarioId: randomUUID() })), { code: 'STALE_GENERATION' });
    const staleLaunch = await makeLaunch(owner);
    const stalePending = judgment(owner.id,staleLaunch);
    await receipts.beginEvaluation(stalePending);
    await launches.beginReset({ launchId: staleLaunch.launchId,
      platformOwnerId: owner.id, platformSessionId: staleLaunch.platformSessionId,
      expectedGeneration: staleLaunch.generation, idempotencyKey: `stale-${stalePending.evaluationId}` });
    await assert.rejects(receipts.recordVerdict({ userId: owner.id,
      evaluationId: stalePending.evaluationId, result: verdict(stalePending) }),
    { code: 'STALE_GENERATION' });
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND evaluation_id=$2`, [owner.id,stalePending.evaluationId])).rows[0].n,0);

    const expiredUser = await makeUser('instance-expired');
    const expired = await makeLaunch(expiredUser);
    await migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [expired.platformSessionId]);
    await assert.rejects(receipts.beginEvaluation(judgment(expiredUser.id,expired)),
      { code: 'STALE_GENERATION' });
    const lockedUser = await makeUser('instance-locked');
    const locked = await makeLaunch(lockedUser);
    await migration.query("UPDATE identity.users SET account_locked_until=clock_timestamp()+interval '1 hour' WHERE id=$1", [lockedUser.id]);
    await assert.rejects(receipts.beginEvaluation(judgment(lockedUser.id,locked)),
      { code: 'STALE_GENERATION' });

    const packet = '{}';
    const unavailable = judgment(owner.id, instanceB, { evidenceDigest: sha(packet),
      recovery: { packet, judgeVersion: 'fixture-v1', ownerKey: 'instance-owner-key', ownerGeneration: '8' } });
    await receipts.beginEvaluation(unavailable);
    const unavailableVerdict = verdict(unavailable,'unavailable');
    unavailableVerdict.errorCode = 'JUDGE_TRANSPORT';
    await receipts.recordVerdict({ userId: owner.id, evaluationId: unavailable.evaluationId,
      result: unavailableVerdict });
    const child = await receipts.beginRetry({ userId: owner.id,
      evaluationId: unavailable.evaluationId, judgeVersion: 'fixture-v1', ownerGeneration: '8' });
    assert.deepEqual(child.receipt.instanceScope, { launchId: instanceB.launchId,
      scenarioId: instanceB.scenarioId, generation: instanceB.generation });
    const childInput = { ...unavailable, evaluationId: child.receipt.evaluationId };
    const childReceipt = await receipts.recordVerdict({ userId: owner.id,
      evaluationId: child.receipt.evaluationId, result: verdict(childInput) });
    assert.equal(childReceipt.disposition,'already_complete');
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_contributions WHERE user_id=$1 AND evaluation_id=$2', [owner.id,child.receipt.evaluationId])).rows[0].n, 1);
    assert.equal((await receipts.beginRetry({ userId: owner.id,
      evaluationId: unavailable.evaluationId, judgeVersion: 'changed-after-terminal',
      ownerGeneration: '8' })).receipt.evaluationId, child.receipt.evaluationId);

    await assert.rejects(runtime.query(`UPDATE workshop_platform.objective_judgments
      SET platform_launch_generation=platform_launch_generation+1
      WHERE user_id=$1 AND evaluation_id=$2`, [owner.id,first.evaluationId]),
    /launch scope is immutable/);
    await assert.rejects(migration.query(`UPDATE workshop_platform.objective_contributions
      SET workshop_generation=workshop_generation+1 WHERE user_id=$1 AND evaluation_id=$2`,
    [owner.id,first.evaluationId]), /contributions are immutable/);

    // Force recordVerdict to pause after authority admission. The reset must
    // wait for its owner/session/launch SHARE locks; after the verdict commits,
    // reset fences the generation. KEY SHARE would let reset cross this point.
    const raced = judgment(owner.id,await makeLaunch(owner));
    await receipts.beginEvaluation(raced);
    const barrierKey = 7319421;
    const blocker = await migration.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT pg_advisory_xact_lock($1)', [barrierKey]);
      await migration.query(`CREATE FUNCTION workshop_platform.block_fixture_verdict()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.evaluation_id='${raced.evaluationId}'::uuid THEN
            PERFORM pg_advisory_xact_lock(${barrierKey});
          END IF;
          RETURN NEW;
        END $$`);
      await migration.query(`CREATE TRIGGER block_fixture_verdict
        BEFORE UPDATE ON workshop_platform.objective_judgments
        FOR EACH ROW EXECUTE FUNCTION workshop_platform.block_fixture_verdict()`);
      const award = receipts.recordVerdict({ userId: owner.id,
        evaluationId: raced.evaluationId, result: verdict(raced) });
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const waiting = (await migration.query(`SELECT count(*)::int AS n FROM pg_locks
          WHERE locktype='advisory' AND granted=false`)).rows[0].n;
        if (waiting > 0) break;
        await new Promise(resolve => setTimeout(resolve,20));
      }
      assert.ok((await migration.query(`SELECT count(*)::int AS n FROM pg_locks
        WHERE locktype='advisory' AND granted=false`)).rows[0].n > 0,
      'verdict reached the post-authority persistence barrier');
      let resetSettled = false;
      const reset = launches.beginReset({ launchId: raced.instanceScope.launchId,
        platformOwnerId: owner.id, platformSessionId: raced.instanceScope.platformSessionId,
        expectedGeneration: raced.instanceScope.generation,
        idempotencyKey: `award-race-${raced.evaluationId}` }).finally(() => { resetSettled = true; });
      await new Promise(resolve => setTimeout(resolve,100));
      assert.equal(resetSettled,false,'reset cannot cross an admitted verdict transaction');
      await blocker.query('COMMIT');
      assert.equal((await award).disposition,'already_complete');
      const fenced = await reset;
      assert.equal(fenced.toGeneration,raced.instanceScope.generation + 1);
      assert.equal((await runtime.query(`SELECT count(*)::int AS n
        FROM workshop_platform.objective_contributions WHERE user_id=$1 AND evaluation_id=$2`,
      [owner.id,raced.evaluationId])).rows[0].n,1);
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  } finally {
    await Promise.all([runtime.end(),migration.end()]);
  }
});
