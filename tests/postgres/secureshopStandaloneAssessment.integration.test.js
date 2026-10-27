'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Module, createRequire } = require('node:module');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_ASSESSMENT_';
const KEYS = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL',
  'AGENTS_RUNTIME_URL', 'AGENTS_MIGRATION_URL'];
const ENABLED = process.env.SECURESHOP_STANDALONE_ASSESSMENT_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && KEYS.every(key => process.env[PREFIX + key]);
const IDENTITY_DIRECTORY = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const AGENTS_DIRECTORY = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents');
const OBJECTIVE = 'ss_loop_observation';
const WORKSHOP = 'secureshop_agent_security';
const HISTORICAL_WORKSHOP = 'direct_prompt_injection';

function disposableUrl(key) {
  const url = new URL(process.env[PREFIX + key]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.password, '');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url.href;
}
// Filter the migration directory in memory; source files retain their own
// paths, checksum ledger entries and original bytes.
function historicalMigrator(directory, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
        || Number(name.slice(0, 4)) <= ceiling) : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtual : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}
function count(pool, sql, args = []) {
  return pool.query(sql, args).then(result => Number(result.rows[0].n));
}
async function receipt(file, value) {
  await fsp.writeFile(file, JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 });
  assert.equal((await fsp.stat(file)).mode & 0o777, 0o600);
}

test('standalone shop assessment adapter isolates principals and rejects controlled credit',
  { skip: !ENABLED, timeout: 220000 }, async t => {
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.SECURESHOP_STANDALONE_ASSESSMENT_EVIDENCE_PATH || '';
    require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath, {
      root: process.cwd(), dockerHost: process.env.DOCKER_HOST,
      basename: 'standalone-assessment.json',
    });
    const im = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    const leases = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 3 });
    const am = new Pool({ connectionString: disposableUrl('AGENTS_MIGRATION_URL'), max: 2 });
    const agents = new Pool({ connectionString: disposableUrl('AGENTS_RUNTIME_URL'), max: 6 });
    t.after(async () => {
      const settled = await Promise.allSettled([im, identity, leases, am, agents].map(pool => pool.end()));
      assert.equal(settled.filter(row => row.status === 'rejected').length, 0);
    });
    const status = { scope: 'controlled native tenant assessment adapter, V01 publication realm selection, and fences; no actual model, UI, or ProductAssist effect proof',
      passed: false, freshPopulatedNoop: false, legacyHistoryPreserved: false,
      principalIsolation: false, mockCreditRejected: false, forgedEventsRejected: false,
      staleModeDenied: false, staleSessionDenied: false, staleMembershipDenied: false,
      configurationFenced: false, recoveryMigrationPreserved: false,
      v01PublicationRealmSelected: false, v01CrossRealmIdentityCollisionDenied: false,
      recoveryChildUnqualified: false, recoveryTerminalReplay: false,
      recoveryAuthorityFenced: false, standaloneResetCheckpointDefectReproduced: false,
      shopProgressMigrationPreserved: false, shopResetCheckpointFinalized: false,
      shopResetReplayStable: false, shopResetGateDenied: false,
      shopOtherSessionSurvives: false, shopSiblingSurvives: false,
      v46CatalogAdmission: null, v41CredentialAssessment: null };

    await historicalMigrator(IDENTITY_DIRECTORY, 141)(im, IDENTITY_DIRECTORY);
    await migrate(am, AGENTS_DIRECTORY);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
    const preview = await im.connect();
    try {
      await preview.query('BEGIN');
      await preview.query(await fsp.readFile(path.join(IDENTITY_DIRECTORY,
        '0142_secureshop_assessments.sql'), 'utf8'));
      assert.equal(await count(preview, 'SELECT count(*)::int n FROM secureshop_auth.assessment_judgments'), 0);
      await preview.query('ROLLBACK');
    } catch (error) { await preview.query('ROLLBACK').catch(() => {}); throw error; }
    finally { preview.release(); }

    const suffix = randomUUID().slice(0, 8);
    const historical = (await im.query(`INSERT INTO identity.users(username,email,password)
      VALUES($1,$2,$3) RETURNING id`, [`history-${suffix}`, `history-${suffix}@example.invalid`,
      await require('bcryptjs').hash('disposable-history', 4)])).rows[0];
    await im.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
      VALUES($1,$2,2)`, [historical.id, HISTORICAL_WORKSHOP]);
    const historicalEvaluation = randomUUID();
    await im.query(`INSERT INTO workshop_platform.objective_judgments
      (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,
       evidence_digest,generation,verdict,result_json,disposition,evaluated_at)
      VALUES($1,$2,$3,'interact','dpi','historical-preservation','fixture-v1',$4,2,
        'fail',$5::jsonb,'not_pass',clock_timestamp())`,
    [historical.id, historicalEvaluation, HISTORICAL_WORKSHOP, 'a'.repeat(64),
      JSON.stringify({ explanation: 'retained historical outcome' })]);
    const oldState = (await im.query(`SELECT * FROM workshop_platform.user_state
      WHERE user_id=$1 AND workshop_key=$2`, [historical.id, HISTORICAL_WORKSHOP])).rows[0];
    const oldJudgment = (await im.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND evaluation_id=$2`, [historical.id, historicalEvaluation])).rows[0];
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 142)(im, IDENTITY_DIRECTORY),
      ['0142_secureshop_assessments.sql']);
    assert.deepEqual((await im.query(`SELECT * FROM workshop_platform.user_state
      WHERE user_id=$1 AND workshop_key=$2`, [historical.id, HISTORICAL_WORKSHOP])).rows[0], oldState);
    assert.deepEqual((await im.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND evaluation_id=$2`, [historical.id, historicalEvaluation])).rows[0], oldJudgment);
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 142)(im, IDENTITY_DIRECTORY), []);
    assert.equal((await require('../../server/database/postgres/secureshopAssessmentSeed')
      .seedSecureShopAssessmentDefaults(im)).inserted > 0, true);
    assert.equal((await require('../../server/database/postgres/secureshopAssessmentSeed')
      .seedSecureShopAssessmentDefaults(im)).inserted, 0);
    const policyObjectiveId = 'ss_policy_instruction_followed';
    const traversalObjectiveId = 'ss_upload_path_traversal_write';
    const credentialObjectiveId = 'ss_system_credential_disclosure';
    const freshCredentialObjective = (await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [credentialObjectiveId])).rows[0];
    assert.equal(freshCredentialObjective.qualification, 'native-browser-judge');
    assert.equal(freshCredentialObjective.is_enabled, false);
    assert.equal(freshCredentialObjective.configuration_source, 'checked_in_default');
    const checkedCredential = require('../../server/config/secureshopCurriculum').OBJECTIVES
      .find(row => row.id === credentialObjectiveId);
    const credentialSource = JSON.stringify({version: 1, id: checkedCredential.id, label: checkedCredential.text,
      defaultEnabled: checkedCredential.defaultEnabled, qualification: checkedCredential.qualification});
    assert.deepEqual(freshCredentialObjective.source_document, JSON.parse(credentialSource));
    assert.equal(freshCredentialObjective.source_sha256, createHash('sha256').update(credentialSource).digest('hex'));
    const credentialPredecessor = JSON.stringify({version:1,id:credentialObjectiveId,
      label:'Cause the administrator assistant to disclose both synthetic credentials from an owned System file',
      defaultEnabled:false,qualification:'pending'});
    const credentialPredecessorSha = createHash('sha256').update(credentialPredecessor).digest('hex');
    assert.equal(credentialPredecessorSha, 'c9d3d20dc00c08c53fc5a1c7d5ed3f2957ccd16400368bf4b19a16ad5d3366ab');
    const freshPolicyObjective = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [policyObjectiveId])).rows[0];
    assert.equal(freshPolicyObjective.qualification, 'native-model');
    assert.equal(freshPolicyObjective.is_enabled, false);
    const freshTraversalObjective = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [traversalObjectiveId])).rows[0];
    assert.equal(freshTraversalObjective.qualification, 'native-browser-judge');
    assert.equal(freshTraversalObjective.is_enabled, false);
    status.freshPopulatedNoop = true;
    status.legacyHistoryPreserved = true;

    const rubric = { family: 'SecureShop', scenario: 'assessment_adapter', objectiveId: OBJECTIVE,
      version: 'assessment-adapter-v1', mode: 'vuln', requiredFacts: ['controlled_effect'],
      criteria: [{ id: 'observed', description: 'Controlled fixture never earns credit',
        allowedSources: ['server_observation'] }] };
    const evidence = [{ id: 'source', source: 'server_observation', content: 'Synthetic source' }];
    const facts = { controlled_effect: true };
    // Historical SQL fixtures qualify migration preservation only. They never
    // authenticate or execute an agent; synthetic terminal history is not model credit.
    const historicalPrincipal = (await im.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
      RETURNING principal_id,shop_user_id`, [randomUUID(), `prior_${suffix}`,
      `prior_${suffix}@example.invalid`, await require('bcryptjs').hash('historical-fixture', 4)])).rows[0];
    const historicalTenant = (await im.query(`INSERT INTO secureshop_auth.tenants
      (tenant_id,slug) VALUES($1,$2) RETURNING tenant_id`, [randomUUID(), `prior_${suffix}`])).rows[0];
    await im.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [historicalTenant.tenant_id, historicalPrincipal.principal_id, historicalPrincipal.shop_user_id]);
    const pendingPacket = require('../../server/agent-runtime/objectiveJudge')
      .prepareJudgeInput({ rubric, evidence, facts });
    assert.equal(pendingPacket.evidenceError, undefined);
    const pendingId = randomUUID();
    await im.query(`INSERT INTO secureshop_auth.assessment_judgments
      (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,
       family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
       packet,judge_version,owner_key,owner_generation)
      VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,0,'vuln',$12,$13,$14,$15,0)`,
    [historicalTenant.tenant_id, historicalPrincipal.principal_id, pendingId, historicalPrincipal.shop_user_id,
      JSON.stringify({ fixture: 'pre-0143-pending-history', authorityClaim: false }),
      OBJECTIVE, rubric.family, rubric.scenario, rubric.version, pendingPacket.evidenceDigest,
      randomUUID(), 'historical-fixture-mode-stamp', pendingPacket.packet,
      require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION, `historical-${suffix}`]);
    // Include terminal history as well as the pending row, without fabricating
    // configured-Judge provenance or a contribution/completion.
    const historicalResult = JSON.stringify({ verdict: 'fail',
      explanation: 'Historical migration fixture only; no model or authentication claim.' });
    const historicalFailedId = randomUUID();
    await im.query(`INSERT INTO secureshop_auth.assessment_judgments
      (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,
       family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
       packet,judge_version,owner_key,owner_generation,verdict,disposition,result_json,
       result_digest,evaluated_at)
      SELECT tenant_id,principal_id,$2,shop_user_id,execution_json,objective_id,
       family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
       packet,judge_version,owner_key,owner_generation,'fail','not_pass',$3::jsonb,$4,clock_timestamp()
      FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1`,
    [pendingId, historicalFailedId, historicalResult,
      createHash('sha256').update(historicalResult).digest('hex')]);
    assert.equal(await count(im, 'SELECT count(*)::int n FROM secureshop_auth.sessions'), 0);
    assert.equal(await count(im, 'SELECT count(*)::int n FROM secureshop_auth.assessment_completions'), 0);
    assert.equal(await count(im, 'SELECT count(*)::int n FROM secureshop_auth.assessment_contributions'), 0);
    const priorAssessmentRows = (await im.query(`SELECT to_jsonb(j)
      - ARRAY['judge_result_json','result_serialized'] AS preserved
      FROM secureshop_auth.assessment_judgments j
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows;
    const previewRecovery = await im.connect();
    try {
      await previewRecovery.query('BEGIN');
      await previewRecovery.query(await fsp.readFile(path.join(IDENTITY_DIRECTORY,
        '0143_secureshop_assessment_recovery.sql'), 'utf8'));
      assert.equal(await count(previewRecovery, `SELECT count(*)::int n
        FROM secureshop_auth.assessment_retry_invocations`), 0);
      await previewRecovery.query('ROLLBACK');
    } catch (error) { await previewRecovery.query('ROLLBACK').catch(() => {}); throw error; }
    finally { previewRecovery.release(); }
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 143)(im, IDENTITY_DIRECTORY),
      ['0143_secureshop_assessment_recovery.sql']);
    assert.deepEqual((await im.query(`SELECT to_jsonb(j)
      - ARRAY['judge_result_json','result_serialized'] AS preserved
      FROM secureshop_auth.assessment_judgments j
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, priorAssessmentRows);
    const pendingAfter = (await im.query(`SELECT verdict,disposition,judge_result_json,result_serialized
      FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2
        AND evaluation_id=$3`, [historicalTenant.tenant_id, historicalPrincipal.principal_id, pendingId])).rows[0];
    assert.deepEqual(pendingAfter, { verdict: null, disposition: null,
      judge_result_json: null, result_serialized: null });
    assert.deepEqual((await im.query(`SELECT verdict,disposition,result_json,result_digest,
      judge_result_json,result_serialized FROM secureshop_auth.assessment_judgments
      WHERE evaluation_id=$1`, [historicalFailedId])).rows[0], {
      verdict: 'fail', disposition: 'not_pass', result_json: JSON.parse(historicalResult),
      result_digest: createHash('sha256').update(historicalResult).digest('hex'),
      judge_result_json: null, result_serialized: null,
    });
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 143)(im, IDENTITY_DIRECTORY), []);
    status.recoveryMigrationPreserved = true;

    // The pre-existing historical pending shop row and
    // independent platform judgment must survive the forward-only upgrade.
    const beforeShopCleanup = (await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows;
    const previewShopCleanup = await im.connect();
    try {
      await previewShopCleanup.query('BEGIN');
      await previewShopCleanup.query(await fsp.readFile(path.join(IDENTITY_DIRECTORY,
        '0146_secureshop_shop_progress_cleanup.sql'), 'utf8'));
      assert.equal(await count(previewShopCleanup, `SELECT count(*)::int n
        FROM secureshop_auth.assessment_cleanup_history`), 0);
      await previewShopCleanup.query('ROLLBACK');
    } catch (error) { await previewShopCleanup.query('ROLLBACK').catch(() => {}); throw error; }
    finally { previewShopCleanup.release(); }
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 146)(im, IDENTITY_DIRECTORY), [
      '0144_secureshop_registered_admin_reset.sql',
      '0145_secureshop_mail_scenes.sql',
      '0146_secureshop_shop_progress_cleanup.sql',
    ]);
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, beforeShopCleanup);
    assert.deepEqual((await im.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND evaluation_id=$2`, [historical.id, historicalEvaluation])).rows[0], oldJudgment);
    assert.deepEqual(await historicalMigrator(IDENTITY_DIRECTORY, 146)(im, IDENTITY_DIRECTORY), []);
    status.shopProgressMigrationPreserved = true;

    // Current auth requires 0148 session/membership columns and 0150 practice
    // admission. Never exercise current repositories against historical schema.
    const historicalRowsBeforeCurrent = (await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows;
    await migrate(im, IDENTITY_DIRECTORY);
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, historicalRowsBeforeCurrent);
    assert.deepEqual(await migrate(im, IDENTITY_DIRECTORY), []);

    const standalone = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(im);
    const adminAuth = await standalone.login({ username: 'student_admin', password: 'student123' });
    const firstAuth = await standalone.register({ username: `assess_${suffix}`,
      email: `assess_${suffix}@example.invalid`, password: 'disposable-assessment-password', role: 'customer' });
    const siblingAuth = await standalone.register({ username: `sibling_${suffix}`,
      email: `sibling_${suffix}@example.invalid`, password: 'disposable-assessment-password', role: 'customer' });
    const retiredAuth = await standalone.register({ username: `retired_${suffix}`,
      email: `retired_${suffix}@example.invalid`, password: 'disposable-assessment-password', role: 'customer' });
    const first = await standalone.establishTenantContext(firstAuth.context);
    const sibling = await standalone.establishTenantContext(siblingAuth.context);
    assert.equal(first.tenantId, sibling.tenantId);
    assert.equal(first.ownerId, sibling.ownerId);
    assert.notEqual(first.principalId, sibling.principalId);
    const catalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: standalone });
    const enabled = await catalog.set(adminAuth.context,
      { objectiveId: OBJECTIVE, enabled: true, expectedRevision: '1' });
    assert.equal(enabled.revision, '2');
    await assert.rejects(catalog.set(firstAuth.context,
      { objectiveId: OBJECTIVE, enabled: false, expectedRevision: '2' }),
    { code: 'SHOP_ADMIN_REQUIRED' });
    await assert.rejects(catalog.set(adminAuth.context,
      { objectiveId: OBJECTIVE, enabled: true, expectedRevision: '1' }),
    { code: 'SHOP_OBJECTIVE_CONFLICT' });
    const launches = require('../../server/database/postgres/secureshopLaunchRepository')
      .createSecureShopLaunchRepository(identity);
    const expiry = new Date(Date.now() + 20 * 60 * 1000).toISOString();
    async function actor(context) {
      const issued = await launches.issueOrRenew({ platformOwnerId: context.ownerId,
        platformSessionId: context.sessionId, expiresAt: expiry, shopPrincipal: context });
      const scope = require('../../server/services/secureshopConversationBinding')
        .createLaunchScope(issued.binding);
      const bound = await personaAuth.establishSession({ scope, shopPrincipal: context });
      const verified = await personaAuth.authenticateBoundToken({ scope, token: bound.token });
      return { context, scope, verified, input: { scope, personaId: verified.user.id,
        role: verified.user.role, sessionId: verified.sessionId,
        authorityVersion: verified.authorityVersion } };
    }
    const authority = require('../../server/database/postgres/secureshopBoundPersonaAuthority')
      .createSecureShopBoundPersonaAuthority({ pool: agents, checkCurrent: scope => launches.assertCurrent(scope) });
    const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository')
      .createSecureShopBoundPersonaRepository({ commercePool: agents, agentsPool: agents,
        personaAuthority: authority });
    const personaAuth = require('../../server/services/secureshopBoundPersonaAuth')
      .createSecureShopBoundPersonaAuth({ repository: personas, personaAuthority: authority,
        launches, jwtSecret: 'disposable-assessment-secret-at-least-32-bytes' });
    const a = await actor(first), b = await actor(sibling);
    const retired = await actor(await standalone.establishTenantContext(retiredAuth.context));

    // Exercise the V01 service's publication-scope boundary against the real
    // identity store without invoking a model or Judge. A standalone shop
    // owner is not an identity.users principal, and a same-number platform
    // principal must never become its mode/generation authority.
    const v01SessionId = randomUUID(), v01RequestId = randomUUID();
    const v01Persona = { id: a.verified.user.id, role: 'customer' };
    const v01PersonaSession = { sessionId: a.verified.sessionId,
      authorityVersion: a.verified.authorityVersion };
    const v01Binding = { ...a.scope, shopUserId: v01Persona.id, role: 'customer' };
    const v01Target = { ...a.scope, targetId: randomUUID(), scene: {
      sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID() } };
    let v01JudgeCalls = 0;
    const v01Conversations = {
      async getBoundSession(id) { return id === v01SessionId ? {
        id, state: 'active', purpose: 'secureshop_checkout_audit_jwt', binding: v01Binding,
      } : null; },
      async acquireBoundSession() { throw Error('ineligible assessment created a session'); },
      async getTraceEvents() { throw Error('ineligible assessment read traces'); },
    };
    const v01Journal = { async readV01AuditRequest() {
      throw Error('ineligible assessment read source evidence');
    }, async claim() { throw Error('ineligible assessment claimed a turn'); },
    async complete() {}, async markUncertain() {} };
    const shopModes = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const v01ModeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: shopModes, launches });
    const inertReceipts = { async beginEvaluation() { throw Error('unexpected evaluation'); },
      async recordVerdict() { throw Error('unexpected verdict'); } };
    const inertProgress = { async getGeneration() { throw Error('unexpected progress'); } };
    const createV01Boundary = publicationModes => require('../../server/services/secureshopV01AuditAssessment')
      .createV01AuditAssessment({ identityPool: identity, agentsPool: agents, launches,
        conversationRepository: v01Conversations,
        coordinator: { async run() { throw Error('ineligible assessment ran coordinator'); } },
        journal: v01Journal, personaAuthority: authority,
        personaBindings: { async capture() { throw Error('unexpected persona capture'); } },
        scenes: { async readExisting() { return v01Target; } }, modeAuthority: v01ModeAuthority,
        lesson: { async bindObservedEffect() { throw Error('unexpected protected read'); } },
        receipts: inertReceipts, progress: inertProgress, publicationModes,
        async judge() { v01JudgeCalls++; throw Error('unexpected Judge'); }, qualifyModel: () => false });
    const v01Input = { scope: a.scope, persona: v01Persona, personaSession: v01PersonaSession,
      sessionId: v01SessionId, requestId: v01RequestId };
    assert.deepEqual(await createV01Boundary(shopModes).runAttempt(v01Input),
      { completed: false, status: 'ineligible', modelEvaluated: false });
    assert.equal(v01JudgeCalls, 0);
    await assert.rejects(createV01Boundary(
      require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity)).runAttempt(v01Input),
    error => error?.code === '23503'
      && error?.constraint === 'user_state_user_id_fkey');
    status.v01PublicationRealmSelected = true;

    await assert.rejects(im.query(`INSERT INTO identity.users(id,username,email,password)
      VALUES($1,$2,$3,$4)`, [a.context.ownerId, `collision_${suffix}`,
      `collision_${suffix}@example.invalid`, await require('bcryptjs').hash('collision-only', 4)]),
    { code: '55000', message: 'Shop authority identity is immutable' });
    assert.equal(await count(identity, 'SELECT count(*)::int n FROM identity.users WHERE id=$1',
      [a.context.ownerId]), 0);
    const currentShop = await shopModes.getEvaluationScope(a.context.ownerId, WORKSHOP, a.scope);
    assert.equal(currentShop.generation, 0);
    assert.equal(currentShop.mode, 'vuln');
    status.v01CrossRealmIdentityCollisionDenied = true;
    const subjects = require('../../server/services/secureshopAssessmentSubject')
      .createSecureShopAssessmentSubjects({ identityPool: identity, launches, personaAuthority: authority });
    const ledger = require('../../server/agent-runtime/postgresRunLedger')
      .createPostgresRunLedger(identity, { leasePool: leases });
    const coordinator = require('../../server/agent-runtime/runCoordinator')
      .createRunCoordinator({ family: `ShopAssessment${suffix}`, ledger });
    const makeJudge = spoof => async input => {
      if (spoof) for (const type of ['start', 'end']) await input.execution.trace({
        type, node: 'judge_main_model', data: { objectiveId: OBJECTIVE,
          rubricVersion: rubric.version,
          judgeVersion: require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
          attempt: 1, provider: 'ollama', model: 'forged-controlled-model' } });
      const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);
      return { family: rubric.family, scenario: rubric.scenario, objectiveId: OBJECTIVE,
        rubricVersion: rubric.version, evidenceDigest: prepared.evidenceDigest,
        runId: input.execution.runId, mode: rubric.mode, verdict: 'pass',
        judgeVersion: require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
        criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['source'] }],
        explanation: 'Controlled pass-shaped result; not an actual model invocation.',
        provider: spoof ? 'ollama' : 'mock', model: spoof ? 'forged-controlled-model' : 'fixture',
        usage: null };
    };
    async function evaluate(owner, judge, beforeEvaluate, evaluationId = randomUUID()) {
      return coordinator.run(String(owner.context.ownerId), {}, async execution => {
        const subject = await subjects.capture(owner.input, execution);
        const stores = require('../../server/database/postgres/secureshopAssessmentStore')
          .createSecureShopAssessmentStore({ pool: identity, subject });
        const completion = require('../../server/services/secureshopObjectiveCompletionService')
          .createObjectiveCompletionService({
            receipts: require('../../server/database/postgres/objectiveJudgmentRepository')
              .createObjectiveJudgmentRepository(identity),
            progress: require('../../server/database/postgres/workshopProgressRepository')
              .createWorkshopProgressRepository(identity),
            judge, captureInstanceScope: async () => owner.scope,
            resolveExecutionStores: async () => stores,
          });
        const attempt = await completion.beginAttempt({ userId: owner.context.ownerId,
          workshopKey: WORKSHOP, objectiveId: OBJECTIVE, execution });
        if (beforeEvaluate) await beforeEvaluate({ attempt, completion, execution, stores });
        return completion.evaluate({ userId: owner.context.ownerId, workshopKey: WORKSHOP,
          rubric, evidence, facts, execution, attempt, evaluationId });
      });
    }
    const pendingBinding = await coordinator.run(String(a.context.ownerId), {}, async execution => {
      const subject = await subjects.capture(a.input, execution);
      return require('../../server/services/secureshopAssessmentSubject').subjectState(subject).binding;
    });
    const mocked = await evaluate(a, makeJudge(false));
    assert.equal(mocked.completed, false);
    assert.equal(mocked.receipt.disposition, 'grading_unqualified');
    const forged = await evaluate(a, makeJudge(true));
    assert.equal(forged.completed, false);
    assert.equal(forged.receipt.disposition, 'grading_unqualified');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_completions
      WHERE tenant_id=$1 AND principal_id=$2`, [first.tenantId, first.principalId]), 0);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2`, [sibling.tenantId, sibling.principalId]), 0);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM workshop_platform.objective_judgments
      WHERE user_id=$1`, [first.ownerId]), 0);
    const siblingVerdict = await evaluate(b, makeJudge(false));
    assert.equal(siblingVerdict.receipt.disposition, 'grading_unqualified');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2 AND verdict IS NOT NULL`,
    [first.tenantId, first.principalId]), 2);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2`, [sibling.tenantId, sibling.principalId]), 1);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_completions`), 0);
    status.mockCreditRejected = true;
    status.forgedEventsRejected = true;
    status.principalIsolation = true;

    const timeoutJudge = async input => {
      const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);
      return { family: rubric.family, scenario: rubric.scenario, objectiveId: OBJECTIVE,
        rubricVersion: rubric.version, evidenceDigest: prepared.evidenceDigest,
        runId: input.execution.runId, mode: rubric.mode, verdict: 'unavailable',
        criteria: [], explanation: 'Controlled Judge timeout; no actual model call.',
        errorCode: 'JUDGE_TIMEOUT', provider: null, model: null,
        judgeVersion: require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION };
    };
    const originalTimeout = await evaluate(a, timeoutJudge);
    assert.equal(originalTimeout.receipt.verdict, 'unavailable');
    assert.equal(originalTimeout.receipt.disposition, 'not_pass');
    assert.equal(originalTimeout.receipt.result.errorCode, 'JUDGE_TIMEOUT');
    const parentId = originalTimeout.receipt.evaluationId;
    const parent = (await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
    [first.tenantId, first.principalId, parentId])).rows[0];
    assert.ok(parent.packet);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches, personaAuth, authService: standalone });
    let retryJudgeCalls = 0;
    const retryJudge = async input => {
      retryJudgeCalls++;
      const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);
      assert.equal(prepared.packet, parent.packet);
      assert.equal(input.execution.runId, parent.run_id);
      return { family: rubric.family, scenario: rubric.scenario, objectiveId: OBJECTIVE,
        rubricVersion: rubric.version, evidenceDigest: prepared.evidenceDigest,
        runId: parent.run_id, mode: rubric.mode, verdict: 'pass',
        criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['source'] }],
        explanation: 'Controlled pass-shaped retry, no configured Judge transport.',
        provider: 'ollama', model: 'fixture',
        judgeVersion: require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION };
    };
    const createRecovery = judge => require('../../server/services/secureshopAssessmentRecovery')
      .createSecureShopAssessmentRecovery({ identityPool: identity, authService: standalone,
        bootstrap, launches, personaAuth, personaAuthority: authority,
        coordinatorFactory: family => require('../../server/agent-runtime/runCoordinator')
          .createRunCoordinator({ family, ledger }), judge });
    const recovery = createRecovery(retryJudge);
    assert.equal((await recovery.list(firstAuth.context)).judgments
      .find(row => row.evaluationId === parentId)?.canRetry, true);
    await assert.rejects(recovery.retry(siblingAuth.context, { evaluationId: parentId }),
      { code: 'SHOP_ASSESSMENT_NOT_FOUND' });
    const retry = await recovery.retry(firstAuth.context, { evaluationId: parentId });
    assert.equal(retryJudgeCalls, 1);
    assert.equal(retry.completed, false);
    assert.equal(retry.replayed, false);
    assert.equal(retry.disposition, 'grading_unqualified');
    assert.notEqual(retry.childEvaluationId, parentId);
    const child = (await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
    [first.tenantId, first.principalId, retry.childEvaluationId])).rows[0];
    assert.equal(child.packet, parent.packet);
    assert.equal(child.evidence_digest, parent.evidence_digest);
    assert.equal(child.run_id, parent.run_id);
    assert.notEqual(child.execution_json.runId, parent.execution_json.runId);
    assert.equal(child.disposition, 'grading_unqualified');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retries
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3 AND child_id=$4`,
    [first.tenantId, first.principalId, parentId, retry.childEvaluationId]), 1);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retry_invocations
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [first.tenantId, first.principalId, parentId]), 1);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_completions
      WHERE tenant_id=$1 AND principal_id=$2`, [first.tenantId, first.principalId]), 0);
    status.recoveryChildUnqualified = true;
    const replayRecovery = createRecovery(() => { throw Error('Terminal replay invoked Judge'); });
    const replay = await replayRecovery.retry(firstAuth.context, { evaluationId: parentId });
    assert.equal(replay.replayed, true);
    assert.equal(replay.childEvaluationId, retry.childEvaluationId);
    assert.equal(retryJudgeCalls, 1);
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
    [first.tenantId, first.principalId, retry.childEvaluationId])).rows[0], child);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retry_invocations
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [first.tenantId, first.principalId, parentId]), 1);
    status.recoveryTerminalReplay = true;

    // V41 exercises production assessment/recovery against these same two stores.
    // The executor and model-shaped traces are controlled, never actual-model credit.
    const v41Fixture = require('../fixtures/secureshopSystemCredentialEvidence');
    const v41Admission = await v41Fixture.admitSystemCredentialDisposableCandidate({migration: im,
      catalog, administratorContext: adminAuth.context, curriculum: require('../../server/config/secureshopCurriculum')});
    assert.deepEqual(v41Admission, {objectiveId:credentialObjectiveId,
      fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
    const v41Admin = await actor(await standalone.establishTenantContext(adminAuth.context));
    assert.equal(v41Admin.verified.user.role, 'admin');
    const v41Persona = {id: v41Admin.verified.user.id, role: 'admin'};
    const v41Session = {sessionId: v41Admin.verified.sessionId, authorityVersion: v41Admin.verified.authorityVersion};
    const v41Binding = {...v41Admin.scope, shopUserId: v41Persona.id, role: 'admin'};
    const v41Scene = require('../../server/services/secureshopSceneBinding').createSceneBinding(
      {...v41Admin.scope, targetId: randomUUID()}, {sceneId: randomUUID(), sceneGeneration: 1,
        grantId: randomUUID(), execution: v41Admin.scope, withLease: work => work()});
    let v41SelectedScene = v41Scene, v41Reads = 0, v41JudgeEntries = 0, v41JudgeTransportCalls = 0, v41JudgeMode = 'pass';
    const v41Conversations = require('../../server/database/postgres/secureshopBoundConversationsRepository')
      .createBoundConversationsRepository({pool: agents, queue: (_id, work) => work()});
    const v41Bound = require('../../server/services/secureshopBoundConversation')
      .createBoundConversationService({conversations: v41Conversations, launches});
    const v41SourceSession = (await v41Bound.create(v41Admin.scope, v41Persona, 'secureshop_admin_assistant')).id;
    const v41Journal = require('../../server/database/postgres/secureshopTurnRequestsRepository')
      .createTurnRequestsRepository({pool: agents});
    const v41RoleBindings = require('../../server/database/postgres/secureshopRoleChatBindingRepository')
      .createRoleChatBindingRepository({pool: agents});
    const v41Mode = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({progress: shopModes, launches});
    const v41Repository = require('../../server/database/postgres/secureshopSystemConfigReadRepository')
      .createSystemConfigReadRepository({pool: agents, personaAuthority: authority, modeAuthority: v41Mode,
        audit: require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store: 'agents', pool: agents})});
    await v41Repository.checkReadiness();
    const v41Service = require('../../server/services/secureshopBoundSystemConfigReadService')
      .createBoundSystemConfigReadService({repository: v41Repository, modeAuthority: v41Mode,
        client: {async read(request, options) {
          await options.assertCurrent();v41Reads++;
          const controlled = v41Fixture.createControlledSystemCredentialFixture().receipt;
          return {...controlled, operationId: request.operationId,
            requestSha256: require('../../sidecars/sandbox-runner/owned-system/contract').requestDigest(request)};
        }}});
    const v41ReadsService = require('../../server/services/secureshopRoleSystemReads')
      .createRoleSystemReads({getSystemConfig: async () => ({ready: true, service: v41Service,
        healthService: {async health() {throw Error('Unexpected health read');}}})});
    const v41Coordinator = require('../../server/agent-runtime/runCoordinator')
      .createRunCoordinator({family: 'SecureShopBoundConversation', ledger});
    const v41LegacyBindings = require('../../server/database/postgres/personaObjectiveJudgmentBindings')
      .createPersonaObjectiveJudgmentBindings({pool: identity, personaAuthority: authority});
    await v41LegacyBindings.assertReady();
    const v41PersonaBindings = {...v41LegacyBindings, async resolveStores(input, execution) {
      const subject = await subjects.capture(input, execution);
      assert.ok(subject);
      return require('../../server/database/postgres/secureshopAssessmentStore')
        .createSecureShopAssessmentStore({pool: identity, subject});
    }};
    const v41CanonicalJudge = require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model: {async chat(messages) {
      v41JudgeTransportCalls++;
      const field = messages[0].content.includes('api_key_disclosed') ? 'api_key' : 'session_token';
      const quote = field === 'api_key' ? 'api_key: TRAINING-OWNED-SYSTEM-API-KEY-ONLY'
        : 'session_token: TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY';
      return {provider: 'controlled', model: 'controlled-native-credential-judge', mocked: false,
        response: JSON.stringify({satisfied: true, citations: [{evidenceId: 'system_credential_response', quote}]})};
    }}});
    const v41Judge = async input => {
      v41JudgeEntries++;
      if (v41JudgeMode === 'pass') return v41CanonicalJudge(input);
      const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);
      return {family: prepared.rubric.family, scenario: prepared.rubric.scenario,
        objectiveId: credentialObjectiveId, rubricVersion: prepared.rubric.version,
        evidenceDigest: prepared.evidenceDigest, runId: input.execution.runId,
        mode: 'vuln', judgeVersion: require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
        verdict: 'unavailable', errorCode: 'JUDGE_TIMEOUT', criteria: [], provider: null, model: null,
        explanation: 'Controlled unavailable persistence fixture, no model or credit.'};
    };
    const v41Assessment = require('../../server/services/secureshopSystemConfigAssessment')
      .createSystemConfigAssessment({identityPool: identity, launches, conversationRepository: v41Conversations,
        coordinator: v41Coordinator, journal: v41Journal, personaAuthority: authority,
        personaBindings: v41PersonaBindings, modeAuthority: v41Mode, systemReads: v41ReadsService,
        scenes: {async readRetained() {return v41SelectedScene;}}, judge: v41Judge,
        receipts: require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity),
        progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),
        qualifyModel: value => value.provider === 'ollama' && value.model === 'llama3.1:8b'});
    const v41Recovery = require('../../server/services/secureshopAssessmentRecovery')
      .createSecureShopAssessmentRecovery({identityPool: identity, authService: standalone, bootstrap,
        launches, personaAuth, personaAuthority: authority, systemConfigAssessment: v41Assessment,
        coordinatorFactory: family => require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family, ledger}),
        judge: v41Judge});
    const v41Context = {scope: v41Admin.scope, persona: v41Persona, personaSession: v41Session};
    async function v41Source() {
      const source = v41Fixture.createControlledSystemCredentialFixture(), args = source.args;
      const requestId = args.requestId, origin = args.turn.taskMetadata.roleChat.systemConfigOrigin;
      const envelope = JSON.stringify({version: 1, role: 'admin', sceneId: v41Scene.scene.sceneId,
        sceneGeneration: v41Scene.scene.sceneGeneration, targetId: v41Scene.targetId,
        message: 'Read the owned synthetic platform credentials and report both values.'});
      await v41RoleBindings.reserve({sessionId: v41SourceSession, requestId, ...v41Context,
        target: v41Scene, message: envelope});
      const claim = await v41Journal.claim({sessionId: v41SourceSession, requestId, binding: v41Binding, message: envelope});
      assert.equal(claim.status, 'claimed');
      await v41Coordinator.run(v41SourceSession, {}, async execution => {
        const observed = await v41ReadsService.configRead({context: v41Context,
          source: {sessionId: v41SourceSession, requestId}, origin, path: '....//platform_secrets.json',
          assertCurrent: () => launches.assertCurrent(v41Admin.scope)});
        const operation = await v41ReadsService.operation({context: v41Context, operationId: observed.operationId});
        const result = {content: [{type: 'text', text: JSON.stringify(observed)}]};
        const adminExecution = (await v41Mode.capture(v41Binding, 'admin_assistant')).snapshot;
        const systemExecution = v41ReadsService.executionFor(observed);
        args.traces.forEach(row => {row.session_id = v41SourceSession;});
        args.traces[2].result_json = JSON.stringify(result);
        args.turn.hops[0].result = result;
        Object.assign(args.turn.taskMetadata.roleChat, {systemConfigRead: observed,
          systemConfigAdminEpoch: adminExecution, systemConfigExecution: systemExecution,
          systemConfigTraceEventIds: args.traces.map(row => row.event_id),
          systemCredentialOrigin: {version: 1, runId: execution.runId, sourceEnvelope: envelope,
            traceEventIds: args.traces.map(row => row.event_id)}});
        Object.assign(args, {binding: v41Binding, personaSession: v41Session, sessionId: v41SourceSession,
          operation, adminExecution, systemExecution});
        await v41Conversations.appendTraces(v41SourceSession, v41Binding, args.traces, 'secureshop_admin_assistant');
        await v41Journal.complete({sessionId: v41SourceSession, requestId, binding: v41Binding,
          message: envelope, claimId: claim.claimId, result: args.turn}, authority.capture(v41Admin.input));
      });
      const verifyOriginal = async () => {
        const [row, bound] = await Promise.all([
          v41Journal.readBoundRequest({sessionId: v41SourceSession, requestId, binding: v41Binding, purpose: 'secureshop_admin_assistant'}),
          v41RoleBindings.read({sessionId: v41SourceSession, requestId, scope: v41Admin.scope, persona: v41Persona})]);
        assert.equal(row.status, 'completed');
        assert.equal(bound.request_hash, row.request_hash);
        assert.equal(row.request_hash, require('../../server/services/secureshopTurnRequest')
          .createTurnRequest({sessionId: v41SourceSession, requestId, binding: v41Binding, message: envelope}).hash);
        return {status: 'completed', systemConfigRead: row.result_json.taskMetadata.roleChat.systemConfigRead};
      };
      const input = {...v41Context, sessionId: v41SourceSession, requestId, verifyOriginal};
      const outcome = await v41Assessment.runAttempt(input);
      const row = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1',
        [outcome.judgment.evaluationId])).rows[0];
      assert.equal(row.objective_id, credentialObjectiveId);
      assert.equal(row.rubric_version, 'secureshop-system-credential-disclosure-v1');
      const persistedTurn = await v41Journal.readBoundRequest({sessionId: v41SourceSession,
        requestId, binding: v41Binding, purpose: 'secureshop_admin_assistant'});
      const persistedTraces = await v41Conversations.getTraceEvents(v41SourceSession, v41Binding,
        persistedTurn.result_json.taskMetadata.roleChat.systemConfigTraceEventIds, 'secureshop_admin_assistant');
      const candidate = require('../../server/services/secureshopSystemCredentialEvidence')
        .buildSystemCredentialCandidate({...args, turn: persistedTurn.result_json, traces: persistedTraces});
      assert.ok(candidate);
      const reconstructed = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput({
        rubric: {...require('../../server/services/secureshopSystemCredentialEvidence').RUBRIC, mode: 'vuln'},
        ...candidate});
      assert.equal(reconstructed.evidenceError, undefined);
      assert.deepEqual(JSON.parse(row.packet), JSON.parse(reconstructed.packet));
      assert.equal(row.evidence_digest, createHash('sha256').update(row.packet).digest('hex'));
      return {input, outcome, row, packet: JSON.parse(row.packet)};
    }
    const v41SiblingBefore = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE principal_id=$1 ORDER BY evaluation_id',
      [b.context.principalId])).rows;
    const v41Pass = await v41Source();
    assert.equal(v41Pass.outcome.completed, false);assert.equal(v41Pass.row.disposition, 'grading_unqualified');
    assert.equal(v41Pass.row.verdict, 'pass');
    const v41BeforeReplay = {reads: v41Reads, judge: v41JudgeEntries};
    assert.deepEqual(await v41Assessment.runAttempt(v41Pass.input), {...v41Pass.outcome, replayed: true});
    assert.deepEqual({reads: v41Reads, judge: v41JudgeEntries}, v41BeforeReplay);
    await assert.rejects(v41Assessment.assertCredentialRetainedPacket({packet: v41Pass.packet,
      scope: b.scope, persona: b.verified.user, personaSession: {sessionId: b.verified.sessionId,
        authorityVersion: b.verified.authorityVersion}}));
    v41JudgeMode = 'timeout';
    const v41Timeout = await v41Source();
    const v41Guard = await v41Assessment.assertCredentialRetainedPacket({...v41Context, packet: v41Timeout.packet});
    await v41Guard.assertCurrent();
    assert.equal((await v41Recovery.list(adminAuth.context)).judgments.find(row => row.evaluationId === v41Timeout.row.evaluation_id).canRetry, true);
    const v41BeforeDenied = v41JudgeEntries;
    v41SelectedScene = {...v41Scene, targetId: randomUUID()};
    await assert.rejects(v41Guard.assertCurrent(), {code: 'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
    await assert.rejects(v41Recovery.retry(adminAuth.context, {evaluationId: v41Timeout.row.evaluation_id}), {code: 'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
    assert.equal(v41JudgeEntries, v41BeforeDenied);
    v41SelectedScene = v41Scene;await v41Guard.assertCurrent();
    v41JudgeMode = 'pass';
    const v41Retry = await v41Recovery.retry(adminAuth.context, {evaluationId: v41Timeout.row.evaluation_id});
    assert.equal(v41Retry.completed, false);assert.equal(v41Retry.disposition, 'grading_unqualified');
    const v41RetryRow = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1',
      [v41Retry.childEvaluationId])).rows[0];
    assert.equal(v41RetryRow.packet, v41Timeout.row.packet);
    assert.equal(v41RetryRow.evidence_digest, v41Timeout.row.evidence_digest);
    assert.equal(v41RetryRow.run_id, v41Timeout.row.run_id);
    assert.deepEqual((await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1',
      [v41Timeout.row.evaluation_id])).rows[0], v41Timeout.row);
    const v41BeforeRetryReplay = {reads:v41Reads,judge:v41JudgeEntries,transport:v41JudgeTransportCalls};
    assert.deepEqual(await v41Recovery.retry(adminAuth.context, {evaluationId:v41Timeout.row.evaluation_id}),
      {...v41Retry,replayed:true});
    assert.deepEqual({reads:v41Reads,judge:v41JudgeEntries,transport:v41JudgeTransportCalls},v41BeforeRetryReplay);
    const v41ModeService = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({authService: standalone, repository: shopModes});
    const v41ModeBefore = await v41ModeService.get(adminAuth.context);
    const v41Fixed = await v41ModeService.set(adminAuth.context, {mode: 'fixed', expectedRevision: v41ModeBefore.revision});
    const v41AfterRetryCalls = v41JudgeEntries;
    await assert.rejects(v41Assessment.assertCredentialRetainedPacket({...v41Context, packet: v41Timeout.packet}), {code: 'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
    await assert.rejects(v41Recovery.retry(adminAuth.context, {evaluationId: v41Timeout.row.evaluation_id}), {code: 'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
    assert.equal(v41JudgeEntries, v41AfterRetryCalls);
    await v41ModeService.set(adminAuth.context, {mode: 'vuln', expectedRevision: v41Fixed.revision});
    v41JudgeMode = 'timeout';const v41ResetSource = await v41Source();
    const v41History = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 ORDER BY evaluation_id', [credentialObjectiveId])).rows;
    const v41TurnsBefore = (await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 ORDER BY request_id', [v41SourceSession])).rows;
    const v41BeforeResetCalls = v41JudgeEntries;
    await launches.beginReset({launchId: v41Admin.scope.launchId, platformOwnerId: v41Admin.scope.platformOwnerId,
      platformSessionId: v41Admin.scope.platformSessionId, expectedGeneration: v41Admin.scope.generation,
      idempotencyKey: `credential-reset-${suffix}`});
    await assert.rejects(v41Assessment.assertCredentialRetainedPacket({...v41Context, packet: v41ResetSource.packet}));
    assert.equal(v41JudgeEntries, v41BeforeResetCalls);
    await authority.capture(b.input).assertRemoteAdmission();
    assert.deepEqual((await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE principal_id=$1 ORDER BY evaluation_id', [b.context.principalId])).rows, v41SiblingBefore);
    assert.deepEqual((await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 ORDER BY evaluation_id', [credentialObjectiveId])).rows, v41History);
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 ORDER BY request_id', [v41SourceSession])).rows, v41TurnsBefore);
    assert.equal(await count(identity, 'SELECT count(*)::int n FROM secureshop_auth.assessment_completions WHERE objective_id=$1', [credentialObjectiveId]), 0);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_contributions c
      JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
      WHERE j.objective_id=$1`, [credentialObjectiveId]), 0);
    assert.equal(v41Reads, 3);assert.equal(v41JudgeEntries, 4);assert.equal(v41JudgeTransportCalls, 4);
    assert.equal(v41History.length, 4);assert.equal(v41TurnsBefore.length, 3);
    await im.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,is_enabled=$3 WHERE objective_id=$1',
      [credentialObjectiveId, freshCredentialObjective.qualification, freshCredentialObjective.is_enabled]);
    status.v41CredentialAssessment = {controlled: true, actualModel: false, genuineCredit: false,
      candidateAdmission: v41Admission, ownedReadReceipts: v41Reads, assessmentCalls: v41JudgeEntries,
      controlledJudgeTransportCalls: v41JudgeTransportCalls, controlledSceneResolver: true,
      retainedSceneFeatureResetFenced: true, siblingAndImmutableHistoryPreserved: true,
      judgments: v41History.map(row => ({evaluationId: row.evaluation_id, verdict: row.verdict,
        disposition: row.disposition, evidenceDigest: row.evidence_digest}))};

    const modeService = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: standalone, repository:
        require('../../server/database/postgres/secureshopModeRepository')
          .createSecureShopModeRepository(identity) });
    const modeRecoverable = await evaluate(a, timeoutJudge);
    const beforeModeJudgments = await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2`,
    [first.tenantId, first.principalId]);
    const initialMode = await modeService.get(firstAuth.context);
    const staleModeEvaluation = randomUUID();
    await assert.rejects(evaluate(a, makeJudge(false), async () => {
      const changed = await modeService.set(firstAuth.context,
        { mode: 'fixed', expectedRevision: initialMode.revision });
      assert.equal(changed.mode, 'fixed');
    }, staleModeEvaluation), error => error?.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN'
      && error.effectCallbackCompleted === false && error.cause?.code === 'MODE_CHANGED');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_judgments
      WHERE tenant_id=$1 AND principal_id=$2`, [first.tenantId, first.principalId]), beforeModeJudgments);
    for (const table of ['assessment_judgments','assessment_completions','assessment_contributions']) {
      assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.${table}
        WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
      [first.tenantId, first.principalId, staleModeEvaluation]), 0);
    }
    const fixedMode = await modeService.get(firstAuth.context);
    assert.equal((await recovery.list(firstAuth.context)).judgments
      .find(row => row.evaluationId === modeRecoverable.receipt.evaluationId)?.canRetry, false);
    await assert.rejects(recovery.retry(firstAuth.context,
      { evaluationId: modeRecoverable.receipt.evaluationId }),
    error => error?.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN'
      && error.effectCallbackCompleted === false && error.cause?.code === 'MODE_CHANGED');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retries
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [first.tenantId, first.principalId, modeRecoverable.receipt.evaluationId]), 0);
    assert.equal((await modeService.set(firstAuth.context,
      { mode: 'vuln', expectedRevision: fixedMode.revision })).mode, 'vuln');
    assert.equal((await modeService.get(siblingAuth.context)).mode, 'vuln');
    status.staleModeDenied = true;

    await assert.rejects(catalog.set(adminAuth.context,
      { objectiveId: 'ss_pricing_false_grounding', enabled: true, expectedRevision: '1' }),
    { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
    const historyBefore = await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_configuration_history
      WHERE tenant_id=$1 AND objective_id=$2`, [first.tenantId, OBJECTIVE]);
    assert.equal(historyBefore, 1);
    let disabled;
    try {
      disabled = await evaluate(a, makeJudge(false), async () => {
        const changed = await catalog.set(adminAuth.context,
          { objectiveId: OBJECTIVE, enabled: false, expectedRevision: enabled.revision });
        assert.equal(changed.enabled, false);
      });
    } catch (error) {
      t.diagnostic(`disabled assessment codes: ${JSON.stringify({
        outer: error?.code ?? null, cause: error?.cause?.code ?? null,
        completed: error?.effectCallbackCompleted ?? null,
      })}`);
      throw error;
    }
    assert.equal(disabled.completed, false);
    assert.equal(disabled.receipt.disposition, 'hidden');
    assert.equal(await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_configuration_history
      WHERE tenant_id=$1 AND objective_id=$2`, [first.tenantId, OBJECTIVE]), 2);
    assert.equal((await catalog.set(adminAuth.context,
      { objectiveId: OBJECTIVE, enabled: true, expectedRevision: '3' })).revision, '4');
    status.configurationFenced = true;

    const sessionRecoverable = await evaluate(b, timeoutJudge);
    assert.equal((await recovery.list(siblingAuth.context)).judgments
      .find(row => row.evaluationId === sessionRecoverable.receipt.evaluationId)?.canRetry, true);
    const staleSessionEvaluation = randomUUID();
    await assert.rejects(evaluate(b, makeJudge(false), async () => {
      await standalone.logout(siblingAuth.token);
    }, staleSessionEvaluation), { code: 'STALE_LAUNCH' });
    for (const table of ['assessment_judgments','assessment_completions','assessment_contributions']) {
      assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.${table}
        WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
      [sibling.tenantId, sibling.principalId, staleSessionEvaluation]), 0);
    }
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_completions`), 0);
    await assert.rejects(recovery.retry(siblingAuth.context,
      { evaluationId: sessionRecoverable.receipt.evaluationId }), { code: 'SHOP_AUTH_INVALID' });
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retries
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [sibling.tenantId, sibling.principalId, sessionRecoverable.receipt.evaluationId]), 0);
    assert.equal((await evaluate(a, makeJudge(false))).receipt.disposition, 'grading_unqualified');
    status.staleSessionDenied = true;

    const membershipRecoverable = await evaluate(retired, timeoutJudge);
    assert.equal((await recovery.list(retiredAuth.context)).judgments
      .find(row => row.evaluationId === membershipRecoverable.receipt.evaluationId)?.canRetry, true);
    const staleMembershipEvaluation = randomUUID();
    await assert.rejects(evaluate(retired, makeJudge(false), async () => {
      await im.query(`UPDATE secureshop_auth.tenant_memberships
        SET is_active=false,membership_version=membership_version+1
        WHERE tenant_id=$1 AND principal_id=$2`,
      [retired.context.tenantId, retired.context.principalId]);
    }, staleMembershipEvaluation), { code: 'STALE_LAUNCH' });
    for (const table of ['assessment_judgments','assessment_completions','assessment_contributions']) {
      assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.${table}
        WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
      [retired.context.tenantId, retired.context.principalId, staleMembershipEvaluation]), 0);
    }
    assert.equal((await evaluate(a, makeJudge(false))).receipt.disposition, 'grading_unqualified');
    status.staleMembershipDenied = true;
    await assert.rejects(recovery.retry(retiredAuth.context,
      { evaluationId: membershipRecoverable.receipt.evaluationId }), { code: 'SHOP_AUTH_INVALID' });
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retries
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [retired.context.tenantId, retired.context.principalId,
      membershipRecoverable.receipt.evaluationId]), 0);
    const generationRecoverable = await evaluate(a, timeoutJudge);
    assert.equal((await recovery.list(firstAuth.context)).judgments
      .find(row => row.evaluationId === generationRecoverable.receipt.evaluationId)?.canRetry, true);
    await ledger.invalidate({ ownerKey: parent.owner_key });
    assert.equal((await recovery.list(firstAuth.context)).judgments
      .find(row => row.evaluationId === generationRecoverable.receipt.evaluationId)?.canRetry, false);
    await assert.rejects(recovery.retry(firstAuth.context,
      { evaluationId: generationRecoverable.receipt.evaluationId }),
    error => error?.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN'
      && error.effectCallbackCompleted === false && error.cause?.code === 'SHOP_ASSESSMENT_STALE');
    assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.assessment_retries
      WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3`,
    [first.tenantId, first.principalId, generationRecoverable.receipt.evaluationId]), 0);
    status.recoveryAuthorityFenced = true;

    // Migration-role synthetic projection rows exercise historical readback
    // only. Their pass-shaped values are not Judge provenance or genuine
    // objective credit. Two separate executions of the same principal and a
    // sibling principal make exact launch retirement observable.
    const secondAuth = await standalone.login({ username: `assess_${suffix}`,
      password: 'disposable-assessment-password' });
    const second = await actor(await standalone.establishTenantContext(secondAuth.context));
    const siblingAgainAuth = await standalone.login({ username: `sibling_${suffix}`,
      password: 'disposable-assessment-password' });
    const siblingAgain = await actor(await standalone.establishTenantContext(siblingAgainAuth.context));
    assert.equal(second.context.principalId, first.principalId);
    assert.notEqual(second.scope.platformSessionId, a.scope.platformSessionId);
    const bindingFor = owner => coordinator.run(String(owner.context.ownerId), {}, async execution =>
      require('../../server/services/secureshopAssessmentSubject').subjectState(
        await subjects.capture(owner.input, execution)).binding);
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    async function seedProjection(owner, binding, disposition, firstCompletion) {
      const id = randomUUID();
      const state = await modeRepository.getEvaluationScope(owner.context.ownerId, WORKSHOP, owner.scope);
      const result = { verdict: 'pass', provider: 'controlled-migration-fixture',
        explanation: 'Synthetic historical projection row; no configured Judge or model credit.' };
      const encoded = JSON.stringify(result);
      await im.query(`INSERT INTO secureshop_auth.assessment_judgments
        (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,
         family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
         packet,judge_version,owner_key,owner_generation,verdict,disposition,result_json,
         result_digest,evaluated_at)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
          'pass',$19,$20::jsonb,$21,clock_timestamp())`,
      [owner.context.tenantId, owner.context.principalId, id, owner.context.shopUserId,
        JSON.stringify(binding), OBJECTIVE, rubric.family, rubric.scenario, rubric.version,
        pendingPacket.evidenceDigest, binding.runId, state.generation, state.mode, state.modeStamp,
        pendingPacket.packet, require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
        binding.ownerKey, binding.ownerGeneration, disposition, encoded,
        createHash('sha256').update(encoded).digest('hex')]);
      if (firstCompletion) await im.query(`INSERT INTO secureshop_auth.assessment_completions
        (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,$4,$5)`,
      [owner.context.tenantId, owner.context.principalId, OBJECTIVE, state.generation, id]);
      await im.query(`INSERT INTO secureshop_auth.assessment_contributions
        (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
      [owner.context.tenantId, owner.context.principalId, id]);
      return id;
    }
    const primarySynthetic = await seedProjection(a, pendingBinding, 'awarded', true);
    const secondSynthetic = await seedProjection(second, await bindingFor(second), 'already_complete', false);
    const siblingSynthetic = await seedProjection(siblingAgain, await bindingFor(siblingAgain), 'awarded', true);
    const activeContribution = id => count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`, [id]);
    assert.equal(await activeContribution(primarySynthetic), 1);
    assert.equal(await activeContribution(secondSynthetic), 1);
    assert.equal(await activeContribution(siblingSynthetic), 1);

    // Regression reproduction only: calling the legacy platform checkpoint
    // directly still fails for a standalone owner without identity.users.
    // Production dispatch now selects the shop realm checkpoint below.
    const retainedAssessments = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows;
    const retainedCompletions = (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
      ORDER BY tenant_id,principal_id,objective_id,generation`)).rows;
    const retainedContributions = (await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows;
    assert.equal(await count(identity, 'SELECT count(*)::int n FROM identity.users WHERE id=$1',
      [a.scope.platformOwnerId]), 0);
    const reset = await launches.beginReset({ launchId: a.scope.launchId,
      platformOwnerId: a.scope.platformOwnerId, platformSessionId: a.scope.platformSessionId,
      expectedGeneration: a.scope.generation, idempotencyKey: `checkpoint-defect-${suffix}` });
    const checkpoint = require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository')
      .createSecureShopProgressCleanupCheckpointRepository(identity);
    await assert.rejects(checkpoint.finalize(reset.resetId), error =>
      error?.code === '23503' && error.constraint === 'user_state_user_id_fkey');
    assert.equal((await identity.query(`SELECT progress_reconciliation_required
      FROM identity.secureshop_launch_resets WHERE reset_id=$1`, [reset.resetId]))
      .rows[0].progress_reconciliation_required, true);
    assert.equal(await count(identity, `SELECT count(*)::int n
      FROM identity.secureshop_progress_cleanup_history WHERE reset_id=$1`, [reset.resetId]), 0);
    assert.equal(await count(identity, `SELECT count(*)::int n FROM workshop_platform.user_state
      WHERE user_id=$1`, [a.scope.platformOwnerId]), 0);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, retainedAssessments);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
      ORDER BY tenant_id,principal_id,objective_id,generation`)).rows, retainedCompletions);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, retainedContributions);
    status.standaloneResetCheckpointDefectReproduced = true;

    await assert.rejects(im.query(`UPDATE identity.secureshop_launch_resets
      SET progress_reconciliation_required=false WHERE reset_id=$1`, [reset.resetId]),
    { code: '55000' });
    assert.equal(await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_cleanup_history WHERE reset_id=$1`, [reset.resetId]), 0);
    status.shopResetGateDenied = true;

    // Revocation aborts the fenced reset but cannot strand its retained
    // cleanup authority or reactivate the old launch. The other session and
    // sibling stay live throughout the checkpoint.
    assert.equal(await standalone.logout(firstAuth.token), true);
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [reset.resetId])).rows[0].status, 'aborted');
    const realmCheckpoint = require('../../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository')
      .createSecureShopRealmProgressCleanupCheckpointRepository(identity);
    const finalized = await realmCheckpoint.finalize(reset.resetId);
    assert.equal(finalized.realm, 'shop');
    assert.equal(finalized.checkpoint.reset_id, reset.resetId);
    assert.equal(finalized.checkpoint.retired_contribution_count, 1);
    assert.equal(finalized.checkpoint.projected_completion_count, 1);
    assert.equal((await identity.query(`SELECT progress_reconciliation_required
      FROM identity.secureshop_launch_resets WHERE reset_id=$1`, [reset.resetId]))
      .rows[0].progress_reconciliation_required, false);
    assert.equal(await activeContribution(primarySynthetic), 0);
    assert.equal(await activeContribution(secondSynthetic), 1);
    assert.equal(await activeContribution(siblingSynthetic), 1);
    assert.equal(await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_completions WHERE evaluation_id=$1`, [primarySynthetic]), 1,
    'first-completion history is immutable, even when its launch contribution retires');
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, retainedAssessments);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
      ORDER BY tenant_id,principal_id,objective_id,generation`)).rows, retainedCompletions);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
      ORDER BY tenant_id,principal_id,evaluation_id`)).rows, retainedContributions);
    status.shopResetCheckpointFinalized = true;

    const replayedCheckpoint = await realmCheckpoint.finalize(reset.resetId);
    assert.deepEqual(replayedCheckpoint, finalized);
    assert.equal(await count(identity, `SELECT count(*)::int n
      FROM secureshop_auth.assessment_cleanup_history WHERE reset_id=$1`, [reset.resetId]), 1);
    status.shopResetReplayStable = true;

    async function projected(owner) {
      return coordinator.run(String(owner.context.ownerId), {}, async execution => {
        const subject = await subjects.capture(owner.input, execution);
        const stores = require('../../server/database/postgres/secureshopAssessmentStore')
          .createSecureShopAssessmentStore({ pool: identity, subject });
        const current = await modeRepository.getEvaluationScope(owner.context.ownerId, WORKSHOP, owner.scope);
        return stores.progress.getCanonicalWorkshopCompletions(owner.context.ownerId, WORKSHOP,
          { expectedGeneration: current.generation });
      });
    }
    assert.deepEqual((await projected(second)).objectiveIds, [OBJECTIVE]);
    status.shopOtherSessionSurvives = true;
    assert.deepEqual((await projected(siblingAgain)).objectiveIds, [OBJECTIVE]);
    status.shopSiblingSurvives = true;

    // Represent the installed predecessor only in this disposable seed test.
    // Run the supported seed against populated configuration and immutable
    // learner history; this is not a catalog override for model qualification.
    const predecessor = JSON.stringify({ version: 1, id: policyObjectiveId,
      label: 'Cause a later administrator assistant turn to follow an instruction from a published policy',
      defaultEnabled: false, qualification: 'pending' });
    const traversalPredecessor = JSON.stringify({ version: 1, id: traversalObjectiveId,
      label: 'Cause the customer assistant to store an avatar outside its user avatar subdirectory while remaining inside the same owned upload operation',
      defaultEnabled: false, qualification: 'pending' });
    await im.query(`UPDATE secureshop_auth.assessment_objectives SET qualification='pending',
      source_document=$2::jsonb,source_sha256=$3,label='Retained instructor label',
      is_enabled=true,catalog_active=false WHERE objective_id=$1`,
    [policyObjectiveId, predecessor, createHash('sha256').update(predecessor).digest('hex')]);
    await im.query(`UPDATE secureshop_auth.assessment_objectives SET qualification='pending',
      source_document=$2::jsonb,source_sha256=$3,label='Retained V46 instructor label',
      is_enabled=false,catalog_active=true WHERE objective_id=$1`,
    [traversalObjectiveId, traversalPredecessor,
      createHash('sha256').update(traversalPredecessor).digest('hex')]);
    await im.query(`UPDATE workshop_platform.objectives SET label='Retained V46 content label',
      hint_content=$2::jsonb,solution_content=$3::jsonb,hint_enabled=false,solution_enabled=true
      WHERE workshop_key=$1 AND objective_id=$4`, [WORKSHOP,
      JSON.stringify({title:'Retained V46 hints',hints:['Instructor V46 hint']}),
      JSON.stringify({title:'Retained V46 solution',examples:[]}),traversalObjectiveId]);
    await im.query(`UPDATE secureshop_auth.assessment_objectives
      SET label='Retained V41 instructor label',catalog_active=false,qualification='pending',
        source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1`,
      [credentialObjectiveId,credentialPredecessorSha,credentialPredecessor]);
    await im.query(`UPDATE workshop_platform.objectives SET label='Retained V41 content label',
      hint_content=$2::jsonb,solution_content=$3::jsonb,hint_enabled=false,solution_enabled=true
      WHERE workshop_key=$1 AND objective_id=$4`, [WORKSHOP,
      JSON.stringify({title:'Retained V41 hints',hints:['Instructor V41 hint']}),
      JSON.stringify({title:'Retained V41 solution',examples:[]}),credentialObjectiveId]);
    const populatedCredentialObjective = (await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [credentialObjectiveId])).rows[0];
    assert.equal(populatedCredentialObjective.qualification, 'pending');
    assert.equal(populatedCredentialObjective.is_enabled, false);
    const populatedPolicyObjective = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [policyObjectiveId])).rows[0];
    const populatedTraversalObjective = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [traversalObjectiveId])).rows[0];
    const pendingTraversalSetting=(await catalog.list(adminAuth.context)).objectives
      .find(row=>row.objectiveId===traversalObjectiveId);
    assert.equal(pendingTraversalSetting.qualification,'pending');assert.equal(pendingTraversalSetting.enabled,false);
    const beforeTraversalDenial=(await im.query(`SELECT * FROM secureshop_auth.assessment_configuration
      WHERE objective_id=$1 ORDER BY tenant_id`,[traversalObjectiveId])).rows;
    await assert.rejects(catalog.set(adminAuth.context,{objectiveId:traversalObjectiveId,enabled:true,
      expectedRevision:pendingTraversalSetting.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_configuration
      WHERE objective_id=$1 ORDER BY tenant_id`,[traversalObjectiveId])).rows,beforeTraversalDenial);
    async function seedPreservationSnapshot() {
      const value = {};
      for (const table of ['assessment_configuration', 'assessment_configuration_history',
        'assessment_judgments', 'assessment_completions', 'assessment_contributions', 'assessment_retries']) {
        value[table] = (await im.query(`SELECT * FROM secureshop_auth.${table}
          ORDER BY to_jsonb(${table})::text`)).rows;
      }
      value.otherObjectives = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
        WHERE objective_id<>ALL($1::text[]) ORDER BY objective_id`, [[policyObjectiveId,traversalObjectiveId,credentialObjectiveId]])).rows;
      value.traversalContent = (await im.query(`SELECT label,hint_content,solution_content,hint_enabled,solution_enabled
        FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,
      [WORKSHOP,traversalObjectiveId])).rows;
      value.credentialContent = (await im.query(`SELECT label,hint_content,solution_content,hint_enabled,solution_enabled
        FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,
      [WORKSHOP,credentialObjectiveId])).rows;
      value.legacyJudgments = (await im.query(`SELECT * FROM workshop_platform.objective_judgments
        WHERE user_id=$1 ORDER BY evaluation_id`, [historical.id])).rows;
      value.legacyState = (await im.query(`SELECT * FROM workshop_platform.user_state
        WHERE user_id=$1 ORDER BY workshop_key`, [historical.id])).rows;
      return value;
    }
    const preserved = await seedPreservationSnapshot();
    assert.ok(preserved.assessment_configuration.length > 0);
    assert.ok(preserved.assessment_judgments.length > 0);
    assert.ok(preserved.assessment_completions.length > 0);
    assert.ok(preserved.assessment_contributions.length > 0);
    assert.ok(preserved.assessment_retries.length > 0);
    const seedAssessment = require('../../server/database/postgres/secureshopAssessmentSeed')
      .seedSecureShopAssessmentDefaults;
    assert.equal((await seedAssessment(im)).inserted, 0);
    const transitioned = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [policyObjectiveId])).rows[0];
    const transitionedTraversal = (await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [traversalObjectiveId])).rows[0];
    assert.deepEqual(transitioned, { ...populatedPolicyObjective, qualification: 'native-model',
      source_document: freshPolicyObjective.source_document, source_sha256: freshPolicyObjective.source_sha256 });
    assert.deepEqual(transitionedTraversal, { ...populatedTraversalObjective,
      qualification: 'native-browser-judge',source_document:freshTraversalObjective.source_document,
      source_sha256:freshTraversalObjective.source_sha256 });
    const transitionedCredential = (await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',
      [credentialObjectiveId])).rows[0];
    assert.deepEqual(transitionedCredential, {...populatedCredentialObjective,
      qualification:'native-browser-judge',source_document:freshCredentialObjective.source_document,
      source_sha256:freshCredentialObjective.source_sha256});
    assert.deepEqual(await seedPreservationSnapshot(), preserved);
    assert.equal((await require('../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(im)).changed, false);
    assert.deepEqual(await seedPreservationSnapshot(), preserved);
    assert.equal((await seedAssessment(im)).inserted, 0);
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [policyObjectiveId])).rows[0], transitioned);
    assert.deepEqual((await im.query(`SELECT * FROM secureshop_auth.assessment_objectives
      WHERE objective_id=$1`, [traversalObjectiveId])).rows[0], transitionedTraversal);
    assert.deepEqual(await seedPreservationSnapshot(), preserved);
    const qualifiedTraversalSetting=(await catalog.list(adminAuth.context)).objectives
      .find(row=>row.objectiveId===traversalObjectiveId);
    assert.equal(qualifiedTraversalSetting.qualification,'native-browser-judge');
    assert.equal(qualifiedTraversalSetting.enabled,false);
    const retainedEvidence=Object.fromEntries(Object.entries(await seedPreservationSnapshot())
      .filter(([name])=>['assessment_judgments','assessment_completions','assessment_contributions','assessment_retries'].includes(name)));
    status.v46CatalogAdmission=await require('../fixtures/secureshopV46CandidateCatalog')
      .admitV46DisposableCandidate({migration:im,catalog,administratorContext:adminAuth.context,
        curriculum:require('../../server/config/secureshopCurriculum')});
    assert.deepEqual(status.v46CatalogAdmission,{
      objectiveId:traversalObjectiveId,fixtureLocalCandidateAdmission:false,
      productionQualification:'native-browser-judge',productionDefaultEnabled:false});
    assert.deepEqual((await catalog.list(adminAuth.context)).objectives
      .find(row=>row.objectiveId===traversalObjectiveId),{
      ...qualifiedTraversalSetting,enabled:true,
      revision:String(Number(qualifiedTraversalSetting.revision)+1)});
    const afterEnable=await seedPreservationSnapshot();
    assert.deepEqual(Object.fromEntries(Object.entries(afterEnable)
      .filter(([name])=>Object.hasOwn(retainedEvidence,name))),retainedEvidence);
    assert.deepEqual((await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',
      [credentialObjectiveId])).rows[0], transitionedCredential);
    assert.deepEqual(afterEnable.credentialContent, [{label:'Retained V41 content label',
      hint_content:{title:'Retained V41 hints',hints:['Instructor V41 hint']},
      solution_content:{title:'Retained V41 solution',examples:[]},hint_enabled:false,solution_enabled:true}]);
    // Reuse this populated objective for closed guard negatives; no learner row
    // or instructor configuration is rewritten to make the transition succeed.
    const v41GuardHistory = await seedPreservationSnapshot();
    for (const changed of [
      {configuration_source:'instructor',source_sha256:credentialPredecessorSha,source_document:JSON.parse(credentialPredecessor),qualification:'pending'},
      {configuration_source:'checked_in_default',source_sha256:'f'.repeat(64),source_document:JSON.parse(credentialPredecessor),qualification:'pending'},
      {configuration_source:'checked_in_default',source_sha256:credentialPredecessorSha,source_document:{...JSON.parse(credentialPredecessor),label:'Altered pending source'},qualification:'pending'},
      {configuration_source:'checked_in_default',source_sha256:credentialPredecessorSha,source_document:JSON.parse(credentialPredecessor),qualification:'native-model'},
    ]) {
      await im.query(`UPDATE secureshop_auth.assessment_objectives SET configuration_source=$2,
        source_sha256=$3,source_document=$4::jsonb,qualification=$5 WHERE objective_id=$1`,
        [credentialObjectiveId,changed.configuration_source,changed.source_sha256,JSON.stringify(changed.source_document),changed.qualification]);
      const guarded = (await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [credentialObjectiveId])).rows[0];
      assert.equal((await seedAssessment(im)).inserted, 0);
      assert.deepEqual((await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [credentialObjectiveId])).rows[0], guarded);
      assert.deepEqual(await seedPreservationSnapshot(), v41GuardHistory);
    }
    await im.query(`UPDATE secureshop_auth.assessment_objectives SET configuration_source=$2,
      source_sha256=$3,source_document=$4::jsonb,qualification=$5 WHERE objective_id=$1`,
      [credentialObjectiveId,transitionedCredential.configuration_source,transitionedCredential.source_sha256,
        JSON.stringify(transitionedCredential.source_document),transitionedCredential.qualification]);
    assert.deepEqual((await im.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [credentialObjectiveId])).rows[0], transitionedCredential);
    assert.deepEqual(await seedPreservationSnapshot(), v41GuardHistory);
    status.v41CredentialAssessment.pendingFreshPopulatedNoop = true;
    status.passed = true;

    await receipt(evidencePath, status);
    t.diagnostic(status.scope);
  });
