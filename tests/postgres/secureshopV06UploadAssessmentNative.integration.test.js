'use strict';

// Native PostgreSQL join/fence qualification only. The trace identity predicate and
// historical judgments are controlled fixtures; this file cannot establish a real
// model/Judge run, physical upload, rendered behavior, or objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs/promises');
const { randomUUID, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate, readMigrations, executionSql } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { seedSecureShopAssessmentDefaults } = require('../../server/database/postgres/secureshopAssessmentSeed');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopAssessmentCatalog } = require('../../server/services/secureshopAssessmentCatalog');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createV06UploadTurnReader } = require('../../server/database/postgres/secureshopV06UploadTurnReader');
const { createSecureShopBoundUploadRepository } = require('../../server/database/postgres/secureshopBoundUploadRepository');
const { createSecureShopBoundUploadAssetRepository } = require('../../server/database/postgres/secureshopBoundUploadAssetRepository');
const { createV06UploadSourceReader } = require('../../server/services/secureshopV06UploadSourceReader');
const { createSecureShopUploadAssetReader } = require('../../server/services/secureshopUploadAssetReader');
const { createV06UploadAssessment, assessmentRequestId } = require('../../server/services/secureshopV06UploadAssessment');
const { projectJudgment } = require('../../server/agent-runtime/dpiSemanticCreditPolicy');
const { createSecureShopAssessmentRecovery } = require('../../server/services/secureshopAssessmentRecovery');
const { createSceneBinding } = require('../../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../../server/services/secureshopTurnRequest');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { prepareJudgeInput, JUDGE_VERSION } = require('../../server/agent-runtime/objectiveJudge');
const { POLICIES } = require('../../server/services/secureshopFeatureModeAuthority');
const { UPLOAD_OBJECTIVE: ID, UPLOAD_PURPOSE, UPLOAD_RUBRIC,
  HISTORICAL_V2_RUBRIC, buildUploadCandidate, buildRetainedUploadCandidate } = require('../../server/services/secureshopV06UploadEvidence');
const curriculum = require('../../server/config/secureshopCurriculum');

const PREFIX = 'PG_SECURESHOP_UPLOAD_ASSESSMENT_';
const DIRECTORIES = Object.freeze({
  IDENTITY_FRESH: path.resolve(__dirname, '../../db/postgres/identity-migrations'),
  IDENTITY_POPULATED: path.resolve(__dirname, '../../db/postgres/identity-migrations'),
  IDENTITY_ASSESSMENT: path.resolve(__dirname, '../../db/postgres/identity-migrations'),
  AGENTS: path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents'),
  REVIEW: path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review'),
});
const ROLE = Object.freeze({ IDENTITY_FRESH: 'identity', IDENTITY_POPULATED: 'identity',
  IDENTITY_ASSESSMENT: 'identity', AGENTS: 'secureshop_agents', REVIEW: 'secureshop_review' });
const enabled = process.env.SECURESHOP_UPLOAD_ASSESSMENT_NATIVE === '1';
const polyglotEnabled = process.env.SECURESHOP_UPLOAD_POLYGLOT_NATIVE === '1';
const V07 = 'ss_upload_polyglot_server_execution';
const sha = value => createHash('sha256').update(value).digest('hex');

function urls(store) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  const result = {};
  for (const type of ['MIGRATION', 'RUNTIME']) {
    const value = new URL(process.env[`${PREFIX}${store}_${type}_URL`]);
    assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
    assert.equal(value.username, `dvaia_${ROLE[store]}_${type.toLowerCase()}`);
    assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
    assert.match(value.pathname, /^\/owasp_ai_goat_test_upload_assessment_[a-f0-9]{12}_[a-z_]+$/);
    result[type.toLowerCase()] = value.href;
  }
  return result;
}
async function open(store, t) {
  const value = urls(store), migration = new Pool({ connectionString: value.migration, max: 3,
    statement_timeout: 20000, lock_timeout: 3000 }), runtime = new Pool({ connectionString: value.runtime,
    max: 8, statement_timeout: 20000, lock_timeout: 3000 });
  t.after(async () => { const settled = await Promise.allSettled([migration.end(), runtime.end()]);
    assert.equal(settled.filter(row => row.status === 'rejected').length, 0); });
  const manifest = (await readMigrations(DIRECTORIES[store])).map(({ name, checksum }) => ({ name, checksum }));
  if (polyglotEnabled && store === 'AGENTS') await qualifyPreviewMigration(migration, runtime);
  else assert.deepEqual(await migrate(migration, DIRECTORIES[store]), manifest.map(row => row.name));
  assert.deepEqual(await migrate(migration, DIRECTORIES[store]), []);
  assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  return { migration, runtime, manifest };
}
async function assessment(pool, id = ID) {
  return (await pool.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [id])).rows[0];
}
async function content(pool, id = ID) {
  return (await pool.query(`SELECT * FROM workshop_platform.objectives
    WHERE workshop_key=$1 AND objective_id=$2`, [curriculum.WORKSHOP_KEY, id])).rows[0];
}
async function defaults(pool, id = ID) {
  return (await pool.query(`SELECT * FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key=$1 AND objective_id=$2 ORDER BY field_name`,
  [curriculum.WORKSHOP_KEY, id])).rows;
}
async function snapshot(pool) {
  const names = ['secureshop_auth.assessment_objectives', 'secureshop_auth.assessment_configuration',
    'secureshop_auth.assessment_configuration_history', 'secureshop_auth.assessment_judgments',
    'secureshop_auth.assessment_completions', 'secureshop_auth.assessment_contributions',
    'secureshop_auth.assessment_retries', 'workshop_platform.objectives',
    'workshop_platform.catalog_field_defaults', 'workshop_platform.config_revision'];
  return Object.fromEntries(await Promise.all(names.map(async name => [name,
    (await pool.query(`SELECT to_jsonb(t) AS row FROM ${name} t ORDER BY to_jsonb(t)::text`)).rows])));
}
async function seedBoth(pool) { await seedSecureShopAssessmentDefaults(pool); return seedWorkshopPlatform(pool); }

const objective = curriculum.OBJECTIVES.find(row => row.id === ID);
const source = JSON.stringify({ version: 1, id: ID, label: objective.text,
  defaultEnabled: objective.defaultEnabled, qualification: objective.qualification });
const PREDECESSOR = JSON.stringify({version:1,id:'ss_upload_extension_bypass',
  label:'Cause the customer assistant to store and serve an avatar with a prohibited extension',
  defaultEnabled:false,qualification:'pending'});
const PREDECESSOR_SHA = '3efe05bed03c3cb5c75a3a14441ac719968faf22f8799be8337b77ade42f8f53';

test('native V06 upload defaults are qualified/disabled and preserve exact pending promotion and populated instructor state on no-op reseed',
  { skip: !enabled, timeout: 180000 }, async t => {
    assert.equal(objective.qualification, 'native-browser-judge'); assert.equal(objective.defaultEnabled, false);
    assert.equal(curriculum.PENDING_OBJECTIVE_IDS.includes(ID), false);assert.equal(sha(PREDECESSOR),PREDECESSOR_SHA);
    const fresh = await open('IDENTITY_FRESH', t);
    await seedBoth(fresh.migration);
    const freshAssessment = await assessment(fresh.runtime), freshContent = await content(fresh.runtime);
    assert.equal(freshAssessment.qualification, 'native-browser-judge'); assert.equal(freshAssessment.is_enabled, false);
    assert.equal(freshAssessment.configuration_source, 'checked_in_default');
    assert.equal(freshAssessment.source_sha256, sha(source));
    assert.deepEqual(freshAssessment.source_document, JSON.parse(source));
    assert.equal(freshContent.is_enabled, false); assert.equal(freshContent.catalog_active, true);
    assert.deepEqual(freshContent.hint_content, curriculum.HINTS[ID]);
    assert.deepEqual(freshContent.solution_content, curriculum.SOLUTIONS[ID]);
    assert.ok((await defaults(fresh.runtime)).every(row => row.provenance_state === 'managed'));
    await seedSecureShopStandaloneDefaults(fresh.migration,{hashPassword:value=>bcrypt.hash(value,4)});
    const freshAuth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:fresh.runtime})});
    const freshAdmin=await freshAuth.login({username:'student_admin',password:'student123'});
    const freshCatalog=createSecureShopAssessmentCatalog({pool:fresh.runtime,authService:freshAuth});
    assert.deepEqual(await require('../fixtures/secureshopV06CandidateCatalog').admitV06DisposableCandidate({
      migration:fresh.migration,catalog:freshCatalog,administratorContext:freshAdmin.context,curriculum}),
    {objectiveId:ID,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
    if (polyglotEnabled) await qualifyPreviewCatalog(fresh,false,{auth:freshAuth,admin:freshAdmin});
    const freshBefore = await snapshot(fresh.migration);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(fresh.migration), { inserted: 0 });
    assert.equal((await seedWorkshopPlatform(fresh.migration)).changed, false);
    assert.deepEqual(await snapshot(fresh.migration), freshBefore);

    const populated = await open('IDENTITY_POPULATED', t);
    await seedBoth(populated.migration);
    await seedSecureShopStandaloneDefaults(populated.migration, { hashPassword: value => bcrypt.hash(value, 4) });
    const auth = createSecureShopStandaloneAuthService({ repository:
      createSecureShopStandaloneAuthRepository({ pool: populated.runtime }) });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const context = await auth.establishTenantContext(admin.context);
    const sibling = curriculum.OBJECTIVES.find(row => row.id !== ID).id, peer = randomUUID();
    await populated.migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
      [peer, `upload-assessment-peer-${peer}`]);
    for (const [tenant, revision] of [[context.tenantId, 7], [peer, 11]]) {
      await populated.migration.query(`INSERT INTO secureshop_auth.assessment_configuration
        (tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,false,$3,$4)`,
      [tenant, ID, revision, context.principalId]);
      await populated.migration.query(`INSERT INTO secureshop_auth.assessment_configuration_history
        (tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id)
        VALUES($1,$2,$3,false,$4,$5)`, [tenant, ID, revision, context.principalId, context.sessionId]);
    }
    const catalog = createSecureShopAssessmentCatalog({ pool: populated.runtime, authService: auth });
    await assertPendingPromotion(populated,catalog,admin,context);
    if (polyglotEnabled) await qualifyPreviewCatalog(populated,true,{auth,admin,context,peer});
    await populated.migration.query(`UPDATE secureshop_auth.assessment_objectives
      SET label='Instructor V06 label',configuration_source='instructor',qualification='pending' WHERE objective_id=$1`, [ID]);
    await populated.migration.query(`UPDATE workshop_platform.objectives
      SET label='Instructor V06 lesson',hint_content=$3::jsonb,solution_content=$4::jsonb,
        hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,
    [curriculum.WORKSHOP_KEY, ID, JSON.stringify({ title: 'Retained V06 hint', hints: ['custom'] }),
      JSON.stringify({ title: 'Retained V06 solution', examples: [] })]);
    await populated.migration.query(`UPDATE workshop_platform.objectives SET label='Retained sibling'
      WHERE workshop_key=$1 AND objective_id=$2`, [curriculum.WORKSHOP_KEY, sibling]);
    const own = await assessment(populated.migration),
      lesson = await content(populated.migration), siblingBefore = await content(populated.migration, sibling);
    const preservedBefore = await snapshot(populated.migration);
    await seedBoth(populated.migration);
    assert.deepEqual(await assessment(populated.runtime), own);
    assert.deepEqual(await content(populated.runtime), lesson);
    assert.deepEqual(await content(populated.runtime, sibling), siblingBefore);
    assert.ok((await defaults(populated.runtime)).filter(row => ['label','hint_content','solution_content'].includes(row.field_name))
      .every(row => row.provenance_state === 'custom'));
    const preservedAfter = await snapshot(populated.migration);
    for (const name of ['secureshop_auth.assessment_configuration',
      'secureshop_auth.assessment_configuration_history', 'secureshop_auth.assessment_judgments',
      'secureshop_auth.assessment_completions', 'secureshop_auth.assessment_contributions',
      'secureshop_auth.assessment_retries']) assert.deepEqual(preservedAfter[name], preservedBefore[name]);
    await assert.rejects(catalog.set(admin.context, { objectiveId: ID, enabled: true, expectedRevision: '7' }),
      { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
    assert.deepEqual(await seedSecureShopAssessmentDefaults(populated.migration), { inserted: 0 });
    assert.equal((await seedWorkshopPlatform(populated.migration)).changed, false);
    assert.deepEqual(await snapshot(populated.migration), preservedAfter);
    for (const store of [fresh, populated]) {
      assert.deepEqual(await migrate(store.migration, DIRECTORIES.IDENTITY_FRESH), []);
      assert.deepEqual((await store.migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
        store.manifest);
    }
  });

// Controlled seed-history rows only; never actual model/Judge or execution proof.
async function insertControlledCatalogHistory({pool,context,objectiveId,fixture}){
  const shopUserId=(await pool.query('SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',[context.principalId])).rows[0].shop_user_id;
  const parent=randomUUID(),child=randomUUID();
  for(const [evaluationId,verdict,disposition] of [[parent,'pass','awarded'],[child,'fail','denied']]){
    const result=JSON.stringify({verdict,fixture,actualModel:false,actualJudge:false});
    await pool.query(`INSERT INTO secureshop_auth.assessment_judgments
      (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,
       evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
      VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop',$14,'fixture-only-v1',$7,$8,0,'vuln',
        $14,$9,0,$10,$11,$12::jsonb,$13,clock_timestamp())`,
    [context.tenantId,context.principalId,evaluationId,shopUserId,JSON.stringify({fixture:'catalog-preservation'}),objectiveId,
      sha(evaluationId),randomUUID(),`fixture:${evaluationId}`,verdict,disposition,result,sha(result),fixture]);
  }
  await pool.query('INSERT INTO secureshop_auth.assessment_completions(tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)',[context.tenantId,context.principalId,objectiveId,parent]);
  await pool.query('INSERT INTO secureshop_auth.assessment_contributions(tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)',[context.tenantId,context.principalId,parent]);
  await pool.query('INSERT INTO secureshop_auth.assessment_retries(tenant_id,principal_id,parent_id,child_id) VALUES($1,$2,$3,$4)',[context.tenantId,context.principalId,parent,child]);
}

async function assertPendingPromotion(store,catalog,admin,context){
  const pool=store.migration;
  await pool.query(`UPDATE secureshop_auth.assessment_objectives SET label='Retained V06 instructor wording',
    qualification='pending',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1`,[ID,PREDECESSOR_SHA,PREDECESSOR]);
  await insertControlledCatalogHistory({pool,context,objectiveId:ID,fixture:'v06-catalog-preservation'});
  const prior=await assessment(store.runtime),before=await snapshot(pool);
  assert.equal(before['secureshop_auth.assessment_judgments'].length,2);assert.equal(before['secureshop_auth.assessment_completions'].length,1);
  assert.equal(before['secureshop_auth.assessment_contributions'].length,1);assert.equal(before['secureshop_auth.assessment_retries'].length,1);
  await assert.rejects(catalog.set(admin.context,{objectiveId:ID,enabled:true,expectedRevision:'7'}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
  assert.deepEqual(await snapshot(pool),before);
  await seedSecureShopAssessmentDefaults(pool);
  assert.deepEqual(await assessment(store.runtime),{...prior,qualification:'native-browser-judge',source_sha256:sha(source),source_document:JSON.parse(source)});
  const after=await snapshot(pool);
  for(const table of Object.keys(before).filter(name=>name!=='secureshop_auth.assessment_objectives'))assert.deepEqual(after[table],before[table],table);
  assert.deepEqual(after['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==ID),before['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==ID));
  assert.deepEqual(await seedSecureShopAssessmentDefaults(pool),{inserted:0});assert.equal((await seedWorkshopPlatform(pool)).changed,false);assert.deepEqual(await snapshot(pool),after);
  for(const override of [{source_sha256:'f'.repeat(64)},
    {source_document:{...JSON.parse(PREDECESSOR),label:'Custom source'}},
    {source_document:{...JSON.parse(PREDECESSOR),extra:true}},{qualification:'native-model'}]){
    const changed={qualification:'pending',source_sha256:PREDECESSOR_SHA,source_document:JSON.parse(PREDECESSOR),...override};
    await pool.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,source_sha256=$3,source_document=$4::jsonb WHERE objective_id=$1',[ID,changed.qualification,changed.source_sha256,JSON.stringify(changed.source_document)]);
    const retained=await snapshot(pool);await seedSecureShopAssessmentDefaults(pool);await seedSecureShopAssessmentDefaults(pool);assert.deepEqual(await snapshot(pool),retained);
  }
  await pool.query("UPDATE secureshop_auth.assessment_objectives SET qualification='pending',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",[ID,PREDECESSOR_SHA,PREDECESSOR]);
  await seedSecureShopAssessmentDefaults(pool);
}

function exactTraceIdentity(value) {
  return value.provider === 'native-controlled-provider' && value.model === 'native-controlled-model'
    && value.mocked === false;
}

// Actual PostgreSQL repositories and source readers are exercised below. The
// persisted model-shaped trace is synthetic and can only qualify structural joins.
test('native V06 assessment binds original PG turn/trace/effect/serve and fences sibling/reset/recovery',
  { skip: !enabled, timeout: 180000 }, async t => {
    const identity = await open('IDENTITY_ASSESSMENT', t), agents = await open('AGENTS', t),
      review = await open('REVIEW', t);
    await seedBoth(identity.migration);
    await seedSecureShopStandaloneDefaults(identity.migration, { hashPassword: value => bcrypt.hash(value, 4) });
    const auth = createSecureShopStandaloneAuthService({ repository:
      createSecureShopStandaloneAuthRepository({ pool: identity.runtime }) });
    const login = await auth.login({ username: 'student_customer', password: 'student123' });
    const context = await auth.establishTenantContext(login.context);
    const launches = createSecureShopLaunchRepository(identity.runtime);
    const issued = await launches.issueOrRenew({ platformOwnerId: context.ownerId,
      platformSessionId: context.sessionId, expiresAt: context.expiresAt, shopPrincipal: context });
    const scope = Object.freeze({ ...createLaunchScope(issued.binding),
      shopUserId: context.shopUserId, role: 'customer' });
    const persona = Object.freeze({ id: context.shopUserId, role: 'customer' });
    const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '1' });
    const targetId = randomUUID(), sceneId = randomUUID(), grantId = randomUUID();
    const target = createSceneBinding({ ...scope, targetId }, { sceneId, sceneGeneration: 1, grantId,
      execution: scope, withLease: work => work() });
    let active = true;
    const current = async value => { if (!active || value.targetId !== targetId)
      throw Object.assign(Error('reset'), { code: 'BOUND_UPLOAD_AUTHORITY_LOST' }); };
    await review.runtime.query(`INSERT INTO secureshop_review.product_targets
      (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
       original_platform_session_id,own_merchant_id,source_count,source_sha256)
      VALUES($1,$2,$3,$4,$5,$6,$7,1,decode($8,'hex'))`,
    [targetId, scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId,
      scope.platformSessionId, scope.shopUserId, '1'.repeat(64)]);
    await review.runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
      (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
       original_platform_owner_id,original_platform_session_id) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`,
    [grantId, sceneId, targetId, scope.launchId, scope.scenarioId, scope.generation,
      scope.platformOwnerId, scope.platformSessionId]);
    const journal = createSecureShopBoundUploadRepository(review.runtime, { checkCurrent: current,
      assertSceneGrant: async raw => assert.equal((await review.runtime.query(`SELECT secureshop_review.assert_scene_execution_grant
        ($1,$2,$3,$4,$5,$6,$7,$8,$9) AS allowed`, [raw.grantId, raw.sceneId, raw.sceneGeneration,
        raw.targetId, raw.launchId, raw.scenarioId, raw.generation, raw.platformOwnerId,
        raw.platformSessionId])).rows[0].allowed, true), checkCleanupAuthority: async () => {} });
    const siblingScope = { ...scope, targetId: randomUUID(), launchId: randomUUID(),
      scenarioId: randomUUID(), platformOwnerId: scope.platformOwnerId + 1000,
      platformSessionId: scope.platformSessionId + 1000, shopUserId: scope.shopUserId + 1000,
      sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(),
      personaSessionId: randomUUID(), personaAuthorityVersion: '1', mode: 'vuln',
      modeGeneration: 2, modeStamp: 'c'.repeat(64) };
    delete siblingScope.role;
    await review.runtime.query(`INSERT INTO secureshop_review.product_targets
      (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
       original_platform_session_id,own_merchant_id,source_count,source_sha256)
      VALUES($1,$2,$3,$4,$5,$6,$7,1,decode($8,'hex'))`,
    [siblingScope.targetId, siblingScope.launchId, siblingScope.scenarioId, siblingScope.generation,
      siblingScope.platformOwnerId, siblingScope.platformSessionId, siblingScope.shopUserId, '2'.repeat(64)]);
    await review.runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
      (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
       original_platform_owner_id,original_platform_session_id) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`,
    [siblingScope.grantId, siblingScope.sceneId, siblingScope.targetId, siblingScope.launchId,
      siblingScope.scenarioId, siblingScope.generation, siblingScope.platformOwnerId,
      siblingScope.platformSessionId]);
    const siblingJournal = createSecureShopBoundUploadRepository(review.runtime, {
      checkCurrent: async value => assert.equal(value.targetId, siblingScope.targetId),
      assertSceneGrant: async () => {}, checkCleanupAuthority: async () => {} });
    const siblingRaw = { operationId: randomUUID(), uploadRequestId: randomUUID(), storageKey: randomUUID(),
      scope: siblingScope, request: { kind: 'avatar', scopeId: siblingScope.shopUserId,
        originalFilename: 'sibling.js', declaredMime: 'text/javascript', public: true,
        byteCount: 9, bodySha256: 'd'.repeat(64) } };
    const siblingAdmission = await siblingJournal.claim(siblingRaw),
      siblingBase = `operations/${siblingAdmission.storageKey}/avatars/${siblingScope.shopUserId}`;
    const siblingEffect = await siblingJournal.recordEffect(siblingAdmission, { effectId: randomUUID(),
      outcome: 'completed', denialCode: null, quarantineRequired: false, file: {
        storageKey: siblingAdmission.storageKey, originalFilename: 'sibling.js', cleanedFilename: 'sibling.js',
        declaredMime: 'text/javascript', byteCount: 9, bodySha256: 'd'.repeat(64),
        baseVirtualPath: siblingBase, resolvedVirtualPath: `${siblingBase}/sibling.js`,
        storedVirtualPath: `${siblingBase}/aabbccdd-sibling.js`, isTraversal: false } });
    await siblingJournal.recordServe(siblingAdmission, { serveId: randomUUID(),
      receiptPath: '/assets/sibling_receipt', status: 200, contentType: 'text/javascript',
      contentDisposition: 'inline; filename="sibling.js"', nosniffPresent: false,
      responseByteCount: 9, responseSha256: 'd'.repeat(64) }, siblingEffect);
    const siblingBefore = (await review.runtime.query(`SELECT to_jsonb(x) row FROM (
      SELECT 'admission' kind,to_jsonb(a) value FROM secureshop_review.bound_upload_admissions a WHERE operation_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e WHERE operation_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s WHERE operation_id=$1
    ) x ORDER BY kind`, [siblingAdmission.operationId])).rows;

    const requestId = randomUUID(), operationId = randomUUID(), storageKey = randomUUID();
    const sourceBytes = Buffer.from('<svg>native</svg>');
    const uploadRoot = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-v06-upload-assessment-')));
    t.after(async () => fs.rm(uploadRoot, { recursive: true, force: true }));
    const raw = { operationId, uploadRequestId: requestId, storageKey, scope: { ...scope,
      targetId, sceneId, sceneGeneration: 1, grantId, personaSessionId: personaSession.sessionId,
      personaAuthorityVersion: personaSession.authorityVersion, mode: 'vuln', modeGeneration: 2,
      modeStamp: 'a'.repeat(64) }, request: { kind: 'avatar', scopeId: scope.shopUserId,
      originalFilename: 'native-proof.html', declaredMime: 'text/html', public: true,
      byteCount: sourceBytes.length, bodySha256: sha(sourceBytes) } };
    delete raw.scope.role;
    const admission = await journal.claim(raw), base = `operations/${storageKey}/avatars/${scope.shopUserId}`;
    const effect = await journal.recordEffect(admission, { effectId: randomUUID(), outcome: 'completed',
      denialCode: null, quarantineRequired: false, file: { storageKey, originalFilename: raw.request.originalFilename,
        cleanedFilename: raw.request.originalFilename, declaredMime: raw.request.declaredMime,
        byteCount: raw.request.byteCount, bodySha256: raw.request.bodySha256, baseVirtualPath: base,
        resolvedVirtualPath: `${base}/${raw.request.originalFilename}`,
        storedVirtualPath: `${base}/12ab34cd-native-proof.html`, isTraversal: false } });
    const serve = await journal.recordServe(admission, { serveId: randomUUID(), receiptPath: '/assets/native_receipt',
      status: 200, contentType: 'text/html', contentDisposition: 'inline; filename="native-proof.html"',
      nosniffPresent: false, responseByteCount: sourceBytes.length, responseSha256: sha(sourceBytes) }, effect);
    const sourcePath = path.join(uploadRoot, effect.file.storedVirtualPath);
    await fs.mkdir(path.dirname(sourcePath), { recursive: true });
    await fs.writeFile(sourcePath, sourceBytes, { flag: 'wx', mode: 0o600 });

    const conversations = createBoundConversationsRepository({ pool: agents.runtime, queue: (_id, work) => work() });
    const sourceSession = randomUUID(), assessmentSession = randomUUID();
    for (const [id, purpose] of [[sourceSession, UPLOAD_PURPOSE], [assessmentSession, 'persona_inbox']]) {
      await conversations.createPendingBoundSession({ id, binding: scope, purpose });
      assert.equal(await conversations.activateBoundSession(id, scope, purpose), true);
    }
    const originalEnvelope = JSON.stringify({ version: 1, message: 'Upload my synthetic avatar.',
      attachment: { filename: raw.request.originalFilename, mime: raw.request.declaredMime,
        byteCount: raw.request.byteCount, bodySha256: raw.request.bodySha256, public: true },
      bindingSha256: admission.bindingSha256, operationId });
    const toolResult = { content: [{ type: 'text', text: JSON.stringify({ ok: true, kind: 'avatar',
      filename: raw.request.originalFilename, size_bytes: sourceBytes.length,
      asset_url: 'http://127.0.0.2:9083/assets/native_receipt' }) }],
      _meta: { operationId, effectId: effect.effectId } };
    const ids = Array.from({ length: 6 }, () => randomUUID()), sourceRun = randomUUID();
    const ownerKey = JSON.stringify(['SecureShopBoundConversation', sourceSession]);
    const effectKey = `${requestId}:${JSON.stringify([1, 'native-call', 'uploads.upload_avatar'])}`;
    const trace = (index, value) => ({ event_id: ids[index], session_id: sourceSession,
      latency_ms: 1, tokens_in: 0, tokens_out: 0, policy_violation: null, ...value });
    const model = { model: 'native-controlled-model', mocked: false };
    const traces = [trace(0, { step: 1, actor: 'supervisor', kind: 'model_decision',
      provider: 'native-controlled-provider', params_json: JSON.stringify({ decision: 'tool_use',
        toolCalls: [{ id: 'native-call', name: 'uploads.upload_avatar', args: {} }] }),
      result_json: JSON.stringify(model) }), trace(1, { step: 1, actor: 'supervisor→task',
      kind: 'local_tool_call', agent_ns: 'uploads', tool_name: 'upload_avatar', params_json: '{}' }),
    trace(2, { step: 1, actor: 'task→supervisor', kind: 'local_tool_result', agent_ns: 'uploads',
      tool_name: 'upload_avatar', result_json: JSON.stringify(toolResult) }),
    trace(3, { step: 2, actor: 'supervisor', kind: 'model_decision', provider: 'native-controlled-provider',
      result_json: JSON.stringify({ ...model, decision: 'final', text: 'Saved.', stopReason: 'end_turn' }) }),
    trace(4, { step: 2, actor: 'supervisor', kind: 'final' }),
    trace(5, { step: 2, actor: 'supervisor', kind: 'terminal', provider: 'native-controlled-provider',
      result_json: JSON.stringify({ ...model, stopReason: 'end_turn', steps: 2, hops: 1 }) })];
    await conversations.appendTraces(sourceSession, scope, traces, UPLOAD_PURPOSE);
    const turn = { stopReason: 'end_turn', text: 'Saved.', steps: 2, hops: [{ step: 1,
      tool: 'uploads.upload_avatar', params: {}, result: toolResult, latencyMs: 1, error: null,
      policyViolation: null }], taskMetadata: { boundUpload: { version: 1, originalEnvelope,
      operationId, uploadRequestId: requestId, effectId: effect.effectId, outcome: 'completed',
      assetCapabilityExpiresAt: Date.now() + 60000,
      assetUrl: 'http://127.0.0.2:9083/assets/native_receipt', traceEventIds: ids,
      graphEffect: { runId: sourceRun, ownerKey, generation: '0', effectKey, status: 'completed',
        step: 1, callId: 'native-call' } } } };
    const request = createTurnRequest({ sessionId: sourceSession, requestId, binding: scope,
      message: originalEnvelope });
    await agents.runtime.query(`INSERT INTO secureshop_agents.turn_requests
      (session_id,request_id,request_hash,request_version,claim_id,status)
      VALUES($1,$2,$3,$4,$5,'started')`, [sourceSession, requestId, request.hash, request.version, randomUUID()]);
    await agents.runtime.query(`UPDATE secureshop_agents.turn_requests SET status='completed',result_json=$3,
      finished_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2`, [sourceSession, requestId, turn]);
    await identity.runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [ownerKey]);
    await identity.runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
      VALUES($1,$2,0,'completed',clock_timestamp())`, [sourceRun, ownerKey]);
    await identity.runtime.query(`INSERT INTO graph_runtime.effects(owner_key,generation,effect_key,run_id,status)
      VALUES($1,0,$2,$3,'completed')`, [ownerKey, effectKey, sourceRun]);

    const turnReader = createV06UploadTurnReader({ pool: agents.runtime });
    const assets = createSecureShopBoundUploadAssetRepository(review.runtime);
    let byteReads = 0;
    const readOwnedAsset = createSecureShopUploadAssetReader({ environment: {
      SECURESHOP_UPLOAD_ROOT: uploadRoot } });
    const sourceReader = createV06UploadSourceReader({ assets, assertCurrent: admission => current(admission.scope),
      read: async file => { byteReads++; return readOwnedAsset(file); } });
    const row = await turnReader.readUploadRequest({ sessionId: sourceSession, requestId,
      binding: scope, purpose: UPLOAD_PURPOSE });
    const retained = await sourceReader.read({ scope, persona, personaSession, operationId,
      effectId: effect.effectId, target, mode: { featureId: 'uploads', mode: 'vuln', generation: 2,
        modeStamp: 'a'.repeat(64) } });
    const storedTraces = await conversations.getTraceEvents(sourceSession, scope, ids, UPLOAD_PURPOSE);
    const graphEffect = (await identity.runtime.query(`SELECT e.run_id,e.owner_key,e.generation::text,
      e.effect_key,e.status,r.status AS run_status,o.generation::text AS live_generation
      FROM graph_runtime.effects e JOIN graph_runtime.runs r USING(run_id)
      JOIN graph_runtime.owners o ON o.owner_key=e.owner_key WHERE e.run_id=$1`, [sourceRun])).rows[0];
    const candidate = buildUploadCandidate({ binding: scope, personaSession, row, retained,
      traces: storedTraces, graphEffect, qualifyModel: exactTraceIdentity });
    assert.equal(candidate.objectiveId, ID); assert.equal(byteReads, 1);
    assert.equal(UPLOAD_RUBRIC.version, 'secureshop-upload-extension-bypass-v3-layered');
    for (const evidence of candidate.evidence.slice(1)) assert.ok(Buffer.byteLength(evidence.content) <= 1000);
    await fs.writeFile(sourcePath, Buffer.alloc(sourceBytes.length, 0x78));
    await assert.rejects(sourceReader.read({ scope, persona, personaSession, operationId,
      effectId: effect.effectId, target, mode: { featureId: 'uploads', mode: 'vuln', generation: 2,
        modeStamp: 'a'.repeat(64) } }), /UPLOAD_ASSET_BYTES_CHANGED/);
    await fs.writeFile(sourcePath, sourceBytes);
    assert.deepEqual(await turnReader.readUploadRequest({ sessionId: sourceSession, requestId,
      binding: { ...scope, platformOwnerId: scope.platformOwnerId + 1 }, purpose: UPLOAD_PURPOSE }), null);

    // Fixture-local admission exercises canonical retained-packet/recovery joins.
    // It does not alter production catalog source and is destroyed with the store.
    await identity.migration.query(`UPDATE secureshop_auth.assessment_objectives
      SET qualification='native-model',is_enabled=true WHERE objective_id=$1`, [ID]);
    const modeRow = (await identity.runtime.query(`SELECT mode,generation,revision::text FROM secureshop_auth.tenant_modes
      WHERE tenant_id=$1 AND principal_id=$2`, [context.tenantId, context.principalId])).rows[0];
    const publication = { mode: modeRow.mode, generation: modeRow.generation,
      modeStamp: sha(JSON.stringify(['shop-tenant-mode-v1', context.tenantId, context.principalId,
        modeRow.generation, modeRow.revision, modeRow.mode])) };
    const packet = prepareJudgeInput({ rubric: UPLOAD_RUBRIC, ...candidate });
    assert.equal(packet.evidenceError, undefined);
    const assessmentOwner = JSON.stringify(['SecureShopBoundConversation', assessmentSession]);
    const assessmentRun = randomUUID(), evaluationId = randomUUID();
    await identity.runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [assessmentOwner]);
    await identity.runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
      VALUES($1,$2,0,'completed',clock_timestamp())`, [assessmentRun, assessmentOwner]);
    const execution = { tenantId: context.tenantId, principalId: context.principalId,
      shopUserId: context.shopUserId, membershipVersion: context.membershipVersion,
      scope: { launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation,
        platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId },
      personaSessionId: personaSession.sessionId, personaAuthorityVersion: personaSession.authorityVersion,
      role: 'customer', runId: assessmentRun, ownerKey: assessmentOwner, ownerGeneration: '0' };
    const unavailable = { verdict: 'unavailable', errorCode: 'JUDGE_TIMEOUT',
      explanation: 'Controlled unavailable fixture; no Judge or model call.' };
    await identity.runtime.query(`INSERT INTO secureshop_auth.assessment_judgments
      (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
       rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,
       owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,0,
       'unavailable','not_pass',$18,$19,clock_timestamp())`, [context.tenantId, context.principalId,
      evaluationId, context.shopUserId, execution, ID, UPLOAD_RUBRIC.family, UPLOAD_RUBRIC.scenario,
      UPLOAD_RUBRIC.version, packet.evidenceDigest, assessmentRun, publication.generation,
      publication.mode, publication.modeStamp, packet.packet, JUDGE_VERSION, assessmentOwner,
      unavailable, sha(JSON.stringify(unavailable))]);

    const token = { snapshot: { version: 1, featureId: 'uploads', policyVersion: POLICIES.uploads,
      mode: 'vuln', generation: 2, modeStamp: 'a'.repeat(64), scope: execution.scope },
      async assertCurrent() { if (!active) throw Error('reset'); }, async assertCurrentAtEffect() { if (!active) throw Error('reset'); } };
    const personaAuthority = { capture(input) { return { binding: { ...input.scope, personaId: input.personaId,
      role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      async assertRemoteAdmission() { if (!active) throw Error('reset'); }, async withCrossStoreEffect(work) { return work({}); } }; } };
    const assessment = createV06UploadAssessment({ identityPool: identity.runtime, agentsPool: agents.runtime,
      launches,
      conversationRepository: conversations, coordinator: { async run() { throw Error('unexpected assessment execution'); } },
      journal: { ...turnReader, async claim() { throw Error('unexpected claim'); }, async complete() {}, async markUncertain() {} },
      personaAuthority, personaBindings: { async capture() { return {}; } }, scenes: { async readRetained() { return target; } },
      modeAuthority: { async capture() { return token; }, assertToken(value) { return value; } }, sourceReader,
      receipts: { async beginEvaluation() { throw Error('unexpected receipt'); }, async recordVerdict() {} },
      progress: { async getGeneration() { return publication.generation; }, async getEvaluationScope() { return publication; } },
      publicationModes: { async getEvaluationScope() { return publication; } },
      async judge() { throw Error('No controlled Judge may run'); }, qualifyModel: exactTraceIdentity });
    const guard = await assessment.assertRetainedPacket({ packet: packet.packet, scope,
      persona, personaSession });
    await guard.assertCurrent();

    const bootstrap = async () => ({ bearer: 'controlled-bearer', persona: { token: 'controlled-persona' } });
    let controlledJudgeCalls = 0;
    const leasePool = new Pool({ connectionString: urls('IDENTITY_ASSESSMENT').runtime, max: 2,
      statement_timeout: 20000, lock_timeout: 3000 });
    t.after(async () => leasePool.end());
    const runLedger = createPostgresRunLedger(identity.runtime, { leasePool });
    const recovery = createSecureShopAssessmentRecovery({ identityPool: identity.runtime, authService: auth,
      bootstrap, launches: { async resolveCapability() { return scope; }, assertCurrent: value => launches.assertCurrent(value) },
      personaAuth: { async authenticateBoundToken() { return { user: persona,
        sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion }; } },
      personaAuthority, uploadAssessment: assessment,
      coordinatorFactory: family => { assert.equal(family, 'SecureShopBoundConversation');
        return createRunCoordinator({ family, ledger: runLedger }); },
      async judge(input) { controlledJudgeCalls++; assert.equal(prepareJudgeInput(input).packet, packet.packet);
        assert.equal(input.execution.runId, assessmentRun); return { family: UPLOAD_RUBRIC.family,
          scenario: UPLOAD_RUBRIC.scenario, objectiveId: ID, rubricVersion: UPLOAD_RUBRIC.version,
          mode: 'vuln', evidenceDigest: packet.evidenceDigest, runId: assessmentRun,
          judgeVersion: JUDGE_VERSION, verdict: 'unavailable', errorCode: 'JUDGE_TIMEOUT', criteria: [],
          provider: null, model: null, explanation: 'Controlled retry persistence; no genuine Judge or credit.' }; } });
    // Reuse the canonical conversations and five stores for exact historical v2 GETs.
    // The controlled semantic pass is grading_unqualified: no completion or credit.
    for (const historicalVerdict of ['pass', 'fail', 'unavailable']) {
      const historicalSourceSession = sourceSession, historicalAssessmentSession = assessmentSession;
      const historicalRequestId = randomUUID(), historicalOperation = randomUUID(), historicalStorage = randomUUID();
      const historicalAdmission = await journal.claim({...raw, operationId: historicalOperation,
        uploadRequestId: historicalRequestId, storageKey: historicalStorage});
      const historicalBase = `operations/${historicalStorage}/avatars/${scope.shopUserId}`;
      const historicalEffect = await journal.recordEffect(historicalAdmission, {effectId: randomUUID(),
        outcome: 'completed', denialCode: null, quarantineRequired: false, file: {...effect.file,
          storageKey: historicalStorage, baseVirtualPath: historicalBase,
          resolvedVirtualPath: `${historicalBase}/${raw.request.originalFilename}`,
          storedVirtualPath: `${historicalBase}/12ab34cd-native-proof.html`}});
      const historicalPath = path.join(uploadRoot, historicalEffect.file.storedVirtualPath);
      await fs.mkdir(path.dirname(historicalPath), {recursive: true});
      await fs.writeFile(historicalPath, sourceBytes, {flag: 'wx', mode: 0o600});
      const historicalServe = await journal.recordServe(historicalAdmission, {serveId: randomUUID(),
        receiptPath: `/assets/native_${historicalOperation}`, status: 200, contentType: 'text/html',
        contentDisposition: 'inline; filename="native-proof.html"', nosniffPresent: false,
        responseByteCount: sourceBytes.length, responseSha256: sha(sourceBytes)}, historicalEffect);
      const historicalRetained = {admission: historicalAdmission, effect: historicalEffect, serve: historicalServe};
      const historicalSourceOwner = ownerKey, historicalSourceRun = randomUUID();
      const historicalIds = ids.map(() => randomUUID());
      const historicalEnvelope = JSON.stringify({...JSON.parse(originalEnvelope),
        bindingSha256: historicalAdmission.bindingSha256, operationId: historicalOperation});
      const historicalToolResult = structuredClone(toolResult);
      historicalToolResult.content[0].text = JSON.stringify({...JSON.parse(toolResult.content[0].text),
        asset_url: `http://127.0.0.2:9083${historicalServe.receiptPath}`});
      historicalToolResult._meta = {operationId: historicalOperation, effectId: historicalEffect.effectId};
      const historicalTraces = traces.map((value, index) => ({...value,
        event_id: historicalIds[index], session_id: historicalSourceSession}));
      historicalTraces[2].result_json = JSON.stringify(historicalToolResult);
      await conversations.appendTraces(historicalSourceSession, scope, historicalTraces, UPLOAD_PURPOSE);
      const historicalTurn = structuredClone(turn);
      historicalTurn.hops[0].result = historicalToolResult;
      const historicalEffectKey = `${historicalRequestId}:${JSON.stringify([1, 'native-call', 'uploads.upload_avatar'])}`;
      Object.assign(historicalTurn.taskMetadata.boundUpload, {traceEventIds: historicalIds,
        originalEnvelope: historicalEnvelope, operationId: historicalOperation,
        uploadRequestId: historicalRequestId, effectId: historicalEffect.effectId,
        assetUrl: `http://127.0.0.2:9083${historicalServe.receiptPath}`,
        graphEffect: {...turn.taskMetadata.boundUpload.graphEffect,
          runId: historicalSourceRun, ownerKey: historicalSourceOwner, effectKey: historicalEffectKey}});
      const historicalRequest = createTurnRequest({sessionId: historicalSourceSession, requestId: historicalRequestId,
        binding: scope, message: historicalEnvelope});
      await agents.runtime.query(`INSERT INTO secureshop_agents.turn_requests
        (session_id,request_id,request_hash,request_version,claim_id,status)
        VALUES($1,$2,$3,$4,$5,'started')`,
      [historicalSourceSession, historicalRequestId, historicalRequest.hash, historicalRequest.version, randomUUID()]);
      await agents.runtime.query(`UPDATE secureshop_agents.turn_requests SET status='completed',result_json=$3,
        finished_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2`,
      [historicalSourceSession, historicalRequestId, historicalTurn]);
      await identity.runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
        VALUES($1,$2,0,'completed',clock_timestamp())`, [historicalSourceRun, historicalSourceOwner]);
      await identity.runtime.query(`INSERT INTO graph_runtime.effects(owner_key,generation,effect_key,run_id,status)
        VALUES($1,0,$2,$3,'completed')`, [historicalSourceOwner, historicalEffectKey, historicalSourceRun]);
      const historicalRow = await turnReader.readUploadRequest({sessionId: historicalSourceSession,
        requestId: historicalRequestId, binding: scope, purpose: UPLOAD_PURPOSE});
      const historicalGraph = {...graphEffect, run_id: historicalSourceRun, owner_key: historicalSourceOwner, effect_key: historicalEffectKey};
      const historicalPacket = prepareJudgeInput({rubric: HISTORICAL_V2_RUBRIC,
        ...buildRetainedUploadCandidate({binding: scope, personaSession, row: historicalRow,
          retained: historicalRetained, traces: historicalTraces, graphEffect: historicalGraph, qualifyModel: exactTraceIdentity,
          receiptVersion: HISTORICAL_V2_RUBRIC.version})});
      assert.ok(historicalPacket.packet && !historicalPacket.evidenceError);
      const historicalEvaluation = randomUUID(), historicalRun = randomUUID();
      const historicalOwner = JSON.stringify(['SecureShopBoundConversation', historicalAssessmentSession]);
      const historicalExecution = {...execution, runId: historicalRun, ownerKey: historicalOwner};
      await identity.runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
        VALUES($1,$2,0,'completed',clock_timestamp())`, [historicalRun, historicalOwner]);
      const historicalResult = {verdict: historicalVerdict,
        ...(historicalVerdict === 'unavailable' ? {errorCode: 'JUDGE_TIMEOUT'} : {}),
        explanation: 'Controlled immutable historical v2 observation; no genuine Judge or credit.'};
      const disposition = historicalVerdict === 'pass' ? 'grading_unqualified' : 'not_pass';
      const serialized = JSON.stringify(historicalResult);
      await identity.runtime.query(`INSERT INTO secureshop_auth.assessment_judgments
        (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
         rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,
         owner_generation,verdict,disposition,result_json,result_digest,result_serialized,evaluated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,0,$18,$19,$20,$21,$22,clock_timestamp())`,
      [context.tenantId, context.principalId, historicalEvaluation, context.shopUserId, historicalExecution,
        ID, HISTORICAL_V2_RUBRIC.family, HISTORICAL_V2_RUBRIC.scenario, HISTORICAL_V2_RUBRIC.version,
        historicalPacket.evidenceDigest, historicalRun, publication.generation, publication.mode,
        publication.modeStamp, historicalPacket.packet, JUDGE_VERSION, historicalOwner,
        historicalVerdict, disposition, historicalResult, sha(serialized), serialized]);
      const historicalOutcome = {completed: false, judgment: {
        ...projectJudgment({disposition, result: historicalResult}),
        evaluationId: historicalEvaluation, canRetry: false}};
      const historicalKey = assessmentRequestId(historicalSourceSession, historicalRequestId);
      const historicalAssessmentRequest = createTurnRequest({sessionId: historicalAssessmentSession,
        requestId: historicalKey, binding: scope, message: JSON.stringify([ID,
          {sessionId: historicalSourceSession, requestId: historicalRequestId},
          sha(JSON.stringify([historicalAdmission.bindingSha256, historicalEffect.effectSha256, historicalServe.serveSha256])),
          personaSession, token.snapshot,
          {generation: publication.generation, mode: publication.mode, modeStamp: publication.modeStamp}])});
      await agents.runtime.query(`INSERT INTO secureshop_agents.turn_requests
        (session_id,request_id,request_hash,request_version,claim_id,status)
        VALUES($1,$2,$3,$4,$5,'started')`,
      [historicalAssessmentSession, historicalKey, historicalAssessmentRequest.hash,
        historicalAssessmentRequest.version, randomUUID()]);
      await agents.runtime.query(`UPDATE secureshop_agents.turn_requests SET status='completed',result_json=$3,
        finished_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2`,
      [historicalAssessmentSession, historicalKey, historicalOutcome]);
      const before = await snapshot(identity.runtime);
      const turnBefore = (await agents.runtime.query('SELECT to_jsonb(t) row FROM secureshop_agents.turn_requests t WHERE session_id=$1 ORDER BY request_id',
        [historicalAssessmentSession])).rows;
      const callsBefore = controlledJudgeCalls;
      assert.deepEqual(await assessment.readOutcome({scope, persona, personaSession,
        sessionId: historicalSourceSession, requestId: historicalRequestId}), {...historicalOutcome, replayed: true});
      await assert.rejects(assessment.assertRetainedPacket({packet: historicalPacket.packet, scope, persona, personaSession}),
        {code: 'UPLOAD_ASSESSMENT_UNAVAILABLE'});
      assert.equal((await recovery.list(login.context)).judgments.find(row => row.evaluationId === historicalEvaluation)?.canRetry, false);
      if (historicalVerdict === 'unavailable') await assert.rejects(recovery.retry(login.context,
        {evaluationId: historicalEvaluation}), {code: 'UPLOAD_ASSESSMENT_UNAVAILABLE'});
      assert.equal(controlledJudgeCalls, callsBefore);
      assert.deepEqual(await snapshot(identity.runtime), before);
      assert.deepEqual((await agents.runtime.query('SELECT to_jsonb(t) row FROM secureshop_agents.turn_requests t WHERE session_id=$1 ORDER BY request_id',
        [historicalAssessmentSession])).rows, turnBefore);
    }
    assert.equal((await recovery.list(login.context)).judgments.find(row => row.evaluationId === evaluationId)?.canRetry, true);
    const siblingLogin = await auth.login({ username: 'student_merchant', password: 'student123' });
    await assert.rejects(recovery.list(siblingLogin.context), { code: 'SHOP_ASSESSMENT_STALE' });

    const retried = await recovery.retry(login.context, { evaluationId });
    assert.equal(retried.verdict, 'unavailable'); assert.equal(retried.completed, false);
    assert.equal(retried.replayed, false); assert.equal(controlledJudgeCalls, 1);
    const retryRows = await identity.runtime.query(`SELECT r.parent_id,r.child_id,c.packet,c.run_id,c.owner_key,
      c.execution_json,c.verdict,c.disposition,i.run_id AS retry_run_id,i.execution_json AS retry_execution
      FROM secureshop_auth.assessment_retries r
      JOIN secureshop_auth.assessment_judgments c ON c.tenant_id=r.tenant_id
        AND c.principal_id=r.principal_id AND c.evaluation_id=r.child_id
      JOIN secureshop_auth.assessment_retry_invocations i ON i.tenant_id=r.tenant_id
        AND i.principal_id=r.principal_id AND i.parent_id=r.parent_id
      WHERE r.parent_id=$1`, [evaluationId]);
    assert.equal(retryRows.rowCount, 1); const retryRow = retryRows.rows[0];
    assert.equal(retryRow.packet, packet.packet); assert.equal(retryRow.run_id, assessmentRun);
    assert.equal(retryRow.owner_key, assessmentOwner); assert.notEqual(retryRow.retry_run_id, assessmentRun);
    assert.equal(retryRow.execution_json.runId, retryRow.retry_run_id);
    assert.equal(retryRow.retry_execution.runId, retryRow.retry_run_id);
    assert.equal(retryRow.verdict, 'unavailable'); assert.equal(retryRow.disposition, 'not_pass');
    assert.deepEqual((await identity.runtime.query(`SELECT owner_key,generation::text,status
      FROM graph_runtime.runs WHERE run_id=$1`, [retryRow.retry_run_id])).rows,
    [{ owner_key: assessmentOwner, generation: '0', status: 'completed' }]);

    const previewChecks = polyglotEnabled ? await qualifyNativePreview({t, identity, agents, review, launches, scope, persona, personaSession, target, current, journal, conversations, uploadRoot, publication, context, runLedger}) : null;
    const retryBefore = Number((await identity.runtime.query(`SELECT count(*) n FROM secureshop_auth.assessment_retries
      WHERE parent_id=$1`, [evaluationId])).rows[0].n);
    await identity.runtime.query('UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key=$1', [ownerKey]);
    assert.equal((await recovery.list(login.context)).judgments.find(row => row.evaluationId === evaluationId)?.canRetry, false);
    await assert.rejects(recovery.retry(login.context, { evaluationId }),
      error => ['UPLOAD_ASSESSMENT_UNAVAILABLE','SECURESHOP_FEATURE_MODE_STALE'].includes(error?.code));
    assert.equal(Number((await identity.runtime.query(`SELECT count(*) n FROM secureshop_auth.assessment_retries
      WHERE parent_id=$1`, [evaluationId])).rows[0].n), retryBefore);
    active = false;
    await assert.rejects(guard.assertCurrent());
    await review.migration.query("UPDATE secureshop_review.product_targets SET lifecycle='retired' WHERE target_id=$1", [targetId]);
    assert.deepEqual((await review.runtime.query(`SELECT to_jsonb(x) row FROM (
      SELECT 'admission' kind,to_jsonb(a) value FROM secureshop_review.bound_upload_admissions a WHERE operation_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e WHERE operation_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s WHERE operation_id=$1
    ) x ORDER BY kind`, [siblingAdmission.operationId])).rows, siblingBefore);
    assert.equal(await sourceReader.read({ scope, persona, personaSession, operationId, effectId: effect.effectId,
      target, mode: { featureId: 'uploads', mode: 'vuln', generation: 2, modeStamp: 'a'.repeat(64) } }).catch(() => null), null);
    if (previewChecks) await previewChecks.assertRetired();
    assert.equal(Number((await identity.runtime.query(`SELECT count(*) n FROM secureshop_auth.assessment_completions
      WHERE tenant_id=$1 AND principal_id=$2`, [context.tenantId, context.principalId])).rows[0].n), 0);
    assert.equal(Number((await identity.runtime.query(`SELECT count(*) n FROM secureshop_auth.assessment_contributions
      WHERE tenant_id=$1 AND principal_id=$2`, [context.tenantId, context.principalId])).rows[0].n), 0);
    for (const [name, store] of [['IDENTITY_ASSESSMENT', identity], ['AGENTS', agents], ['REVIEW', review]]) {
      assert.deepEqual(await migrate(store.migration, DIRECTORIES[name]), []);
      assert.deepEqual((await store.migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
        store.manifest);
    }
  });

// V07 remains an optional branch of these same five disposable stores/two tests.
// Model, persona capture and worker are controlled. SQL journals, graph effects,
// files, source reconstruction and canonical assessment persistence are real.
async function qualifyPreviewCatalog(store,populated=false,{auth,admin,context,peer}={}) {
  const row=curriculum.OBJECTIVES.find(value=>value.id===V07);
  assert.equal(row.qualification,'native-browser-judge');assert.equal(row.defaultEnabled,false);
  assert.equal(curriculum.PENDING_OBJECTIVE_IDS.includes(V07),false);
  const document={version:1,id:V07,label:row.text,defaultEnabled:false,qualification:'native-browser-judge'};
  const source=JSON.stringify(document),predecessor=JSON.stringify({...document,qualification:'pending'});
  assert.equal(sha(source),'1dc3738895592d6ddd8ff92a3bb169355d8ef14cd47653a2dfefde2d70cde98e');
  assert.equal(sha(predecessor),'00be7f7921bafa94f62a633575f39e63469369c30d935239a67f41540f238dd8');
  const original=await assessment(store.runtime,V07),lesson=await content(store.runtime,V07);
  assert.equal(original.is_enabled,false);assert.equal(original.qualification,'native-browser-judge');
  assert.equal(original.configuration_source,'checked_in_default');assert.equal(original.source_sha256,sha(source));
  assert.deepEqual(original.source_document,document);assert.equal(lesson.is_enabled,false);assert.equal(lesson.catalog_active,true);
  assert.deepEqual(lesson.hint_content,curriculum.HINTS[V07]);assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[V07]);
  const catalog=createSecureShopAssessmentCatalog({pool:store.runtime,authService:auth});
  if(!populated){
    assert.deepEqual(await require('../fixtures/secureshopV06CandidateCatalog').admitV07DisposableCandidate({
      migration:store.migration,catalog,administratorContext:admin.context,curriculum}),
      {objectiveId:V07,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
    assert.deepEqual(await assessment(store.runtime,V07),original);
  }else{
    const pool=store.migration;
    await pool.query(`UPDATE secureshop_auth.assessment_objectives SET label='Instructor V07',is_enabled=true,
      qualification='pending',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1`,[V07,sha(predecessor),predecessor]);
    await pool.query(`UPDATE workshop_platform.objectives SET label='Instructor preview lesson',is_enabled=true,
      hint_content=$3::jsonb,solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true
      WHERE workshop_key=$1 AND objective_id=$2`,[curriculum.WORKSHOP_KEY,V07,
      JSON.stringify({title:'Retained preview hint',hints:['instructor content']}),JSON.stringify({title:'Retained preview solution',examples:[]})]);
    for(const [tenant,revision,enabled] of [[context.tenantId,7,true],[peer,11,false]]){
      await pool.query(`INSERT INTO secureshop_auth.assessment_configuration
        (tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)`,[tenant,V07,enabled,revision,context.principalId]);
      await pool.query(`INSERT INTO secureshop_auth.assessment_configuration_history
        (tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id) VALUES($1,$2,$3,$4,$5,$6)`,
        [tenant,V07,revision,enabled,context.principalId,context.sessionId]);
    }
    await insertControlledCatalogHistory({pool,context,objectiveId:V07,fixture:'v07-controlled-seed-history-no-model-judge-credit'});
    const prior=await assessment(store.runtime,V07),contentBefore=await content(store.runtime,V07),before=await snapshot(pool);
    const targetRows=table=>before[table].filter(item=>item.row.objective_id===V07);
    assert.equal(targetRows('secureshop_auth.assessment_judgments').length,2);
    assert.equal(targetRows('secureshop_auth.assessment_completions').length,1);
    const ids=targetRows('secureshop_auth.assessment_judgments').map(item=>item.row.evaluation_id);
    assert.equal(before['secureshop_auth.assessment_contributions'].filter(item=>ids.includes(item.row.evaluation_id)).length,1);
    assert.equal(before['secureshop_auth.assessment_retries'].filter(item=>ids.includes(item.row.parent_id)&&ids.includes(item.row.child_id)).length,1);
    await assert.rejects(catalog.set(admin.context,{objectiveId:V07,enabled:true,expectedRevision:'7'}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});assert.deepEqual(await snapshot(pool),before);
    await seedSecureShopAssessmentDefaults(pool);
    assert.deepEqual(await assessment(store.runtime,V07),{...prior,qualification:'native-browser-judge',source_sha256:sha(source),source_document:document});
    assert.deepEqual(await content(store.runtime,V07),contentBefore);
    const after=await snapshot(pool);
    for(const table of Object.keys(before).filter(name=>name!=='secureshop_auth.assessment_objectives'))assert.deepEqual(after[table],before[table],table);
    assert.deepEqual(after['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V07),before['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V07));
    await seedBoth(pool);const seeded=await snapshot(pool);assert.deepEqual(await content(store.runtime,V07),contentBefore);
    for(const table of Object.keys(after).filter(name=>name.startsWith('secureshop_auth.')||name==='workshop_platform.objectives'))assert.deepEqual(seeded[table],after[table],table);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(pool),{inserted:0});assert.equal((await seedWorkshopPlatform(pool)).changed,false);assert.deepEqual(await snapshot(pool),seeded);
    for(const override of [{source_sha256:'f'.repeat(64)},{source_document:{...JSON.parse(predecessor),label:'Custom source'}},
      {source_document:{...JSON.parse(predecessor),extra:true}},{qualification:'native-model'},{configuration_source:'instructor'},
      {configuration_source:'instructor',source_document:{...JSON.parse(predecessor),label:'Instructor owned source'}}]){
      const changed={qualification:'pending',source_sha256:sha(predecessor),source_document:JSON.parse(predecessor),configuration_source:'checked_in_default',...override};
      await pool.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,source_sha256=$3,source_document=$4::jsonb,configuration_source=$5 WHERE objective_id=$1',
        [V07,changed.qualification,changed.source_sha256,JSON.stringify(changed.source_document),changed.configuration_source]);
      const retained=await snapshot(pool);await seedSecureShopAssessmentDefaults(pool);await seedSecureShopAssessmentDefaults(pool);assert.deepEqual(await snapshot(pool),retained);
    }
  }
  const all=await snapshot(store.runtime);await seedBoth(store.migration);assert.deepEqual(await snapshot(store.runtime),all);
}
function nativePersonaAuthority(pool, check) {
  const {withTransaction}=require('../../server/database/postgres');
  return {capture(input) {
    const binding={...createLaunchScope(input.scope),personaId:input.personaId,role:input.role,
      sessionId:input.sessionId,authorityVersion:input.authorityVersion};
    return {binding,assertRemoteAdmission:check,
      withPersonaEffect:work=>withTransaction(pool,async client=>{await check();const value=await work(client);await check();return value;}),
      withCrossStoreEffect:async work=>{await check();const value=await work();await check();return value;}};
  }};
}
async function qualifyPreviewMigration(pool, runtime) {
  const {withTransaction,verifyServer}=require('../../server/database/postgres');
  const all=await readMigrations(DIRECTORIES.AGENTS), name='0112_upload_preview_registry_successor.sql';
  assert.equal(all.at(-1).name,name);
  const prefix=all.filter(row=>row.name<name), successor=all.at(-1);
  assert.equal(prefix.at(-1).name,'0111_admin_user_lookup_registry_successor.sql');
  await withTransaction(pool,async client=>{
    await verifyServer(client); await client.query('SELECT pg_advisory_xact_lock(1886610804,1)');
    await client.query('CREATE SCHEMA dvaia_migrations');
    await client.query('CREATE TABLE dvaia_migrations.ledger(name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())');
    for(const row of prefix){await client.query(executionSql(row));await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',[row.name,row.checksum]);}
    // Fresh tail DDL is independently exercised without populating or committing it.
    await client.query('SAVEPOINT fresh_preview');await client.query(executionSql(successor));
    assert.equal((await client.query(`SELECT count(*)::int n FROM pg_constraint WHERE conname='bound_tool_registry_successor_v35'`)).rows[0].n,1);
    await client.query('ROLLBACK TO SAVEPOINT fresh_preview');
  });
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:901,platformSessionId:902};
  const vals=[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId];
  const old='974d64bf78037ad3de2dbba5a28f277feab87487c13477b8b81b6c11540c8ea1';
  await pool.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
    (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,
     policy_version,enforcement_enabled,registry_sha256) VALUES($1,$2,$3,$4,$5,33,true,decode($6,'hex'))`,[...vals,'435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc']);
  await pool.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
    (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,tool_key,role,allowed)
    VALUES($1,$2,$3,$4,$5,'uploads.upload_avatar','customer',false),($1,$2,$3,$4,$5,'admin.users_search','admin',true)`,vals);
  const overrides=[{toolKey:'admin.users_search',role:'admin',allowed:true},{toolKey:'uploads.upload_avatar',role:'customer',allowed:false}];
  // The historical upgrade evidence, added denial and successor head are one
  // committed transition, as required by the existing deferred commit fence.
  await withTransaction(pool,async client=>{
    await client.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
      (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,
       predecessor_version,successor_version,predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
      VALUES($1,$2,$3,$4,$5,33,34,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,
      [...vals,'435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc',old,JSON.stringify(overrides),JSON.stringify([{toolKey:'admin.user_lookup',role:'admin'}])]);
    await client.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
      (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,tool_key,role,allowed)
      VALUES($1,$2,$3,$4,$5,'admin.user_lookup','admin',false)`,vals);
    await client.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=34,registry_sha256=decode($6,'hex')
      WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3 AND original_platform_owner_id=$4 AND original_platform_session_id=$5`,[...vals,old]);
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
  });
  const tables=['bound_tool_policy_heads','bound_tool_policy_overrides','bound_tool_registry_upgrades','bound_tool_admissions'];
  const snap=async()=>Object.fromEntries(await Promise.all(tables.map(async table=>[table,(await pool.query(`SELECT to_jsonb(t) row FROM secureshop_agents.${table} t ORDER BY to_jsonb(t)::text`)).rows])));
  const before=await snap();assert.equal(before.bound_tool_policy_heads.length,1);assert.equal(before.bound_tool_policy_overrides.length,3);assert.equal(before.bound_tool_registry_upgrades.length,1);
  assert.deepEqual(await migrate(pool,DIRECTORIES.AGENTS),[name]);assert.deepEqual(await snap(),before);
  await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness').assertBoundToolPolicyReadiness(runtime);
  const repository=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
    personaAuthority:nativePersonaAuthority(runtime,async()=>{}),audit:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:runtime})});
  const input={scope,persona:{id:903,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
  const policy=await repository.readPolicy(input);
  assert.equal(policy.registrySha256,require('../../server/services/secureshopBoundAclRegistry').REGISTRY_SHA256);
  assert.equal(policy.version,'35');assert.equal(policy.enforcement,true);
  assert.equal(policy.rows.find(row=>row.toolKey==='uploads.preview_legacy_image').allowed.customer,false);
  assert.equal(policy.rows.find(row=>row.toolKey==='uploads.upload_avatar').allowed.customer,false);
  assert.equal(policy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true);
  const after=await snap();assert.equal(after.bound_tool_registry_upgrades.length,2);
  assert.deepEqual(after.bound_tool_registry_upgrades.find(value=>value.row.successor_version===34),before.bound_tool_registry_upgrades[0]);
  assert.deepEqual(after.bound_tool_registry_upgrades.find(value=>value.row.successor_version===35).row.added_denials,[{toolKey:'uploads.preview_legacy_image',role:'customer'}]);
  assert.deepEqual(await migrate(pool,DIRECTORIES.AGENTS),[]);await repository.readPolicy(input);assert.deepEqual(await snap(),after);
}
async function qualifyNativePreview({t,identity,agents,review,launches,scope,persona,personaSession,target,current,journal:uploads,conversations,uploadRoot,publication,context,runLedger}) {
  const E=require('../../server/services/secureshopV07UploadEvidence');
  const {createV07UploadSourceReader,previewIdentity}=require('../../server/services/secureshopV07UploadSourceReader');
  const {createV07UploadPreviewGraph}=require('../../server/services/secureshopV07UploadPreviewGraph');
  const {requestDigest,ISOLATION}=require('../../sidecars/sandbox-runner/owned-system/upload-preview-contract');
  const {createSecureShopBoundUploadGraph}=require('../../server/services/secureshopBoundUploadGraph');
  const originalFetch=globalThis.fetch;globalThis.fetch=async()=>{throw Error('Native V07 forbids model/network calls');};
  t.after(()=>{globalThis.fetch=originalFetch;});
  const productionCatalog=await assessment(identity.runtime,V07);
  assert.equal(productionCatalog.qualification,'native-browser-judge');assert.equal(productionCatalog.is_enabled,false);
  const catalogAuth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:identity.runtime})});
  const catalogAdmin=await catalogAuth.login({username:'student_admin',password:'student123'});
  const catalogContext=await catalogAuth.establishTenantContext(catalogAdmin.context);assert.equal(catalogContext.tenantId,context.tenantId);
  const catalog=createSecureShopAssessmentCatalog({pool:identity.runtime,authService:catalogAuth});
  assert.deepEqual(await require('../fixtures/secureshopV06CandidateCatalog').admitV07DisposableCandidate({migration:identity.migration,catalog,administratorContext:catalogAdmin.context,curriculum}),
    {objectiveId:V07,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
  assert.deepEqual(await assessment(identity.runtime,V07),productionCatalog);
  // Controlled credential setup satisfies the actual registered-actor admission
  // trigger. No permissive tool-policy repository or invented admission receipt.
  await agents.runtime.query(`INSERT INTO secureshop_agents.bound_actor_identities
    (shop_user_id,username,email,base_role,principal_id,original_platform_owner_id) VALUES($1,$2,$3,$4,$5,$6)`,
    [persona.id,context.username,context.email,'customer',context.principalId,context.principalOwnerId]);
  await agents.runtime.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
    (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role,is_active)
    VALUES($1,$2,$3,$4,$5,$6,'customer',true)`,
    [scope.platformOwnerId,context.tenantId,persona.id,context.principalId,context.principalOwnerId,context.membershipVersion]);
  await agents.runtime.query(`INSERT INTO secureshop_agents.bound_persona_sessions
    (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
     original_platform_session_id,shop_user_id,username,role,email,expires_at,credential_version,standalone_principal_id,
     standalone_session_id,bootstrap_jti,standalone_credential_version,standalone_authority_version,
     bootstrap_persona_authority_version,bootstrap_membership_version)
    VALUES($1,sha256(convert_to($1::uuid::text,'UTF8')),$2,$3,$4,$5,$6,$7,$8,'customer',$9,
     clock_timestamp()+interval '1 hour',1,$10,$6,$11,1,1,1,$12)`,
    [personaSession.sessionId,scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,
      persona.id,context.username,context.email,context.principalId,randomUUID(),context.membershipVersion]);
  let mode='vuln', selected='uploads.upload_avatar',actors=0,workers=0,judges=0;
  const check=()=>current(target), authority=nativePersonaAuthority(agents.runtime,check);
  const modeAuthority={async capture(){const captured=mode;return {snapshot:{version:1,featureId:'uploads',policyVersion:POLICIES.uploads,
    mode:captured,generation:2,modeStamp:sha(captured),scope:createLaunchScope(scope)},async assertCurrent(){await check();assert.equal(mode,captured);},async assertCurrentAtEffect(){await check();assert.equal(mode,captured);}};},assertToken:value=>value};
  const assertUploadCurrent=async admission=>{await check();assert.equal(admission.scope.mode,mode);assert.equal(admission.scope.modeStamp,sha(mode));
    assert.equal(admission.scope.personaSessionId,personaSession.sessionId);assert.equal(admission.scope.shopUserId,persona.id);};
  const journal={...require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents.runtime}),
    ...createV06UploadTurnReader({pool:agents.runtime})};
  const assets=createSecureShopBoundUploadAssetRepository(review.runtime);
  const read=createSecureShopUploadAssetReader({environment:{SECURESHOP_UPLOAD_ROOT:uploadRoot}});
  const policy=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({personaAuthority:authority,
    audit:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents.runtime})});
  const coordinator=createRunCoordinator({family:'SecureShopBoundConversation',ledger:runLedger});
  const provider={async chat(){actors++;return {provider:'native-controlled-provider',model:'native-controlled-model',mocked:false,stop_reason:'tool_use',tool_uses:[{id:`native_${actors}`,name:selected,args:{}}]};},
    async finalResponse(input){actors++;assert.ok(input.messages.some(row=>row.role==='tool'));return {provider:'native-controlled-provider',model:'native-controlled-model',mocked:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled original preview response; no actual model proof.'};}};
  const qualifyModel=row=>row.provider==='native-controlled-provider'&&row.model==='native-controlled-model'&&row.mocked===false;
  const capability=require('../../server/services/secureshopUploadAssetCapability').createSecureShopUploadAssetCapability({secret:'controlled-native-preview-capability-secret-32bytes'});
  const writer=require('../../server/services/secureshopUploadWriter').createSecureShopUploadWriter({environment:{SECURESHOP_UPLOAD_ROOT:uploadRoot}});
  const application=require('../../server/services/secureshopBoundUploadApplication').createSecureShopBoundUploadApplication({effects:uploads,writer,journal:uploads});
  const upload=createSecureShopBoundUploadGraph({launches,conversationRepository:conversations,journal,coordinator,provider,uploadApplication:application,uploadJournal:uploads,
    personaAuthority:authority,modeAuthority,toolPolicyRepository:policy,assetOrigin:'http://127.0.0.2:9083',assetCapability:capability,resolveTarget:async()=>target,
    assertUploadCurrent,verifyEffect:async admission=>{await assertUploadCurrent(admission);return uploads.find(admission);}});
  const sourceReader=createV07UploadSourceReader({identityPool:identity.runtime,agentsPool:agents.runtime,assets,assertCurrent:assertUploadCurrent,read,journal,conversationRepository:conversations,qualifyModel});
  const client={async assertReady(){await check();},async preview(request,{assertCurrent}){
    workers++;await assertCurrent();const fixed=request.mode==='fixed';
    return {version:1,operationId:request.operationId,uploadOperationId:request.uploadOperationId,uploadEffectId:request.uploadEffectId,storageKey:request.storageKey,
      requestSha256:requestDigest(request),bindingSha256:request.bindingSha256,bodySha256:request.bodySha256,mode:request.mode,isolation:ISOLATION,
      runtime:{nodeVersion:'v26.10.0',platform:'linux',arch:'arm64'},decoder:{sharpVersion:'0.35.4',vipsVersion:'8.18.0',logicalWidth:10799,logicalHeight:1,width:1,height:1,pages:1,rawSha256:sha(Buffer.alloc(4)),rawByteCount:4},
      status:fixed?'fixed_reencoded':'executed',scriptSyntaxValid:fixed?null:true,originalInterpreterStarted:!fixed,reencoded:fixed?{format:'png',bodySha256:sha('controlled png'),byteCount:91}:null,
      exitCode:fixed?null:0,timedOut:false,truncated:false,drained:true,workerAttested:true,codeEffectObserved:!fixed,effectSha256:fixed?null:sha('controlled canary, not an execution proof')};}};
  const publicationModes={async getEvaluationScope(){return {...publication,mode};}};
  const preview=createV07UploadPreviewGraph({identityPool:identity.runtime,agentsPool:agents.runtime,launches,conversationRepository:conversations,journal,coordinator,provider,
    personaAuthority:authority,modeAuthority,publicationModes,scenes:{readRetained:async()=>target},sourceReader,client,toolPolicyRepository:policy});
  const subjects=require('../../server/services/secureshopAssessmentSubject').createSecureShopAssessmentSubjects({identityPool:identity.runtime,launches,personaAuthority:authority});
  const personaBindings={async capture(){return {};},async resolveStores(input,execution){return require('../../server/database/postgres/secureshopAssessmentStore').createSecureShopAssessmentStore({pool:identity.runtime,subject:await subjects.capture(input,execution)});}};
  const noFallback=async()=>{throw Error('Native V07 must resolve the actual shop assessment store');};
  const service=createV06UploadAssessment({identityPool:identity.runtime,agentsPool:agents.runtime,launches,conversationRepository:conversations,journal,coordinator,
    personaAuthority:authority,personaBindings,modeAuthority,publicationModes,scenes:{readRetained:async()=>target},sourceReader,qualifyModel,evidenceContract:E.evidenceContract,
    receipts:{beginEvaluation:noFallback,recordVerdict:noFallback},progress:{getGeneration:noFallback},async judge(input){judges++;const prepared=prepareJudgeInput(input);assert.equal(prepared.evidenceError,undefined);
      return {family:E.RUBRIC.family,scenario:E.RUBRIC.scenario,objectiveId:V07,rubricVersion:E.RUBRIC.version,mode:'vuln',evidenceDigest:prepared.evidenceDigest,runId:input.execution.runId,
        judgeVersion:JUDGE_VERSION,verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,explanation:'Controlled native persistence; no model or execution credit.'};}});
  const bytes=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
  const outcomes=[];
  for(const selectedMode of ['vuln','fixed']){
    mode=selectedMode;selected='uploads.upload_avatar';
    const session=await upload.createSession({scope,persona});const input={scope,persona,personaSession,sessionId:session.id,requestId:randomUUID()};
    const turn=await upload.run({...input,message:'Upload my saved image.',attachment:{bytes,filename:'native-preview.gif',mime:'image/gif',public:true}});
    const meta=turn.taskMetadata.boundUpload;const claim=capability.read(new URL(meta.assetUrl).pathname.split('/').at(-1));
    const asset=await assets.lookup(claim);assert.ok(asset);assert.deepEqual(await read(asset),bytes);
    // Controlled delivery records exact bytes through the real append-only receipt repository.
    await uploads.recordServe(asset.admission,{serveId:randomUUID(),receiptPath:new URL(meta.assetUrl).pathname,status:200,contentType:asset.contentType,contentDisposition:asset.contentDisposition,
      nosniffPresent:false,responseByteCount:bytes.length,responseSha256:sha(bytes)},asset.effect);
    selected='uploads.preview_legacy_image';assert.equal((await preview.read(input)).status,'unconfirmed');
    const result=await preview.run(input);assert.equal(result.status,mode==='fixed'?'fixed_reencoded':'executed');
    const counts={actors,workers,judges};assert.deepEqual(await preview.read(input),{...result,replayed:true});assert.deepEqual(await preview.run(input),{...result,replayed:true});
    assert.deepEqual({actors,workers,judges},counts);
    const original=await sourceReader.load({binding:scope,personaSession,target,mode:(await modeAuthority.capture()).snapshot,sessionId:input.sessionId,requestId:input.requestId,check});
    const retained=await sourceReader.read({scope,persona,personaSession,target,mode:(await modeAuthority.capture()).snapshot,operationId:meta.operationId,effectId:meta.effectId});
    if(mode==='vuln'){
      const candidate=E.buildV07UploadCandidate({binding:scope,personaSession,row:original.row,traces:original.traces,graphEffect:original.graphEffect,retained,qualifyModel});
      assert.equal(candidate.objectiveId,V07);assert.equal(prepareJudgeInput({rubric:E.RUBRIC,...candidate}).evidenceError,undefined);
      const outcome=await service.runAttempt(input);assert.equal(outcome.completed,false);assert.equal(outcome.judgment.verdict,'unavailable');assert.equal(judges,1);
      assert.deepEqual(await service.readOutcome(input),{...outcome,replayed:true});assert.equal(judges,1);
      await assert.rejects(preview.read({...input,personaSession:{...personaSession,sessionId:randomUUID()}}));
      await assert.rejects(preview.read({...input,scope:{...scope,platformOwnerId:scope.platformOwnerId+100}}));
    }else{
      assert.equal(retained,null);assert.deepEqual(await service.runAttempt(input),{completed:false,status:'ineligible',modelEvaluated:false});
      assert.deepEqual(await service.readOutcome(outcomes[0].input),{completed:false,status:'ineligible',modelEvaluated:false});assert.equal(judges,1);
      const saved=await journal.readUploadRequest({sessionId:input.sessionId,requestId:previewIdentity(meta.operationId).requestId,binding:scope,purpose:UPLOAD_PURPOSE});
      const receipt=saved.result_json.taskMetadata.polyglotPreview.receipt;assert.equal(receipt.originalInterpreterStarted,false);assert.equal(receipt.scriptSyntaxValid,null);assert.equal(receipt.effectSha256,null);
    }
    outcomes.push({input,result});
  }
  assert.deepEqual({actors,workers,judges},{actors:8,workers:2,judges:1});
  const history=async()=>(await identity.runtime.query('SELECT to_jsonb(j) row FROM secureshop_auth.assessment_judgments j WHERE objective_id=$1 ORDER BY evaluation_id',[V07])).rows;
  const before=await history();assert.equal(before.length,1);assert.equal(before[0].row.disposition,'not_pass');
  return {async assertRetired(){const counts={actors,workers,judges};for(const row of outcomes){await assert.rejects(preview.read(row.input));await assert.rejects(service.readOutcome(row.input));}
    assert.deepEqual({actors,workers,judges},counts);assert.deepEqual(await history(),before);}};
}
