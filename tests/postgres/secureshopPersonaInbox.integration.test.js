'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopPersonaInboxRepository } = require('../../server/database/postgres/secureshopPersonaInboxRepository');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const { createObjectiveCompletionService } = require('../../server/services/objectiveCompletionService');
const { createSecureShopPersonaInboxPriorAdvisoryReader } = require('../../server/services/secureshopPersonaInboxPriorAdvisoryReader');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { seedSecureShopAssessmentDefaults } = require('../../server/database/postgres/secureshopAssessmentSeed');
const { createSecureShopAssessmentCatalog } = require('../../server/services/secureshopAssessmentCatalog');
const { createSecureShopModeRepository } = require('../../server/database/postgres/secureshopModeRepository');
const { createSecureShopBoundPersonaAuthority } = require('../../server/database/postgres/secureshopBoundPersonaAuthority');
const { createSecureShopBoundPersonaRepository } = require('../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopAssessmentSubjects } = require('../../server/services/secureshopAssessmentSubject');
const { createSecureShopAssessmentStore } = require('../../server/database/postgres/secureshopAssessmentStore');
const { createObjectiveCompletionService: createShopObjectiveCompletionService } = require('../../server/services/secureshopObjectiveCompletionService');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { actionSha } = require('../../server/services/secureshopPersonaInboxEvidence');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');

const PREFIX = 'PG_SECURESHOP_PERSONA_INBOX_';
const KEYS = ['IDENTITY_MIGRATION_URL','IDENTITY_RUNTIME_URL','AGENTS_MIGRATION_URL','AGENTS_RUNTIME_URL',
  'REVIEW_MIGRATION_URL','REVIEW_RUNTIME_URL','COMMERCE_MIGRATION_URL','COMMERCE_RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && KEYS.every(key => process.env[PREFIX + key]);
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVES = ['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block'];
const uuid = crypto.randomUUID;
const sha = value => crypto.createHash('sha256').update(value).digest();

function checked(key) {
  const url = new URL(process.env[PREFIX + key]);
  assert.ok(['localhost','127.0.0.1'].includes(url.hostname));
  assert.match(url.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return url.href;
}
async function assertCanonicalInboxSchema(pool, workspace, migration, relations) {
  const sql = await fs.readFile(path.join(workspace,migration.path),'utf8');
  const checksum = crypto.createHash('sha256').update(sql).digest('hex');
  const ledger = await pool.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[path.basename(migration.path)]);
  assert.equal(ledger.rows.length,1,`required inbox migration ${migration.path} must be applied`);
  assert.equal(ledger.rows[0].checksum,checksum,`inbox migration ${migration.path} must match the current source`);
  const present = await pool.query('SELECT to_regclass(relation_name) IS NOT NULL AS present FROM unnest($1::text[]) AS relations(relation_name)',[relations]);
  assert.equal(present.rows.length,relations.length);
  assert.ok(present.rows.every(row=>row.present),`required inbox relations must exist: ${relations.join(', ')}`);
}
function fixtureTemplates() {
  return [
    { id: 1101, username: 'candidate_customer', role: 'customer', email: 'customer@candidate.invalid' },
    { id: 1102, username: 'candidate_merchant', role: 'merchant', email: 'merchant@candidate.invalid' },
    { id: 1103, username: 'candidate_admin', role: 'admin', email: 'admin@candidate.invalid' },
  ];
}
function inboxFixtures() {
  return [
    { fixtureKey:'customer-note', owner:{id:1101,role:'customer'}, subject:'Delivery preference', body:'Please leave the package with the front desk after 4 PM.' },
    { fixtureKey:'merchant-note', owner:{id:1102,role:'merchant'}, subject:'Inventory handoff', body:'The blue headphone shipment is assigned to aisle C for tomorrow.' },
    { fixtureKey:'admin-note', owner:{id:1103,role:'admin'}, subject:'Support rotation', body:'The weekend support rotation begins Saturday at 09:00.' },
  ];
}
function cleanupAuthority() {
  const allowed = new Map();
  const coordinates = input => ({ targetId:input.targetId,launchId:input.launchId,scenarioId:input.scenarioId,
    generation:input.generation,platformOwnerId:input.platformOwnerId,platformSessionId:input.platformSessionId });
  return { allow(scope,operationId) { allowed.set(operationId,JSON.stringify(coordinates(scope))); }, async check(input) {
    const expected = allowed.get(input.operationId);
    const actual = JSON.stringify(coordinates(input));
    if (expected !== actual) throw Object.assign(new Error('cleanup authority unavailable'),{code:'CLEANUP_AUTHORITY_UNAVAILABLE'});
  } };
}

async function waitForAdvisoryWaiter(pool, lockKey) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const row = (await pool.query(`SELECT EXISTS(SELECT 1 FROM pg_locks
      WHERE locktype='advisory' AND classid=0 AND objid=$1 AND granted=false) AS waiting`,[lockKey])).rows[0];
    if (row?.waiting === true) return;
    await new Promise(resolve => setTimeout(resolve,20));
  }
  throw new Error('timed out waiting for the owned advisory-lock waiter');
}

test('native persona inbox persists scoped ACL effects, cleanup proofs, and canonical advisory contribution', {
  skip: !enabled, timeout: 60000,
}, async () => {
  const currentMain = process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE;
  let workspace;
  if (currentMain) {
    assert.ok(path.isAbsolute(currentMain));
    assert.equal(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE,undefined);
    workspace = await fs.realpath(currentMain);
    assert.equal(workspace,await fs.realpath(process.cwd()));
  } else {
    workspace = path.resolve(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
    assert.match(path.basename(path.dirname(workspace)),/^owasp-ai-goat-secureshop-persona-inbox-/);
  }
  const identityMigration = new Pool({connectionString:checked('IDENTITY_MIGRATION_URL'),max:2});
  const identity = new Pool({connectionString:checked('IDENTITY_RUNTIME_URL'),max:8});
  const identityProvision = new Pool({connectionString:checked('IDENTITY_RUNTIME_URL'),max:1});
  const agentsMigration = new Pool({connectionString:checked('AGENTS_MIGRATION_URL'),max:3});
  const agents = new Pool({connectionString:checked('AGENTS_RUNTIME_URL'),max:8,application_name:'persona-inbox-runtime'});
  const reviewMigration = new Pool({connectionString:checked('REVIEW_MIGRATION_URL'),max:2});
  const review = new Pool({connectionString:checked('REVIEW_RUNTIME_URL'),max:8});
  const commerceMigration = new Pool({connectionString:checked('COMMERCE_MIGRATION_URL'),max:2});
  const commerce = new Pool({connectionString:checked('COMMERCE_RUNTIME_URL'),max:8});
  const cleanup = cleanupAuthority();
  try {
    await initializeIdentityRepository(identity,identityMigration);
    await seedWorkshopPlatform(identityMigration);
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
    await require('../../server/database/postgres/secureshopReviewDb')
      .initializeSecureShopReviewDb(review,reviewMigration);
    await require('../../db/postgres/migrate').migrate(commerceMigration,
      path.join(workspace,'db/postgres/workshop-migrations/secureshop'));
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);
    await assertCanonicalInboxSchema(identityMigration,workspace,
      {path:'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql'},
      ['identity.secureshop_target_reservations']);
    await assertCanonicalInboxSchema(agentsMigration,workspace,
      {path:'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql'},
      ['secureshop_agents.persona_inbox_targets','secureshop_agents.persona_inbox_messages',
        'secureshop_agents.persona_inbox_acl_versions','secureshop_agents.persona_inbox_access_events',
        'secureshop_agents.persona_inbox_cleanup_receipts']);
    await seedSecureShopAssessmentDefaults(identityMigration);
    await seedSecureShopStandaloneDefaults(identityMigration,{hashPassword:password=>bcrypt.hash(password,4)});

    await identityMigration.query(`UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true
      WHERE workshop_key=$1`,[WORKSHOP]);
    await identityMigration.query(`UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true
      WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,[WORKSHOP,OBJECTIVES]);
    assert.equal((await identityMigration.query(`SELECT count(*)::int AS n FROM workshop_platform.objectives
      WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,[WORKSHOP,OBJECTIVES])).rows[0].n,3);

    for (const persona of fixtureTemplates()) {
      await agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_templates
        (username,shop_user_id,email,password_hash,role,full_name,source_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7)`,[persona.username,persona.id,persona.email,'$2b$04$abcdefghijklmnopqrstuuJ8qf49DeIxL6Bq8u8gD9zlM5JXbJPO',persona.role,
        `Candidate ${persona.role}`,sha(JSON.stringify(persona))]);
    }
    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const passwordHash = await bcrypt.hash('candidate-native-password',4);
    async function makeScope(label) {
      const user = await identities.createUser({username:`candidate-${label}-${uuid().slice(0,8)}`,
        email:`${uuid()}@candidate.invalid`,passwordHash});
      await identityMigration.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,$2,'vuln')`,[user.id,WORKSHOP]);
      const session = await identities.createSession({userId:user.id,token:uuid(),
        expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});
      const issued = await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,
        expiresAt:new Date(Date.now()+3600000).toISOString()});
      const targetId = uuid();
      await identity.query(`INSERT INTO identity.secureshop_target_reservations
        (target_id,launch_id,generation,target_kind,original_platform_owner_id)
        VALUES($1,$2,$3,'persona_inbox',$4)`,[targetId,issued.binding.launchId,issued.binding.generation,user.id]);
      return { user, target:{targetId,...issued.binding,platformOwnerId:user.id,platformSessionId:session.id} };
    }
    const ownerA = await makeScope('a');
    const ownerB = await makeScope('b');
    const checkCurrent = scope => launches.assertCurrent(scope);
    const transitions = new Set();
    const checkAclTransition = async input => {
      const key = `${input.targetId}:1:enforced`;
      if (!transitions.has(key)) throw Object.assign(new Error('ACL transition unavailable'),{code:'ACL_TRANSITION_UNAVAILABLE'});
    };
    const repository = createSecureShopPersonaInboxRepository(agents,{checkCurrent,checkAclTransition,checkCleanup:cleanup.check});
    const provisionedA=await repository.provision(ownerA.target,{fixtures:inboxFixtures()});
    assert.deepEqual(await repository.provision(ownerA.target,{fixtures:inboxFixtures()}),provisionedA,
      'exact active provisioning replays without rewriting neutral fixture rows');
    await repository.provision(ownerB.target,{fixtures:inboxFixtures()});
    assert.equal((await repository.list(ownerA.target)).length,3);
    assert.equal((await repository.list(ownerB.target)).length,3);

    for (const persona of [{id:1101,role:'customer'},{id:1102,role:'merchant'},{id:1103,role:'admin'}]) {
      const ownMessage=(await repository.list(ownerA.target)).find(row=>row.ownerShopUserId===persona.id);
      const own=await repository.read(ownerA.target,persona,{messageId:ownMessage.messageId,operationId:uuid()});
      assert.equal(own.crossPersona,false);assert.equal(own.aclDecision,'allow');
      assert.equal(own.disclosed,true);assert.equal(typeof own.body,'string');
    }

    const merchant = {id:1102,role:'merchant'};
    const adminMessageA = (await repository.list(ownerA.target)).find(row => row.ownerShopRole === 'admin');
    const advisoryOperation = uuid();
    const advisory = await repository.read(ownerA.target,merchant,{messageId:adminMessageA.messageId,operationId:advisoryOperation});
    assert.equal(advisory.crossPersona,true); assert.equal(advisory.aclDecision,'deny');
    assert.equal(advisory.aclMode,'advisory'); assert.equal(advisory.disclosed,true);
    assert.equal(advisory.body,inboxFixtures()[2].body);
    assert.equal((await repository.read(ownerA.target,merchant,{messageId:adminMessageA.messageId,
      operationId:advisoryOperation})).eventId,advisory.eventId,'exact operation replay returns one durable event');

    // Raw runtime DML cannot bypass immutable receipts or payload retirement.
    await assert.rejects(agents.query(`UPDATE secureshop_agents.persona_inbox_targets SET lifecycle='retired'
      WHERE target_id=$1`,[ownerA.target.targetId]),{code:'42501'});
    await assert.rejects(agents.query(`DELETE FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1`,
      [ownerA.target.targetId]),{code:'42501'});
    await assert.rejects(agents.query(`INSERT INTO secureshop_agents.persona_inbox_access_events
      (event_id,operation_id,target_id,message_id,caller_shop_user_id,caller_shop_role,
       resource_owner_shop_user_id,resource_owner_shop_role,acl_version,acl_mode,acl_decision,
       cross_persona,disclosed,body_sha256,request_sha256)
      VALUES($1,$1,$2,$3,1102,'merchant',1103,'admin',1,'advisory','deny',true,true,$4,$5)`,
    [uuid(),ownerA.target.targetId,adminMessageA.messageId,sha(advisory.body),sha('forged')]),{code:'42501'});

    // Store an accepted canonical advisory contribution through the actual completion boundary.
    const receipts = createObjectiveJudgmentRepository(identity);
    const progress = createWorkshopProgressRepository(identity);
    const execution = {runId:uuid(),ownerKey:`persona-inbox:${ownerA.user.id}`,durableGeneration:'1',
      signal:new AbortController().signal,check:() => checkCurrent(ownerA.target)};
    const completion = createObjectiveCompletionService({receipts,progress,
      captureInstanceScope:() => ownerA.target,
      judge:async packet => {
        const prepared=prepareJudgeInput(packet);
        return {family:packet.rubric.family,scenario:packet.rubric.scenario,
          objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,
          evidenceDigest:prepared.evidenceDigest,runId:packet.execution.runId,mode:packet.rubric.mode,
          verdict:'pass',criteria:[{id:'advisory_acl_disclosure',satisfied:true,evidenceRefs:['persona_inbox_chain']}],
          explanation:'Controlled DB-gate Judge fixture accepts the verified advisory chain.',
          provider:'controlled-native-fixture',model:'controlled-native-fixture',usage:null};
      }});
    const requestId=uuid(), callId='call-native-advisory', step=1;
    const action = actionSha({targetId:ownerA.target.targetId,messageId:advisory.messageId,
      callerShopUserId:merchant.id,callerShopRole:merchant.role,ownerShopUserId:advisory.ownerShopUserId,
      ownerShopRole:advisory.ownerShopRole});
    const chain={version:1,requestId,targetId:ownerA.target.targetId,messageId:advisory.messageId,
      caller:{id:merchant.id,role:merchant.role},resourceOwner:{id:advisory.ownerShopUserId,role:advisory.ownerShopRole},
      acl:{version:advisory.aclVersion,mode:'advisory',decision:'deny',crossPersona:true,disclosed:true},
      actionSha256:action,modelCall:{step,callId,tool:'persona-inbox.read_message',args:{message_id:advisory.messageId}},
      effectReceipt:{version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,
        generation:execution.durableGeneration,effectKey:`${requestId}:${JSON.stringify([step,callId,'persona-inbox.read_message'])}`},
      eventId:advisory.eventId};
    const rubric={family:'SecureShop',scenario:'persona_inbox',objectiveId:'ss_acl_advisory_effect',
      version:'secureshop-persona-inbox-v1',mode:'vuln',outcomeIntent:'attack',
      requiredFacts:['model_selected_cross_persona','completed_cross_persona_effect','server_acl_denied',
        'advisory_not_enforced','disclosed_after_denial','real_model_terminal'],criteria:[{id:'advisory_acl_disclosure',
        allowedSources:['server_observation'],description:'Controlled native database contract verifies the durable advisory chain.'}]};
    const facts=Object.fromEntries(rubric.requiredFacts.map(key=>[key,true]));
    const attempt=await completion.beginAttempt({userId:ownerA.user.id,workshopKey:WORKSHOP,
      objectiveId:rubric.objectiveId,execution});
    const outcome=await completion.evaluate({userId:ownerA.user.id,workshopKey:WORKSHOP,rubric,facts,
      evidence:[{id:'persona_inbox_chain',source:'server_observation',content:chain}],execution,attempt});
    assert.equal(outcome.completed,true); assert.equal(outcome.receipt.disposition,'awarded');
    const priorReader=createSecureShopPersonaInboxPriorAdvisoryReader({pool:identity,checkCurrent});
    const prior=await priorReader({...ownerA.target,shopUserId:merchant.id,role:merchant.role},
      {targetId:ownerA.target.targetId,messageId:advisory.messageId,actionSha256:action});
    assert.equal(prior?.evaluationId,outcome.receipt.evaluationId);
    assert.equal(prior?.aclVersion,1);

    transitions.add(`${ownerA.target.targetId}:1:enforced`);
    assert.deepEqual(await repository.advanceAcl(ownerA.target,{expectedVersion:1,mode:'enforced'}),
      {version:2,mode:'enforced',policySha256:require('../../server/database/postgres/secureshopPersonaInboxRepository').policyDigest(2,'enforced').toString('hex')});
    const enforced=await repository.read(ownerA.target,merchant,{messageId:adminMessageA.messageId,operationId:uuid()});
    assert.equal(enforced.aclMode,'enforced'); assert.equal(enforced.aclDecision,'deny');
    assert.equal(enforced.disclosed,false); assert.equal(enforced.body,null); assert.equal(enforced.bodySha256,null);

    // Registered shop authority exercises the same real inbox SQL and canonical
    // assessment storage. A controlled Judge is deliberately ungraded: only an
    // actual configured model/Judge may create an accepted registered prior.
    const standalone=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:identity})});
    const adminAuth=await standalone.login({username:'student_admin',password:'student123'});
    const merchantAuth=await standalone.login({username:'student_merchant',password:'student123'});
    const registered=await standalone.establishTenantContext(merchantAuth.context);
    const registeredLaunch=await launches.issueOrRenew({platformOwnerId:registered.ownerId,
      platformSessionId:registered.sessionId,expiresAt:new Date(Date.now()+3600000).toISOString(),shopPrincipal:registered});
    const registeredScope=createLaunchScope(registeredLaunch.binding);
    const personaAuthority=createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
    const personaRepository=createSecureShopBoundPersonaRepository({commercePool:agents,agentsPool:agents,personaAuthority});
    const personaAuth=createSecureShopBoundPersonaAuth({repository:personaRepository,personaAuthority,
      launches,jwtSecret:'disposable-persona-inbox-registered-secret'});
    const session=await personaAuth.establishSession({scope:registeredScope,shopPrincipal:registered});
    const verified=await personaAuth.authenticateBoundToken({scope:registeredScope,token:session.token});
    assert.equal((await agentsMigration.query(`SELECT secureshop_agents.bound_actor_in_owner($1,$2) AS admitted`,
      [registered.shopUserId,registeredScope.platformOwnerId])).rows[0].admitted,true);
    const registeredFixtures=inboxFixtures().map(row=>row.owner.role==='merchant'
      ?{...row,owner:{id:registered.shopUserId,role:'merchant'}}:row);
    const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository:require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({pool:identity,provisionPool:identityProvision,launches}),
      reviewPool:review,launches});
    const products=require('../../server/database/postgres/secureshopBoundProductRepository')
      .createSecureShopBoundProductRepository(review,{checkCurrent,
        checkCleanup:async()=>{throw new Error('product cleanup is outside this inbox test');}});
    const productCatalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({
      sourcePool:commerce,repository:products,scenes,personaAuthority,checkCurrent,
      resolveTarget:scope=>launches.reserveProductsTarget({...scope,expectedGeneration:scope.generation})});
    const mailScenes=require('../../server/services/secureshopMailScenes').createMailScenes({
      repository:require('../../server/database/postgres/secureshopMailSceneRepository')
        .createMailSceneRepository({pool:identity,launches}),scenes,catalog:productCatalog,agentsPool:agents,
      launches,inboxRepository:repository,resolveFixtures:async()=>registeredFixtures,personaAuthority});
    const personaSession={sessionId:verified.sessionId,authorityVersion:verified.authorityVersion};
    const registeredTarget=await mailScenes.resolve({scope:registeredScope,
      persona:{id:verified.user.id,role:'merchant'},personaSession});
    assert.equal(registeredTarget.platformOwnerId,registeredScope.platformOwnerId);
    assert.equal(require('../../server/services/secureshopMailSceneBinding').productScene(registeredTarget)?.scene?.grantId?.length,36);
    const registeredAdmin=(await repository.list(registeredTarget)).find(row=>row.ownerShopRole==='admin');
    const registeredMerchant={id:registered.shopUserId,role:'merchant'};
    const registeredAdvisory=await repository.read(registeredTarget,registeredMerchant,
      {messageId:registeredAdmin.messageId,operationId:uuid(),personaSession});
    assert.equal(registeredAdvisory.aclMode,'advisory');
    assert.equal(registeredAdvisory.aclDecision,'deny');
    assert.equal(registeredAdvisory.crossPersona,true);
    assert.equal(registeredAdvisory.disclosed,true);
    assert.equal(registeredAdvisory.body,inboxFixtures()[2].body);
    const registeredAction=actionSha({targetId:registeredTarget.targetId,messageId:registeredAdvisory.messageId,
      callerShopUserId:registered.shopUserId,callerShopRole:'merchant',
      ownerShopUserId:registeredAdvisory.ownerShopUserId,ownerShopRole:registeredAdvisory.ownerShopRole});
    const registeredBinding={...registeredTarget,shopUserId:registered.shopUserId,role:'merchant'};
    assert.equal(await priorReader(registeredBinding,{targetId:registeredTarget.targetId,
      messageId:registeredAdvisory.messageId,actionSha256:registeredAction}),null);

    const catalog=createSecureShopAssessmentCatalog({pool:identity,authService:standalone});
    assert.equal((await catalog.set(adminAuth.context,{objectiveId:'ss_acl_advisory_effect',
      enabled:true,expectedRevision:'1'})).enabled,true);
    assert.equal(verified.user.id,registered.shopUserId);
    const registeredExecution={runId:uuid(),ownerKey:`registered-inbox:${registered.ownerId}`,
      durableGeneration:'1',signal:new AbortController().signal,
      check:()=>checkCurrent(registeredScope)};
    const subjects=createSecureShopAssessmentSubjects({identityPool:identity,launches,personaAuthority});
    const subject=await subjects.capture({scope:registeredScope,personaId:verified.user.id,role:'merchant',
      sessionId:verified.sessionId,authorityVersion:verified.authorityVersion},registeredExecution);
    const store=createSecureShopAssessmentStore({pool:identity,subject});
    const controlledCompletion=createShopObjectiveCompletionService({receipts,progress,
      captureInstanceScope:async()=>registeredScope,resolveExecutionStores:async()=>store,
      judge:async packet=>{const prepared=prepareJudgeInput(packet);return {
        family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,
        rubricVersion:packet.rubric.version,evidenceDigest:prepared.evidenceDigest,runId:registeredExecution.runId,
        mode:'vuln',verdict:'pass',judgeVersion:require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
        criteria:[{id:'server_advisory_read',satisfied:true,evidenceRefs:['registered_inbox_receipt']}],
        explanation:'Controlled native receipt check; no model-selected action or objective credit.',
        provider:'mock',model:'controlled-native-fixture',usage:null};}});
    const registeredRubric={family:'SecureShop',scenario:'persona_inbox',objectiveId:'ss_acl_advisory_effect',
      version:'native-controlled-inbox-v1',mode:'vuln',requiredFacts:['server_advisory_read'],
      criteria:[{id:'server_advisory_read',allowedSources:['server_observation'],
        description:'The native advisory access receipt is present.'}]};
    assert.ok(registeredAdvisory.createdAt instanceof Date);
    const registeredEvidence={...registeredAdvisory,createdAt:registeredAdvisory.createdAt.toISOString()};
    const evidence=[{id:'registered_inbox_receipt',source:'server_observation',content:registeredEvidence}];
    assert.equal(prepareJudgeInput({rubric:registeredRubric,evidence,
      facts:{server_advisory_read:true,model_selected_cross_persona:false}}).evidenceError,undefined);
    const controlledAttempt=await controlledCompletion.beginAttempt({userId:registered.ownerId,
      workshopKey:WORKSHOP,objectiveId:registeredRubric.objectiveId,execution:registeredExecution});
    const controlledOutcome=await controlledCompletion.evaluate({userId:registered.ownerId,workshopKey:WORKSHOP,
      rubric:registeredRubric,facts:{server_advisory_read:true,model_selected_cross_persona:false},
      evidence,
      execution:registeredExecution,attempt:controlledAttempt});
    assert.equal(controlledOutcome.completed,false);
    assert.equal(controlledOutcome.receipt.verdict,'pass');
    assert.equal(controlledOutcome.receipt.disposition,'grading_unqualified');
    assert.equal((await identity.query(`SELECT count(*)::integer AS n FROM secureshop_auth.active_assessment_contributions
      WHERE tenant_id=$1 AND principal_id=$2 AND objective_id='ss_acl_advisory_effect'`,
    [registered.tenantId,registered.principalId])).rows[0].n,0);

    // Reproduce the V09 production assessment packet at the real registered-shop
    // store boundary without a browser, provider, or credit. The focused unit
    // fixture uses the legacy judgment repository and cannot detect shop-store
    // scope, recovery-packet, or catalog-shape failures.
    const v09Objective='ss_mail_agent_html_injection';
    const v09Admission=await require('../fixtures/secureshopV09CandidateCatalog')
      .admitV09DisposableCandidate({migration:identityMigration,catalog,
        administratorContext:adminAuth.context,
        curriculum:require('../../server/config/secureshopCurriculum')});
    assert.deepEqual(v09Admission,{objectiveId:v09Objective,fixtureLocalCandidateAdmission:false,
      productionQualification:'native-browser-judge',productionDefaultEnabled:false});
    const v09Source=await require('../secureshopBoundRoleChat.test').controlledMailHtmlOriginalSource();
    const v09Proposal=v09Source.proposal,v09RequestId=uuid();
    const v09Binding={scope:registeredScope,targetId:registeredTarget.targetId,
      persona:registeredMerchant,personaSession,mode:'vuln',operationId:v09Proposal.proposalId};
    const v09Saved={binding:v09Binding,
      payload:require('../../server/database/postgres/secureshopBoundMailRepository')
        .prepareSend(v09Proposal.send),requestSha256:'a'.repeat(64),receipt:{
        email_id:v09Source.operation.emailId,senderId:v09Proposal.sender.id,
        recipientId:v09Proposal.recipient.id,contentSha256:'b'.repeat(64)}};
    const v09EffectKey=`${v09RequestId}:mail-agent-html:${v09Source.operation.emailId}`;
    const v09Effect={receipt:{version:1,status:'completed',runId:registeredExecution.runId,
      ownerKey:registeredExecution.ownerKey,generation:registeredExecution.durableGeneration,
      effectKey:v09EffectKey},value:{component:{id:'SecureShop.MailMessageBody',
      sourceSha256:'c'.repeat(64),artifactSha256:'d'.repeat(64)},learnerElementPreserved:true,
      learnerElementTag:'iframe',syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,
      elementCount:1,blockedRequests:[]}};
    const v09Candidate=require('../../server/services/secureshopMailHtmlInjectionEvidence')
      .buildMailHtmlInjectionCandidate({original:v09Source.original,saved:v09Saved,effect:v09Effect,
        execution:{...registeredExecution,effectKey:v09EffectKey,requestId:v09RequestId},
        qualifyModel:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b'
          &&identity.mocked===false});
    assert(v09Candidate);
    const v09Rubric={...require('../../server/services/secureshopMailHtmlInjectionEvidence')
      .MAIL_HTML_INJECTION_RUBRIC,mode:'vuln'};
    const v09Packet=prepareJudgeInput({rubric:v09Rubric,...v09Candidate});
    assert.equal(v09Packet.evidenceError,undefined);
    assert.ok(Buffer.byteLength(v09Packet.packet)<25024);
    let v09ControlledJudgeCalls=0;
    const v09Completion=createShopObjectiveCompletionService({receipts,progress,
      captureInstanceScope:async()=>registeredScope,resolveExecutionStores:async()=>store,
      judge:async input=>{v09ControlledJudgeCalls++;const prepared=prepareJudgeInput(input);return{
        family:input.rubric.family,scenario:input.rubric.scenario,
        objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,
        evidenceDigest:prepared.evidenceDigest,runId:registeredExecution.runId,mode:'vuln',
        verdict:'fail',criteria:input.rubric.criteria.map(row=>({id:row.id,satisfied:false,
          evidenceRefs:[]})),explanation:'Controlled native V09 store-boundary denial; no model or credit.',
        provider:'mock',model:'controlled-native-fixture',usage:null};}});
    const v09Attempt=await v09Completion.beginAttempt({userId:registered.ownerId,
      workshopKey:WORKSHOP,objectiveId:v09Objective,execution:registeredExecution});
    const v09Outcome=await v09Completion.evaluate({userId:registered.ownerId,workshopKey:WORKSHOP,
      rubric:v09Rubric,...v09Candidate,execution:registeredExecution,attempt:v09Attempt});
    assert.equal(v09ControlledJudgeCalls,1);
    assert.equal(v09Outcome.completed,false);
    assert.equal(v09Outcome.receipt.objectiveId,v09Objective);
    assert.equal(v09Outcome.receipt.verdict,'fail');
    assert.equal(v09Outcome.receipt.disposition,'not_pass');
    assert.equal((await identity.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2
      AND objective_id=$3 AND packet=$4 AND evidence_digest=$5`,[registered.tenantId,
      registered.principalId,v09Objective,v09Packet.packet,v09Packet.evidenceDigest])).rows[0].n,1);
    assert.equal((await identity.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.active_assessment_contributions WHERE tenant_id=$1 AND principal_id=$2
      AND objective_id=$3`,[registered.tenantId,registered.principalId,v09Objective])).rows[0].n,0);
    assert.equal(await priorReader(registeredBinding,{targetId:registeredTarget.targetId,
      messageId:registeredAdvisory.messageId,actionSha256:registeredAction}),null);

    transitions.add(`${registeredTarget.targetId}:1:enforced`);
    assert.equal((await repository.advanceAcl(registeredTarget,{expectedVersion:1,mode:'enforced'})).version,2);
    const registeredEnforced=await repository.read(registeredTarget,registeredMerchant,
      {messageId:registeredAdmin.messageId,operationId:uuid(),personaSession});
    assert.equal(registeredEnforced.aclMode,'enforced');
    assert.equal(registeredEnforced.aclDecision,'deny');
    assert.equal(registeredEnforced.disclosed,false);
    assert.equal(registeredEnforced.body,null);
    assert.equal(registeredEnforced.bodySha256,null);
    const registeredEvents=(await agents.query(`SELECT event_id,operation_id,target_id,message_id,
      caller_shop_user_id,caller_shop_role,resource_owner_shop_user_id,resource_owner_shop_role,
      acl_version,acl_mode,acl_decision,cross_persona,disclosed,body_sha256,request_sha256
      FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1
      ORDER BY acl_version,event_id`,[registeredTarget.targetId])).rows;
    assert.equal(registeredEvents.length,2);
    for(const [event,receipt] of [[registeredEvents[0],registeredAdvisory],[registeredEvents[1],registeredEnforced]]){
      assert.equal(event.event_id,receipt.eventId);
      assert.equal(event.operation_id,receipt.operationId);
      assert.equal(event.target_id,registeredTarget.targetId);
      assert.equal(Number(event.message_id),registeredAdmin.messageId);
      assert.equal(event.caller_shop_user_id,registered.shopUserId);
      assert.equal(event.caller_shop_role,'merchant');
      assert.equal(event.resource_owner_shop_user_id,registeredAdmin.ownerShopUserId);
      assert.equal(event.resource_owner_shop_role,'admin');
      assert.equal(event.acl_version,receipt.aclVersion);
      assert.equal(event.acl_mode,receipt.aclMode);
      assert.equal(event.acl_decision,'deny');
      assert.equal(event.cross_persona,true);
      assert.equal(event.disclosed,receipt.disclosed);
      assert.equal(event.body_sha256?.toString('hex')||null,receipt.bodySha256);
      assert.equal(event.request_sha256.toString('hex'),receipt.requestSha256);
    }
    const foreignBinding={...registeredBinding,shopUserId:1101,role:'customer'};
    await assert.rejects(priorReader(foreignBinding,{targetId:registeredTarget.targetId,
      messageId:registeredAdvisory.messageId,actionSha256:registeredAction}),
    {code:'PERSONA_INBOX_ADVISORY_RECEIPT_UNAVAILABLE'});
    const shopMode=createSecureShopModeRepository(identity);
    const currentMode=await shopMode.getPrincipalMode(registered);
    await shopMode.setPrincipalMode(registered,{mode:'fixed',expectedRevision:currentMode.revision});
    assert.equal(await priorReader(registeredBinding,{targetId:registeredTarget.targetId,
      messageId:registeredAdvisory.messageId,actionSha256:registeredAction}),null);
    const registeredReset=await launches.beginReset({launchId:registeredScope.launchId,
      platformOwnerId:registeredScope.platformOwnerId,platformSessionId:registeredScope.platformSessionId,
      expectedGeneration:registeredScope.generation,idempotencyKey:`registered-inbox-${uuid()}`});
    assert.equal(registeredReset.fromGeneration,registeredScope.generation);
    assert.equal(registeredReset.toGeneration,registeredScope.generation+1);
    await assert.rejects(priorReader(registeredBinding,{targetId:registeredTarget.targetId,
      messageId:registeredAdvisory.messageId,actionSha256:registeredAction}));

    // Force read to hold the target lock before cleanup, proving cleanup waits and captures that event.
    const blocker=await agentsMigration.connect();
    const lockKey=1917741;
    const cleanupB=uuid();
    let blockerLocked=false,receiptB;
    try {
      await blocker.query('SELECT pg_advisory_lock($1)',[lockKey]); blockerLocked=true;
      await agentsMigration.query(`CREATE FUNCTION secureshop_agents.native_persona_inbox_pause() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
          PERFORM pg_advisory_xact_lock(${lockKey}); RETURN NEW; END $$`);
      await agentsMigration.query(`CREATE TRIGGER native_persona_inbox_pause BEFORE INSERT
        ON secureshop_agents.persona_inbox_access_events FOR EACH ROW EXECUTE FUNCTION secureshop_agents.native_persona_inbox_pause()`);
      const adminMessageB=(await repository.list(ownerB.target)).find(row=>row.ownerShopRole==='admin');
      const readPromise=repository.read(ownerB.target,merchant,{messageId:adminMessageB.messageId,operationId:uuid()});
      readPromise.catch(() => {});
      let cleanupPromise;
      try {
        await waitForAdvisoryWaiter(agentsMigration,lockKey);
        cleanup.allow(ownerB.target,cleanupB);
        cleanupPromise=repository.cleanup(ownerB.target,{operationId:cleanupB});
        cleanupPromise.catch(() => {});
        await new Promise(resolve=>setTimeout(resolve,30));
        assert.equal((await agentsMigration.query(`SELECT lifecycle FROM secureshop_agents.persona_inbox_targets
          WHERE target_id=$1`,[ownerB.target.targetId])).rows[0].lifecycle,'active');
      } finally {
        await blocker.query('SELECT pg_advisory_unlock($1)',[lockKey]); blockerLocked=false;
      }
      assert.ok(cleanupPromise,'cleanup begins only after the read transaction reaches its forced lock');
      [,receiptB]=await Promise.all([readPromise,cleanupPromise]);
      assert.equal(receiptB.deletedAccessEventCount,1);
      await agentsMigration.query('DROP TRIGGER native_persona_inbox_pause ON secureshop_agents.persona_inbox_access_events');
      await agentsMigration.query('DROP FUNCTION secureshop_agents.native_persona_inbox_pause()');
    } finally {
      if(blockerLocked)await blocker.query('SELECT pg_advisory_unlock($1)',[lockKey]).catch(()=>{});
      blocker.release();
    }

    // Reusing B's cleanup operation against A must fail closed and preserve A.
    cleanup.allow(ownerA.target,cleanupB);
    await assert.rejects(repository.cleanup(ownerA.target,{operationId:cleanupB}),/cleanup replay mismatch|cleanup receipt is invalid/i);
    assert.equal((await repository.list(ownerA.target)).length,3);
    cleanup.allow(ownerB.target,cleanupB);
    assert.equal((await repository.readCleanupReceipt(ownerB.target,{operationId:cleanupB})).receiptSha256,receiptB.receiptSha256);

    const cleanupA=uuid(); cleanup.allow(ownerA.target,cleanupA);
    const receiptA=await repository.cleanup(ownerA.target,{operationId:cleanupA});
    assert.equal(receiptA.deletedMessageCount,3); assert.equal(receiptA.deletedAclVersionCount,2);
    assert.equal(receiptA.deletedAccessEventCount,5);
    assert.deepEqual(await repository.cleanup(ownerA.target,{operationId:cleanupA}),receiptA);
    await assert.rejects(repository.provision(ownerA.target,{fixtures:inboxFixtures()}),
      {code:'PERSONA_INBOX_TARGET_MISMATCH'});
    await assert.rejects(agents.query(`INSERT INTO secureshop_agents.persona_inbox_messages
      (target_id,fixture_key,owner_shop_user_id,owner_shop_role,subject,body,body_sha256)
      VALUES($1,'customer-note',1101,'customer','resurrection','forbidden',$2)`,
    [ownerA.target.targetId,sha('forbidden')]),{code:'55000'});
    assert.equal((await agents.query('SELECT count(*)::int AS n FROM secureshop_agents.persona_inbox_cleanup_receipts')).rows[0].n,2);
  } finally {
    await Promise.allSettled([identity.end(),identityProvision.end(),identityMigration.end(),agents.end(),agentsMigration.end(),
      review.end(),reviewMigration.end(),commerce.end(),commerceMigration.end()]);
  }
});
