'use strict';

const { activationPolicy: personaInboxActivationPolicy } = require('./secureshopPersonaInboxActivationPolicy');
const { activationPolicy: mcpTrustActivationPolicy } = require('./secureshopMcpTrustActivationPolicy');
const { PREFERRED_REVIEW_FIXTURES, LEGACY_REVIEW_FIXTURES } = require(
  './secureshopBoundReviewFixtureProfiles');

const path = require('node:path');
const { readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../database/postgres');
const { createSecureShopLaunchRepository } = require('../database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require(
  '../database/postgres/secureshopResetCleanupAuthorityRepository');
const { createBoundConversationsRepository } = require(
  '../database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../database/postgres/secureshopTurnRequestsRepository');
const { createSecureShopConversationLifecycleRepository } = require(
  '../database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopProgressCleanupCheckpointRepository } = require(
  '../database/postgres/secureshopProgressCleanupCheckpointRepository');
const { createSecureShopTargetReconciliationRepository } = require(
  '../database/postgres/secureshopTargetReconciliationRepository');
const { createSecureShopBoundReviewRepository } = require(
  '../database/postgres/secureshopBoundReviewRepository');
const { createSecureShopBoundProductRepository } = require(
  '../database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundCommerceRepository } = require(
  '../database/postgres/secureshopBoundCommerceRepository');
const { createSecureShopBoundAccountRepository } = require(
  '../database/postgres/secureshopBoundAccountRepository');
const { createSecureShopBoundCommerce } = require('./secureshopBoundCommerce');
const { createSecureShopBoundRefundRepository } = require('../database/postgres/secureshopBoundRefundRepository');
const { createSecureShopBoundRefundRuntime } = require('./secureshopBoundRefundRuntime');
const { createBoundRefundRouter } = require('../routes/secureshop/boundRefund');
const { createSecureShopBoundCustomerChat } = require('./secureshopBoundCustomerChat');
const { createCustomerChatBindingRepository } = require('../database/postgres/secureshopCustomerChatBindingRepository');
const { createSecureShopOwnedAgencyRoleRepository } = require('../database/postgres/secureshopOwnedAgencyRoleRepository');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { withSceneLease } = require('./secureshopSceneBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');
const { createBoundCustomerChatRouter } = require('../routes/secureshop/boundCustomerChat');
const { createSecureShopBoundRoleChat, TOOLS: ROLE_CHAT_TOOLS, ORIGINAL_REGISTER_TOOL } = require('./secureshopBoundRoleChat');
const { ORIGINAL_DESCRIBE_TOOL, ORIGINAL_LIST_TOOL } = require('./secureshopOriginalRegistrationRuntime');
const { createRoleChatBindingRepository } = require('../database/postgres/secureshopRoleChatBindingRepository');
const { createBoundRoleChatRouter } = require('../routes/secureshop/boundRoleChat');
const { createSecureShopBoundAccount } = require('./secureshopBoundAccount');
const { createSecureShopBoundPersonaRepository } = require(
  '../database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopOwnerResetRepository } = require(
  '../database/postgres/secureshopOwnerResetRepository');
const { createObjectiveJudgmentRepository } = require('../database/postgres/objectiveJudgmentRepository');
const { createWorkshopProgressRepository } = require('../database/postgres/workshopProgressRepository');
const { createPostgresRunLedger } = require('../agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../agent-runtime/runCoordinator');
const { runSessionExclusive } = require('./secureshop/sessionStore');
const { createSecureShopConversationLifecycle } = require('./secureshopConversationLifecycle');
const { createSecureShopConversationCleanupCheckpointRepository: checkpointRepositoryFactory } = require(
  '../database/postgres/secureshopConversationCleanupCheckpointRepository');
const { createSecureShopReviewCleanupReceiptReader } = require('./secureshopReviewCleanupReceiptReader');
const { createSecureShopFileCleanupReceiptReader } = require('./secureshopFileCleanupReceiptReader');
const { createSecureShopFileTargetCleanup } = require('./secureshopFileTargetCleanup');
const { createSecureShopReviewResetCoordinator } = require('./secureshopReviewResetCoordinator');
const { createSecureShopLaunchResetCoordinator } = require('./secureshopLaunchResetCoordinator');
const { createSecureShopOwnerResetService } = require('./secureshopOwnerResetService');
const { createSecureShopStudentDeletionCleanup } = require('./secureshopStudentDeletionCleanup');
const { createSecureShopCleanupComposition, getSecureShopCleanupComposition,
  closeSecureShopCleanupComposition, createDefaultMcpTrustBundle } = require('./secureshopCleanupComposition');
const { createBoundReviewRuntime } = require('./secureshopBoundReviewRuntime');
const { createSecureShopReviewExecutionConfig } = require('./secureshopReviewExecutionConfig');
const { createSecureShopBoundCatalog } = require('./secureshopBoundCatalog');
const { createSecureShopBoundProductAssist } = require('./secureshopBoundProductAssist');
const { createSecureShopLoopAssessment } = require('./secureshopLoopAssessment');
const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
const { createSecureShopBoundManualIngestion } = require('./secureshopBoundManualIngestion');
const { createSecureShopReservedFileWriter } = require('./secureshopReservedFileWriter');
const { extractAndChunk } = require('./secureshopBoundManualExtraction');
const { createSecureShopBoundManualIngestRepository } = require('../database/postgres/secureshopBoundManualIngestRepository');
const { createSecureShopBoundProductRetrieval } = require('./secureshopBoundProductRetrieval');
const { createSecureShopEmbeddingRevisionRepository } = require('../database/postgres/secureshopEmbeddingRevisionRepository');
const { createSecureShopEmbeddingReindex } = require('./secureshopEmbeddingReindex');
const { createSecureShopProductEmbedder } = require('./secureshopProductEmbedder');
const { createSecureShopBoundProductTools } = require('./secureshopBoundProductTools');
const { createSecureShopBoundProductRetrievalRepository } = require('../database/postgres/secureshopBoundProductRetrievalRepository');
const { createSecureShopBoundPersonaAuth } = require('./secureshopBoundPersonaAuth');
const { createSecureShopStoredBrowserAssessment } = require('./secureshopStoredBrowserAssessment');
const { loadSecureShopReviewCardRenderer } = require('./secureshopReviewCardRenderer');
const { createXssBrowserQualification } = require('./xssBrowserQualification');
const { createBoundBrowserRouter } = require('../routes/secureshop/boundBrowser');
const { createSecureShopPersonaInboxComposition } = require('./secureshopPersonaInboxComposition');
const { assertSecureShopMcpTrustReadiness, createSecureShopMcpTrustProduction }
  = require('./secureshopMcpTrustProduction');
const { createBoundMcpTrustRouter } = require('../routes/secureshop/boundMcpTrust');
const { activationPolicy: ssrfActivationPolicy, createSecureShopSsrfRepositoryBundle,
  assertSecureShopSsrfReadiness } = require('./secureshopSsrfProduction');
const { createSecureShopSsrfComposition } = require('./secureshopSsrfComposition');
const { createBoundSsrfRouter } = require('../routes/secureshop/boundSsrf');

const WORKSHOP_KEY = 'secureshop_agent_security';
// These objectives belong to the review and browser panels that are always
// mounted by the bound application. Feature-gated panels validate their own
// objective subsets only when their activation policy is requested.
const DEFAULT_OBJECTIVES = Object.freeze([
  'ss_loop_observation', 'ss_content_persist', 'ss_content_followed',
  'ss_stored_browser_execution',
]);
const STORE_MIGRATIONS = Object.freeze({
  identity: path.join(__dirname, '../../db/postgres/identity-migrations'),
  agents: path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents'),
  review: path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review'),
  commerce: path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop'),
});
const EXPECTED_ROLES = Object.freeze({
  identity: 'dvaia_identity_runtime',
  agents: 'dvaia_secureshop_agents_runtime',
  review: 'dvaia_secureshop_review_runtime',
  commerce: 'dvaia_secureshop_runtime',
});
const EXPECTED_MIGRATION_ROLES = Object.freeze({
  identity: 'dvaia_identity_migration',
  agents: 'dvaia_secureshop_agents_migration',
  review: 'dvaia_secureshop_review_migration',
  commerce: 'dvaia_secureshop_migration',
});
const MIGRATION_ENV = Object.freeze({ identity: 'IDENTITY_MIGRATION_DATABASE_URL',
  agents: 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',
  review: 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL',
  commerce: 'SECURESHOP_MIGRATION_DATABASE_URL' });
const REQUIRED_ENV = Object.freeze([
  'IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL',
  'SECURESHOP_AGENTS_DATABASE_URL', 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',
  'SECURESHOP_REVIEW_DATABASE_URL', 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL',
  'SECURESHOP_DATABASE_URL', 'SECURESHOP_MIGRATION_DATABASE_URL', 'JWT_SECRET',
]);
const REQUIRED_RELATIONS = Object.freeze({
  identity: Object.freeze(['identity.secureshop_launches',
    'secureshop_auth.principals', 'secureshop_auth.sessions',
    'secureshop_auth.practice_preferences', 'secureshop_auth.practice_selections',
    'secureshop_auth.practice_operations', 'secureshop_auth.practice_publications',
    'identity.secureshop_authority_owners', 'identity.secureshop_authority_sessions',
    'identity.secureshop_scenes', 'identity.secureshop_scene_execution_grants',
    'identity.secureshop_launch_resets',
    'identity.secureshop_target_reservations',
    'identity.secureshop_target_cleanup_history',
    'identity.secureshop_conversation_cleanup_history',
    'identity.secureshop_progress_cleanup_history',
    'identity.secureshop_owner_resets',
    'identity.secureshop_owner_reset_launches',
    'identity.student_deletion_jobs',
    'identity.student_deletion_steps',
    'identity.student_deletion_run_blocks',
    'identity.student_deletion_secureshop_resets',
    'workshop_platform.objective_contributions']),
  agents: Object.freeze(['secureshop_agents.turn_requests',
    'secureshop_agents.customer_chat_turn_bindings',
    'secureshop_agents.role_chat_turn_bindings',
    'secureshop_agents.conversation_generation_retirements',
    'secureshop_agents.bound_persona_template_catalog',
    'secureshop_agents.bound_persona_templates',
    'secureshop_agents.bound_actor_identities',
    'secureshop_agents.bound_persona_sessions']),
  review: Object.freeze(['secureshop_review.reviews',
    'secureshop_review.scene_execution_grants',
    'secureshop_review.review_cleanup_receipts',
    'secureshop_review.product_targets', 'secureshop_review.product_target_products',
    'secureshop_review.product_target_cart_items', 'secureshop_review.product_target_orders',
    'secureshop_review.product_target_order_items',
    'secureshop_review.practice_payment_methods',
    'secureshop_review.chat_commerce_choices',
    'secureshop_review.chat_commerce_operations',
    'secureshop_review.owned_idor_lesson_births',
    'secureshop_review.owned_idor_lesson_operations',
    'secureshop_review.product_target_merchant_listings',
    'secureshop_review.product_target_listing_overlays',
    'secureshop_review.owned_merchant_listing_edit_receipts',
    'secureshop_review.owned_merchant_listing_create_receipts',
    'secureshop_review.product_listing_cleanup_receipts',
    'secureshop_review.product_target_profile_overlays',
    'secureshop_review.product_target_addresses',
    'secureshop_review.product_account_cleanup_receipts',
    'secureshop_review.product_cleanup_receipts',
    'secureshop_review.product_target_refund_requests',
    'secureshop_review.product_target_refund_cleanup_receipts',
    'secureshop_review.product_target_retrieval_config',
    'secureshop_review.product_target_retrieval_documents',
    'secureshop_review.product_target_retrieval_ingest_receipts',
    'secureshop_review.product_target_retrieval_cleanup_receipts',
    'secureshop_review.product_target_manual_ingests',
    'secureshop_review.product_target_manual_runtime_receipts',
    'secureshop_review.product_target_embedding_revisions',
    'secureshop_review.product_target_embedding_preimages',
    'secureshop_review.product_target_manual_preimages',
    'secureshop_review.product_target_embedding_vectors',
    'secureshop_review.product_target_embedding_heads',
    'secureshop_review.product_target_embedding_cleanup_receipts',
    'secureshop_review.bound_system_restart_targets',
    'secureshop_review.bound_system_restart_operations',
    'secureshop_review.bound_system_restart_retirements',
    'secureshop_review.bound_system_restart_owner_deletion_receipts']),
  commerce: Object.freeze(['secureshop.shop_users', 'secureshop.products',
    'secureshop.product_images']),
});
const MANUAL_APPEND_ARGUMENTS = 'uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb';
const EMBEDDING_READ_TABLES = Object.freeze(['manual_runtime_receipts', 'embedding_revisions',
  'embedding_vectors', 'embedding_heads', 'embedding_cleanup_receipts', 'embedding_preimages', 'manual_preimages'].map(
  name => `secureshop_review.product_target_${name}`));
const EMBEDDING_EXECUTE_FUNCTIONS = Object.freeze([
  `secureshop_review.append_product_manual_retrieval_attested(${MANUAL_APPEND_ARGUMENTS},bytea)`,
  'secureshop_review.manual_runtime_receipt_digest(uuid,bytea,bytea)',
    'secureshop_review.capture_product_manual_preimage(uuid,uuid,jsonb)',
  'secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb)',
  'secureshop_review.product_embedding_source_digest(uuid,bigint)',
]);
const EMBEDDING_DENIED_FUNCTIONS = Object.freeze([
  `secureshop_review.append_product_manual_retrieval(${MANUAL_APPEND_ARGUMENTS})`,
  'secureshop_review.cleanup_retired_product_embeddings(uuid)',
]);

async function assertEmbeddingPrivileges(pool) {
  // Check effective runtime privileges, including inherited and PUBLIC grants.
  const tables = (await pool.query(`SELECT value,
    has_table_privilege(current_user,to_regclass(value),'SELECT')
    AND NOT has_table_privilege(current_user,to_regclass(value),'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege(current_user,to_regclass(value),'INSERT,UPDATE,REFERENCES') AS ready
    FROM unnest($1::text[]) value`, [EMBEDDING_READ_TABLES])).rows;
  const functions = (await pool.query(`SELECT value,
    to_regprocedure(value) IS NOT NULL AND
    has_function_privilege(current_user,to_regprocedure(value),'EXECUTE') = expected AS ready
    FROM unnest($1::text[],$2::boolean[]) AS required(value,expected)`, [
    [...EMBEDDING_EXECUTE_FUNCTIONS, ...EMBEDDING_DENIED_FUNCTIONS],
    [...EMBEDDING_EXECUTE_FUNCTIONS.map(() => true), ...EMBEDDING_DENIED_FUNCTIONS.map(() => false)],
  ])).rows;
  if (tables.length !== EMBEDDING_READ_TABLES.length
      || functions.length !== EMBEDDING_EXECUTE_FUNCTIONS.length + EMBEDDING_DENIED_FUNCTIONS.length
      || [...tables, ...functions].some(row => row.ready !== true)) {
    throw unavailable('SecureShop embedding runtime privileges are not ready');
  }
}
const MAX_FIXTURES = 256;

function unavailable(message = 'SecureShop bound review runtime is unavailable') {
  return Object.assign(new Error(message), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
}

function createCheckoutAuditReadStore({ reviewPool, launches } = {}) {
  if (!callable(reviewPool, ['query', 'connect']) || !callable(launches, ['assertCurrent'])) {
    throw unavailable('Checkout audit read authority unavailable');
  }
  return require('../database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({
    store: 'review', pool: reviewPool, checkCurrent: value => launches.assertCurrent(value),
  });
}
function createMailActionPolicyCheck(repository){
  return async({context,action,beforeEffect}={})=>{
    const toolKey=action==='send'?'merchant.mail_send_prepare'
      :action==='reply'?'merchant.mail_reply_prepare':null;
    if(!toolKey||typeof repository?.readPolicy!=='function')
      throw Object.assign(new Error('Mail action unavailable'),{code:'ACL_TOOL_UNAVAILABLE'});
    const policy=await repository.readPolicy(context);
    const row=policy?.rows?.find(value=>value.toolKey===toolKey);
    if(typeof policy?.enforcement!=='boolean'||!row?.supported
      ||row.roleApplicability?.merchant!==true)
      throw Object.assign(new Error('Mail action unavailable'),{code:'ACL_TOOL_UNAVAILABLE'});
    if(policy.enforcement&&row.allowed?.merchant!==true)
      throw Object.assign(new Error('Mail action denied'),{code:'MAIL_ACTION_POLICY_DENIED'});
    await beforeEffect?.();
  };
}
function callable(value, names) {
  return value && names.every(name => typeof value[name] === 'function');
}
function snapshotObjectives(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 64
      || Object.keys(values).length !== values.length
      || values.some(value => typeof value !== 'string' || !/^[a-z][a-z0-9_]{0,99}$/.test(value))
      || new Set(values).size !== values.length) throw unavailable('SecureShop catalog requirements are invalid');
  return Object.freeze([...values].sort());
}
function snapshotFixtures(values) {
  if (!Array.isArray(values) || values.length > MAX_FIXTURES
      || Object.keys(values).length !== values.length) throw unavailable('SecureShop review fixtures are invalid');
  return Object.freeze(values.map(row => Object.freeze({ productId: row.productId,
    authorId: row.authorId, body: row.body, rating: row.rating })));
}
function snapshotFixtureProfiles(values) {
  if (!Array.isArray(values) || values.length > 16
      || Object.keys(values).length !== values.length) {
    throw unavailable('SecureShop compatible review fixture profiles are invalid');
  }
  return Object.freeze(values.map(snapshotFixtures));
}

async function assertLedger(pool, directory) {
  const expected = await readMigrations(directory);
  const actual = (await pool.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  if (actual.length !== expected.length
      || actual.some((row, index) => row.name !== expected[index].name
        || row.checksum !== expected[index].checksum)) {
    throw unavailable('SecureShop store migration history is not ready');
  }
}

async function assertSecureShopBoundReviewReadiness({ identityPool, agentsPool, reviewPool, commercePool,
  migrationPools, requiredObjectives = DEFAULT_OBJECTIVES } = {}) {
  const pools = { identity: identityPool, agents: agentsPool, review: reviewPool, commerce: commercePool };
  const ledgers = migrationPools || pools;
  if (Object.values(pools).some(pool => !callable(pool, ['query']))
      || Object.values(ledgers).some(pool => !callable(pool, ['query']))) throw unavailable();
  const objectives = snapshotObjectives(requiredObjectives);
  // Drain every store probe before callers close the short-lived migration
  // pools. Promise.all would reject early while sibling ledger reads were
  // still using pools that the getter's finally block had begun to close.
  const probed = await Promise.allSettled(Object.entries(pools).map(async ([store, pool]) => {
    const row = (await pool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
    if (row?.role !== EXPECTED_ROLES[store] || typeof row.database !== 'string' || !row.database) {
      throw unavailable('SecureShop store runtime identity is not ready');
    }
    const migration = (await ledgers[store].query(
      'SELECT current_user AS role,current_database() AS database')).rows[0];
    if (migration?.role !== EXPECTED_MIGRATION_ROLES[store]
        || migration.database !== row.database) {
      throw unavailable('SecureShop store migration identity is not ready');
    }
    await assertLedger(ledgers[store], STORE_MIGRATIONS[store]);
    const relations = (await pool.query(
      'SELECT value,to_regclass(value) IS NOT NULL AS ready FROM unnest($1::text[]) value',
      [REQUIRED_RELATIONS[store]])).rows;
    if (relations.length !== REQUIRED_RELATIONS[store].length
        || relations.some(row => row.ready !== true)) {
      throw unavailable('SecureShop store schema is not ready');
    }
    if (store === 'review') await assertEmbeddingPrivileges(pool);
    if (store === 'identity') {
      const capabilities = (await pool.query(`SELECT conname,
          position(quote_literal('products') in pg_get_constraintdef(oid))>0 AS ready
        FROM pg_constraint WHERE conname=ANY($1::text[])
        ORDER BY conname`, [[
        'secureshop_target_cleanup_history_target_kind_check',
        'secureshop_target_reservations_target_kind_check',
      ]])).rows;
      if (capabilities.length !== 2 || capabilities.some(row => row.ready !== true)) {
        throw unavailable('SecureShop product reservation capability is not ready');
      }
    }
    return row.database;
  }));
  const failed = probed.find(result => result.status === 'rejected');
  if (failed) throw failed.reason;
  const identities = probed.map(result => result.value);
  if (new Set(identities).size !== identities.length) {
    throw unavailable('SecureShop stores are not isolated');
  }
  const catalog=(await identityPool.query(`SELECT objective_id,catalog_active FROM secureshop_auth.assessment_objectives
    WHERE objective_id=ANY($1::text[])`,[objectives])).rows;
  if(!objectives.every(id=>catalog.some(row=>row.objective_id===id&&row.catalog_active===true)))
    throw unavailable('SecureShop grading catalog is not ready');
  return Object.freeze({ workshopKey: WORKSHOP_KEY, objectives });
}

async function assertPersonaInboxReadiness({ identityPool, agentsPool } = {}) {
  const relations = ['secureshop_agents.persona_inbox_targets',
    'secureshop_agents.persona_inbox_messages', 'secureshop_agents.persona_inbox_acl_versions',
    'secureshop_agents.persona_inbox_access_events', 'secureshop_agents.persona_inbox_cleanup_receipts'];
  const rows = (await agentsPool.query(
    'SELECT value,to_regclass(value) IS NOT NULL AS ready FROM unnest($1::text[]) value', [relations])).rows;
  const constraints = (await identityPool.query(`SELECT conname,
      position(quote_literal('persona_inbox') in pg_get_constraintdef(oid))>0 AS ready
    FROM pg_constraint WHERE conname=ANY($1::text[]) ORDER BY conname`, [[
    'secureshop_target_cleanup_history_target_kind_check',
    'secureshop_target_reservations_target_kind_check',
  ]])).rows;
  const objectives = (await identityPool.query(`SELECT objective_id,catalog_active
    FROM secureshop_auth.assessment_objectives WHERE objective_id=ANY($1::text[])`,
  [Object.values(require('./secureshopPersonaInboxAssessment').OBJECTIVES)])).rows;
  if (rows.length !== relations.length || rows.some(row => row.ready !== true)
      || constraints.length !== 2 || constraints.some(row => row.ready !== true)
      || objectives.length !== 3 || objectives.some(row => row.catalog_active !== true)) {
    throw unavailable('Persona inbox feature schema or objectives are not ready');
  }
  return true;
}

function createAgencyRoleSourceReader({identityPool,agentsPool,conversations,customerChat,personaAuthority,
 agencyRoleRepository,bindingRepository}){
 if([identityPool?.query,agentsPool?.query,conversations?.getMessages,conversations?.getTraceEvents,
  customerChat?.readRequest,personaAuthority?.capture,agencyRoleRepository?.readWithClient,bindingRepository?.read]
  .some(fn=>typeof fn!=='function'))throw unavailable('Agency role source reader unavailable');
 const fail=()=>unavailable('Agency role source unavailable');
 const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[0-9a-f]{12}$/i;
 return Object.freeze({async read(input){
  if(!uuid.test(input?.sessionId||'')||!uuid.test(input?.requestId||'')||typeof input.check!=='function'
   ||!input.target?.scene)throw fail();
  await input.check();
  const saved=await customerChat.readRequest(input.scope,input.persona,input.personaSession,
   input.sessionId,input.requestId);
  if(saved.status!=='completed'||!saved.agencyRole)return null;
  const binding=createConversationBinding(input.scope,input.persona);
  const rows=(await agentsPool.query(`SELECT tr.session_id,tr.request_id,tr.request_hash,tr.request_version,
    tr.status,tr.result_json FROM secureshop_agents.turn_requests tr
    JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
    WHERE tr.session_id=$1 AND tr.request_id=$2 AND s.authority_mode='launch_bound'
      AND s.binding_state='active' AND s.conversation_purpose=$3
      AND s.platform_launch_id=$4 AND s.platform_scenario_id=$5 AND s.platform_launch_generation=$6
      AND s.original_platform_owner_id=$7 AND s.original_platform_session_id=$8
      AND s.user_id=$9 AND s.role='customer' LIMIT 2`,
   [input.sessionId,input.requestId,SECURESHOP_CONVERSATION_PURPOSES.customerChat,
    binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,
    binding.platformSessionId,binding.shopUserId])).rows;
  await input.check();if(rows.length!==1||rows[0].status!=='completed')throw fail();
  const row=rows[0],meta=row.result_json?.taskMetadata?.agencyRole;
  if(!meta||meta.receipt?.after?.role!==saved.agencyRole.teachingRole)throw fail();
  const r=meta.receipt;
  const messages=await conversations.getMessages(input.sessionId,binding,SECURESHOP_CONVERSATION_PURPOSES.customerChat);
  const originals=messages.filter(m=>{if(m?.role!=='user'||typeof m.content!=='string')return false;
   try{return createTurnRequest({sessionId:input.sessionId,requestId:input.requestId,
    binding,message:m.content}).hash===row.request_hash}catch{return false}});
  if(originals.length!==1)throw fail();
  const bound=await bindingRepository.read({sessionId:input.sessionId,requestId:input.requestId,
   scope:binding,persona:input.persona});
  const captured=require('../database/postgres/secureshopCustomerChatBindingRepository').capture({
   sessionId:input.sessionId,requestId:input.requestId,scope:binding,persona:input.persona,
   personaSession:input.personaSession,target:input.target,message:originals[0].content});
  if(!bound||bound.envelope_sha256!==captured.envelopeSha256
   ||bound.request_hash!==captured.requestHash||row.request_hash!==captured.requestHash)throw fail();
  const traces=await conversations.getTraceEvents(input.sessionId,binding,meta.traceEventIds,
   SECURESHOP_CONVERSATION_PURPOSES.customerChat);
  await input.check();if(traces.length!==meta.traceEventIds.length)throw fail();
  const ownerKey=JSON.stringify(['SecureShopBoundConversation',input.sessionId]);
  const runs=(await identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,status
    FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2 LIMIT 2`,[r.runId,ownerKey])).rows;
  await input.check();if(runs.length!==1)throw fail();
  const effects=(await identityPool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,
    e.effect_key,e.status,run.status AS run_status,owner.generation::text AS live_generation
    FROM graph_runtime.effects e JOIN graph_runtime.runs run
      ON run.run_id=e.run_id AND run.owner_key=e.owner_key AND run.generation=e.generation
    JOIN graph_runtime.owners owner ON owner.owner_key=e.owner_key
    WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4 LIMIT 2`,
   [r.runId,ownerKey,runs[0].generation,`${input.requestId}:${r.effectKey}`])).rows;
  await input.check();if(effects.length!==1)throw fail();
  const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,
   role:'customer',...input.personaSession});
  if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function')throw fail();
  const readback=await withSceneLease(input.target,async()=>{await input.check();
   const value=await fence.withPersonaEffect(client=>agencyRoleRepository.readWithClient(client,{
    scope:r.scope,scene:r.scene,persona:r.persona,personaSession:input.personaSession}));
   await input.check();return value});
  return Object.freeze({row:structuredClone(row),originalEnvelope:originals[0].content,
   sourceBinding:structuredClone(captured),
   traces:structuredClone(traces),graphRun:structuredClone(runs[0]),
   graphEffect:structuredClone(effects[0]),readback:structuredClone(readback)});
 }});
}

function createSecureShopBoundReviewComposition({ identityPool, agentsPool, reviewPool, commercePool, leasePool, gradingCore, gradingBootstrap, assessmentReleaseAdmission,
  agentRuntime, authenticatePersona, personaAuth, personaRepository, catalog, productRepository, modeAuthority, scenes,
  productAssist, toolPolicyRepository, promptPolicyRepository, promptPolicyRenderer, uploadAssetOrigin, uploadAssetCapability, uploadPreviewClient, taskPoliciesEnabled = false, couponDependencies, couponProbeDependencies, productSearchDependencies, orderStatusDependencies,
  inventoryApplication, pricingApplication, rawListingAssessment,
  account, accountRepository, administrationRepository, passwordResetRepository, audit,
  jwtSecret, files, fixtures, compatibleFixtures, requiredObjectives,
  launches, cleanupAuthority,
  conversationRepository, journal, reviewRepository, runCoordinator, judge,
  browserLifecycleObserver, searchEchoEvidenceVersion = 2, checkoutAuditLessonFeature = false, fileSummaryFeature = false, filePathSummaryFeature = false,
  reviewCardRenderer, browserQualification, policyOutputBrowserQualification, resetComposition, personaInboxFeature = false,
  ownedMcpRegistryReads = false, mcpRegistryApplication = () => null, mcpRegistrationApplication,
  registeredInvocationApplication = () => null,
  getAuditSearch = () => null, getAuditSummary = () => null, getAuditAgentReady = () => false,
  getSystemConfig = async () => null,
  getSystemRestart = () => null, getSystemDiagnostic = () => null,
  getMailApplication = () => null, getListingsApplication = () => null,
  mcpTrustFeature = false, mcpTrustFixtureRoot, ssrfFeature = false, ssrfFixtureRoot } = {}) {
  if (![2, 8, 9].includes(searchEchoEvidenceVersion)) throw unavailable('Unsupported search echo assessment evidence version');
  if (typeof taskPoliciesEnabled !== 'boolean') throw unavailable('Task policy readiness must be boolean');
  if (taskPoliciesEnabled && (promptPolicyRepository === undefined || productAssist !== undefined))
    throw unavailable('Task policies require owned product and review consumers');
  if (typeof personaInboxFeature !== 'boolean') throw unavailable('Persona inbox readiness must be boolean');
  if (typeof fileSummaryFeature !== 'boolean') throw unavailable('File summary feature must be boolean');
  if (typeof filePathSummaryFeature !== 'boolean') throw unavailable('File path summary feature must be boolean');
  if (typeof checkoutAuditLessonFeature !== 'boolean') throw unavailable('Checkout audit lesson readiness must be boolean');
  if (typeof ssrfFeature !== 'boolean') throw unavailable('SSRF readiness must be boolean');
  if (typeof mcpTrustFeature !== 'boolean') throw unavailable('MCP trust readiness must be boolean');
  if (typeof getAuditSearch !== 'function' || typeof getAuditSummary !== 'function'
      || typeof getAuditAgentReady !== 'function' || typeof getSystemConfig !== 'function'
      || typeof getSystemRestart !== 'function' || typeof getSystemDiagnostic !== 'function' || typeof getMailApplication !== 'function'
      || typeof getListingsApplication !== 'function') throw unavailable('Bound admin read composition required');
  const provider = agentRuntime?.provider || agentRuntime?.providerRouter;
  if (!callable(identityPool, ['query', 'connect']) || !callable(agentsPool, ['query', 'connect'])
      || !callable(reviewPool, ['query', 'connect'])
      || (!resetComposition && !callable(leasePool, ['query', 'connect']))
      || !callable(provider, ['chat'])) throw unavailable();
  if(gradingBootstrap!==undefined&&gradingCore!==undefined)throw unavailable('Prepared persona grading bootstrap required');
  require('./secureshopAssessmentReleaseAdmission').resolveAssessmentReleaseAdmission(
    assessmentReleaseAdmission,{identityPool,agentsPool,reviewPool,commercePool});
  if(assessmentReleaseAdmission!==undefined&&gradingBootstrap===undefined)
    throw unavailable('Disposable candidate requires prepared persona grading');
  let prepared;
  if(gradingBootstrap!==undefined){try{prepared=require('./secureshopGradingBootstrap').resolveSecureShopGradingBootstrap(
    gradingBootstrap,{identityPool,agentsPool,resetComposition,assessmentReleaseAdmission});}catch{throw unavailable('Prepared persona grading bootstrap required');}}
  const selectedCore=prepared?.gradingCore||gradingCore;
  const personaAuthority=prepared?.personaAuthority;
  const personaBindings=prepared?.personaBindings;
  if(toolPolicyRepository!==undefined && (typeof toolPolicyRepository?.admitTool!=='function'
      || !personaAuthority || productAssist!==undefined)) throw unavailable('Complete bound tool policy composition required');
  const grading = selectedCore === undefined
    ? {receipts:createObjectiveJudgmentRepository(identityPool),progress:createWorkshopProgressRepository(identityPool)}
    : require('./objectiveGradingCore').resolveObjectiveGradingDependencies(selectedCore,{identityPool,
      ...(prepared?{personaBindings}:{})});
  // Production persona readiness and effect dependencies must be installed as
  // one unit before a required-persona core may enter this composition.
  if (grading.personaBindings !== undefined && !prepared) throw unavailable('Persona grading production readiness unavailable');
  if(prepared&&(grading.personaBindings!==personaBindings
      ||prepared.assessmentDependencies!==grading))throw unavailable('Prepared persona grading dependencies mismatch');
  const objectiveReceipts = grading.receipts;
  const workshopProgress = grading.progress;
  resetComposition ||= createSecureShopCleanupComposition({ identityPool, agentsPool, reviewPool,
    leasePool, files, launches, cleanupAuthority, conversationRepository, journal, audit,
    reviewRepository, productRepository, runCoordinator,
    ...(mcpTrustFeature ? { mcpTrustFactory: createDefaultMcpTrustBundle, mcpTrustFixtureRoot } : {}),
    ...(ssrfFeature ? { ssrfFactory: createSecureShopSsrfRepositoryBundle, ssrfFixtureRoot } : {}) });
  if (audit && resetComposition.audit !== audit) throw unavailable('Audit writes and cleanup must share one bundle');
  audit = resetComposition.audit;
  if (files && files !== resetComposition.files) throw unavailable('File ingestion and cleanup must share one primitive');
  files = resetComposition.files;
  launches = resetComposition.launches;
  if (!callable(launches, ['assertCurrent', 'resolveCapability', 'reserveReviewsTarget',
    'reserveProductsTarget', 'beginReset', 'commitReset'])) throw unavailable();
  if(taskPoliciesEnabled&&!callable(launches,['readExistingProductsTarget']))throw unavailable('Policy retrieval target unavailable');
  const usesDefaultFixtures = fixtures === undefined;
  const configuredFixtures = snapshotFixtures(usesDefaultFixtures ? PREFERRED_REVIEW_FIXTURES : fixtures);
  const configuredCompatibleFixtures = snapshotFixtureProfiles(compatibleFixtures === undefined
    ? (usesDefaultFixtures ? [LEGACY_REVIEW_FIXTURES] : []) : compatibleFixtures);
  const authority = resetComposition.cleanupAuthority;
  if (!callable(authority, ['getOperation', 'checkTarget', 'checkReviewTarget', 'checkProductTarget', 'listTargets',
    'assertResolved', 'finalizeReconciliation'])) throw unavailable();
  const coordinator = resetComposition.runCoordinator;
  if (!callable(coordinator, ['run', 'reset'])) throw unavailable();
  const conversations = resetComposition.conversations;
  const turnsJournal = resetComposition.journal;
  const reviews = resetComposition.reviews;
  const products = resetComposition.products;
  async function resolveProductTarget(scope) {
    const reservation = await launches.reserveProductsTarget({ launchId: scope.launchId,
      platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
      expectedGeneration: scope.generation });
    return reservation;
  }
  if (!catalog) {
    if (!callable(commercePool, ['query'])) throw unavailable();
    catalog = createSecureShopBoundCatalog({ sourcePool: commercePool, repository: products,modeAuthority,
      ...(personaAuthority?{personaAuthority}:{}), ...(scenes ? { scenes } : {}),
      resolveTarget: resolveProductTarget, checkCurrent: value => launches.assertCurrent(value) });
  }
  if (!callable(catalog, ['listProducts', 'getProduct', 'listMerchantProducts',
    'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct',
    'hasProduct', 'prepareTarget'])) {
    throw unavailable();
  }
  const mailScenes = scenes && resetComposition.personaInbox && personaAuthority
    ? require('./secureshopMailScenes').createMailScenes({
      repository:require('../database/postgres/secureshopMailSceneRepository').createMailSceneRepository({pool:identityPool,launches}),
      scenes,catalog,agentsPool,launches,personaAuthority,
      inboxRepository:resetComposition.personaInbox.repository,
      resolveFixtures:async()=>require('./secureshopPersonaInboxComposition').mapPersonaInboxFixtures(await personaRepository.listPersonas()),
    }) : undefined;
  let productManualIngestion, roleProductRetrieval, manualRag, productSummary;
  if (productAssist === undefined || files) {
    const checkCurrent = value => launches.assertCurrent(value);
    const retrievalRepository = createSecureShopBoundProductRetrievalRepository(reviewPool, {
      checkCurrent, checkCleanup: value => authority.checkProductTarget(value),
    });
    const embedder = createSecureShopProductEmbedder();
    const revisionRepository = createSecureShopEmbeddingRevisionRepository(reviewPool, {
      checkCurrent, getRuntimeFingerprint: () => embedder.getRuntimeFingerprint()?.fingerprint,
    });
    const reindex = createSecureShopEmbeddingReindex({ repository: revisionRepository, embedder, checkCurrent });
    const retrieval = createSecureShopBoundProductRetrieval({ catalog,
      repository: retrievalRepository, embedder, checkCurrent, revisionRepository, reindex });
    roleProductRetrieval = retrieval;
    // Retrieval mutations are private to this graph's local tool. The retained
    // coordinator holds its session lease until tools drain; launch reset retires
    // every bound session before cleaning the canonical product target.
    let policySearch;
    if(taskPoliciesEnabled){
      const repository={async searchPolicies(input){
        const reservation=scenes ? await scenes.readExisting(input.scope) : await launches.readExistingProductsTarget(input.scope);
        if(!reservation||(!reservation.scene&&reservation.kind!=='products'))throw unavailable('Policy retrieval target unavailable');
        const binding=reservation.scene ? reservation : Object.freeze({...input.scope,targetId:reservation.targetId});await products.open(binding);
        const encoded=await embedder.embed(input.query);
        return revisionRepository.searchPolicies(binding,{embedding:encoded.embedding,limit:input.limit,policyVersion:input.policyVersion,policySnapshotSha256:input.policySnapshotSha256});
      }};
      policySearch=require('./secureshopBoundPolicySearch').createSecureShopBoundPolicySearch({repository,checkCurrent});
    }
    productAssist ||= createSecureShopBoundProductAssist({ launches, catalog, scenes, modeAuthority, taskPoliciesEnabled,
      ...(scenes && personaAuthority && personaBindings ? { afterSimilarCommit: async input => {
        if (manualRag) await manualRag.assessment.runAttempt(input);
      }, afterSummaryCommit: async input => {
        if (productSummary) await productSummary.assessment.runAttempt(input);
      } } : {}), ...(policySearch?{policySearch}:{}), ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
      conversationRepository: conversations, journal: turnsJournal, coordinator, provider,
      assessmentFactory: createSecureShopLoopAssessment({ receipts: objectiveReceipts,
        progress: workshopProgress, qualifyModel: createSecureShopModelQualifier(provider),
        ...(personaBindings?{personaBindings}:{}),
        ...(judge ? { judge } : {}),
      }).assessmentFactory,
      ...(personaAuthority?{personaAuthority}:{}),createProductTools: input => createSecureShopBoundProductTools({
        ...input, catalog, retrieval,
      }),
    });
    if (files) {
      if (!callable(catalog, ['getOwnedMerchantProduct'])) throw unavailable('Merchant product ownership unavailable');
      productManualIngestion = createSecureShopBoundManualIngestion({ launches, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
        conversationRepository: conversations, journal: turnsJournal, coordinator, provider,
        catalog, retrieval, writer: createSecureShopReservedFileWriter({ launches, files }),
        extractor: extractAndChunk, embedder,
        repository: createSecureShopBoundManualIngestRepository(reviewPool, { checkCurrent,
          getRuntimeFingerprint: () => embedder.getRuntimeFingerprint()?.fingerprint, ...(audit?{auditStore:audit.review}:{}) }),
        ...(personaAuthority?{personaAuthority}:{}),
      });
    }
  }
  if (!callable(productAssist, ['summary', 'similar'])) throw unavailable('Bound product assistant unavailable');
  if(couponDependencies&&(!personaAuthority||!couponDependencies.repository||(couponDependencies.workflow!==undefined&&typeof couponDependencies.workflow.apply!=='function')))throw unavailable('Bound coupon authority unavailable');
  const commerceRepository = createSecureShopBoundCommerceRepository(reviewPool, {
    ...(couponDependencies?{couponRepository:couponDependencies.repository}:{}),
    ...(personaAuthority ? { effectTimeoutMs: 3000 } : {}),
    ...(audit?{auditStore:audit.review}:{}),
    checkCurrent: value => launches.assertCurrent(value),
  });
  if (!personaRepository && commercePool) personaRepository = createSecureShopBoundPersonaRepository({ commercePool, agentsPool,
    ...(personaAuthority?{personaAuthority}:{}),...(audit?{auditStore:audit.agents}:{}) });
  const selectedSceneEffect = scenes && personaAuthority
    ? require('../database/postgres/secureshopSelectedSceneEffect')
      .createSelectedSceneEffect({ pool: identityPool, launches }) : undefined;
  const commerce = createSecureShopBoundCommerce({ repository: commerceRepository, catalog, personaRepository, ...(couponDependencies?{couponWorkflow:couponDependencies.workflow,mode:couponDependencies.mode,modeAuthority:couponDependencies.modeAuthority}:{}), ...(personaAuthority ? { personaAuthority, resolveExistingTarget: scope => scenes ? scenes.readExisting(scope) : launches.readExistingProductsTarget(scope) } : {}),
    ...(selectedSceneEffect ? { withSelectedSceneEffect: selectedSceneEffect } : {}) });
  // Direct prepared compositions use the same persona-bound ACL repository as
  // the installed lifecycle. Never expose conversational commerce with an
  // optional policy admission seam.
  const customerToolPolicy = scenes && prepared
    ? toolPolicyRepository || require('../database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority, audit: audit.agents })
    : toolPolicyRepository;
  let agencyRole;
  const agencyRoleRepository=createSecureShopOwnedAgencyRoleRepository();
  const customerBindingRepository=createCustomerChatBindingRepository({pool:agentsPool});
  const customerChat = scenes && personaAuthority ? createSecureShopBoundCustomerChat({
    launches,personaAuthority,modeAuthority,conversations,journal:turnsJournal,coordinator,provider,
    catalog,productRepository:products,commerceRepository,profileCommerce:commerce,scenes,
    bindingRepository:customerBindingRepository,
    agencyRoleRepository,afterRoleCommit:async input=>{if(agencyRole)await agencyRole.assessment.runAttempt(input)},
    ...(customerToolPolicy?{toolPolicyRepository:customerToolPolicy}:{}),...(promptPolicyRepository?{promptPolicyRepository}:{}),
  }) : null;
  if (!personaAuth && commercePool) {
    personaRepository ||= createSecureShopBoundPersonaRepository({ commercePool, agentsPool,
      ...(personaAuthority?{personaAuthority}:{}),...(audit?{auditStore:audit.agents}:{}) });
    personaAuth = createSecureShopBoundPersonaAuth({ repository: personaRepository,
      launches, jwtSecret, ...(personaAuthority?{personaAuthority}:{}) });
  }
  authenticatePersona ||= personaAuth?.authenticatePersona;
  if (typeof authenticatePersona !== 'function') throw unavailable();
  const customerChatRouter = customerChat ? createBoundCustomerChatRouter({launches,authenticatePersona,runtime:customerChat}) : null;
  let couponAgent;
  if (customerChat && selectedSceneEffect && couponDependencies?.workflow) {
    if (!callable(couponDependencies.workflow, ['apply', 'applyConfirmed', 'readConfirmed'])
      || !callable(modeAuthority, ['capture', 'assertToken'])
      || couponDependencies.modeAuthority !== modeAuthority
      || typeof couponDependencies.readCouponReceipt !== 'function'
      || !personaBindings
      || !callable(customerChat, ['captureCouponConfirmation'])
      || !callable(commerce, ['applyConfirmedCoupon','readConfirmedCoupon']))
      throw unavailable('Customer coupon confirmation unavailable');
    const confirmation = require('./secureshopCouponAgentConfirmation')
      .createCouponAgentConfirmation({
        captureCurrent: input => customerChat.captureCouponConfirmation(input),
        bindingRepository: createCustomerChatBindingRepository({ pool: agentsPool }),
        journal: turnsJournal, conversations,
        applyConfirmedCoupon: input => commerce.applyConfirmedCoupon(input),
        readConfirmedCoupon: input => commerce.readConfirmedCoupon(input),
        qualifyModel: createSecureShopModelQualifier(provider),
      });
    const couponJournal = Object.freeze({ ...turnsJournal,
      ...require('../database/postgres/secureshopCouponAgentAssessmentReader')
        .createCouponAgentAssessmentReader({ pool: agentsPool }) });
    const assessment = require('./secureshopCouponAgentAssessment').createCouponAgentAssessment({
      identityPool, launches, conversationRepository: conversations, coordinator,
      journal: couponJournal, personaAuthority, personaBindings,
      receipts: objectiveReceipts, progress: workshopProgress,
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider),
      captureCurrent: input => customerChat.captureCouponConfirmation(input),
      bindingRepository: createCustomerChatBindingRepository({ pool: agentsPool }),
      readConfirmedCoupon: input => commerce.readConfirmedCoupon(input),
      readCouponReceipt: couponDependencies.readCouponReceipt,
    });
    const router = require('express').Router();
    router.use(require('../routes/secureshop/boundCouponAgentConfirm')
      .createBoundCouponAgentConfirmRouter({ launches, authenticatePersona, confirmation }));
    router.use(require('../routes/secureshop/boundCouponAgentAssessment')
      .createBoundCouponAgentAssessmentRouter({ launches, authenticatePersona, assessment }));
    couponAgent = Object.freeze({ ready: true, confirmation, assessment, router });
  }
  let couponProbe;
  if (couponProbeDependencies !== undefined) {
    couponProbe = require('./secureshopCouponProbeComposition').createCouponProbeComposition({
      identityPool, agentsPool, launches, conversations, journal: turnsJournal,
      coordinator, provider, personaAuthority, personaBindings,
      receipts: objectiveReceipts, progress: workshopProgress, modeAuthority,
      customerChat, toolPolicyRepository: customerToolPolicy, promptPolicyRepository,
      authenticatePersona, probeDependencies: couponProbeDependencies, judge,
    });
  }
  const fileSummary = fileSummaryFeature ? require('./secureshopFileSummaryApplication')
    .createFileSummaryApplication({ launches, files: files ?? require('./secureshopOwnedFiles').getSecureShopOwnedFiles(),
      scenes, personaAuthority, modeAuthority, conversationRepository: conversations,
      journal: turnsJournal, coordinator, provider, toolPolicyRepository, identityPool, agentsPool,
      authenticatePersona, personaBindings, receipts: objectiveReceipts, progress: workshopProgress,
      publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider) }) : undefined;
  const filePathSummary = filePathSummaryFeature ? require('./secureshopV44FilePathSummaryApplication')
    .createFilePathSummaryApplication({ launches, files: files ?? require('./secureshopOwnedFiles').getSecureShopOwnedFiles(),
      scenes, personaAuthority, modeAuthority, conversationRepository: conversations,
      journal: turnsJournal, coordinator, provider, toolPolicyRepository, identityPool, agentsPool,
      authenticatePersona, personaBindings, receipts: objectiveReceipts, progress: workshopProgress,
      publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider) }) : undefined;
  let avatarUpload, accountAvatar, uploadRepository, uploadEffectReader, uploadWriter, uploadTraversalWriter;
  if (personaAuthority && modeAuthority && typeof scenes?.readRetained === 'function') {
    const {withTransaction}=require('../database/postgres');
    const sceneCheck=async scope=>{const target=await scenes.readRetained(scope);if(!target?.scene||target.targetId!==scope.targetId||target.scene.sceneId!==scope.sceneId||target.scene.sceneGeneration!==scope.sceneGeneration||target.scene.grantId!==scope.grantId)throw unavailable('Upload scene changed');return withTransaction(reviewPool,client=>require('./secureshopSceneBinding').assertSceneGrant(client,target));};
    const checkCurrent=scope=>launches.assertCurrent(scope);
    uploadRepository=require('../database/postgres/secureshopBoundUploadRepository').createSecureShopBoundUploadRepository(reviewPool,{checkCurrent,assertSceneGrant:sceneCheck,checkCleanupAuthority:(scope,operationId)=>resetComposition.cleanupAuthority.checkTarget({...scope,targetKind:'products',fromGeneration:scope.generation,operationId})});
    uploadEffectReader=require('../database/postgres/secureshopBoundUploadEffectReader').createSecureShopBoundUploadEffectReader(reviewPool,{checkCurrent,assertSceneGrant:sceneCheck});
    uploadWriter=require('./secureshopUploadWriter').createSecureShopUploadWriter();
    uploadTraversalWriter=require('./secureshopV46TraversalWriter').createSecureShopV46TraversalWriter();
    accountAvatar=require('./secureshopBoundAccountAvatar').createSecureShopBoundAccountAvatar({pool:reviewPool,launches,resolveTarget:scope=>scenes.readRetained(scope),personaAuthority,modeAuthority,journal:uploadRepository,effects:uploadEffectReader,writer:uploadWriter,traversalWriter:uploadTraversalWriter});
  }
  if (uploadAssetOrigin !== undefined || uploadAssetCapability !== undefined) {
    if (uploadAssetOrigin === undefined || uploadAssetCapability === undefined) throw unavailable('Bound avatar upload asset configuration incomplete');
    if (!uploadRepository || !toolPolicyRepository || typeof authenticatePersona !== 'function') throw unavailable('Bound avatar upload authority unavailable');
    const assetRepository=require('../database/postgres/secureshopBoundUploadAssetRepository').createSecureShopBoundUploadAssetRepository(reviewPool);
    avatarUpload=require('./secureshopBoundUploadComposition').createSecureShopBoundUploadComposition({identityPool,agentsPool,reviewPool,launches,conversationRepository:conversations,journal:turnsJournal,coordinator,provider,personaAuthority,modeAuthority,toolPolicyRepository,authenticatePersona,assetOrigin:uploadAssetOrigin,assetCapability:uploadAssetCapability,uploadPreviewClient,uploadRepository:uploadRepository,effectReader:uploadEffectReader,assetRepository,resolveTarget:scope=>scenes.readRetained(scope),writer:uploadWriter,traversalWriter:uploadTraversalWriter,personaBindings,scenes,receipts:objectiveReceipts,progress:workshopProgress,publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),qualifyModel:createSecureShopModelQualifier(provider)});
  }
  let productSearch;
  if (productSearchDependencies !== undefined) {
    productSearch = require('./secureshopProductSearchComposition').createProductSearchComposition({
      identityPool, agentsPool, launches, conversations, journal: turnsJournal,
      coordinator, provider, personaAuthority, personaBindings,
      receipts: objectiveReceipts, progress: workshopProgress, modeAuthority,
      customerChat, toolPolicyRepository: customerToolPolicy, promptPolicyRepository,
      authenticatePersona, searchDependencies: productSearchDependencies, judge,
    });
  }
  let orderStatus;
  if (orderStatusDependencies !== undefined) {
    orderStatus = require('./secureshopOrderStatusComposition').createOrderStatusComposition({
      identityPool, agentsPool, launches, conversations, journal: turnsJournal,
      coordinator, provider, personaAuthority, personaBindings,
      receipts: objectiveReceipts, progress: workshopProgress, modeAuthority,
      customerChat, toolPolicyRepository: customerToolPolicy, promptPolicyRepository,
      authenticatePersona, orderStatusDependencies: orderStatusDependencies, judge,
    });
  }
  let ticketAgent;
  if (customerChat && scenes && personaAuthority) {
    if (!callable(modeAuthority, ['capture', 'assertToken'])
        || !callable(customerChat, ['captureTicketConfirmation']))
      throw unavailable('Customer ticket confirmation unavailable');
    const repository = require('../database/postgres/secureshopTicketRepository')
      .createSecureShopTicketRepository({ pool: reviewPool,
        checkCurrent: scope => launches.assertCurrent(scope), modeAuthority });
    const confirmation = require('./secureshopTicketAgentConfirmation')
      .createTicketAgentConfirmation({
        captureCurrent: input => customerChat.captureTicketConfirmation(input),
        bindingRepository: createCustomerChatBindingRepository({ pool: agentsPool }),
        journal: turnsJournal, conversations,
        confirmTicket: input => {
          if (typeof input.withEffect !== 'function') throw unavailable('Ticket persona effect unavailable');
          // Repository acquires scene authority before entering this captured
          // persona fence, then opens its bounded review-store transaction.
          return repository.confirm(input);
        },
        readSavedTicket: input => repository.readSavedCustomer(input),
        qualifyModel: createSecureShopModelQualifier(provider),
      });
    const administration = require('./secureshopTicketAdministration')
      .createTicketAdministration({ launches, personaAuthority, modeAuthority, scenes, repository });
    const router = require('express').Router();
    router.use(require('../routes/secureshop/boundTicketConfirmation')
      .createBoundTicketConfirmationRouter({ launches, authenticatePersona, confirmation }));
    router.use(require('../routes/secureshop/boundTicketAdmin')
      .createBoundTicketAdminRouter({ launches, authenticatePersona, administration }));
    let assessment, ownedTicketBrowser, ticketBrowserClosed = false;
    const ticketBrowser = () => {
      if (ticketBrowserClosed) throw unavailable('Ticket browser assessment closed');
      return ownedTicketBrowser ||= require('./secureshopTicketBrowserQualification')
        .createSecureShopTicketBrowserQualification();
    };
    if (personaBindings) {
      const ticketJournal = Object.freeze({ ...turnsJournal,
        ...require('../database/postgres/secureshopTicketBrowserAssessmentReader')
          .createTicketBrowserAssessmentReader({ pool: agentsPool }) });
      assessment = require('./secureshopTicketBrowserAssessment').createTicketBrowserAssessment({
        identityPool, launches, conversationRepository: conversations, coordinator,
        journal: ticketJournal,
        bindingRepository: createCustomerChatBindingRepository({ pool: agentsPool }),
        personaAuthority, personaBindings, scenes, modeAuthority, ticketRepository: repository,
        receipts: objectiveReceipts, progress: workshopProgress,
        publicationModes: require('../database/postgres/secureshopModeRepository')
          .createSecureShopModeRepository(identityPool),
        judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
        qualifyModel: createSecureShopModelQualifier(provider),
        browserQualification: Object.freeze({
          readComponent: () => ticketBrowser().readComponent(),
          qualifyTicket: input => ticketBrowser().qualifyTicket(input),
        }),
      });
      if (!callable(assessment, ['runAttempt', 'readOutcome', 'assertRetainedPacket']))
        throw unavailable('Ticket assessment recovery unavailable');
      router.use(require('../routes/secureshop/boundTicketAssessment')
        .createBoundTicketAssessmentRouter({ launches, authenticatePersona, assessment }));
    }
    ticketAgent = Object.freeze({ ready: true, confirmation, administration, repository, router,
      ...(assessment ? { assessment } : {}),
      async close() { ticketBrowserClosed = true; await ownedTicketBrowser?.close(); },
    });
  }
  let searchEcho;
  if (customerChat && scenes && personaAuthority && personaBindings) {
    let ownedSearchBrowser, closed = false;
    const browser = () => {
      if (closed) throw unavailable('Search assessment closed');
      return ownedSearchBrowser ||= require('./secureshopSearchEchoBrowserQualification')
        .createSecureShopSearchEchoBrowserQualification();
    };
    const assessment = require('./secureshopSearchEchoBrowserAssessment').createSearchEchoBrowserAssessment({
      evidenceVersion: searchEchoEvidenceVersion,
      identityPool, agentsPool, launches, conversationRepository: conversations, coordinator,
      journal: turnsJournal, bindingRepository: createCustomerChatBindingRepository({ pool: agentsPool }),
      personaAuthority, personaBindings, scenes, modeAuthority,
      receipts: objectiveReceipts, progress: workshopProgress,
      publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider),
      browserQualification: Object.freeze({ readComponent: () => browser().readComponent(),
        qualifySearchEcho: input => browser().qualifySearchEcho(input) }),
    });
    searchEcho = Object.freeze({ ready: true, assessment,
      router: require('../routes/secureshop/boundSearchEchoAssessment')
        .createBoundSearchEchoAssessmentRouter({ launches, authenticatePersona, assessment }),
      async close() { closed = true; await ownedSearchBrowser?.close(); },
    });
  }
  if (scenes && personaAuthority && personaBindings) {
    const sourceAdapters = require('../database/postgres/secureshopManualRagSourceAdapter')
      .createManualRagSourceAdapter({ identityPool, agentsPool, reviewPool });
    const assessment = require('./secureshopManualRagAssessment').createManualRagAssessment({
      identityPool, agentsPool, launches, conversationRepository: conversations, coordinator,
      journal: turnsJournal, personaAuthority, personaBindings, scenes, modeAuthority,
      receipts: objectiveReceipts, progress: workshopProgress,
      publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      createSourceReader: current => require('./secureshopManualRagSourceReader')
        .createManualRagSourceReader({ ...sourceAdapters, current,
          qualifyModel: createSecureShopModelQualifier(provider) }),
    });
    manualRag = Object.freeze({ ready: true, assessment,
      router: require('../routes/secureshop/boundManualRagAssessment')
        .createBoundManualRagAssessmentRouter({ launches, authenticatePersona, assessment }) });
  }
  if (scenes && personaAuthority && personaBindings) {
    const assessment = require('./secureshopProductSummaryAssessment').createProductSummaryAssessment({
      identityPool, agentsPool, launches, conversationRepository: conversations, coordinator,
      journal: turnsJournal, personaAuthority, personaBindings, scenes, modeAuthority,
      receipts: objectiveReceipts, progress: workshopProgress,
      publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      createSourceReader: current => require('./secureshopProductSummarySourceReader')
        .createProductSummarySourceReader({ identityPool, agentsPool, reviewPool, current,
          qualifyModel: createSecureShopModelQualifier(provider) }),
    });
    productSummary = Object.freeze({ ready: true, assessment,
      router: require('../routes/secureshop/boundProductSummaryAssessment')
        .createBoundProductSummaryAssessmentRouter({ launches, authenticatePersona, assessment }) });
  }
  if(customerChat&&scenes&&personaAuthority&&personaBindings){
    const assessment=require('./secureshopAgencyRoleAssessment').createAgencyRoleAssessment({
      identityPool,agentsPool,launches,conversationRepository:conversations,coordinator,
      journal:turnsJournal,personaAuthority,personaBindings,scenes,modeAuthority,
      receipts:objectiveReceipts,progress:workshopProgress,
      publicationModes:require('../database/postgres/secureshopModeRepository')
       .createSecureShopModeRepository(identityPool),
      judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel:createSecureShopModelQualifier(provider),
      sourceReader:createAgencyRoleSourceReader({identityPool,agentsPool,conversations,customerChat,
       personaAuthority,agencyRoleRepository,bindingRepository:customerBindingRepository}),
    });
    agencyRole=Object.freeze({ready:true,assessment,
      router:require('../routes/secureshop/boundAgencyRoleAssessment')
       .createBoundAgencyRoleAssessmentRouter({launches,authenticatePersona,assessment})});
  }
  let idorLesson;
  if (scenes && personaAuthority && personaBindings) {
    const { createSecureShopBoundIdorLessonRepository, createImmutableTemplateVictimReader } =
      require('../database/postgres/secureshopBoundIdorLessonRepository');
    const lessonRepository = createSecureShopBoundIdorLessonRepository(reviewPool, {
      modeAuthority, readVictimIdentity: createImmutableTemplateVictimReader(agentsPool),
    });
    const lessonJournal = Object.freeze({ ...turnsJournal,
      ...require('../database/postgres/secureshopIdorLessonTurnReader')
        .createSecureShopIdorLessonTurnReader({ pool: agentsPool }),
    });
    const assessment = require('./secureshopIdorLessonAssessment').createIdorLessonAssessment({
      identityPool, assessmentReleaseAdmission, launches, conversationRepository: conversations, coordinator,
      journal: lessonJournal, personaAuthority, personaBindings, scenes,
      lessonRepository, receipts: objectiveReceipts, progress: workshopProgress,
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider), modeAuthority,
    });
    const lessonChat = require('./secureshopBoundIdorLessonChat')
      .createSecureShopBoundIdorLessonChat({ launches, personaAuthority, modeAuthority,
        conversations, journal: lessonJournal, coordinator, provider, scenes,
        lessonRepository, assessment });
    if (!callable(assessment, ['readOutcome','runAttempt']))
      throw unavailable('Isolated lesson assessment recovery unavailable');
    const lessonRuntime = Object.freeze({ ...lessonChat,
      readAssessment: input => assessment.readOutcome(input),
      retryAssessment: input => assessment.runAttempt(input),
    });
    idorLesson = Object.freeze({ ready: true, runtime: lessonRuntime,
      router: require('../routes/secureshop/boundIdorLesson').createBoundIdorLessonRouter({
        launches, authenticatePersona, runtime: lessonRuntime,
      }),
    });
  }
  let checkoutAuditLesson;
  if (checkoutAuditLessonFeature) {
    if (!scenes || !personaAuthority || !personaBindings || !jwtSecret || !audit?.review)
      throw unavailable('Checkout audit lesson authority unavailable');
    const secretMaterial = require('node:crypto').hkdfSync('sha256',
      Buffer.from(jwtSecret, 'utf8'), Buffer.from('dvaia/secureshop/v01/root/v1'),
      Buffer.from('isolated checkout audit teaching verifier'), 32);
    // The shared audit bundle owns append and cleanup, but its generic reader
    // has no launch authority. V01's protected order join uses the same review
    // store through a read-only capability that rechecks the current launch.
    const checkoutAuditStore = createCheckoutAuditReadStore({ reviewPool, launches });
    const lesson = require('./secureshopV01CheckoutAuditLesson').createV01CheckoutAuditLesson({
      secretMaterial: Buffer.from(secretMaterial),
      checkoutHistory: require('../database/postgres/secureshopCheckoutHistoryRepository')
        .createCheckoutHistoryRepository({pool:reviewPool,
          checkCurrent:value=>launches.assertCurrent(value)}),
      auditStore: checkoutAuditStore, launches, personaAuthority, modeAuthority,
      resolveExistingTarget: scope => scenes.readExisting(scope),
    });
    const lessonJournal = Object.freeze({...turnsJournal,
      ...require('../database/postgres/secureshopV01AuditTurnReader')
        .createV01AuditTurnReader({pool:agentsPool})});
    const chat = require('./secureshopV01AuditChat').createSecureShopV01AuditChat({
      launches, personaAuthority, modeAuthority, conversations,
      journal:lessonJournal, coordinator, provider, scenes, lesson,
    });
    const assessment = require('./secureshopV01AuditAssessment').createV01AuditAssessment({
      identityPool,agentsPool,launches,conversationRepository:conversations,
      coordinator,journal:lessonJournal,personaAuthority,personaBindings,scenes,
      modeAuthority,lesson,receipts:objectiveReceipts,progress:workshopProgress,
      publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
      judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel:createSecureShopModelQualifier(provider),
    });
    checkoutAuditLesson = Object.freeze({ready:true,runtime:chat,lesson,assessment,
      router:require('../routes/secureshop/boundV01AuditLesson')
        .createBoundV01AuditLessonRouter({ launches,authenticatePersona,runtime:chat,assessment }),
    });
  }
  const refundRepository = createSecureShopBoundRefundRepository(reviewPool, {
    ...(audit?{auditStore:audit.review}:{}),
    checkCurrent: value => launches.assertCurrent(value),
    checkCleanup: value => authority.checkProductTarget(value),
  });
  // Product reservations are deliberately minimal cleanup records.  Refund
  // tools also need the full launch/persona binding used by commerce and the
  // order repository, so resolve through the catalog's validated preparation
  // path rather than passing the raw reservation through.
  const resolveRefundTarget = scope => catalog.prepareTarget({
    scope,
    persona: { id: scope.shopUserId, role: scope.role },
  });
  accountRepository ||= createSecureShopBoundAccountRepository(reviewPool, {
    ...(personaAuthority?{effectTimeoutMs:3000}:{}),
    ...(audit?{auditStore:audit.review}:{}),
    checkCurrent: value => launches.assertCurrent(value),
  });
  if (!account) {
    if (!personaRepository) throw unavailable('Bound account persona source is unavailable');
    account = createSecureShopBoundAccount({ repository: accountRepository, personaRepository, catalog, ...(personaAuthority?{personaAuthority}:{}) });
  }
  const adminReads = require('../database/postgres/secureshopBoundAdminReadRepository').createSecureShopBoundAdminReadRepository({agentsPool,reviewPool});
  if (personaAuthority && !administrationRepository) {
    // This private repository instance exposes only effective-state reads to
    // BoundAdmin. Keep its mutation audit dependency fail closed when the
    // optional shared audit composition is absent.
    const adminAudit = typeof audit?.agents?.append === 'function' ? audit.agents
      : Object.freeze({ async append() { throw unavailable('Bound admin audit authority unavailable'); } });
    administrationRepository = require('../database/postgres/secureshopBoundUserAdministrationRepository')
      .createSecureShopBoundUserAdministrationRepository({ pool: agentsPool, auditStore: adminAudit,
        registeredRepository: require('../database/postgres/secureshopRegisteredUserAdministrationRepository').createRegisteredUserAdministrationRepository({pool:identityPool,checkCurrent:value=>launches.assertCurrent(value),personaAuthority}),
        checkCurrent: value => launches.assertCurrent(value) });
  }
  let mcpDiscoveryAssessmentForRead;
  const admin = personaRepository ? require('./secureshopBoundAdmin').createSecureShopBoundAdmin({
    launches, personas: personaRepository, account, catalog, commerceRepository, conversations,
    ...(personaAuthority ? { personaAuthority, accountRepository, administrationRepository } : {}),
    readAdapter: require('./secureshopOwnedMcpRegistryAdminReadOverlay').createOwnedMcpRegistryAdminReadOverlay({enabled:ownedMcpRegistryReads,readDiscoveryAssessment:async scope=>!!mcpDiscoveryAssessmentForRead
        &&(await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,scope,['ss_mcp_registry_internal_discovery'])).includes('ss_mcp_registry_internal_discovery'),repository:require('../database/postgres/secureshopOwnedMcpRegistryAdminReadRepository').createOwnedMcpRegistryAdminReadRepository({pool:agentsPool}),base:require('./secureshopBoundAdminReadAdapter').createSecureShopBoundAdminReadAdapter({
      repository: adminReads,
      mcpConfigured: mcpTrustFeature,
      readMcpAvailability: () => mcpTrustProduction.availability.read(),
      readRuntimeHealth: require('./secureshopBoundRuntimeHealth').createSecureShopBoundRuntimeHealth({
        repository:adminReads,provider,isServing:()=>!closing,
      }),
    })}),
    ...(audit?{auditRepository:audit.reader}:{}),
  }) : undefined;
  const personaObservations = personaAuthority ? require('./secureshopBoundPersonaObservations')
    .createBoundPersonaObservations({ conversations, personaAuthority, launches }) : undefined;
  const promptPolicies = promptPolicyRepository === undefined ? undefined
    : require('./secureshopBoundPromptPolicyService').createBoundPromptPolicyService({repository:promptPolicyRepository,renderer:promptPolicyRenderer,modeAuthority});
  const policyChat = promptPolicies ? require('./secureshopBoundPolicyChat').createBoundPolicyChat({
    service:promptPolicies,supportedTaskTargets:taskPoliciesEnabled?['summarizer','review-moderator']:[],
  }) : undefined;
  const policyTemplateAssessment = policyChat && personaAuthority && personaBindings
    ? require('./secureshopPolicyTemplateAssessment').createPolicyTemplateAssessment({
      identityPool, launches, conversationRepository: conversations, coordinator, journal: turnsJournal,
      personaAuthority, personaBindings, receipts: objectiveReceipts, progress: workshopProgress,
      judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel: createSecureShopModelQualifier(provider), modeAuthority, policyChat,
    }) : undefined;
  const mcpRegistryChat = ownedMcpRegistryReads && typeof admin?.mcpServers === 'function'
    && typeof admin?.mcpHistory === 'function' && typeof admin?.mcpTools === 'function'
    ? require('./secureshopBoundMcpRegistryChat').createBoundMcpRegistryChat({
      admin,getRegistry:mcpRegistryApplication}) : undefined;
  const accessControl = toolPolicyRepository === undefined ? undefined
    : require('./secureshopBoundAccessControl').createSecureShopBoundAccessControl({repository:toolPolicyRepository});
  const aclChat = accessControl ? require('./secureshopBoundAclChat')
    .createBoundAclChat({accessControl}) : undefined;
  const userAdministration = personaAuthority && administrationRepository && admin
    && typeof audit?.agents?.append === 'function'
    ? require('./secureshopBoundUserAdministration').createSecureShopBoundUserAdministration({
      repository: administrationRepository, personas: personaRepository, account,
      personaAuthority, modeAuthority, directory: admin,
      ...(passwordResetRepository===undefined?{}:{passwordResetRepository}),
      lookupRepository: require('../database/postgres/secureshopSyntheticUserDirectoryRepository')
        .createSyntheticUserDirectoryRepository({ pool: agentsPool, audit: audit.agents }),
    }) : undefined;
  const auditChat=admin&&typeof admin.audit==='function'
    ?require('./secureshopBoundAuditChat').createBoundAuditChat({admin,getAuditSearch}):undefined;
  const auditJobs=admin&&typeof admin.audit==='function'
    ?require('./secureshopBoundAuditJobs').createBoundAuditJobs({getAuditSearch,getAuditSummary,
      personaAuthority,modeAuthority,journal:turnsJournal,
      conversations:resetComposition.conversationService}):undefined;
  const systemReads=require('./secureshopRoleSystemReads').createRoleSystemReads({getSystemConfig});
  const systemConfigAssessment=personaAuthority&&personaBindings&&systemReads
    ?require('./secureshopSystemConfigAssessment').createSystemConfigAssessment({
      identityPool,launches,conversationRepository:conversations,coordinator,journal:turnsJournal,
      personaAuthority,personaBindings,receipts:objectiveReceipts,progress:workshopProgress,
      judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
      qualifyModel:createSecureShopModelQualifier(provider),modeAuthority,systemReads,scenes,
    }):undefined;
  const systemRestartChat=require('./secureshopBoundSystemRestartChat')
    .createBoundSystemRestartChat({getRestart:getSystemRestart});
  const systemDiagnosticChat=require('./secureshopBoundSystemDiagnosticChat')
    .createBoundSystemDiagnosticChat({getDiagnostic:getSystemDiagnostic});
  let mailChatApplication,mailChatAdapter;
  const activeMailChat=()=>{
    const application=getMailApplication();
    if(!application)throw Object.assign(new Error('Mail assistant unavailable'),{code:'MAIL_UNAVAILABLE'});
    if(application!==mailChatApplication){
      mailChatAdapter=require('./secureshopRoleMailRead').createBoundMailChat({
        mailApplication:application,listMailActors:scope=>personaRepository.listMailActors(scope),
        modeAuthority,mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln'});
      mailChatApplication=application;
    }
    return mailChatAdapter;
  };
  const mailChat=mailScenes&&typeof personaRepository?.listMailActors==='function'
    ?Object.freeze({get ready(){return getMailApplication()!=null},
      recipients:input=>activeMailChat().recipients(input),
      list:input=>activeMailChat().list(input),
      page:input=>activeMailChat().page(input),
      detail:input=>activeMailChat().detail(input),
      verify:input=>activeMailChat().verify(input)}) : undefined;
  let mailActionsApplication,mailActionsAdapter;
  const activeMailActions=()=>{
    const application=getMailApplication();
    if(!application)throw Object.assign(new Error('Mail assistant unavailable'),{code:'MAIL_UNAVAILABLE'});
    if(application!==mailActionsApplication){
      mailActionsAdapter=require('./secureshopRoleMailActions').createBoundMailActions({
        mailApplication:application,listMailActors:scope=>personaRepository.listMailActors(scope),
        modeAuthority,mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln'});
      mailActionsApplication=application;
    }
    return mailActionsAdapter;
  };
  const mailActions=mailChat?Object.freeze({get ready(){return getMailApplication()!=null},
    prepare:input=>activeMailActions().prepare(input),
    reconstruct:input=>activeMailActions().reconstruct(input),
    confirm:input=>activeMailActions().confirm(input),
    recover:input=>activeMailActions().recover(input)}):undefined;
  const listingsSetupAdapter=require('./secureshopRoleListingActionSetup')
    .createListingsChatSetup({getApplication:getListingsApplication});
  const listingsSetup=Object.freeze({get ready(){return getListingsApplication()!=null},
    prepare:input=>listingsSetupAdapter.prepare(input),
    reconstruct:input=>listingsSetupAdapter.reconstruct(input)});
  const assertMailActionAllowed=createMailActionPolicyCheck(toolPolicyRepository);
  // Role assistants are read-only until the separate trusted confirmation
  // adapter is qualified. No policy repository means no executable role tools.
  let roleReviewService;
  const roleAssistants = {};
  if (scenes && personaAuthority && toolPolicyRepository) {
    const admission = require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission;
    const bindingRepository = createRoleChatBindingRepository({pool:agentsPool});
    const policyInstructionAssessment=personaBindings&&promptPolicyRepository?.readAssessmentSnapshot
      &&promptPolicyRepository?.readAssessmentPublication&&typeof scenes.readRetained==='function'
      &&systemConfigAssessment
      ?require('./secureshopPolicyInstructionAssessment').createPolicyInstructionAssessment({
        identityPool,launches,conversationRepository:conversations,coordinator,journal:turnsJournal,
        roleBindings:bindingRepository,policyRepository:promptPolicyRepository,personaAuthority,
        personaBindings,receipts:objectiveReceipts,progress:workshopProgress,
        judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
        qualifyModel:createSecureShopModelQualifier(provider),modeAuthority,systemReads,scenes,
        readRetainedTarget:scope=>scenes.readRetained(scope),
      }):undefined;
    const systemDiagnosticAssessment = personaBindings
      ? require('./secureshopSystemDiagnosticAssessment').createSystemDiagnosticAssessment({
        identityPool, agentsPool, launches, conversationRepository: conversations, coordinator,
        journal: turnsJournal, personaAuthority, personaBindings, scenes, modeAuthority,
        receipts: objectiveReceipts, progress: workshopProgress,
        publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
        judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
        qualifyModel: createSecureShopModelQualifier(provider),
        readSource: input => roleAssistants.admin.runtime.readSystemDiagnosticAssessmentSource(input),
      }) : undefined;
    const systemRestartInjectionAssessment = personaBindings
      ? require('./secureshopSystemRestartInjectionAssessment').createSystemRestartInjectionAssessment({
        identityPool, agentsPool, launches, conversationRepository: conversations, coordinator,
        journal: turnsJournal, personaAuthority, personaBindings, scenes, modeAuthority,
        receipts: objectiveReceipts, progress: workshopProgress,
        publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
        judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
        qualifyModel: createSecureShopModelQualifier(provider),
        readSource: input => roleAssistants.admin.runtime.readSystemRestartInjectionAssessmentSource(input),
      }) : undefined;
    for (const role of ['merchant','admin']) {
      if (role === 'admin' && typeof admin?.audit !== 'function') continue;
      const toolPolicyAdmission = admission({repository:toolPolicyRepository,
        workflow:role==='admin'&&typeof mcpRegistrationApplication==='function'?'admin-registration-assistant':`${role}-assistant`,
        declaredTools:role==='admin'&&typeof mcpRegistrationApplication==='function'?[...ROLE_CHAT_TOOLS[role],ORIGINAL_REGISTER_TOOL,ORIGINAL_DESCRIBE_TOOL,ORIGINAL_LIST_TOOL]:ROLE_CHAT_TOOLS[role]});
      const roleChat = createSecureShopBoundRoleChat({role,launches,personaAuthority,modeAuthority,
        conversations,journal:turnsJournal,coordinator,provider,catalog,scenes,bindingRepository,
        toolPolicyAdmission,...(promptPolicyRepository?{promptPolicyRepository}:{}),
        ...(role==='admin'&&policyChat?{policyChat,policyTaskTargets:taskPoliciesEnabled?['summarizer','review-moderator']:[],policyTemplateAssessment}:{}),
        ...(role==='admin'?{mcpRegistryChat,mcpRegistrationApplication,registeredInvocationApplication,auditChat,auditJobs,
          auditAgentApplication:getAuditAgentReady,auditSummaryApplication:getAuditSummary,systemReads,systemConfigAssessment,policyInstructionAssessment,
          systemRestartChat,systemRestartApplication:getSystemRestart,systemDiagnosticChat,systemDiagnosticApplication:getSystemDiagnostic,systemDiagnosticAssessment,systemRestartInjectionAssessment,identityPool,aclChat}:{}),
        commerce,admin,productRetrieval:roleProductRetrieval,
        ...(role==='admin'?{userAdministration,userLookupAssessmentReady:async binding=>(await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,binding,['ss_user_lookup_sensitive_disclosure'],assessmentReleaseAdmission)).includes('ss_user_lookup_sensitive_disclosure')}:{}),
        inventoryApplication,pricingApplication,reviewApplication:()=>roleReviewService,
        ...(role==='merchant'?{listingsSetup}:{}),
        ...(role==='merchant'&&mailChat?{mailChat,mailActions,assertMailActionAllowed}:{})});
      const userLookupAssessment = role==='admin'&&personaBindings&&typeof userAdministration?.readAgentLookup==='function'
        ?require('./secureshopUserLookupAssessment').createUserLookupAssessment({
          identityPool,assessmentReleaseAdmission,agentsPool,launches,conversationRepository:conversations,coordinator,
          turnJournal:turnsJournal,bindingRepository,scenes,userAdministration,personaAuthority,personaBindings,
          receipts:objectiveReceipts,progress:workshopProgress,modeAuthority,
          publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
          judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
          qualifyModel:createSecureShopModelQualifier(provider),
        }):undefined;
      const mailAgentReadAssessment = role === 'merchant' && mailChat && personaBindings
        ? require('./secureshopMailAgentReadAssessment').createMailAgentReadAssessment({
          identityPool, agentsPool, launches, conversationRepository: conversations,
          coordinator, journal: turnsJournal, personaAuthority, personaBindings, scenes, modeAuthority,
          receipts: objectiveReceipts, progress: workshopProgress,
          publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
          judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
          qualifyModel: createSecureShopModelQualifier(provider),
          readSource: require('./secureshopMailAgentReadOriginalReader').createMailAgentReadOriginalReader({
            journal: turnsJournal, conversations, identityPool,
            readRequest: (...args) => roleChat.readRequest(...args),
            qualifyModel: createSecureShopModelQualifier(provider),
          }).read,
        }) : undefined;
      const mcpManifestAssessment = role === 'admin' && mcpRegistryChat && personaBindings
        ? require('./secureshopMcpManifestAssessment').createMcpManifestAssessment({
          identityPool, agentsPool, launches, conversationRepository: conversations,
          coordinator, turnJournal: turnsJournal, personaAuthority, personaBindings,
          bindingRepository, scenes,
          publicationModes: require('../database/postgres/secureshopModeRepository')
            .createSecureShopModeRepository(identityPool),
          registryRepository: require('../database/postgres/secureshopOwnedMcpRegistryRepository')
            .createOwnedMcpRegistryRepository({pool:agentsPool,personaAuthority}),
          receipts: objectiveReceipts, progress: workshopProgress,
          judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
          qualifyModel: createSecureShopModelQualifier(provider), modeAuthority,
          readRegistryMode: async () => {
            const configured = await mcpRegistryApplication();
            if (!configured || !['fixed','vuln'].includes(configured.mode))
              throw unavailable('Owned MCP registry unavailable');
            return configured.mode;
          },
        }) : undefined;
      const mcpRegistrySsrfAssessment = role === 'admin' && mcpRegistryChat && personaBindings
        ? require('./secureshopMcpRegistrySsrfAssessment').createMcpRegistrySsrfAssessment({
          identityPool, agentsPool, launches, conversationRepository: conversations,
          coordinator, turnJournal: turnsJournal, personaAuthority, personaBindings,
          bindingRepository, scenes,
          publicationModes: require('../database/postgres/secureshopModeRepository')
            .createSecureShopModeRepository(identityPool),
          registryRepository: require('../database/postgres/secureshopOwnedMcpRegistryRepository')
            .createOwnedMcpRegistryRepository({pool:agentsPool,personaAuthority}),
          receipts: objectiveReceipts, progress: workshopProgress,
          judge: judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
          qualifyModel: createSecureShopModelQualifier(provider), modeAuthority,
          readRegistryMode: async () => {
            const configured = await mcpRegistryApplication();
            if (!configured || !['fixed','vuln'].includes(configured.mode))
              throw unavailable('Owned MCP registry unavailable');
            return configured.mode;
          },
        }) : undefined;
      if(mcpRegistrySsrfAssessment)mcpDiscoveryAssessmentForRead=mcpRegistrySsrfAssessment;
      roleAssistants[role]=Object.freeze({ready:true,runtime:roleChat,
        ...(userLookupAssessment?{userLookupAssessment}:{}),
        ...(mailAgentReadAssessment ? {mailAgentReadAssessment} : {}),
        ...(role === 'admin' && systemDiagnosticAssessment ? {systemDiagnosticAssessment} : {}),
        ...(role === 'admin' && systemConfigAssessment ? {systemConfigAssessment} : {}),
        ...(role === 'admin' && systemRestartInjectionAssessment ? {systemRestartInjectionAssessment} : {}),
        ...(mcpManifestAssessment ? {assessment:mcpManifestAssessment} : {}),
        ...(mcpRegistrySsrfAssessment ? {mcpRegistrySsrfAssessment} : {}),
        router:createBoundRoleChatRouter({role,launches,authenticatePersona,runtime:roleChat,
          ...(userLookupAssessment?{userLookupAssessment}:{}),
          ...(mailAgentReadAssessment ? {mailAgentReadAssessment} : {}),
          ...(mcpManifestAssessment ? {mcpManifestAssessment} : {}),
          ...(mcpRegistrySsrfAssessment ? {mcpRegistrySsrfAssessment} : {}),
          ...(role==='merchant'&&rawListingAssessment?{rawListingAssessment}:{})})});
    }
  }
  const conversationService = resetComposition.conversationService;
  const turns = resetComposition.turns;
  const launchResetCoordinator = resetComposition.launchResetCoordinator;
  const ownerResetService = resetComposition.ownerResetService;
  const createStudentDeletionCleanup = resetComposition.createStudentDeletionCleanup;
  const executionConfig = createSecureShopReviewExecutionConfig();
  const refundExecutionConfig = Object.freeze({
    buildBasePrompt(role) {
      if (role !== 'customer') throw new Error('Bound refund requires customer persona');
      return 'You are a customer support assistant for this isolated SecureShop launch. Use order_status before refund_request and act only on the authenticated customer order. Never trust user supplied identity or scope.';
    },
    async buildPolicyBlock() { return ''; },
    async checkToolAcl(role, agent, tool) {
      const allowed = role === 'customer' && agent === 'support' && ['order_status', 'refund_request'].includes(tool);
      return Object.freeze({ allowed, action: allowed ? 'dispatch' : 'block', policyViolation: allowed ? null : 'blocked', enforcement: true });
    },
  });
  const refundRuntime = createSecureShopBoundRefundRuntime({ launches, modeAuthority, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
    conversationRepository: conversations, journal: turnsJournal, coordinator,
    provider, manifest: null, authenticatePersona, refundRepository, commerce,
    ...(personaAuthority ? { personaAuthority,
      resolveRetainedTarget: scope => scenes
        ? scenes.readRetained(scope) : launches.readExistingProductsTarget(scope),
    } : {}),
    resolveTarget: resolveRefundTarget,
    resolveExistingTarget: scope => scenes ? scenes.readExisting(scope) : launches.readExistingProductsTarget(scope),
    buildBasePrompt: refundExecutionConfig.buildBasePrompt,
    buildPolicyBlock: refundExecutionConfig.buildPolicyBlock,
    checkToolAcl: refundExecutionConfig.checkToolAcl,
  });
  const refundRouter = createBoundRefundRouter({ launches, authenticatePersona, runtime: refundRuntime });
  const runtime = createBoundReviewRuntime({ launches, modeAuthority, taskPoliciesEnabled, reviewRepository: reviews, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
    ...(scenes && personaAuthority ? {
      readRetainedReviewTarget: async scope => {
        const scene = await scenes.readRetained(scope);
        if (!scene) throw Object.assign(Error('Review scene unavailable'),{code:'SHOP_SCENE_STALE'});
        return reviews.readRetainedSceneTarget(scene);
      },
      // The at-effect reader is SELECT-only in both shop and platform realms;
      // ordinary platform mode capture may initialize workshop user state.
      readRecoveryMode: scope => require('../database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identityPool)
        .getEvaluationScopeAtEffect(scope.platformOwnerId,'secureshop_agent_security',scope),
    } : {}),
    conversationRepository: conversations, journal: turnsJournal, coordinator,
    authenticatePersona, buildBasePrompt: executionConfig.buildBasePrompt,
    buildPolicyBlock: executionConfig.buildPolicyBlock, checkToolAcl: executionConfig.checkToolAcl,
    provider, manifest: executionConfig.manifest,
    objectiveReceipts, workshopProgress,
    ...(personaAuthority?{personaAuthority}:{}),...(personaBindings?{personaBindings}:{}),
    fixtures: configuredFixtures, compatibleFixtures: configuredCompatibleFixtures,
    enableReviewContentAssessment: true,
    ...(scenes ? { withProvisionLease: scenes.withProvisionLease,
      mirrorReviewScene: resetComposition.sceneResetPreflight.mirrorReviewScene,
      resolveProductScene: async input => {
        if (input.persona) return catalog.prepareTarget(input);
        return scenes.readExisting(input.scope);
      } } : {}),
    validateProduct: input => catalog.hasProduct(input),
    ...(judge ? { judge } : {}),
  });
  if(scenes&&personaAuthority)roleReviewService=require('./secureshopRoleReviewService').createRoleReviewService({repository:reviews,application:runtime.application,authority:personaAuthority,modeAuthority,scenes});
  reviewCardRenderer ||= loadSecureShopReviewCardRenderer();
  if (!callable(reviewCardRenderer, ['renderReviewCard'])
      || typeof reviewCardRenderer.sourceSha256 !== 'string'
      || typeof reviewCardRenderer.artifactSha256 !== 'string') throw unavailable();
  const ownedBrowser = browserQualification === undefined;
  browserQualification ||= createXssBrowserQualification();
  const browserAssessment = createSecureShopStoredBrowserAssessment({ conversations: conversationService,
    turns, journal: turnsJournal, application: runtime.application, reviewRepository: reviews,
    receipts: objectiveReceipts, progress: workshopProgress,
    publicationModes: require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
    judge, browserQualification,
    renderReviewCard: reviewCardRenderer.renderReviewCard,
    componentSourceDigest: reviewCardRenderer.sourceSha256,
    componentArtifactDigest: reviewCardRenderer.artifactSha256,
    ...(personaAuthority?{personaAuthority}:{}),...(personaBindings?{personaBindings}:{}) });
  const browserRouter = createBoundBrowserRouter({ launches, authenticatePersona,
    assessment: browserAssessment,
    ...(browserLifecycleObserver ? { observeLifecycle: browserLifecycleObserver } : {}) });
  const personaInbox = createSecureShopPersonaInboxComposition({ enabled: personaInboxFeature, modeAuthority, mailScenes, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
    identityPool, provider, authenticatePersona, personaRepository, resetComposition, ...(selectedCore === undefined ? {} : {gradingCore:selectedCore}),
    ...(personaAuthority?{personaAuthority}:{}),...(personaBindings?{personaBindings}:{}),
    ...(judge ? { judge } : {}) });
  const mcpTrustProduction=createSecureShopMcpTrustProduction({enabled:mcpTrustFeature,modeAuthority, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),identityPool,provider,...(selectedCore === undefined ? {} : {gradingCore:selectedCore}),
    ...(personaAuthority?{personaAuthority}:{}),...(personaBindings?{personaBindings}:{}),
    resetComposition,...(judge?{judge}:{})});
  const mcpTrust=mcpTrustProduction.ready===true?Object.freeze({...mcpTrustProduction,
    router:createBoundMcpTrustRouter({launches,authenticatePersona,application:mcpTrustProduction.application})})
    :mcpTrustProduction;
  const ssrfProduction=createSecureShopSsrfComposition({enabled:ssrfFeature,modeAuthority, ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}), ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),identityPool,agentsPool,provider,...(selectedCore === undefined ? {} : {gradingCore:selectedCore}),
    ...(personaAuthority?{personaAuthority}:{}),...(personaBindings?{personaBindings}:{}),
    resetComposition,upstreamPool:agentRuntime?.pool,...(policyOutputBrowserQualification===undefined?{}:{policyOutputBrowserQualification}),...(judge?{judge}:{})});
  const ssrf=ssrfProduction.ready?Object.freeze({...ssrfProduction,
    router:createBoundSsrfRouter({launches,authenticatePersona,feature:ssrfProduction})}):ssrfProduction;
  let browserClosed = false;
  async function closeBrowserAssessment() {
    if (browserClosed) return;
    browserClosed = true;
    const closed = await Promise.allSettled([
      ...(ownedBrowser ? [browserQualification.close()] : []),
      ...(ticketAgent ? [ticketAgent.close()] : []),
      ...(searchEcho ? [searchEcho.close()] : []),
      ...(avatarUpload?.close ? [avatarUpload.close()] : []),
      ...(ssrfProduction?.close ? [ssrfProduction.close()] : []),
    ]);
    const failures = closed.filter(result => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new AggregateError(failures, 'Browser assessment cleanup incomplete');
  }
  return Object.freeze({ router: runtime.router, browserRouter, browserAssessment, browserQualification, personaInbox, mcpTrust, ssrf,
    ...(customerChatRouter?{customerChat:Object.freeze({ready:true,router:customerChatRouter,runtime:customerChat})}:{}),
    ...(idorLesson ? { idorLesson } : {}),
    ...(checkoutAuditLesson ? { checkoutAuditLesson } : {}),
    ...(couponAgent ? { couponAgent } : {}),
    ...(couponProbe ? { couponProbe } : {}),
    ...(avatarUpload ? { avatarUpload } : {}),
    ...(accountAvatar ? { accountAvatar } : {}),
    ...(fileSummary ? { fileSummary } : {}),
    ...(filePathSummary ? { filePathSummary } : {}),
    ...(productSearch ? { productSearch } : {}),
    ...(orderStatus ? { orderStatus } : {}),
    ...(ticketAgent ? { ticketAgent } : {}),
    ...(searchEcho ? { searchEcho } : {}),
    ...(manualRag ? { manualRag } : {}),
    ...(productSummary ? { productSummary } : {}),
    ...(agencyRole ? { agencyRole } : {}),
    roleAssistants:Object.freeze(roleAssistants),
    refund: Object.freeze({ ready: true, router: refundRouter, runtime: refundRuntime, repository: refundRepository }),
    closeBrowserAssessment, runtime, launches, catalog, commerce,
    conversationalCommerce: require('./secureshopConversationalCommerce').createConversationalCommerce({commerce}),
    account, admin, personaObservations, ...(scenes ? { scenes } : {}), ...(mailScenes ? {mailScenes} : {}),
    ...(userAdministration ? { userAdministration } : {}),
    ...(accessControl ? { accessControl } : {}),
    ...(promptPolicies ? { promptPolicies, ...(taskPoliciesEnabled ? { promptPolicyTaskTargets: Object.freeze(['summarizer', 'review-moderator']) } : {}) } : {}),
    ...(productAssist ? { productAssist } : {}),
    ...(productManualIngestion ? { productManualIngestion } : {}),
    ...(personaAuth ? { personaAuth } : {}),
    launchResetCoordinator, ownerResetService, createStudentDeletionCleanup,
    runCoordinator: coordinator,
    repositories: Object.freeze({ reviews, products, commerce: commerceRepository,
      account: accountRepository, conversations, journal: turnsJournal,
      ...(personaRepository ? { personas: personaRepository } : {}), refund: refundRepository }),
    requiredObjectives: snapshotObjectives(requiredObjectives || DEFAULT_OBJECTIVES) });
}

let retained;
let retainedInputs;
let pending;
let closing;
const OPTION_KEYS = Object.freeze(['gradingCore', 'gradingBootstrap', 'assessmentReleaseAdmission', 'agentRuntime', 'files', 'fixtures', 'compatibleFixtures', 'productAssist',
  'requiredObjectives', 'judge', 'policyOutputBrowserQualification', 'promptPolicyRenderer', 'uploadAssetOrigin', 'uploadAssetCapability', 'uploadPreviewClient', 'systemConfigClient', 'systemDiagnosticClient', 'systemRestartClient', 'pricingHttpClient', 'listingTemplateClient', 'systemRebuildEnabled', 'auditSummaryFeature', 'personaInboxFeature', 'mcpTrustFeature', 'mcpTrustFixtureRoot', 'ssrfFeature', 'ssrfFixtureRoot', 'checkoutAuditLessonFeature', 'fileSummaryFeature', 'filePathSummaryFeature']);
function sameInputs(left, right) {
  return left && right && OPTION_KEYS.every(key => left[key] === right[key]);
}
function snapshotProductionOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw unavailable();
  const identity = Object.freeze(Object.fromEntries(OPTION_KEYS.map(key => [key, options[key]])));
  const runtime = options.agentRuntime;
  const configured = Object.freeze({
    agentRuntime: runtime && Object.freeze({ provider: runtime.provider,
      providerRouter: runtime.providerRouter, pool: runtime.pool }),
    gradingCore: options.gradingCore,
    gradingBootstrap: options.gradingBootstrap,
    assessmentReleaseAdmission: options.assessmentReleaseAdmission,
    files: options.files,
    fixtures: snapshotFixtures(options.fixtures === undefined ? PREFERRED_REVIEW_FIXTURES : options.fixtures),
    compatibleFixtures: snapshotFixtureProfiles(options.compatibleFixtures === undefined
      ? (options.fixtures === undefined ? [LEGACY_REVIEW_FIXTURES] : []) : options.compatibleFixtures),
    requiredObjectives: snapshotObjectives(options.requiredObjectives === undefined
      ? DEFAULT_OBJECTIVES : options.requiredObjectives),
    judge: options.judge,
    ...(options.policyOutputBrowserQualification === undefined ? {} : {policyOutputBrowserQualification:options.policyOutputBrowserQualification}),
    ...(options.promptPolicyRenderer === undefined ? {} : {promptPolicyRenderer:options.promptPolicyRenderer}),
    ...(options.uploadAssetOrigin === undefined ? {} : {uploadAssetOrigin:options.uploadAssetOrigin}),
    ...(options.uploadAssetCapability === undefined ? {} : {uploadAssetCapability:options.uploadAssetCapability}),
    ...(options.uploadPreviewClient === undefined ? {} : {uploadPreviewClient:options.uploadPreviewClient}),
    ...(options.systemConfigClient === undefined ? {} : {systemConfigClient:options.systemConfigClient}),
    ...(options.systemDiagnosticClient === undefined ? {} : {systemDiagnosticClient:options.systemDiagnosticClient}),
    ...(options.systemRestartClient === undefined ? {} : {systemRestartClient:options.systemRestartClient}),
    ...(options.pricingHttpClient === undefined ? {} : {pricingHttpClient:options.pricingHttpClient}),
    ...(options.listingTemplateClient === undefined ? {} : {listingTemplateClient:options.listingTemplateClient}),
    systemRebuildEnabled: options.systemRebuildEnabled === true,
    auditSummaryFeature: options.auditSummaryFeature===true,
    personaInboxFeature: options.personaInboxFeature === true,
    mcpTrustFeature: options.mcpTrustFeature === true,
    mcpTrustFixtureRoot: options.mcpTrustFixtureRoot,
    ssrfFeature: options.ssrfFeature === true,
    checkoutAuditLessonFeature: options.checkoutAuditLessonFeature === true,
    fileSummaryFeature: options.fileSummaryFeature === true,
    filePathSummaryFeature: options.filePathSummaryFeature === true,
    ssrfFixtureRoot: options.ssrfFixtureRoot,
  });
  return Object.freeze({ identity, configured });
}

function attachAnalyticsComposition(composition, analytics) {
  // Analytics consumes policy snapshots, but is not an editable task target
  // in the prompt-policy mutation contract. Preserve the qualified targets.
  return Object.freeze({ ...composition, analytics });
}

async function createOptionalSystemConfigComposition({ systemConfigClient, preparedGrading,
  agentsPool, audit, authenticatePersona, modeAuthority } = {}, factories = {}) {
  if (systemConfigClient === undefined) return undefined;
  const createComposition = factories.createComposition
    || require('./secureshopSystemConfigComposition').createSecureShopSystemConfigComposition;
  if (!preparedGrading || typeof createComposition !== 'function') {
    throw unavailable('Prepared persona authority required for System config');
  }
  return createComposition({ agentsPool, personaAuthority: preparedGrading.personaAuthority,
    audit, client: systemConfigClient, authenticatePersona, modeAuthority });
}
async function createOptionalSystemDiagnosticComposition({ systemDiagnosticClient, preparedGrading,
  agentsPool, audit, authenticatePersona, modeAuthority } = {}, factories = {}) {
  if (systemDiagnosticClient === undefined) return undefined;
  const createComposition = factories.createComposition
    || require('./secureshopSystemDiagnosticComposition').createSecureShopSystemDiagnosticComposition;
  if (!preparedGrading || typeof createComposition !== 'function') {
    throw unavailable('Prepared persona authority required for System diagnostic');
  }
  return createComposition({ agentsPool, personaAuthority: preparedGrading.personaAuthority,
    audit, client: systemDiagnosticClient, authenticatePersona, modeAuthority });
}
async function createOptionalSystemRebuildComposition({ enabled, preparedGrading, reviewPool,
  launches, products, audit, authenticatePersona, policyRepository, scenes } = {}, factories = {}) {
  if (enabled !== true) return undefined;
  const createComposition = factories.createComposition
    || require('./secureshopSystemRebuildComposition').createSecureShopSystemRebuildComposition;
  if (!preparedGrading || typeof createComposition !== 'function') {
    throw unavailable('Prepared persona authority required for System rebuild');
  }
  return createComposition({ reviewPool, launches, products,
    ...(scenes ? { scenes } : {}),
    personaAuthority: preparedGrading.personaAuthority, audit, authenticatePersona,
    ...(policyRepository === undefined ? {} : { policyRepository }) });
}
async function createOptionalSystemRestartComposition({ systemRestartClient, preparedGrading, reviewPool,
  launches, products, audit, authenticatePersona, scenes, modeAuthority } = {}, factories = {}) {
  if (systemRestartClient === undefined) return undefined;
  const createComposition = factories.createComposition
    || require('./secureshopSystemRestartComposition').createSecureShopSystemRestartComposition;
  if (!preparedGrading || typeof createComposition !== 'function') {
    throw unavailable('Prepared persona authority required for System restart');
  }
  const createTargetResolver = factories.createTargetResolver
    || require('./secureshopSystemRebuildTarget').createSystemRebuildTargetResolver;
  const resolve = createTargetResolver({ launches, products,
    ...(scenes ? { scenes } : {}),
    personaAuthority: preparedGrading.personaAuthority });
  return createComposition({ reviewPool, personaAuthority: preparedGrading.personaAuthority, audit,
    client: systemRestartClient, authenticatePersona, modeAuthority,
    resolveTarget: async (input, options) => {
      const value = await resolve(input, options);
      return Object.freeze({ targetId: value.binding.targetId,
        ...(value.binding.scene ? { binding: value.binding } : {}) });
    },
  });
}
async function getSecureShopBoundReviewComposition(options = {}) {
  if (closing) throw unavailable('SecureShop bound review runtime is closing');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw unavailable();
  const input = Object.freeze(Object.fromEntries(OPTION_KEYS.map(key => [key, options[key]])));
  if (retained) {
    if (!sameInputs(retainedInputs, input)) throw unavailable('SecureShop bound review runtime is already configured');
    return retained.value;
  }
  if (pending) {
    if (!sameInputs(retainedInputs, input)) throw unavailable('SecureShop bound review runtime is already configuring');
    return pending;
  }
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres'
      || REQUIRED_ENV.some(key => typeof process.env[key] !== 'string' || !process.env[key])) {
    throw unavailable('SecureShop bound review store configuration is incomplete');
  }
  if (options.filePathSummaryFeature !== undefined && typeof options.filePathSummaryFeature !== 'boolean') throw unavailable('File path summary feature must be boolean');
  if (options.fileSummaryFeature !== undefined && typeof options.fileSummaryFeature !== 'boolean') throw unavailable('File summary feature must be boolean');
  if (options.personaInboxFeature !== undefined && typeof options.personaInboxFeature !== 'boolean') {
    throw unavailable('Persona inbox readiness must be boolean');
  }
  const personaPolicy = personaInboxActivationPolicy(process.env);
  if (options.personaInboxFeature !== personaPolicy.requested) {
    throw unavailable('Persona inbox activation policy does not match the requested composition');
  }
  if (options.mcpTrustFeature !== undefined && typeof options.mcpTrustFeature !== 'boolean') {
    throw unavailable('MCP trust readiness must be boolean');
  }
  const mcpTrustPolicy=mcpTrustActivationPolicy(process.env);
  if((options.mcpTrustFeature===true)!==mcpTrustPolicy.requested)throw unavailable('MCP trust activation policy does not match the requested composition');
  if(mcpTrustPolicy.requested&&(typeof options.mcpTrustFixtureRoot!=='string'||!path.isAbsolute(options.mcpTrustFixtureRoot)))
    throw unavailable('MCP trust fixture root is not ready');
  if(options.ssrfFeature!==undefined&&typeof options.ssrfFeature!=='boolean')throw unavailable();
  const ssrfPolicy=ssrfActivationPolicy(process.env);
  if((options.ssrfFeature===true)!==ssrfPolicy.requested)throw unavailable('SSRF activation policy mismatch');
  if(ssrfPolicy.requested&&(typeof options.ssrfFixtureRoot!=='string'||!path.isAbsolute(options.ssrfFixtureRoot)))throw unavailable();
  if(options.auditSummaryFeature!==undefined&&typeof options.auditSummaryFeature!=='boolean')throw unavailable('Audit summary readiness must be boolean');
  if((options.auditSummaryFeature===true)!==(process.env.SS_AUDIT_SUMMARY_ENABLED==='true'))throw unavailable('Audit summary activation policy mismatch');
  if (options.systemRebuildEnabled !== undefined && typeof options.systemRebuildEnabled !== 'boolean') {
    throw unavailable('System rebuild readiness must be boolean');
  }
  const snapshot = snapshotProductionOptions(options);
  retainedInputs = snapshot.identity;
  pending = (async () => {
    let createdListings;
    let createdOwnedMcpRegistry,createdRegisteredInvocation,createdOriginalRegistration,registrationShutdown;
    const registrationAdapters=new Set();
    let createdMail,createdAuditSummary,createdAuditUnbounded;
    let createdInventory;
    let createdPricing;
    const identityPool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    const agentsPool = require('../database/postgres/secureshopPools').getAgentsPool();
    const commercePool = require('../database/postgres/secureshopPools').getCommercePool();
    const reviewPool = require('../database/postgres/secureshopReviewDb').getSecureShopReviewPool();
    const assessmentReleaseAdmission = snapshot.configured.assessmentReleaseAdmission;
    const releaseAdmission = require('./secureshopAssessmentReleaseAdmission').resolveAssessmentReleaseAdmission(
      assessmentReleaseAdmission,{identityPool,agentsPool,reviewPool,commercePool});
    await releaseAdmission.assertCurrent();
    const migrationPools = {};
    try {
      for (const [store, key] of Object.entries(MIGRATION_ENV)) {
        migrationPools[store] = createPool(process.env, key);
      }
      await assertSecureShopBoundReviewReadiness({ identityPool, agentsPool, reviewPool, commercePool,
        migrationPools, requiredObjectives: snapshot.configured.requiredObjectives });
      if (snapshot.configured.personaInboxFeature) {
        await assertPersonaInboxReadiness({ identityPool, agentsPool });
      }
      if(snapshot.configured.ssrfFeature)await assertSecureShopSsrfReadiness({identityPool,agentsPool});
      if(snapshot.configured.mcpTrustFeature)await assertSecureShopMcpTrustReadiness({identityPool,agentsPool});
    } finally {
      const closed = await Promise.allSettled(Object.values(migrationPools).map(pool => pool.end()));
      const failures = closed.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'SecureShop readiness pool cleanup failed');
    }
    try {
      const resetComposition = await getSecureShopCleanupComposition({ files: snapshot.configured.files,
        mcpTrustFeature:snapshot.configured.mcpTrustFeature,
        mcpTrustFixtureRoot:snapshot.configured.mcpTrustFixtureRoot,
        ssrfFeature:snapshot.configured.ssrfFeature,ssrfFixtureRoot:snapshot.configured.ssrfFixtureRoot,
        ...(snapshot.configured.systemRestartClient===undefined?{}:{systemRestartClient:snapshot.configured.systemRestartClient}) });
      const preparedGrading=snapshot.configured.gradingBootstrap;
      let toolPolicyRepository;
      if(preparedGrading){
        await require('../database/postgres/secureshopBoundToolPolicyReadiness').assertBoundToolPolicyReadiness(agentsPool);
        toolPolicyRepository=require('../database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
          personaAuthority:preparedGrading.personaAuthority,audit:resetComposition.audit.agents});
      }
      const featureModeAuthority=resetComposition.modeAuthority;
      let promptPolicyRepository;
      if (snapshot.configured.promptPolicyRenderer !== undefined) {
        if (!preparedGrading || typeof snapshot.configured.promptPolicyRenderer?.render !== 'function') {
          throw unavailable('Prompt policy renderer and prepared persona authority required');
        }
        promptPolicyRepository = require('../database/postgres/secureshopBoundPromptPolicyRepository').createBoundPromptPolicyRepository({
          pool: agentsPool, personaAuthority: preparedGrading.personaAuthority, audit: resetComposition.audit.agents,
          checkRunBinding: require('./secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding({identityPool}),
          modeAuthority: featureModeAuthority,
        });
        await promptPolicyRepository.checkReadiness();
      }
      const resolveAgentSnapshotPolicies = require('./secureshopAgentSnapshotPolicies').createAgentSnapshotPolicyResolver({
        repository: promptPolicyRepository, personaAuthority: preparedGrading?.personaAuthority,
        agentsPool, identityPool, auditStore: resetComposition.audit.agents,
      });
      const passwordResetRepository=preparedGrading
        ? await require('./secureshopPasswordResetComposition').preparePasswordResetRepository({
          filePath:process.env.SS_PASSWORD_RESET_KEY_PATH,pool:agentsPool,auditStore:resetComposition.audit.agents})
        : undefined;
      const couponDependencies=process.env.SS_BOUND_COUPONS_ENABLED==='true'?await require('./secureshopCouponProduction').prepareCouponDependencies({modeAuthority:featureModeAuthority,reviewPool,commercePool,launches:resetComposition.launches,runtime:resetComposition.analyticsRuntime,lifecycle:resetComposition.analyticsLifecycle,mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln'}):await require('./secureshopCouponProduction').prepareCommerceDependencies({modeAuthority:featureModeAuthority,reviewPool,launches:resetComposition.launches,mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln'});
      const couponProbeDependencies = process.env.SS_BOUND_COUPON_PROBE_ENABLED === 'true'
        ? await require('./secureshopCouponProbeProduction').prepareCouponProbeDependencies({
          runtime: resetComposition.analyticsRuntime, lifecycle: resetComposition.analyticsLifecycle, commercePool })
        : undefined;
      const productSearchDependencies = process.env.SS_BOUND_PRODUCT_SEARCH_ENABLED === 'true'
        ? await require('./secureshopProductSearchProduction').prepareProductSearchDependencies({
          runtime: resetComposition.analyticsRuntime, lifecycle: resetComposition.analyticsLifecycle })
        : undefined;
      const orderStatusDependencies = process.env.SS_BOUND_ORDER_STATUS_ENABLED === 'true'
        ? await require('./secureshopOrderStatusProduction').prepareOrderStatusDependencies({
          runtime: resetComposition.analyticsRuntime, lifecycle: resetComposition.analyticsLifecycle })
        : undefined;
      const registryModule=require('./secureshopOwnedMcpRegistryProduction');
      const registryConfiguration=await registryModule.readConfiguration();
      const registryEnabled=registryModule.PRODUCTION_QUALIFIED&&registryConfiguration?.enabled===true;
      const scenes = require('./secureshopScenes').createSecureShopScenes({
        repository: require('../database/postgres/secureshopSceneRepository').createSecureShopProductionSceneRepository({
          pool: identityPool, provisionPool: resetComposition.provisionPool,
          leasePool: resetComposition.graphLeasePool,
          launches: resetComposition.launches }),
        reviewPool, launches: resetComposition.launches,
      });
      let value;
      let rawListingBrowserAssessment;
      const rawListingAssessmentForwarder = Object.freeze(Object.fromEntries(
        ['runAttempt', 'readOutcome'].map(method => [method, input => {
          if (!rawListingBrowserAssessment) throw unavailable('Raw listing assessment unavailable');
          return rawListingBrowserAssessment[method](input);
        }])));
      value = createSecureShopBoundReviewComposition({ identityPool, agentsPool, reviewPool, modeAuthority:featureModeAuthority,
        commercePool, resetComposition, jwtSecret: process.env.JWT_SECRET, ...snapshot.configured,
        uploadPreviewClient:snapshot.configured.uploadPreviewClient ?? require('./secureshopSystemManagedEnvironment').getUploadPreviewClient() ?? undefined, scenes, ownedMcpRegistryReads:registryEnabled,
        mcpRegistryApplication:()=>createdOwnedMcpRegistry?.ready===true
          ?{service:createdOwnedMcpRegistry.service,mode:registryConfiguration.mode}:null,
        ...(registryEnabled?{mcpRegistrationApplication:()=>createdOriginalRegistration}:{}),
        registeredInvocationApplication:()=>createdRegisteredInvocation?.ready===true?createdRegisteredInvocation:null,
        getAuditSearch:()=>value?.auditSearch,getAuditSummary:()=>value?.auditSummary,
        getAuditAgentReady:()=>value?.auditAgentReady===true,
        getSystemConfig:async()=>value?.systemConfig,
        getSystemRestart:()=>value?.systemRestart,
        getSystemDiagnostic:()=>value?.systemDiagnostic,
        getMailApplication:()=>value?.mail?.ready===true?value.mail.application:null,
        getListingsApplication:()=>value?.listings?.ready===true?value.listings.application:null,
        inventoryApplication:()=>createdInventory?.application,
        pricingApplication:()=>createdPricing?.application,
        ...(preparedGrading?{rawListingAssessment:rawListingAssessmentForwarder}:{}),
        ...(couponDependencies?{couponDependencies}:{}),
        ...(couponProbeDependencies ? { couponProbeDependencies } : {}),
        ...(productSearchDependencies ? { productSearchDependencies } : {}),
        ...(orderStatusDependencies ? { orderStatusDependencies } : {}),
        ...(passwordResetRepository===undefined?{}:{passwordResetRepository}),
        ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}),
        ...(promptPolicyRepository===undefined?{}:{promptPolicyRepository,taskPoliciesEnabled:true}) });
      if (preparedGrading && value.roleAssistants?.merchant?.runtime) {
        const rawListingProvider = snapshot.configured.agentRuntime?.provider
          || snapshot.configured.agentRuntime?.providerRouter;
        rawListingBrowserAssessment = require('./secureshopListingRawBrowserAssessment')
          .createListingRawBrowserAssessment({
            ...preparedGrading.assessmentDependencies,
            launches: value.launches, conversationRepository: resetComposition.conversations,
            coordinator: resetComposition.runCoordinator, journal: resetComposition.journal,
            readOriginal: input => value.roleAssistants.merchant.runtime.readListingCreateEvidence(input),
            catalog: value.catalog, modeAuthority: featureModeAuthority, identityPool, agentsPool,
            personaAuthority: preparedGrading.personaAuthority,
            publicationModes: require('../database/postgres/secureshopModeRepository')
              .createSecureShopModeRepository(identityPool),
            judge: snapshot.configured.judge || require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
            qualifyModel: createSecureShopModelQualifier(rawListingProvider),
            browserQualification: value.browserQualification,
            productRenderer: require('./secureshopProductDescriptionRenderer')
              .loadSecureShopProductDescriptionRenderer(),
          });
      }
      const standaloneService = require('./secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
        sessionTtlSeconds: require('./sessionLifetimeConfiguration').readSessionLifetimeConfiguration(process.env).shopSessionTtlSeconds,
        repository: require('../database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identityPool }),
      });
      const standaloneReset = typeof resetComposition.sceneResetPreflight?.preview === 'function'
        && typeof resetComposition.launchResetCoordinator?.reset === 'function'
        && typeof resetComposition.launchResetCoordinator?.resumeExisting === 'function'
        && typeof resetComposition.launchResetCoordinator?.recover === 'function'
        ? require('./secureshopStandaloneReset').createSecureShopStandaloneReset({
          identityPool, authService: standaloneService, launches: value.launches, scenes,
          resetCoordinator: resetComposition.launchResetCoordinator,
          preflight: resetComposition.sceneResetPreflight,
        }) : undefined;
      const registeredAdminReset = await require('./secureshopPasswordResetComposition')
        .prepareRegisteredAdminResetService({ filePath: process.env.SS_PASSWORD_RESET_KEY_PATH, pool: identityPool });
      const externalMailTransportModule = require('./secureshopExternalMailTransport');
      const externalMailConfig = externalMailTransportModule.readExternalMailConfiguration();
      const externalMailTransport = externalMailTransportModule.createExternalMailTransport({config:externalMailConfig});
      const externalMail = preparedGrading?.personaAuthority ? Object.freeze({
        launches:value.launches,personaAuth:value.personaAuth,
        application:require('./secureshopExternalMail').createExternalMailApplication({
          repository:require('../database/postgres/secureshopExternalMailRepository')
            .createExternalMailRepository({pool:identityPool}),
          authority:require('../database/postgres/secureshopExternalMailAuthority')
            .createExternalMailAuthority({pool:identityPool,personaAuthority:preparedGrading.personaAuthority,
              sender:externalMailConfig.sender}),
          transport:externalMailTransport,sender:externalMailConfig.sender,
        }),
      }) : undefined;
      value = Object.freeze({ ...value, standaloneAuth: Object.freeze({ service: standaloneService,
        registeredAdminReset, ...(externalMail ? {externalMail} : {}),
        practices: require('./secureshopPracticeAdmission').createSecureShopPracticeAdmission({
          repository: require('../database/postgres/secureshopPracticeAdmissionRepository')
            .createSecureShopPracticeAdmissionRepository({ pool: identityPool }), catalog: value.catalog }),
        ...(standaloneReset ? { reset: standaloneReset } : {}),
        assessmentProgress: require('./secureshopAssessmentProgress').createSecureShopAssessmentProgress({
          repository: require('../database/postgres/secureshopAssessmentProgressRepository')
            .createSecureShopAssessmentProgressRepository({ pool: identityPool, assessmentReleaseAdmission }),
        }),
        assessmentObjectives: require('./secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({pool:identityPool,authService:standaloneService,assessmentReleaseAdmission}),
        mode: require('./secureshopStandaloneMode').createSecureShopStandaloneMode({
          authService: standaloneService, repository: require('../database/postgres/secureshopModeRepository')
            .createSecureShopModeRepository(identityPool) }),
        bootstrap: require('./secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
          launches: value.launches, personaAuth: value.personaAuth, authService: standaloneService }),
      }) });
      if(preparedGrading){value=Object.freeze({...value,standaloneAuth:Object.freeze({...value.standaloneAuth,
        assessmentRecovery:require('./secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({identityPool,assessmentReleaseAdmission,
          authService:standaloneService,bootstrap:value.standaloneAuth.bootstrap,launches:value.launches,
          personaAuth:value.personaAuth,personaAuthority:preparedGrading.personaAuthority,modeAuthority:featureModeAuthority,
          scenes:value.scenes,couponAssessment:value.couponAgent?.assessment,
          couponBlindAssessment:value.couponProbe?.assessment,
          v01AuditAssessment:value.checkoutAuditLesson?.assessment,
          uploadAssessment:value.avatarUpload?.assessment,
          polyglotUploadAssessment:value.avatarUpload?.polyglotAssessment,
          traversalAssessment:value.avatarUpload?.traversalAssessment,
          fileSummaryAssessment:value.fileSummary?.assessment,
          filePathSummaryAssessment:value.filePathSummary?.assessment,
      mailAgentReadAssessment:value.roleAssistants?.merchant?.mailAgentReadAssessment,
          svgUploadAssessment:value.avatarUpload?.svgAssessment,
          productUnionAssessment:value.productSearch?.assessment,
          orderStatusErrorAssessment:value.orderStatus?.assessment,
          ticketAssessment:value.ticketAgent?.assessment,
          searchEchoAssessment:value.searchEcho?.assessment,
          manualRagAssessment:value.manualRag?.assessment,
          productSummaryAssessment:value.productSummary?.assessment,
          agencyRoleAssessment:value.agencyRole?.assessment,
          systemDiagnosticAssessment:value.roleAssistants?.admin?.systemDiagnosticAssessment,
          systemConfigAssessment:value.roleAssistants?.admin?.systemConfigAssessment,
          systemRestartInjectionAssessment:value.roleAssistants?.admin?.systemRestartInjectionAssessment,
          mailInlineAssessment:{assertRetainedPacket:input=>{
            const assessment=value.mail?.inline?.assessment;
            if(typeof assessment?.assertRetainedPacket!=='function')throw unavailable('Mail inline assessment unavailable');
            return assessment.assertRetainedPacket(input);
          }},
          mailHtmlInjectionAssessment:{assertRetainedPacket:input=>{
            const assessment=value.mail?.htmlInjectionAssessment;
            if(typeof assessment?.assertRetainedPacket!=='function')throw unavailable('Mail HTML injection assessment unavailable');
            return assessment.assertRetainedPacket(input);
          }},
          analyticsNlSqlAssessment:{assertRetainedPacket:input=>{
            const assessment=value.analytics?.nlSqlAssessment;
            if(typeof assessment?.assertRetainedPacket!=='function')throw unavailable('Analytics NL SQL assessment unavailable');
            return assessment.assertRetainedPacket(input);
          }},
          qualifyAnalyticsModel:createSecureShopModelQualifier(snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter),
          mcpDescriptionAssessment:{assertRetainedPacket:input=>{
            const assessment=createdRegisteredInvocation?.descriptionAssessment;
            if(typeof assessment?.assertRetainedPacket!=='function')throw unavailable('Registered description assessment unavailable');
            return assessment.assertRetainedPacket(input);
          }},
          mcpManifestAssessment:value.roleAssistants?.admin?.assessment,
          mcpRegistrySsrfAssessment:value.roleAssistants?.admin?.mcpRegistrySsrfAssessment,
          userLookupAssessment:value.roleAssistants?.admin?.userLookupAssessment,
          qualifyCouponModel:createSecureShopModelQualifier(
            snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter),
          qualifyIdorModel:createSecureShopModelQualifier(
            snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter)})})});}
      value = Object.freeze({ ...value,
        publicCatalog: require('../database/postgres/secureshopStorePublicCatalogRepository')
          .createSecureShopStorePublicCatalogRepository({ identityPool, reviewPool, commercePool }) });
      if (typeof value.commerce?.importGuestCart === 'function') {
        value = Object.freeze({ ...value, standaloneAuth: Object.freeze({ ...value.standaloneAuth,
          cartImport: require('./secureshopStandaloneCartImport').createSecureShopStandaloneCartImport({
            bootstrap: value.standaloneAuth.bootstrap, launches: value.launches,
            personaAuth: value.personaAuth, commerce: value.commerce,
          }),
        }) });
      }
      if(registryEnabled){
        if(!preparedGrading)throw unavailable('Owned registry persona authority unavailable');
        const registryProduction=await registryModule.createOwnedMcpRegistryProduction({configuration:registryConfiguration,agentsPool,personaAuthority:preparedGrading.personaAuthority,authenticatePersona:value.personaAuth.authenticatePersona,expectedDatabase:new URL(process.env.SECURESHOP_AGENTS_DATABASE_URL).pathname.slice(1)});
        createdOwnedMcpRegistry=Object.freeze({...registryProduction,async close(){
          const results=await Promise.allSettled([registryProduction.close(),...[...registrationAdapters].map(adapter=>adapter.close())]);
          const failed=results.filter(result=>result.status==='rejected').map(result=>result.reason);
          try{await registrationShutdown?.shutdown();}catch(error){failed.push(error);}
          if(failed.length)throw new AggregateError(failed,'Owned registration shutdown drain incomplete');
        }});
        value=Object.freeze({...value,ownedMcpRegistry:createdOwnedMcpRegistry});
        const infrastructure=resetComposition.registeredInvocation;
        if(infrastructure?.registrationJournal&&infrastructure?.client?.registrationHealth){
          registrationShutdown=require('./secureshopOwnedMcpRegistrationLifecycle').createOwnedMcpRegistrationLifecycle({
            journal:infrastructure.registrationJournal,client:infrastructure.client});
          // An older installed executor cannot advertise the original command
          // path merely because generic registry administration is available.
          try{
            await infrastructure.client.registrationHealth();
            createdOriginalRegistration=Object.freeze({ready:true,mode:registryConfiguration.mode,
              create:context=>{
                const adapter=require('./secureshopV23RegisterAdapter').createV23RegisterAdapter({...context,
                  registrationJournal:infrastructure.registrationJournal,launches:infrastructure.launches,
                  ownedMcpRegistry:createdOwnedMcpRegistry.service,client:infrastructure.client});
                registrationAdapters.add(adapter);
                return Object.freeze({...adapter,async close(){await adapter.close();registrationAdapters.delete(adapter);}});
              }});
          }catch(error){
            if(error?.code!=='MCP_REGISTRY_EXECUTOR_UNAVAILABLE')throw error;
          }
        }
      }
      const invocationModule=require('./secureshopRegisteredInvocationProduction');
      const invocationMigrationPool=invocationModule.REGISTERED_INVOCATION_QUALIFIED&&resetComposition.registeredInvocation?.configuration.enabled===true
        ? createPool(process.env,'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL'):undefined;
      try{createdRegisteredInvocation=await invocationModule.createRegisteredInvocationProduction({identityPool,assessmentReleaseAdmission,gradingBootstrap:preparedGrading,...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{}),modeAuthority:featureModeAuthority,infrastructure:resetComposition.registeredInvocation,resetComposition,provider:snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter,authenticatePersona:value.personaAuth?.authenticatePersona,migrationPool:invocationMigrationPool});}
      finally{await invocationMigrationPool?.end();}
      if(createdRegisteredInvocation.ready)value=Object.freeze({...value,registeredInvocation:createdRegisteredInvocation});
      const selectedGradingCore=preparedGrading?.gradingCore||snapshot.configured.gradingCore;
      const sharedGrading = selectedGradingCore === undefined ? undefined
        : require('./objectiveGradingCore').resolveObjectiveGradingDependencies(selectedGradingCore,{identityPool,
          ...(preparedGrading?{personaBindings:preparedGrading.personaBindings}:{})});
      if (value.userAdministration) await require('../database/postgres/secureshopBoundUserAdministrationRepository')
        .assertUserAdministrationReadiness(agentsPool);
      if (value.userAdministration) await value.userAdministration.checkReadiness();
      await value.repositories.personas.ensureTemplates();
      if (snapshot.configured.systemConfigClient !== undefined) {
        const systemConfig = await createOptionalSystemConfigComposition({
          systemConfigClient: snapshot.configured.systemConfigClient, preparedGrading, agentsPool,
          audit: resetComposition.audit.agents,
          authenticatePersona: value.personaAuth.authenticatePersona, modeAuthority: featureModeAuthority,
        });
        value = Object.freeze({ ...value, systemConfig });
      }
      if (snapshot.configured.systemDiagnosticClient !== undefined) {
        const systemDiagnostic = await createOptionalSystemDiagnosticComposition({
          systemDiagnosticClient: snapshot.configured.systemDiagnosticClient, preparedGrading, agentsPool, modeAuthority:featureModeAuthority,
          audit: resetComposition.audit.agents,
          authenticatePersona: value.personaAuth.authenticatePersona,
        });
        value = Object.freeze({ ...value, systemDiagnostic });
      }
      if (snapshot.configured.systemRebuildEnabled) {
        const systemRebuild = await createOptionalSystemRebuildComposition({ enabled: true,
          preparedGrading, reviewPool, launches: value.launches, scenes: value.scenes,
          products: value.repositories.products, audit: resetComposition.audit.review,
          authenticatePersona: value.personaAuth.authenticatePersona,
          ...(promptPolicyRepository === undefined ? {} : { policyRepository: promptPolicyRepository }) });
        value = Object.freeze({ ...value, systemRebuild });
      }
      if (snapshot.configured.systemRestartClient !== undefined) {
        const systemRestart = await createOptionalSystemRestartComposition({
          systemRestartClient: snapshot.configured.systemRestartClient, preparedGrading, reviewPool, modeAuthority:featureModeAuthority,
          launches: value.launches, products: value.repositories.products, scenes: value.scenes,
          audit: resetComposition.audit.review,
          authenticatePersona: value.personaAuth.authenticatePersona,
        });
        value = Object.freeze({ ...value, systemRestart });
      }
      if (snapshot.configured.pricingHttpClient !== undefined) {
        if (!preparedGrading) throw unavailable('Pricing requires original persona grading authority');
        const pricingProvider=snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter;
        const pricing=await require('./secureshopPricingProduction').createSecureShopPricingProduction({
          enabled:true,modeAuthority:featureModeAuthority,identityPool,agentsPool,reviewPool,resetComposition,catalog:value.catalog,
          productRepository:value.repositories.products,personaAuthority:preparedGrading.personaAuthority,
          provider:pricingProvider,promptPolicyRepository,toolPolicyRepository,
          client:snapshot.configured.pricingHttpClient,authenticatePersona:value.personaAuth.authenticatePersona,
          createAssessmentFactory:async ({publishAndRead,scope})=>{
            const ids=require('./secureshopPricingEvidence').OBJECTIVES.filter(id=>require('../config/secureshopCurriculum').isQualifiedObjective(id)||releaseAdmission.isCandidate(id));
            if(!ids.length)return undefined;
            const enabled=await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,scope,ids,assessmentReleaseAdmission);
            return require('./secureshopPricingAssessment').createPricingAssessmentCollection({...preparedGrading.assessmentDependencies,
              qualifyModel:createSecureShopModelQualifier(pricingProvider),judge:snapshot.configured.judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge()},
              {objectiveIds:enabled,publishAndRead});
          }
        });
        createdPricing=pricing;value=Object.freeze({...value,pricing});
      }
      const inventoryModule=require('./secureshopInventoryProduction');
      if(process.env.SS_BOUND_INVENTORY_ENABLED!==undefined&&!['true','false'].includes(process.env.SS_BOUND_INVENTORY_ENABLED))throw unavailable('Inventory readiness flag must be boolean');
      if(process.env.SS_BOUND_INVENTORY_ENABLED!=='false'&&inventoryModule.PRODUCTION_QUALIFIED){
        if(!preparedGrading)throw unavailable('Inventory requires canonical persona grading');
        const inventory=await inventoryModule.createInventoryProduction({modeAuthority:featureModeAuthority,enabled:true,identityPool,agentsPool,reviewPool,resetComposition,catalog:value.catalog,
          resolveExistingTarget:scope=>value.scenes.readExisting(scope),
          personaAuthority:preparedGrading.personaAuthority,provider:snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter,
          promptPolicyRepository:await resolveAgentSnapshotPolicies(),toolPolicyRepository,authenticatePersona:value.personaAuth.authenticatePersona,
          mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln',assessmentDependencies:{...preparedGrading.assessmentDependencies,
            judge:snapshot.configured.judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge()}});
        createdInventory=inventory;value=Object.freeze({...value,inventory});
      }
      const mail=await require('./secureshopMailComposition').createOptionalMailComposition({flag:process.env.SS_BOUND_MAIL_ENABLED,loadDependencies:async()=>{
        if(!preparedGrading)throw unavailable('Mail requires canonical persona grading');
        return {modeAuthority:featureModeAuthority,identityPool,agentsPool,resetComposition,mailScenes:value.mailScenes,
          createBrowserQualification:()=>require('./secureshopMailBrowserQualification').createSecureShopMailBrowserQualification(),
          personaAuthority:preparedGrading.personaAuthority,personaRepository:value.repositories.personas,
          provider:snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter,
          promptPolicyRepository:await resolveAgentSnapshotPolicies(),toolPolicyRepository,authenticatePersona:value.personaAuth.authenticatePersona,
          mode:process.env.LAB_MODE==='fixed'?'fixed':'vuln',assessmentDependencies:{...preparedGrading.assessmentDependencies,
            publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
            judge:snapshot.configured.judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge()}};
      }});
      if(mail){createdMail=mail;value=Object.freeze({...value,mail});}
      if(resetComposition.listingsRuntime?.admissions===true){
        if(!preparedGrading)throw unavailable('Listings requires canonical persona grading');
        const listingsProvider=snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter;
        const listings=await require('./secureshopListingsProduction').createListingsProduction({runtime:resetComposition.listingsRuntime,
          readChatSetup:input=>{
            const runtime=value?.roleAssistants?.merchant?.runtime;
            if(typeof runtime?.readListingsSetup!=='function')throw unavailable('Merchant Listings setup unavailable');
            return runtime.readListingsSetup(input);
          },
          identityPool,agentsPool,reviewPool,resetComposition,catalog:value.catalog,personaAuthority:preparedGrading.personaAuthority,
          provider:listingsProvider,promptPolicyRepository:await resolveAgentSnapshotPolicies(),toolPolicyRepository,authenticatePersona:value.personaAuth.authenticatePersona,
          browserQualification:value.browserQualification,listingTemplateClient:snapshot.configured.listingTemplateClient,systemDiagnosticClient:snapshot.configured.systemDiagnosticClient,assessmentDependencies:{...preparedGrading.assessmentDependencies,
            publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
            qualifyModel:createSecureShopModelQualifier(listingsProvider),judge:snapshot.configured.judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge()}});
        createdListings=listings;value=Object.freeze({...value,listings});
      }
      if(resetComposition.analyticsRuntime?.admissions===true){
        if(!preparedGrading)throw unavailable('Analytics requires canonical persona grading');
        const analyticsProvider=snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter;
        const analyticsPolicies=await resolveAgentSnapshotPolicies();
        await resetComposition.analyticsRuntime.assertReady();if(resetComposition.analyticsRuntime.fixedCapabilities!==true)throw unavailable('Analytics fixed capability upgrade required');
        const analytics=await require('./secureshopAnalyticsComposition').createAnalyticsComposition({runtime:resetComposition.analyticsRuntime,...(resetComposition.analyticsRuntime.fixedCapabilities===true?{modeAuthority:require('./secureshopAnalyticsModeAuthority').createAnalyticsModeAuthority({progress:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),launches:value.launches})}:{}),agentsPool,launches:value.launches,personaAuthority:preparedGrading.personaAuthority,conversationRepository:resetComposition.conversations,journal:resetComposition.journal,coordinator:resetComposition.runCoordinator,provider:analyticsProvider,promptPolicyRepository:analyticsPolicies,
          assessmentFactory:createSecureShopLoopAssessment({...preparedGrading.assessmentDependencies,qualifyModel:createSecureShopModelQualifier(analyticsProvider),...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{})}).assessmentFactory,
          disclosureAssessmentFactory:require('./secureshopAnalyticsDisclosureAssessment').createAnalyticsDisclosureAssessment({...preparedGrading.assessmentDependencies,qualifyModel:createSecureShopModelQualifier(analyticsProvider),...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{}),isAvailable:async scope=>{
            const objective=require('./secureshopAnalyticsDisclosureAssessment').OBJECTIVE;if(!require('../config/secureshopCurriculum').isQualifiedObjective(objective))return false;
            return(await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,scope,[objective])).includes(objective);
          }}),
          identityPool,qualifyModel:createSecureShopModelQualifier(analyticsProvider),
          nlSqlAssessmentFactory:require('./secureshopAnalyticsNlSqlAssessment').createAnalyticsNlSqlAssessment({...preparedGrading.assessmentDependencies,qualifyModel:createSecureShopModelQualifier(analyticsProvider),...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{}),isAvailable:async scope=>{
            const objective=require('./secureshopAnalyticsNlSqlEvidence').OBJECTIVE;
            if(!require('../config/secureshopCurriculum').isQualifiedObjective(objective))return false;
            return(await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,scope,[objective])).includes(objective);
          }}),
          authenticatePersona:value.personaAuth.authenticatePersona,lifecycle:resetComposition.analyticsLifecycle});
        value=attachAnalyticsComposition(value,analytics);
      }
      const auditSqlRuntime=await require('./secureshopOwnedAuditProduction').getOwnedAuditProduction();
      if(auditSqlRuntime?.agentAdmissions&&!require('../config/secureshopCurriculum').isQualifiedObjective('ss_audit_sql_extraction'))throw unavailable('Audit SQL model objective is not qualified');
      if(auditSqlRuntime?.admissions){
        const ownedAudit=require('./secureshopOwnedAuditComposition').createOwnedAuditComposition({assessmentReleaseAdmission,modeAuthority:featureModeAuthority,identityPool,launches:value.launches,...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}),...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),personaAuth:value.personaAuth,auditReader:resetComposition.audit.reader,cleanupAuthority:resetComposition.cleanupAuthority,turns:resetComposition.turns,journal:resetComposition.journal,conversations:resetComposition.conversationService,conversationRepository:resetComposition.conversations,client:auditSqlRuntime.client,...(preparedGrading?{gradingBootstrap:preparedGrading,agentsPool,resetComposition}:{}),...(auditSqlRuntime.agentAdmissions?{agentEnabled:true,provider:snapshot.configured.agentRuntime?.provider||snapshot.configured.agentRuntime?.providerRouter,receipts:sharedGrading?.receipts||require('../database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityPool),progress:sharedGrading?.progress||require('../database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityPool),...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{})}:{})});
        await ownedAudit.checkReadiness();value=Object.freeze({...value,auditSearch:ownedAudit.application,
          auditAgentReady:auditSqlRuntime.agentAdmissions===true,auditTimingReady:auditSqlRuntime.agentAdmissions===true});
      }

      if(snapshot.configured.auditSummaryFeature){
        const auditOptions={modeAuthority:featureModeAuthority,scenes:value.scenes,
          ...(toolPolicyRepository===undefined?{}:{toolPolicyRepository}),...(promptPolicyRepository===undefined?{}:{promptPolicyRepository}),
          agentsPool,reviewPool,ledger:resetComposition.auditLedger,turns:resetComposition.turns,
          conversations:resetComposition.conversationService,journal:resetComposition.journal,
          receipts:sharedGrading?.receipts||require('../database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityPool),
          progress:sharedGrading?.progress||require('../database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityPool),
          ...(preparedGrading?{personaAuthority:preparedGrading.personaAuthority,personaBindings:preparedGrading.personaBindings}:{}),
          ...(snapshot.configured.judge?{judge:snapshot.configured.judge}:{}),
          baseUrl:process.env.OLLAMA_BASE_URL||'http://127.0.0.1:11434',model:process.env.OLLAMA_MODEL||'llama3.1:8b',
        };
        const lifecycle=require('./secureshopAuditRuntimeLifecycle');
        const auditSummary=createdAuditSummary=await lifecycle.createSecureShopAuditRuntimeLifecycle(auditOptions);
        const auditUnbounded=createdAuditUnbounded=await lifecycle.createSecureShopAuditRuntimeLifecycle({...auditOptions,assessmentVariant:'unbounded'});
        value=Object.freeze({...value,auditSummary,auditUnbounded});
        if(closing)throw unavailable('SecureShop bound review runtime is closing');
      }

      // close() may have begun while readiness was pending. Do not publish a
      // newly initialized runtime into a process that is already draining.
      if (closing) throw unavailable('SecureShop bound review runtime is closing');
      retained = { value };
      return value;
    } catch (error) {
      const failures=[error];for(const feature of [createdAuditUnbounded,createdAuditSummary,createdRegisteredInvocation,createdOwnedMcpRegistry,createdInventory,createdMail,createdListings]){try{await feature?.close();}catch(closeError){failures.push(closeError);}}
      if(failures.length>1)throw new AggregateError(failures,'Bound feature startup cleanup failed');
      throw error;
    }
  })();
  try { return await pending; }
  catch (error) { retainedInputs = undefined; throw error; }
  finally { pending = undefined; }
}

function getSecureShopBoundRunCoordinator() {
  if (!retained) throw unavailable();
  return retained.value.runCoordinator;
}
function getSecureShopLaunchResetCoordinator() {
  if (!retained) throw unavailable();
  return retained.value.launchResetCoordinator;
}
async function closeSecureShopBoundReviewComposition() {
  if (closing) return closing;
  closing = (async () => {
    if (pending) {
      try { await pending; } catch {}
    }
    if (!retained) {
      retainedInputs = undefined;
      return;
    }
    const owned = retained;
    // Call only after the HTTP server has drained requests. The shared run
    // coordinator fences in-flight work, but has no process-wide "stop all"
    // primitive; closing its lease pool is therefore the final shutdown step.
    try {
      await require('./secureshopBoundShutdown').closeSecureShopBoundResources({
        registeredInvocation:owned.value.registeredInvocation,ownedMcpRegistry:owned.value.ownedMcpRegistry,mail:owned.value.mail,
        auditSummary:owned.value.auditSummary,auditUnbounded:owned.value.auditUnbounded,listings:owned.value.listings,inventory:owned.value.inventory,
        closeBrowserAssessment:()=>owned.value.closeBrowserAssessment(),
        closeCleanup:closeSecureShopCleanupComposition,
      });
    } finally {
      if (retained === owned) {
        retained = undefined;
        retainedInputs = undefined;
      }
    }
  })();
  try { await closing; } finally { closing = undefined; }
}

module.exports = { WORKSHOP_KEY, DEFAULT_OBJECTIVES,
  attachAnalyticsComposition,
  createCheckoutAuditReadStore,
  createAgencyRoleSourceReader,
  createMailActionPolicyCheck,
  assertSecureShopBoundReviewReadiness, assertEmbeddingPrivileges, assertPersonaInboxReadiness, createSecureShopBoundReviewComposition,
  createOptionalSystemConfigComposition,
  createOptionalSystemDiagnosticComposition,
  createOptionalSystemRebuildComposition,
  createOptionalSystemRestartComposition,
  getSecureShopBoundReviewComposition, getSecureShopBoundRunCoordinator,
  getSecureShopLaunchResetCoordinator, closeSecureShopBoundReviewComposition };
