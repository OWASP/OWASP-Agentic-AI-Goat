'use strict';

const path = require('node:path');
const { readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../database/postgres');
const { createSecureShopLaunchRepository } = require('../database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../database/postgres/secureshopResetCleanupAuthorityRepository');
const { createBoundConversationsRepository } = require('../database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../database/postgres/secureshopTurnRequestsRepository');
const { createSecureShopConversationLifecycleRepository } = require('../database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopRealmProgressCleanupCheckpointRepository } = require('../database/postgres/secureshopRealmProgressCleanupCheckpointRepository');
const { createSecureShopTargetReconciliationRepository } = require('../database/postgres/secureshopTargetReconciliationRepository');
const { createSecureShopBoundReviewRepository } = require('../database/postgres/secureshopBoundReviewRepository');
const { createSecureShopBoundProductRepository } = require('../database/postgres/secureshopBoundProductRepository');
const { createSecureShopOwnerResetRepository } = require('../database/postgres/secureshopOwnerResetRepository');
const { createPostgresRunLedger } = require('../agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../agent-runtime/runCoordinator');
const { runSessionExclusive } = require('./secureshop/sessionStore');
const { createSecureShopConversationLifecycle } = require('./secureshopConversationLifecycle');
const { createSecureShopConversationCleanupCheckpointRepository } = require('../database/postgres/secureshopConversationCleanupCheckpointRepository');
const { createSecureShopReviewCleanupReceiptReader } = require('./secureshopReviewCleanupReceiptReader');
const { createSecureShopFileCleanupReceiptReader } = require('./secureshopFileCleanupReceiptReader');
const { createSecureShopFileTargetCleanup } = require('./secureshopFileTargetCleanup');
const { createSecureShopReviewResetCoordinator } = require('./secureshopReviewResetCoordinator');
const { createSecureShopLaunchResetCoordinator } = require('./secureshopLaunchResetCoordinator');
const { createSecureShopOwnerResetService } = require('./secureshopOwnerResetService');
const { createSecureShopSceneResetPreflight } = require('./secureshopSceneResetPreflight');
const { createSecureShopStudentDeletionCleanup } = require('./secureshopStudentDeletionCleanup');
const { createSecureShopPersonaInboxRepositoryBundle }
  = require('./secureshopPersonaInboxComposition');
const { createSecureShopMcpTrustAvailability } = require('./secureshopMcpTrustAvailability');
const { createSecureShopMcpTrustRepositoryBundle } = require('./secureshopMcpTrustProduction');
const { activationPolicy: mcpTrustPolicy } = require('./secureshopMcpTrustActivationPolicy');
const { activationPolicy: ssrfPolicy, createSecureShopSsrfRepositoryBundle } = require('./secureshopSsrfProduction');

const STORES = Object.freeze({
  identity: Object.freeze({ runtimeEnv: 'IDENTITY_DATABASE_URL', migrationEnv: 'IDENTITY_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_identity_runtime', migrationRole: 'dvaia_identity_migration',
    directory: path.join(__dirname, '../../db/postgres/identity-migrations'),
    relations: Object.freeze(['identity.secureshop_launches','identity.secureshop_launch_resets',
      'identity.secureshop_target_reservations','identity.secureshop_target_cleanup_history',
      'identity.secureshop_conversation_cleanup_history','identity.secureshop_progress_cleanup_history',
      'secureshop_auth.assessment_cleanup_history','secureshop_auth.active_assessment_contributions',
      'identity.secureshop_owner_resets','identity.secureshop_owner_reset_launches',
      'identity.student_deletion_jobs','identity.student_deletion_steps','identity.student_deletion_secureshop_resets']) }),
  agents: Object.freeze({ runtimeEnv: 'SECURESHOP_AGENTS_DATABASE_URL', migrationEnv: 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_secureshop_agents_runtime', migrationRole: 'dvaia_secureshop_agents_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents'),
    relations: Object.freeze(['secureshop_agents.agent_sessions','secureshop_agents.turn_requests',
      'secureshop_agents.conversation_generation_retirements','secureshop_agents.bound_persona_sessions',
      'secureshop_agents.bound_audit_events','secureshop_agents.bound_audit_owner_deletion_receipts',
      'secureshop_agents.bound_audit_runs','secureshop_agents.bound_audit_run_artifacts',
      'secureshop_agents.bound_audit_run_chunks','secureshop_agents.bound_audit_run_publications',
      'secureshop_agents.bound_audit_run_deletion_receipts']) }),
  review: Object.freeze({ runtimeEnv: 'SECURESHOP_REVIEW_DATABASE_URL', migrationEnv: 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_secureshop_review_runtime', migrationRole: 'dvaia_secureshop_review_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review'),
    relations: Object.freeze(['secureshop_review.reviews','secureshop_review.review_cleanup_receipts',
      'secureshop_review.product_targets','secureshop_review.product_target_products',
      'secureshop_review.product_target_cart_items','secureshop_review.product_target_orders',
      'secureshop_review.product_target_order_items',
      'secureshop_review.product_target_profile_overlays','secureshop_review.product_target_addresses',
      'secureshop_review.product_target_merchant_listings','secureshop_review.product_target_listing_overlays',
      'secureshop_review.product_listing_cleanup_receipts',
      'secureshop_review.product_account_cleanup_receipts',
      'secureshop_review.product_cleanup_receipts',
      'secureshop_review.product_target_refund_requests',
      'secureshop_review.product_target_refund_cleanup_receipts',
      'secureshop_review.product_target_support_tickets',
      'secureshop_review.product_target_support_ticket_receipts',
      'secureshop_review.product_target_support_ticket_retirements',
      'secureshop_review.bound_audit_events','secureshop_review.bound_audit_owner_deletion_receipts',
      'secureshop_review.bound_system_restart_targets','secureshop_review.bound_system_restart_operations',
      'secureshop_review.bound_system_restart_retirements','secureshop_review.bound_system_restart_owner_deletion_receipts']) }),
});
const CLEANUP_VISIBILITY_MIGRATION = Object.freeze({
  name: '0039_secureshop_cleanup_catalog_independence.sql',
  checksum: '7b83acc118e07715ee001951080cd9b2f59fe1be84e176f437799a0ff45c956a',
});
function unavailable(message = 'SecureShop cleanup runtime is unavailable') {
  return Object.assign(new Error(message), { code: 'SECURESHOP_CLEANUP_UNAVAILABLE', statusCode: 503 });
}
function callable(value, names) { return value && names.every(name => typeof value[name] === 'function'); }
function createPersonaInboxTransportCleanup(repository) {
  const callbacks = new Set();
  return Object.freeze({
    register(callback) {
      if (typeof callback !== 'function') throw unavailable();
      callbacks.add(callback); return () => callbacks.delete(callback);
    },
    async cleanup(scope, options) {
      if (typeof repository?.cleanup !== 'function') throw unavailable();
      const receipt = await repository.cleanup(scope, options);
      // Reset completion waits for verified retirement and every owned drain.
      for (const callback of callbacks) await callback(scope, options, receipt);
      return receipt;
    },
  });
}
function createDefaultMcpTrustBundle({ identityPool, agentsPool, launches, cleanupAuthority,
  fixtureRoot, auditStore } = {}) {
  return createSecureShopMcpTrustRepositoryBundle({ agentsPool, launches, cleanupAuthority,
    availability: createSecureShopMcpTrustAvailability(identityPool), fixtureRoot, auditStore });
}
async function assertLedger(pool, directory, required) {
  const expected = await readMigrations(directory);
  if (required && !expected.some(row => row.name === required.name)) expected.push(required);
  expected.sort((left,right) => left.name.localeCompare(right.name));
  const actual = (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  if (actual.length !== expected.length || actual.some((row,index) => row.name !== expected[index].name
      || row.checksum !== expected[index].checksum)) throw unavailable('SecureShop cleanup migration history is not ready');
  return actual;
}
async function assertSecureShopCleanupReadiness({ identityPool, agentsPool, reviewPool, migrationPools } = {}) {
  const pools = { identity: identityPool, agents: agentsPool, review: reviewPool };
  if (Object.values(pools).some(pool => !callable(pool,['query','connect']))
      || !migrationPools || Object.values(migrationPools).some(pool => !callable(pool,['query']))) throw unavailable();
  const probes = await Promise.allSettled(Object.entries(STORES).map(async ([name, config]) => {
    const runtime = (await pools[name].query('SELECT current_user AS role,current_database() AS database')).rows[0];
    const migration = (await migrationPools[name].query('SELECT current_user AS role,current_database() AS database')).rows[0];
    if (runtime?.role !== config.runtimeRole || migration?.role !== config.migrationRole
        || !runtime.database || migration.database !== runtime.database) throw unavailable('SecureShop cleanup store identity is not ready');
    const ledger = await assertLedger(migrationPools[name], config.directory,
      name === 'identity' ? CLEANUP_VISIBILITY_MIGRATION : undefined);
    if (name === 'identity' && !ledger.some(row => row.name === CLEANUP_VISIBILITY_MIGRATION.name
        && row.checksum === CLEANUP_VISIBILITY_MIGRATION.checksum)) {
      throw unavailable('SecureShop cleanup lifecycle capability is not ready');
    }
    const relations = (await pools[name].query(
      'SELECT value,to_regclass(value) IS NOT NULL AS ready FROM unnest($1::text[]) value',[config.relations])).rows;
    if (relations.length !== config.relations.length || relations.some(row => row.ready !== true)) {
      throw unavailable('SecureShop cleanup schema is not ready');
    }
    if(name==='agents')await require('../database/postgres/secureshopOwnedMcpRegistryRepository').assertOwnedMcpRegistryReady({pool:pools[name],expectedDatabase:runtime.database});
    return runtime.database;
  }));
  const failed = probes.find(result => result.status === 'rejected');
  if (failed) throw failed.reason;
  if (new Set(probes.map(result => result.value)).size !== probes.length) throw unavailable('SecureShop cleanup stores are not isolated');
  return true;
}

function createSecureShopCleanupComposition({ identityPool, agentsPool, reviewPool, leasePool, provisionPool, files,
  launches, cleanupAuthority, conversationRepository, journal, reviewRepository, productRepository,
  runCoordinator, audit, auditSqlLifecycle, analyticsLifecycle, analyticsRuntime, systemRestartClient, ownedMcpInvocationManager, registeredInvocation, listingsConfiguration, modeAuthority, personaInboxFactory = createSecureShopPersonaInboxRepositoryBundle,
  mcpTrustFactory = false, mcpTrustFixtureRoot, mcpTrust, ssrf, ssrfFactory = false, ssrfFixtureRoot } = {}) {
  if (![identityPool,agentsPool,reviewPool,leasePool].every(pool => callable(pool,['query','connect']))) throw unavailable();
  if(provisionPool!==undefined&&!callable(provisionPool,['query','connect']))throw unavailable();
  if(provisionPool&&(provisionPool===identityPool||provisionPool===leasePool))throw unavailable();
  if (audit !== undefined && (!callable(audit.agents, ['append', 'recent'])
      || !callable(audit.review, ['append', 'recent']) || !callable(audit.reader, ['recent'])
      || typeof audit.cleanup !== 'function')) throw unavailable('Audit composition is incomplete');
  if(registeredInvocation){
    if(launches&&launches!==registeredInvocation.launches)throw unavailable('Registered invocation launch authority mismatch');
    launches=registeredInvocation.launches;ownedMcpInvocationManager=registeredInvocation.retirer;
  }
  launches ||= createSecureShopLaunchRepository(identityPool);
  const featureModeAuthority=modeAuthority||require('./secureshopFeatureModeAuthority').createFeatureModeAuthority({
    progress:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),launches});
  const authority = cleanupAuthority || createSecureShopResetCleanupAuthorityRepository(identityPool);
  if (personaInboxFactory !== false && typeof personaInboxFactory !== 'function') throw unavailable();
  if (mcpTrustFactory !== false && typeof mcpTrustFactory !== 'function') throw unavailable();
  if (mcpTrust !== undefined && mcpTrustFactory !== false) throw unavailable();
  if (mcpTrustFactory !== false && (typeof mcpTrustFixtureRoot !== 'string'
      || !path.isAbsolute(mcpTrustFixtureRoot))) throw unavailable();
  if (ssrfFactory !== false && typeof ssrfFactory !== 'function') throw unavailable();
  if (ssrf !== undefined && ssrfFactory !== false) throw unavailable();
  ssrf = ssrf === undefined && ssrfFactory !== false
    ? ssrfFactory({ identityPool, agentsPool, launches, cleanupAuthority: authority, fixtureRoot: ssrfFixtureRoot, ...(audit?{auditStore:audit.agents}:{}) }) : ssrf;
  const personaInbox = personaInboxFactory === false ? null
    : personaInboxFactory({ agentsPool, launches, cleanupAuthority: authority, ...(audit?{auditStore:audit.agents}:{}) });
  mcpTrust = mcpTrust === undefined && mcpTrustFactory !== false
    ? mcpTrustFactory({ identityPool, agentsPool, launches, cleanupAuthority: authority,
      fixtureRoot: mcpTrustFixtureRoot, ...(audit?{auditStore:audit.agents}:{}) }) : mcpTrust;
  if (personaInbox && (typeof personaInbox.repository?.cleanup !== 'function'
      || typeof personaInbox.repository?.readCleanupReceipt !== 'function')) throw unavailable();
  if (mcpTrust !== undefined && (typeof mcpTrust?.cleanup !== 'function'
      || typeof mcpTrust?.readCleanupReceipt !== 'function')) throw unavailable();
  if (ssrf !== undefined && (typeof ssrf?.cleanup !== 'function'
      || typeof ssrf?.readCleanupReceipt !== 'function')) throw unavailable();
  const auditLedger = runCoordinator ? undefined : createPostgresRunLedger(identityPool,{leasePool});
  const coordinator = runCoordinator || createRunCoordinator({ family: 'SecureShopBoundConversation',ledger:auditLedger });
  const conversations = conversationRepository || createBoundConversationsRepository({pool:agentsPool,queue:runSessionExclusive});
  const turnJournal = journal || createTurnRequestsRepository({pool:agentsPool});
  const reviews = reviewRepository || createSecureShopBoundReviewRepository(reviewPool,{
    ...(audit ? {auditStore:audit.review} : {}),
    enableLearnerSubmissions:true, checkCurrent: scope => launches.assertCurrent(scope),
    checkRetirement: async()=>{throw Object.assign(new Error('Review retirement requires cleanup authority'),{code:'RESET_CLEANUP_AUTHORITY_REQUIRED'});},
    checkCleanup: input => authority.checkReviewTarget(input),
  });
  const products = productRepository || createSecureShopBoundProductRepository(reviewPool,{
    ...(audit ? {auditStore:audit.review} : {}),
    modeAuthority:featureModeAuthority,
    checkCurrent:value=>launches.assertCurrent(value),checkCleanup:input=>authority.checkProductTarget(input),
  });
  if(systemRestartClient!==undefined&&(!callable(systemRestartClient,['retire','retirement','forget'])))throw unavailable('System restart cleanup transport is incomplete');
  const restartLifecycle=systemRestartClient===undefined?undefined:require('./secureshopSystemRestartLifecycle').createSecureShopSystemRestartLifecycle({pool:reviewPool,client:systemRestartClient,checkCleanup:input=>authority.checkProductTarget(input)});
  const listingsRuntime=listingsConfiguration?require('./secureshopListingsRuntime').createListingsRuntime({configuration:listingsConfiguration,modeAuthority:featureModeAuthority,launches,products,reviewPool,mode:process.env.LAB_MODE||'vuln'}):undefined;
  const listingProducts=listingsRuntime?.lifecycle||products;
  let productCleanup=restartLifecycle?Object.freeze({async cleanup(input,options){const retirement=await restartLifecycle.cleanup(input,options),result=await listingProducts.cleanup(input,options);if(retirement.state==='completed')await restartLifecycle.forget(input,{...options,canonicalReceiptSha256:result.receiptSha256});return result;}}):listingProducts;
  const lifecycleRows = createSecureShopConversationLifecycleRepository({pool:agentsPool});
  const conversationService = require('./secureshopBoundConversation').createBoundConversationService({conversations,launches});
  const turns = require('./secureshopBoundTurns').createBoundTurns({conversations:conversationService,coordinator});
  // Registry SQL cleanup remains mandatory even when registry serving is disabled.
  const invocationJournal = registeredInvocation?.journal || require('../database/postgres/secureshopOwnedMcpInvocationJournal').createOwnedMcpInvocationJournal({pool:agentsPool});
  const invocationLifecycle = require('./secureshopOwnedMcpInvocationLifecycle').createOwnedMcpInvocationLifecycle({journal:invocationJournal,cleanupAuthority:authority,manager:ownedMcpInvocationManager});
  const registrationJournal=registeredInvocation?.registrationJournal||require('../database/postgres/secureshopOwnedMcpRegistrationJournal').createOwnedMcpRegistrationJournal({pool:agentsPool});
  const registrationLifecycle=require('./secureshopOwnedMcpRegistrationLifecycle').createOwnedMcpRegistrationLifecycle({journal:registrationJournal,client:registeredInvocation?.client,cleanupAuthority:authority});
  const registryLifecycle = require('./secureshopOwnedMcpRegistryLifecycle').createOwnedMcpRegistryLifecycle({pool:agentsPool,cleanupAuthority:authority,invocationLifecycle,registrationLifecycle});
  const lifecycle = registryLifecycle.decorateConversation(createSecureShopConversationLifecycle({repository:lifecycleRows,turns,cleanupAuthority:authority}));
  const conversationCheckpoint = createSecureShopConversationCleanupCheckpointRepository(identityPool,{
    getOperation: resetId=>authority.getOperation(resetId),readRetirementReceipt:resetId=>lifecycle.readReceipt(resetId),
  });
  const reviewReceipt = createSecureShopReviewCleanupReceiptReader({repository:reviews});
  let fileCleanup; let fileReceipt;
  if (files !== undefined) {
    fileCleanup=createSecureShopFileTargetCleanup({files,cleanupAuthority:authority});
    fileReceipt=createSecureShopFileCleanupReceiptReader({files,cleanupAuthority:authority});
  }
  // Avatar uploads belong to scene product targets, not reserved filesystem targets.
  const uploadJournal=require('../database/postgres/secureshopBoundUploadRepository').createSecureShopBoundUploadRepository(reviewPool,{
    checkCurrent:async()=>{throw unavailable('Retired upload cleanup cannot use active authority');},
    assertSceneGrant:async()=>{throw unavailable('Retired upload cleanup cannot use active scene authority');},
    checkCleanupAuthority:(scope,operationId)=>authority.checkTarget({...scope,targetKind:'products',fromGeneration:scope.generation,operationId}),
  });
  productCleanup=require('./secureshopBoundUploadResetAdapter').createSecureShopBoundUploadResetAdapter({
    pool:reviewPool,fileCleanup:productCleanup,targetKind:'products',journal:uploadJournal,cleanupAuthority:authority,
    storage:require('./secureshopUploadStorageLifecycle').createSecureShopUploadStorageLifecycle({
      root:require('./secureshop/assetPaths').getSecureShopUploadRoot(),
    }),
  });

  const reconciler=createSecureShopTargetReconciliationRepository(identityPool,{
    checkAuthority:input=>authority.checkTarget(input),
    readCleanupReceipt:input=>{
      if(input.targetKind==='reviews')return reviewReceipt(input);
      if(input.targetKind==='products')return listingProducts.readCleanupReceipt({targetId:input.targetId,launchId:input.launchId,
        scenarioId:input.scenarioId,generation:input.fromGeneration,platformOwnerId:input.platformOwnerId,
        platformSessionId:input.platformSessionId},{operationId:input.operationId});
      if(input.targetKind==='files'&&fileReceipt)return fileReceipt(input);
      if(input.targetKind==='persona_inbox'&&personaInbox)return personaInbox.repository.readCleanupReceipt({
        targetId:input.targetId,launchId:input.launchId,scenarioId:input.scenarioId,
        generation:input.fromGeneration,platformOwnerId:input.platformOwnerId,
        platformSessionId:input.platformSessionId},{operationId:input.operationId}).then(receipt=>
        Object.freeze({...receipt,kind:'persona_inbox'}));
      if(['mcp_rogue','mcp_rug_pull'].includes(input.targetKind)&&mcpTrust)return mcpTrust.readCleanupReceipt(input,
        {operationId:input.operationId});
      if(input.targetKind==='controlled_ssrf'&&ssrf)return ssrf.readCleanupReceipt(input,
        {operationId:input.operationId});
      throw Object.assign(new Error('Target cleanup adapter is unavailable'),{code:'UNSUPPORTED_TARGET_CLEANUP'});
    },
  });
  const sceneResetPreflight=createSecureShopSceneResetPreflight({identityPool,reviewPool});
  const inboxCleanup = createPersonaInboxTransportCleanup(personaInbox?.repository);
  const registerPersonaInboxTransportCleanup = inboxCleanup.register;
  const targetCoordinator=createSecureShopReviewResetCoordinator({launches,cleanupAuthority:authority,
    reviewRepository:reviews,reconciler,productCleanup,...(fileCleanup?{fileCleanup}: {}),
    ...(personaInbox?{personaInboxCleanup:inboxCleanup}: {}),...(mcpTrust?{mcpTrustCleanup:mcpTrust}: {}),
    ...(ssrf?{ssrfCleanup:ssrf}: {})});
  const launchResetCoordinator=createSecureShopLaunchResetCoordinator({launches,cleanupAuthority:authority,
    sceneResetPreflight,
    conversationLifecycle:lifecycle,conversationCheckpoint,targetCoordinator,auditSqlLifecycle,analyticsLifecycle,
    progressCheckpoint:createSecureShopRealmProgressCleanupCheckpointRepository(identityPool)});
  const ownerResetService=createSecureShopOwnerResetService({repository:createSecureShopOwnerResetRepository(identityPool),
    launchResetCoordinator,launches,sceneResetPreflight});
  const createStudentDeletionCleanup=repository=>createSecureShopStudentDeletionCleanup({repository,launchResetCoordinator,auditCleanup:async input=>{if(!audit)throw unavailable('Canonical audit deletion required for registry cleanup');await registryLifecycle.beforeDeletion(input);const receipt=await audit.cleanup(input);await registryLifecycle.verifyDeletion(input);return receipt;},...(auditSqlLifecycle?{auditSqlCleanup:auditSqlLifecycle.destroyForDeletion}:{}),...(analyticsLifecycle?{analyticsCleanup:analyticsLifecycle.destroyForDeletion}:{})});
  let featureTransportClosing;
  function closeFeatureTransports(){
    featureTransportClosing ||= (async()=>{
      const results=await Promise.allSettled([mcpTrust,ssrf,analyticsRuntime].filter(value=>typeof value?.close==='function').map(async value=>value.close()));
      const failures=results.filter(result=>result.status==='rejected').map(result=>result.reason);
      if(failures.length)throw new AggregateError(failures,'SecureShop target transport shutdown failed');
    })();
    return featureTransportClosing;
  }
  return Object.freeze({...(audit?{audit}:{}),auditLedger,files,launches,registeredInvocation,modeAuthority:featureModeAuthority,cleanupAuthority:authority,runCoordinator:coordinator,conversations,
    graphLeasePool:leasePool,...(provisionPool?{provisionPool}:{}),
    journal:turnJournal,reviews,products,restartLifecycle,listingsRuntime,conversationService,turns,analyticsLifecycle,analyticsRuntime,launchResetCoordinator,ownerResetService,sceneResetPreflight,
    createStudentDeletionCleanup,closeFeatureTransports,registerPersonaInboxTransportCleanup,...(personaInbox?{personaInbox}: {}),...(mcpTrust?{mcpTrust}: {}),...(ssrf?{ssrf}: {})});
}

let retained; let retainedFiles; let retainedMcpTrustFeature; let retainedMcpTrustFixtureRoot;
let retainedSsrfFeature; let retainedSsrfFixtureRoot; let retainedSystemRestartClient; let pendingSsrfFeature; let pendingSsrfFixtureRoot; let pendingSystemRestartClient;
let pending; let pendingFiles; let pendingMcpTrustFeature; let pendingMcpTrustFixtureRoot; let closing;
async function getSecureShopCleanupComposition(options={}) {
  if (closing) throw unavailable('SecureShop cleanup runtime is closing');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw unavailable();
  const restartClientSpecified=Object.prototype.hasOwnProperty.call(options,'systemRestartClient');
  const files=options.files ?? require('./secureshopOwnedFiles').getSecureShopOwnedFiles(),mcpTrustFeature=options.mcpTrustFeature ?? mcpTrustPolicy(process.env).requested,
    mcpTrustFixtureRoot=options.mcpTrustFixtureRoot ?? (mcpTrustFeature?process.env.SS_MCP_TRUST_FIXTURE_ROOT:undefined),
    ssrfFeature=options.ssrfFeature ?? ssrfPolicy(process.env).requested,
    ssrfFixtureRoot=options.ssrfFixtureRoot ?? (ssrfFeature?process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT:undefined),systemRestartClient=options.systemRestartClient;
  if(typeof ssrfFeature!=='boolean')throw unavailable();
  if(ssrfFeature&&(typeof ssrfFixtureRoot!=='string'||!path.isAbsolute(ssrfFixtureRoot)))throw unavailable();
  if (options.mcpTrustFeature !== undefined && typeof options.mcpTrustFeature !== 'boolean') throw unavailable();
  if (mcpTrustFeature && (typeof mcpTrustFixtureRoot !== 'string'
      || !path.isAbsolute(mcpTrustFixtureRoot))) throw unavailable('SecureShop MCP trust fixture root is not ready');
  if (retained) {
    if (retainedFiles !== files || retainedMcpTrustFeature !== mcpTrustFeature
        || retainedMcpTrustFixtureRoot !== mcpTrustFixtureRoot
        || retainedSsrfFeature !== ssrfFeature || retainedSsrfFixtureRoot !== ssrfFixtureRoot
        || (restartClientSpecified && retainedSystemRestartClient !== systemRestartClient)) throw unavailable('SecureShop cleanup runtime is already configured');
    return retained.value;
  }
  if (pending) {
    if (pendingFiles !== files || pendingMcpTrustFeature !== mcpTrustFeature
        || pendingMcpTrustFixtureRoot !== mcpTrustFixtureRoot
        || pendingSsrfFeature !== ssrfFeature || pendingSsrfFixtureRoot !== ssrfFixtureRoot
        || (restartClientSpecified && pendingSystemRestartClient !== systemRestartClient)) throw unavailable('SecureShop cleanup runtime is already configuring');
    return pending;
  }
  if (process.env.PLATFORM_DATABASE_ENGINE!=='postgres'
      || Object.values(STORES).some(store=>!process.env[store.runtimeEnv]||!process.env[store.migrationEnv])) {
    throw unavailable('SecureShop cleanup store configuration is incomplete');
  }
  pendingSsrfFeature=ssrfFeature;pendingSsrfFixtureRoot=ssrfFixtureRoot;pendingSystemRestartClient=systemRestartClient;
  pendingFiles=files;pendingMcpTrustFeature=mcpTrustFeature;pendingMcpTrustFixtureRoot=mcpTrustFixtureRoot;
  pending=(async()=>{
    const identityPool=require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    const agentsPool=require('../database/postgres/secureshopPools').getAgentsPool();
    const reviewPool=require('../database/postgres/secureshopReviewDb').getSecureShopReviewPool();
    const migrationPools={};
    try {
      for(const [name,store] of Object.entries(STORES))migrationPools[name]=createPool(process.env,store.migrationEnv);
      await assertSecureShopCleanupReadiness({identityPool,agentsPool,reviewPool,migrationPools});
    } finally {
      const results=await Promise.allSettled(Object.values(migrationPools).map(pool=>pool.end()));
      const errors=results.filter(result=>result.status==='rejected').map(result=>result.reason);
      if(errors.length)throw new AggregateError(errors,'SecureShop cleanup readiness pool cleanup failed');
    }
    const {assertSecureShopBoundAuditReadiness,createSecureShopBoundAuditComposition}=require('./secureshopBoundAuditComposition');
    await assertSecureShopBoundAuditReadiness({agentsPool,reviewPool,includeRunArtifacts:true});
    // Storage cleanup remains required when new summary runs are disabled.
    const audit=createSecureShopBoundAuditComposition({agentsPool,reviewPool,includeRunArtifacts:true});
    const auditSqlRuntime=await require('./secureshopOwnedAuditProduction').getOwnedAuditProduction();
    if(!auditSqlRuntime){
      const targetJournal=(await identityPool.query("SELECT to_regclass('identity.secureshop_audit_target_admissions') IS NOT NULL AS present")).rows[0]?.present;
      const debt=(await identityPool.query(`SELECT EXISTS(${targetJournal?'SELECT 1 FROM identity.secureshop_audit_target_admissions UNION ALL ':''}SELECT 1 FROM identity.secureshop_audit_query_operations UNION ALL SELECT 1 FROM identity.secureshop_audit_manual_operations) AS present`)).rows[0];
      if(debt?.present)throw unavailable('Owned audit cleanup configuration is missing');
    }
    const auditSqlLifecycle=auditSqlRuntime?require('./secureshopOwnedAuditLifecycle').createOwnedAuditLifecycle({cleanupAuthority:require('../database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identityPool),client:auditSqlRuntime.client}):undefined;
    const analyticsRuntime=await require('./secureshopOwnedAnalyticsProduction').getOwnedAnalyticsProduction();
    const analyticsLifecycle=require('./secureshopAnalyticsLifecycle').createAnalyticsLifecycle({cleanupAuthority:require('../database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identityPool),service:analyticsRuntime?.service,agentsPool,reviewPool});
    const listingsConfiguration=require('./secureshopListingsRuntime').loadConfiguration();
    if(!listingsConfiguration)await require('./secureshopListingsRuntime').assertNoUnmanagedListingsDebt(reviewPool);
    const invocationModule=require('./secureshopRegisteredInvocationProduction');
    const registeredInvocation=invocationModule.createRegisteredInvocationInfrastructure({configuration:await invocationModule.readConfiguration(),identityPool,agentsPool});
    const leasePool=createPool(process.env,'IDENTITY_DATABASE_URL',{purpose:'lease'});
    let provisionPool;
    try {
      provisionPool=createPool(process.env,'IDENTITY_DATABASE_URL',{purpose:'provision'});
      const value=createSecureShopCleanupComposition({identityPool,agentsPool,reviewPool,leasePool,provisionPool,files,audit,auditSqlLifecycle,analyticsLifecycle,analyticsRuntime,systemRestartClient,listingsConfiguration,registeredInvocation,
        ...(mcpTrustFeature?{mcpTrustFactory:createDefaultMcpTrustBundle,mcpTrustFixtureRoot}: {}),
        ...(ssrfFeature?{ssrfFactory:createSecureShopSsrfRepositoryBundle,ssrfFixtureRoot}: {})});
      if(closing)throw unavailable('SecureShop cleanup runtime is closing');
      retained={value,leasePool,provisionPool};retainedFiles=files;retainedMcpTrustFeature=mcpTrustFeature;
      retainedMcpTrustFixtureRoot=mcpTrustFixtureRoot;retainedSsrfFeature=ssrfFeature;retainedSsrfFixtureRoot=ssrfFixtureRoot;retainedSystemRestartClient=systemRestartClient;return value;
    }catch(error){
      const closed=await Promise.allSettled([provisionPool,leasePool].filter(Boolean).map(pool=>pool.end()));
      const failures=closed.filter(result=>result.status==='rejected').map(result=>result.reason);
      if(failures.length)throw new AggregateError([error,...failures],
        'SecureShop cleanup pool setup failed');
      throw error;
    }
  })();
  try{return await pending;}finally{pending=undefined;pendingFiles=undefined;pendingMcpTrustFeature=undefined;
    pendingMcpTrustFixtureRoot=undefined;pendingSsrfFeature=undefined;pendingSsrfFixtureRoot=undefined;pendingSystemRestartClient=undefined;}
}
async function closeSecureShopCleanupComposition(){
  if(closing)return closing;
  closing=(async()=>{if(pending){try{await pending;}catch{}}const owned=retained;retained=undefined;retainedFiles=undefined;
    retainedMcpTrustFeature=undefined;retainedMcpTrustFixtureRoot=undefined;retainedSsrfFeature=undefined;retainedSsrfFixtureRoot=undefined;retainedSystemRestartClient=undefined;
    if(owned){const results=[];try{await owned.value.closeFeatureTransports();results.push({status:'fulfilled'});}
      catch(reason){results.push({status:'rejected',reason});}
      results.push(...await Promise.allSettled([owned.leasePool,owned.provisionPool]
        .filter(Boolean).map(pool=>pool.end())));
      const failures=results.filter(result=>result.status==='rejected').map(result=>result.reason);
      if(failures.length)throw new AggregateError(failures,'SecureShop cleanup runtime shutdown failed');}})();
  try{await closing;}finally{closing=undefined;}
}
module.exports={STORES,CLEANUP_VISIBILITY_MIGRATION,assertSecureShopCleanupReadiness,createSecureShopCleanupComposition,
  createPersonaInboxTransportCleanup,createDefaultMcpTrustBundle,getSecureShopCleanupComposition,closeSecureShopCleanupComposition};
