'use strict';

const { createMcpOwnedResourceComposition, createMcpOwnedResourceReadiness } = require('./ownedResourceComposition');
const { createMcpOwnedTargetClient } = require('./ownedTargetClient');
const { createMcpConversationRepository } = require('../../database/postgres/mcpConversationRepository');
const { createMcpRequestRepository } = require('../../database/postgres/mcpRequestRepository');
const { createOwnedQualification, createOwnedToolAuthorizer, PROTECTED_STATE_CAPABILITY,
  OBSERVED_ACTION_CAPABILITY, PACKAGE_INSTALL_CAPABILITY,
  TICKET_READ_CAPABILITY, CATALOG_OBSERVATION_CAPABILITY, SHADOW_CAPABILITY, withShadowQualification } = require('./ownedQualification');
const { attachCleanupErrors } = require('./protectedRecoveryProduction');

const CONVERSATION_RELATIONS = Object.freeze(['workshop_conversations.turns', 'workshop_conversations.requests']);

function enabled(env) {
  const value = env.MCP_OWNED_RESOURCES_ENABLED;
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error('MCP_OWNED_RESOURCES_ENABLED must be true or false');
}

function observedActionEnabled(env) {
  const value = env.MCP_OBSERVED_ACTION_ENABLED;
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error('MCP_OBSERVED_ACTION_ENABLED must be true or false');
}

function indirectInjectionEnabled(env) {
  const value = env.MCP_INDIRECT_INJECTION_ENABLED;
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error('MCP_INDIRECT_INJECTION_ENABLED must be true or false');
}

function supplyChainEnabled(env) {
  const value = env.MCP_SUPPLY_CHAIN_ENABLED;
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error('MCP_SUPPLY_CHAIN_ENABLED must be true or false');
}

async function conversationReadiness(identityPool) {
  try {
    for (const relation of CONVERSATION_RELATIONS) {
      const found = (await identityPool.query('SELECT to_regclass($1)::text AS name', [relation])).rows[0];
      if (found?.name !== relation) return false;
      const row = (await identityPool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS can_select,
        has_table_privilege(current_user,$1,'INSERT') AS can_insert`, [relation])).rows[0];
      if (row?.can_select !== true || row.can_insert !== true) return false;
    }
    const update = (await identityPool.query(
      "SELECT has_column_privilege(current_user,'workshop_conversations.requests','response_json','UPDATE') AS response_update, has_column_privilege(current_user,'workshop_conversations.requests','user_text','UPDATE') AS text_update, has_table_privilege(current_user,'workshop_conversations.turns','DELETE') AS turn_delete"
    )).rows[0];
    return update?.response_update === true && update.text_update === true && update.turn_delete === true;
  } catch {
    return false;
  }
}

async function installMcpOwnedResourceProductionCore({ env = process.env, route,
  identityAdapter, resourcePool, targets, mailReadiness, ownedHttp, ownedShadow,
  compositionFactory = createMcpOwnedResourceComposition,
  protocolManager = require('./sdk/sessionManager') } = {},
{ enableObservedAction = false, enableIndirectInjection = false,
  enableSupplyChain = false, enableCatalogRecon = false } = {}) {
  if (!enabled(env)) return Object.freeze({ enabled: false, installed: false });
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw new Error('Owned MCP resources require PostgreSQL platform and workshop stores');
  }
  if (!route || typeof route.installOwnedRuntime !== 'function') {
    throw new TypeError('MCP workshop activation seams are required');
  }
  identityAdapter ||= require('../postgresIdentityAdapter').getPostgresIdentityAdapter();
  resourcePool ||= await require('../../database/mcpWorkshopDb').runtimePool();
  targets ||= createMcpOwnedTargetClient({ baseURL: env.MCP_OWNED_TARGET_URL,
    token: env.MCP_OWNED_TARGET_TOKEN });
  mailReadiness ||= require('./mailClient').readiness;
  if (!identityAdapter?.pool || typeof identityAdapter.validateSession !== 'function'
      || !resourcePool || typeof resourcePool.query !== 'function'
      || typeof mailReadiness !== 'function') throw new TypeError('Canonical MCP production dependencies are required');

  try {
    targets = await require('./ownedHttpProduction').composeOwnedHttpProduction({
      env, resourcePool, identityPool: identityAdapter.pool, targets, ownedHttp,
    });
  } catch (cause) {
    throw Object.assign(new Error('Qualified MCP HTTP lifecycle is unavailable', { cause }),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }
  targets = await require('./ownedShadowProduction').composeOwnedShadowProduction({env,resourcePool,identityPool:identityAdapter.pool,targets,configuration:ownedShadow});
  let protectedRecovery=null;
  const runnerReadiness = createMcpOwnedResourceReadiness({ resourcePool, targets });
  const liveReadiness = async () => {
    try {
      const [resources, conversationsReady, mail] = await Promise.all([
        runnerReadiness(), conversationReadiness(identityAdapter.pool), mailReadiness(),
      ]);
      if(protectedRecovery)await protectedRecovery.readiness();
      return Object.freeze({ ...resources,
        ready: resources.ready === true && conversationsReady === true && mail?.ready === true,
        conversationsReady, mailReady: mail?.ready === true,
        catalogObservationCapability: protocolManager?.catalogObservationCapability });
    } catch {
      return Object.freeze({ ready: false, repositoryReady: false, runnerReady: false,
        conversationsReady: false, mailReady: false });
    }
  };
  const resources = await liveReadiness();
  if (resources.ready !== true) {
    throw Object.assign(new Error('Qualified MCP owned runtime is unavailable'), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }
  if (enableSupplyChain && (resources.protectedStateCapability !== PROTECTED_STATE_CAPABILITY
      || resources.observedActionCapability !== OBSERVED_ACTION_CAPABILITY
      || resources.packageInstallCapability !== PACKAGE_INSTALL_CAPABILITY)) {
    throw Object.assign(new Error('Qualified MCP package-install capability is unavailable'),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }
  if (enableIndirectInjection && (resources.protectedStateCapability !== PROTECTED_STATE_CAPABILITY
      || resources.observedActionCapability !== OBSERVED_ACTION_CAPABILITY
      || resources.ticketReadCapability !== TICKET_READ_CAPABILITY)) {
    throw Object.assign(new Error('Qualified MCP indirect-injection capabilities are unavailable'),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }
  if (enableCatalogRecon
      && protocolManager?.catalogObservationCapability !== CATALOG_OBSERVATION_CAPABILITY) {
    throw Object.assign(new Error('Qualified MCP catalog observation capability is unavailable'),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }

  let qualification = createOwnedQualification(true, {
    protectedStateCapability: resources.protectedStateCapability === PROTECTED_STATE_CAPABILITY
      ? resources.protectedStateCapability : null,
    observedActionCapability: resources.observedActionCapability === OBSERVED_ACTION_CAPABILITY
      ? resources.observedActionCapability : null,
    ticketReadCapability: resources.ticketReadCapability === TICKET_READ_CAPABILITY
      ? resources.ticketReadCapability : null,
    packageInstallCapability: resources.packageInstallCapability === PACKAGE_INSTALL_CAPABILITY
      ? resources.packageInstallCapability : null,
    catalogObservationCapability: enableCatalogRecon
      ? protocolManager.catalogObservationCapability : null,
    httpCapability: resources.httpCapability,
    enableObservedAction,
    enableIndirectInjection,
    enableSupplyChain,
    enableCatalogRecon,
  });
  if(resources.shadowCapability===SHADOW_CAPABILITY&&resources.shadowObjectiveQualified===true)qualification=withShadowQualification(qualification,{capability:resources.shadowCapability,enabled:true});
  protectedRecovery=await require('./protectedRecoveryProduction').createProtectedRecoveryProduction({env,identityAdapter,targets});
  try {
  const application = compositionFactory({ validateSession: token => identityAdapter.validateSession(token),
    resourcePool, identityPool: identityAdapter.pool, targets, readiness: liveReadiness, qualification,
    protectedResourceLeasePool:protectedRecovery?.resourceLeasePool||null,
    authorizeTool: createOwnedToolAuthorizer(qualification) });
  if (application?.qualification?.version !== qualification.version
      || application.qualification?.qualifiedObjectives !== qualification.qualifiedObjectives) {
    throw new TypeError('MCP owned runtime qualification differs from its readiness capability');
  }
  const requests = createMcpRequestRepository(identityAdapter.pool);
  const conversations = createMcpConversationRepository(identityAdapter.pool);
  // All checks and object construction finish before either public seam changes.
  route.installOwnedRuntime({ application, requests, conversations, protectedRecovery });
  return Object.freeze({ enabled: true, installed: true, qualification: application.qualification,
    readiness: resources, ...(protectedRecovery?{protectedRecoveryReady:true,close:protectedRecovery.close}:{}) });
  }catch(error){try{await protectedRecovery?.close();}catch(cleanup){attachCleanupErrors(error,cleanup.cleanupErrors||[{name:cleanup?.name||'Error',message:String(cleanup?.message||cleanup)}]);}throw error;}
}

async function installMcpOwnedResourceProduction(options) {
  const env = options?.env || process.env;
  const enableObservedAction = observedActionEnabled(env);
  const enableIndirectInjection = indirectInjectionEnabled(env);
  const enableSupplyChain = supplyChainEnabled(env);
  if (enableSupplyChain && (!enabled(env) || !enableObservedAction)) {
    throw new Error('MCP_SUPPLY_CHAIN_ENABLED requires MCP_OWNED_RESOURCES_ENABLED and MCP_OBSERVED_ACTION_ENABLED');
  }
  if (enableIndirectInjection && (!enabled(env) || !enableObservedAction)) {
    throw new Error('MCP_INDIRECT_INJECTION_ENABLED requires MCP_OWNED_RESOURCES_ENABLED and MCP_OBSERVED_ACTION_ENABLED');
  }
  return installMcpOwnedResourceProductionCore(options,
    { enableObservedAction, enableIndirectInjection, enableSupplyChain, enableCatalogRecon: true });
}

module.exports = { installMcpOwnedResourceProduction, conversationReadiness, CONVERSATION_RELATIONS,
  _internals: { enabled, observedActionEnabled, indirectInjectionEnabled, supplyChainEnabled,
    ...(process.env.EXPORT_INTERNALS === '1'
    ? { installObservedActionCandidate: options => installMcpOwnedResourceProductionCore(options,
      { enableObservedAction: true }),
      installIndirectInjectionCandidate: options => installMcpOwnedResourceProductionCore(options,
        { enableObservedAction: true, enableIndirectInjection: true }),
      installCatalogReconCandidate: options => {
        const env = options?.env || process.env;
        const enableObservedAction = observedActionEnabled(env);
        const enableSupplyChain = supplyChainEnabled(env);
        if (enableSupplyChain && (!enabled(env) || !enableObservedAction)) {
          throw new Error('MCP_SUPPLY_CHAIN_ENABLED requires MCP_OWNED_RESOURCES_ENABLED and MCP_OBSERVED_ACTION_ENABLED');
        }
        return installMcpOwnedResourceProductionCore(options,
          { enableObservedAction, enableSupplyChain, enableCatalogRecon: true });
      } } : {}) } };
