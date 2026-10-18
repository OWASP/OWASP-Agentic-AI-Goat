'use strict';

const { createMcpPlatformSessionResolver } = require('./platformSessionBinding');
const { createMcpResourceRepository } = require('../../database/postgres/mcpResourceRepository');
const { createDurableMcpMailResources } = require('./durableMailResources');
const mailClient = require('./mailClient');
const { createMcpOwnedResourceApplication } = require('./ownedResourceApplication');

const RESOURCE_RELATIONS = Object.freeze(['mcp.runner_targets', 'mcp.runner_target_cleanups',
  'mcp.mail_intents', 'mcp.mail_cleanups']);

function createMcpOwnedResourceReadiness({ resourcePool, targets } = {}) {
  if (!resourcePool || typeof resourcePool.query !== 'function' || !targets || typeof targets.readiness !== 'function') {
    throw new TypeError('MCP resource pool and owned target readiness are required');
  }
  return async function readiness() {
    const catalog = (await resourcePool.query('SELECT to_regclass($1)::text AS name', [RESOURCE_RELATIONS[0]])).rows[0];
    // One query per fixed server-owned relation avoids interpolating catalog
    // names and makes a partially installed draft fail before any allocation.
    const present = [catalog?.name];
    for (const relation of RESOURCE_RELATIONS.slice(1)) {
      present.push((await resourcePool.query('SELECT to_regclass($1)::text AS name', [relation])).rows[0]?.name);
    }
    if (present.some((name, index) => name !== RESOURCE_RELATIONS[index])) {
      return Object.freeze({ ready: false, repositoryReady: false, runnerReady: false });
    }
    for (const relation of RESOURCE_RELATIONS) {
      const row = (await resourcePool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS can_select,
        has_table_privilege(current_user,$1,'INSERT') AS can_insert,
        has_table_privilege(current_user,$1,'UPDATE') AS can_update`, [relation])).rows[0];
      if (row?.can_select !== true || row.can_insert !== true || row.can_update !== true) {
        return Object.freeze({ ready: false, repositoryReady: false, runnerReady: false });
      }
    }
    const runner = await targets.readiness();
    const runnerReady = runner?.ready === true && runner.runnerReady === true;
    return Object.freeze({ ready: runnerReady, repositoryReady: true, runnerReady,
      httpCapability: runner?.httpCapability || null,
      ...(runner?.shadowCapability ? {shadowCapability:runner.shadowCapability,shadowObjectiveQualified:runner.shadowObjectiveQualified===true} : {}),
      runnerVersion: runner?.version || null, runnerIsolation: runner?.isolation || null,
      supervisorProfile: runner?.supervisorProfile || null,
      protectedStateCapability: runner?.protectedStateCapability || null,
      ...(runner?.protectedJournalCapability?{protectedJournalCapability:runner.protectedJournalCapability}:{}),
      ...(runner?.protectedReadbackCapability?{protectedReadbackCapability:runner.protectedReadbackCapability}:{}),
      ...(runner?.observedActionCapability ? { observedActionCapability: runner.observedActionCapability } : {}),
      ...(runner?.packageInstallCapability ? { packageInstallCapability: runner.packageInstallCapability } : {}),
      ...(runner?.ticketReadCapability ? { ticketReadCapability: runner.ticketReadCapability } : {}),
      runnerEndpoint: typeof runner?.endpoint === 'string' ? runner.endpoint : null });
  };
}

// Startup composition hook. The production installer is mounted default-off;
// activation still requires the authoritative identity/JWT validator and a
// runner adapter whose live readiness includes its native isolation receipt.
function createMcpOwnedResourceComposition({ validateSession, resourcePool, targets, readiness, identityPool, ownedHttp = null, protectedResourceLeasePool = null,
  authorizeTool, qualification, verifyMessageReadback = mailClient.verifyMessageReadback,
  createToolDescriptions,
  sendMail = mailClient.sendOwnedReport,
  deleteMessages = ids => mailClient.deleteMessagesBySmtpIds(ids),
  listMessages = ids => mailClient.listMessagesBySmtpIds(ids) } = {}) {
  if (!resourcePool || typeof resourcePool.query !== 'function') throw new TypeError('MCP resource pool is required');
  // A supplied configuration is trusted startup input. Keep the composite even
  // when disabled so historical HTTP leases still require retirement.
  const effectiveTargets = ownedHttp === null ? targets : require('./ownedHttpCompositeTargets').createOwnedHttpCompositeTargets({
    cli: targets, http: ownedHttp.client || null,
    leases: require('../../database/postgres/mcpHttpLeaseRepository').createMcpHttpLeaseRepository(resourcePool),
    receiptRepository: identityPool ? require('../../database/postgres/mcpHttpReceiptRepository').createMcpHttpReceiptRepository(identityPool) : null,
    readMode: ownedHttp.readMode, enabled: ownedHttp.enabled === true,
  });
  const repository = createMcpResourceRepository(resourcePool);
  const mailResources = createDurableMcpMailResources({ repository, sendMail, deleteMessages, listMessages });
  return createMcpOwnedResourceApplication({
    sessionResolver: createMcpPlatformSessionResolver({ validateSession }),
    readiness: readiness || createMcpOwnedResourceReadiness({ resourcePool, targets: effectiveTargets }), repository, mailResources, targets: effectiveTargets,
    authorizeTool, qualification, verifyMessageReadback, createToolDescriptions,
    protectedAdmission: protectedResourceLeasePool ? require('./protectedOperationAdmission').createProtectedOperationAdmission({identityPool,resourceLeasePool:protectedResourceLeasePool}) : null,
  });
}

module.exports = { createMcpOwnedResourceComposition, createMcpOwnedResourceReadiness, RESOURCE_RELATIONS };
