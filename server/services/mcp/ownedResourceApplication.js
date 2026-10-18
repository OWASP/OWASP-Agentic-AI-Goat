'use strict';

const crypto = require('node:crypto');
const { createSandboxFactory } = require('./sandboxShell');
const protocol = require('./protocolContext');
const { createMcpProtocolSessionManager } = require('./sdk/sessionManager');
const { createMcpServer } = require('./sdk/vulnerableMcpServer');
const confusedDeputyObservation = require('./confusedDeputyObservation');
const indirectInjectionObservation = require('./indirectInjectionObservation');
const commandObservation = require('./commandObservation');
const deliveredMailObservation = require('./deliveredMailObservation');
const protectedStateObservation = require('./protectedStateObservation');
const observedActionObservation = require('./observedActionObservation');
const supplyChainObservation = require('./supplyChainObservation');
const { createOwnedQualification, canExecuteOwnedTool, PROTECTED_QUALIFICATION_VERSION,
  PROTECTED_STATE_CAPABILITY, OBSERVED_ACTION_QUALIFICATION_VERSION,
  OBSERVED_ACTION_CAPABILITY, SUPPLY_CHAIN_QUALIFICATION_VERSION,
  PACKAGE_INSTALL_CAPABILITY, TICKET_READ_CAPABILITY, INDIRECT_INJECTION_QUALIFICATION_VERSION,
  CATALOG_OBSERVATION_CAPABILITY, CATALOG_QUALIFICATION_VERSION,
  PROTECTED_CATALOG_QUALIFICATION_VERSION,
  OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION, SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
  INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
  INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION } = require('./ownedQualification');
const catalogObservation = require('./catalogObservation');

const fail = (code, message, statusCode = 503) => {
  const error = new Error(message); error.code = code; error.statusCode = statusCode; throw error;
};
function normalizedGeneration(value) {
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)
      && BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  return null;
}
function retirementOwner(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'An exact MCP platform owner is required', 409);
  }
  return value;
}
function retirementScope(value, platformOwnerId) {
  const generation = normalizedGeneration(value?.generation);
  if (!value || typeof value.targetId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.targetId)
      || value.platformOwnerId !== platformOwnerId
      || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1
      || value.platformSessionId > 2147483647 || generation === null) {
    fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Owned MCP retirement returned a mismatched target scope', 409);
  }
  return Object.freeze({ targetId: value.targetId.toLowerCase(), platformOwnerId,
    platformSessionId: value.platformSessionId, generation });
}
function uuidFrom(value) {
  const bytes = Buffer.from(crypto.createHash('sha256').update(value).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return `${bytes.toString('hex', 0, 4)}-${bytes.toString('hex', 4, 6)}-${bytes.toString('hex', 6, 8)}-${bytes.toString('hex', 8, 10)}-${bytes.toString('hex', 10, 16)}`;
}
function exactExecution(owner, execution) {
  const generation = normalizedGeneration(execution?.durableGeneration);
  if (!execution || execution.ownerKey !== JSON.stringify(['MCP', String(owner)])
      || typeof execution.runId !== 'string' || typeof execution.check !== 'function'
      || typeof execution.effect !== 'function' || generation === null) {
    fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A current durable MCP owner execution is required', 409);
  }
  return generation;
}
function bindingKey(scope) {
  return JSON.stringify([scope.platformOwnerId, scope.platformSessionId, scope.generation]);
}
function sameScope(left, right) {
  return left?.targetId === right?.targetId && left?.platformOwnerId === right?.platformOwnerId
    && left?.platformSessionId === right?.platformSessionId && left?.generation === right?.generation;
}
function bindExecution(execution, identity) {
  if (typeof identity?.assertCurrent !== 'function') {
    fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A current durable platform session check is required', 409);
  }
  const check = async () => {
    await execution.check(); await identity.assertCurrent(); await execution.check();
  };
  return Object.freeze({ ...execution, check, effect: async (key, work) => {
    await check();
    return execution.effect(key, async () => {
      await check(); const value = await work(); await check(); return value;
    });
  } });
}

function createDisabledMcpOwnedResourceApplication() {
  return Object.freeze({ enabled: false, async admitChat() { return null; },
    qualification: createOwnedQualification(false), async readOnly() { return null; },
    async readiness() { return null; }, async reset() { return null; }, state() { return null; } });
}

// Candidate production boundary. The route does not construct these
// dependencies: startup may install this application only after the draft
// schema and the strict Linux runner have independently passed readiness.
function createMcpOwnedResourceApplication({ sessionResolver, readiness, repository, mailResources,
  targets, verifyMessageReadback, sandboxFactory = null, createToolDescriptions, protectedAdmission = null,
  authorizeTool = canExecuteOwnedTool,
  qualification = createOwnedQualification(true) } = {}) {
  if (!sessionResolver || typeof sessionResolver.resolveRequest !== 'function'
      || typeof readiness !== 'function' || !repository
      || !mailResources || typeof mailResources.send !== 'function' || typeof mailResources.cleanup !== 'function'
      || typeof mailResources.project !== 'function'
      || !targets || typeof targets.admit !== 'function' || typeof targets.retire !== 'function') {
    throw new TypeError('Complete MCP owned-resource dependencies are required');
  }
  const deliveryObserver = typeof mailResources.observeAccepted === 'function'
    ? deliveredMailObservation.createDeliveredMailObservation({ mailResources, verifyMessageReadback }) : null;
  const active = new Map();
  const retiring = new Map();
  const retiringOwners = new Set();
  const queues = new Map();
  async function locked(key, work) {
    const previous = queues.get(key) || Promise.resolve();
    let release; const tail = new Promise(resolve => { release = resolve; }); queues.set(key, tail);
    await previous;
    try { return await work(); }
    finally { release(); if (queues.get(key) === tail) queues.delete(key); }
  }
  const factory = sandboxFactory || createSandboxFactory({
    authorizeTool, createToolDescriptions,
    createRunner: context => Object.freeze({
      exec: (...args) => context.runner.exec(...args),
      ...Object.fromEntries(['listOwnedImportedTools', 'registerOwnedServer', 'invokeOwnedImportedTool']
        .filter(name => typeof context.runner[name] === 'function')
        .map(name => [name, (...args) => context.runner[name](...args)])),
      ...(typeof context.runner.fetchOwnedUrl === 'function'
        ? { fetchOwnedUrl: (...args) => context.runner.fetchOwnedUrl(...args) } : {}),
      ...(typeof context.runner.readTicket === 'function'
        ? { readTicket: (...args) => context.runner.readTicket(...args) } : {}),
      ...(typeof context.runner.observeCommand === 'function'
        ? { observeCommand: (...args) => context.runner.observeCommand(...args) } : {}),
      ...(typeof context.runner.protectedOperation === 'function'
        ? { protectedOperation: (...args) => context.runner.protectedOperation(...args) } : {}),
      ...(typeof context.runner.installPackage === 'function'
        ? { installPackage: (...args) => context.runner.installPackage(...args) } : {}),
    }),
    createMailDelivery: context => async mail => {
      const invocation = protocol.requireProtocolContext(`mcp_${context.scope.platformOwnerId}`);
      const intentId = confusedDeputyObservation.intentIdFor(invocation.execution.runId, invocation.effectKey);
      const result = await mailResources.send({ ...mail, intentId, scope: context.scope, execution: invocation.execution });
      return confusedDeputyObservation.bindDelivery(result, { scope: context.scope, intentId,
        runId: invocation.execution.runId, effectKey: invocation.effectKey,
        to: mail.to, subject: mail.subject, body: mail.body,
        messageId: result.messageId });
    },
  });
  async function ready() {
    const result = await readiness();
    const {baseQualification,hasHttpQualification,HTTP_CAPABILITY,hasShadowQualification,SHADOW_CAPABILITY}=require('./ownedQualification');
    const requiredVersion=baseQualification(qualification)?.version;
    if ((hasShadowQualification(qualification) && (result?.shadowCapability !== SHADOW_CAPABILITY
          || result?.shadowObjectiveQualified !== true))
        || (hasHttpQualification(qualification) && result?.httpCapability !== HTTP_CAPABILITY)
        || result?.ready !== true || result.runnerReady !== true || result.repositoryReady !== true
        || result.runnerIsolation !== 'bwrap-seccomp-v1'
        || ([PROTECTED_QUALIFICATION_VERSION, OBSERVED_ACTION_QUALIFICATION_VERSION,
          SUPPLY_CHAIN_QUALIFICATION_VERSION, INDIRECT_INJECTION_QUALIFICATION_VERSION,
          PROTECTED_CATALOG_QUALIFICATION_VERSION,
          OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
          SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION].includes(requiredVersion)
          && result.protectedStateCapability !== PROTECTED_STATE_CAPABILITY)
        || ([OBSERVED_ACTION_QUALIFICATION_VERSION, SUPPLY_CHAIN_QUALIFICATION_VERSION,
          INDIRECT_INJECTION_QUALIFICATION_VERSION,
          OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
          SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION].includes(requiredVersion)
          && result.observedActionCapability !== OBSERVED_ACTION_CAPABILITY)
        || ([SUPPLY_CHAIN_QUALIFICATION_VERSION, SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION].includes(requiredVersion)
          && result.packageInstallCapability !== PACKAGE_INSTALL_CAPABILITY)
        || ([INDIRECT_INJECTION_QUALIFICATION_VERSION,
          INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION].includes(requiredVersion)
          && result.ticketReadCapability !== TICKET_READ_CAPABILITY)
        || ([CATALOG_QUALIFICATION_VERSION, PROTECTED_CATALOG_QUALIFICATION_VERSION,
          OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
          SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
          INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION].includes(requiredVersion)
          && result.catalogObservationCapability !== CATALOG_OBSERVATION_CAPABILITY)) {
      fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'Owned MCP resources are not ready');
    }
    return result;
  }
  async function requestScope(request, execution) {
    await ready();
    const identity = await sessionResolver.resolveRequest(request);
    const generation = exactExecution(identity.platformOwnerId, execution);
    return { identity, generation };
  }
  async function retireOwnedResources({ platformOwnerId: rawOwnerId, check }) {
    const platformOwnerId = retirementOwner(rawOwnerId);
    if (typeof check !== 'function') {
      fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A current MCP retirement authority check is required', 409);
    }
    const ownerKey = `mcp_${platformOwnerId}`;
    return locked(ownerKey, async () => {
      await check();
      const contexts = [...new Map([...retiring, ...active]).entries()]
        .filter(([,context]) => context.scope.platformOwnerId === platformOwnerId);
      const contextScopes = contexts.map(([,context]) => retirementScope(context.scope, platformOwnerId));
      await check();
      const durable = await repository.listRunnerTargetsForOwner({ platformOwnerId });
      await check();
      if (!Array.isArray(durable)) {
        fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Owned MCP retirement target inventory is invalid', 409);
      }
      const scopes = durable.map(item => retirementScope(item, platformOwnerId));
      const byTarget = new Map();
      for (const scope of [...scopes, ...contextScopes]) {
        const previous = byTarget.get(scope.targetId);
        if (previous && !sameScope(previous, scope)) {
          fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Owned MCP retirement target inventory conflicts', 409);
        }
        byTarget.set(scope.targetId, scope);
      }
      await check();
      retiringOwners.add(ownerKey);
      for (const [key, context] of contexts) {
        active.delete(key); context.retired = true; retiring.set(key, context);
      }
      for (const [,context] of contexts) {
        await check();
        const protocolRetirement = await context.protocol.retireSession(ownerKey);
        await check();
        if (protocolRetirement?.ok !== true) {
          fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'MCP protocol retirement is incomplete');
        }
      }
      const receipts = [];
      for (const scope of byTarget.values()) {
        const operationId = uuidFrom(`mcp-runner-retirement:${scope.targetId}`);
        await check();
        await repository.beginRunnerRetirement({ ...scope, operationId });
        await check();
        await targets.retire({ scope, operationId });
        await check();
        const mailReceipt = await mailResources.cleanup({ scope, operationId });
        await check();
        const runnerReceipt = await targets.readRetirement({ scope, operationId });
        await check();
        await repository.completeRunnerRetirement({ ...scope, operationId, receipt: runnerReceipt });
        await check();
        receipts.push(Object.freeze({ scope, operationId, mailReceipt, runnerReceipt }));
      }
      for (const [key] of contexts) { retiring.delete(key); factory.retire(key); }
      retiringOwners.delete(ownerKey);
      await check();
      return Object.freeze({ ok: true, receipts: Object.freeze(receipts) });
    });
  }
  return Object.freeze({
    enabled: true,
    qualification,
    readiness: ready,
    async admitChat(request, execution) {
      const { identity, generation } = await requestScope(request, execution);
      const ownerKey = `mcp_${identity.platformOwnerId}`;
      const key = bindingKey({ ...identity, generation });
      const currentExecution = bindExecution(execution, identity);
      return locked(ownerKey, async () => {
        if (retiringOwners.has(ownerKey) || retiring.has(key)) fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'MCP resource retirement is incomplete');
        await currentExecution.check();
        const previous = active.get(key);
        let scope = await repository.readActiveRunnerTarget({ ...identity, generation });
        if (!scope) {
          if (previous) fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Durable MCP resource binding disappeared', 409);
          const outstanding = await repository.listRunnerTargetsForOwner({ platformOwnerId: identity.platformOwnerId });
          if (outstanding.some(item => item.state === 'retiring')) {
            retiringOwners.add(ownerKey);
            fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'MCP resource retirement is incomplete');
          }
          if (outstanding.some(item => item.platformSessionId === identity.platformSessionId && item.generation === generation)) {
            fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'MCP resource retirement is incomplete');
          }
          scope = { targetId: crypto.randomUUID(), ...identity, generation };
          await repository.reserveRunnerTarget(scope);
        }
        if (previous && !sameScope(previous.scope, scope)) {
          fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Durable MCP resource binding changed', 409);
        }
        const admitted = await targets.admit({ scope, execution: currentExecution,
          ...(protectedAdmission ? {withProtectedOperation:protectedAdmission.forExecution(scope,currentExecution)} : {}) });
        const admittedScope = admitted?.scope;
        if (!admittedScope || admittedScope.targetId !== scope.targetId
            || admittedScope.platformOwnerId !== identity.platformOwnerId
            || admittedScope.platformSessionId !== identity.platformSessionId || admittedScope.generation !== generation
            || !admitted.runner || typeof admitted.runner.exec !== 'function') {
          fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Runner admission returned a mismatched binding', 409);
        }
        await currentExecution.check();
        const context = previous || { scope: Object.freeze({ ...scope }), execution: currentExecution,
          runner: admitted.runner, retired: false };
        context.execution = currentExecution;
        context.runner = admitted.runner;
        if (!context.sandbox) context.sandbox = factory.getOrCreate(key, context, ownerKey);
        for (const receipt of admitted.packageInstalls || []) {
          if (receipt?.targetId !== context.scope.targetId
              || receipt?.platformOwnerId !== context.scope.platformOwnerId
              || receipt?.platformSessionId !== context.scope.platformSessionId
              || receipt?.generation !== context.scope.generation
              || typeof context.sandbox.restoreInstalledPackage !== 'function'
              || context.sandbox.restoreInstalledPackage(receipt) !== true) {
            fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Owned package inventory returned an invalid binding', 409);
          }
        }
        if (!context.protocol) context.protocol = createMcpProtocolSessionManager({ catalogScope: context.scope,
          createServer: async sessionId => {
          if (context.retired || active.get(key) !== context || sessionId !== ownerKey) {
            fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
          }
          return createMcpServer(sessionId, { sandbox: context.sandbox });
        } });
        active.set(key, context);
        return Object.freeze({ sandbox: context.sandbox, scope: context.scope, protocol: context.protocol,
          execution: currentExecution, state: () => factory.state(key),
          readShadowSource: async () => {
            await currentExecution.check();
            if (context.retired || active.get(key) !== context || typeof context.runner.readOwnedShadowSource !== 'function') {
              fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'Owned shadow source is unavailable');
            }
            const value = await context.runner.readOwnedShadowSource();
            await currentExecution.check();
            if (context.retired || active.get(key) !== context) {
              fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
            }
            return value;
          },
          writeShadowSource: async value => {
            await currentExecution.check();
            if (context.retired || active.get(key) !== context || typeof context.runner.writeOwnedShadowSource !== 'function') {
              fail('MCP_OWNED_RESOURCES_UNAVAILABLE', 'Owned shadow source is unavailable');
            }
            const receipt = await currentExecution.effect(`shadow_source_${value.operationId}`,
              () => {
                if (context.retired || active.get(key) !== context) {
                  fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
                }
                return context.runner.writeOwnedShadowSource(value);
              });
            await currentExecution.check();
            if (context.retired || active.get(key) !== context) {
              fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
            }
            return receipt;
          },
          observeObjective: async ({ objectiveId, result }) => {
            if (objectiveId === 'mcp_ssrf') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = require('./ownedHttpToolAdapter').witnessFor(result,
                { scope: context.scope, execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ ownedHttpWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_shadow_server') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = require('./ownedShadowToolAdapter').witnessFor(result,
                { scope: context.scope, execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ ownedShadowWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_cmd_injection') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = commandObservation.witnessFor(result,
                { scope: context.scope, execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ commandObservationWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_recon') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = catalogObservation.witnessFor({ result, scope: context.scope,
                execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ catalogWitness: witness }) : Object.freeze({});
            }
            if (['mcp_secret_exposure', 'mcp_broken_authz', 'mcp_audit_gap'].includes(objectiveId)) {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = protectedStateObservation.witnessFor({ objectiveId, result, scope: context.scope,
                execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ protectedStateWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_tool_poisoning') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = observedActionObservation.witnessFor({ result, scope: context.scope,
                execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ observedActionWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_supply_chain') {
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = supplyChainObservation.witnessFor({ result, scope: context.scope,
                execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              return witness ? Object.freeze({ supplyChainWitness: witness }) : Object.freeze({});
            }
            if (objectiveId === 'mcp_indirect_injection') {
              const observation = confusedDeputyObservation.readIndirectTool(result);
              if (!observation || observation.runId !== currentExecution.runId
                  || !sameScope(observation.scope, context.scope) || !deliveryObserver) return Object.freeze({});
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const delivered = await deliveryObserver.observe({ ...observation, execution: currentExecution });
              await currentExecution.check();
              if (context.retired || active.get(key) !== context) {
                fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
              }
              const witness = indirectInjectionObservation.witnessFor({ result, scope: context.scope,
                execution: currentExecution, deliveredMail: delivered });
              return witness ? Object.freeze({ indirectInjectionWitness: witness }) : Object.freeze({});
            }
            if (objectiveId !== 'mcp_confused_deputy') return Object.freeze({});
            const observation = confusedDeputyObservation.readTool(result);
            if (!observation || observation.runId !== currentExecution.runId
                || !sameScope(observation.scope, context.scope)) return Object.freeze({});
            await currentExecution.check();
            if (context.retired || active.get(key) !== context) {
              fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
            }
            if (!deliveryObserver) return Object.freeze({});
            const delivered = await deliveryObserver.observe({ ...observation, execution: currentExecution });
            await currentExecution.check();
            if (context.retired || active.get(key) !== context) {
              fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
            }
            return delivered ? Object.freeze({
              confusedDeputyWitness: deliveredMailObservation.acceptedWitnessFor(delivered),
              deliveredMailObservation: delivered,
            }) : Object.freeze({});
          } });
      });
    },
    async readOnly(request) {
      const readinessReceipt = await ready();
      const identity = await sessionResolver.resolveRequest(request);
      const matches = [...active.values()].filter(context => context.scope.platformOwnerId === identity.platformOwnerId
        && context.scope.platformSessionId === identity.platformSessionId && !context.retired);
      if (matches.length !== 1) {
        fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
      }
      await identity.assertCurrent?.();
      const context = matches[0];
      const key = bindingKey(context.scope);
      const assertActive = () => {
        if (context.retired || active.get(key) !== context) {
          fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'Current MCP resource binding is unavailable', 409);
        }
      };
      assertActive();
      return Object.freeze({ protocol: context.protocol, sandbox: context.sandbox,
        state: () => factory.state(key), ownerId: identity.platformOwnerId,
        realExecution: Object.freeze({ available: true, isolation: readinessReceipt.runnerIsolation, bwrap: true }),
        async mailProjection() {
          await identity.assertCurrent();
          assertActive();
          const ids = []; const seen = new Set();
          for (let index = context.sandbox.sentReports.length - 1; index >= 0 && ids.length < 20; index -= 1) {
            const report = context.sandbox.sentReports[index]; const messageId = report?.messageId;
            if (report?.delivered === true && typeof messageId === 'string' && !seen.has(messageId)) {
              seen.add(messageId); ids.push(messageId);
            }
          }
          const projection = await mailResources.project({ scope: context.scope, messageIds: ids });
          await identity.assertCurrent();
          assertActive();
          return projection;
        } });
    },
    async retireOwner({ platformOwnerId, check } = {}) {
      retirementOwner(platformOwnerId);
      if (typeof check !== 'function') {
        fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A current MCP retirement authority check is required', 409);
      }
      await check();
      await ready();
      await check();
      return retireOwnedResources({ platformOwnerId, check });
    },
    async reset(request, { check: outerCheck } = {}) {
      if (outerCheck !== undefined && typeof outerCheck !== 'function') {
        fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A valid outer MCP reset authority check is required', 409);
      }
      const checkOuter = outerCheck || (async () => {});
      await checkOuter();
      await ready();
      await checkOuter();
      const identity = await sessionResolver.resolveRequest(request);
      await checkOuter();
      if (typeof identity?.assertCurrent !== 'function') {
        fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'A current platform session check is required', 409);
      }
      const platformOwnerId = retirementOwner(identity.platformOwnerId);
      const check = async () => {
        await checkOuter();
        await identity.assertCurrent();
        await checkOuter();
      };
      await check();
      return retireOwnedResources({ platformOwnerId, check });
    },
    state(ownerId) {
      const matches = [...active.entries()].filter(([,context]) => context.scope.platformOwnerId === Number(ownerId));
      if (matches.length !== 1) fail('MCP_OWNED_RESOURCE_SCOPE_INVALID', 'An exact MCP session binding is required', 409);
      return factory.state(matches[0][0]);
    },
  });
}

module.exports = { createMcpOwnedResourceApplication, createDisabledMcpOwnedResourceApplication,
  _internals: { uuidFrom, exactExecution, normalizedGeneration, retirementOwner, retirementScope,
    bindingKey, bindExecution, sameScope } };
