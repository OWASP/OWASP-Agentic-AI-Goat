'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createMcpTargetStore, CONTROLLED_TICKET_IDS } = require('./mcpTargets');

const VERSION = 'mcp-owned-target-http.v1';
const PROTECTED_READBACK_CAPABILITY='mcp-owned-protected-readback.v1';
const PROTECTED_JOURNAL_CAPABILITY='mcp-owned-protected-operation-journal.v1';
const PROTECTED_STATE_CAPABILITY = 'mcp-owned-protected-state-transition.v2';
const OBSERVED_ACTION_CAPABILITY = 'mcp-owned-observed-action.v1';
const PACKAGE_INSTALL_CAPABILITY = 'mcp-owned-package-install.v1';
const TICKET_READ_CAPABILITY = 'mcp-owned-ticket-read.v2';
const CONTROLLED_TICKET_ID_SET = new Set(CONTROLLED_TICKET_IDS);
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;

function timingSafeToken(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(actual); const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function scope(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'generation,platformOwnerId,platformSessionId,targetId') {
    const error = new Error('Exact owned target scope is required'); error.code = 'TARGET_SCOPE_INVALID'; throw error;
  }
  return { targetId: value.targetId, ownerId: value.platformOwnerId,
    platformSessionId: value.platformSessionId, generation: value.generation };
}

function publicScope(value) {
  return Object.freeze({ targetId: value.targetId, platformOwnerId: value.ownerId,
    platformSessionId: value.platformSessionId, generation: value.generation });
}

function exactBody(body, fields) {
  if (!body || Object.getPrototypeOf(body) !== Object.prototype
      || Object.keys(body).sort().join(',') !== [...fields].sort().join(',')) {
    const error = new Error('Owned target request fields are invalid'); error.code = 'TARGET_REQUEST_INVALID'; throw error;
  }
  return body;
}

function createOwnedTargetApi({ token, store, expectedSupervisorProfile,
  readSupervisorProfile = async () => (await fs.readFile('/proc/self/attr/current', 'utf8')).trim() } = {}) {
  if (!TOKEN.test(token || '') || !store || typeof store.provisionTarget !== 'function'
      || typeof store.recoverTarget !== 'function' || typeof store.executeTarget !== 'function'
      || typeof store.executeProtectedOperation !== 'function'
      || typeof store.readTicket !== 'function'
      || typeof store.installPackage !== 'function'
      || typeof store.listInstalledPackages !== 'function'
      || typeof store.retireTarget !== 'function' || typeof store.readRetirementReceipt !== 'function'
      || typeof store.checkReadiness !== 'function' || typeof expectedSupervisorProfile !== 'string'
      || !/^dvaia-mcp-sandbox(?:-[a-f0-9]{12})?$/.test(expectedSupervisorProfile)) {
    throw new TypeError('Strict owned target API configuration is required');
  }
  const authorize = async () => true;
  async function readiness() {
    const current = await readSupervisorProfile();
    if (current !== `${expectedSupervisorProfile} (enforce)`) {
      const error = new Error('Owned target supervisor AppArmor profile is unavailable');
      error.code = 'TARGET_PROFILE_UNAVAILABLE'; throw error;
    }
    await store.checkReadiness();
    return Object.freeze({ ready: true, version: VERSION, isolation: 'bwrap-seccomp-v1',
      supervisorProfile: current, protectedStateCapability: PROTECTED_STATE_CAPABILITY,
      observedActionCapability: OBSERVED_ACTION_CAPABILITY,
      packageInstallCapability: PACKAGE_INSTALL_CAPABILITY,
      ticketReadCapability: TICKET_READ_CAPABILITY,
      ...(typeof store.executeProtectedJournal==='function' && typeof store.readProtectedReceipt==='function' ? {protectedJournalCapability:PROTECTED_JOURNAL_CAPABILITY,protectedReadbackCapability:PROTECTED_READBACK_CAPABILITY}: {}) });
  }
  async function recover(input) {
    const admitted=await store.recoverTarget(scope(exactBody(input,['scope']).scope),{authorize});
    return Object.freeze({version:VERSION,scope:publicScope(admitted.binding),capability:admitted.capability});
  }
  async function admit(input) {
    const requested = scope(exactBody(input, ['scope']).scope);
    let admitted;
    try { admitted = await store.recoverTarget(requested, { authorize }); }
    catch (error) {
      if (error.code !== 'TARGET_INCOMPLETE') throw error;
      try { admitted = await store.provisionTarget(requested, { authorize }); }
      catch (provisionError) {
        if (provisionError.code !== 'TARGET_ALREADY_EXISTS') throw provisionError;
        admitted = await store.recoverTarget(requested, { authorize });
      }
    }
    return Object.freeze({ version: VERSION, scope: publicScope(admitted.binding), capability: admitted.capability });
  }
  async function execute(input) {
    exactBody(input, ['capability', 'command']);
    const result = await store.executeTarget(input.capability, authorize, input.command);
    return Object.freeze({ version: VERSION, ok: true, exitCode: result.code,
      stdout: result.stdout, stderr: result.stderr, isolation: 'bwrap-seccomp-v1', timedOut: false, truncated: false });
  }
  async function observeCommand(input) {
    exactBody(input, ['capability', 'command', 'runId', 'operationId']);
    if (typeof store.observeCommand !== 'function') { const error = new Error('Command observation unavailable');error.code='COMMAND_OBSERVATION_UNAVAILABLE';throw error; }
    return store.observeCommand(input.capability, authorize, {command:input.command,runId:input.runId,operationId:input.operationId});
  }
  async function executeProtected(input) {
    if(input && Object.hasOwn(input,'operationId')){
      exactBody(input,['arguments','capability','operation','operationId','runId']);
      if(typeof store.executeProtectedJournal!=='function')throw Object.assign(Error('Protected journal unavailable'),{code:'PROTECTED_JOURNAL_UNAVAILABLE'});
      const {capability,...request}=input;return store.executeProtectedJournal(capability,authorize,request);
    }
    exactBody(input, ['arguments', 'capability', 'operation', 'runId']);
    return store.executeProtectedOperation(input.capability, authorize, {
      operation: input.operation, arguments: input.arguments, runId: input.runId,
    });
  }
  async function readProtectedReceipt(input){
    exactBody(input,['arguments','capability','operation','operationId','runId']);
    if(typeof store.readProtectedReceipt!=='function')throw Object.assign(Error('Protected journal unavailable'),{code:'PROTECTED_JOURNAL_UNAVAILABLE'});
    const {capability,...request}=input;return store.readProtectedReceipt(capability,authorize,request);
  }
  async function installPackage(input) {
    exactBody(input, ['capability', 'operationId', 'runId', 'source']);
    return store.installPackage(input.capability, authorize, {
      operationId: input.operationId, runId: input.runId, source: input.source,
    });
  }
  async function listPackages(input) {
    exactBody(input, ['capability']);
    return Object.freeze({ version: VERSION,
      packages: await store.listInstalledPackages(input.capability, authorize) });
  }
  async function readTicket(input) {
    exactBody(input, ['capability', 'operationId', 'runId', 'ticketId']);
    if (typeof input.ticketId !== 'string' || !CONTROLLED_TICKET_ID_SET.has(input.ticketId)) {
      const error = new Error('Controlled ticket id is unavailable'); error.code = 'TARGET_REQUEST_INVALID'; throw error;
    }
    return store.readTicket(input.capability, authorize, {
      operationId: input.operationId, runId: input.runId, ticketId: input.ticketId,
    });
  }
  async function retire(input) {
    exactBody(input, ['operationId', 'scope']);
    return store.retireTarget(scope(input.scope), { operationId: input.operationId, authorize });
  }
  async function readRetirement(input) {
    exactBody(input, ['operationId', 'scope']);
    return store.readRetirementReceipt(scope(input.scope), { operationId: input.operationId, authorize });
  }
  async function handle(request) {
    if (!timingSafeToken(request?.token, token)) return { status: 404, body: { error: 'not found' } };
    try {
      if (request.method === 'GET' && request.path === '/owned-targets/health') {
        return { status: 200, body: await readiness() };
      }
      if (request.method !== 'POST') return { status: 404, body: { error: 'not found' } };
      const handlers = { '/owned-targets/admit': admit, '/owned-targets/recover': recover, '/owned-targets/exec': execute, '/owned-targets/command-observation': observeCommand,
        '/owned-targets/protected-operation': executeProtected,
        '/owned-targets/protected-receipt': readProtectedReceipt,
        '/owned-targets/package-install': installPackage,
        '/owned-targets/package-installs': listPackages,
        '/owned-targets/ticket-read': readTicket,
        '/owned-targets/retire': retire, '/owned-targets/retirement': readRetirement };
      if (!handlers[request.path]) return { status: 404, body: { error: 'not found' } };
      return { status: 200, body: await handlers[request.path](request.body) };
    } catch (error) {
      return { status: error.code === 'TARGET_LOCKED' ? 409 : 503,
        body: { error: error.code || 'TARGET_UNAVAILABLE', message: error.message } };
    }
  }
  return Object.freeze({ handle, readiness });
}

function createOwnedTargetApiFromEnvironment(env = process.env) {
  if (env.MCP_OWNED_TARGETS_ENABLED !== 'true') return null;
  return createOwnedTargetApi({ token: env.MCP_OWNED_TARGET_TOKEN,
    expectedSupervisorProfile: env.MCP_OWNED_TARGET_APPARMOR_PROFILE,
    store: createMcpTargetStore({ root: env.MCP_OWNED_TARGET_ROOT || '/sandbox/owned-targets',
      fixtureRoot: env.MCP_OWNED_TARGET_FIXTURES || '/opt/lab-template' }) });
}

module.exports = { createOwnedTargetApi, createOwnedTargetApiFromEnvironment, VERSION, PACKAGE_INSTALL_CAPABILITY,
  TICKET_READ_CAPABILITY,
  _internals: { timingSafeToken, scope, publicScope, exactBody } };
