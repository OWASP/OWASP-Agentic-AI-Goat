'use strict';

const { createMcpServer } = require('./vulnerableMcpServer');
const protocol = require('../protocolContext');
const catalogObservation = require('../catalogObservation');

let sdk;
async function loadSdk() {
  if (!sdk) {
    const [{ Client }, { InMemoryTransport }, { StreamableHTTPServerTransport }] = await Promise.all([
      import('@modelcontextprotocol/sdk/client/index.js'),
      import('@modelcontextprotocol/sdk/inMemory.js'),
      import('@modelcontextprotocol/sdk/server/streamableHttp.js'),
    ]);
    sdk = { Client, InMemoryTransport, StreamableHTTPServerTransport };
  }
  return sdk;
}

function managerError(code, message) { return Object.assign(new Error(message), { code }); }
function generationKey(sessionId, execution) {
  protocol._internals.validateExecution(sessionId, execution);
  return `${sessionId}@${protocol._internals.normalizeGeneration(execution)}`;
}

function createMcpProtocolSessionManager({ createServer = createMcpServer, catalogScope = null } = {}) {
  const internal = new Map();
  const external = new Map();
  const externalCurrent = new Map();
  const retirementDebt = new Map();

  async function once(map, sessionId, factory) {
    const existing = map.get(sessionId);
    if (existing) return existing;
    const pending = Promise.resolve().then(factory).catch(error => { map.delete(sessionId); throw error; });
    map.set(sessionId, pending);
    return pending;
  }

  async function getOrCreateInternalSession(sessionId, execution) {
    if (retirementDebt.has(sessionId)) throw managerError('MCP_PROTOCOL_RETIREMENT_INCOMPLETE', 'MCP protocol session retirement is incomplete');
    const key = generationKey(sessionId, execution);
    return once(internal, key, async () => {
      const { Client, InMemoryTransport } = await loadSdk();
      const { server, sandbox } = await createServer(sessionId);
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'owasp-ai-goat-mcp-workshop-agent', version: '1.0.0' });
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      return { sessionId, server, sandbox, client, clientTransport, serverTransport, retired: false };
    });
  }

  async function getOrCreateSession(sessionId, execution) {
    if (retirementDebt.has(sessionId)) throw managerError('MCP_PROTOCOL_RETIREMENT_INCOMPLETE', 'MCP protocol session retirement is incomplete');
    const key = generationKey(sessionId, execution);
    return once(external, key, async () => {
      const { StreamableHTTPServerTransport } = await loadSdk();
      const { server, sandbox } = await createServer(sessionId);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => sessionId,
        onsessioninitialized: () => {}, enableJsonResponse: true });
      await server.connect(transport);
      const prior = externalCurrent.get(sessionId);
      const generation = protocol._internals.normalizeGeneration(execution);
      // Retirement may have removed this pending factory from the map while
      // connect was in flight. Never republish that retired generation.
      if (!retirementDebt.has(sessionId) && external.has(key)
          && (!prior || BigInt(generation) >= BigInt(prior.generation))) {
        externalCurrent.set(sessionId, { key, generation });
      }
      return { sessionId, server, sandbox, transport, retired: false };
    });
  }

  async function assertActive(entryPromise) {
    const entry = await entryPromise;
    if (entry.retired) throw managerError('MCP_PROTOCOL_SESSION_RETIRED', 'MCP protocol session is retired');
    return entry;
  }

  async function listTools(sessionId, { execution, surface = 'chat', actor } = {}) {
    const entry = await assertActive(getOrCreateInternalSession(sessionId, execution));
    const invoked = await protocol.withProtocolInvocation({ sessionId, execution, surface, actor }, async () => {
      const before = protocol.requireProtocolContext(sessionId);
      const value = await entry.client.listTools();
      const after = protocol.requireProtocolContext(sessionId);
      if (before !== after) throw Object.assign(new Error('MCP protocol invocation changed during tools/list'),
        { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
      return surface === 'chat' ? { ...value,
        tools: catalogObservation.captureSdkCatalog(value?.tools || [], sessionId, catalogScope) } : value;
    });
    if (entry.retired) throw managerError('MCP_PROTOCOL_SESSION_RETIRED', 'MCP protocol session is retired');
    return invoked.value.tools || [];
  }

  async function callTool(sessionId, name, args, { execution, surface = 'chat', purpose = null,
    observation = null, effectKey, actor } = {}) {
    const entry = await assertActive(getOrCreateInternalSession(sessionId, execution));
    const invoked = await protocol.withProtocolInvocation({ sessionId, execution, surface, purpose,
      observation, effectKey, actor }, () => entry.client.callTool({ name, arguments: args }));
    if (entry.retired) throw managerError('MCP_PROTOCOL_SESSION_RETIRED', 'MCP protocol session is retired');
    if (!invoked.toolResult || !invoked.receipt) throw managerError('MCP_PROTOCOL_RESULT_MISSING', 'MCP tool result receipt is unavailable');
    return invoked.toolResult;
  }

  async function handleHttp(sessionId, req, res, { execution, actor } = {}) {
    const entry = await assertActive(getOrCreateSession(sessionId, execution));
    const invoked = await protocol.withProtocolInvocation({ sessionId, execution, surface: 'streamable_http',
      effectKey: `mcp_http_${execution.runId}`, actor }, () => entry.transport.handleRequest(req, res, req.body));
    if (entry.retired) throw managerError('MCP_PROTOCOL_SESSION_RETIRED', 'MCP protocol session is retired');
    return invoked.value;
  }

  async function handleReadOnlyHttp(sessionId, req, res, { ownerId } = {}) {
    if (String(sessionId) !== `mcp_${String(ownerId)}`) throw managerError('MCP_PROTOCOL_OWNER_MISMATCH', 'MCP protocol owner mismatch');
    if (retirementDebt.has(sessionId)) throw managerError('MCP_PROTOCOL_RETIREMENT_INCOMPLETE', 'MCP protocol session retirement is incomplete');
    const current = externalCurrent.get(sessionId);
    if (!current) throw managerError('MCP_PROTOCOL_SESSION_REQUIRED', 'Initialize the MCP protocol session before opening its event stream');
    const pending = external.get(current.key);
    if (!pending) {
      externalCurrent.delete(sessionId);
      throw managerError('MCP_PROTOCOL_SESSION_REQUIRED', 'Initialize the MCP protocol session before opening its event stream');
    }
    const entry = await assertActive(pending);
    if (externalCurrent.get(sessionId)?.key !== current.key || entry.retired) {
      throw managerError('MCP_PROTOCOL_SESSION_RETIRED', 'MCP protocol session is retired');
    }
    return entry.transport.handleRequest(req, res);
  }

  function retireSession(sessionId) {
    const existing = retirementDebt.get(sessionId);
    if (existing?.operation) return existing.operation;
    const debt = existing || { entries: [], operation: null };
    // Publish the admission fence before awaiting a factory that may still be
    // connecting transports. No new generation can enter during cleanup.
    retirementDebt.set(sessionId, debt);
    externalCurrent.delete(sessionId);
    debt.operation = (async () => {
      try {
        const entries = [...debt.entries];
        for (const map of [internal, external]) {
          for (const [key, pending] of map) {
            if (!key.startsWith(`${sessionId}@`)) continue;
            map.delete(key);
            entries.push(await pending.catch(() => null));
          }
        }
        debt.entries = entries.filter(Boolean);
        for (const entry of debt.entries) entry.retired = true;
        if (externalCurrent.get(sessionId)
            && !external.has(externalCurrent.get(sessionId).key)) externalCurrent.delete(sessionId);
        const settled = await Promise.allSettled(debt.entries.flatMap(entry => [
          entry.client?.close?.(), entry.transport?.close?.(), entry.server?.close?.(),
        ].filter(Boolean)));
        const failed = settled.filter(item => item.status === 'rejected').length;
        if (failed) return { ok: false, retired: debt.entries.length, failed };
        if (retirementDebt.get(sessionId) === debt) retirementDebt.delete(sessionId);
        return { ok: true, retired: debt.entries.length };
      } finally { debt.operation = null; }
    })();
    return debt.operation;
  }

  return Object.freeze({ listTools, callTool, handleHttp, handleReadOnlyHttp,
    catalogObservationCapability: catalogObservation.CAPABILITY,
    retireSession, _sizes: () => ({ internal: internal.size, external: external.size }) });
}

const singleton = createMcpProtocolSessionManager();
module.exports = { createMcpProtocolSessionManager,
  listTools: singleton.listTools,
  callTool: singleton.callTool,
  handleHttp: singleton.handleHttp,
  handleReadOnlyHttp: singleton.handleReadOnlyHttp,
  catalogObservationCapability: catalogObservation.CAPABILITY,
  retireSession: singleton.retireSession,
  _singleton: singleton,
};
