'use strict';

/** Build a real MCP server from the workshop's single canonical registry. */
const mcpSandbox = require('../sandboxShell');
const registry = require('../toolRegistry');
const protocol = require('../protocolContext');
const confusedDeputyObservation = require('../confusedDeputyObservation');
const indirectInjectionObservation = require('../indirectInjectionObservation');
const commandObservation = require('../commandObservation');
const protectedStateObservation = require('../protectedStateObservation');
const observedActionObservation = require('../observedActionObservation');
const supplyChainObservation = require('../supplyChainObservation');

let sdk;
async function loadSdk() {
  if (!sdk) {
    const [{ Server }, types] = await Promise.all([
      import('@modelcontextprotocol/sdk/server/index.js'),
      import('@modelcontextprotocol/sdk/types.js'),
    ]);
    sdk = { Server, ...types };
  }
  return sdk;
}

function toolResponse(result) {
  const text = result?.error || result?.output || '(no output)';
  return { content: [{ type: 'text', text: String(text) }], isError: Boolean(result?.blocked || result?.error) };
}

async function createMcpServer(sessionId, { sandbox = mcpSandbox.getOrCreateSandbox(sessionId) } = {}) {
  const { Server, ListToolsRequestSchema, CallToolRequestSchema,
    ListResourcesRequestSchema, ReadResourceRequestSchema } = await loadSdk();
  const server = new Server({ name: 'acme-ops-mcp', version: '1.3.0' }, {
    capabilities: { tools: { listChanged: true }, resources: { listChanged: false } },
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    protocol.requireProtocolContext(sessionId);
    return { tools: await registry.catalogForAsync(sandbox) };
  });
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const state = protocol.requireProtocolContext(sessionId);
    const name = String(request.params?.name || '');
    const args = registry.validateArguments(name, request.params?.arguments || {},await registry.catalogForAsync(sandbox));
    await state.execution.check();
    state.validatedProtectedTool=Object.freeze({name,argsSha256:protocol.canonicalDigest(args)});
    const perform = async () => {
      await state.execution.check();
      const value = await registry.performTool(sandbox, name, args, {
        purpose: state.purpose, observation: state.observation,
        checkOwner: () => state.execution.check(),
      });
      await state.execution.check();
      const normalized = { tool: name, args: { ...args }, ...value };
      confusedDeputyObservation.adoptTool(value, normalized);
      indirectInjectionObservation.adoptTool(value, normalized);
      commandObservation.adoptTool(value, normalized);
      require('../ownedHttpToolAdapter').adoptTool(value, normalized);
      require('../ownedShadowToolAdapter').adoptTool(value,normalized);
      protectedStateObservation.adoptTool(value, normalized);
      supplyChainObservation.adoptTool(value, normalized);
      return observedActionObservation.bindTool(observedActionObservation.adoptTool(value, normalized),
        { state, tool: name, args });
    };
    let result;
    try { result = await state.execution.effect(state.effectKey, perform); }
    catch (error) {
      if (require('../ownedTargetClient').isProtectedOperationUncertain(error)) state.protectedOperationFailure = error;
      throw error;
    }
    await state.execution.check();
    protocol.bindResult(state, name, args, result);
    return toolResponse(result);
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    protocol.requireProtocolContext(sessionId);
    return { resources: [
    { name: 'server-readme', uri: 'mcp://acme-ops/readme', mimeType: 'text/plain', description: 'Server documentation' },
    { name: 'allowlist-policy', uri: 'mcp://acme-ops/policy/allowlist', mimeType: 'text/plain', description: 'Command allowlist security policy' },
    ] };
  });
  server.setRequestHandler(ReadResourceRequestSchema, async request => {
    protocol.requireProtocolContext(sessionId);
    const uri = String(request.params?.uri || '');
    if (uri.includes('readme')) {
      const tools = await registry.catalogForAsync(sandbox);
      const lines = tools.map(tool => `- ${tool.name}: ${tool.description.split('\n')[0]}`).join('\n');
      return { contents: [{ uri, mimeType: 'text/plain', text: `ACME Ops MCP Server v1.3.0\n\nAvailable tools (${tools.length}):\n${lines}\n` }] };
    }
    if (uri.includes('allowlist')) {
      return { contents: [{ uri, mimeType: 'text/plain', text: `Command Allowlist Policy\n\nPermitted first tokens: ${[...mcpSandbox.ADVERTISED_ALLOWLIST].join(', ')}\nValidation: first-token extraction only\nKnown limitation: chained commands (; && |) are not re-validated.\n` }] };
    }
    return { contents: [] };
  });

  return { server, sandbox };
}

module.exports = { createMcpServer, _internals: { toolResponse, loadSdk } };
