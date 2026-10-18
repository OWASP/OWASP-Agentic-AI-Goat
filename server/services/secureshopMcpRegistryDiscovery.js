'use strict';
const { mcpSchemaDigest } = require('./secureshopMcpSchemaDigest');
const LIMITS = Object.freeze({ tools:64, schemaBytes:65536, pages:8, timeoutMs:10000 });
function freezeSnapshot(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freezeSnapshot(item);
    Object.freeze(value);
  }
  return value;
}
const invalid = message => { throw Object.assign(new Error(message), { code:'MCP_DISCOVERY_INVALID' }); };

// The caller owns a connected SDK client and its isolated transport lifecycle.
// This primitive neither resolves a learner URL nor spawns a learner command.
async function discoverRegistryTools(client, { signal } = {}) {
  if (typeof client?.listTools !== 'function') throw new TypeError('Connected MCP client required');
  const started = performance.now(), tools = [], names = new Set(), cursors = new Set();
  let cursor;
  for (let page = 0; page < LIMITS.pages; page++) {
    signal?.throwIfAborted();
    const remaining = Math.floor(LIMITS.timeoutMs - (performance.now() - started));
    if (remaining <= 0) invalid('MCP discovery deadline exceeded');
    const response = await client.listTools(cursor === undefined ? undefined : { cursor },
      { signal, timeout:remaining, maxTotalTimeout:remaining, resetTimeoutOnProgress:false });
    signal?.throwIfAborted();
    if (!response || !Array.isArray(response.tools)) invalid('MCP discovery returned no tool list');
    for (const tool of response.tools) {
      if (!tool || typeof tool.name !== 'string' || !tool.name.trim() || Buffer.byteLength(tool.name) > 256
          || names.has(tool.name) || !tool.inputSchema || tool.inputSchema.type !== 'object'
          || (tool.description !== undefined && typeof tool.description !== 'string')) invalid('MCP discovery returned invalid or duplicate tools');
      names.add(tool.name); tools.push(tool);
      if (tools.length > LIMITS.tools) invalid('MCP discovery tool limit exceeded');
    }
    if (Buffer.byteLength(JSON.stringify(tools), 'utf8') > LIMITS.schemaBytes) invalid('MCP discovery schema limit exceeded');
    if (response.nextCursor === undefined) {
      // Snapshot protocol data: later server rotations cannot mutate this result.
      const snapshot = freezeSnapshot(JSON.parse(JSON.stringify(tools)));
      return Object.freeze({ tools:snapshot, schemaSha256:mcpSchemaDigest(snapshot), pages:page + 1 });
    }
    if (typeof response.nextCursor !== 'string' || !response.nextCursor || Buffer.byteLength(response.nextCursor) > 2048
        || cursors.has(response.nextCursor)) invalid('MCP discovery cursor is invalid or repeated');
    cursors.add(response.nextCursor); cursor = response.nextCursor;
  }
  invalid('MCP discovery page limit exceeded');
}
module.exports = { discoverRegistryTools, MCP_REGISTRY_DISCOVERY_LIMITS:LIMITS };
