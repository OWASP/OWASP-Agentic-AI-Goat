const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const {
  list_servers, register, remove, describe_tools, import_manifest,
} = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'mcp-registry';

const TOOLS = [
  {
    name: 'list_servers',
    description: 'List every MCP server currently registered.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'register',
    description: 'Register a new MCP server. For SSE transport the server-side runtime fetches ${url}/mcp/list_tools to discover tools. Stdio commands require the separate owner-scoped isolated executor.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        url: { type: 'string' },
        transport: { type: 'string', enum: ['sse', 'stdio'] },
        stdio_cmd: { type: 'string' },
      },
      required: ['name'],
    },
  },
  {
    name: 'remove',
    description: 'Remove a registry entry and its cached tools by name.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
  },
  {
    name: 'describe_tools',
    description: 'Return the cached tool schemas for a registered server (verbatim descriptions).',
    inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
  },
  {
    name: 'import_manifest',
    description: 'Fetch an XML manifest and register every <server> declared in it.',
    inputSchema: { type: 'object', properties: { xml_url: { type: 'string' } }, required: ['xml_url'] },
  },
];

function _wrap(r) { return { content: [{ type: 'text', text: JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.2.0' },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params || {};
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — mcp-registry is admin-only. `list_servers` and
    // `describe_tools` are read-only but we still gate them so a jailbroken
    // customer supervisor can't enumerate the poisoned tool cache.
    // Preserves mcp01-tool-poisoning / mcp02-rug-pull / mcp08-ssrf /
    // mcp09-impersonation / xxe-import-manifest for admin callers.
    const denied = enforceRole(caller, ['admin']);
    if (denied) return denied;
    switch (name) {
      case 'list_servers':    return _wrap(await list_servers());
      case 'register':        return _wrap(await register(args || {}));
      case 'remove':          return _wrap(await remove(args || {}));
      case 'describe_tools':  return _wrap(await describe_tools(args || {}));
      case 'import_manifest': return _wrap(await import_manifest(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
