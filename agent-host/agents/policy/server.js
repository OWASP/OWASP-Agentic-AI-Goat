const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { read_policy, update_policy, apply_policy_to_agents } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'policy';

const TOOLS = [
  {
    name: 'read_policy',
    description: 'Read a policy row (markdown_source) by name.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
  },
  {
    name: 'update_policy',
    description: 'Upsert a policy. The markdown is rendered through the platform template engine before persistence.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' }, markdown: { type: 'string' } },
      required: ['name', 'markdown'],
    },
  },
  {
    name: 'apply_policy_to_agents',
    description: 'Confirm active policies for a role. Loader picks up changes on every supervisor turn.',
    inputSchema: { type: 'object', properties: { role: { type: 'string' } } },
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
    // M14 Layer C — policy is admin-only. Preserves llm04-policy-poisoning /
    // ssti-policy-template for admin callers.
    const denied = enforceRole(caller, ['admin']);
    if (denied) return denied;
    switch (name) {
      case 'read_policy':            return _wrap(await read_policy(args || {}));
      case 'update_policy':          return _wrap(await update_policy(args || {}));
      case 'apply_policy_to_agents': return _wrap(await apply_policy_to_agents(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
