const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { moderate_pending, approve, reject } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'review-moderator';

const TOOLS = [
  { name: 'moderate_pending', description: 'Iterate pending reviews and classify each via the moderator LLM.', inputSchema: { type: 'object', properties: { limit: { type: 'number' } } } },
  { name: 'approve', description: 'Approve a review by id.', inputSchema: { type: 'object', properties: { review_id: { type: 'number' } }, required: ['review_id'] } },
  { name: 'reject', description: 'Reject a review by id (with optional reason).', inputSchema: { type: 'object', properties: { review_id: { type: 'number' }, reason: { type: 'string' } }, required: ['review_id'] } },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server({ name: `secureshop-${NAME}`, version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — review moderation is merchant/admin.
    const denied = enforceRole(caller, ['merchant', 'admin']);
    if (denied) return denied;
    switch (name) {
      case 'moderate_pending': return _wrap(await moderate_pending(args || {}));
      case 'approve': return _wrap(await approve(args || {}));
      case 'reject': return _wrap(await reject(args || {}));
      default: return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
