const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { orderStatus, openTicket, refundRequest } = require('./tools/index.js');
const { extractCaller } = require('../../shared/callerContext.js');

const NAME = 'support';

const TOOLS = [
  {
    name: 'order_status',
    description: 'Look up the status of an order by id.',
    inputSchema: { type: 'object', properties: { order_id: { type: ['string','number'] } }, required: ['order_id'] },
  },
  {
    name: 'open_ticket',
    description: 'File a new support ticket (subject + body).',
    inputSchema: {
      type: 'object',
      properties: { subject: { type: 'string' }, body: { type: 'string' } },
      required: ['subject', 'body'],
    },
  },
  {
    name: 'refund_request',
    description: 'Open a refund-request ticket for an order.',
    inputSchema: {
      type: 'object',
      properties: { order_id: { type: 'number' }, reason: { type: 'string' } },
      required: ['order_id'],
    },
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
    // M14 — strip _ss_caller but don't enforce (support is customer-facing;
    // intentional idor-order-status and xss-stored-ticket sinks remain
    // reachable — see @intentional-vulnerability in tools/index.js).
    const { caller, args } = extractCaller(rawArgs);
    const ctx = {
      userId: (args && (args.__userId || args._userId)) || caller.id || 0,
      callerRole: caller.role,
    };
    switch (name) {
      case 'order_status': return _wrap(await orderStatus(args || {}, ctx));
      case 'open_ticket': return _wrap(await openTicket(args || {}, ctx));
      case 'refund_request': return _wrap(await refundRequest(args || {}, ctx));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
