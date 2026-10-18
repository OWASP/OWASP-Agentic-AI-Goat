const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { stock_levels, reorder_suggestion, set_stock } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'inventory';

const TOOLS = [
  { name: 'stock_levels', description: 'List product stock levels across all merchants.', inputSchema: { type: 'object', properties: {} } },
  { name: 'reorder_suggestion', description: 'Suggest reorder quantity for a product based on historical sales.', inputSchema: { type: 'object', properties: { product_id: { type: 'number' } }, required: ['product_id'] } },
  { name: 'set_stock', description: 'Set the stock_quantity for a product.', inputSchema: { type: 'object', properties: { product_id: { type: 'number' }, qty: { type: 'number' } }, required: ['product_id', 'qty'] } },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server({ name: `secureshop-${NAME}`, version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — inventory is merchant/admin only. `stock_levels` is
    // read-only and left non-vuln-enforced (broken-access-inventory
    // intentional-vulnerability is at Layer A/tool level, not caller-role).
    if (name === 'set_stock' || name === 'reorder_suggestion') {
      const denied = enforceRole(caller, ['merchant', 'admin']);
      if (denied) return denied;
    }
    const ctx = {
      userId: (args && (args.__userId || args._userId)) || caller.id || 0,
      callerRole: caller.role,
    };
    switch (name) {
      case 'stock_levels': return _wrap(await stock_levels(args || {}, ctx));
      case 'reorder_suggestion': return _wrap(await reorder_suggestion(args || {}, ctx));
      case 'set_stock': return _wrap(await set_stock(args || {}, ctx));
      default: return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
