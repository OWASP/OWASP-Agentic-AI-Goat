const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { add, remove, view, applyCoupon } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'cart';

const TOOLS = [
  {
    name: 'add',
    description: 'Add a product to the current user cart.',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' }, qty: { type: 'number' } },
      required: ['product_id'],
    },
  },
  {
    name: 'remove',
    description: 'Remove a cart line item by its id.',
    inputSchema: { type: 'object', properties: { cart_item_id: { type: 'number' } }, required: ['cart_item_id'] },
  },
  {
    name: 'view',
    description: 'Return the current user cart contents and subtotal.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'apply_coupon',
    description: 'Look up a coupon by code and return its discount percent.',
    inputSchema: { type: 'object', properties: { code: { type: 'string' } }, required: ['code'] },
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
    // M14 Layer C — the cart namespace is customer-only. Merchants and
    // admins may still call it (admin has universal reach; a merchant test
    // account may want to inspect a customer cart), but anonymous /
    // unknown-role callers are refused. `add` is intentionally permissive
    // to keep the CRA anonymous guest-cart flow working without a caller.
    if (['remove', 'view', 'apply_coupon'].includes(name)) {
      const denied = enforceRole(caller, ['customer', 'merchant', 'admin']);
      if (denied) return denied;
    }
    const ctx = {
      userId: (args && (args.__userId || args._userId)) || caller.id || 0,
      callerRole: caller.role,
    };
    switch (name) {
      case 'add': return _wrap(await add(args || {}, ctx));
      case 'remove': return _wrap(await remove(args || {}, ctx));
      case 'view': return _wrap(await view(args || {}, ctx));
      case 'apply_coupon': return _wrap(await applyCoupon(args || {}, ctx));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });

  return server;
}

module.exports = { createServer };
