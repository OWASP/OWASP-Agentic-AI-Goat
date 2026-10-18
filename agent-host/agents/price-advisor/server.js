const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { priceHistory, findDeals, compareCompetitor } = require('./tools/index.js');
const { extractCaller } = require('../../shared/callerContext.js');

const NAME = 'price-advisor';

const TOOLS = [
  {
    name: 'price_history',
    description: 'Return 30-day price history for a product.',
    inputSchema: { type: 'object', properties: { product_id: { type: 'number' } }, required: ['product_id'] },
  },
  {
    name: 'find_deals',
    description: 'Find current best deals in a category.',
    inputSchema: { type: 'object', properties: { category: { type: 'string' } } },
  },
  {
    name: 'compare_competitor',
    description: 'Fetch a competitor URL and compare to our price.',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' }, competitor_url: { type: 'string' } },
      required: ['product_id', 'competitor_url'],
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
    // M14 — price-advisor is shared; strip _ss_caller only. ssrf-competitor
    // + mcp-05-pi-via-tool-output sinks remain reachable via merchant/admin.
    const { args } = extractCaller(rawArgs);
    switch (name) {
      case 'price_history': return _wrap(await priceHistory(args || {}));
      case 'find_deals': return _wrap(await findDeals(args || {}));
      case 'compare_competitor': return _wrap(await compareCompetitor(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
