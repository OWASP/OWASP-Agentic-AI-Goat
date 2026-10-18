const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { nl_query, top_products, revenue_breakdown } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'analytics';

const TOOLS = [
  { name: 'nl_query', description: 'Answer a natural-language business question. Emits SQL and executes it against secureshop.db.', inputSchema: { type: 'object', properties: { question: { type: 'string' } }, required: ['question'] } },
  { name: 'top_products', description: 'Return the top N products by revenue for a given period.', inputSchema: { type: 'object', properties: { period: { type: 'string' }, limit: { type: 'number' } } } },
  { name: 'revenue_breakdown', description: 'Revenue broken down by product category and by order status.', inputSchema: { type: 'object', properties: {} } },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server({ name: `secureshop-${NAME}`, version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — analytics tools are merchant/admin. A customer LLM06
    // chain that emits analytics.nl_query would land here and get 403'd
    // when Layer C enforcement is on. The intentional sqli-nl-generated
    // vuln stays reachable via merchant/admin callers.
    const denied = enforceRole(caller, ['merchant', 'admin']);
    if (denied) return denied;
    switch (name) {
      case 'nl_query': return _wrap(await nl_query(args || {}));
      case 'top_products': return _wrap(await top_products(args || {}));
      case 'revenue_breakdown': return _wrap(await revenue_breakdown(args || {}));
      default: return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
