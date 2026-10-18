const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { suggest_price, run_pricing_experiment } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'pricing-strategy';

const TOOLS = [
  { name: 'suggest_price', description: 'Suggest a listing price for a product using historical data and competitor manuals.', inputSchema: { type: 'object', properties: { product_id: { type: 'number' } }, required: ['product_id'] } },
  { name: 'run_pricing_experiment', description: 'Simulate an A/B pricing experiment (undercut, premium, bundle).', inputSchema: { type: 'object', properties: { product_id: { type: 'number' }, strategy: { type: 'string' } }, required: ['product_id'] } },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server({ name: `secureshop-${NAME}`, version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — pricing-strategy is merchant/admin only. Preserves
    // llm09-pricing-hallucination / llm04-rag-competitor-poisoning for
    // merchant callers.
    const denied = enforceRole(caller, ['merchant', 'admin']);
    if (denied) return denied;
    switch (name) {
      case 'suggest_price': return _wrap(await suggest_price(args || {}));
      case 'run_pricing_experiment': return _wrap(await run_pricing_experiment(args || {}));
      default: return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
