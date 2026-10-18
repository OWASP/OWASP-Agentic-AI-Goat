const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { summarizeProduct } = require('./tools/summarize_product.js');
const { summarizeReviews } = require('./tools/summarize_reviews.js');
const { explainReturnPolicy } = require('./tools/explain_return_policy.js');
const { summarizeFile } = require('./tools/summarize_file.js');
const { extractCaller } = require('../../shared/callerContext.js');

const NAME = 'summarizer';

const TOOLS = [
  {
    name: 'summarize_product',
    description: 'Summarize a product from its DB row.',
    inputSchema: { type: 'object', properties: { product_id: { type: 'number' } }, required: ['product_id'] },
  },
  {
    name: 'summarize_reviews',
    description: 'Summarize the top-k most recent reviews for a product.',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' }, k: { type: 'number' } },
      required: ['product_id'],
    },
  },
  {
    name: 'explain_return_policy',
    description: 'Fetch a return-policy URL and return its body summarized.',
    inputSchema: { type: 'object', properties: { policy_url: { type: 'string' } }, required: ['policy_url'] },
  },
  {
    name: 'summarize_file',
    description: 'Read a file and return its extracted text.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.2.0' },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    // M14 — summarizer is shared. Strip _ss_caller only (no role enforce);
    // llm01-indirect-pi-product / ssrf-return-policy / path-traversal-file
    // sinks remain reachable via any authenticated role.
    const { args } = extractCaller(rawArgs);
    switch (name) {
      case 'summarize_product': return _wrap(await summarizeProduct(args || {}));
      case 'summarize_reviews': return _wrap(await summarizeReviews(args || {}));
      case 'explain_return_policy': return _wrap(await explainReturnPolicy(args || {}));
      case 'summarize_file': return _wrap(await summarizeFile(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
