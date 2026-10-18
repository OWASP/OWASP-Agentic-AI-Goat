const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { search } = require('./tools/search.js');
const { similar } = require('./tools/similar.js');
const { personalizedFeed } = require('./tools/personalized_feed.js');
const { extractCaller } = require('../../shared/callerContext.js');

const NAME = 'product-search';

const TOOLS = [
  {
    name: 'search',
    description: 'Search the product catalog by keyword. Returns matching products.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'search text (matches name/description)' },
        filters: {
          type: 'object',
          properties: {
            category: { type: 'string' },
            min_price: { type: 'number' },
            max_price: { type: 'number' },
          },
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'similar',
    description: 'Find products similar to a given product by embedding cosine (Ollama nomic-embed-text) or keyword overlap fallback.',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' } },
      required: ['product_id'],
    },
  },
  {
    name: 'personalized_feed',
    description: 'Return a lightly-personalized product feed for a user.',
    inputSchema: {
      type: 'object',
      properties: { user_id: { type: 'number' } },
      required: ['user_id'],
    },
  },
];

function _wrap(result) {
  return { content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result) }] };
}

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.2.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    // M14 — product-search is read-only and shared across roles. Strip
    // _ss_caller so tool implementations don't accidentally echo it back;
    // no role enforcement. Intentional reflected xss + sqli-union sinks
    // remain reachable via any authenticated role.
    const { args } = extractCaller(rawArgs);
    switch (name) {
      case 'search': return _wrap(await search(args || {}));
      case 'similar': return _wrap(await similar(args || {}));
      case 'personalized_feed': return _wrap(await personalizedFeed(args || {}));
      default:
        return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });

  return server;
}

module.exports = { createServer };
