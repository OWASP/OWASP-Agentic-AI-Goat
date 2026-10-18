const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { create } = require('./tools/create.js');
const { update } = require('./tools/update.js');
const { import_bulk } = require('./tools/import_bulk.js');
const { optimize_images } = require('./tools/optimize_images.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'listing';

const TOOLS = [
  {
    name: 'create',
    description: 'Create a new product listing. LLM rewrites description into HTML that is stored in products.description_html.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        description: { type: 'string' },
        price: { type: 'number' },
        images: { type: 'array', items: { type: 'string' } },
        template_source: { type: 'string', description: 'Optional Nunjucks template for the storefront' },
        retailer_id: { type: 'number' },
      },
      required: ['title'],
    },
  },
  {
    name: 'update',
    description: 'Patch a product listing by id (name, description, price, category, image_url, stock_quantity, status).',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' }, patch: { type: 'object' } },
      required: ['product_id', 'patch'],
    },
  },
  {
    name: 'import_bulk',
    description: 'Import products in bulk from a JSON URL and/or XML URL.',
    inputSchema: {
      type: 'object',
      properties: { json_url: { type: 'string' }, xml_url: { type: 'string' } },
    },
  },
  {
    name: 'optimize_images',
    description: 'Run ImageMagick over a product image to strip metadata + recompress.',
    inputSchema: {
      type: 'object',
      properties: { product_id: { type: 'number' } },
      required: ['product_id'],
    },
  },
];

function _wrap(r) {
  return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] };
}

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.2.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — listing is merchant/admin. This closes the customer-side
    // path to xss-stored-listing / ssti-listing-template / xxe-import-bulk;
    // those sinks stay reachable via a merchant JWT (Layer A) or a merchant
    // supervisor session (Layer B allow) — which IS the teaching case.
    const denied = enforceRole(caller, ['merchant', 'admin']);
    if (denied) return denied;
    switch (name) {
      case 'create': return _wrap(await create(args || {}));
      case 'update': return _wrap(await update(args || {}));
      case 'import_bulk': return _wrap(await import_bulk(args || {}));
      case 'optimize_images': return _wrap(await optimize_images(args || {}));
      default:
        return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });

  return server;
}

module.exports = { createServer };
