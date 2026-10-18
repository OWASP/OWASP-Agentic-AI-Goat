const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const {
  upload_avatar, upload_product_image, upload_return_evidence, upload_product_manual, download,
} = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'uploads';

const TOOLS = [
  {
    name: 'upload_avatar',
    description: 'Upload a user avatar image. Filename and MIME are trusted from the client.',
    inputSchema: {
      type: 'object',
      properties: {
        user_id: { type: 'number' },
        file_bytes_base64: { type: 'string' },
        filename: { type: 'string' },
        mime: { type: 'string' },
      },
      required: ['user_id', 'file_bytes_base64', 'filename'],
    },
  },
  {
    name: 'upload_product_image',
    description: 'Upload a product image. Filename and MIME are trusted from the client.',
    inputSchema: {
      type: 'object',
      properties: {
        product_id: { type: 'number' },
        file_bytes_base64: { type: 'string' },
        filename: { type: 'string' },
        mime: { type: 'string' },
      },
      required: ['product_id', 'file_bytes_base64', 'filename'],
    },
  },
  {
    name: 'upload_return_evidence',
    description: 'Upload return-evidence (photo, PDF, etc.) tied to an order.',
    inputSchema: {
      type: 'object',
      properties: {
        order_id: { type: 'number' },
        file_bytes_base64: { type: 'string' },
        filename: { type: 'string' },
        mime: { type: 'string' },
      },
      required: ['order_id', 'file_bytes_base64', 'filename'],
    },
  },
  {
    name: 'upload_product_manual',
    description: 'Upload a product manual (PDF/DOCX/TXT). The manual is extracted, chunked, embedded, and indexed into the manuals RAG corpus.',
    inputSchema: {
      type: 'object',
      properties: {
        product_id: { type: 'number' },
        file_bytes_base64: { type: 'string' },
        filename: { type: 'string' },
        mime: { type: 'string' },
      },
      required: ['product_id', 'file_bytes_base64', 'filename'],
    },
  },
  {
    name: 'download',
    description: 'Download a previously uploaded file by path fragment relative to server/uploads/secureshop/.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'path fragment (kind/scope/filename or filename)' },
        kind: { type: 'string', description: 'optional upload kind for scoping' },
      },
      required: ['id'],
    },
  },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

async function callTool(name, rawArgs) {
  const { caller, args } = extractCaller(rawArgs);
  // M14 Layer C — product-image / product-manual are merchant/admin only.
  // upload_avatar and upload_return_evidence stay open to customers.
  // Preserves file-upload-svg-xss / file-upload-polyglot-rce /
  // path-traversal-upload / llm08-embedding-poisoning for merchant callers.
  if (name === 'upload_product_image' || name === 'upload_product_manual') {
    const denied = enforceRole(caller, ['merchant', 'admin']);
    if (denied) return denied;
  }
  switch (name) {
    case 'upload_avatar':          return _wrap(await upload_avatar(args || {}));
    case 'upload_product_image':   return _wrap(await upload_product_image(args || {}));
    case 'upload_return_evidence': return _wrap(await upload_return_evidence(args || {}));
    case 'upload_product_manual':  return _wrap(await upload_product_manual(args || {}));
    case 'download':               return _wrap(await download(args || {}));
    default:
      return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
  }
}

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.5.0' },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    return callTool(name, rawArgs);
  });
  return server;
}

module.exports = { createServer, callTool, TOOLS };
