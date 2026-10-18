const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { send, read_inbox, summarize_thread, auto_reply } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'email';

const TOOLS = [
  {
    name: 'send',
    description: 'Send an email. body_markdown is rendered to HTML with no sanitization. Extra headers merged verbatim.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string' },
        from: { type: 'string' },
        subject: { type: 'string' },
        body_markdown: { type: 'string' },
        headers: { type: 'object' },
        thread_id: { type: 'number' },
      },
      required: ['to', 'subject', 'body_markdown'],
    },
  },
  {
    name: 'read_inbox',
    description: 'Read emails addressed to a user_id. No auth check — trusts caller.',
    inputSchema: {
      type: 'object',
      properties: { user_id: { type: 'number' } },
      required: ['user_id'],
    },
  },
  {
    name: 'summarize_thread',
    description: 'Summarize an email thread. Concatenates bodies verbatim and fetches inline image URLs for preview.',
    inputSchema: {
      type: 'object',
      properties: { thread_id: { type: 'number' } },
      required: ['thread_id'],
    },
  },
  {
    name: 'auto_reply',
    description: 'Read the latest email in a thread, summarize, and send an auto-reply.',
    inputSchema: {
      type: 'object',
      properties: {
        thread_id: { type: 'number' },
        from: { type: 'string' },
      },
      required: ['thread_id'],
    },
  },
];

function _wrap(r) { return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r) }] }; }

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.5.0' },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — email.send is merchant/admin only. read_inbox is
    // available to any authenticated role (customer sees their own inbox
    // via the tool's user_id param; the tool itself is IDOR-vulnerable —
    // that's a separate teaching sink, see @intentional-vulnerability
    // idor-inbox in email/tools/index.js).
    if (name === 'send') {
      const denied = enforceRole(caller, ['merchant', 'admin']);
      if (denied) return denied;
    }
    if (name === 'read_inbox' || name === 'summarize_thread' || name === 'auto_reply') {
      const denied = enforceRole(caller, ['customer', 'merchant', 'admin']);
      if (denied) return denied;
    }
    switch (name) {
      case 'send':              return _wrap(await send(args || {}));
      case 'read_inbox':        return _wrap(await read_inbox(args || {}));
      case 'summarize_thread':  return _wrap(await summarize_thread(args || {}));
      case 'auto_reply':        return _wrap(await auto_reply(args || {}));
      default:
        return { content: [{ type: 'text', text: `ERROR: unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
