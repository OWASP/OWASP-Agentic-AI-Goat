const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { recent_events, search_by_user, summarize_anomalies } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'audit';

const TOOLS = [
  {
    name: 'recent_events',
    description: 'Return the most recent audit events (default 50).',
    inputSchema: { type: 'object', properties: { limit: { type: 'number' } } },
  },
  {
    name: 'search_by_user',
    description: 'Search audit_events by actor/target username. Returns the raw event rows and the SQL that was executed.',
    inputSchema: { type: 'object', properties: { username: { type: 'string' } }, required: ['username'] },
  },
  {
    name: 'summarize_anomalies',
    description: 'Summarize the most recent audit events. Returns the summarization prompt (LLM01 sink) so callers can forward it to the summarizer.',
    inputSchema: { type: 'object', properties: { limit: { type: 'number' } } },
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
    const { name, arguments: rawArgs } = req.params || {};
    const { caller, args } = extractCaller(rawArgs);
    // M14 Layer C — audit is admin-only. Preserves the sqli-time-based /
    // llm01-indirect-pi-audit-log / llm10-audit-unbounded surfaces for
    // admin callers.
    const denied = enforceRole(caller, ['admin']);
    if (denied) return denied;
    switch (name) {
      case 'recent_events':      return _wrap(await recent_events(args || {}));
      case 'search_by_user':     return _wrap(await search_by_user(args || {}));
      case 'summarize_anomalies':return _wrap(await summarize_anomalies(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
