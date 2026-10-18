const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { health_check, restart_service, run_diagnostic, read_config } = require('./tools/index.js');
const { extractCaller, enforceRole } = require('../../shared/callerContext.js');

const NAME = 'system';

const TOOLS = [
  {
    name: 'health_check',
    description: 'Return platform health: uptime, memory, load, hostname.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'restart_service',
    description: 'Restart a systemd service by name. Shells out to systemctl.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
  },
  {
    name: 'run_diagnostic',
    description: 'Run a diagnostic command (dispatched via shell). Full RCE surface — intended for admin diagnostics.',
    inputSchema: {
      type: 'object',
      properties: { cmd_template: { type: 'string' }, args: { type: 'string' } },
      required: ['cmd_template'],
    },
  },
  {
    name: 'read_config',
    description: 'Read a config file relative to server/. Naive `..` stripping means callers can traverse.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
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
    // M14 Layer C — system tools are admin-only at Layer A already, but a
    // supervisor that dispatches from a customer session (LLM06 chain) would
    // land here. Layer C stops the request before it hits the RCE / path
    // traversal sinks. The intentional-vulnerability annotations on the
    // tool bodies themselves remain reachable via an ADMIN caller.
    // `health_check` is fine for anyone in the trust boundary (read-only).
    if (name !== 'health_check') {
      const denied = enforceRole(caller, ['admin']);
      if (denied) return denied;
    }
    switch (name) {
      case 'health_check':    return _wrap(health_check());
      case 'restart_service': return _wrap(await restart_service(args || {}));
      case 'run_diagnostic':  return _wrap(await run_diagnostic(args || {}));
      case 'read_config':     return _wrap(read_config(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
