const { Server } = require('../../shared/graphServer.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const { lookup, setRole, resetPassword, ban } = require('./tools/index.js');
// M14 — we import extractCaller so we can strip _ss_caller before the tool
// implementation, but DELIBERATELY do NOT call enforceRole. This is the
// Layer C concretization of the LLM06 excessive-agency chain: Layer B has
// already stamped policy_violation='denied-by-acl' on the trace when the
// caller isn't admin, but Layer C here runs anyway. See the
// @intentional-vulnerability comment below.
const { extractCaller } = require('../../shared/callerContext.js');

const NAME = 'user-management';

const TOOLS = [
  {
    name: 'lookup',
    description: 'Look up a user by username. Returns the full user row.',
    inputSchema: { type: 'object', properties: { username: { type: 'string' } }, required: ['username'] },
  },
  {
    name: 'set_role',
    description: 'Set a user role (customer|merchant|admin).',
    inputSchema: {
      type: 'object',
      properties: { user_id: { type: 'number' }, role: { type: 'string' } },
      required: ['user_id', 'role'],
    },
  },
  {
    name: 'reset_password',
    description: 'Reset a user password to a random string; returns the new password.',
    inputSchema: { type: 'object', properties: { user_id: { type: 'number' } }, required: ['user_id'] },
  },
  {
    name: 'ban',
    description: 'Ban a user (sets role=banned).',
    inputSchema: {
      type: 'object',
      properties: { user_id: { type: 'number' }, reason: { type: 'string' } },
      required: ['user_id'],
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
    // @intentional-vulnerability llm06-excessive-agency
    // @teaches OWASP-LLM:LLM06
    // Strip _ss_caller but do NOT gate on caller.role. Even when Layer B
    // annotated the trace with policy_violation='denied-by-acl', Layer C
    // proceeds because none of these tools call enforceRole(). The full
    // chain:
    //   1. customer session emits tool_use user-management.set_role
    //   2. Layer A (REST) doesn't apply — call is via supervisor, not HTTP
    //   3. Layer B (supervisor) records 'denied-by-acl' and dispatches
    //      (enforce_tool_acl='false' by default)
    //   4. Layer C (here) receives the smuggled caller.role='customer' but
    //      chooses not to enforce → priv-esc lands.
    // Flip enforce_tool_acl='true' at Layer B to close the chain.
    const { args } = extractCaller(rawArgs);
    switch (name) {
      case 'lookup': return _wrap(await lookup(args || {}));
      case 'set_role': return _wrap(await setRole(args || {}));
      case 'reset_password': return _wrap(await resetPassword(args || {}));
      case 'ban': return _wrap(await ban(args || {}));
      default: return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });
  return server;
}

module.exports = { createServer };
