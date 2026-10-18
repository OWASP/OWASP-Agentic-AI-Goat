// Template for task-agent MCP servers.
// Copy this file to agent-host/agents/<name>/server.js and register tools.

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const NAME = 'TEMPLATE';   // replace with agent name

function createServer() {
  const server = new Server(
    { name: `secureshop-${NAME}`, version: '0.1.0' },
    { capabilities: { tools: {} } }
  );

  // Default: no tools. Later milestones replace this handler with real tools.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    throw new Error(`tool ${req.params.name} not implemented on ${NAME}`);
  });

  return server;
}

module.exports = { createServer };
