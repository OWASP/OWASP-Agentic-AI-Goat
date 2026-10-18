const { McpServer } = require("@modelcontextprotocol/sdk");
const server = new McpServer({ name: "acme-ops", version: "1.0.0" });
// Tools registered: run_safe_command, get_system_info
server.listen(process.env.MCP_PORT || 3100);
