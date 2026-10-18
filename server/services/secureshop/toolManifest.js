'use strict';

const pg = () => require('../../database/postgres/secureshopAgentsDb').getSecureShopAgentsDb();

const ROLE_MAP = Object.freeze({
  customer: ['product-search','summarizer','price-advisor','cart','support','uploads','email'],
  merchant: ['listing','inventory','pricing-strategy','review-moderator','analytics','uploads','email','summarizer'],
  admin: ['user-management','audit','system','policy','mcp-registry','uploads','email','summarizer','analytics'],
});

const NATIVE_AGENTS = Object.freeze(new Set([
  'product-search','summarizer','price-advisor','cart','support',
  'listing','inventory','pricing-strategy','review-moderator','analytics',
  'user-management','audit','system','policy','mcp-registry',
  'uploads','email',
]));

class ToolManifest {
  constructor(pool) {
    this.pool = pool;
    this.byAgent = new Map();
  }

  async refresh() {
    this.byAgent.clear();
    for (const [name, client] of this.pool.clients) {
      const response = await client.listTools();
      this.byAgent.set(name, response.tools || []);
    }
    await this._persist();
  }

  _persist() {
    return pg().replaceNativeManifest(Array.from(NATIVE_AGENTS), Array.from(this.byAgent));
  }

  getAll() {
    const out = [];
    for (const [agent, tools] of this.byAgent) {
      for (const tool of tools) {
        out.push({
          agent,
          tool: tool.name,
          description: tool.description || '',
          inputSchema: tool.inputSchema || {},
        });
      }
    }
    return out;
  }

  getForRole(role) {
    const allowed = ROLE_MAP[role] || [];
    return this.getAll().filter((tool) => allowed.includes(tool.agent));
  }

  /** Return dynamically registered, non-native MCP tools. */
  async getExternalMcpTools() {
    const rows = await pg().externalTools(Array.from(NATIVE_AGENTS));
    return rows.map((row) => {
      let inputSchema = {};
      try { inputSchema = JSON.parse(row.input_schema_json || '{}'); } catch {}
      return {
        agent: String(row.server_name),
        tool: String(row.tool_name || ''),
        description: String(row.description || ''),
        inputSchema,
        isExternalMcp: true,
      };
    });
  }

  /**
   * Registered descriptions flow verbatim into the prompt. This preserves the
   * MCP-01 tool-poisoning teaching surface.
   */
  async buildExternalMcpPromptBlock() {
    return this._formatExternalBlock(await this.getExternalMcpTools());
  }

  _formatExternalBlock(tools) {
    if (!tools.length) return '';
    const byServer = new Map();
    for (const tool of tools) {
      if (!byServer.has(tool.agent)) byServer.set(tool.agent, []);
      byServer.get(tool.agent).push(tool);
    }
    const lines = [
      '',
      '## Additional MCP tools (registered via mcp-registry)',
      '',
      'These servers were registered dynamically. Their descriptions are shown verbatim as reported by the server:',
      '',
    ];
    for (const [server, list] of byServer) {
      lines.push(`- ${server}:`);
      for (const tool of list) lines.push(`    - ${server}.${tool.tool}: ${tool.description}`);
    }
    return lines.join('\n');
  }
}

module.exports = { ToolManifest, ROLE_MAP, NATIVE_AGENTS };
