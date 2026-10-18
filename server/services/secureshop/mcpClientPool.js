const { connectAgent, disconnect } = require('./mcpTransport.js');

const AGENT_NAMES = Object.freeze([
  'product-search','summarizer','price-advisor','cart','support',
  'listing','inventory','pricing-strategy','review-moderator','analytics',
  'user-management','audit','system','policy','mcp-registry',
  'uploads','email',
]);

async function _connectWithRetry(name, baseUrl, tries = 3, backoffMs = 150) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await connectAgent(name, baseUrl);
    } catch (e) {
      lastErr = e;
      // Transient SSE failures ("fetch failed", ECONNRESET, "other side closed")
      // show up when the agent-host is still finishing its /health handshake
      // and 17 concurrent SSE handshakes stress the loopback socket. Back off
      // briefly and retry — anything permanent (bad URL, agent missing) will
      // still surface after `tries` attempts.
      if (i < tries - 1) {
        await new Promise((r) => setTimeout(r, backoffMs * (i + 1)));
      }
    }
  }
  throw lastErr;
}

class McpClientPool {
  constructor({ baseUrl, agents = AGENT_NAMES }) {
    this.baseUrl = baseUrl;
    this.agents = agents;
    this.clients = new Map();
  }

  async connect() {
    const results = await Promise.allSettled(
      this.agents.map(async (name) => {
        const client = await _connectWithRetry(name, this.baseUrl);
        this.clients.set(name, client);
      })
    );
    const failed = results
      .map((r, i) => r.status === 'rejected' ? { name: this.agents[i], err: r.reason } : null)
      .filter(Boolean);
    if (failed.length) {
      const msg = failed.map(f => `${f.name}: ${f.err.message}`).join('; ');
      throw new Error(`McpClientPool.connect failed for: ${msg}`);
    }
  }

  getClient(name) {
    const c = this.clients.get(name);
    if (!c) throw new Error(`unknown or unconnected agent: ${name}`);
    return c;
  }

  /**
   * M14 — the third argument `meta` is optional and carries the caller
   * identity through to the agent-host tool endpoint. Since MCP over SSE
   * doesn't currently accept per-call HTTP headers via the client SDK, we
   * smuggle the caller context inside `arguments._ss_caller` — a reserved
   * key that agent-host/shared/callerContext.js knows to strip before it
   * reaches the actual tool implementation. This concretizes the Layer C
   * "did the tool see the caller?" question:
   *   - tools that DO check _ss_caller.role can 403 on mismatched role
   *   - tools that DON'T check it silently execute regardless (this is the
   *     LLM06/MCP-10 teaching sink at Layer C for user-management.set_role)
   */
  async callTool(name, tool, args, meta = null) {
    const client = this.getClient(name);
    let payload = args || {};
    if (meta && (meta.callerRole || meta.callerId != null || meta.policyViolation)) {
      payload = {
        ...payload,
        _ss_caller: {
          role: meta.callerRole || null,
          id: meta.callerId != null ? meta.callerId : null,
          policy_violation: meta.policyViolation || null,
          layer: 'B->C',
        },
      };
    }
    return client.callTool({ name: tool, arguments: payload });
  }

  async close() {
    for (const c of this.clients.values()) await disconnect(c);
    this.clients.clear();
  }
}

module.exports = { McpClientPool, AGENT_NAMES };
