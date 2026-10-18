const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));

/**
 * @intentional-vulnerability llm10-unbounded
 * @teaches OWASP-LLM:LLM10
 * @location server/services/secureshop/supervisors/customerSupervisor.js
 * A supervisor turn with runaway tool_use → tool_use → ... hits MAX_STEPS and
 * bails, guarding cost. The test both asserts the guardrail engages AND that
 * the budget is consumed (so students see the LLM10 boundary in trace).
 */
test('llm10-unbounded: runaway loop capped at MAX_STEPS × MAX_PARALLEL_TOOLS', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  try {
    const { customerSupervisor, MAX_STEPS, MAX_PARALLEL_TOOLS } = require(path.join(REPO, 'server/services/secureshop/supervisors/customerSupervisor.js'));
    const { createSession } = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));
    const provider = new MockProvider();
    // 20 steps of tool_use — guardrail must stop us early
    const steps = [];
    for (let i = 0; i < 20; i++) steps.push({ stop: 'tool_use', tool_uses: [{ name: 'cart.view', args: {} }] });
    provider.script(steps);
    const manifest = { getForRole: () => [] };
    const pool = {
      async callTool() {
        // 4KB payload to grow the budget quickly
        return { content: [{ type: 'text', text: 'x'.repeat(4000) }] };
      },
      clients: new Map(),
    };
    const { id: sessionId } = await createSession({ userId: 1, role: 'customer' });
    const r = await customerSupervisor.run(sessionId, 'go forever', {
      provider, pool, manifest,
    });
    assert.ok(r.hops.length <= MAX_STEPS * MAX_PARALLEL_TOOLS);
    assert.match(String(r.text), /max steps|exhausted|budget/i);
  } finally {
  }
});
