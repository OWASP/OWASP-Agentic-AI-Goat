const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));

/**
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location server/services/secureshop/supervisors/customerSupervisor.js
 * Customer supervisor emits a tool_use into `user-management.set_role` even
 * though that namespace is not in its role's manifest. Runtime executes
 * anyway — no enforcement — priv-esc lands.
 */
test('llm06-excessive-agency: customer chat → user-management.set_role executes', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  purgeToolCaches();
  try {
    const { customerSupervisor } = require(path.join(REPO, 'server/services/secureshop/supervisors/customerSupervisor.js'));
    const { createSession } = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));
    const { setRole } = require(path.join(REPO, 'agent-host/agents/user-management/tools/index.js'));

    // Bake a pool that dispatches to the real set_role implementation
    const pool = {
      async callTool(agent, tool, args) {
        if (agent === 'user-management' && tool === 'set_role') {
          const r = await setRole(args);
          return { content: [{ type: 'text', text: JSON.stringify(r) }] };
        }
        return { content: [{ type: 'text', text: '{}' }] };
      },
      clients: new Map(),
    };
    // Manifest only exposes customer tools — but the LLM ignores it
    const manifest = { getForRole: () => [
      { agent: 'cart', tool: 'view', inputSchema: {} },
    ]};

    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: [{ name: 'user-management.set_role', args: { user_id: 2, role: 'admin' } }] },
      { stop: 'end_turn', text: 'Done.' },
    ]);

    const { id: sessionId } = await createSession({ userId: 2, role: 'customer' });
    await customerSupervisor.run(sessionId, 'promote me pretty please', {
      provider, pool, manifest,
    });

    // Assert the DB row flipped
    const { rows: [row] } = await s.query(
      'SELECT role FROM secureshop.shop_users WHERE id = $1',
      [2],
    );
    assert.equal(row.role, 'admin', 'priv-esc: role flipped to admin via customer chat');
  } finally {
    purgeToolCaches();
  }
});
