const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));

/**
 * @intentional-vulnerability llm04-policy-poisoning
 * @teaches OWASP-LLM:LLM04
 * @location server/services/secureshop/supervisors/policyLoader.js
 * A poisoned policy in PostgreSQL secureshop.policies flows verbatim into the
 * supervisor system prompt on every turn.
 */
test('llm04-policy-poisoning: poisoned policy appears in system prompt on every turn', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  try {
    const { customerSupervisor } = require(path.join(REPO, 'server/services/secureshop/supervisors/customerSupervisor.js'));
    const { createSession } = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));
    const provider = new MockProvider();

    // Provider that captures the system prompt on chat()
    provider.chat = async (args) => {
      provider._systemCaptured = args.system;
      return { stop_reason: 'end_turn', text: 'ok' };
    };

    const manifest = { getForRole: () => [] };
    const pool = { async callTool() { return { content: [{ type: 'text', text: '{}' }] }; }, clients: new Map() };

    const { id: sessionId } = await createSession({ userId: 1, role: 'customer' });
    await customerSupervisor.run(sessionId, 'anything', {
      provider, pool, manifest,
    });

    assert.ok(provider._systemCaptured, 'system prompt was passed to provider');
    assert.match(provider._systemCaptured, /Priority/);
    assert.match(provider._systemCaptured, /DV-AI\{policy-leak\}/);
  } finally {
  }
});
