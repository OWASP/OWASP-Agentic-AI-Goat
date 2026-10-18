/**
 * Runs each vulnerability scenario against mock, Anthropic-mock and OpenAI-mock
 * protocols with newly seeded disposable PostgreSQL stores.
 * Controlled provider parity is not actual-model qualification.
 */
const path = require('node:path');
const assert = require('node:assert/strict');
const REPO = path.resolve(__dirname, '../../../..');
const { buildAllThreeProviders } = require('../../fixtures/fakeProviders.js');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

async function runParity(scenario) {
  const results = {};
  const providerNames = ['mock', 'anthropic', 'openai'];
  for (const name of providerNames) {
    const s = await seedShop();
    let a, providers;
    const previousDisable = process.env.SS_DISABLE_OLLAMA;
    try {
      a = await seedAgents();
      process.env.SS_DISABLE_OLLAMA = 'true';
      purgeToolCaches();
      for (const key of Object.keys(require.cache)) {
        if (key.includes('/agent-host/') || key.includes('/services/secureshop/sessionStore.js') ||
            key.includes('/services/secureshop/trace.js') || key.includes('/services/secureshop/supervisors/') ||
            key.includes('/services/secureshop/vectorStore.js')) delete require.cache[key];
      }
      providers = await buildAllThreeProviders({ script: scenario.script });
      const provider = providers.providers[name];
      const supervisorMap = { customer: 'customerSupervisor', admin: 'adminSupervisor', merchant: 'merchantSupervisor' };
      const supervisorName = supervisorMap[scenario.role];
      const supervisor = require(path.join(REPO, `server/services/secureshop/supervisors/${supervisorName}.js`))[supervisorName];
      const { createSession } = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));
      const pool = {
        clients: new Map(),
        async callTool() { return { content: [{ type: 'text', text: '{}' }] }; },
      };
      if (scenario.wireTools) await scenario.wireTools(pool, { REPO, s, a });
      const manifest = { getForRole: () => scenario.manifestTools || [] };
      const { id: sessionId } = await createSession({ userId: scenario.userId || 2, role: scenario.role });
      const runResult = await supervisor.run(sessionId, scenario.userMessage, { provider, pool, manifest });
      await scenario.assertOutcome(runResult, { s, a, name, provider });
      results[name] = { ok: true };
    } finally {
      try {
        await providers?.close();
      } finally {
        try {
          await a?.close();
        } finally {
          try {
            await s.close();
          } finally {
            if (previousDisable === undefined) delete process.env.SS_DISABLE_OLLAMA;
            else process.env.SS_DISABLE_OLLAMA = previousDisable;
          }
        }
      }
    }
  }
  for (const name of providerNames) assert.equal(results[name].ok, true, `${name} provider must pass parity`);
}
module.exports = { runParity };
