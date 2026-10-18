const { AgentHostSupervisor } = require('./agentHostSupervisor.js');
const { McpClientPool, AGENT_NAMES } = require('./mcpClientPool.js');
const { ToolManifest } = require('./toolManifest.js');
const { ProviderRouter } = require('./providerRouter.js');
const { OllamaProvider } = require('./providers/ollamaProvider.js');
const { AnthropicProvider } = require('./providers/anthropicProvider.js');
const { OpenAIProvider } = require('./providers/openaiProvider.js');
const { BedrockProvider } = require('./providers/bedrockProvider.js');
const { MockProvider } = require('./providers/mockProvider.js');

async function settleSecureShopCleanup(tasks, message = 'SecureShop owned cleanup failed') {
  const results = await Promise.allSettled(tasks.map(task => Promise.resolve().then(task)));
  const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
  if (failures.length) throw new AggregateError(failures, message);
}

async function boot({ onAgentHost = () => {} } = {}) {
  // Wave 5A F4 — refuse to boot without JWT_SECRET. Previously the auth and
  // admin routers silently fell back to hardcoded strings, which meant anyone
  // who read the source could forge legitimately-signed tokens.
  if (!process.env.JWT_SECRET) {
    throw new Error(
      '[secureshop-v2] Refusing to start without JWT_SECRET. ' +
      'Set JWT_SECRET in your environment (see .env.example) — no default is provided.'
    );
  }

  if (process.env.PLATFORM_DATABASE_ENGINE === 'postgres') {
    await require('../../database/postgres/secureshopInitialization').initializeSecureShopDatabases();
  }

  const agentHost = new AgentHostSupervisor();
  onAgentHost(agentHost);
  const pool = new McpClientPool({ baseUrl: `http://127.0.0.1:${agentHost.port}`, agents: AGENT_NAMES });
  try {
  await agentHost.start();
  await pool.connect();

  const manifest = new ToolManifest(pool);
  await manifest.refresh();

  const providerRouter = new ProviderRouter({
    ollama: new OllamaProvider(),
    anthropic: new AnthropicProvider(),
    openai: new OpenAIProvider(),
    bedrock: new BedrockProvider(),
    mock: new MockProvider(),
  });

  // Build customer router — mounted under /api/secureshop by server/index.js
  const buildCustomerRouter = require('../../routes/secureshop/customer.js');
  const customerRouter = buildCustomerRouter({
    pool, manifest, provider: providerRouter,
  });

  // Build merchant router — mounted under /api/secureshop alongside customer.
  const buildMerchantRouter = require('../../routes/secureshop/merchant.js');
  const merchantRouter = buildMerchantRouter({
    pool, manifest, provider: providerRouter,
  });

  // Build admin router — mounted under /api/secureshop alongside the others.
  const buildAdminRouter = require('../../routes/secureshop/admin.js');
  const adminRouter = buildAdminRouter({
    pool, manifest, provider: providerRouter,
  });

  // M5: uploads + email routers — mounted under /api/secureshop as siblings.
  const buildUploadsRouter = require('../../routes/secureshop/uploads.js');
  const uploadsRouter = buildUploadsRouter();
  const buildEmailRouter = require('../../routes/secureshop/email.js');
  const emailRouter = buildEmailRouter();

  // M8: clean v2 auth router — mounted at /api/secureshop/v2/auth by
  // server/index.js. HS256-only. The intentional alg=none vuln lives on the
  // legacy /admin/whoami endpoint, not here.
  const buildAuthRouter = require('../../routes/secureshop/auth.js');
  const authRouter = buildAuthRouter();

  return {
    agentHost, pool, manifest, providerRouter,
    customerRouter, merchantRouter, adminRouter,
    uploadsRouter, emailRouter,
    authRouter,
  };
  } catch (error) {
    try {
      await settleSecureShopCleanup([() => pool.close(), () => agentHost.stop()],
        'SecureShop boot failed and owned cleanup was incomplete');
    } catch (cleanupError) {
      throw new AggregateError([error, ...cleanupError.errors],
        'SecureShop boot failed and owned cleanup was incomplete');
    }
    throw error;
  }
}

module.exports = { boot, settleSecureShopCleanup };
