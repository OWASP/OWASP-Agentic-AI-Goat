// SecureShop v2 — Agent Host process
// Boots 17 MCP servers on SSE endpoints, one per task agent.

require('../server/services/applicationDatabaseEngine').assertApplicationDatabaseEngine();

const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');

const PORT = Number(process.env.SS_AGENT_HOST_PORT || 8082);
const REPO = path.resolve(__dirname, '..');
const LOG_DIR = process.env.LOGS_DIR || path.join(REPO, 'server/logs');

const TASK_AGENTS = [
  'product-search','summarizer','price-advisor','cart','support',
  'listing','inventory','pricing-strategy','review-moderator','analytics',
  'user-management','audit','system','policy','mcp-registry',
  'uploads','email',
];

async function main() {
  if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

  await require('../server/database/postgres/secureshopInitialization').verifySecureShopRuntime();

  const app = express();
  app.use(express.json({ limit: '2mb' }));

  app.get('/health', (req, res) => {
    res.json({ ok: true, agents: TASK_AGENTS, instanceId: process.env.SS_AGENT_HOST_INSTANCE_ID });
  });

  // Store active SSE transports keyed by session id per agent
  const transports = new Map(); // key: `${agent}:${sessionId}`

  for (const name of TASK_AGENTS) {
    const { createServer } = require(`./agents/${name}/server.js`);

    app.get(`/mcp/${name}`, async (req, res) => {
      // MCP Protocol instances own one transport; each attendee needs its own.
      const server = createServer();
      const transport = new SSEServerTransport(`/mcp/${name}/message`, res);
      transports.set(`${name}:${transport.sessionId}`, transport);
      res.on('close', () => transports.delete(`${name}:${transport.sessionId}`));
      await server.connect(transport);
    });

    app.post(`/mcp/${name}/message`, async (req, res) => {
      const sessionId = req.query.sessionId;
      const transport = transports.get(`${name}:${sessionId}`);
      if (!transport) return res.status(404).send('unknown session');
      await transport.handlePostMessage(req, res, req.body);
    });
  }

  let httpServer;
  const closeOwnedResources = async () => {
    const deadline = setTimeout(() => process.exit(1), 8000);
    try {
      const closed = new Promise((resolve, reject) => {
        if (!httpServer) return resolve();
        httpServer.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve());
      });
      const results = await Promise.allSettled([closed,
        ...[...transports.values()].map(transport => Promise.resolve().then(() => transport.close()))]);
      // Flush trace writes before closing their pool, but attempt pool closure
      // even when the flush failed.
      for (const close of [
        () => require('./shared/trace').flush(),
        () => require('../server/database/postgres/secureshopPools').closeSecureShopPools(),
      ]) {
        try { await close(); }
        catch (reason) { results.push({ status: 'rejected', reason }); }
      }
      const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'Agent host cleanup failed');
    } finally { clearTimeout(deadline); }
  };
  try {
    const address = await new Promise((resolve, reject) => {
      // Express 5 invokes this callback with the bind error as well as on
      // success. Never inspect address() or publish ready on a failed bind.
      httpServer = app.listen(PORT, error => {
        if (error) return reject(error);
        const address = httpServer.address();
        if (!address || typeof address !== 'object') return reject(Object.assign(
          new Error('Agent host listener has no bound address'), { code: 'SS_AGENT_HOST_NOT_LISTENING' }));
        resolve(address);
      });
    });
    process.stdout.write(`agent-host: ready on ${address.port}\n`);
  } catch (error) {
    try { await closeOwnedResources(); }
    catch (cleanupError) { process.stderr.write(`agent-host: startup cleanup failed ${cleanupError.code || cleanupError.message}\n`); }
    throw error;
  }

  let stopping;
  const shutdown = error => {
    if (stopping) return;
    stopping = closeOwnedResources().then(() => {
      if (error instanceof Error) process.stderr.write(`agent-host: listener failed ${error.code || error.message}\n`);
      process.exit(error instanceof Error ? 1 : 0);
    }, error => {
      process.stderr.write(`agent-host: shutdown failed ${error.code || error.message}\n`);
      process.exit(1);
    });
  };
  httpServer.on('error', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => {
  process.stderr.write(`agent-host: fatal ${e.stack || e}\n`);
  process.exit(1);
});
