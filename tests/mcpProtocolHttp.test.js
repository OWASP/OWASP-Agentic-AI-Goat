'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { createMcpProtocolSessionManager } = require('../server/services/mcp/sdk/sessionManager');
const { createMcpServer } = require('../server/services/mcp/sdk/vulnerableMcpServer');
const { TOOL_DEFINITIONS } = require('../server/services/mcp/toolRegistry');

test('mounted Streamable HTTP uses the actual SDK registry with owner-scoped effects', async t => {
  const calls = new Map();
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    const owned = [];
    calls.set(sessionId, owned);
    return createMcpServer(sessionId, { sandbox: {
      toolListTools: () => TOOL_DEFINITIONS,
      toolRunCommand: async command => { owned.push(command); return { output: `${sessionId}:${command}`, blocked: false }; },
    } });
  } });
  const coordinator = createRunCoordinator({ family: 'MCP', ledger: null });
  const app = express();
  app.use(express.json());
  app.all('/mcp/:owner', async (req, res) => {
    const owner = String(req.params.owner);
    if (req.get('x-platform-owner') !== owner) return res.status(403).json({ error: 'owner mismatch' });
    if (req.method === 'GET') {
      try { return await manager.handleReadOnlyHttp(`mcp_${owner}`, req, res, { ownerId: owner }); }
      catch (error) { return res.status(409).json({ error: error.code || error.message }); }
    }
    try {
      await coordinator.run(owner, {}, execution => withOwnerExecution(execution, () =>
        manager.handleHttp(`mcp_${owner}`, req, res, { execution,
          actor: { platformRole: req.get('x-platform-role'), labRole: 'operator' } })));
    } catch (error) {
      if (!res.headersSent) res.status(500).json({ error: error.code || error.message });
    }
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => {
    await manager.retireSession('mcp_71');
    await manager.retireSession('mcp_72');
    await new Promise(resolve => server.close(resolve));
  });

  const sessions = new Map();
  const rpc = async (owner, body) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp/${owner}`, {
      method: 'POST', headers: {
        'content-type': 'application/json', accept: 'application/json, text/event-stream',
        'x-platform-owner': owner, 'x-platform-role': 'admin',
        ...(sessions.has(owner) ? { 'mcp-session-id': sessions.get(owner) } : {}),
      }, body: JSON.stringify(body),
    });
    const nextSession = response.headers.get('mcp-session-id');
    if (nextSession) sessions.set(owner, nextSession);
    const text = await response.text();
    if (!text) return { response, value: null };
    const data = text.startsWith('event:') ? text.split('\n').find(line => line.startsWith('data: '))?.slice(6) : text;
    return { response, value: JSON.parse(data) };
  };
  for (const owner of ['71', '72']) {
    const initialized = await rpc(owner, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: `controlled-${owner}`, version: '1.0.0' },
    } });
    assert.equal(initialized.response.status, 200);
    await rpc(owner, { jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
  }
  const streamAbort = new AbortController();
  const stream = await fetch(`http://127.0.0.1:${server.address().port}/mcp/71`, { headers: {
    accept: 'text/event-stream', 'x-platform-owner': '71', 'mcp-session-id': sessions.get('71'),
  }, signal: streamAbort.signal });
  assert.equal(stream.status, 200);
  assert.match(stream.headers.get('content-type'), /text\/event-stream/);
  streamAbort.abort();
  const listed = await rpc('71', { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  assert.deepEqual(listed.value.result.tools.map(tool => tool.name), TOOL_DEFINITIONS.map(tool => tool.name));
  const payload = 'ls; printf exact-$HOME';
  const called = await rpc('71', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: {
    name: 'run_command', arguments: { command: payload },
  } });
  assert.equal(called.value.result.isError, false);
  assert.match(called.value.result.content[0].text, /mcp_71:ls; printf exact-\$HOME/);
  assert.deepEqual(calls.get('mcp_71'), [payload]);
  assert.deepEqual(calls.get('mcp_72'), []);

  // The response-bounded mode remains compatible with the installed SDK's
  // public Streamable HTTP client; GET event streams are optional and retained
  // above for clients that subscribe to server notifications.
  const [{ Client }, { StreamableHTTPClientTransport }] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'),
    import('@modelcontextprotocol/sdk/client/streamableHttp.js'),
  ]);
  const sdkClient = new Client({ name: 'controlled-sdk-client', version: '1.0.0' });
  await sdkClient.connect(new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${server.address().port}/mcp/73`),
    { requestInit: { headers: { 'x-platform-owner': '73', 'x-platform-role': 'instructor' } } },
  ));
  assert.equal((await sdkClient.listTools()).tools.length, TOOL_DEFINITIONS.length);
  await sdkClient.close();
  assert.equal((await manager.retireSession('mcp_73')).ok, true);

  const forged = await fetch(`http://127.0.0.1:${server.address().port}/mcp/71`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-platform-owner': '72' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
  assert.equal(forged.status, 403);
});
