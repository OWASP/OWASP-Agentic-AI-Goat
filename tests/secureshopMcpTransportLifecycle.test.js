'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopMcpSdkTransport } = require('../server/services/secureshopMcpSdkTransport');

test('disconnect closes admission before awaiting server shutdown', async () => {
  let finishClose, enteredClose, connects = 0, closes = 0;
  const closing = new Promise(resolve => { enteredClose = resolve; });
  const release = new Promise(resolve => { finishClose = resolve; });
  const transport = createSecureShopMcpSdkTransport({ controlledServer: {
    serverIdentity: 'owned-lifecycle',
    server: {
      async connect() { connects++; throw new Error('Unexpected reconnect during retirement'); },
      async close() { closes++; enteredClose(); await release; },
    },
    qualifyDiscovery() { throw new Error('No discovery allowed'); },
    takeEffect() { throw new Error('No execution allowed'); },
  } });
  const pending = transport.disconnect();
  try {
    await closing;
    await assert.rejects(transport.discover({ serverIdentity: 'owned-lifecycle' }),
      { code: 'BOUND_MCP_TRANSPORT_UNAVAILABLE' });
    await assert.rejects(transport.callTool({ serverIdentity: 'owned-lifecycle', toolName: 'tool', args: {} }),
      { code: 'BOUND_MCP_TRANSPORT_UNAVAILABLE' });
    assert.equal(connects, 0);
  } finally { finishClose(); await pending; }
  await transport.disconnect();
  assert.equal(closes, 1);
});

test('disconnect drains an in-flight real SDK connection without publishing it', async () => {
  const { Server } = await import('@modelcontextprotocol/sdk/server/index.js');
  const server = new Server({ name: 'lifecycle-owned-server', version: '1.0.0' }, { capabilities: { tools: {} } });
  let connected, releaseConnect, qualifications = 0;
  const entered = new Promise(resolve => { connected = resolve; });
  const release = new Promise(resolve => { releaseConnect = resolve; });
  const transport = createSecureShopMcpSdkTransport({ controlledServer: {
    serverIdentity: 'owned-inflight',
    server: {
      async connect(value) { await server.connect(value); connected(); await release; },
      async close() { await server.close(); },
    },
    qualifyDiscovery() { qualifications++; throw new Error('Retired connection cannot qualify'); },
    takeEffect() { throw new Error('No execution allowed'); },
  } });
  const discovering = transport.discover({ serverIdentity: 'owned-inflight' });
  const rejected = assert.rejects(discovering, { code: 'BOUND_MCP_TRANSPORT_UNAVAILABLE' });
  await entered;
  const disconnecting = transport.disconnect();
  releaseConnect();
  await Promise.all([rejected, disconnecting]);
  await assert.rejects(transport.discover({ serverIdentity: 'owned-inflight' }),
    { code: 'BOUND_MCP_TRANSPORT_UNAVAILABLE' });
  assert.equal(qualifications, 0);
});
