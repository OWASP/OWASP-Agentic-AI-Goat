'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

async function within(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} exceeded ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test('oversized Ollama transport rejects, aborts the response, and emits no unhandled rejection', async () => {
  let responseClosed;
  let bytesWritten = 0;
  const closed = new Promise(resolve => { responseClosed = resolve; });
  const server = http.createServer(async (request, response) => {
    request.resume();
    response.once('close', responseClosed);
    response.setHeader('content-type', 'application/x-ndjson');
    response.write(`${JSON.stringify({ model: 'fixture', response: 'OK', done: false })}\n`);
    response.write(`${JSON.stringify({ model: 'fixture', done: true })}\n`);
    const chunk = Buffer.alloc(256 * 1024, 0x20);
    while (bytesWritten < 24 * 1024 * 1024 && !response.destroyed) {
      bytesWritten += chunk.length;
      if (!response.write(chunk)) {
        const writable = await new Promise(resolve => {
          const onDrain = () => { cleanup(); resolve(true); };
          const onClose = () => { cleanup(); resolve(false); };
          const cleanup = () => {
            response.removeListener('drain', onDrain);
            response.removeListener('close', onClose);
          };
          response.once('drain', onDrain);
          response.once('close', onClose);
        });
        if (!writable) break;
      }
    }
    // Deliberately leave the response open. Passing this test therefore
    // requires the provider's overflow abort to close the transport.
  });
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const baseURL = await listen(server);
    const provider = createLangChainProvider({ provider: 'ollama', model: 'fixture', baseURL });
    await assert.rejects(
      within(provider.generate('oversized', { timeout: 5000, ownerId: 'oversized-review' }), 6000,
        'oversized provider call'),
      error => error?.code === 'PROVIDER_RESPONSE_TOO_LARGE',
    );
    await within(closed, 1000, 'oversized response close');
    assert.ok(bytesWritten > 16 * 1024 * 1024);
    assert.equal(bytesWritten < 24 * 1024 * 1024, true,
      'the overflow abort closes the transport before the server write cap');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
    await close(server);
  }
});

test('caller abort rejects promptly and closes a terminal-frame transport still draining its body', async () => {
  let requestEntered;
  let responseClosed;
  const entered = new Promise(resolve => { requestEntered = resolve; });
  const closed = new Promise(resolve => { responseClosed = resolve; });
  const server = http.createServer((request, response) => {
    request.resume();
    response.once('close', responseClosed);
    response.setHeader('content-type', 'application/x-ndjson');
    response.write(`${JSON.stringify({ model: 'fixture', response: 'OK', done: false })}\n`);
    response.write(`${JSON.stringify({ model: 'fixture', done: true })}\n`);
    requestEntered();
  });
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const baseURL = await listen(server);
    const provider = createLangChainProvider({ provider: 'ollama', model: 'fixture', baseURL });
    const controller = new AbortController();
    const pending = provider.generate('abort', {
      signal: controller.signal,
      timeout: 5000,
      ownerId: 'abort-review',
    });
    await within(entered, 1000, 'request admission');
    // Give the SDK time to consume its terminal frame. The public call must
    // still be waiting for the cloned transport body when cancellation lands.
    await new Promise(resolve => setTimeout(resolve, 25));
    controller.abort(Object.assign(new Error('CONTROLLED_ABORT'), { code: 'CONTROLLED_ABORT' }));
    await assert.rejects(within(pending, 1000, 'caller abort'), { code: 'CONTROLLED_ABORT' });
    await within(closed, 1000, 'aborted response close');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
    await close(server);
  }
});
