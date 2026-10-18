'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createLangChainProvider, ollamaContextWindow } = require('../server/agent-runtime/providers/langchainProvider');

test('Ollama context window rejects invalid explicit and configured values', () => {
  assert.equal(ollamaContextWindow({}, {}), 8192);
  assert.equal(ollamaContextWindow({}, { OLLAMA_CONTEXT_WINDOW: '16384' }), 16384);
  assert.equal(ollamaContextWindow({ num_ctx: 32768 }, { OLLAMA_CONTEXT_WINDOW: '16384' }), 32768);
  for (const value of [null, 0, -1, 1.5, Infinity, NaN, '0', '8192junk', '', ' 8192', '9007199254740992']) {
    assert.throws(() => ollamaContextWindow({ num_ctx: value }, {}), /positive integer/);
  }
  assert.throws(() => ollamaContextWindow({}, { OLLAMA_CONTEXT_WINDOW: 'bad' }), /positive integer/);
});

test('Ollama generate and chat wire include bounded default, configured, and explicit context', async () => {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    requests.push(JSON.parse(body));
    res.setHeader('content-type', 'application/x-ndjson');
    if (req.url === '/api/generate') res.end(JSON.stringify({ model: 'fixture', response: 'ok', done: false }) + '\n'
      + JSON.stringify({ model: 'fixture', response: '', done: true, done_reason: 'stop' }) + '\n');
    else res.end(JSON.stringify({ model: 'fixture', message: { role: 'assistant', content: 'ok' }, done: false }) + '\n'
      + JSON.stringify({ model: 'fixture', message: { role: 'assistant', content: '' }, done: true, done_reason: 'stop' }) + '\n');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const previous = process.env.OLLAMA_CONTEXT_WINDOW;
  delete process.env.OLLAMA_CONTEXT_WINDOW;
  try {
    const provider = createLangChainProvider({ provider: 'ollama', model: 'fixture', baseURL: `http://127.0.0.1:${server.address().port}` });
    await provider.generate('default', { ownerId: 'context-default' });
    await provider.chat([{ role: 'user', content: 'actor default' }], [], { ownerId: 'context-chat-default' });
    process.env.OLLAMA_CONTEXT_WINDOW = '16384';
    await provider.generate('configured', { ownerId: 'context-configured' });
    await provider.chat([{ role: 'user', content: 'actor configured' }], [], { ownerId: 'context-chat-configured' });
    await provider.generate('explicit', { ownerId: 'context-explicit', num_ctx: 4096 });
    await provider.chat([{ role: 'user', content: 'judge' }], [], { ownerId: 'context-judge', num_ctx: 32768 });
    assert.deepEqual(requests.map(request => request.options.num_ctx), [8192, 8192, 16384, 16384, 4096, 32768]);
  } finally {
    if (previous === undefined) delete process.env.OLLAMA_CONTEXT_WINDOW;
    else process.env.OLLAMA_CONTEXT_WINDOW = previous;
    await new Promise(resolve => server.close(resolve));
  }
});
