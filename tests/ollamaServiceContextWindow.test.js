'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const logsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-ollama-context-'));
process.env.LOGS_DIR = logsDir;
const { OllamaService } = require('../server/services/ollamaService');

test('direct Ollama service uses the shared requested context and preserves lesson-specific bounds', async () => {
  const previous = process.env.OLLAMA_CONTEXT_WINDOW;
  delete process.env.OLLAMA_CONTEXT_WINDOW;
  const calls = [];
  const service = new OllamaService('http://unused.fixture', {
    providerFactory: () => ({ async generate(prompt, options) {
      calls.push({ prompt, options });
      return { response: 'Step 1: controlled response', metadata: {}, tokens: 1 };
    } }),
  });
  try {
    assert.equal(service.getModelCapabilities().requested_defaults.context_window, 8192);
    assert.equal((await service.generateResponse('default')).success, true);
    assert.equal(calls.at(-1).options.num_ctx, 8192);
    await service.generateResponse('explicit', { num_ctx: 4096 });
    assert.equal(calls.at(-1).options.num_ctx, 4096);

    await service.processChainOfThoughtAttack('controlled');
    assert.equal(calls.at(-1).options.num_ctx, 8192);
    await service.processMultiTurnJailbreak([], 'controlled', { num_ctx: 3072 });
    assert.equal(calls.at(-1).options.num_ctx, 3072);

    const short = await service.processContextStuffing('question', 'short');
    assert.equal(short.max_context, 8192);
    assert.equal(calls.at(-1).options.num_ctx, Math.min(8192, short.context_length + 1000));
    const long = await service.processContextStuffing('question', 'x'.repeat(12000));
    assert.equal(long.max_context, 8192);
    assert.equal(long.overflow_risk, true);
    assert.equal(calls.at(-1).options.num_ctx, 8192);

    process.env.OLLAMA_CONTEXT_WINDOW = '16384';
    assert.equal(service.getModelCapabilities().requested_defaults.context_window, 16384);
    await service.generateResponse('configured');
    assert.equal(calls.at(-1).options.num_ctx, 16384);
    await service.processChainOfThoughtAttack('configured', { num_ctx: 2048 });
    assert.equal(calls.at(-1).options.num_ctx, 2048);
    const configured = await service.processContextStuffing('question', 'x'.repeat(12000));
    assert.equal(configured.max_context, 16384);
    assert.equal(calls.at(-1).options.num_ctx, Math.min(16384, configured.context_length + 1000));
    const explicit = await service.processContextStuffing('question', 'x'.repeat(12000), { num_ctx: 4096 });
    assert.equal(explicit.max_context, 4096);
    assert.equal(calls.at(-1).options.num_ctx, 4096);

    await assert.rejects(service.generateResponse('invalid', { num_ctx: 0 }), /positive integer/);
    process.env.OLLAMA_CONTEXT_WINDOW = 'invalid';
    assert.throws(() => service.getModelCapabilities(), /positive integer/);
  } finally {
    if (previous === undefined) delete process.env.OLLAMA_CONTEXT_WINDOW;
    else process.env.OLLAMA_CONTEXT_WINDOW = previous;
    fs.rmSync(logsDir, { recursive: true, force: true });
  }
});
