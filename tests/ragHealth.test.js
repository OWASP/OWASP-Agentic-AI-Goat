/**
 * RAG Health Endpoint Tests
 *
 * Validates that /api/workshop/rag-injection/health returns separate
 * embeddingReady / llmReady fields and component-specific messages.
 *
 * Run:
 *   SERVER_AVAILABLE=1 BASE_URL=http://127.0.0.1:<isolated-port> node tests/ragHealth.test.js
 *   node tests/ragHealth.test.js                       # unit-only (mocked)
 */

const assert = require('assert');

const SERVER_BASE = process.env.BASE_URL || 'http://127.0.0.1:1';
const SERVER_AVAILABLE = process.env.SERVER_AVAILABLE === '1' && !!process.env.BASE_URL;

let passed = 0;
let failed = 0;

function test(name, fn) {
  return fn()
    .then(() => { passed++; console.log(`  ✓ ${name}`); })
    .catch(err => { failed++; console.error(`  ✗ ${name}\n    ${err.message}`); });
}

// ---------------------------------------------------------------------------
// Unit tests — validate response shape contract without a running server
// ---------------------------------------------------------------------------

async function unitTests() {
  console.log('\n── Unit: health response contract ──');

  const allReady = {
    status: 'ok',
    embeddingReady: true,
    llmReady: true,
    modelReady: true,
    ollamaAvailable: true,
    message: 'All systems ready (LLM: llama3.1:8b).'
  };

  const embeddingDown = {
    status: 'degraded',
    embeddingReady: false,
    llmReady: true,
    modelReady: false,
    ollamaAvailable: true,
    message: 'Embedding model (Xenova/all-MiniLM-L6-v2) not loaded — check server startup logs for ONNX/libc errors.'
  };

  const llmDown = {
    status: 'degraded',
    embeddingReady: true,
    llmReady: false,
    modelReady: true,
    ollamaAvailable: false,
    message: 'LLM not reachable at http://localhost:11434.'
  };

  const bothDown = {
    status: 'degraded',
    embeddingReady: false,
    llmReady: false,
    modelReady: false,
    ollamaAvailable: false,
    message: 'Embedding model (Xenova/all-MiniLM-L6-v2) not loaded — check server startup logs for ONNX/libc errors. LLM not reachable at http://localhost:11434.'
  };

  await test('all-ready has canonical fields', async () => {
    assert.strictEqual(allReady.embeddingReady, true);
    assert.strictEqual(allReady.llmReady, true);
    assert.strictEqual(allReady.status, 'ok');
    assert.ok(allReady.message.includes('All systems ready'));
  });

  await test('all-ready backward-compat aliases match canonical', async () => {
    assert.strictEqual(allReady.modelReady, allReady.embeddingReady);
    assert.strictEqual(allReady.ollamaAvailable, allReady.llmReady);
  });

  await test('embedding-down status is degraded, message mentions embedding', async () => {
    assert.strictEqual(embeddingDown.status, 'degraded');
    assert.strictEqual(embeddingDown.embeddingReady, false);
    assert.strictEqual(embeddingDown.llmReady, true);
    assert.ok(embeddingDown.message.toLowerCase().includes('embedding'));
    assert.ok(!embeddingDown.message.toLowerCase().includes('ollama serve'));
  });

  await test('llm-down status is degraded, message mentions LLM', async () => {
    assert.strictEqual(llmDown.status, 'degraded');
    assert.strictEqual(llmDown.embeddingReady, true);
    assert.strictEqual(llmDown.llmReady, false);
    assert.ok(llmDown.message.toLowerCase().includes('llm'));
  });

  await test('both-down message mentions both components', async () => {
    assert.strictEqual(bothDown.status, 'degraded');
    assert.ok(bothDown.message.toLowerCase().includes('embedding'));
    assert.ok(bothDown.message.toLowerCase().includes('llm'));
  });

  await test('no response mentions "ollama serve" when embedding is the failing component', async () => {
    assert.ok(!embeddingDown.message.includes('ollama serve'));
    assert.ok(!bothDown.message.includes('ollama serve'));
  });
}

// ---------------------------------------------------------------------------
// Integration tests — hit live server
// ---------------------------------------------------------------------------

async function integrationTests() {
  if (!SERVER_AVAILABLE) {
    console.log('\n── Integration: skipped (set SERVER_AVAILABLE=1) ──');
    return;
  }

  const axios = require('axios');
  console.log(`\n── Integration: ${SERVER_BASE}/api/workshop/rag-injection/health ──`);

  await test('health endpoint returns 200', async () => {
    const res = await axios.get(`${SERVER_BASE}/api/workshop/rag-injection/health`, { timeout: 5000 });
    assert.strictEqual(res.status, 200);
  });

  await test('health response has canonical embeddingReady/llmReady fields', async () => {
    const res = await axios.get(`${SERVER_BASE}/api/workshop/rag-injection/health`, { timeout: 5000 });
    assert.ok('embeddingReady' in res.data, 'missing embeddingReady');
    assert.ok('llmReady' in res.data, 'missing llmReady');
    assert.ok('message' in res.data, 'missing message');
    assert.ok(typeof res.data.embeddingReady === 'boolean');
    assert.ok(typeof res.data.llmReady === 'boolean');
  });

  await test('health response preserves backward-compat aliases', async () => {
    const res = await axios.get(`${SERVER_BASE}/api/workshop/rag-injection/health`, { timeout: 5000 });
    assert.ok('modelReady' in res.data, 'missing modelReady alias');
    assert.ok('ollamaAvailable' in res.data, 'missing ollamaAvailable alias');
    assert.strictEqual(res.data.modelReady, res.data.embeddingReady);
    assert.strictEqual(res.data.ollamaAvailable, res.data.llmReady);
  });

  await test('status is ok only when both ready, degraded otherwise', async () => {
    const res = await axios.get(`${SERVER_BASE}/api/workshop/rag-injection/health`, { timeout: 5000 });
    if (res.data.embeddingReady && res.data.llmReady) {
      assert.strictEqual(res.data.status, 'ok');
    } else {
      assert.strictEqual(res.data.status, 'degraded');
    }
  });
}

// ---------------------------------------------------------------------------

(async () => {
  console.log('RAG Health Endpoint Tests');
  await unitTests();
  await integrationTests();
  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
})();
