const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm08-embedding-inversion
 * @teaches OWASP-LLM:LLM08
 * @location server/services/secureshop/vectorStore.js
 * @location agent-host/agents/uploads/tools/index.js
 *
 * Stable legacy ID: the observed mechanism is unprotected plaintext RAG
 * retrieval, NOT vector-only inversion or model-training-data extraction.
 * A topic-only query must disclose a previously unknown synthetic secret.
 */
test('llm08-embedding-inversion (legacy ID): topic-only retrieval exposes a synthetic manual secret', async (t) => {
  const names = ['SECURESHOP_UPLOAD_ROOT', 'SS_VECTOR_INDEX_DIR', 'SS_EMBED_PROVIDER',
    'SS_DISABLE_OLLAMA'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  const ownedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-embedding-inversion-'));
  process.env.SECURESHOP_UPLOAD_ROOT = path.join(ownedRoot, 'uploads');
  process.env.SS_VECTOR_INDEX_DIR = path.join(ownedRoot, 'indexes');
  process.env.SS_EMBED_PROVIDER = 'hash';
  purgeToolCaches();
  try {
    const uploads = require(path.join(REPO, 'agent-host/agents/uploads/tools/index.js'));
    const { VectorStore } = require(path.join(REPO, 'server/services/secureshop/vectorStore.js'));
    const query = 'internal account recovery operations manual';
    const secret = 'synthetic-marker-' + crypto.randomBytes(16).toString('hex');
    const queryTokens = new Set(query.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
    assert.ok(secret.toLowerCase().split(/[^a-z0-9]+/).every(token => !queryTokens.has(token)));
    const publicManual = await uploads.upload_product_manual({
      product_id: 11, filename: 'public.txt', mime: 'text/plain',
      file_bytes_base64: Buffer.from('Public product cleaning instructions. Wash the coffee mug.').toString('base64'),
    });
    assert.equal(publicManual.ok, true);
    const before = await new VectorStore({ corpus: 'manuals' }).search(query, 1);
    assert.equal(JSON.stringify(before).includes(secret), false);

    const victimBody = `Internal account recovery operations manual. Recovery token: ${secret}.`;
    const uploaded = await uploads.upload_product_manual({
      product_id: 42, filename: 'ops.txt', mime: 'text/plain',
      file_bytes_base64: Buffer.from(victimBody).toString('base64'),
    });
    assert.equal(uploaded.ok, true);
    assert.equal(fs.readFileSync(uploaded.written_path, 'utf8'), victimBody);
    assert.equal(uploaded.chunk_count, 1);
    assert.equal(uploaded.indexed_corpus, 'manuals');
    assert.equal(Object.hasOwn(uploaded, 'embedding'), false);
    const results = await new VectorStore({ corpus: 'manuals' }).search(query, 1);
    assert.equal(results.length, 1);
    assert.equal(results[0].sourceId, 42);
    assert.equal(results[0].text, victimBody);
    assert.ok(results[0].text.includes(secret), 'topic query discloses the unknown seeded token');
    assert.ok(Number.isFinite(results[0].score));
  } finally {
    fs.rmSync(ownedRoot, { recursive: true, force: true });
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
    purgeToolCaches();
  }
});
