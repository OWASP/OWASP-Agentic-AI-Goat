'use strict';

const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function fixture() {
  return {
    commerce: {
      state: {
        product: { id: 9, name: 'Desk Lamp', description: 'Warm task lighting' },
        reviews: [
          { id: 1, rating: 5, body: 'Bright and compact' },
          { id: 2, rating: 3, body: 'Useful but warm' },
        ],
      },
      methods: {
        summarizer_summarizeProduct_1: async ({ state }, productId) => (
          productId === state.product.id ? state.product : null
        ),
        summarizer_summarizeReviews_1: async ({ state }, productId, limit) => {
          assert.equal(productId, state.product.id);
          return state.reviews.slice(0, limit);
        },
      },
    },
  };
}

test('summarize_product and summarize_reviews preserve repository-backed content', async () => {
  await withPostgresRepositoryDoubles(fixture(), async (scope) => {
    const { summarizeProduct } = scope.loadFresh('agent-host/agents/summarizer/tools/summarize_product.js');
    const { summarizeReviews } = scope.loadFresh('agent-host/agents/summarizer/tools/summarize_reviews.js');
    const product = await summarizeProduct({ product_id: 9 });
    const reviews = await summarizeReviews({ product_id: 9, k: 2 });

    assert.equal(product.product_id, 9);
    assert.match(product.summary, /Desk Lamp/);
    assert.match(product.summary, /Warm task lighting/);
    assert.equal(reviews.count, 2);
    assert.match(reviews.concatenated_bodies, /Bright and compact/);
    assert.deepEqual(scope.calls.map((call) => call.method), [
      'summarizer_summarizeProduct_1',
      'summarizer_summarizeReviews_1',
    ]);
  });
});

test('summarize_return_policy fetches and returns owned loopback content', async (t) => {
  const body = 'Returns accepted within 30 days with receipt.';
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  await withPostgresRepositoryDoubles({}, async (scope) => {
    const { explainReturnPolicy } = scope.loadFresh('agent-host/agents/summarizer/tools/explain_return_policy.js');
    const address = server.address();
    const result = await explainReturnPolicy({
      policy_url: `http://127.0.0.1:${address.port}/policy`,
    });

    assert.equal(result.status, 200);
    assert.equal(result.body, body);
    assert.deepEqual(scope.calls, []);
  });
});

test('summarize_file reads an owned temporary teaching fixture verbatim', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-summarizer-'));
  const filePath = path.join(directory, 'owned-summary.txt');
  const content = 'Owned teaching fixture\nraw-marker: preserve-me\n';
  fs.writeFileSync(filePath, content, 'utf8');
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  await withPostgresRepositoryDoubles({}, async (scope) => {
    const { summarizeFile } = scope.loadFresh('agent-host/agents/summarizer/tools/summarize_file.js');
    const result = await summarizeFile({ path: filePath });

    assert.equal(result.body, content);
    assert.match(result.summary, /raw-marker: preserve-me/);
    assert.deepEqual(scope.calls, []);
  });
});
