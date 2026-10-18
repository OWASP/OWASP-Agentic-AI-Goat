const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability insecure-deser-listing-import
 * @teaches OWASP-Web:A08
 * @location agent-host/agents/listing/tools/import_bulk.js
 * JSON payload with __proto__ key reaches an unsafe recursive merge,
 * polluting Object.prototype. This proves the merge primitive, not code execution.
 */
test('insecure-deser-listing-import: __proto__ payload pollutes Object.prototype', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    // Serve a JSON catalog whose element carries a __proto__ pollution payload.
    // JSON.stringify strips __proto__ from a live object, so hand-write the JSON.
    const jsonPayload = '[{"name":"Legit","description":"legit","price":9.99,"__proto__":{"pollutedFlag":"DVAIA-pwn"}}]';
    const server = http.createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(jsonPayload);
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    // Directly exercise the sink helper to keep the assertion clean.
    const { _mergeUnsafe } = require(path.join(REPO, 'agent-host/agents/listing/tools/import_bulk.js'));
    const raw = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${port}/`, (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', c => { buf += c; });
        res.on('end', () => resolve(buf));
      }).on('error', reject);
    });
    await new Promise(resolve => server.close(resolve));

    // Parse with __proto__ handling — JSON.parse forwards it as a normal key
    const parsed = JSON.parse(raw);
    // Assert Object.prototype is NOT polluted before merge (clean baseline).
    assert.equal(({}).pollutedFlag, undefined, 'baseline unpolluted');

    // Now trigger the sink.
    const target = {};
    _mergeUnsafe(target, parsed[0]);

    // Recursive traversal follows target.__proto__ into Object.prototype,
    // so a fresh object inherits the flag. Object.assign alone would only
    // replace the target's prototype; it is not the primitive tested here.
    assert.equal(({}).pollutedFlag, 'DVAIA-pwn', 'Object.prototype polluted (intentional)');
  } finally {
    // Clean up prototype pollution so we don't leak into later tests.
    // eslint-disable-next-line no-proto
    try { delete Object.prototype.pollutedFlag; } catch {}
    await s.close();
  }
});
