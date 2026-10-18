'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { SCAN_DIRS, TEST_DIR, walk, extractTags } = require('../../../scripts/generate-vuln-map.js');
const { collectTags } = require('../../../scripts/verify-secureshop-vuln-coverage.js');

test('coverage verifier and map generator share strict annotation parsing', () => {
  assert.deepEqual(extractTags('See @intentional-vulnerability below.\n// @intentional-vulnerability real-tag'), [{ id: 'real-tag', teaches: null }]);
  const codeTags = collectTags(SCAN_DIRS.flatMap(dir => walk(dir)));
  const testTags = collectTags(walk(TEST_DIR));
  for (const id of ['llm03-supply-chain', 'path-traversal', 'sqli-coupon', 'xss-stored-review']) {
    assert.ok(codeTags.has(id), `${id} is in generated source inventory`);
    assert.ok(testTags.has(id), `${id} has a behavioral proof annotation`);
  }
  for (const noise of ['below', 'comment', 'header', 'in']) {
    assert.equal(codeTags.has(noise), false, `prose token ${noise} is ignored`);
  }
});

test('strict parser requires a complete hyphenated annotation line', () => {
  const source = fs.readFileSync(path.join(__dirname, '../../../agent-host/agents/email/server.js'), 'utf8');
  assert.equal(extractTags(source).some(tag => tag.id === 'separate'), false);
});
