'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { parseOwnedListingXml } = require('../sidecars/sandbox-runner/owned-listings/xml-parser');
const document = uri => `<!DOCTYPE products [<!ENTITY lesson SYSTEM "${uri}">]><products><product><name>Owned</name><description>&lesson;</description><price>3.5</price></product></products>`;
test('XML parser resolves actual owned file bytes and records their provenance', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-listing-xml-'));
  try {
    const file = path.join(dir, 'synthetic.txt'); await fs.writeFile(file, 'OWNED_SYNTHETIC_ONLY');
    const result = await parseOwnedListingXml(document('file:///owned/synthetic.txt'), {
      mode: 'vuln', resolveEntity: async uri => { assert.equal(uri, 'file:///owned/synthetic.txt'); return fs.readFile(file); }
    });
    assert.equal(result.products[0].description, 'OWNED_SYNTHETIC_ONLY');
    assert.equal(result.entityReads[0].byteCount, 20);
    assert.match(result.entityReads[0].sha256, /^[a-f0-9]{64}$/);
    assert.ok(Object.isFrozen(result.products));
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('fixed mode denies entity resolution and resolver errors never become success markers', async () => {
  let calls = 0;
  const resolveEntity = async () => { calls++; throw Error('owned endpoint unavailable'); };
  await assert.rejects(parseOwnedListingXml(document('http://owned.internal/data'), { mode: 'fixed', resolveEntity }), { code: 'LISTING_XML_ENTITIES_DISABLED' });
  assert.equal(calls, 0);
  await assert.rejects(parseOwnedListingXml(document('http://owned.internal/data'), { mode: 'vuln', resolveEntity }), /owned endpoint unavailable/);
  assert.equal(calls, 1);
});
test('malformed, ambiguous and excessive XML fails before publication', async () => {
  const options = { mode: 'vuln', resolveEntity: async () => Buffer.from('x') };
  for (const xml of ['<products/>', '<products><product></products>',
    '<products><product><name>a</name><name>b</name></product></products>',
    '<products><product><name><nested>silently lost</nested></name></product></products>',
    '<!DOCTYPE products [<!ENTITY x "internal expansion">]><products><product><name>&x;</name></product></products>',
    '<products>' + '<product><name>x</name></product>'.repeat(101) + '</products>']) {
    await assert.rejects(parseOwnedListingXml(xml, options));
  }
  await assert.rejects(parseOwnedListingXml(document('file:///owned/large'), { ...options, resolveEntity: async () => Buffer.alloc(1024 * 1024) }), { code: 'LISTING_XML_LIMIT' });
});
test('XML rejects silently discarded structure and preserves exact field content', async () => {
 const options={mode:'vuln',resolveEntity:async()=>Buffer.from('  synthetic value\n')};
 for(const xml of [
  '<products><ignored>lost</ignored><product><name>ok</name></product></products>',
  '<products discarded="value"><product><name>ok</name></product></products>',
  '<products><product sku="lost"><name>ok</name></product></products>',
  '<products><product><name language="lost">ok</name></product></products>',
  '<products>lost<product><name>ok</name></product></products>',
  '<products><product>lost<name>ok</name></product></products>'
 ])await assert.rejects(parseOwnedListingXml(xml,options),{code:'LISTING_XML_INVALID'});
 const result=await parseOwnedListingXml(document('file:///owned/value'),options);
 assert.equal(result.products[0].description,'  synthetic value\n');
});
