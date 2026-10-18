'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const worker = path.resolve(__dirname, '../sidecars/sandbox-runner/owned-listings/json-worker.js');
function run(input, mode = 'vuln') {
  const result = spawnSync(process.execPath, [worker, mode], { input, encoding: 'utf8', timeout: 2000, maxBuffer: 3 * 1024 * 1024 });
  assert.equal(result.error, undefined);
  return result;
}
test('actual prototype mutation stays in a disposable worker and fixed mode rejects its effect', () => {
  const input = '{"name":"Synthetic product","__proto__":{"listingTeachingMarker":"owned-only"}}';
  const vulnerable = run(input);
  assert.equal(vulnerable.status, 0, vulnerable.stderr);
  const result = JSON.parse(vulnerable.stdout);
  assert.equal(result.prototypeEffect.observed, true);
  assert.equal(result.prototypeEffect.inheritedProperties[0].name, 'listingTeachingMarker');
  assert.match(result.prototypeEffect.inheritedProperties[0].valueSha256, /^[a-f0-9]{64}$/);
  assert.equal(({}).listingTeachingMarker, undefined, 'parent process remains untouched');
  const fixed = run(input, 'fixed'); assert.equal(fixed.status, 0, fixed.stderr);
  assert.equal(JSON.parse(fixed.stdout).prototypeEffect.observed, false);
  const later = run('{"name":"Clean product"}'); assert.equal(later.status, 0, later.stderr);
  assert.equal(JSON.parse(later.stdout).prototypeEffect.observed, false, 'fresh worker does not inherit prior mutation');
});
test('invalid, oversized and excessively nested imports produce no product result', () => {
  const deep = JSON.stringify({ name: 'Deep', value: JSON.parse('['.repeat(34) + '0' + ']'.repeat(34)) });
  for (const input of ['{broken', '[]', '{"price":2}', JSON.stringify(Array.from({ length: 101 }, () => ({ name: 'p' }))), deep, ' '.repeat(1024 * 1024 + 1)]) {
    const result = run(input);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(JSON.parse(result.stderr).code, /^LISTING_JSON_/);
  }
});
test('overwriting an existing inherited property is recorded as an actual pollution effect', () => {
  const result = run('{"name":"Synthetic","__proto__":{"toString":"owned replacement"}}');
  assert.equal(result.status, 0, result.stderr);
  const effect = JSON.parse(result.stdout).prototypeEffect;
  assert.equal(effect.observed, true);
  assert.equal(effect.inheritedProperties[0].name, 'toString');
  assert.equal(typeof ({}).toString, 'function');
});

test('owned supplier prototype route bytes cause only the disposable vulnerable parser effect', () => {
  const { prototypeResponse } = require('../sidecars/sandbox-runner/owned-listings/namespace-worker');
  for (const args of [[0,'GET','/prototype.json'],[1,'GET','/prototype.json'],[2,'GET','/prototype.json'],[3,'POST','/prototype.json'],[3,'GET','/prototype.json?x=1'],[3,'GET','/unknown']]) assert.equal(prototypeResponse(...args), null);
  const bytes = prototypeResponse(3,'GET','/prototype.json');
  assert.ok(Buffer.isBuffer(bytes) && bytes.length < 1024);
  assert.equal(Object.hasOwn(JSON.parse(bytes).products[0], '__proto__'), true);
  const vulnerable = run(bytes);assert.equal(vulnerable.status,0,vulnerable.stderr);
  const effect = JSON.parse(vulnerable.stdout).prototypeEffect;
  assert.deepEqual(effect.inheritedProperties,[{name:'listingTrainingMarker',valueSha256:require('node:crypto').createHash('sha256').update(JSON.stringify('owned-only')).digest('hex')}]);
  assert.equal(effect.observed,true);assert.equal(({}).listingTrainingMarker,undefined);
  const fixed = run(bytes,'fixed');assert.equal(fixed.status,0,fixed.stderr);assert.equal(JSON.parse(fixed.stdout).prototypeEffect.observed,false);
  bytes.fill(0);assert.ok(prototypeResponse(3,'GET','/prototype.json').toString().includes('Prototype training lamp'));
});
