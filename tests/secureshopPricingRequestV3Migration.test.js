'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { request, requestDigest } = require('../server/services/secureshopPricingContract');

const migrations = path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const source = fs.readFileSync(path.join(migrations, '0078_pricing_compare_request_v3.sql'), 'utf8');
const predecessor = fs.readFileSync(path.join(migrations, '0057_pricing_experiment_request_v2.sql'), 'utf8');
const blockedSuccessor = fs.readFileSync(path.join(migrations, '0081_pricing_blocked_denial_outcome.sql'), 'utf8');
const readiness = fs.readFileSync(path.join(__dirname, '../server/database/postgres/secureshopPricingReadiness.js'), 'utf8');
const body = sql => {
  const match = /CREATE OR REPLACE FUNCTION secureshop_agents\.guard_pricing_actor\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/.exec(sql);
  assert.ok(match);
  return match[1];
};

test('forward Pricing v3 guard changes only the closed comparison branch and readiness hash', () => {
  const old = body(predecessor);
  const current = body(source);
  const branch = "    OR ((SELECT count(*) FROM jsonb_object_keys(NEW.request_json))=5\n      AND NEW.request_json->>'task'='pricing-strategy'\n      AND NEW.request_json ?& ARRAY['operationId','task','productId','message','competitorUrl']\n      AND jsonb_typeof(NEW.request_json->'competitorUrl')='string'\n      AND octet_length(NEW.request_json->>'competitorUrl') BETWEEN 1 AND 2048)\n";
  assert.equal(current.replace(branch, ''), old);
  const digest = createHash('sha256').update(current).digest('hex');
  assert.equal(digest, '92763e6d115dda50cf960912e0da82a4cfd33eb4882d720ceb63512a52835527');
  const currentDigest = createHash('sha256').update(body(blockedSuccessor)).digest('hex');
  assert.match(readiness, new RegExp(`guard_pricing_actor' THEN '${currentDigest}'`));
  assert.doesNotMatch(source, /CREATE\s+(?:TABLE|TRIGGER)|ALTER\s+TABLE|GRANT\s+|REVOKE\s+/i);
});

test('v3 is merchant-only, exact-key and literal URL-bound; v1 and v2 hashes remain distinct', () => {
  const base = { operationId: randomUUID(), task: 'pricing-strategy', productId: 1, message: 'Compare this item.' };
  const v3 = { ...base, competitorUrl: 'http://competitor.example/quote?item=1' };
  assert.deepEqual(request(v3), v3);
  assert.match(requestDigest(v3), /^[0-9a-f]{64}$/);
  assert.notEqual(requestDigest(v3), requestDigest(base));
  assert.notEqual(requestDigest(v3), requestDigest({ ...base, experiment: { strategy: 'undercut', durationDays: 1 } }));
  for (const invalid of [
    { ...v3, task: 'price-advisor' },
    { ...v3, experiment: { strategy: 'undercut', durationDays: 1 } },
    { ...v3, extra: true },
    { ...v3, competitorUrl: '' },
    { ...v3, competitorUrl: 'https://competitor.example/' },
    { ...v3, competitorUrl: 'http://user@competitor.example/' },
    { ...v3, competitorUrl: 'http://competitor.example/#fragment' },
    { ...v3, competitorUrl: `http://competitor.example/${'x'.repeat(2048)}` },
  ]) assert.throws(() => request(invalid), { code: 'PRICING_INVALID_ARGUMENT' });
});
