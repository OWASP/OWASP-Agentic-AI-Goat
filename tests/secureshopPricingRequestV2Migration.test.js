'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { request } = require('../server/services/secureshopPricingContract');

const migration = path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents/0057_pricing_experiment_request_v2.sql');

function guardBody(source) {
  const match = /CREATE OR REPLACE FUNCTION secureshop_agents\.guard_pricing_actor\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/.exec(source);
  assert.ok(match, 'forward migration must replace only the pricing actor trigger');
  return match[1];
}

test('Pricing v2 migration remains immutable and retains the exact reviewed guard', () => {
  const sql = fs.readFileSync(migration, 'utf8');
  const body = guardBody(sql);
  const digest = createHash('sha256').update(body).digest('hex');
  assert.equal(digest, '470f0df88b219e8ba2a36b1fd44dbb21fd33ad62fa09d02ae26c349bc1275800');
  assert.match(body, /COALESCE\(\([\s\S]*\),FALSE\)=FALSE/);
  assert.match(body, /CASE WHEN jsonb_typeof\(NEW\.request_json->'experiment'\)='object' THEN/);
  assert.doesNotMatch(sql, /CREATE\s+(?:TABLE|TRIGGER)|ALTER\s+TABLE|GRANT\s+|REVOKE\s+/i);
});

test('canonical Pricing contract keeps v1 and closed merchant experiment v2 distinct', () => {
  const base = { operationId: randomUUID(), task: 'pricing-strategy', productId: 1, message: 'Run one experiment.' };
  assert.deepEqual(request(base), base);
  assert.deepEqual(request({ ...base, experiment: { strategy: 'undercut', durationDays: 7 } }),
    { ...base, experiment: { strategy: 'undercut', durationDays: 7 } });
  for (const experiment of [
    null, {}, { strategy: 'undercut' }, { durationDays: 7 },
    { strategy: null, durationDays: 7 }, { strategy: 'undercut', durationDays: null },
    { strategy: 'undercut', durationDays: 7, extra: true },
    { strategy: 'undercut', durationDays: 0 }, { strategy: 'undercut', durationDays: 91 },
  ]) assert.throws(() => request({ ...base, experiment }), { code: 'PRICING_INVALID_ARGUMENT' });
  assert.throws(() => request({ ...base, extra: true }), { code: 'PRICING_INVALID_ARGUMENT' });
  assert.throws(() => request({ ...base, task: 'price-advisor', experiment: { strategy: 'undercut', durationDays: 7 } }),
    { code: 'PRICING_INVALID_ARGUMENT' });
});
