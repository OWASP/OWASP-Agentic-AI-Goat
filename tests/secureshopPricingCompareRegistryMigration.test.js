'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const {
  REGISTRY, BASE_REGISTRY_UPGRADES, MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,
  PRICING_COMPARE_PREPARE_KEY, PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,
} = require('../server/services/secureshopBoundAclRegistry');

const directory = path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const predecessor = fs.readFileSync(path.join(directory, '0076_admin_management_prepare_registry_successor.sql'), 'utf8');
const migration = fs.readFileSync(path.join(directory, '0079_pricing_compare_prepare_registry_successor.sql'), 'utf8');
const readiness = fs.readFileSync(path.join(__dirname, '../server/database/postgres/secureshopBoundToolPolicyReadiness.js'), 'utf8');
const guard = source => {
  const match = /CREATE OR REPLACE FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/.exec(source);
  assert.ok(match);
  return match[1];
};

test('v19 pins its exact registry guard, retains historical edges and adds only legal successor edges', () => {
  const old = guard(predecessor);
  const current = guard(migration);
  const digest = createHash('sha256').update(current).digest('hex');
  assert.equal(digest, '3196e9f3c519372ca760223a952889a6688451370cf5cf41c5a6bbbb3cf577ba');
  assert.equal(PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256, 'e01641f40076b2de5a3b250ef5e62156ae9fca0752c467cfeee5e9ff846f8c83');
  assert.match(migration, /DROP CONSTRAINT bound_tool_registry_successor_v18/);
  assert.match(migration, /ADD CONSTRAINT bound_tool_registry_successor_v19 CHECK/);
  assert.match(readiness, /bound_tool_registry_successor_v37/);
  assert.doesNotMatch(migration, /GRANT\s+|REVOKE\s+|CREATE\s+TABLE/i);
  const priorPairs = [...old.matchAll(/OR \(encode\(NEW\.predecessor_sha256,'hex'\)='([0-9a-f]{64})' AND encode\(NEW\.successor_sha256,'hex'\)='([0-9a-f]{64})'\)/g)]
    .map(match => `${match[1]}:${match[2]}`);
  for (const pair of priorPairs) assert.ok(current.includes(pair.split(':').map((sha, index) =>
    index ? `encode(NEW.successor_sha256,'hex')='${sha}'` : `encode(NEW.predecessor_sha256,'hex')='${sha}'`).join(' AND ')));
  assert.equal((current.match(/encode\(NEW\.successor_sha256,'hex'\)='ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf'\)/g) || []).length,
    Object.keys(BASE_REGISTRY_UPGRADES).length);
});

test('every predecessor adds the one comparison denial without changing old override evidence', () => {
  const row = REGISTRY.find(entry => entry.toolKey === PRICING_COMPARE_PREPARE_KEY);
  assert.deepEqual(row.roleApplicability, { customer: false, merchant: true, admin: false });
  assert.deepEqual(row.defaultAllowed, row.roleApplicability);
  assert.deepEqual(BASE_REGISTRY_UPGRADES[PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256], [PRICING_COMPARE_PREPARE_KEY]);
  for (const [prior, keys] of Object.entries(BASE_REGISTRY_UPGRADES)) {
    assert.equal(keys.filter(key => key === PRICING_COMPARE_PREPARE_KEY).length, 1, prior);
    const added = REGISTRY.filter(entry => keys.includes(entry.toolKey))
      .flatMap(entry => ['customer', 'merchant', 'admin'].filter(role => entry.roleApplicability[role])
        .map(role => ({ toolKey: entry.toolKey, role })));
    assert.match(migration, new RegExp(`WHEN '${prior}' THEN '${JSON.stringify(added).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'::jsonb`));
    assert.match(migration, new RegExp(`encode\\(predecessor_sha256,'hex'\\)='${prior}' AND encode\\(successor_sha256,'hex'\\)='${MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length\\(added_denials\\)=${added.length}`));
  }
});
