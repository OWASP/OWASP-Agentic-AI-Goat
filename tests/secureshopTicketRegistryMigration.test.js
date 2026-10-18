'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const current = require('../server/services/secureshopBoundAclRegistry');
const legacyTools = new Map(require('../server/data/secureshopAgentSeeds').TOOLS);
const postV25Keys = new Set([current.DIAGNOSTIC_PREPARE_KEY, current.MAIL_SUMMARY_KEY,
 current.COUPON_PROBE_KEY, current.PRODUCT_SEARCH_UNION_KEY, current.ARITHMETIC_SUM_KEY,
 current.AVATAR_UPLOAD_KEY, ...current.LISTING_OPTIMIZE_KEYS, current.FILE_SUMMARY_KEY,
 current.USER_LOOKUP_KEY, current.UPLOAD_PREVIEW_KEY, current.AGENCY_ROLE_KEY]);
const postV25Hashes = new Set([current.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,
 current.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256, current.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256,
 current.PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256, current.ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256,
 current.AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256, current.LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256,
 current.FILE_SUMMARY_PREDECESSOR_REGISTRY_SHA256, current.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256,
 current.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256, current.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256]);
const historicalRow = row => Object.freeze({ toolKey: row.toolKey, workflow: null, supported: false,
 roleApplicability: Object.freeze({ customer: false, merchant: false, admin: false }),
 defaultAllowed: Object.freeze(Object.fromEntries(current.ROLES.map(role =>
  [role, legacyTools.get(row.toolKey)?.[role] === true]))),
 unavailableReason: 'No supported bound execution workflow' });
const R = { ...current, REGISTRY_VERSION: 25,
 REGISTRY_SHA256: current.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY: current.REGISTRY.flatMap(row => !postV25Keys.has(row.toolKey)
  ? [row] : legacyTools.has(row.toolKey) ? [historicalRow(row)] : []),
 REGISTRY_UPGRADES: Object.fromEntries(Object.entries(current.REGISTRY_UPGRADES)
  .filter(([hash]) => !postV25Hashes.has(hash))
  .map(([hash, keys]) => [hash, keys.filter(key => !postV25Keys.has(key))])) };
const directory = join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const read = name => readFileSync(join(directory, name), 'utf8');
const digest = value => createHash('sha256').update(value).digest('hex');
const couponMigration = read('0087_customer_coupon_prepare_registry_successor.sql');
const migration = read('0088_customer_ticket_prepare_registry_successor.sql');

function constant(source, name) {
  const match = source.match(new RegExp(`^ ${name} constant text := (E?'(?:''|[^'])*');$`, 'm'));
  assert.ok(match, name);
  const escaped = match[1].startsWith('E');
  const value = match[1].slice(escaped ? 2 : 1, -1).replaceAll("''", "'");
  return escaped ? value.replace(/\\(.)/gs, (_whole, char) => char === 'n' ? '\n' : char) : value;
}

function advance(body, source, previous, current) {
  assert.equal(digest(body), constant(source, 'old_guard_sha256'));
  const edge = constant(source, 'old_edge'), marker = constant(source, previous);
  assert.equal(body.split(edge).length, 2, 'exact historical edge anchor');
  assert.equal(body.split(marker).length, 2, 'exact historical branch anchor');
  const next = body.replace(edge, `${edge}\n${constant(source, 'new_edges')}`)
    .replace(marker, constant(source, current) + marker);
  assert.equal(digest(next), constant(source, 'upgraded_guard_sha256'));
  return next;
}

const v21 = read('0082_merchant_mail_reads_registry_successor.sql')
  .match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)[1];
const v22 = advance(v21, read('0084_merchant_mail_prepare_registry_successor.sql'), 'v21_branch', 'v22_branch');
const v23 = advance(v22, read('0085_merchant_listing_setup_registry_successor.sql'), 'v22_branch', 'v23_branch');
const v24 = advance(v23, couponMigration, 'v23_branch', 'v24_branch');

const v25 = advance(v24, migration, 'v24_branch', 'v25_branch');

test('0088 preserves the complete historical guard and adds only exact v25 registry edges', () => {
  assert.equal((migration.match(/^DO \$\$$/gm) || []).length, 1);
  assert.equal((migration.match(/^END \$\$;$/gm) || []).length, 1);
  assert.equal(R.REGISTRY_VERSION, 25);
  assert.equal(R.REGISTRY_SHA256, '2df507e918c1ecba5d8ebac3a0d0ba63e88909c70f0b37d8c198082cc1baad7d');
  assert.equal(digest(v24), 'a3816517181267a942c742a942ae472a64b21a59068596edb47216bb9f42af6c');
  const marker = constant(migration, 'v24_branch');
  assert.equal(v25.slice(v25.indexOf(marker)), v24.slice(v24.indexOf(marker)));
  const edges = body => [...body.matchAll(/\(encode\(NEW\.predecessor_sha256,'hex'\)='([a-f0-9]{64})' AND encode\(NEW\.successor_sha256,'hex'\)='([a-f0-9]{64})'\)/g)]
    .map(match => match.slice(1).join(':'));
  const oldEdges = edges(v24), newEdges = edges(v25);
  assert.equal(oldEdges.length, 276);
  assert.equal(newEdges.length, 300);
  for (const edge of oldEdges) assert.ok(newEdges.includes(edge));
  assert.deepEqual(newEdges.filter(edge => !oldEdges.includes(edge)).sort(),
    Object.keys(R.REGISTRY_UPGRADES).map(hash => `${hash}:${R.REGISTRY_SHA256}`).sort());
  assert.match(migration, /regexp_count\(constraint_def,'jsonb_array_length'\)<>276/);
  assert.match(migration, /ADD CONSTRAINT bound_tool_registry_successor_v25/);
  assert.match(migration, /DROP CONSTRAINT bound_tool_registry_successor_v24/);
  assert.doesNotMatch(migration, /GRANT\s|CREATE\s+TABLE|INSERT\s+INTO|UPDATE\s+secureshop_agents/i);
  assert.match(migration, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('every published predecessor has exact denials, including one new customer ticket denial', () => {
  assert.deepEqual(R.REGISTRY_UPGRADES[R.TICKET_PREDECESSOR_REGISTRY_SHA256], [R.TICKET_PREPARE_KEY]);
  const row = R.REGISTRY.find(entry => entry.toolKey === R.TICKET_PREPARE_KEY);
  assert.deepEqual(row.roleApplicability, { customer: true, merchant: false, admin: false });
  const sort = (a, b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : a.role < b.role ? -1 : a.role > b.role ? 1 : 0;
  const lengths = [];
  for (const [hash, keys] of Object.entries(R.REGISTRY_UPGRADES)) {
    const denials = R.REGISTRY.filter(entry => keys.includes(entry.toolKey))
      .flatMap(entry => R.ROLES.filter(role => entry.roleApplicability[role])
        .map(role => ({ toolKey: entry.toolKey, role }))).sort(sort);
    assert.ok(v25.includes(`WHEN '${hash}' THEN '${JSON.stringify(denials)}'::jsonb`));
    assert.ok(constant(migration, 'constraint_additions').includes(
      `encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
    assert.deepEqual(denials.filter(denial => denial.toolKey === R.TICKET_PREPARE_KEY),
      [{ toolKey: R.TICKET_PREPARE_KEY, role: 'customer' }]);
    lengths.push(denials.length);
  }
  const prior = read('0087_customer_coupon_prepare_registry_successor.sql')
    .match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  const current = migration.match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  assert.deepEqual(current, [...new Set([...prior, ...lengths])].sort((a, b) => a - b));
  assert.ok(v25.includes('NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials'));
  assert.ok(v25.includes("prior->>'toolKey'=denied.\"toolKey\" AND prior->>'role'=denied.role"));
});


test('historical v25 guard remains distinct from current readiness and private head guard stays unchanged',()=>{
 const readiness=readFileSync(join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert.ok(!readiness.includes(`row.upgrade_guard_sha256!=='${digest(v25)}'`));
 assert.ok(readiness.includes(`bound_tool_registry_successor_v${current.REGISTRY_VERSION}`));
 assert.ok(current.REGISTRY_VERSION>R.REGISTRY_VERSION);
 assert.match(readiness,/row\.head_guard_sha256!=='6830fb9d9680c1150204c3f3991345be6692008cae800e035b5e06e6b1549d95'/);
});
