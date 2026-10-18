'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const latest = require('../server/services/secureshopBoundAclRegistry');
const { registryV29Rows } = require('./helpers/secureshopHistoricalRegistry');
const legacyDefaults = new Map([
 ['cart.apply_coupon', { customer:true, merchant:false, admin:true }],
 ['product-search.search', { customer:true, merchant:true, admin:true }],
]);
const R = { ...latest, REGISTRY_VERSION:26, REGISTRY_SHA256:latest.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY:registryV29Rows(latest.REGISTRY).map(row=>legacyDefaults.has(row.toolKey)?{
  toolKey:row.toolKey,workflow:null,supported:false,
  roleApplicability:{customer:false,merchant:false,admin:false},
  defaultAllowed:legacyDefaults.get(row.toolKey),
  unavailableReason:'No supported bound execution workflow',
 }:row).filter(row=>row.toolKey!==latest.MAIL_SUMMARY_KEY),
 REGISTRY_UPGRADES:Object.fromEntries(Object.entries(latest.PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES)
  .filter(([hash])=>hash!==latest.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256
   &&hash!==latest.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256)
  .map(([hash,keys])=>[hash,keys.filter(key=>key!==latest.MAIL_SUMMARY_KEY)])) };
const directory = join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const read = name => readFileSync(join(directory, name), 'utf8');
const digest = value => createHash('sha256').update(value).digest('hex');
const couponMigration = read('0087_customer_coupon_prepare_registry_successor.sql');
const ticketMigration = read('0088_customer_ticket_prepare_registry_successor.sql');
const migration = read('0089_admin_system_diagnostic_prepare_registry_successor.sql');

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

const v25 = advance(v24, ticketMigration, 'v24_branch', 'v25_branch');
const v26 = advance(v25, migration, 'v25_branch', 'v26_branch');

test('0089 preserves the complete historical guard and adds only exact v26 registry edges', () => {
  assert.equal((migration.match(/^DO \$\$$/gm) || []).length, 1);
  assert.equal((migration.match(/^END \$\$;$/gm) || []).length, 1);
  assert.equal(R.REGISTRY_VERSION, 26);
  assert.equal(R.REGISTRY_SHA256, '5aa6284201a2d234efd7dbe2d2d31599e1e167f410d23aa8b2890f48c561ee9b');
  assert.equal(digest(v25), '47f07012763e1aa5cdb185e2a021266d60a561533003d6c7c4620f7a9a9c603c');
  const marker = constant(migration, 'v25_branch');
  assert.equal(v26.slice(v26.indexOf(marker)), v25.slice(v25.indexOf(marker)));
  const edges = body => [...body.matchAll(/\(encode\(NEW\.predecessor_sha256,'hex'\)='([a-f0-9]{64})' AND encode\(NEW\.successor_sha256,'hex'\)='([a-f0-9]{64})'\)/g)]
    .map(match => match.slice(1).join(':'));
  const oldEdges = edges(v25), newEdges = edges(v26);
  assert.equal(oldEdges.length, 300);
  assert.equal(newEdges.length, 325);
  for (const edge of oldEdges) assert.ok(newEdges.includes(edge));
  assert.deepEqual(newEdges.filter(edge => !oldEdges.includes(edge)).sort(),
    Object.keys(R.REGISTRY_UPGRADES).map(hash => `${hash}:${R.REGISTRY_SHA256}`).sort());
  assert.match(migration, /regexp_count\(constraint_def,'jsonb_array_length'\)<>300/);
  assert.match(migration, /ADD CONSTRAINT bound_tool_registry_successor_v26/);
  assert.match(migration, /DROP CONSTRAINT bound_tool_registry_successor_v25/);
  assert.doesNotMatch(migration, /GRANT\s|CREATE\s+TABLE|INSERT\s+INTO|UPDATE\s+secureshop_agents/i);
  assert.match(migration, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('every published predecessor has exact denials, including one new admin diagnostic denial', () => {
  assert.deepEqual(R.REGISTRY_UPGRADES[R.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256], [R.DIAGNOSTIC_PREPARE_KEY]);
  const row = R.REGISTRY.find(entry => entry.toolKey === R.DIAGNOSTIC_PREPARE_KEY);
  assert.deepEqual(row.roleApplicability, { customer: false, merchant: false, admin: true });
  const sort = (a, b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : a.role < b.role ? -1 : a.role > b.role ? 1 : 0;
  const lengths = [];
  for (const [hash, keys] of Object.entries(R.REGISTRY_UPGRADES)) {
    const denials = R.REGISTRY.filter(entry => keys.includes(entry.toolKey))
      .flatMap(entry => R.ROLES.filter(role => entry.roleApplicability[role])
        .map(role => ({ toolKey: entry.toolKey, role }))).sort(sort);
    assert.ok(v26.includes(`WHEN '${hash}' THEN '${JSON.stringify(denials)}'::jsonb`));
    assert.ok(constant(migration, 'constraint_additions').includes(
      `encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
    assert.deepEqual(denials.filter(denial => denial.toolKey === R.DIAGNOSTIC_PREPARE_KEY),
      [{ toolKey: R.DIAGNOSTIC_PREPARE_KEY, role: 'admin' }]);
    lengths.push(denials.length);
  }
  const prior = read('0088_customer_ticket_prepare_registry_successor.sql')
    .match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  const current = migration.match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  assert.deepEqual(current, [...new Set([...prior, ...lengths])].sort((a, b) => a - b));
  assert.ok(v26.includes('NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials'));
  assert.ok(v26.includes("prior->>'toolKey'=denied.\"toolKey\" AND prior->>'role'=denied.role"));
});


test('v26 readiness pins the exact private guard; fresh admin only and exact v25 reconstruction',()=>{
 const readiness=readFileSync(join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert.equal(constant(migration, 'upgraded_guard_sha256'), digest(v26));
 assert.match(migration,/bound_tool_registry_successor_v26/);
 assert.match(readiness,/row\.head_guard_sha256!=='6830fb9d9680c1150204c3f3991345be6692008cae800e035b5e06e6b1549d95'/);
 const row=R.REGISTRY.find(row=>row.toolKey===R.DIAGNOSTIC_PREPARE_KEY);
 assert.equal(row.workflow,'admin-assistant');
 assert.deepEqual(row.defaultAllowed,{customer:false,merchant:false,admin:true});
 assert.equal(digest(JSON.stringify({version:25,rows:R.REGISTRY.filter(row=>row.toolKey!==R.DIAGNOSTIC_PREPARE_KEY)})),R.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256);
});
