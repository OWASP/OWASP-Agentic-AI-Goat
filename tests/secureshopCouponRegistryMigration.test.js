'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const latest = require('../server/services/secureshopBoundAclRegistry');
const laterKeys = new Set([latest.TICKET_PREPARE_KEY, latest.DIAGNOSTIC_PREPARE_KEY,
  latest.MAIL_SUMMARY_KEY, latest.COUPON_PROBE_KEY, latest.PRODUCT_SEARCH_UNION_KEY,
  latest.ARITHMETIC_SUM_KEY, latest.AVATAR_UPLOAD_KEY, ...latest.LISTING_OPTIMIZE_KEYS,
  latest.FILE_SUMMARY_KEY, latest.USER_LOOKUP_KEY, latest.UPLOAD_PREVIEW_KEY, latest.AGENCY_ROLE_KEY, latest.MCP_REGISTRATION_KEY]);
const laterPredecessors = new Set([latest.TICKET_PREDECESSOR_REGISTRY_SHA256,
  latest.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256, latest.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256,
  latest.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256, latest.PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256,
  latest.ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256, latest.AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256,
  latest.LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256, latest.FILE_SUMMARY_PREDECESSOR_REGISTRY_SHA256,
  latest.USER_LOOKUP_PREDECESSOR_REGISTRY_SHA256, latest.UPLOAD_PREVIEW_PREDECESSOR_REGISTRY_SHA256,
  latest.AGENCY_ROLE_PREDECESSOR_REGISTRY_SHA256, latest.MCP_REGISTRATION_PREDECESSOR_REGISTRY_SHA256]);
const R = {...latest, REGISTRY_VERSION:24, REGISTRY_SHA256:latest.TICKET_PREDECESSOR_REGISTRY_SHA256,
  REGISTRY:latest.REGISTRY.filter(row=>!laterKeys.has(row.toolKey)),
  REGISTRY_UPGRADES:Object.fromEntries(Object.entries(latest.REGISTRY_UPGRADES)
    .filter(([hash])=>!laterPredecessors.has(hash))
    .map(([hash,keys])=>[hash,keys.filter(key=>!laterKeys.has(key))]))};
const directory = join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const read = name => readFileSync(join(directory, name), 'utf8');
const digest = value => createHash('sha256').update(value).digest('hex');
const migration = read('0087_customer_coupon_prepare_registry_successor.sql');

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
const v24 = advance(v23, migration, 'v23_branch', 'v24_branch');

test('0087 preserves the complete historical guard and adds only exact v24 registry edges', () => {
  assert.equal((migration.match(/^DO \$\$$/gm) || []).length, 1);
  assert.equal((migration.match(/^END \$\$;$/gm) || []).length, 1);
  assert.equal(R.REGISTRY_VERSION, 24);
  assert.equal(R.REGISTRY_SHA256, '1744f9c32cc93cf6708d6512288313c833fce84ca5496515f6155c50d1a39fff');
  assert.equal(digest(v23), '06c33ce3114d68003f0271384d4524f0a1a7256adc5a172c333513a433b8d02b');
  const marker = constant(migration, 'v23_branch');
  assert.equal(v24.slice(v24.indexOf(marker)), v23.slice(v23.indexOf(marker)));
  const edges = body => [...body.matchAll(/\(encode\(NEW\.predecessor_sha256,'hex'\)='([a-f0-9]{64})' AND encode\(NEW\.successor_sha256,'hex'\)='([a-f0-9]{64})'\)/g)]
    .map(match => match.slice(1).join(':'));
  const oldEdges = edges(v23), newEdges = edges(v24);
  assert.equal(oldEdges.length, 253);
  assert.equal(newEdges.length, 276);
  for (const edge of oldEdges) assert.ok(newEdges.includes(edge));
  assert.deepEqual(newEdges.filter(edge => !oldEdges.includes(edge)).sort(),
    Object.keys(R.REGISTRY_UPGRADES).map(hash => `${hash}:${R.REGISTRY_SHA256}`).sort());
  assert.match(migration, /regexp_count\(constraint_def,'jsonb_array_length'\)<>253/);
  assert.match(migration, /ADD CONSTRAINT bound_tool_registry_successor_v24/);
  assert.match(migration, /DROP CONSTRAINT bound_tool_registry_successor_v23/);
  assert.doesNotMatch(migration, /GRANT\s|CREATE\s+TABLE|INSERT\s+INTO|UPDATE\s+secureshop_agents/i);
  assert.match(migration, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('every published predecessor has exact denials, including one new customer coupon denial', () => {
  assert.deepEqual(R.REGISTRY_UPGRADES[R.COUPON_PREDECESSOR_REGISTRY_SHA256], [R.COUPON_PREPARE_KEY]);
  const row = R.REGISTRY.find(entry => entry.toolKey === R.COUPON_PREPARE_KEY);
  assert.deepEqual(row.roleApplicability, { customer: true, merchant: false, admin: false });
  const sort = (a, b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : a.role < b.role ? -1 : a.role > b.role ? 1 : 0;
  const lengths = [];
  for (const [hash, keys] of Object.entries(R.REGISTRY_UPGRADES)) {
    const denials = R.REGISTRY.filter(entry => keys.includes(entry.toolKey))
      .flatMap(entry => R.ROLES.filter(role => entry.roleApplicability[role])
        .map(role => ({ toolKey: entry.toolKey, role }))).sort(sort);
    assert.ok(v24.includes(`WHEN '${hash}' THEN '${JSON.stringify(denials)}'::jsonb`));
    assert.ok(constant(migration, 'constraint_additions').includes(
      `encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
    assert.deepEqual(denials.filter(denial => denial.toolKey === R.COUPON_PREPARE_KEY),
      [{ toolKey: R.COUPON_PREPARE_KEY, role: 'customer' }]);
    lengths.push(denials.length);
  }
  const prior = read('0085_merchant_listing_setup_registry_successor.sql')
    .match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  const current = migration.match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  assert.deepEqual(current, [...new Set([...prior, ...lengths])].sort((a, b) => a - b));
  assert.ok(v24.includes('NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials'));
  assert.ok(v24.includes("prior->>'toolKey'=denied.\"toolKey\" AND prior->>'role'=denied.role"));
});

test('the gated native fixture executes current accounting while keeping historical keys separate', () => {
  const nativePath = join(__dirname, 'postgres/secureshopBoundAclFoundation.integration.test.js');
  const source = readFileSync(nativePath, 'utf8');
  const start = source.indexOf(' const {REGISTRY_SHA256,');
  const end = source.indexOf(' const denialsFor=', start);
  assert.ok(start >= 0 && end > start);
  // Execute the actual fixture's pure accounting block without its gated DB
  // body. This catches drift hidden by the expected no-resource native skip.
  const pureAccounting = source.slice(start, end)
    .replace(/^ assert\.deepEqual\(actualDenialCounts,.*$/gm, '')
    .replace(/^ assert\.equal\(Object\.keys\(actualDenialCounts\).*$/gm, '');
  const accounting = require('node:vm').runInThisContext('(function(require,assert){'
    + pureAccounting
    + '\nreturn {actualDenialCounts,currentAddedKeys,historicalAddedKeys};})',
  { timeout: 1000 });
  const result = accounting(require('node:module').createRequire(nativePath), assert);
  const denialCounts = Object.fromEntries(Object.entries(latest.REGISTRY_UPGRADES).map(([hash,keys])=>[
    hash,latest.REGISTRY.filter(row=>keys.includes(row.toolKey))
      .reduce((count,row)=>count+latest.ROLES.filter(role=>row.roleApplicability[role]).length,0)]));
  assert.deepEqual(result.actualDenialCounts, denialCounts);
  const postV30Keys = new Set([latest.AVATAR_UPLOAD_KEY,...latest.LISTING_OPTIMIZE_KEYS,
    latest.FILE_SUMMARY_KEY,latest.USER_LOOKUP_KEY,latest.UPLOAD_PREVIEW_KEY,latest.AGENCY_ROLE_KEY,latest.MCP_REGISTRATION_KEY]);
  assert.deepEqual(Array.from(result.currentAddedKeys),
    latest.REGISTRY_UPGRADES[latest.PREDECESSOR_REGISTRY_SHA256].filter(key=>!postV30Keys.has(key)));
  assert.ok(result.currentAddedKeys.includes(latest.COUPON_PREPARE_KEY));
  assert.equal(result.historicalAddedKeys.includes(latest.COUPON_PREPARE_KEY), false);
  const freshStart = source.indexOf(' assert.equal(freshPolicy.rows.find');
  const freshEnd = source.indexOf("  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades", freshStart);
  assert.ok(freshStart > end && freshEnd > freshStart);
  const checkFreshDefaults = require('node:vm').runInThisContext('(function(require,assert,freshPolicy){'
    + pureAccounting + '\n' + source.slice(freshStart, freshEnd) + '\n})',
  { timeout: 1000 });
  // Contract-only projection: no SQL, session, execution or credit is created.
  // Exercise the actual native assertions against the immutable fresh defaults.
  const freshPolicy = { rows: latest.REGISTRY.map(row => ({ ...row,
    allowed: { ...row.defaultAllowed } })) };
  checkFreshDefaults(require('node:module').createRequire(nativePath), assert, freshPolicy);
  const wronglyDenied = structuredClone(freshPolicy);
  wronglyDenied.rows.find(row => row.toolKey === R.COUPON_PREPARE_KEY).allowed.customer = false;
  assert.throws(() => checkFreshDefaults(require('node:module').createRequire(nativePath),
    assert, wronglyDenied));
});
