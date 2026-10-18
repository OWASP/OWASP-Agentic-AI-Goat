'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const R = require('../server/services/secureshopBoundAclRegistry');
const directory = join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
const read = name => readFileSync(join(directory, name), 'utf8');
const digest = value => createHash('sha256').update(value).digest('hex');
const couponMigration = read('0087_customer_coupon_prepare_registry_successor.sql');
const ticketMigration = read('0088_customer_ticket_prepare_registry_successor.sql');
const migration = read('0092_mail_summary_registry_successor.sql');

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
const v26 = advance(v25, read('0089_admin_system_diagnostic_prepare_registry_successor.sql'), 'v25_branch', 'v26_branch');
const v27 = advance(v26, migration, 'v26_branch', 'v27_branch');
const v27Hash = R.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256;
const v27Upgrades = Object.fromEntries(Object.entries(R.PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES)
  .filter(([prior]) => prior !== v27Hash));

test('mail summary adds one merchant capability and preserves every v26 row and reply permission', () => {
  assert.equal(v27Hash, 'f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c');
  assert.equal(digest(JSON.stringify({ version: R.REGISTRY_VERSION, rows: R.REGISTRY })), R.REGISTRY_SHA256);
  assert.equal(Object.keys(v27Upgrades).length, 26);
  const declaredTools = [{ agent: 'email', tool: 'read_thread' },
    { agent: 'email', tool: 'summarize_thread' }];
  const summary = R.createBoundAclResolver({ workflow: 'mail-summary', declaredTools });
  const reply = R.createBoundAclResolver({ workflow: 'mail-reply',
    declaredTools: [declaredTools[0], { agent: 'email', tool: 'send_reply' }] });
  assert.equal(summary.resolve('email', 'read_thread'), reply.resolve('email', 'read_thread'));
  assert.deepEqual(reply.resolve('email', 'read_thread').roleApplicability,
    { customer: true, merchant: true, admin: true });
  assert.deepEqual(summary.resolve('email', 'summarize_thread').defaultAllowed,
    { customer: false, merchant: true, admin: false });
  for (const role of R.ROLES) assert.equal(summary.isRoleApplicable(role), role === 'merchant');
  assert.equal(summary.resolve('email', 'send_reply'), null);
  assert.throws(() => R.createBoundAclResolver({ workflow: 'mail-summary', declaredTools: declaredTools.slice(1) }));
  assert.throws(() => R.createBoundAclResolver({ workflow: 'mail-summary', declaredTools: [...declaredTools, declaredTools[0]] }));
});

test('0092 appends 26 exact edges while retaining all 325 historical guard edges and bodies', () => {
  assert.equal(digest(v26), '4bd88aa6a32f0984e303b0c58612cf9fec83cce900ac9bf3a1a15b3a78ae0577');
  const marker = constant(migration, 'v26_branch');
  assert.equal(v27.slice(v27.indexOf(marker)), v26.slice(v26.indexOf(marker)));
  const edges = body => [...body.matchAll(/\(encode\(NEW\.predecessor_sha256,'hex'\)='([a-f0-9]{64})' AND encode\(NEW\.successor_sha256,'hex'\)='([a-f0-9]{64})'\)/g)]
    .map(match => match.slice(1).join(':'));
  const previous = edges(v26), current = edges(v27);
  assert.equal(previous.length, 325); assert.equal(current.length, 351);
  for (const edge of previous) assert.ok(current.includes(edge));
  assert.deepEqual(current.filter(edge => !previous.includes(edge)).sort(),
    Object.keys(v27Upgrades).map(hash => `${hash}:${v27Hash}`).sort());
  assert.match(migration, /regexp_count\(constraint_def,'jsonb_array_length'\)<>325/);
  assert.match(migration, /ADD CONSTRAINT bound_tool_registry_successor_v27/);
  assert.match(migration, /DROP CONSTRAINT bound_tool_registry_successor_v26/);
  assert.doesNotMatch(migration, /GRANT\s|CREATE\s+TABLE|INSERT\s+INTO|UPDATE\s+secureshop_agents/i);
  assert.match(migration, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('all published predecessors add only the new merchant denial to their retained denial sets', () => {
  assert.deepEqual(v27Upgrades[R.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256], [R.MAIL_SUMMARY_KEY]);
  const lengths = [];
  for (const [hash, keys] of Object.entries(v27Upgrades)) {
    assert.deepEqual(R.REGISTRY_UPGRADES[hash].slice(0, keys.length), keys);
    const denials = R.REGISTRY.filter(row => keys.includes(row.toolKey))
      .flatMap(row => R.ROLES.filter(role => row.roleApplicability[role]).map(role => ({ toolKey: row.toolKey, role })))
      .sort((a,b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : a.role < b.role ? -1 : a.role > b.role ? 1 : 0);
    assert.ok(v27.includes(`WHEN '${hash}' THEN '${JSON.stringify(denials)}'::jsonb`));
    assert.ok(constant(migration, 'constraint_additions').includes(
      `encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${v27Hash}' AND jsonb_array_length(added_denials)=${denials.length}`));
    assert.deepEqual(denials.filter(row => row.toolKey === R.MAIL_SUMMARY_KEY),
      [{ toolKey: R.MAIL_SUMMARY_KEY, role: 'merchant' }]);
    assert.ok(!denials.some(row => row.toolKey === 'email.read_thread'));
    lengths.push(denials.length);
  }
  const prior = read('0089_admin_system_diagnostic_prepare_registry_successor.sql')
    .match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  const current = migration.match(/jsonb_array_length\(added_denials\) IN\s*\(([^)]+)\)/)[1].split(',').map(Number);
  assert.deepEqual(current, [...new Set([...prior, ...lengths])].sort((a,b) => a-b));
  assert.ok(v27.includes('NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials'));
  const readiness = readFileSync(join(__dirname, '../server/database/postgres/secureshopBoundToolPolicyReadiness.js'), 'utf8');
  assert.match(readiness, /row\.upgrade_guard_sha256!==('[a-f0-9]{64}')/);
  assert.ok(readiness.includes(`bound_tool_registry_successor_v${R.REGISTRY_VERSION}`));
});
