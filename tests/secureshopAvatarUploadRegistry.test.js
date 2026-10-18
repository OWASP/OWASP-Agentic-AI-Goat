'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const R = require('../server/services/secureshopBoundAclRegistry');
const base = path.join(process.cwd(), 'db/postgres/workshop-migrations/secureshop_agents'),
  sql = fs.readFileSync(path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents/0103_avatar_upload_registry_successor.sql'), 'utf8'),
  repairSql = fs.readFileSync(path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents/0104_avatar_upload_registry_guard_repair.sql'), 'utf8');
const hash = s => crypto.createHash('sha256').update(s).digest('hex');
function literals(s) {
  const o = {};
  for (const m of s.matchAll(/(\w+) (?:constant )?text := (E)?'((?:''|[^'])*)';/g)) {
    let v = m[3].replaceAll("''", "'");
    if (m[2]) v = v.replace(/\\([nrt\\])/g, (_, c) => ({
      n: '\n',
      r: '\r',
      t: '\t',
      '\\': '\\'
    })[c]);
    o[m[1]] = v;
  }
  return o;
}
function read(n) {
  return fs.readFileSync(path.join(base, n), 'utf8');
}
function v29() {
  let b = read('0082_merchant_mail_reads_registry_successor.sql').match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)[1];
  for (const f of ['0084_merchant_mail_prepare_registry_successor.sql', '0085_merchant_listing_setup_registry_successor.sql', '0087_customer_coupon_prepare_registry_successor.sql', '0088_customer_ticket_prepare_registry_successor.sql', '0089_admin_system_diagnostic_prepare_registry_successor.sql', '0092_mail_summary_registry_successor.sql']) {
    const q = read(f),
      v = literals(q),
      m = q.match(/guard_source:=replace\(guard_source,(v\d+_branch),(v\d+_branch)\|\|/);
    b = b.replaceAll(v.old_edge, v.old_edge + '\n' + v.new_edges).replaceAll(v[m[1]], v[m[2]] + v[m[1]]);
  }
  let v = literals(read('0096_coupon_probe_registry_successor.sql'));
  b = b.replaceAll(` IF encode(NEW.successor_sha256,'hex')='${v.old_hash}' THEN`, v.branch + ` IF encode(NEW.successor_sha256,'hex')='${v.old_hash}' THEN`);
  v = literals(read('0098_product_search_union_registry_successor.sql'));
  return b.replaceAll(v.old_edge, v.old_edge + '\n' + v.new_edges).replaceAll(v.v28_branch, v.v29_branch + v.v28_branch).replaceAll(v.denial_anchor, '\n END IF;' + v.denial_anchor);
}
test('v31 adds only the customer avatar tool across every exact predecessor', () => {
  const historical = R.PRE_LISTING_OPTIMIZE_REGISTRY_UPGRADES;
  assert.equal(R.LISTING_OPTIMIZE_PREDECESSOR_REGISTRY_SHA256, '0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c');
  assert.deepEqual(historical[R.AVATAR_UPLOAD_PREDECESSOR_REGISTRY_SHA256], [R.AVATAR_UPLOAD_KEY]);
  assert.equal(Object.keys(historical).length, 30);
  for (const [prior, keys] of Object.entries(historical)) {
    assert.equal(keys.at(-1), R.AVATAR_UPLOAD_KEY);
    assert.equal(new Set(keys).size, keys.length);
    assert.ok(prior.match(/^[a-f0-9]{64}$/));
    assert.deepEqual(R.REGISTRY_UPGRADES[prior].slice(0, keys.length), keys);
  }
});
test('0103 reconstructs checksum-bound v31 and preserves v30 reversibly', () => {
  const a = literals(read('0100_coupon_probe_guided_v2_registry_successor.sql'));
  let old = v29();
  old = old.replace(a.old_edge, a.old_edge + '\n' + a.new_edges).replace(a.v29_branch, a.v30_branch + a.v29_branch).replace(a.denial_anchor, '\n END IF;' + a.denial_anchor);
  const v = literals(sql);
  assert.equal(hash(old), v.old_guard_sha256);
  for (const anchor of [v.old_edge, v.v30_branch, v.denial_anchor]) assert.equal(old.split(anchor).length - 1, 1);
  assert.ok(!v.v30_branch.includes('undefined'));
  assert.equal((v.new_edges.match(/OR \(encode/g) || []).length, 30);
  const next = old.replace(v.old_edge, v.old_edge + '\n' + v.new_edges).replace(v.v30_branch, v.v31_branch + v.v30_branch).replace(v.denial_anchor, '\n END IF;' + v.denial_anchor);
  assert.equal(hash(next), v.upgraded_guard_sha256);
  assert.ok(next.includes(v.v31_branch));
  assert.match(sql, /successor_v31/);
  assert.match(sql, /DROP CONSTRAINT bound_tool_registry_successor_v30/);
  assert.doesNotMatch(sql, /UPDATE secureshop_agents|DELETE FROM|INSERT INTO/);
});
test('0104 repairs only the missing exclusive v31 branch and pins the resulting guard', () => {
  const a = literals(read('0100_coupon_probe_guided_v2_registry_successor.sql'));
  let old = v29();
  old = old.replace(a.old_edge, a.old_edge + '\n' + a.new_edges).replace(a.v29_branch, a.v30_branch + a.v29_branch).replace(a.denial_anchor, '\n END IF;' + a.denial_anchor);
  const v = literals(sql);
  old = old.replace(v.old_edge, v.old_edge + '\n' + v.new_edges).replace(v.v30_branch, v.v31_branch + v.v30_branch).replace(v.denial_anchor, '\n END IF;' + v.denial_anchor);
  const repair = literals(repairSql);
  assert.equal(hash(old), repair.old_guard_sha256);
  assert.equal(old.split(repair.broken_anchor).length - 1, 1);
  const fixed = old.replace(repair.broken_anchor, repair.repaired_anchor);
  assert.equal(hash(fixed), repair.repaired_guard_sha256);
  assert.match(fixed, /END;\n ELSE\n IF encode\(NEW\.successor_sha256,'hex'\)='e747a555/);
  assert.match(repairSql, /CREATE OR REPLACE FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade/);
  assert.match(repairSql, /SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents/);
  assert.match(repairSql, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime/);
  assert.doesNotMatch(repairSql, /UPDATE secureshop_agents|DELETE FROM|INSERT INTO/);
});
