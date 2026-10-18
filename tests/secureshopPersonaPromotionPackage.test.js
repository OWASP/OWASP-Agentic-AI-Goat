'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(ROOT, relative));
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

test('hidden persona promotion pins only the two immutable structural migrations', () => {
  const manifest = JSON.parse(read('docs/modernization/drafts/secureshop-persona-inbox-promotion-manifest-2026-09-14.json'));
  const expected = new Map(manifest.order.map(row => [row.store, row]));
  assert.deepEqual([...expected.keys()].sort(), ['identity', 'secureshop_agents']);
  for (const [store, draft, target] of [
    ['identity', 'docs/modernization/drafts/secureshop-persona-inbox-identity.sql',
      'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql'],
    ['secureshop_agents', 'docs/modernization/drafts/secureshop-persona-inbox-agents.sql',
      'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql'],
  ]) {
    assert.equal(sha256(read(draft)), expected.get(store).sha256);
    assert.equal(fs.existsSync(path.join(ROOT, target)), true);
    assert.equal(sha256(read(target)), expected.get(store).sha256);
  }
  assert.equal(manifest.defaults.environmentDefault, false);
  assert.equal(manifest.defaults.workshopVisible, false);
  assert.equal(manifest.defaults.objectivesEnabled, false);
});

test('promotion runner reuses protected recovery and drains every SecureShop writer before dump', () => {
  const source = read('tests/postgres/run-secureshop-persona-promotion.py').toString('utf8');
  assert.match(source, /from sensitive_info_recovery_safety import \([\s\S]*SignalGate[\s\S]*protected_cleanup/);
  assert.match(source, /state\['backendDrainState'\] = wait_gone\(backend_pid\)/);
  assert.match(source, /assert_agent_host_quiet\(\)/);
  assert.match(source, /for url in urls\.values\(\): assert_store_quiet\(url\)/);
  assert.match(source, /started = True; state\['creationAttempted'\] = True; write_state\(\)/);
  assert.match(source, /if not exact_container_absence\(\):/);
  assert.match(source, /if readiness!=expected_ready/);
  assert.doesNotMatch(source, /atomic_copy\([^\n]*secureshopCurriculum/);
});
