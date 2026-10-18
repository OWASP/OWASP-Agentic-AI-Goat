'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const curriculum = require('../server/config/secureshopCurriculum');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();
const { readHistoricalSources, SOURCES } = require('./fixtures/secureshopPersonaHistoricalSources');

const root = path.join(__dirname, '..');
const manifestPath = path.join(root,
  'docs/modernization/drafts/secureshop-persona-inbox-promotion-manifest-2026-09-14.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

test('retained promotion snapshot is available for in-memory historical replay', () => {
  const historical = readHistoricalSources();
  for (const [filename, expected] of Object.entries(manifest.sourceSnapshot)) {
    assert.equal(SOURCES[filename].sha256, expected, `${filename} archive pin changed`);
    assert.equal(hashBytes(historical[filename]), expected, `${filename} archive bytes changed`);
  }
});

function hashBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

test('persona inbox promotion package records the coordinated immutable forward suffixes', () => {
  assert.equal(manifest.status, 'promoted-hidden-structural');
  assert.equal(manifest.prerequisites.identity.requiredHead, '0044_sensitive_info_aggregate_reset.sql');
  assert.equal(manifest.prerequisites.identity.currentReviewedHead,
    '0044_sensitive_info_aggregate_reset.sql');
  assert.equal(manifest.prerequisites.identity.fileCount, 43);
  assert.equal(manifest.prerequisites.secureshop_agents.requiredHead,
    '0009_secureshop_bound_persona_renewal.sql');
  assert.equal(manifest.prerequisites.secureshop_agents.fileCount, 9);
  assert.deepEqual(manifest.order.map(item => [item.store, item.promotionName]), [
    ['identity', '0045_secureshop_persona_inbox_identity.sql'],
    ['secureshop_agents', '0010_secureshop_persona_inbox.sql'],
  ]);
  for (const item of manifest.order) {
    const draft = path.join(root, 'docs/modernization/drafts', item.draft);
    assert.equal(hash(draft), item.sha256, `${item.draft} changed after qualification`);
    const destination = item.store === 'identity'
      ? path.join(root, 'db/postgres/identity-migrations', item.promotionName)
      : path.join(root, 'db/postgres/workshop-migrations/secureshop_agents', item.promotionName);
    assert.equal(fs.existsSync(destination), true, `${item.promotionName} is missing after promotion`);
    assert.equal(hash(destination), item.sha256, `${item.promotionName} differs from its promoted bytes`);
  }
});

test('activation review pins the qualified production source and records the current-head gap', () => {
  if (!phase.generated) for (const [filename, expected] of Object.entries(manifest.sourceSnapshot)) {
    assert.equal(hash(path.join(root, filename)), expected, `${filename} changed after activation review`);
  }
  assert.match(manifest.activationReview.currentHeadGap, /identity0044/);
  assert.match(manifest.activationReview.sourceReleaseGap, /still say pending/);
});

test('promotion package preserves hidden controls across candidate and generated phases', () => {
  assert.deepEqual(manifest.objectives, [
    'ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block',
  ]);
  for (const id of manifest.objectives) {
    const objective = curriculum.OBJECTIVES.find(item => item.id === id);
    assert.equal(objective?.qualification, phase.generated ? 'native-model' : 'pending');
    assert.equal(objective?.defaultEnabled, false);
  }
  assert.equal(curriculum.CHALLENGE.route, phase.generated ? '/workshop/secureshop' : '');
  assert.equal(curriculum.CHALLENGE.defaultVisible, false);
  assert.equal(manifest.defaults.environmentDefault, false);
  assert.equal(manifest.defaults.draftsRegistered, true);
  assert.equal(manifest.requiredSourceRepair.status, 'implemented-focused-qualified');
  assert.match(manifest.requiredSourceRepair.contract, /separately checks current canonical exercise visibility/);
});

test('remaining sequence distinguishes qualified browser evidence from missing MCP and SSRF effects', () => {
  assert.deepEqual(manifest.remainingSequence.map(item => item.priority), [1, 2, 3]);
  assert.equal(manifest.remainingSequence[0].state, 'connected-qualified-awaiting-catalog-release');
  assert.equal(manifest.remainingSequence[1].state, 'missing-secureshop-production-vertical');
  assert.equal(manifest.remainingSequence[2].state, 'missing-real-scoped-tool-and-target');
  assert.match(manifest.remainingSequence[0].reason, /h3s9g0qg/);
});
