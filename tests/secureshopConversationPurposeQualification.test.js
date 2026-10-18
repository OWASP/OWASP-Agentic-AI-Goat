'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const read = name => fs.readFileSync(path.join(ROOT, name), 'utf8');

test('purpose qualifier covers upgrade compatibility, isolation, replay and aggregate reset', () => {
  const source = read('tests/postgres/secureshopConversationPurpose.integration.test.js');
  assert.match(source, /the pre-0013 DTO must not expose a field/);
  assert.match(source, /createAgentsMigrationView\(10\)/);
  assert.match(source, /createAgentsMigrationView\(13\)/);
  assert.match(source, /view13\.migrate\(pools\.POPULATED_MIGRATION, prefixDirectory\), STAGED/);
  assert.match(source, /actualFresh\.slice\(-3\)\.map\(row => row\.name\), STAGED/);
  assert.match(source, /mcp_rogue_registration/);
  assert.match(source, /mcp_rug_pull/);
  assert.match(source, /Promise\.all\(concurrentIds/);
  assert.match(source, /CONVERSATION_UNAVAILABLE/);
  assert.match(source, /ConversationLifecycleRepository/);
  assert.match(source, /retirable\.length, PURPOSES\.length/);
  assert.match(source, /receipt\.sessionCount, PURPOSES\.length/);
  assert.match(source, /replayed: true/);
});

test('single-use launcher stages reserved agents0013 from frozen copied source', () => {
  const source = read('tests/postgres/run-secureshop-conversation-purpose-isolated.py');
  assert.match(source, /EXPECTED_DOCKER = 'unix:\/\/\/Users\/averma5\/\.colima\/dvaia-pg-verify\/docker\.sock'/);
  assert.match(source, /OWNER = '\/root\/purpose_native_review'/);
  assert.match(source, /0013_secureshop_conversation_purpose\.sql/);
  assert.match(source, /0011_secureshop_mcp_trust\.sql/);
  assert.match(source, /0012_secureshop_controlled_ssrf\.sql/);
  assert.match(source, /if any\(\(SOURCE \/ destination\)\.exists\(\) for destination in STAGED\)/);
  assert.match(source, /grant\.get\('sourceHashes'\) != source_hashes/);
  assert.match(source, /verify_source_copy/);
  assert.match(source, /staged migration differs from frozen draft/);
  assert.match(source, /handle != os\.getpid\(\)/);
  assert.match(source, /details\.get\('Mounts'\)/);
  assert.match(source, /exact_container_absence\(\)/);
  assert.match(source, /'fresh', 'populated'/);
  assert.doesNotMatch(source, /LIVE_OLLAMA_TEST|OLLAMA_BASE_URL|ANTHROPIC_API_KEY|OPENAI_API_KEY/);
});

test('purpose native manifest retains historical pins and the exact staged draft', () => {
  const manifest = JSON.parse(read('tests/release-inputs/secureshop-conversation-purpose-native-manifest.json'));
  const archive = JSON.parse(read('docs/modernization/archive/secureshop-conversation-purpose-reviewed-sources.json'));
  const digest = name => createHash('sha256').update(fs.readFileSync(path.join(ROOT, name))).digest('hex');
  assert.equal(archive.version, 1);
  assert.equal(archive.evidence, 'tasks/secureshop-conversation-purpose-native-manifest.json');
  assert.deepEqual(Object.keys(archive.sources).sort(), [
    'db/postgres/migrate.js',
    'server/database/postgres/secureshopBoundConversationsRepository.js',
    'server/services/secureshopConversationPurpose.js',
  ]);
  assert.equal(manifest.owner, '/root/purpose_native_review');
  assert.equal(Object.keys(manifest.sourceHashes).length, 23);
  for (const [name, expected] of Object.entries(manifest.sourceHashes)) {
    if (name === 'tests/postgres/secureshopConversationPurpose.integration.test.js') {
      assert.equal(expected, '2a4f5f0dbaefaca477993854d2eeeb95077501b482350a3ef51ce4508afa6d43');
      assert.equal(digest(name), 'bc3ae2ba59ef850c0e4adda86dd6c135425d0dbe0758e1dbc7833ffdb55ec61e',
        `${name} admitted current fixture`);
      continue; // The supported current fixture uses a virtual migration view; this pin is historical evidence.
    }
    const historical = archive.sources[name];
    if (historical) {
      assert.equal(historical.sha256, expected, `${name} archive metadata`);
      assert.equal(digest(historical.archivePath), expected, `${name} archived source`);
    } else assert.equal(digest(name), expected, name);
  }
  assert.deepEqual(manifest.stagedMigrations, {
    'db/postgres/workshop-migrations/secureshop_agents/0011_secureshop_mcp_trust.sql':
      digest('docs/modernization/drafts/secureshop-mcp-trust-agents.sql'),
    'db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql':
      digest('docs/modernization/drafts/secureshop-controlled-ssrf-agents.sql'),
    'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql':
      digest('docs/modernization/drafts/secureshop-conversation-purpose-agents.sql'),
  });
});
