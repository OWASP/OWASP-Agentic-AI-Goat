'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const sha = name => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex');

test('registered identity0050 and MCP0004 retain the reviewed migration bytes and privileges', () => {
  assert.equal(fs.existsSync(path.join(root, 'db/postgres/identity-migrations/0050_mcp_conversation_history.sql')), true);
  assert.equal(fs.existsSync(path.join(root, 'db/postgres/workshop-migrations/mcp/0004_mcp_owned_resources.sql')), true);
  const identity = read('db/postgres/identity-migrations/0050_mcp_conversation_history.sql');
  assert.equal(identity, read('docs/modernization/drafts/0050_mcp_conversation_history.sql'));
  const mcp = read('db/postgres/workshop-migrations/mcp/0004_mcp_owned_resources.sql');
  assert.equal(mcp, read('docs/modernization/drafts/0004_mcp_owned_resources.sql'));
  assert.match(identity, /RESERVED IDENTITY 0050, DRAFT ONLY/);
  assert.match(identity, /GRANT SELECT,INSERT ON workshop_conversations\.turns TO dvaia_identity_runtime/);
  assert.match(identity, /GRANT UPDATE\(user_text,response_json\) ON workshop_conversations\.requests TO dvaia_identity_runtime/);
  assert.match(mcp, /RESERVED MCP 0004, DRAFT ONLY/);
  assert.match(mcp, /GRANT SELECT,INSERT,UPDATE ON mcp\.runner_targets,mcp\.runner_target_cleanups/);
  assert.doesNotMatch(mcp, /GRANT .*DELETE .*mcp\.mail_intents/);
});

test('identity0050 loader gate pins the exact qualified 0047-0049 predecessors', () => {
  assert.equal(sha('docs/modernization/drafts/secureshop-persona-inbox-catalog-transition.sql'),
    'e12496c0ebf7c3927ab2d967afa286b3e5774d88f4223527444c222c19ed3e64');
  assert.equal(sha('docs/modernization/drafts/workshop-catalog-field-provenance.sql'),
    '96ea10297e339cc277a0c76db8dad7028f5683b1dbc1db46a3d913889fe24de2');
  assert.equal(sha('docs/modernization/drafts/workshop-catalog-field-provenance-persona-adoption.sql'),
    'aa22efe7d731bbb378f6cc9d7954f109af34573773f2f0f6ade10098b02abccb');
});

test('owned migration launcher rejects omitted, null, partial, and changed source inventories', () => {
  const launcher = read('tests/postgres/run-mcp-owned-runtime-migrations-isolated.py');
  assert.match(launcher, /frozen=grant\.get\('sourceHashes'\)/);
  assert.match(launcher, /if not isinstance\(frozen,dict\) or set\(frozen\)!=set\(tracked\)/);
  assert.match(launcher, /frozen\[name\]!=digest\(source\/name\) or frozen\[name\]!=digest\(workspace\/name\)/);
  assert.match(launcher, /POSTGRES_INITDB_ARGS=--wal-segsize=1/,
    'the 4MB\/16MB bounded WAL settings require a 1MB initialized segment');
  assert.match(launcher, /\['logs','--tail','200',container\]/,
    'startup failure evidence must be private and bounded');
});

test('owned migration fixture uses the graph ledger terminal timestamp', () => {
  const fixture = read('tests/postgres/mcpOwnedRuntimeMigrations.integration.test.js');
  assert.match(fixture, /graph_runtime\.runs SET status='completed',finished_at=clock_timestamp\(\)/);
  assert.doesNotMatch(fixture, /graph_runtime\.runs SET status='completed',completed_at=/);
});

test('owned migration fixture checks the canonical durable session shape', () => {
  const fixture = read('tests/postgres/mcpOwnedRuntimeMigrations.integration.test.js');
  assert.match(fixture, /validated\.user\.id, user\.id/);
  assert.match(fixture, /validated\.session\.user_id, user\.id/);
  assert.match(fixture, /validated\.session\.id, session\.internalSessionId/);
  assert.match(fixture, /validated\.decoded\.userId, user\.id/);
  assert.match(fixture, /resolved\.assertCurrent\(\)/);
  assert.match(fixture, /PG-only gate must not admit a target/);
  assert.match(fixture, /PG-only gate must not retire a target/);
  assert.doesNotMatch(fixture, /validateSession\(session\.token\)\)\.user_id/);
});
