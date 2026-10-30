'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const launcherPath = path.join(root, 'tests/postgres/run-mcp-owned-runtime-live-promotion.py');
const source = () => fs.readFileSync(launcherPath, 'utf8');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function assertReviewedSourceClosure(manifest, read) {
  assert.ok(Object.keys(manifest.sourceHashes).length > 0);
  for (const [file, expected] of Object.entries(manifest.sourceHashes)) {
    assert.equal(digest(read(file)), expected, 'Reviewed source changed: ' + file);
  }
}

test('live promotion binds the named isolated daemon and one-use owner handshake', () => {
  const text = source();
  assert.match(text, /unix:\/\/\/Users\/averma5\/\.colima\/owasp-ai-goat-pg-verify\/docker\.sock/);
  assert.match(text, /args\.colima_profile != 'colima-owasp-ai-goat-pg-verify'/);
  assert.match(text, /stat\.S_ISSOCK\(docker_socket\.stat\(\)\.st_mode\)/);
  assert.match(text, /grant\.get\('allowedLaunches'\) != 1/);
  assert.match(text, /grant\.get\('sourceHashes'\) != state\['sourceHashes'\]/);
  assert.match(text, /ownerHandle/);
  assert.match(text, /owner_registration_failed/);
});

test('promotion is identity and MCP only and preserves the private environment', () => {
  const text = source();
  assert.match(text, /IDENTITY_MIGRATION_DATABASE_URL/);
  assert.match(text, /MCP_WORKSHOP_MIGRATION_DATABASE_URL/);
  assert.match(text, /0050_mcp_conversation_history\.sql/);
  assert.match(text, /0004_mcp_owned_resources\.sql/);
  assert.match(text, /assert_private_config_unchanged\(\)/);
  assert.match(text, /st_mode\) & 0o077/);
  assert.match(text, /owned MCP resources must remain disabled during database promotion/);
  assert.doesNotMatch(text, /initializeApplication\s*\(/);
  assert.match(text, /restored_before_seed/);
  assert.match(text, /current startup catalog seed would change the identity snapshot/);
  assert.doesNotMatch(text, /FINFLOW_DATABASE_URL|AWS_/);
});

test('promotion proves two-store restore, all-ledger replay, and post-restart preservation', () => {
  const text = source();
  assert.match(text, /for name in \('identity','mcp'\)/);
  assert.match(text, /restored store inventory differs from the quiet backup/);
  assert.match(text, /set\(before\)!=set\(INITIALIZER_NAMES\)/);
  assert.match(text, /migration replay is not empty/);
  assert.match(text, /post-restart workshop catalog differs/);
  assert.match(text, /postRestartBackendPid/);
  assert.match(text, /resolve_backend\(excluded_pid=backend_pid,require_running=True\)/);
  assert.match(text, /oldBackendExit.*wait_gone\(backend_pid\)/);
  assert.match(text, /os\.kill\(args\.watcher_pid,signal\.SIGHUP\)/);
  assert.match(text, /nodemonProvenance/);
  assert.match(text, /qualification_stage\('--ledger','ledger-post-restart\.log'\)/);
  assert.match(text, /post-restart migration ledger differs/);
  assert.match(text, /workshop catalog changed/);
});

test('post-mutation failures retain repair state and runner activation is a separate gate', () => {
  const text = source();
  assert.match(text, /watcherHeldAfterPostMutationFailure/);
  assert.match(text, /backendHeldAfterPostMutationFailure/);
  assert.match(text, /watcherHeldForRepair/);
  assert.match(text, /'performed':False,'requiredBeforeActivation':True/);
  assert.doesNotMatch(text, /mcp-owned-provision\.js',\s*'--/);
  assert.match(text, /docker \+ \['ps','-a','--filter',f'name=\^\/{container}\$'/);
});

test('historical review manifest preserves exact migrations and is not current-source acceptance', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root,
    'docs/modernization/drafts/mcp-owned-runtime-live-promotion-source-hashes-2026-09-14.json')));
  assert.equal(manifest.status, 'draft-unlaunched');
  assert.equal(manifest.candidates.identity.sha256,
    'fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f');
  assert.equal(manifest.candidates.mcp.sha256,
    '30b9980f2ad0e37be8134a9868c00190b2590f4ce8e0e11c1d2d4fbc3c86ae6d');
  assert.ok(Object.keys(manifest.sourceHashes).length > 250);
  for (const [file, expected] of Object.entries(manifest.sourceHashes)) {
    assert.match(expected, /^[0-9a-f]{64}$/, file);
  }
  for (const candidate of Object.values(manifest.candidates)) {
    assert.equal(digest(fs.readFileSync(path.join(root,candidate.draft))),candidate.sha256);
    assert.equal(digest(fs.readFileSync(path.join(root,candidate.target))),candidate.sha256);
  }
  assert.equal(manifest.sourceHashes[manifest.launcher],manifest.launcherSha256);
  // Keep the complete historical byte fence. Its stale source inventory must
  // fail closed; it cannot qualify the updated main tree by checking only SQL.
  assert.throws(() => assertReviewedSourceClosure(manifest,
    file => fs.readFileSync(path.join(root, file))),
  error => error.code === 'ERR_ASSERTION' || error.code === 'ENOENT');
});

test('reviewed source closure checks every file and rejects partial source drift', () => {
  const files = new Map([['first.js', Buffer.from('first')], ['last.js', Buffer.from('last')]]);
  const manifest = { sourceHashes: Object.fromEntries([...files].map(([name, bytes]) => [name, digest(bytes)])) };
  assertReviewedSourceClosure(manifest, name => files.get(name));
  files.set('last.js', Buffer.from('lost'));
  assert.throws(() => assertReviewedSourceClosure(manifest, name => files.get(name)),
    /Reviewed source changed: last.js/);
});
