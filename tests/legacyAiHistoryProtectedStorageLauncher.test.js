'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const LAUNCHER = path.join(ROOT, 'tests/postgres/run-legacy-ai-history-protected-storage-isolated.py');
const source = fs.readFileSync(LAUNCHER, 'utf8');

test('protected-history launcher is an inert exact one-use root-owned draft gate', () => {
  assert.match(source, /if __name__ == '__main__':/);
  assert.match(source, /allowedLaunches': 1/);
  assert.match(source, /grant\.get\('status'\) != 'granted'/);
  assert.match(source, /grant\.update\(status='consumed'/);
  assert.match(source, /runStatus='waiting_owner_handle'/);
  assert.match(source, /terminal_grant\.update\(runStatus='terminal_pass'/);
  assert.match(source, /terminalGrantRecorded/);
  assert.match(source, /WAITING_OWNER_HANDLE/);
  assert.match(source, /expectedLauncherPid': os\.getpid\(\)/);
  assert.match(source, /activation'\) != 'unregistered-draft-only'/);
  assert.match(source, /registeredIdentityHead/);
  assert.match(source, /0065_ipi_email_artifacts\.sql/);
  assert.match(source, /REVIEWED_IDENTITY_MIGRATIONS_SHA256 = '[0-9a-f]{64}'/);
  assert.match(source, /verify_reviewed_identity_migrations\(package \/ 'source'/);
  assert.match(source, /verify_reviewed_identity_migrations\(canonical/);
  assert.match(source, /reviewedIdentityMigrationsSha256/);
  assert.doesNotMatch(source, /db\/postgres\/identity-migrations\/\$\{/);
});

test('protected-history launcher uses one fresh identity store and only its prefixed URLs', () => {
  assert.match(source, /dvaia_test_legacy_ai_history_/);
  assert.match(source, /CREATE ROLE \{MIGRATION_ROLE\} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(source, /CREATE ROLE \{RUNTIME_ROLE\} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(source, /CREATE DATABASE \{database\} OWNER \{MIGRATION_ROLE\}/);
  assert.match(source, /PG_LEGACY_AI_HISTORY_IDENTITY_MIGRATION_URL=/);
  assert.match(source, /PG_LEGACY_AI_HISTORY_IDENTITY_RUNTIME_URL=/);
  assert.doesNotMatch(source, /process\.env|os\.environ\[['"](?:IDENTITY|DATABASE|PG_LEGACY)/);
  assert.match(source, /base_env = \{key: os\.environ\[key\] for key in \('PATH',\)/);
});

test('protected-history launcher pins runtime, image, immutable closure and exact suite result', () => {
  assert.match(source, /NODE_VERSION = 'v26\.8\.2'/);
  assert.match(source, /POSTGRES_IMAGE_ID = 'sha256:[0-9a-f]{64}'/);
  assert.match(source, /DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'/);
  assert.match(source, /daemon_info\.get\('ID'\) != DOCKER_DAEMON_ID/);
  assert.match(source, /daemon_info\.get\('Name'\) != 'colima-dvaia-pg-verify'/);
  assert.match(source, /--pull', 'never'/);
  assert.match(source, /'pg_isready', '-h', '127\.0\.0\.1'/);
  assert.match(source, /package_inventory\(package\)/);
  assert.match(source, /sourceFilesSha256/);
  assert.match(source, /dependencyFilesSha256/);
  assert.match(source, /dependencySymlinksSha256/);
  assert.match(source, /legacyAiHistoryProtectedStorage\.integration\.test\.js/);
  assert.match(source, /'server\/database\/postgres\/legacyAiHistoryDraftImporter\.js'/);
  assert.match(source, /'tests\/legacyAiHistoryDraftImporter\.test\.js'/);
  assert.match(source, /'server\/database\/postgres\/legacyAiHistoryArchiveAttestation\.js'/);
  assert.match(source, /'tests\/legacyAiHistoryArchiveAttestation\.test\.js'/);
  assert.match(source, /'server\/database\/postgres\/legacyAiHistoryImportTarget\.js'/);
  assert.match(source, /'tests\/legacyAiHistoryImportTarget\.test\.js'/);
  assert.match(source, /'server\/services\/legacyAiHistoryRequestService\.js'/);
  assert.match(source, /'tests\/legacyAiHistoryRequestService\.test\.js'/);
  assert.match(source, /'server\/services\/legacyAiProtectedHistoryComposition\.js'/);
  assert.match(source, /'tests\/legacyAiProtectedHistoryComposition\.test\.js'/);
  assert.match(source, /'tests\/postgres\/helpers\/legacyAiHistoryHttpQualification\.js'/);
  assert.match(source, /'server\/routes\/legacyAiProtectedHistoryDraftRouter\.js'/);
  assert.match(source, /'server\/middleware\/bearerToken\.js'/);
  assert.match(source, /# pass 1/);
  assert.match(source, /# fail 0/);
  assert.match(source, /# skipped 0/);
  const controlCheck = source.indexOf(
    "verify_reviewed_identity_migrations(canonical, 'canonical identity migration control source')");
  const grantConsumption = source.indexOf("grant.update(status='consumed'");
  const resourceClient = source.indexOf("docker = ['docker', '--host', DOCKER_HOST]");
  assert.ok(controlCheck > 0 && controlCheck < grantConsumption && grantConsumption < resourceClient,
    'reviewed migration control must run before grant consumption and resource setup');
});

test('protected-history launcher proves owned process, database and exact container cleanup', () => {
  assert.match(source, /start_new_session=True/);
  assert.match(source, /terminate_group\(active_pgid/);
  assert.match(source, /DROP DATABASE IF EXISTS \{database\} WITH \(FORCE\)/);
  assert.match(source, /databaseAbsent/);
  assert.match(source, /remove_owned_container\(docker, container_name, container_id, labels\)/);
  assert.match(source, /containerNameAbsent/);
  assert.match(source, /containerIdAbsent/);
  assert.match(source, /allProcessGroupsAbsent/);
  assert.match(source, /allProcessIdsAbsent/);
  assert.match(source, /terminal_pass_cleaned/);
});

test('launcher helper contract rejects malformed nonce and inexact Docker absence', () => {
  const script = String.raw`
import importlib.util,sys
spec=importlib.util.spec_from_file_location('candidate',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert m.database_name('012345abcdef')=='dvaia_test_legacy_ai_history_012345abcdef'
for value in ('ABCDEF012345','short','012345abcdef0'):
 try:m.database_name(value)
 except ValueError:pass
 else:raise AssertionError(value)
assert m.docker_missing_exact_target('Error: No such container: exact-name\n','exact-name')
assert not m.docker_missing_exact_target('Error: No such container: exact-name-extra\n','exact-name')
assert not m.docker_missing_exact_target('permission denied','exact-name')
`;
  const result = spawnSync('python3', ['-c', script, LAUNCHER], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('immutable package inventory rejects writable source and nondependency symlinks', t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-history-launcher-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const script = String.raw`
import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('candidate',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=Path(sys.argv[2]);source=root/'source';source.mkdir();leaf=source/'reviewed.js';leaf.write_text('reviewed')
leaf.chmod(0o444);source.chmod(0o555)
inventory=m.package_inventory(root);assert inventory['sourceFiles']['source/reviewed.js']
source.chmod(0o755);leaf.chmod(0o644)
try:m.package_inventory(root)
except RuntimeError:pass
else:raise AssertionError('writable source accepted')
leaf.unlink();outside=root/'outside';outside.write_text('outside');(source/'escape').symlink_to(outside)
source.chmod(0o555)
try:m.package_inventory(root)
except RuntimeError:pass
else:raise AssertionError('source symlink accepted')
source.chmod(0o755)
`;
  const result = spawnSync('python3', ['-c', script, LAUNCHER, temporary], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('reviewed migration inventory rejects extra, missing, altered and symlink entries without source copies', () => {
  const script = String.raw`
import importlib.util,sys,io
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('candidate',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=Path(sys.argv[2]);directory=root/'db/postgres/identity-migrations'
target=directory/'0037_nosqli9_identity_content.sql'
assert len(m.REVIEWED_IDENTITY_MIGRATIONS)==61
# Verify the real current source rejects its unreviewed tail before any overlay.
actual={entry:entry.read_bytes() for entry in directory.iterdir() if entry.suffix=='.sql'}
assert any(entry.name not in m.REVIEWED_IDENTITY_MIGRATIONS for entry in actual)
def rejected(reason):
 try:m.verify_reviewed_identity_migrations(root)
 except RuntimeError:pass
 else:raise AssertionError(reason)
rejected('real unreviewed migration tail accepted')
entries=dict(actual);symlinks=set();nonfiles=set()
original_iterdir=Path.iterdir;original_open=Path.open
original_symlink=Path.is_symlink;original_file=Path.is_file
# Only the known migration directory is overlaid; hash implementation unchanged.
def iterdir(p):return iter(entries) if p==directory else original_iterdir(p)
def opened(p,*args,**kwargs):
 if p.parent==directory and p in entries:
  assert args==('rb',) and not kwargs
  return io.BytesIO(entries[p])
 return original_open(p,*args,**kwargs)
with patch.object(Path,'iterdir',iterdir),patch.object(Path,'open',opened),patch.object(Path,'is_symlink',lambda p:p in symlinks or original_symlink(p)),patch.object(Path,'is_file',lambda p:False if p in nonfiles else original_file(p)):
 rejected('overlay unreviewed tail accepted')
 entries={p:b for p,b in actual.items() if p.name in m.REVIEWED_IDENTITY_MIGRATIONS}
 assert m.verify_reviewed_identity_migrations(root)==m.REVIEWED_IDENTITY_MIGRATIONS_SHA256
 content=entries.pop(target);rejected('missing intermediate accepted')
 entries[target]=content
 assert m.verify_reviewed_identity_migrations(root)==m.REVIEWED_IDENTITY_MIGRATIONS_SHA256
 entries[target]=content+b'\n-- altered negative fixture\n';rejected('altered intermediate accepted')
 entries[target]=content;symlinks.add(target);rejected('SQL symlink accepted')
 symlinks.clear();nonfiles.add(target);rejected('non-file SQL entry accepted')
 nonfiles.clear();symlinks.add(directory);rejected('symlink migration directory accepted')
# Real source never changed, including the extra migration tail.
assert actual=={entry:entry.read_bytes() for entry in directory.iterdir() if entry.suffix=='.sql'}
`;
  const result = spawnSync('python3', ['-B', '-c', script, LAUNCHER, ROOT], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
