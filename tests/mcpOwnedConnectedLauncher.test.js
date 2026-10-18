'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');

test('connected launcher rejects changed source, copied bytes, and grant inventory before external mutation', t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-mcp-launcher-provenance-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const source = path.join(temporary, 'source');
  const copied = path.join(temporary, 'copied');
  fs.mkdirSync(source); fs.mkdirSync(copied);
  fs.writeFileSync(path.join(source, 'one.txt'), 'reviewed');
  fs.writeFileSync(path.join(copied, 'one.txt'), 'reviewed');
  const helper = path.join(root, 'tests/postgres/native_source_provenance.py');
  const python = String.raw`
import hashlib,sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
from native_source_provenance import verify_source_copy
source,copied=Path(sys.argv[2]),Path(sys.argv[3]); tracked=['one.txt']
expected={'one.txt':hashlib.sha256(b'reviewed').hexdigest()}
assert verify_source_copy(source,copied,tracked,granted=expected)==expected
for missing in (None,{}):
 try: verify_source_copy(source,copied,tracked,granted=missing)
 except RuntimeError: pass
 else: raise AssertionError('missing/null grant inventory was accepted')
for mutation in ('copy','grant','source'):
 if mutation=='copy': (copied/'one.txt').write_text('changed')
 if mutation=='source': (source/'one.txt').write_text('changed')
 grant=expected if mutation!='grant' else {'one.txt':'0'*64}
 try: verify_source_copy(source,copied,tracked,granted=grant)
 except RuntimeError: pass
 else: raise AssertionError(mutation+' mutation was accepted')
 if mutation=='copy': (copied/'one.txt').write_text('reviewed')
 if mutation=='source': (source/'one.txt').write_text('reviewed')
`;
  const result = spawnSync('python3', ['-c', python, helper, source, copied], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(result.status, 0, result.stderr);

  const launcher = fs.readFileSync(path.join(root,
    'tests/postgres/run-mcp-owned-connected-isolated.py'), 'utf8');
  const inventoryPath = path.join(root,
    'docs/modernization/drafts/mcp-owned-connected-v20-tracked-files-2026-09-14.json');
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  assert.equal(inventory.version, 1);
  assert.deepEqual(inventory.trackedFiles, [...new Set(inventory.trackedFiles)].sort());
  for (const required of [
    'docs/modernization/drafts/mcp-owned-connected-v20-tracked-files-2026-09-14.json',
    'server/routes/mcpWorkshop.js', 'server/services/mcp/config.js',
    'server/services/mcp/ownedTargetClient.js', 'server/services/workshopConfigService.js',
    'server/services/mcp/catalogObservation.js',
    'server/services/mcp/observedActionObservation.js',
    'server/services/mcp/protectedStateObservation.js', 'server/services/mcpObjectiveGrader.js',
    'tests/objectiveJudgmentRepositoryMetadata.test.js',
    'docs/modernization/drafts/graph-judge-validation-code.sql',
    'tests/graphJudgeValidationCodeDraft.test.js',
    'tests/postgres/graphJudgeValidationCode.integration.test.js',
    'server/services/platformSigningConfiguration.js',
    'sidecars/sandbox-runner/mcpProtectedState.js',
    'sidecars/sandbox-runner/mcpPackageCatalog.js',
    'sidecars/sandbox-runner/package.json',
    'sidecars/sandbox-runner/entrypoint.sh',
    'sidecars/sandbox-runner/labfs/opt/app/config/.env',
    'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt',
    'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz',
    'server/utils/progressSync.js', 'scripts/render-mcp-sandbox-apparmor.js',
    'tests/postgres/mcpOwnedConnected.integration.test.js',
    'tests/postgres/native_readiness_evidence.py',
    'tests/postgres/native_copied_permissions.py',
    'tests/postgres/run-mcp-owned-connected-isolated.py',
    'db/postgres/identity-migrations/0061_mcp_supply_chain_curriculum_defaults.sql',
  ]) assert.ok(inventory.trackedFiles.includes(required), required);
  assert.match(launcher, /workspace\/'scripts\/render-mcp-sandbox-apparmor\.js'/);
  assert.match(launcher, /'scripts\/render-mcp-sandbox-apparmor\.js'/);
  assert.match(launcher, /inventory\.get\('trackedFiles'\)/);
  assert.match(launcher, /make_copied_directories_owner_writable\(workspace\)/);
  assert.match(launcher, /jwt_secret=secrets\.token_urlsafe\(64\)/);
  assert.match(launcher, /JWT_SECRET=jwt_secret/);
  assert.match(launcher, /choices=\['protected-state','tool-poisoning','recon','recon-production'\]/);
  assert.match(launcher, /MCP_OBSERVED_ACTION_CANDIDATE='yes' if tool_poisoning_candidate else 'no'/);
  assert.match(launcher, /MCP_CATALOG_RECON_CANDIDATE='yes' if recon_candidate else 'no'/);
  assert.match(launcher, /MCP_CATALOG_RECON_PRODUCTION='yes' if recon_production else 'no'/);
  assert.match(launcher, /'installerPath':'production' if recon_production else \('test-only-candidate' if recon_candidate else 'existing'\)/);
  assert.match(launcher, /'objectives':\['mcp_recon'\] if \(recon_candidate or recon_production\)/);
  assert.match(launcher, /observedActionCapability':'mcp-owned-observed-action\.v1'/);
  assert.match(launcher, /packageInstallCapability':'mcp-owned-package-install\.v1'/);
  assert.match(launcher, /workspace\/'sidecars\/sandbox-runner\/labfs\/opt\/app\/config\/\.env'\)\.write_bytes/);
  assert.match(launcher, /workspace\/'sidecars\/sandbox-runner\/labfs\/opt\/app\/config\/\.env'\)\.chmod\(0o444\)/);
  const runnerDockerfile = fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/Dockerfile'), 'utf8');
  assert.match(runnerDockerfile, /chmod -R a\+rX \/opt\/lab-template/);
  assert.ok(launcher.indexOf("granted=grant.get('sourceHashes')") <
    launcher.indexOf('remote_creation_attempted=True'));

  const qualifier = fs.readFileSync(path.join(root,
    'tests/postgres/mcpOwnedConnected.integration.test.js'), 'utf8');
  assert.doesNotMatch(qualifier, /dvaia-secret-key-2024/);
  for (const registered of [
    '0047_secureshop_persona_inbox_catalog.sql',
    '0048_workshop_catalog_field_provenance.sql',
    '0049_workshop_catalog_persona_adoption.sql',
    '0050_mcp_conversation_history.sql',
    '0051_secureshop_mcp_trust.sql',
    '0052_secureshop_controlled_ssrf.sql',
    '0053_codebot_request_journal.sql',
    '0054_finflow_log_policy_defaults.sql',
    '0055_finflow_admin_artifact_defaults.sql',
    '0056_finflow_authentic_curriculum_defaults.sql',
    '0057_graph_agent_outcome.sql',
    '0058_finflow_durable_log_overlay_tip.sql',
    '0059_dpi_policy_trace_metadata.sql',
    '0060_finflow_description_default.sql',
    '0061_mcp_supply_chain_curriculum_defaults.sql',
  ]) assert.match(qualifier, new RegExp(`registeredIdentityTail[\\s\\S]*${registered}`));
  assert.match(qualifier, /ORDER BY name DESC LIMIT 1/);
  assert.doesNotMatch(qualifier, /stagedIdentityCandidate|mcpCandidateBytes/);
  assert.doesNotMatch(qualifier, /for \(const \[name, draft, checksum\] of identityCandidates\)/);
  assert.match(qualifier, /production\._internals\.installObservedActionCandidate/);
  assert.match(qualifier, /production\._internals\.installCatalogReconCandidate/);
  assert.match(qualifier, /catalogReconProduction \|\| indirectProduction\) \{\s*assert\.strictEqual\(installCandidate, production\.installMcpOwnedResourceProduction\)/);
  assert.match(qualifier, /installerPath: catalogReconProduction \? 'production' : 'test-only-candidate'/);
  assert.match(qualifier, /CATALOG_QUALIFIED_OBJECTIVES/);
  assert.match(qualifier, /catalogWitness/);
  assert.match(qualifier, /authoritative_sdk_catalog/);
  assert.match(qualifier, /mcp_owned_recon\.v3/);
  assert.match(qualifier, /learner_response_catalog_names/);
  assert.match(qualifier, /learner_facing_catalog_names_and_purposes/);
  assert.match(qualifier, /catalog purpose grading must remain a semantic Judge decision/);
  assert.match(qualifier, /namedRefusal = 'I cannot explain run_command or read_file/);
  assert.match(qualifier, /namedRefusalJudgment = await actualJudge/);
  assert.match(qualifier, /Judge-only named-refusal control performed a new SDK catalog request/);
  assert.match(qualifier, /Judge-only named-refusal control wrote durable workflow state/);
  assert.match(qualifier, /MCP_PROTOCOL_TEST_UNAVAILABLE/);
  assert.match(qualifier, /sdkListToolsInvocations/);
  assert.match(qualifier, /judgeInvocations/);
  assert.match(qualifier, /request-id replay invoked the SDK catalog or Judge again/);
  assert.match(qualifier, /gradingRetryExercised: false/);
  assert.match(qualifier, /progressAfterCredit\.runtimeQualification\.objectives\s*\n\s*\.find\(item => item\.objectiveId === 'mcp_recon'\)\?\.qualified, true/);
  assert.doesNotMatch(qualifier, /progressAfterCredit\.objectives\.find/);
  assert.match(qualifier, /progressAfterReset\.completed\.includes\('mcp_recon'\), false/);
  assert.match(qualifier, /direct-read-denied/);
  assert.match(qualifier, /trusted_observed_action_receipt/);
  assert.match(qualifier, /mcp_observed_action\.v4/);
  assert.match(qualifier, /observedActionWitness/);
  assert.match(qualifier, /protected_file_disclosed/);
  assert.match(qualifier, /revokedSessionDenied: true/);
  assert.match(qualifier, /assert\.equal\(response\.toolUsed, 'check_system_status'\)/);
  assert.match(qualifier, /const compound = response\.toolResult/);
  assert.doesNotMatch(qualifier, /const compound = response\.toolObservations\[0\]/);
  assert.match(qualifier, /approvedProtectedFixtures/);
  assert.match(qualifier, /assert\.equal\(compound\.consequenceOutput, protectedFixture\)/);
  assert.match(qualifier, /assert\.equal\(observedWitness\?\.returned\?\.sha256, protectedFixtureSha256\)/);
  assert.doesNotMatch(qualifier, /TRAINING_MASTER_KEY/);
});
// Native qualifier retains actual approvedProtectedFixtures bytes and witness digest checks.
// This unit format example does not qualify the installed protected file.
test('synthetic protected-file format example; actual native byte integrity is a separate pending gate', () => {
  const protectedFixture = 'ACME CORP — MASTER ENCRYPTION KEY\nKey ID: mk-prod-2026-001\nAlgorithm: AES-256-GCM\nKey: SYNTHETIC_UNIT_ONLY';
  assert.match(protectedFixture, /^ACME CORP — MASTER ENCRYPTION KEY/m);
  assert.match(protectedFixture, /^Key ID:\s+mk-prod-2026-001$/m);
  assert.match(protectedFixture, /^Algorithm:\s+AES-256-GCM$/m);
  assert.match(protectedFixture, /^Key:\s+\S+$/m);
});

test('copied directory repair preserves readonly source and rejects symlink escape', t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-mcp-copy-modes-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const helper = path.join(root, 'tests/postgres/native_copied_permissions.py');
  const python = String.raw`
import os,shutil,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent))
from native_copied_permissions import make_copied_directories_owner_writable
temporary=Path(sys.argv[2]).resolve()
source=temporary/'readonly-source'; nested=source/'sidecars'/'fixture'
nested.mkdir(parents=True); reviewed=nested/'reviewed.txt'; reviewed.write_text('reviewed')
reviewed.chmod(0o444)
for directory in [nested,nested.parent,source]: directory.chmod(0o555)
copied=temporary/'copied'; shutil.copytree(source,copied)
make_copied_directories_owner_writable(copied)
fixture=copied/'sidecars'/'fixture'/'generated.env'; fixture.write_text('SYNTHETIC=1\n')
assert fixture.read_text()=='SYNTHETIC=1\n'
assert stat.S_IMODE(source.lstat().st_mode)==0o555
assert stat.S_IMODE(nested.lstat().st_mode)==0o555
assert stat.S_IMODE(reviewed.lstat().st_mode)==0o444
assert stat.S_IMODE((copied/'sidecars'/'fixture'/'reviewed.txt').lstat().st_mode)==0o444
assert stat.S_IMODE((copied/'sidecars'/'fixture').lstat().st_mode)&0o300==0o300

outside=temporary/'outside'; outside.mkdir(); outside.chmod(0o555)
bad=temporary/'bad-copy'; bad.mkdir()
(bad/'outside-link').symlink_to(outside,target_is_directory=True); bad.chmod(0o555)
try: make_copied_directories_owner_writable(bad)
except RuntimeError: pass
else: raise AssertionError('copied directory symlink was accepted')
assert stat.S_IMODE(bad.lstat().st_mode)==0o555
assert stat.S_IMODE(outside.lstat().st_mode)==0o555

root_link=temporary/'root-link'; root_link.symlink_to(outside,target_is_directory=True)
try: make_copied_directories_owner_writable(root_link)
except RuntimeError: pass
else: raise AssertionError('symlinked copied root was accepted')
assert stat.S_IMODE(outside.lstat().st_mode)==0o555
for directory in [source,source/'sidecars',nested,bad,outside]: directory.chmod(0o700)
`;
  const result = spawnSync('python3', ['-c', python, helper, temporary], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(result.status, 0, result.stderr);
});

test('readiness failure evidence survives independent owned cleanup', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-mcp-readiness-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const helper = path.join(root, 'tests/postgres/native_readiness_evidence.py');
  const script = String.raw`
import json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent))
from native_readiness_evidence import capture_failure,probe
root=Path(sys.argv[2]); fake=root/'fake-docker'
fake.write_text("#!/bin/sh\ncase \"$1\" in\n inspect) printf '%s\\n' '{\"Status\":\"exited\",\"Running\":false,\"ExitCode\":7}' ;;\n logs) printf 'bounded owned startup failure\\n' >&2; exit 7 ;;\n rm) rm -f \"$3\" ;;\nesac\n")
fake.chmod(0o700)
services={'postgres':probe(['/bin/sh','-c','exit 1'],{},2),
          'mailpit':probe(['/bin/sh','-c','exit 0'],{},2),
          'runner':probe(['/bin/sh','-c','printf not-json'],{},2,health=True)}
record=capture_failure(root,services,{'runner':'owned-runner'},[str(fake)],{})
assert services['postgres']['status']=='unavailable'
assert services['runner']['status']=='invalid-response'
assert Path(record['path']).stat().st_mode & 0o777 == 0o600
assert Path(record['logs']['runner']['path']).stat().st_mode & 0o777 == 0o600
before=Path(record['path']).read_bytes()
(root/'owned-runner').write_text('owned')
os.unlink(root/'owned-runner')
assert Path(record['path']).read_bytes()==before
payload=json.loads(before)
assert payload['containers']['runner']['state']['ExitCode']==7
assert payload['logs']['runner']['sha256']==record['logs']['runner']['sha256']
log_payload=json.loads(Path(record['logs']['runner']['path']).read_text())
assert len(log_payload['stderr'])<=4096
`;
  const result = spawnSync('python3', ['-c', script, helper, directory], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(result.status, 0, result.stderr);
});

test('copied synthetic target fixture is made readable after a conservative launcher umask', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-mcp-fixture-mode-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, '.env');
  const prior = process.umask(0o077);
  try { fs.writeFileSync(file, 'TRAINING_ONLY=1\n'); }
  finally { process.umask(prior); }
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  fs.chmodSync(file, 0o444);
  assert.equal(fs.statSync(file).mode & 0o777, 0o444);
  assert.equal(fs.readFileSync(file, 'utf8'), 'TRAINING_ONLY=1\n');
});
