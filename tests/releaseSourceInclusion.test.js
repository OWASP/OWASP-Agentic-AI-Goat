'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  CONTROLLED_TEACHING_FIXTURE_SHA256,
  RUNTIME_ASSET_PATHS,
  SOURCE_PLAN_RULES,
  collectApprovedSourcePlan,
  inspectRepository,
  isForbiddenPath,
} = require('../scripts/verify-release-source-inclusion');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-source-inclusion-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'client'), { recursive: true });
  fs.mkdirSync(path.join(root, 'scripts', 'lib'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { verify: 'node scripts/check.js' } }));
  fs.writeFileSync(path.join(root, 'client/package.json'), JSON.stringify({ scripts: {}, jest: {} }));
  fs.writeFileSync(path.join(root, 'scripts/check.js'), "require('./lib/current');\n");
  fs.writeFileSync(path.join(root, 'scripts/lib/current.js'), 'module.exports = true;\n');
  return root;
}

function inspect(root, overrides = {}) {
  return inspectRepository({
    repoRoot: root,
    rootScriptNames: ['verify'],
    clientScriptNames: [],
    directSourcePaths: [],
    migrationDirectories: [],
    seedDirectory: 'absent-seeds',
    buildManifestPath: 'absent-build-manifest.json',
    sourcePlanRules: [],
    runtimeAssetPaths: [],
    teachingFixtureHashes: {},
    trackedPaths: ['package.json', 'client/package.json', 'scripts/check.js'],
    stagedPaths: [],
    ...overrides,
  });
}

test('live script imports define the closure without freezing the historical inventory', t => {
  const root = fixture(t);
  let result = inspect(root);
  assert.deepEqual(result.entrypoints, ['scripts/check.js']);
  assert.deepEqual(result.untracked, ['scripts/lib/current.js']);
  assert.equal(result.counts.localImportClosure, 2);

  fs.writeFileSync(path.join(root, 'scripts/lib/future.js'), 'module.exports = true;\n');
  fs.writeFileSync(path.join(root, 'scripts/check.js'), "require('./lib/future');\n");
  result = inspect(root, { trackedPaths: ['package.json', 'client/package.json', 'scripts/check.js', 'scripts/lib/future.js'] });
  assert.equal(result.counts.localImportClosure, 2);
  assert.deepEqual(result.untracked, []);
  assert.ok(!result.requiredPaths.includes('scripts/lib/current.js'));
});

test('tracked source omitted from an explicit candidate is reported independently', t => {
  const root = fixture(t);
  const trackedPaths = ['package.json', 'client/package.json', 'scripts/check.js', 'scripts/lib/current.js'];
  const result = inspect(root, {
    trackedPaths,
    candidateExportPaths: trackedPaths.filter(name => name !== 'scripts/lib/current.js'),
  });
  assert.deepEqual(result.untracked, []);
  assert.deepEqual(result.missingFromCandidate, ['scripts/lib/current.js']);
  assert.equal(result.counts.missingFromCandidate, 1);
  assert.deepEqual(inspect(root, { trackedPaths, candidateExportPaths: trackedPaths }).missingFromCandidate, []);
});

test('approved source roots include unimported application source and public assets', t => {
  const root = fixture(t);
  const files = {
    'server/unimported.mjs': 'export default true;\n',
    'scripts/unimported.cjs': 'module.exports = true;\n',
    'db/postgres/unimported.js': 'module.exports = true;\n',
    'sidecars/example/native.c': 'int main(void) { return 0; }\n',
    'sidecars/example/network.json': '{}\n',
    'sidecars/example/Dockerfile.test': 'FROM scratch\n',
    'agent-host/unimported.js': 'module.exports = true;\n',
    'client/src/Unimported.jsx': 'export default null;\n',
    'client/src/style.css': 'body {}\n',
    'client/public/icon.svg': '<svg/>\n',
    'server/not-source.txt': 'not selected\n',
  };
  for (const [relative, contents] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), contents);
  }

  const result = inspect(root, { sourcePlanRules: SOURCE_PLAN_RULES });
  for (const relative of Object.keys(files).filter(filename => filename !== 'server/not-source.txt')) {
    assert.ok(result.requiredPaths.includes(relative), relative);
  }
  assert.ok(!result.requiredPaths.includes('server/not-source.txt'));
});

test('explicit runtime assets include non-JavaScript helpers and data without import discovery', t => {
  const root = fixture(t);
  const paths = [
    'start_all.sh',
    'scripts/lib/archive-installed-history.py',
    'docs/modernization/learning-dependencies.json',
    'server/assets/csrf_samples/csrf_x1_solution.html',
    'server/workshop_data/transactions/FF-001.json',
    'server/sensitive_files/traversal-fixtures/etc/passwd',
    'sidecars/analytics-sql-target/control-migrations/0001_control.sql',
    'sidecars/sandbox-runner/entrypoint.sh',
  ];
  for (const relative of paths) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), 'controlled fixture\n');
  }
  const result = inspect(root, { runtimeAssetPaths: paths });
  assert.deepEqual(result.runtimeAssetPaths, paths);
  for (const relative of paths) assert.ok(result.requiredPaths.includes(relative), relative);
});

test('independent Windows prerequisites are included in the release without maintenance recovery authority', () => {
  const component = 'scripts/install/Windows/prerequisites.ps1';
  assert.ok(RUNTIME_ASSET_PATHS.includes(component));
  const manifest = require('../server/services/applicationMaintenanceInprocessSources-v35.json');
  assert.equal(Object.hasOwn(manifest.files, component), false);
  assert.equal(manifest.recoveryFiles.includes(component), false);
});

test('independent Windows package component is required release source without maintenance authority', () => {
  const component = 'scripts/install/Windows/packages.ps1';
  assert.equal(RUNTIME_ASSET_PATHS.filter(relative => relative === component).length, 1);
  const manifest = require('../server/services/applicationMaintenanceInprocessSources-v35.json');
  assert.equal(Object.hasOwn(manifest.files, component), false);
  assert.equal(manifest.recoveryFiles.includes(component), false);
});

test('Windows prerequisite coordinator is included without granting maintenance authority', () => {
  const component = 'scripts/install/Windows/dependencies.ps1';
  assert.equal(RUNTIME_ASSET_PATHS.filter(relative => relative === component).length, 1);
  const manifest = require('../server/services/applicationMaintenanceInprocessSources-v38.json');
  assert.equal(Object.hasOwn(manifest.files, component), false);
  assert.equal(manifest.recoveryFiles.includes(component), false);
});
test('masked owned teaching build fixtures retain exact release hashes outside maintenance admission',()=>{
 const manifest=require('../server/services/applicationMaintenanceInprocessSources-v44.json');
 const fixtures={
  'sidecars/sandbox-runner/labfs/opt/app/config/.env':'c90c0fb0c438f25014ca86033d6758c75c7dd1e08b453ce0bdfd179d1b919a7f',
  'sidecars/sandbox-runner/labfs/var/secrets/credentials.json':'1c6eef81a9d339d2c751d9efd4b755e8badb303848f8ce8ec0033353b0d30734',
  'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt':'6a3179f3d798450ddc12f6cff75ab45c4383a45695a43dfdf11c5475d806436f',
 };
 for(const [name,sha256] of Object.entries(fixtures)){assert.equal(CONTROLLED_TEACHING_FIXTURE_SHA256[name],sha256);assert(RUNTIME_ASSET_PATHS.includes(name));assert.equal(Object.hasOwn(manifest.files,name),false);assert.equal(manifest.recoveryFiles.includes(name),false);}
 assert(RUNTIME_ASSET_PATHS.includes('scripts/install/Windows/owned-hyperv-observer.ps1'));
});
test('Windows base service helper was release inventory before v44 maintenance binding',()=>{
 const component='scripts/install/windows-base-lab-services.js',root=path.resolve(__dirname,'..');
 assert(collectApprovedSourcePlan(root,SOURCE_PLAN_RULES.filter(rule=>rule.directory==='scripts')).includes(component));
 const manifest=require('../server/services/applicationMaintenanceInprocessSources-v43.json');
 assert.equal(Object.hasOwn(manifest.files,component),false);assert.equal(manifest.recoveryFiles.includes(component),false);
});

test('default runtime inventory binds current manifests, helpers, assets and sidecar inputs', () => {
  const expected = [
    'start_all.sh',
    'stop_all.sh',
    'scripts/install/runtime-version-policy.sh',
    'scripts/install/qualification/secureshop-listings-package-2026-10-10.json',
    'scripts/lib/archive-installed-history.py',
    'scripts/windows/windows-private-state.ps1',
    'scripts/windows/windows-private-state.cs',
    'scripts/windows/windows-owned-process.ps1',
    'scripts/windows/windows-owned-process.cs',
    'scripts/windows/windows-private-publication.ps1',
    'scripts/windows/windows-private-publication.cs',
    'scripts/windows/windows-process-identity.ps1',
    'scripts/windows/windows-process-identity.cs',
    'scripts/install/Windows/dependency-plan.ps1',
    'scripts/install/Windows/wrapper-handoff.ps1',
    'scripts/install/Windows/prerequisites.ps1',
    'scripts/install/Windows/packages.ps1',
    'scripts/install/Windows/dependencies.ps1',
  'scripts/install/Windows/host-preflight.ps1',
  'scripts/install/Windows/owned-hyperv-observer.ps1',
    'docs/modernization/learning-dependencies.json',
    'docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json',
    'server/services/applicationMaintenanceInprocessSources.json',
    'server/services/applicationMaintenanceInprocessSources-v10.json',
    'server/services/applicationMaintenanceInprocessSources-v11.json',
  'server/services/applicationMaintenanceInprocessSources-v12.json',
  'server/services/applicationMaintenanceInprocessSources-v13.json',
  'server/services/applicationMaintenanceInprocessSources-v14.json',
  'server/services/applicationMaintenanceInprocessSources-v15.json',
  'server/services/applicationMaintenanceInprocessSources-v16.json',
  'server/services/applicationMaintenanceInprocessSources-v17.json',
  'server/services/applicationMaintenanceInprocessSources-v18.json',
  'server/services/applicationMaintenanceInprocessSources-v19.json',
  'server/services/applicationMaintenanceInprocessSources-v20.json',
  'server/services/applicationMaintenanceInprocessSources-v21.json',
  'server/services/applicationMaintenanceInprocessSources-v22.json',
  'server/services/applicationMaintenanceInprocessSources-v23.json',
  'server/services/applicationMaintenanceInprocessSources-v24.json',
  'server/services/applicationMaintenanceInprocessSources-v25.json',
  'server/services/applicationMaintenanceInprocessSources-v26.json',
  'server/services/applicationMaintenanceInprocessSources-v27.json',
  'server/services/applicationMaintenanceInprocessSources-v28.json',
  'server/services/applicationMaintenanceInprocessSources-v29.json',
  'server/services/applicationMaintenanceInprocessSources-v30.json',
  'server/services/applicationMaintenanceInprocessSources-v31.json',
  'server/services/applicationMaintenanceInprocessSources-v32.json',
  'server/services/applicationMaintenanceInprocessSources-v33.json',
  'server/services/applicationMaintenanceInprocessSources-v34.json',
  'server/services/applicationMaintenanceInprocessSources-v35.json',
  'server/services/applicationMaintenanceInprocessSources-v36.json',
  'server/services/applicationMaintenanceInprocessSources-v37.json',
  'server/services/applicationMaintenanceInprocessSources-v38.json',
  'server/services/applicationMaintenanceInprocessSources-v39.json',
  'server/services/applicationMaintenanceInprocessSources-v40.json',
  'server/services/applicationMaintenanceInprocessSources-v41.json',
  'server/services/applicationMaintenanceInprocessSources-v42.json',
  'server/services/applicationMaintenanceInprocessSources-v43.json',
  'server/services/applicationMaintenanceInprocessSources-v44.json',
  'server/services/applicationMaintenanceInprocessSources-v45.json',
  'server/services/applicationMaintenanceInprocessSources-v46.json',
    'server/assets/rag_samples/normal_policy.txt',
    'server/assets/csrf_samples/csrf_x3_solution.html',
    'server/workshop_data/transactions/FF-001.json',
    'server/sensitive_files/traversal-fixtures/config/secrets.env',
    'sidecars/audit-sql-target/schema.sql',
    'sidecars/analytics-sql-target/control-migrations/0001_control.sql',
    'sidecars/sandbox-runner/entrypoint.sh',
    'sidecars/sandbox-runner/labfs/opt/lab/packages/analytics-boost-1.0.0.tgz',
  ];
  for (const relative of expected) assert.ok(RUNTIME_ASSET_PATHS.includes(relative), relative);
  for (let version = 2; version <= 87; version += 1) {
    assert.ok(RUNTIME_ASSET_PATHS.includes(`server/services/applicationMaintenanceInprocessSources-v${version}.json`));
  }
  for (const relative of Object.keys(CONTROLLED_TEACHING_FIXTURE_SHA256)) {
    assert.ok(RUNTIME_ASSET_PATHS.includes(relative), relative);
  }
});

test('missing, forbidden and private findings report paths without exposing file contents', t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, 'scripts/check.js'), "require('./missing'); const evidence='backups/private-recovery/secret-token-value';\n");
  const result = inspect(root, {
    directSourcePaths: ['tasks/private-receipt.json'],
    stagedPaths: ['server/database/runtime.db'],
  });
  assert.ok(result.missing.some(item => item.requested === './missing'));
  assert.deepEqual(result.privateReferences, ['scripts/check.js']);
  assert.deepEqual(result.forbiddenRequired, ['tasks/private-receipt.json']);
  assert.deepEqual(result.forbiddenStaged, ['server/database/runtime.db']);
  assert.ok(!JSON.stringify(result).includes('secret-token-value'));
});

test('candidate export inventory rejects private data while retaining source and placeholders', t => {
  const root = fixture(t);
  const candidateExportPaths = [
    '.env.local',
    'server/database/legacy.db',
    'tasks/private.json',
    '.env.example',
    'agent-host/agents/uploads/tools/index.js',
    'server/uploads/secureshop/.gitkeep',
    'server/database/vector-indexes/.gitkeep',
    'server/uploads/secureshop/avatars/private.png',
    'server/database/vector-indexes/manuals.hnsw',
    'client/public/.env',
    'client/public/.env.local',
  ];
  const result = inspect(root, { candidateExportPaths });
  assert.deepEqual(result.forbiddenExport, [
    '.env.local',
    'client/public/.env',
    'client/public/.env.local',
    'server/database/legacy.db',
    'server/database/vector-indexes/manuals.hnsw',
    'server/uploads/secureshop/avatars/private.png',
    'tasks/private.json',
  ]);
});

test('controlled teaching env and archives require exact path and digest', t => {
  const root = fixture(t);
  const crypto = require('node:crypto');
  const controlledEnv = 'sidecars/sandbox-runner/labfs/opt/app/config/.env';
  const controlledArchive = 'sidecars/sandbox-runner/labfs/opt/lab/packages/lesson.tgz';
  const bytes = Buffer.from('synthetic teaching bytes\n');
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  for (const relative of [controlledEnv, controlledArchive]) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), bytes);
  }
  const teachingFixtureHashes = { [controlledEnv]: expected, [controlledArchive]: expected };
  let result = inspect(root, {
    runtimeAssetPaths: [controlledEnv, controlledArchive],
    teachingFixtureHashes,
    candidateExportPaths: [controlledEnv, controlledArchive, 'client/public/.env.local', 'client/public/private.tgz'],
    candidateExportHashes: { [controlledEnv]: expected, [controlledArchive]: expected },
  });
  assert.deepEqual(result.teachingFixtureDigestMismatches, []);
  assert.deepEqual(result.teachingFixtureCandidateDigestMismatches, []);
  assert.deepEqual(result.forbiddenRequired, []);
  assert.deepEqual(result.forbiddenExport, ['client/public/.env.local', 'client/public/private.tgz']);

  fs.writeFileSync(path.join(root, controlledEnv), 'changed\n');
  result = inspect(root, {
    runtimeAssetPaths: [controlledEnv, controlledArchive],
    teachingFixtureHashes,
    candidateExportPaths: [controlledEnv, controlledArchive],
    candidateExportHashes: { [controlledEnv]: expected, [controlledArchive]: expected },
  });
  assert.deepEqual(result.teachingFixtureDigestMismatches, [controlledEnv]);
  assert.deepEqual(result.teachingFixtureCandidateDigestMismatches, []);
  assert.deepEqual(result.forbiddenRequired, [controlledEnv]);
  assert.deepEqual(result.forbiddenExport, []);
});

test('candidate teaching exception hashes index bytes independently of the worktree', t => {
  const root = fixture(t);
  const crypto = require('node:crypto');
  const controlledEnv = 'sidecars/sandbox-runner/labfs/opt/app/config/.env';
  const bytes = Buffer.from('known synthetic teaching bytes\n');
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  const stagedDifferent = crypto.createHash('sha256').update('unsafe staged bytes\n').digest('hex');
  fs.mkdirSync(path.dirname(path.join(root, controlledEnv)), { recursive: true });
  fs.writeFileSync(path.join(root, controlledEnv), bytes);

  const result = inspect(root, {
    runtimeAssetPaths: [controlledEnv],
    teachingFixtureHashes: { [controlledEnv]: expected },
    candidateExportPaths: [controlledEnv],
    candidateExportHashes: { [controlledEnv]: stagedDifferent },
  });
  assert.deepEqual(result.teachingFixtureDigestMismatches, []);
  assert.deepEqual(result.teachingFixtureCandidateDigestMismatches, [controlledEnv]);
  assert.deepEqual(result.forbiddenRequired, []);
  assert.deepEqual(result.forbiddenExport, [controlledEnv]);
});

test('forbidden path classification keeps source migrations and rejects runtime artifacts', () => {
  assert.equal(isForbiddenPath('db/postgres/workshop-migrations/aria/0001.sql'), false);
  assert.equal(isForbiddenPath('.env.example'), false);
  assert.equal(isForbiddenPath('agent-host/agents/uploads/tools/index.js'), false);
  assert.equal(isForbiddenPath('server/uploads/secureshop/.gitkeep'), false);
  assert.equal(isForbiddenPath('server/database/vector-indexes/.gitkeep'), false);
  assert.equal(isForbiddenPath('server/uploads/secureshop/avatars/private.png'), true);
  assert.equal(isForbiddenPath('server/database/vector-indexes/manuals.hnsw'), true);
  assert.equal(isForbiddenPath('client/public/private.tgz'), true);
  assert.equal(isForbiddenPath('server/database/lesson.db-wal'), true);
  assert.equal(isForbiddenPath('backups/private-recovery/receipt.json'), true);
  assert.equal(isForbiddenPath('scripts/__pycache__/probe.cpython-314.pyc'), true);
  assert.equal(isForbiddenPath('tests/fixtures/probe.pyc'), true);
  assert.equal(isForbiddenPath('tests/fixtures/probe.pyo'), true);
});

test('generated frontend captures are rejected from staged and exported source without excluding portable inputs', t => {
  const root = fixture(t);
  const generated = [
    'tests/release-inputs/frontend-build-owned/report.json',
    'tests/release-inputs/frontend-build-owned/inputs-before.json',
    'tests/release-inputs/frontend-build-owned/tmp/node-compile-cache/v26/01f4a2c2',
  ];
  const portable = [
    'tests/release-inputs/record-current-frontend-build.py',
    'tests/release-inputs/mail-browser-frozen-inputs.json',
    'tests/release-inputs/frontend-build-contract.json',
    'tests/fixtures/frontend-build-owned/report.json',
  ];
  for (const filename of [...generated, ...portable]) {
    fs.mkdirSync(path.dirname(path.join(root, filename)), { recursive: true });
    fs.writeFileSync(path.join(root, filename), 'retained bytes\n');
  }
  const result = inspect(root, {
    trackedPaths: portable,
    stagedPaths: [...portable, ...generated],
    candidateExportPaths: [...portable, ...generated],
    runtimeAssetPaths: portable,
  });
  assert.deepEqual(result.forbiddenStaged, [...generated].sort());
  assert.deepEqual(result.forbiddenExport, [...generated].sort());
  assert.deepEqual(result.forbiddenRequired, []);
  assert(portable.every(filename => !isForbiddenPath(filename)));
  for (const filename of [...generated, ...portable]) {
    assert.equal(fs.readFileSync(path.join(root, filename), 'utf8'), 'retained bytes\n');
  }

  // Exercise Git's actual directory rule, not a second approximation of the glob.
  const { spawnSync } = require('node:child_process');
  fs.copyFileSync(path.join(__dirname, '..', '.gitignore'), path.join(root, '.gitignore'));
  const gitCommand = process.platform === 'darwin'
    && fs.existsSync('/Library/Developer/CommandLineTools/usr/bin/git')
    ? '/Library/Developer/CommandLineTools/usr/bin/git' : 'git';
  const git = args => spawnSync(gitCommand, ['-C', root, ...args], {
    encoding: 'utf8',
    // The isolated unit boundary intentionally excludes the host Xcode Git
    // configuration. This assertion needs only the copied repository rule.
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
  });
  const initialized = git(['init', '--quiet']);
  assert.equal(initialized.status, 0, initialized.stderr);
  // Pass paths explicitly to avoid depending on the caller's Git index.
  const checked = git(['check-ignore', '--no-index', ...generated, ...portable]);
  assert.equal(checked.status, 0);
  assert.deepEqual(checked.stdout.trim().split('\n').sort(), [...generated].sort());
});

test('reached Windows wrappers base teaching build and Audit bootstrap inputs are sealed by v44',()=>{
 const manifest=require('../server/services/applicationMaintenanceInprocessSources-v44.json');
 const required=[
  "scripts/install/Windows/dependencies.ps1",
  "scripts/install/Windows/dependency-plan.ps1",
  "scripts/install/Windows/install-windows.ps1",
  "scripts/install/Windows/packages.ps1",
  "scripts/install/Windows/prerequisites.ps1",
  "scripts/install/Windows/start_all.ps1",
  "scripts/install/Windows/wrapper-handoff.ps1",
  "scripts/install/audit-sql-activate.js",
  "scripts/install/audit-sql-target.js",
  "scripts/install/windows-base-lab-services.js",
  "scripts/lib/audit-sql-private-state.js",
  "sidecars/audit-sql-target/bootstrap.js",
  "sidecars/audit-sql-target/migrations/0002_query_receipts.sql",
  "sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql",
  "sidecars/audit-sql-target/schema.sql",
  "sidecars/rogue-mcp/Dockerfile",
  "sidecars/rogue-mcp/index.js",
  "sidecars/ssrf-target/Dockerfile",
  "sidecars/ssrf-target/index.js"
];
 for(const name of required){
  const inventoried=RUNTIME_ASSET_PATHS.includes(name)||SOURCE_PLAN_RULES.some(rule=>name.startsWith(rule.directory+'/')&&rule.matches(path.posix.basename(name)));
  assert(inventoried,name);assert(Object.hasOwn(manifest.files,name),name);assert(manifest.recoveryFiles.includes(name),name);
 }
});

test('release includes exact static FinFlow teaching logs and rejects changed or operational logs', t => {
  const root = fixture(t), crypto = require('node:crypto');
  const names = ['access', 'audit', 'error', 'llm_requests'].map(name => `server/sensitive_files/logs/${name}.log`);
  for (const relative of names) {
    assert(RUNTIME_ASSET_PATHS.includes(relative));
    assert.equal(isForbiddenPath(relative), true, 'log extension stays forbidden without exact fixture identity');
    const bytes = fs.readFileSync(path.join(__dirname, '..', relative));
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), CONTROLLED_TEACHING_FIXTURE_SHA256[relative]);
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), bytes);
  }
  const hashes = Object.fromEntries(names.map(name => [name, CONTROLLED_TEACHING_FIXTURE_SHA256[name]]));
  let result = inspect(root, {
    runtimeAssetPaths: names, teachingFixtureHashes: hashes,
    candidateExportPaths: [...names, 'server/logs/access.log', 'server/sensitive_files/logs/debug.log'],
    candidateExportHashes: hashes,
  });
  assert(names.every(name => result.requiredPaths.includes(name)));
  assert.deepEqual(result.forbiddenRequired, []);
  assert.deepEqual(result.forbiddenExport, ['server/logs/access.log', 'server/sensitive_files/logs/debug.log']);
  assert.deepEqual(result.teachingFixtureDigestMismatches, []);
  assert.deepEqual(result.teachingFixtureCandidateDigestMismatches, []);
  const changed = names[0];
  fs.appendFileSync(path.join(root, changed), 'new runtime entry\n');
  const changedHash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, changed))).digest('hex');
  result = inspect(root, {
    runtimeAssetPaths: names, teachingFixtureHashes: hashes,
    candidateExportPaths: names, candidateExportHashes: { ...hashes, [changed]: changedHash },
  });
  assert.deepEqual(result.teachingFixtureDigestMismatches, [changed]);
  assert.deepEqual(result.teachingFixtureCandidateDigestMismatches, [changed]);
  assert.deepEqual(result.forbiddenRequired, [changed]);
  assert.deepEqual(result.forbiddenExport, [changed]);
});
