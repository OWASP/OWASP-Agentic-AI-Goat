#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const DEFAULT_ROOT = path.resolve(__dirname, '..');
const BASELINE = Object.freeze({ entrypoints: 40, localImportClosure: 792 });
const ROOT_SCRIPT_NAMES = Object.freeze([
  'setup', 'setup:mcp-owned', 'test:modernization', 'test:ollama:8b',
  'db:initialize-all', 'db:postgres:initialize', 'db:postgres:migrate',
  'test:postgres', 'test:native-operator', 'test:unit:isolated',
  'test:secureshop:isolated', 'test:api', 'verify:learning-dependencies',
  'verify:workshop:browser', 'test:judge:8b',
  'db:postgres:provision', 'test:native-browser',
  'test:admin-bundle',
]);
const CLIENT_SCRIPT_NAMES = Object.freeze([
  'build:review-renderer', 'build:product-description-renderer', 'build:mail-renderer',
  'build:ticket-renderer', 'build:search-echo-renderer', 'build:policy-output-renderer',
]);
const DIRECT_SOURCE_PATHS = Object.freeze([
  'package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json',
  'scripts/verify-release-source-inclusion.js',
  'tests/releaseSourceInclusion.test.js',
  'client/src/pages/secureshop/components/ReviewCard.jsx',
  'client/src/pages/secureshop/components/reviewCardServerRenderer.jsx',
  'client/src/pages/secureshop/components/ProductDescription.jsx',
  'client/src/pages/secureshop/components/productDescriptionServerRenderer.jsx',
  'client/src/pages/secureshop/components/MailMessageBody.jsx',
  'client/src/pages/secureshop/components/mailMessageClientRenderer.jsx',
  'client/src/pages/secureshop/components/AdminTicketBody.jsx',
  'client/src/pages/secureshop/components/ticketDetailClientRenderer.jsx',
  'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx',
  'client/src/pages/secureshop/searchEchoClientRenderer.jsx',
  'client/src/pages/secureshop/components/AgentLane/Turn.jsx',
  'client/src/pages/secureshop/policyOutputClientRenderer.jsx',
]);
const MIGRATION_DIRECTORIES = Object.freeze([
  'db/postgres/migrations', 'db/postgres/identity-migrations',
  'db/postgres/maintenance-migrations', 'db/postgres/workshop-migrations',
]);
const SEED_DIRECTORY = 'db/postgres/seeds';
const BUILD_MANIFEST = 'scripts/install/manifests/secureshop-owned-mcp-registry-build.json';
const SOURCE_PLAN_RULES = Object.freeze([
  Object.freeze({ directory: 'server', matches: name => /\.(?:js|cjs|mjs)$/u.test(name) }),
  Object.freeze({ directory: 'scripts', matches: name => /\.(?:js|cjs|mjs)$/u.test(name) }),
  Object.freeze({ directory: 'scripts/install/manifests', matches: name => name.endsWith('.json') }),
  Object.freeze({ directory: 'db/postgres', matches: name => /\.(?:js|cjs|mjs)$/u.test(name) }),
  Object.freeze({
    directory: 'sidecars',
    matches: name => /\.(?:js|cjs|mjs|c|h|json)$/u.test(name)
      || name.endsWith('.apparmor.in') || name.startsWith('Dockerfile'),
  }),
  Object.freeze({ directory: 'agent-host', matches: name => /\.(?:js|cjs|mjs|json)$/u.test(name) }),
  Object.freeze({ directory: 'client/src', matches: () => true }),
  Object.freeze({ directory: 'client/public', matches: () => true }),
]);
const RUNTIME_ASSET_PATHS = Object.freeze([
  'start_all.sh',
  'stop_all.sh',
  'scripts/install/runtime-path.sh',
  'scripts/install/runtime-version-policy.sh',
    'scripts/install/qualification/secureshop-listings-package-2026-10-10.json',
  'scripts/install/bootstrap-unix.sh',
  'scripts/install/macos-prerequisites.sh',
  'scripts/install/linux-prerequisites.sh',
  'scripts/install/Mac/install-macos.sh',
  'scripts/install/Mac/macos-dev-setup.sh',
  'scripts/install/Mac/test-macos-install.sh',
  'scripts/install/Linux/install-linux.sh',
  'scripts/install/Ubuntu/install-dvaia-ubuntu.sh',
  'scripts/install/Ubuntu/quick-start.sh',
  'scripts/install/Windows/install-windows.ps1',
  'scripts/install/Windows/start_all.ps1',
  'scripts/install/Windows/wrapper-handoff.ps1',
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
    'scripts/install/Windows/prerequisites.ps1',
    'scripts/install/Windows/packages.ps1',
    'scripts/install/Windows/dependencies.ps1',
  'scripts/install/Windows/host-preflight.ps1',
  'scripts/install/Windows/owned-hyperv-observer.ps1',
  'docs/modernization/learning-dependencies.json',
  'docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json',
  'server/services/applicationMaintenanceInprocessSources.json',
  ...Array.from({ length: 8 }, (_, index) => `server/services/applicationMaintenanceInprocessSources-v${index + 2}.json`),
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
  'server/services/applicationMaintenanceInprocessSources-v47.json',
  'server/services/applicationMaintenanceInprocessSources-v48.json',
  'server/services/applicationMaintenanceInprocessSources-v49.json',
  'server/services/applicationMaintenanceInprocessSources-v50.json',
  'server/services/applicationMaintenanceInprocessSources-v51.json',
  'server/services/applicationMaintenanceInprocessSources-v52.json',
  'server/services/applicationMaintenanceInprocessSources-v53.json',
  'server/services/applicationMaintenanceInprocessSources-v54.json',
  'server/services/applicationMaintenanceInprocessSources-v55.json',
  'server/services/applicationMaintenanceInprocessSources-v56.json',
  'server/services/applicationMaintenanceInprocessSources-v57.json',
  'server/services/applicationMaintenanceInprocessSources-v58.json',
  'server/services/applicationMaintenanceInprocessSources-v59.json',
  'server/services/applicationMaintenanceInprocessSources-v60.json',
  'server/services/applicationMaintenanceInprocessSources-v61.json',
  'server/services/applicationMaintenanceInprocessSources-v62.json',
  'server/services/applicationMaintenanceInprocessSources-v63.json',
  'server/services/applicationMaintenanceInprocessSources-v64.json',
  'server/services/applicationMaintenanceInprocessSources-v65.json',
  'server/services/applicationMaintenanceInprocessSources-v66.json',
  'server/services/applicationMaintenanceInprocessSources-v67.json',
  'server/services/applicationMaintenanceInprocessSources-v68.json',
  'server/services/applicationMaintenanceInprocessSources-v69.json',
  'server/services/applicationMaintenanceInprocessSources-v70.json',
  'server/services/applicationMaintenanceInprocessSources-v71.json',
  'server/services/applicationMaintenanceInprocessSources-v72.json',
  'server/services/applicationMaintenanceInprocessSources-v73.json',
  'server/services/applicationMaintenanceInprocessSources-v74.json',
  'server/services/applicationMaintenanceInprocessSources-v75.json',
  'server/services/applicationMaintenanceInprocessSources-v76.json',
  'server/services/applicationMaintenanceInprocessSources-v77.json',
  'server/services/applicationMaintenanceInprocessSources-v78.json',
  'server/services/applicationMaintenanceInprocessSources-v79.json',
  'server/services/applicationMaintenanceInprocessSources-v80.json',
  'server/services/applicationMaintenanceInprocessSources-v81.json',
  'server/services/applicationMaintenanceInprocessSources-v82.json',
  'server/services/applicationMaintenanceInprocessSources-v83.json',
  'server/services/applicationMaintenanceInprocessSources-v84.json',
  'server/services/applicationMaintenanceInprocessSources-v85.json',
  'server/services/applicationMaintenanceInprocessSources-v86.json',
  'server/services/applicationMaintenanceInprocessSources-v87.json',
  'server/services/applicationMaintenanceInprocessSources-v88.json',
  'server/services/applicationMaintenanceInprocessSources-v89.json',
  'server/services/applicationMaintenanceInprocessSources-v90.json',
  'server/services/applicationMaintenanceInprocessSources-v91.json',
  'server/services/applicationMaintenanceInprocessSources-v92.json',
  'server/services/applicationMaintenanceInprocessSources-v93.json',
  'server/services/applicationMaintenanceInprocessSources-v94.json',
  'server/services/applicationMaintenanceInprocessSources-v95.json',
  'server/services/applicationMaintenanceInprocessSources-v96.json',
  'server/services/applicationMaintenanceInprocessSources-v97.json',
  'server/services/applicationMaintenanceInprocessSources-v98.json',
  'server/services/applicationMaintenanceInprocessSources-v99.json',
  'server/services/applicationMaintenanceInprocessSources-v100.json',
  'server/services/applicationMaintenanceInprocessSources-v101.json',
  'server/services/applicationMaintenanceInprocessSources-v102.json',
  'server/database/bsides_users.json',
  'server/database/postgres/legacyFileSsiReadinessManifest.json',
  'server/assets/rag_samples/injected_document.txt',
  'server/assets/rag_samples/normal_policy.txt',
  'server/assets/rag_samples/query_injection_demo.txt',
  'server/assets/rag_samples/random_document.txt',
  ...['g2', 'g3', 'i1', 'i2', 'i3', 'p1', 'p2', 'p3', 'x1', 'x2', 'x3']
    .flatMap(id => ['skeleton', 'solution'].map(kind => `server/assets/csrf_samples/csrf_${id}_${kind}.html`)),
  'server/workshop_data/transactions/FF-001.json',
  'server/workshop_data/transactions/FF-002.json',
  'server/workshop_data/documents/statement-FF-001-2024.txt',
  'server/workshop_data/documents/statement-FF-002-2024.txt',
  'server/sensitive_files/logs/access.log',
  'server/sensitive_files/logs/audit.log',
  'server/sensitive_files/logs/error.log',
  'server/sensitive_files/logs/llm_requests.log',
  'server/sensitive_files/traversal-fixtures/config/secrets.env',
  'server/sensitive_files/traversal-fixtures/config/llm_config.yml',
  'server/sensitive_files/traversal-fixtures/etc/passwd',
  'sidecars/audit-sql-target/schema.sql',
  'sidecars/audit-sql-target/migrations/0002_query_receipts.sql',
  'sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql',
  'sidecars/analytics-sql-target/control-migrations/0001_control.sql',
  'sidecars/analytics-sql-target/control-migrations/0002_fixed_capability.sql',
  'sidecars/sandbox-runner/entrypoint.sh',
  'sidecars/sandbox-runner/policy-render/assets/NUNJUCKS-LICENSE.txt',
  'sidecars/sandbox-runner/labfs/etc/hosts.lab',
  'sidecars/sandbox-runner/labfs/etc/passwd',
  'sidecars/sandbox-runner/labfs/home/mcp-admin/.bash_history',
  'sidecars/sandbox-runner/labfs/home/mcp-admin/notes.txt',
  'sidecars/sandbox-runner/labfs/home/mcp-admin/readme.txt',
  'sidecars/sandbox-runner/labfs/opt/app/config/.env',
  'sidecars/sandbox-runner/labfs/opt/app/config/database.yml',
  'sidecars/sandbox-runner/labfs/opt/app/config/mcp.yml',
  'sidecars/sandbox-runner/labfs/opt/lab/bin/malicious_postinstall.sh',
  'sidecars/sandbox-runner/labfs/opt/lab/bin/rotate_keys.sh',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz.sig',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-package-signing-public.pem',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/analytics-boost-1.0.0.tgz',
  'sidecars/sandbox-runner/labfs/var/log/syslog',
  'sidecars/sandbox-runner/labfs/var/secrets/credentials.json',
  'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt',
]);
const CONTROLLED_TEACHING_FIXTURE_SHA256 = Object.freeze({
  // Static FinFlow teaching logs; operational server/logs remain forbidden.
  'server/sensitive_files/logs/access.log': '44f13d63c97178c9d0434049d1e3c5694a23a28362a2422e5e2953349bad4992',
  'server/sensitive_files/logs/audit.log': '3d99a2ffed2e3c3ab07819a446f51c189bd2b9154787baeab2ab8d79b80bb85d',
  'server/sensitive_files/logs/error.log': 'd06ca3d984446ec4592688eca9bc503d7e0d0f549b2b9df1e237fa3481a846ed',
  'server/sensitive_files/logs/llm_requests.log': 'e3ea56185d1abd80ac16e977b562b22eb618abdffa943c44515b0e601c191c69',
  'sidecars/sandbox-runner/labfs/var/secrets/credentials.json': '1c6eef81a9d339d2c751d9efd4b755e8badb303848f8ce8ec0033353b0d30734',
  'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt': '6a3179f3d798450ddc12f6cff75ab45c4383a45695a43dfdf11c5475d806436f',
  'sidecars/sandbox-runner/labfs/opt/app/config/.env': 'c90c0fb0c438f25014ca86033d6758c75c7dd1e08b453ce0bdfd179d1b919a7f',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz': 'd43b1b73d2f859eb5b70e77d7a2b0d42bc2e3db7754443a25a9b951fd8b74b6c',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz.sig': 'ed91bd66d3bf69d69c1b5893c988bbb57d8245360913d192dfbf7ea26a651edc',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/acme-package-signing-public.pem': '4c93bef9395ac4887e5ac48cc3bc79ab6c9023380ba6f4a23d7ba79f856fd1e6',
  'sidecars/sandbox-runner/labfs/opt/lab/packages/analytics-boost-1.0.0.tgz': '28ad1b38813766bd06c9297a5297440b0a6dcac37dffee83f35167569b0869e1',
});
const LOCAL_EXTENSIONS = Object.freeze(['', '.js', '.cjs', '.mjs', '.json', '.jsx']);
const IMPORT_PATTERN = /(?:require\s*\(\s*|import\s*\(\s*|(?:import|export)\s+(?:[^'"]*?\s+from\s+)?)["']([^'"]+)["']/gu;
const PRIVATE_REFERENCE_PATTERNS = Object.freeze([
  /backups\/private-recovery/u,
  /tasks\/main-workspace-preservation/u,
  /\/Users\/[A-Za-z0-9._-]+\//u,
  /file:\/\//u,
]);

function normalizeRelative(repoRoot, filename) {
  const relative = path.relative(repoRoot, path.resolve(filename)).split(path.sep).join('/');
  if (!relative || relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) return null;
  return relative;
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

function commandFiles(command, cwd, repoRoot) {
  const files = [];
  for (const raw of String(command || '').split(/\s+/u)) {
    let token = raw.replace(/^["']|["',;()]+$/gu, '');
    if (token.startsWith('./')) token = token.slice(2);
    if (!/\.(?:js|cjs|mjs|json|jsx)$/u.test(token)) continue;
    const absolute = path.resolve(cwd, token);
    const relative = normalizeRelative(repoRoot, absolute);
    if (relative) files.push(relative);
  }
  return files;
}

function collectEntrypoints(repoRoot, {
  rootScriptNames = ROOT_SCRIPT_NAMES,
  clientScriptNames = CLIENT_SCRIPT_NAMES,
} = {}) {
  const rootPackage = readJson(path.join(repoRoot, 'package.json'));
  const clientPackage = readJson(path.join(repoRoot, 'client/package.json'));
  const result = new Set();
  for (const name of rootScriptNames) {
    for (const filename of commandFiles(rootPackage.scripts?.[name], repoRoot, repoRoot)) result.add(filename);
  }
  for (const name of clientScriptNames) {
    for (const filename of commandFiles(clientPackage.scripts?.[name], path.join(repoRoot, 'client'), repoRoot)) result.add(filename);
  }
  for (const value of clientPackage.jest?.setupFilesAfterEnv || []) {
    if (!String(value).startsWith('<rootDir>/')) continue;
    const filename = value.replace(/^<rootDir>\//u, '');
    const relative = normalizeRelative(repoRoot, path.join(repoRoot, 'client', filename));
    if (relative) result.add(relative);
  }
  for (const value of Object.values(clientPackage.jest?.moduleNameMapper || {})) {
    if (!String(value).startsWith('<rootDir>/')) continue;
    const filename = String(value).replace(/^<rootDir>\//u, '');
    const relative = normalizeRelative(repoRoot, path.join(repoRoot, 'client', filename));
    if (relative) result.add(relative);
  }
  return [...result].sort();
}

function resolveLocalSpecifier(repoRoot, importer, specifier) {
  if (!specifier.startsWith('.')) return null;
  const bases = [path.resolve(path.dirname(importer), specifier), path.resolve(repoRoot, specifier)];
  for (const base of bases) {
    for (const extension of LOCAL_EXTENSIONS) {
      const candidate = `${base}${extension}`;
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const relative = normalizeRelative(repoRoot, candidate);
        if (relative) return { relative, repoRootFallback: base === bases[1] };
      }
    }
    for (const extension of LOCAL_EXTENSIONS.slice(1)) {
      const candidate = path.join(base, `index${extension}`);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const relative = normalizeRelative(repoRoot, candidate);
        if (relative) return { relative, repoRootFallback: base === bases[1] };
      }
    }
  }
  return { missing: specifier };
}

function collectLocalClosure(repoRoot, entrypoints) {
  const queue = [...entrypoints];
  const closure = new Set();
  const missing = [];
  const rootFallbacks = [];
  const privateReferences = new Set();
  while (queue.length > 0) {
    const relative = queue.pop();
    if (closure.has(relative)) continue;
    closure.add(relative);
    const absolute = path.join(repoRoot, relative);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
      missing.push({ importer: null, requested: relative });
      continue;
    }
    const source = fs.readFileSync(absolute, 'utf8');
    if (PRIVATE_REFERENCE_PATTERNS.some(pattern => pattern.test(source))) privateReferences.add(relative);
    IMPORT_PATTERN.lastIndex = 0;
    for (const match of source.matchAll(IMPORT_PATTERN)) {
      const resolved = resolveLocalSpecifier(repoRoot, absolute, match[1]);
      if (!resolved) continue;
      if (resolved.missing) missing.push({ importer: relative, requested: match[1] });
      else {
        if (resolved.repoRootFallback) rootFallbacks.push({ importer: relative, target: resolved.relative });
        if (!closure.has(resolved.relative)) queue.push(resolved.relative);
      }
    }
  }
  return {
    closure: [...closure].sort(),
    missing,
    rootFallbacks,
    privateReferences: [...privateReferences].sort(),
  };
}

function walkFiles(repoRoot, relativeDirectory, predicate) {
  const root = path.join(repoRoot, relativeDirectory);
  if (!fs.existsSync(root)) return [];
  const result = [];
  const queue = [root];
  while (queue.length > 0) {
    const directory = queue.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) queue.push(absolute);
      else if (entry.isFile() && predicate(entry.name)) result.push(normalizeRelative(repoRoot, absolute));
    }
  }
  return result.filter(Boolean).sort();
}

function collectApprovedSourcePlan(repoRoot, rules = SOURCE_PLAN_RULES) {
  const result = new Set();
  for (const rule of rules) {
    for (const filename of walkFiles(repoRoot, rule.directory, rule.matches)) {
      if (!isForbiddenPath(filename)) result.add(filename);
    }
  }
  return [...result].sort();
}

function gitPaths(repoRoot, args) {
  const result = spawnSync('git', ['-C', repoRoot, ...args, '-z'], { encoding: 'buffer' });
  if (result.status !== 0) throw new Error('Git path inventory is unavailable');
  return new Set(result.stdout.toString('utf8').split('\0').filter(Boolean).map(value => value.split(path.sep).join('/')));
}

function gitIndexSha256(repoRoot, filename) {
  const result = spawnSync('git', ['-C', repoRoot, 'show', `:${filename}`], {
    encoding: 'buffer', maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) return null;
  return crypto.createHash('sha256').update(result.stdout).digest('hex');
}

function isForbiddenPath(filename) {
  const value = filename.split(path.sep).join('/');
  const base = path.posix.basename(value);
  const pythonCache = value.split('/').includes('__pycache__') || /\.(?:pyc|pyo)$/u.test(base);
  const frontendBuildCapture = /^tests\/release-inputs\/frontend-build-[^/]*\//u.test(value);
  const runtimeUpload = value.startsWith('server/uploads/') && base !== '.gitkeep';
  const runtimeVectorIndex = value.startsWith('server/database/vector-indexes/') && base !== '.gitkeep';
  return pythonCache || frontendBuildCapture || value.startsWith('tasks/') || value.startsWith('backups/')
    || value.includes('/private-recovery/') || value.startsWith('node_modules/')
    || value.includes('/node_modules/') || value.startsWith('client/build/')
    || value.startsWith('build/') || value.startsWith('dist/')
    || value.startsWith('coverage/') || value.startsWith('server/logs/')
    || runtimeVectorIndex || runtimeUpload
    || base === '.env' || (base.startsWith('.env.') && base !== '.env.example') || base.endsWith('.log')
    || base === '.DS_Store' || base.startsWith('._')
    || /\.(?:db|sqlite|sqlite3)(?:-|$)/u.test(base)
    || /\.(?:dump|bak|tar|tar\.gz|tgz|zip)$/u.test(base);
}

function sha256(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

function inspectRepository({
  repoRoot = DEFAULT_ROOT,
  rootScriptNames,
  clientScriptNames,
  directSourcePaths = DIRECT_SOURCE_PATHS,
  migrationDirectories = MIGRATION_DIRECTORIES,
  seedDirectory = SEED_DIRECTORY,
  buildManifestPath = BUILD_MANIFEST,
  sourcePlanRules = SOURCE_PLAN_RULES,
  runtimeAssetPaths = RUNTIME_ASSET_PATHS,
  teachingFixtureHashes = CONTROLLED_TEACHING_FIXTURE_SHA256,
  trackedPaths,
  stagedPaths,
  candidateExportPaths,
  candidateExportHashes,
} = {}) {
  repoRoot = path.resolve(repoRoot);
  const entrypoints = collectEntrypoints(repoRoot, { rootScriptNames, clientScriptNames });
  const graph = collectLocalClosure(repoRoot, entrypoints);
  const required = new Set([...graph.closure, ...directSourcePaths]);
  const missing = [...graph.missing];
  const sourcePlanFiles = collectApprovedSourcePlan(repoRoot, sourcePlanRules);
  for (const filename of sourcePlanFiles) required.add(filename);
  for (const filename of runtimeAssetPaths) required.add(filename);
  for (const filename of Object.keys(teachingFixtureHashes)) required.add(filename);

  for (const directory of migrationDirectories) {
    for (const filename of walkFiles(repoRoot, directory, name => name.endsWith('.sql'))) required.add(filename);
  }
  for (const filename of walkFiles(repoRoot, seedDirectory, name => name.endsWith('.json'))) required.add(filename);

  let manifestInputs = [];
  const manifestAbsolute = path.join(repoRoot, buildManifestPath);
  if (!fs.existsSync(manifestAbsolute)) missing.push({ importer: null, requested: buildManifestPath });
  else {
    required.add(buildManifestPath);
    const manifest = readJson(manifestAbsolute);
    manifestInputs = Object.keys(manifest.files || {}).sort();
    for (const filename of manifestInputs) required.add(filename);
  }

  const requiredPaths = [...required].sort();
  for (const filename of requiredPaths) {
    const absolute = path.join(repoRoot, filename);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
      if (!missing.some(item => item.requested === filename)) missing.push({ importer: null, requested: filename });
    }
  }

  const tracked = trackedPaths ? new Set(trackedPaths) : gitPaths(repoRoot, ['ls-files']);
  const staged = stagedPaths ? new Set(stagedPaths) : gitPaths(repoRoot, ['diff', '--cached', '--name-only', '--diff-filter=ACMR']);
  const candidateExport = candidateExportPaths ? new Set(candidateExportPaths) : tracked;
  const suppliedCandidateHashes = candidateExportHashes instanceof Map
    ? candidateExportHashes : new Map(Object.entries(candidateExportHashes || {}));
  const verifiedWorktreeTeachingFixtures = new Set();
  const verifiedCandidateTeachingFixtures = new Set();
  const teachingFixtureDigestMismatches = [];
  const teachingFixtureCandidateDigestMismatches = [];
  for (const [filename, expected] of Object.entries(teachingFixtureHashes)) {
    const absolute = path.join(repoRoot, filename);
    if (fs.existsSync(absolute) && fs.statSync(absolute).isFile()) {
      if (sha256(absolute) === expected) verifiedWorktreeTeachingFixtures.add(filename);
      else teachingFixtureDigestMismatches.push(filename);
    }
    if (candidateExport.has(filename)) {
      const candidateDigest = candidateExportHashes === undefined
        ? gitIndexSha256(repoRoot, filename) : suppliedCandidateHashes.get(filename) || null;
      if (candidateDigest === expected) verifiedCandidateTeachingFixtures.add(filename);
      else teachingFixtureCandidateDigestMismatches.push(filename);
    }
  }
  const forbiddenWorktree = filename => isForbiddenPath(filename) && !verifiedWorktreeTeachingFixtures.has(filename);
  const forbiddenCandidate = filename => isForbiddenPath(filename) && !verifiedCandidateTeachingFixtures.has(filename);
  const untracked = requiredPaths.filter(filename => !tracked.has(filename));
  const missingFromCandidate = requiredPaths.filter(filename => !candidateExport.has(filename));
  const forbiddenRequired = requiredPaths.filter(forbiddenWorktree);
  const forbiddenStaged = [...staged].filter(forbiddenCandidate).sort();
  const forbiddenExport = [...candidateExport].filter(forbiddenCandidate).sort();
  const digestMismatches = [];
  if (fs.existsSync(manifestAbsolute)) {
    const manifest = readJson(manifestAbsolute);
    for (const [filename, expected] of Object.entries(manifest.files || {})) {
      const absolute = path.join(repoRoot, filename);
      if (fs.existsSync(absolute) && fs.statSync(absolute).isFile() && sha256(absolute) !== expected) digestMismatches.push(filename);
    }
  }

  return {
    baseline: BASELINE,
    counts: {
      entrypoints: entrypoints.length,
      localImportClosure: graph.closure.length,
      required: requiredPaths.length,
      sourcePlanFiles: sourcePlanFiles.length,
      runtimeAssets: runtimeAssetPaths.length,
      manifestInputs: manifestInputs.length,
      missing: missing.length,
      untracked: untracked.length,
      missingFromCandidate: missingFromCandidate.length,
      forbiddenRequired: forbiddenRequired.length,
      forbiddenStaged: forbiddenStaged.length,
      forbiddenExport: forbiddenExport.length,
      privateReferences: graph.privateReferences.length,
      digestMismatches: digestMismatches.length,
      teachingFixtureDigestMismatches: teachingFixtureDigestMismatches.length,
      teachingFixtureCandidateDigestMismatches: teachingFixtureCandidateDigestMismatches.length,
    },
    entrypoints,
    sourcePlanFiles,
    runtimeAssetPaths: [...runtimeAssetPaths],
    requiredPaths,
    missing,
    untracked,
    missingFromCandidate,
    forbiddenRequired,
    forbiddenStaged,
    forbiddenExport,
    privateReferences: graph.privateReferences,
    digestMismatches: digestMismatches.sort(),
    teachingFixtureDigestMismatches: teachingFixtureDigestMismatches.sort(),
    teachingFixtureCandidateDigestMismatches: teachingFixtureCandidateDigestMismatches.sort(),
    rootFallbacks: graph.rootFallbacks,
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--repo-root') options.repoRoot = path.resolve(argv[++index]);
    else throw new Error(`Unknown argument: ${argv[index]}`);
  }
  return options;
}

function printPaths(label, paths, limit = 24) {
  if (paths.length === 0) return;
  console.error(`${label} (${paths.length}):`);
  for (const filename of paths.slice(0, limit)) console.error(`  ${filename}`);
  if (paths.length > limit) console.error(`  ... ${paths.length - limit} more`);
}

function main() {
  let result;
  try { result = inspectRepository(parseArgs(process.argv.slice(2))); }
  catch (error) {
    console.error(`FAIL release-source-inclusion: ${error.message}`);
    process.exitCode = 1;
    return;
  }
  const c = result.counts;
  console.log(`release-source-inclusion inventory: entrypoints=${c.entrypoints} (reference ${BASELINE.entrypoints}), local-closure=${c.localImportClosure} (reference ${BASELINE.localImportClosure}), source-plan=${c.sourcePlanFiles}, runtime-assets=${c.runtimeAssets}, required=${c.required}, manifest-inputs=${c.manifestInputs}`);
  console.log(`release-source-inclusion findings: missing=${c.missing}, untracked=${c.untracked}, missing-from-candidate=${c.missingFromCandidate}, forbidden-required=${c.forbiddenRequired}, forbidden-staged=${c.forbiddenStaged}, forbidden-export=${c.forbiddenExport}, private-references=${c.privateReferences}, manifest-digest-mismatches=${c.digestMismatches}, teaching-fixture-digest-mismatches=${c.teachingFixtureDigestMismatches}, teaching-fixture-candidate-digest-mismatches=${c.teachingFixtureCandidateDigestMismatches}`);
  printPaths('ACTION missing', result.missing.map(item => item.importer ? `${item.importer} -> ${item.requested}` : item.requested));
  const entrypointSet = new Set(result.entrypoints);
  const orderedUntracked = [...result.untracked].sort((a, b) => Number(entrypointSet.has(b)) - Number(entrypointSet.has(a)) || a.localeCompare(b));
  printPaths('ACTION include in repository', orderedUntracked);
  printPaths('ACTION include required source in candidate export', result.missingFromCandidate);
  printPaths('ACTION remove forbidden required path', result.forbiddenRequired);
  printPaths('ACTION unstage/exclude forbidden path', result.forbiddenStaged);
  printPaths('ACTION exclude from candidate export', result.forbiddenExport);
  printPaths('ACTION remove private source reference', result.privateReferences);
  printPaths('ACTION refresh owned MCP build manifest after reviewed source change', result.digestMismatches);
  printPaths('ACTION restore exact controlled teaching fixture', result.teachingFixtureDigestMismatches);
  printPaths('ACTION restore exact controlled teaching fixture in candidate export', result.teachingFixtureCandidateDigestMismatches);
  const failed = c.missing + c.untracked + c.missingFromCandidate + c.forbiddenRequired + c.forbiddenStaged + c.forbiddenExport
    + c.privateReferences + c.digestMismatches + c.teachingFixtureDigestMismatches
    + c.teachingFixtureCandidateDigestMismatches > 0;
  console.log('Scope: bounded source inventory only; this does not qualify a clean checkout or release.');
  if (failed) process.exitCode = 1;
  else console.log('PASS: bounded source inclusion inventory is tracked and free of forbidden paths.');
}

if (require.main === module) main();

module.exports = {
  BASELINE,
  CONTROLLED_TEACHING_FIXTURE_SHA256,
  RUNTIME_ASSET_PATHS,
  SOURCE_PLAN_RULES,
  collectApprovedSourcePlan,
  collectEntrypoints,
  collectLocalClosure,
  inspectRepository,
  isForbiddenPath,
  parseArgs,
  resolveLocalSpecifier,
};
