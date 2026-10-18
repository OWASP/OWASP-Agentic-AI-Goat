const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function sourceFiles(relativeRoot) {
  const files = [];
  const pending = [path.join(root, relativeRoot)];
  // These directories are runtime-owned or teaching-data roots, not application source.
  // Some runs make their contents unreadable while the server is active; the
  // transport assertions below must remain independent of that mutable data.
  const generatedRuntimeRoots = new Set([
    path.join(root, 'server', 'uploads'),
    path.join(root, 'server', 'logs'),
    path.join(root, 'server', 'database', 'vector-indexes'),
    path.join(root, 'server', 'sensitive_files'),
  ]);
  while (pending.length > 0) {
    const directory = pending.pop();
    if (generatedRuntimeRoots.has(directory)) continue;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute);
      if ([...generatedRuntimeRoots].some((runtimeRoot) =>
        absolute === runtimeRoot || absolute.startsWith(`${runtimeRoot}${path.sep}`))) continue;
      if (relative.startsWith('client/src/pages/secureshop/') ||
          relative.startsWith('server/routes/secureshop/') ||
          relative.startsWith('server/services/secureshop/')) continue;
      if (entry.isDirectory()) pending.push(absolute);
      if (entry.isFile() && /\.(?:js|jsx|ts|tsx)$/.test(entry.name)) files.push(relative);
    }
  }
  return files;
}

test('application runtime contains no owned WebSocket transport', () => {
  assert.equal(fs.existsSync(path.join(root, 'server/services/websocketService.js')), false);
  assert.equal(fs.existsSync(path.join(root, 'server/services/websocketAuth.js')), false);

  const files = [...sourceFiles('server'), ...sourceFiles('client/src')];
  for (const relative of files) {
    const source = read(relative);
    assert.doesNotMatch(source, /new\s+WebSocket\s*\(|WebSocket\.Server|require\(['"]ws['"]\)|\/ws\/visibility/, relative);
    assert.doesNotMatch(source, /(?:websocketService|websocketAuth)/, relative);
  }
});

test('HTTP routes and admin mutation compatibility hooks remain mounted', () => {
  const index = read('server/index.js') + '\n' + read('server/applicationServer.js');
  const adminExercises = read('server/routes/adminExercises.js');

  assert.match(index, /app\.use\(['"]\/api\/admin\/exercises['"],\s*createAdminExercisesRouter\(\)\)/);
  assert.match(index, /app\.use\(['"]\/api\/workshop\/config['"][\s\S]*createWorkshopConfigRouter\(\)/);
  assert.match(index, /app\.use\(['"]\/api\/changes['"],\s*createChangeRevisionsRouter/);
  assert.match(adminExercises, /onCommitted/);
  assert.match(adminExercises, /onContentCommitted/);
  assert.doesNotMatch(adminExercises, /websocket|broadcast/i);
});

test('supported startup does not initialize or retire legacy WebSocket metadata', () => {
  const index = read('server/index.js') + '\n' + read('server/applicationServer.js');

  assert.doesNotMatch(index, /retireLegacyWebSocketConfigFile|legacy_websocket_retirement_failed/);
  assert.doesNotMatch(index, /CREATE TABLE IF NOT EXISTS websocket_config/);
  assert.doesNotMatch(index, /INSERT OR REPLACE INTO websocket_config/);
  assert.doesNotMatch(index, /websocket_services\s*:/);
  assert.doesNotMatch(index, /WebSocket services configured|Initializing websocket services/i);
});

test('root dependency and development proxy require ordinary HTTP only', () => {
  const packageJson = JSON.parse(read('package.json'));
  const packageLock = JSON.parse(read('package-lock.json'));
  const rootPackage = packageLock.packages?.[''] || {};
  const proxy = read('client/src/setupProxy.js');

  assert.equal(packageJson.dependencies?.ws, undefined);
  assert.equal(packageJson.devDependencies?.ws, undefined);
  assert.equal(rootPackage.dependencies?.ws, undefined);
  assert.doesNotMatch(proxy, /\/ws\//);
  assert.doesNotMatch(proxy, /\bws\s*:\s*true/);
  assert.match(proxy, /['"]\/api['"]/);
});

test('Ubuntu install wrappers contain no application socket or host-service configuration', () => {
  const wrappers = [
    ['scripts/install/Ubuntu/install-dvaia-ubuntu.sh', /bootstrap-unix\.sh/],
    ['scripts/install/Ubuntu/quick-start.sh', /install-dvaia-ubuntu\.sh/],
  ];
  for (const [relative, delegatedEntrypoint] of wrappers) {
    const source = read(relative);
    assert.doesNotMatch(source, /REACT_APP_WEBSOCKET_URL|location\s+\/ws\/|proxy_set_header\s+Upgrade|Connection\s+["']?upgrade/i, relative);
    assert.doesNotMatch(source, /apt-get|systemctl|nginx|ufw/i, relative);
    assert.match(source, delegatedEntrypoint, relative);
  }
  for (const relative of [
    'scripts/install/bootstrap-unix.sh',
    'scripts/install/linux-prerequisites.sh',
  ]) {
    assert.doesNotMatch(read(relative), /REACT_APP_WEBSOCKET_URL|location\s+\/ws\/|proxy_set_header\s+Upgrade|Connection\s+["']?upgrade/i, relative);
  }
  assert.match(read('scripts/install/bootstrap-unix.sh'), /npm run setup/);
});

test('active architecture docs describe database-backed HTTP polling', () => {
  for (const relative of [
    'docs/ARCHITECTURE.md',
    'CLAUDE.md',
  ]) {
    const source = read(relative);
    assert.match(source, /database-backed HTTP revision polling/i, relative);
    assert.doesNotMatch(
      source,
      /REST API \+ WebSockets|agent tools, WebSocket,|Starts WebSocket services/i,
      relative,
    );
  }
});
