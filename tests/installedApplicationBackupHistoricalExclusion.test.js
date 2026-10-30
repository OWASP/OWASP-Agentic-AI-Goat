'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  filesystemSpecs,
  parseArgs,
  selectFilesystemScopes,
} = require('../scripts/backup-installed-application');

test('historical archive exclusion has a closed CLI grammar', () => {
  assert.deepEqual(
    parseArgs(['--output', '/private/backup']),
    { output: '/private/backup', excludeHistoricalArchives: false },
  );
  assert.deepEqual(
    parseArgs(['--output', '/private/backup', '--exclude-historical-archives']),
    { output: '/private/backup', excludeHistoricalArchives: true },
  );
  for (const argv of [
    [],
    ['--exclude-historical-archives'],
    ['--output'],
    ['--output', '/private/backup', '--unknown'],
    ['--output', '/private/backup', '--exclude-historical-archives', '--exclude-historical-archives'],
  ]) assert.throws(() => parseArgs(argv));
});

test('historical exclusion retains every ordinary private manager and excludes only archive history', () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'backup-history-scope-')));
  try {
    const workspace = path.join(directory, 'workspace');
    const home = path.join(directory, 'home');
    fs.mkdirSync(path.join(workspace, 'server', 'database'), { recursive: true, mode: 0o700 });
    const workspaceId = crypto.createHash('sha256').update(fs.realpathSync(workspace)).digest('hex').slice(0, 12);
    const privateRoot = path.join(home, '.owasp-ai-goat', workspaceId);
    fs.mkdirSync(privateRoot, { recursive: true, mode: 0o700 });

    for (const name of ['activation-backups', 'dependency-backups', 'model-cache', 'app-data']) {
      fs.mkdirSync(path.join(privateRoot, name), { mode: 0o700 });
    }
    for (const name of [
      'secureshop-owned-listings.json',
      'policy-renderer-managed.json',
      'secureshop-owned-mcp-registry.json',
    ]) fs.writeFileSync(path.join(privateRoot, name), '{}\n', { mode: 0o600 });

    const scope = filesystemSpecs(workspace, home);
    const selected = selectFilesystemScopes(scope, { excludeHistoricalArchives: true });
    const ordinaryNames = selected.ordinary.map(spec => path.basename(spec.source));

    assert.deepEqual(selected.historical, []);
    assert.deepEqual(selected.excludedHistoricalArchives, ['activation-backups', 'dependency-backups']);
    assert.deepEqual(scope.excluded, ['model-cache']);
    for (const name of [
      'app-data',
      'secureshop-owned-listings.json',
      'policy-renderer-managed.json',
      'secureshop-owned-mcp-registry.json',
    ]) assert.ok(ordinaryNames.includes(name), `${name} must remain in filesystem.archive`);
    for (const name of selected.excludedHistoricalArchives) assert.ok(!ordinaryNames.includes(name));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('default selection preserves separate historical archive behavior', () => {
  const privateRoot = '/private/root';
  const scope = {
    privateRoot,
    excluded: ['model-cache'],
    specs: [
      { source: path.join(privateRoot, 'activation-backups') },
      { source: path.join(privateRoot, 'dependency-backups') },
      { source: path.join(privateRoot, 'secureshop-owned-listings.json') },
    ],
  };

  const selected = selectFilesystemScopes(scope, { excludeHistoricalArchives: false });
  assert.deepEqual(selected.excludedHistoricalArchives, []);
  assert.deepEqual(selected.historical.map(spec => path.basename(spec.source)), [
    'activation-backups',
    'dependency-backups',
  ]);
  assert.deepEqual(selected.ordinary.map(spec => path.basename(spec.source)), [
    'secureshop-owned-listings.json',
  ]);
});
