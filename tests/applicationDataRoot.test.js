'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ensureApplicationDataRoot, workspaceId } = require('../scripts/application-data-root');

function fixture(t) {
  const created = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-app-data-root-'));
  const parent = fs.realpathSync(created);
  const workspace = path.join(parent, 'workspace');
  const home = path.join(parent, 'home');
  fs.mkdirSync(workspace, { mode: 0o700 });
  fs.mkdirSync(home, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, workspace: fs.realpathSync(workspace), home };
}

test('default root is private, workspace-bound and stable across restarts', t => {
  const value = fixture(t), firstEnvironment = {};
  const first = ensureApplicationDataRoot({ workspace: value.workspace, homeDirectory: value.home,
    environment: firstEnvironment });
  assert.equal(first, path.join(value.home, '.owasp-ai-goat', workspaceId(value.workspace), 'app-data'));
  assert.equal(firstEnvironment.OWASP_AI_GOAT_APP_DATA_ROOT, first);
  assert.equal(fs.lstatSync(first).isDirectory(), true);
  if (process.platform !== 'win32') assert.equal(fs.statSync(first).mode & 0o777, 0o700);
  fs.writeFileSync(path.join(first, 'restart-sentinel'), 'preserved', { mode: 0o600 });
  const restarted = ensureApplicationDataRoot({ workspace: value.workspace, homeDirectory: value.home,
    environment: {} });
  assert.equal(restarted, first);
  assert.equal(fs.readFileSync(path.join(restarted, 'restart-sentinel'), 'utf8'), 'preserved');
});

test('explicit canonical root is authoritative and existing content survives', t => {
  const value = fixture(t), target = path.join(value.parent, 'explicit-data');
  const environment = { OWASP_AI_GOAT_APP_DATA_ROOT: target };
  assert.equal(ensureApplicationDataRoot({ workspace: value.workspace, homeDirectory: value.home, environment }), target);
  fs.writeFileSync(path.join(target, 'owned'), 'yes', { mode: 0o600 });
  assert.equal(ensureApplicationDataRoot({ workspace: value.workspace, homeDirectory: value.home, environment }), target);
  assert.equal(fs.readFileSync(path.join(target, 'owned'), 'utf8'), 'yes');
});

test('unsafe roots, permissive roots and owner mismatches fail closed', t => {
  const value = fixture(t), permissive = path.join(value.parent, 'permissive');
  fs.mkdirSync(permissive, { mode: 0o755 });
  if (process.platform !== 'win32') fs.chmodSync(permissive, 0o755);
  const attempts = [path.parse(value.workspace).root, value.workspace, path.dirname(value.workspace), `${value.parent}${path.sep}nested${path.sep}..${path.sep}data`];
  for (const target of attempts) assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
    homeDirectory: value.home, environment: { OWASP_AI_GOAT_APP_DATA_ROOT: target } }), { code: 'INVALID_APPLICATION_DATA_ROOT' });
  if (process.platform !== 'win32') assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
    environment: { OWASP_AI_GOAT_APP_DATA_ROOT: permissive } }), /permissions must be 0700/);
  if (typeof process.getuid === 'function') {
    const owned = path.join(value.parent, 'owned');fs.mkdirSync(owned, { mode: 0o700 });
    assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
      environment: { OWASP_AI_GOAT_APP_DATA_ROOT: owned }, uid: process.getuid() + 1 }),
    { code: 'INVALID_APPLICATION_DATA_ROOT' });
  }
});

test('writable ancestor paths fail before adoption', t => {
  const value = fixture(t), writable = path.join(value.parent, 'writable-parent');
  fs.mkdirSync(writable, { mode: 0o700 });
  if (process.platform !== 'win32') fs.chmodSync(writable, 0o777);
  if (process.platform !== 'win32') assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
    environment: { OWASP_AI_GOAT_APP_DATA_ROOT: path.join(writable, 'data') } }), /ancestors must not be writable/);
  assert.equal(fs.existsSync(path.join(value.home, '.owasp-ai-goat')), false);
});

function windowsFixture() {
  const calls = [];
  const directories = new Set(['c:\\users\\learner', 'c:\\private']);
  const privateState = {
    ensurePrivateDirectory(directory) {
      calls.push(['ensure', directory]);
      assert.ok(directories.has(path.win32.dirname(directory).toLowerCase()), 'parent must already exist');
      directories.add(directory.toLowerCase());
    },
    inspectPrivateDirectory(directory) {
      calls.push(['inspect', directory]);
      assert.ok(directories.has(directory.toLowerCase()));
    },
  };
  return { calls, directories, options: {
    workspace: 'C:\\Code\\owasp-ai-goat', homeDirectory: 'C:\\Users\\Learner', platform: 'win32',
    environment: {}, realpath: value => value.toLowerCase() === 'c:\\code\\owasp-ai-goat' ? 'C:\\Code\\owasp-ai-goat' : value, privateState,
  } };
}

test('controlled Windows default creates private leaves in order and preserves restart identity', () => {
  const value = windowsFixture();
  const id = workspaceId(value.options.workspace, { realpath: value.options.realpath });
  const parents = ['C:\\Users\\Learner\\.owasp-ai-goat', `C:\\Users\\Learner\\.owasp-ai-goat\\${id}`];
  const target = `${parents[1]}\\app-data`;
  assert.equal(ensureApplicationDataRoot(value.options), target);
  assert.equal(value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT, target);
  assert.deepEqual(value.calls, [...parents, target].map(directory => ['ensure', directory])
    .concat([...parents, target].map(directory => ['inspect', directory])));
  assert.equal(ensureApplicationDataRoot({ ...value.options, environment: {}, workspace: 'c:\\CODE\\OWASP-AI-GOAT' }), target);
});

test('controlled Windows explicit root uses native admission and normalizes the drive', () => {
  const value = windowsFixture();
  value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT = 'c:\\Private\\Data';
  assert.equal(ensureApplicationDataRoot(value.options), 'C:\\Private\\Data');
  assert.deepEqual(value.calls, [['ensure', 'C:\\Private\\Data'], ['inspect', 'C:\\Private\\Data']]);
});

test('controlled Windows workspace overlap and unsupported names fail before private operations', () => {
  for (const target of ['C:\\', 'c:\\CODE\\owasp-ai-goat', 'C:\\code', 'C:\\CODE\\OWASP-AI-GOAT\\data',
    '\\\\server\\share\\data', '\\\\?\\C:\\Private\\Data', 'C:/Private/Data', 'C:\\Private\\..\\Data',
    'C:\\Private\\Data:stream', 'C:\\Private\\Data.', 'C:\\Private\\Data ', 'C:\\Private\\NUL',
    `C:\\${'a'.repeat(240)}`, null, 12]) {
    const value = windowsFixture();
    value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT = target;
    assert.throws(() => ensureApplicationDataRoot(value.options), { code: 'INVALID_APPLICATION_DATA_ROOT' });
    assert.deepEqual(value.calls, []);
    assert.equal(value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT, target);
  }
  const value = windowsFixture();
  value.options.homeDirectory = '\\\\server\\share\\home';
  assert.throws(() => ensureApplicationDataRoot(value.options), { code: 'INVALID_APPLICATION_DATA_ROOT' });
  assert.deepEqual(value.calls, []);
  assert.equal(Object.hasOwn(value.options.environment, 'OWASP_AI_GOAT_APP_DATA_ROOT'), false);
});

test('controlled Windows failed native creation or reinspection never publishes environment state', () => {
  // Native NTFS/owner/ACL/reparse failures all deny through the same helper
  // boundary. Simulate denial at each hierarchy and final inspection stage.
  for (let failAt = 1; failAt <= 6; failAt++) {
    const value = windowsFixture();
    let operation = 0;
    for (const method of ['ensurePrivateDirectory', 'inspectPrivateDirectory']) {
      const admitted = value.options.privateState[method];
      value.options.privateState[method] = directory => {
        if (++operation === failAt) throw new Error('private native exception');
        return admitted(directory);
      };
    }
    assert.throws(() => ensureApplicationDataRoot(value.options), error => {
      assert.equal(error.code, 'INVALID_APPLICATION_DATA_ROOT');
      assert.doesNotMatch(error.message, /private native exception/);
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(Object.hasOwn(value.options.environment, 'OWASP_AI_GOAT_APP_DATA_ROOT'), false);
  }
  const value = windowsFixture();
  value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT = 'C:\\Absent\\Parent\\Data';
  assert.throws(() => ensureApplicationDataRoot(value.options), { code: 'INVALID_APPLICATION_DATA_ROOT' });
  assert.equal(value.options.environment.OWASP_AI_GOAT_APP_DATA_ROOT, 'C:\\Absent\\Parent\\Data');
});

test('leaf and ancestor symlinks are rejected without writing through them', t => {
  const value = fixture(t), outside = path.join(value.parent, 'outside');
  fs.mkdirSync(outside, { mode: 0o700 });
  const parentLink = path.join(value.parent, 'linked-parent');
  const leafLink = path.join(value.parent, 'linked-leaf');
  fs.symlinkSync(outside, parentLink, 'dir');
  fs.symlinkSync(outside, leafLink, 'dir');
  assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
    environment: { OWASP_AI_GOAT_APP_DATA_ROOT: path.join(parentLink, 'data') } }), /symbolic links/);
  assert.throws(() => ensureApplicationDataRoot({ workspace: value.workspace,
    environment: { OWASP_AI_GOAT_APP_DATA_ROOT: leafLink } }), /symbolic links/);
  assert.deepEqual(fs.readdirSync(outside), []);
});

test('setup and both startup paths establish the root before dependent work without persisting it to env', () => {
  const start = fs.readFileSync(path.join(__dirname, '../scripts/start-application.js'), 'utf8');
  const setup = fs.readFileSync(path.join(__dirname, '../scripts/setup-application.js'), 'utf8');
  const server = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  assert.ok(start.indexOf("args.includes('--plan')") < start.indexOf('ensureApplicationDataRoot'));
  assert.ok(start.indexOf('ensureApplicationDataRoot') < start.lastIndexOf('createApplicationSupervisor({'));
  assert.ok(server.indexOf('ensureApplicationDataRoot') < server.indexOf('assertApplicationDatabaseEngine'));
  assert.ok(setup.indexOf("throw new SetupError('An .env already exists") < setup.lastIndexOf('ensureApplicationDataRoot'));
  const environmentStart = setup.indexOf('const applicationEnv =');
  const runtimeEnvironmentStart = setup.indexOf('setPhaseEnvironment(', environmentStart);
  const initializationStart = setup.indexOf('await initializeApplication({ maintenanceScope })', runtimeEnvironmentStart);
  assert.ok(environmentStart >= 0 && runtimeEnvironmentStart > environmentStart);
  assert.ok(initializationStart > runtimeEnvironmentStart);
  const applicationEnv = setup.slice(environmentStart, runtimeEnvironmentStart);
  assert.doesNotMatch(applicationEnv, /OWASP_AI_GOAT_APP_DATA_ROOT/);
  assert.match(applicationEnv, /prepareFreshEnvironmentPublication\(/);
  assert.match(setup.slice(runtimeEnvironmentStart, initializationStart), /OWASP_AI_GOAT_APP_DATA_ROOT: appDataRoot/);
  assert.match(setup, /appDataEnvironment = \{ \.\.\.state\.parsed, \.\.\.processEnvironment \}/);
});
