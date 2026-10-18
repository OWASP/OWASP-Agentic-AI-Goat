'use strict';

// Controlled providers verify facade admission and sequencing. They do not
// establish native Windows, Multipass, SSH, or private-publication evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');
const { createWindowsLabInstallation } = require('../scripts/lib/windows-lab-installation');
const { createWindowsProvisioningJournal } = require('../scripts/lib/windows-provisioning-journal');

const root = 'C:\\Users\\Learner\\repo';
const homeDirectory = 'C:\\Users\\Learner';
const id = crypto.createHash('sha256').update(root).digest('hex').slice(0, 12);
const directory = path.win32.join(homeDirectory, '.dvaia', id);
const configPath = path.win32.join(directory, 'windows-lab-installation.json');
const environment = {
  DVAIA_WINDOWS_MULTIPASS_EXECUTABLE: 'C:\\Program Files\\Multipass\\bin\\multipass.exe',
  DVAIA_WINDOWS_SSH_EXECUTABLE: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
};
const identity = fileId => ({ volumeSerial: 9, fileId: fileId.toString(16).padStart(16, '0') });

function fixture() {
  const files = new Map(), directories = new Map([[homeDirectory, identity(1)]]), calls = [], intents = new Map();
  let sequence = 1, minted = 0, closeCount = 0, bindCount = 0, denyOwner = false, denyBind = false;
  const privateState = {
    inspectWorkspaceDirectory(p) { calls.push(['workspace', p]); if (p !== root) throw Error('foreign workspace secret'); return { identity: identity(2) }; },
    ensurePrivateDirectory(p) { calls.push(['ensure', p]); if (!directories.has(p)) directories.set(p, identity(++sequence)); return { identity: directories.get(p) }; },
    inspectPrivateDirectory(p) { calls.push(['inspect', p]); if (!directories.has(p)) throw Error('missing private directory secret'); return { identity: directories.get(p) }; },
    readPrivateFile(p) { calls.push(['read-private', p]); if (!files.has(p)) throw Error('missing private file secret'); return Buffer.from(files.get(p)); },
  };
  const publication = {
    preparePrivatePublication(request) {
      calls.push(['prepare', request.targetPath]);
      if (files.has(request.targetPath) || request.originalBytes !== null) throw Error('create-new refused');
      intents.set(request.intentPath, request);
      const sha = crypto.createHash('sha256').update(request.resultBytes).digest('hex');
      return { state: 'prepared', intentSha256: sha, size: request.resultBytes.length, identity: identity(99) };
    },
    publishPrivatePublication(request) {
      calls.push(['publish', request.targetPath]);
      const prepared = intents.get(request.intentPath);
      if (!prepared) throw Error('missing intent');
      files.set(request.targetPath, Buffer.from(prepared.resultBytes));
      const sha = crypto.createHash('sha256').update(prepared.resultBytes).digest('hex');
      return { state: 'committed', intentSha256: sha, size: prepared.resultBytes.length, identity: identity(99) };
    },
  };
  const journal = createWindowsProvisioningJournal({ platform: 'win32', privateState, publication });
  const session = {
    async bindDaemon() { bindCount++; calls.push(['bind']); if (denyBind) throw Error('daemon secret'); return { daemonId: 'owned-daemon' }; },
    async closeForwards() { closeCount++; calls.push(['close']); },
  };
  const ownLabChild = async () => ({ async stopAndJoin() {} });
  const ownedLab = { async prepareOwnedLab(options) { calls.push(['prepare-lab', options]); return session; } };
  const fileSystem = {
    realpathSync(p) { if (![root, homeDirectory].includes(p)) throw Error('foreign path'); return p; },
    lstatSync(p) { if (files.has(p)) return { isFile: () => true }; throw Object.assign(Error('missing'), { code: 'ENOENT' }); },
  };
  const facade = createWindowsLabInstallation({ platform: 'win32', fileSystem, privateState, journal, ownedLab,
    createForwardOwner() { calls.push(['owner']); if (denyOwner) throw Error('forward secret'); return ownLabChild; },
    randomUUID() { minted++; return minted === 1 ? '11111111-1111-4111-8111-111111111111' : '22222222-2222-4222-8222-222222222222'; },
  });
  return { facade, files, directories, calls, session, ownLabChild,
    get minted() { return minted; }, get closeCount() { return closeCount; }, get bindCount() { return bindCount; },
    denyOwner() { denyOwner = true; }, denyBind() { denyBind = true; } };
}

test('fresh journals branded installation identity before owned VM preparation and drains forwards once', async () => {
  const f = fixture();
  const result = await f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' });
  const config = JSON.parse(f.files.get(configPath));
  assert.equal(f.minted, 2);
  assert.deepEqual(config, { version: 1, workspaceId: id, workspaceRoot: root,
    installationId: '11111111-1111-4111-8111-111111111111', operationId: '22222222-2222-4222-8222-222222222222',
    instanceName: 'dvaia-lab-' + id, multipassExecutable: environment.DVAIA_WINDOWS_MULTIPASS_EXECUTABLE,
    sshExecutable: environment.DVAIA_WINDOWS_SSH_EXECUTABLE, image: '24.04' });
  assert.equal(f.calls.findIndex(call => call[0] === 'publish') < f.calls.findIndex(call => call[0] === 'prepare-lab'), true);
  assert.equal(f.calls.findIndex(call => call[0] === 'prepare-lab') < f.calls.findIndex(call => call[0] === 'bind'), true);
  assert.equal(f.calls.findIndex(call => call[0] === 'bind') < f.calls.findIndex(call => call[0] === 'owner'), true);
  assert.deepEqual(f.calls.find(call => call[0] === 'prepare-lab')[1], { directory, workspaceId: id,
    installationId: config.installationId, operationId: config.operationId, instanceName: config.instanceName,
    multipassExecutable: config.multipassExecutable, sshExecutable: config.sshExecutable, image: '24.04', existingOnly: false });
  assert.equal(result.session, f.session); assert.equal(result.ownLabChild, f.ownLabChild); assert(Object.isFrozen(result));
  assert.equal(f.bindCount, 1);
  await result.close(); await result.close(); assert.equal(f.closeCount, 1);
});

test('existing and explicit fresh retry reuse exact retained IDs without a second publication', async () => {
  const f = fixture();
  await f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' });
  const retained = Buffer.from(f.files.get(configPath));
  const before = f.calls.filter(call => call[0] === 'publish').length;
  await f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment: {}, mode: 'existing' });
  await f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment: {}, mode: 'fresh' });
  assert.equal(f.minted, 2); assert(f.files.get(configPath).equals(retained));
  assert.equal(f.bindCount, 3);
  assert.equal(f.calls.filter(call => call[0] === 'publish').length, before);
  assert.deepEqual(f.calls.filter(call => call[0] === 'prepare-lab').map(call => call[1].existingOnly), [false, true, false]);
  assert.equal(f.calls.filter(call => call[0] === 'ensure').length, 4);
});

test('existing-only refuses absent settings before minting, publication or owned lab calls', async () => {
  const f = fixture();
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment: {}, mode: 'existing' }),
    { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  assert.equal(f.minted, 0); assert.equal(f.files.size, 0);
  assert(!f.calls.some(call => ['ensure', 'publish', 'prepare-lab'].includes(call[0])));
});

test('fresh requires admitted absolute executable bindings and refuses malformed retained identity', async () => {
  const f = fixture();
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment: {}, mode: 'fresh' }),
    { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory,
    environment: { ...environment, DVAIA_WINDOWS_SSH_EXECUTABLE: 'C:\\Windows\\System32\\cmd.exe' }, mode: 'fresh' }),
  { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  assert.equal(f.minted, 0); assert.equal(f.files.size, 0);
  await f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' });
  const config = JSON.parse(f.files.get(configPath));
  f.files.set(configPath, Buffer.from(JSON.stringify({ ...config, instanceName: 'dvaia-lab-foreign' }) + '\n'));
  const count = f.calls.filter(call => call[0] === 'prepare-lab').length;
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment: {}, mode: 'existing' }),
    { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  assert.equal(f.calls.filter(call => call[0] === 'prepare-lab').length, count);
});

test('facade assembly denial closes a prepared session and scrubs native diagnostics', async () => {
  const f = fixture(); f.denyOwner();
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' }), error => {
    assert.equal(error.code, 'WINDOWS_LAB_INSTALLATION_DENIED');
    assert(!String(error.stack).includes('forward secret'));
    return true;
  });
  assert.equal(f.closeCount, 1);
});

test('daemon binding failure closes the prepared session before exposing it', async () => {
  const f = fixture(); f.denyBind();
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' }), error => {
    assert.equal(error.code, 'WINDOWS_LAB_INSTALLATION_DENIED');
    assert(!String(error.stack).includes('daemon secret'));
    return true;
  });
  assert.equal(f.bindCount, 1); assert.equal(f.closeCount, 1);
  assert(!f.calls.some(call => call[0] === 'owner'));
});

test('unsupported platform and workspace overlap fail before private or VM authority', async () => {
  const f = fixture();
  const unavailable = createWindowsLabInstallation({ platform: 'linux', privateState: new Proxy({}, { get() { throw Error('native helper reached'); } }) });
  await assert.rejects(unavailable.prepareWindowsLabInstallation({ root, homeDirectory, environment, mode: 'fresh' }),
    { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  await assert.rejects(f.facade.prepareWindowsLabInstallation({ root: homeDirectory, homeDirectory, environment, mode: 'fresh' }),
    { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
  assert.equal(f.files.size, 0); assert(!f.calls.some(call => call[0] === 'prepare-lab'));
});
