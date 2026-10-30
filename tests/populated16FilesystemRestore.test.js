'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const archive = require('../scripts/qualify-application-filesystem-backup');
const {
  restoreFiles,
  verifyRegeneratedPrivateState,
} = require('./release-inputs/populated16-rehearsal.cjs');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');

test('populated restore retains ordinary manager state and regenerates cluster-bound CTF journals', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'populated16-files-')));
  try {
    const backup = path.join(root, 'backup');
    const installation = path.join(root, 'installation');
    const home = path.join(root, 'home');
    const directory = path.join(home, '.owasp-ai-goat', 'controlled');
    fs.mkdirSync(backup, { mode: 0o700 });
    fs.mkdirSync(installation, { mode: 0o700 });
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

    const inputs = [
      ['private_0', 'secureshop-owned-listings.json', '{"status":"ready"}\n'],
      ['private_1', 'ctf-authority.json', '{"cluster":"installed"}\n'],
      ['private_2', 'ctf-delivery.json', '{"cluster":"installed"}\n'],
      ['private_3', 'ctf-delivery.json.pending', '{"cluster":"installed","status":"incomplete"}\n'],
    ].map(([label, name, contents]) => {
      const source = path.join(root, 'source', name);
      fs.mkdirSync(path.dirname(source), { recursive: true, mode: 0o700 });
      fs.writeFileSync(source, contents, { mode: 0o600 });
      return archive.inspectRoot({ label, policy: 'private', source });
    });
    const archivePath = path.join(backup, 'filesystem.archive');
    archive.writeArchive(archivePath, inputs);
    const saved = { filesystem: { sha256: sha(fs.readFileSync(archivePath)), roots: inputs } };

    const result = restoreFiles(saved, backup, installation, home, directory, {});
    assert.deepEqual(result.regenerated.map(row => row.name), ['ctf-authority.json', 'ctf-delivery.json', 'ctf-delivery.json.pending']);
    assert.equal(fs.readFileSync(path.join(directory, 'secureshop-owned-listings.json'), 'utf8'), '{"status":"ready"}\n');
    for (const row of result.regenerated) assert.equal(fs.existsSync(row.target), false);

    const pending = result.regenerated.find(row => row.name === 'ctf-delivery.json.pending');
    const pendingSource = inputs.find(row => path.basename(row.source) === pending.name);
    const originalPending = fs.readFileSync(pendingSource.source);
    assert.deepEqual(fs.readFileSync(path.join(installation, 'backup-restored', pendingSource.label)), originalPending);
    assert.equal(sha(fs.readFileSync(archivePath)), saved.filesystem.sha256);
    assert.throws(() => verifyRegeneratedPrivateState([pending]), { code: 'ENOENT' });
    fs.writeFileSync(pending.target, originalPending, { mode: 0o600 });
    assert.throws(() => verifyRegeneratedPrivateState([pending]), /retained a foreign cluster binding/);

    for (const row of result.regenerated) fs.writeFileSync(row.target, '{"cluster":"disposable"}\n', { mode: 0o600 });
    verifyRegeneratedPrivateState(result.regenerated);
    assert.deepEqual(fs.readFileSync(pendingSource.source), originalPending);
    assert.deepEqual(fs.readFileSync(path.join(installation, 'backup-restored', pendingSource.label)), originalPending);
    assert.equal(sha(fs.readFileSync(archivePath)), saved.filesystem.sha256);
    for (const row of result.immutable) assert.equal(sha(fs.readFileSync(row.path)), row.sha256);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
