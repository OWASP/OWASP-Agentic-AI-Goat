'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Admission only: the caller must still create receipts exclusively (wx).
// Local admission is restricted to the launcher's owned disposable runtime.
function assertNativeEvidencePath(file, { root, dockerHost, basename }) {
  assert.ok(path.isAbsolute(root) && path.resolve(root) === root);
  assert.ok(path.isAbsolute(file) && path.resolve(file) === file);
  assert.ok(typeof basename === 'string' && /^[a-z0-9-]+\.json$/.test(basename));
  const profileRoot = path.join(root, '.qualification');
  const prefix = `unix://${profileRoot}/`;
  if (!dockerHost?.startsWith(prefix)) {
    assert.ok(!file.startsWith(`${root}${path.sep}`));
    return file; // Preserve historical external admission for other launchers.
  }
  assert.match(dockerHost.slice(prefix.length), /^(?:goat|dvaia)-[a-z0-9]+(?:-[a-z0-9]+)*\/docker\.sock$/);
  const run = path.dirname(file);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(file, path.join(root, 'tasks', 'qualification', path.basename(run), basename));
  const owned = (directory, mode) => {
    const stat = fs.lstatSync(directory);
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink());
    assert.equal(stat.uid, process.getuid());
    assert.equal(fs.realpathSync(directory), directory);
    if (mode !== undefined) assert.equal(stat.mode & 0o777, mode);
  };
  owned(root);
  owned(path.join(root, 'tasks'));
  owned(path.join(root, 'tasks', 'qualification'), 0o700);
  owned(run, 0o700);
  owned(profileRoot);
  const socketPath = dockerHost.slice('unix://'.length);
  owned(path.dirname(socketPath));
  const socket = fs.lstatSync(socketPath);
  assert.ok(socket.isSocket() && !socket.isSymbolicLink());
  assert.equal(socket.uid, process.getuid());
  assert.throws(() => fs.lstatSync(file), error => error.code === 'ENOENT');
  return file;
}

module.exports = { assertNativeEvidencePath };
