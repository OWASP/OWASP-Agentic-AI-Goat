'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Admit only the launcher's private V19 run. No other cohort gains a repository
// evidence exception, and neither a path alias nor a pre-existing receipt is usable.
function assertV19RepositoryPaths({ root, supportReceipt, cohortReceipt, ownedFilesRoot }) {
  assert.ok(path.isAbsolute(root) && path.resolve(root) === root);
  assert.equal(fs.realpathSync(root), root);
  const run = path.dirname(cohortReceipt);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(path.dirname(run), path.join(root, 'tasks', 'qualification'));
  assert.equal(supportReceipt, path.join(run, 'customer-checkout-browser.json'));
  assert.equal(cohortReceipt, path.join(run, 'customer-file-summary-v19-browser.json'));
  assert.equal(ownedFilesRoot, path.join(run, 'runtime', 'v19-owned-files'));
  for (const [directory, mode] of [
    [path.join(root, 'tasks'), undefined],
    [path.join(root, 'tasks', 'qualification'), 0o700],
    [run, 0o700], [path.join(run, 'runtime'), 0o700], [ownedFilesRoot, 0o700]
  ]) {
    const info = fs.lstatSync(directory);
    assert.ok(info.isDirectory() && !info.isSymbolicLink());
    assert.equal(info.uid, process.getuid());
    assert.equal(fs.realpathSync(directory), directory);
    if (mode !== undefined) assert.equal(info.mode & 0o777, mode);
  }
  for (const file of [supportReceipt, cohortReceipt, path.join(run, 'v19-original-evidence.json')]) {
    assert.throws(() => fs.lstatSync(file), error => error.code === 'ENOENT');
  }
  return true;
}

module.exports = { assertV19RepositoryPaths };
