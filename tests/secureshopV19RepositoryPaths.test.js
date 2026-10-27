'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { assertV19RepositoryPaths } = require('./fixtures/secureshopV19RepositoryPaths');

const root = path.resolve(__dirname, '..');
function owned(t) {
  const run = fs.mkdtempSync(path.join(root, 'tasks/qualification/run-v19-path-'));
  t.after(() => fs.rmSync(run, { recursive: true, force: true }));
  const runtime = path.join(run, 'runtime');
  const ownedFilesRoot = path.join(runtime, 'v19-owned-files');
  fs.mkdirSync(runtime, { mode: 0o700 });
  fs.mkdirSync(ownedFilesRoot, { mode: 0o700 });
  return { root, supportReceipt: path.join(run, 'customer-checkout-browser.json'),
    cohortReceipt: path.join(run, 'customer-file-summary-v19-browser.json'), ownedFilesRoot, run, runtime };
}

test('V19 admits only its fresh, private, owned repository run paths', t => {
  const { run, runtime, ...input } = owned(t);
  const other = owned(t);
  assert.equal(assertV19RepositoryPaths(input), true);
  const bad = [
    { supportReceipt: path.join(run, 'other.json') },
    { cohortReceipt: path.join(run, 'other.json') },
    { ownedFilesRoot: path.join(runtime, 'other') },
    { supportReceipt: `${run}/runtime/../customer-checkout-browser.json` },
    { cohortReceipt: path.join(root, 'tasks/tmp/customer-file-summary-v19-browser.json') },
    { supportReceipt: other.supportReceipt },
    { ownedFilesRoot: other.ownedFilesRoot },
    { ownedFilesRoot: `${run}/../v19-owned-files` },
    { root: `${root}/tasks/..` },
  ];
  for (const mutation of bad) assert.throws(() => assertV19RepositoryPaths({ ...input, ...mutation }));
  fs.writeFileSync(input.supportReceipt, '{}', { mode: 0o600 });
  assert.throws(() => assertV19RepositoryPaths(input));
  fs.unlinkSync(input.supportReceipt);
  for (const file of [input.cohortReceipt, path.join(run, 'v19-original-evidence.json')]) {
    fs.writeFileSync(file, '{}', { mode: 0o600 });
    assert.throws(() => assertV19RepositoryPaths(input));
    fs.unlinkSync(file);
  }
  fs.chmodSync(runtime, 0o755);
  assert.throws(() => assertV19RepositoryPaths(input));
  fs.chmodSync(runtime, 0o700);
  assert.equal(assertV19RepositoryPaths(input), true);
});

test('V19 rejects a linked or foreign-owned files directory', t => {
  const { run, ...input } = owned(t);
  const alias = fs.mkdtempSync(path.join(root, 'tasks/qualification/run-v19-alias-'));
  fs.rmdirSync(alias);
  fs.symlinkSync(run, alias, 'dir');
  t.after(() => fs.unlinkSync(alias));
  assert.throws(() => assertV19RepositoryPaths({ ...input,
    supportReceipt: path.join(alias, 'customer-checkout-browser.json'),
    cohortReceipt: path.join(alias, 'customer-file-summary-v19-browser.json'),
    ownedFilesRoot: path.join(alias, 'runtime/v19-owned-files') }));
  const real = path.join(run, 'real-v19-files');
  fs.renameSync(input.ownedFilesRoot, real);
  fs.symlinkSync(real, input.ownedFilesRoot, 'dir');
  assert.throws(() => assertV19RepositoryPaths(input));
  fs.unlinkSync(input.ownedFilesRoot);
  fs.renameSync(real, input.ownedFilesRoot);
  const original = fs.lstatSync;
  t.mock.method(fs, 'lstatSync', value => {
    const info = original(value);
    return value === input.ownedFilesRoot ? { uid: process.getuid() + 1, mode: info.mode,
      isDirectory: () => info.isDirectory(), isSymbolicLink: () => info.isSymbolicLink() } : info;
  });
  assert.throws(() => assertV19RepositoryPaths(input), { code: 'ERR_ASSERTION' });
});

test('actual evidence-path branch admits V19 owned paths and rejects other cohorts inside the repository', t => {
  const checkout = fs.readFileSync(path.join(root, 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'), 'utf8');
  const cohort = fs.readFileSync(path.join(root, 'tests/fixtures/secureshopV19RenderedCohort.js'), 'utf8');
  const start = checkout.indexOf('    if (V19_SUMMARY) require(');
  const end = checkout.indexOf('    const executablePath = ', start);
  assert(start >= 0 && end > start);
  const execute = new Function('V19_SUMMARY', 'require', 'process', 'root', 'receiptPath', 'assert', 'path',
    `${checkout.slice(start, end)}\nreturn ownedCheckout;`);
  const localRequire = require('node:module').createRequire(path.join(root,
    'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'));
  const input = owned(t);
  const env = { SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH: input.cohortReceipt,
    SECURESHOP_V19_OWNED_FILES_ROOT: input.ownedFilesRoot };
  assert.equal(env.SECURESHOP_COMMERCE_TEST_NO_SANDBOX, undefined);
  const admit = (selected, supportReceipt, environment = env) => execute(selected, localRequire,
    { env: environment }, root, supportReceipt, assert, path);
  assert.equal(admit(true, input.supportReceipt), false);
  assert.throws(() => admit(true, path.join(input.run, 'wrong.json')));
  assert.throws(() => admit(true, input.supportReceipt,
    { ...env, SECURESHOP_V19_OWNED_FILES_ROOT: path.join(input.runtime, 'foreign') }));
  // No writes or resources outside the repository: these are path admission
  // checks only, with the actual non-V19 predicate and no commerce opt-in.
  assert.equal(admit(false, path.join(path.dirname(root), 'external-evidence.json')), false);
  assert.throws(() => admit(false, input.supportReceipt));
  assert.throws(() => admit(false, 'relative-evidence.json'));
  assert.match(cohort, /require\('\.\/secureshopV19RepositoryPaths'\)\.assertV19RepositoryPaths/);
});
