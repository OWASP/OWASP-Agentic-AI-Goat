 'use strict';
// Real file reads through the installed owner-isolated FinFlow teaching boundary.
// Synthetic fixture content is read from real files; no host/private file is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createTraversalFixture, execution } = require('./helpers/finflowTraversalFixture');
const { createSensitiveInfoWorkshopStateStore, executeVaultCorpTool } = require('../server/services/sensitiveInfoWorkshopAgent');
const cases = [
  ['secrets', '../../config/secrets.env', 'config/secrets.env'],
  ['llm configuration', '../../sensitive_files/config/llm_config.yml', 'sensitive_files/config/llm_config.yml'],
  ['passwd fixture', '/etc/passwd', 'etc/passwd'],
];
function content(result) {
  const separator = '─'.repeat(50) + '\n';
  const index = result.indexOf(separator);
  assert.notEqual(index, -1, 'controlled traversal header must identify the returned artifact');
  return result.slice(index + separator.length);
}
function setup(t) {
  const fixture = createTraversalFixture(t);
  const states = createSensitiveInfoWorkshopStateStore({ traversalManager: fixture.manager });
  const call = (owner, tool, logicalPath, mode = 'vulnerable') => executeVaultCorpTool(tool,
    tool === 'get_transaction_history' ? { account_id: logicalPath } : { document_path: logicalPath },
    mode, states.getUserState(owner), execution(owner));
  return { ...fixture, call };
}
for (const tool of ['get_transaction_history', 'download_statement']) {
  for (const [label, logicalPath, relative] of cases) {
    test(`${tool}: ${label} returns the exact controlled file bytes`, async t => {
      const f = setup(t);
      const requestPath = tool === 'get_transaction_history' && logicalPath === '/etc/passwd'
        ? '../../../../etc/passwd' : logicalPath;
      const result = await f.call('alice', tool, requestPath);
      assert.equal(result.success, true);
      const target = await f.repository.get(execution('alice'));
      assert.equal(target.state, 'active');
      const filename = path.join(f.root, target.targetToken, relative);
      assert.equal(fs.lstatSync(filename).isSymbolicLink(), false);
      assert.equal(content(result.result), fs.readFileSync(filename, 'utf8'));
      assert.ok(content(result.result).length > 0);
    });
  }
}
test('fixed mode denies the same traversal requests without provisioning a target', async t => {
  const f = setup(t);
  for (const tool of ['get_transaction_history', 'download_statement']) {
    for (const [, logicalPath] of cases) {
      const requestPath = tool === 'get_transaction_history' && logicalPath === '/etc/passwd'
        ? '../../../../etc/passwd' : logicalPath;
      const result = await f.call('alice', tool, requestPath, 'fixed');
      assert.equal(result.success, false);
    }
  }
  assert.equal(f.repository.rows.size, 0);
});
test('owners read separate files and one owner file change never appears in another result', async t => {
  const f = setup(t);
  await f.call('alice', 'get_transaction_history', cases[0][1]);
  const bobBaseline = await f.call('bob', 'get_transaction_history', cases[0][1]);
  const alice = await f.repository.get(execution('alice'));
  const bob = await f.repository.get(execution('bob'));
  assert.notEqual(alice.targetToken, bob.targetToken);
  const filename = path.join(f.root, alice.targetToken, cases[0][2]);
  fs.writeFileSync(filename, 'CONTROLLED_OWNER_MARKER=alice-only\n');
  const changed = await f.call('alice', 'get_transaction_history', cases[0][1]);
  const unchanged = await f.call('bob', 'get_transaction_history', cases[0][1]);
  assert.equal(content(changed.result), fs.readFileSync(filename, 'utf8'));
  assert.equal(content(unchanged.result), content(bobBaseline.result));
  assert.doesNotMatch(unchanged.result, /alice-only/);
});

for (const account of ['FF-001', 'FF-002']) {
  for (const tool of ['get_transaction_history', 'download_statement']) {
    test(`${tool}: legitimate ${account} read retains exact file content`, async t => {
      const f = setup(t);
      const filename = tool === 'get_transaction_history' ? `${account}.json` : `statement-${account}-2024.txt`;
      const result = await f.call('alice', tool, tool === 'get_transaction_history' ? account : filename);
      assert.equal(result.success, true);
      const expected = fs.readFileSync(path.join(__dirname, '../server/workshop_data',
        tool === 'get_transaction_history' ? 'transactions' : 'documents', filename), 'utf8');
      const separator = '─'.repeat(50) + '\n';
      assert.equal(result.result.includes(separator) ? content(result.result) : result.result, expected);
    });
  }
}

test('get_transaction_history: legitimate FF-002.json input retains exact file content', async t => {
  const f = setup(t);
  const result = await f.call('alice', 'get_transaction_history', 'FF-002.json');
  assert.equal(result.success, true);
  const expected = fs.readFileSync(path.join(__dirname, '../server/workshop_data/transactions/FF-002.json'), 'utf8');
  assert.equal(result.result, expected);
});
