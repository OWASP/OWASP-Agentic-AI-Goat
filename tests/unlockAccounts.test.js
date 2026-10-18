'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { parseArguments, unlockAccounts } = require('../scripts/admin/unlock-accounts');

test('unlock requires an explicit account or all-accounts selection', () => {
  assert.deepEqual(parseArguments(['--username', 'student']), { username: 'student' });
  assert.deepEqual(parseArguments(['--all']), { username: null });
  for (const args of [[], ['student'], ['--username'], ['--username', ''], ['--all', 'extra']]) {
    assert.throws(() => parseArguments(args), /Usage:/);
  }
});
test('username remains a parameter and unlock returns only the affected count', async () => {
  const username = "student' OR true--";
  let calls = 0;
  const count = await unlockAccounts({ query: async (sql, values) => {
    calls++;
    assert.deepEqual(values, [username]);
    assert.ok(!sql.includes(username));
    assert.match(sql, /UPDATE identity\.users/);
    assert.doesNotMatch(sql, /SET[^]*password\s*=|SET[^]*is_active\s*=/);
    return { rowCount: 1 };
  } }, { username });
  assert.equal(count, 1);
  assert.equal(calls, 1);
});
test('help and no arguments do not import database drivers or private configuration', () => {
  const entry = path.resolve(__dirname, '../scripts/admin/unlock-accounts.js');
  for (const args of [[], ['--help']]) {
    const program = `const Module=require('node:module');const load=Module._load;
      Module._load=function(name){if(/dotenv|sqlite|postgres|^pg$/.test(name))throw new Error('Unexpected database/config import');return load.apply(this,arguments)};
      require(${JSON.stringify(entry)}).main(${JSON.stringify(args)}).catch(e=>{console.error(e);process.exitCode=1});`;
    const result = spawnSync(process.execPath, ['-e', program], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Usage:/);
    assert.doesNotMatch(result.stdout, /password:/i);
  }
});
