const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const script = path.resolve(__dirname, '../scripts/seed-bulk-data.js');

test('retired bulk operator command fails closed for default, new and existing targets', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-seed-bulk-'));
  const absent = path.join(directory, 'new.db');
  const existing = path.join(directory, 'existing.db');
  const sentinel = Buffer.from('owned synthetic fixture sentinel\n');
  try {
    fs.chmodSync(directory, 0o700);
    fs.writeFileSync(existing, sentinel, { mode: 0o600, flag: 'wx' });
    assert.equal(fs.existsSync(absent), false);

    for (const target of [undefined, absent, existing]) {
      const env = { ...process.env };
      if (target === undefined) delete env.SS_SECURESHOP_DB_PATH;
      else env.SS_SECURESHOP_DB_PATH = target;
      const result = spawnSync(process.execPath, [script], {
        env,
        cwd: directory,
        encoding: 'utf8',
        timeout: 5000,
      });
      assert.equal(result.status, 1, result.error?.message || result.stderr);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /SQLite repair command is retired/);
      assert.match(result.stderr, /PostgreSQL/);
      assert.match(result.stderr, /owned disposable DB_OUTPUT_DIR/);
      assert.equal(fs.existsSync(absent), false);
      assert.deepEqual(fs.readFileSync(existing), sentinel);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
