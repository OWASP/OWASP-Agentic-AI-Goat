'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

for (const script of ['sync-pi-solutions-to-db.js', 'verify-pr6-indirect-prompt-visibility.js']) {
  test(`${script} explains retirement without database dependencies or mutation`, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-retired-maintenance-'));
    try {
      fs.mkdirSync(path.join(root, 'scripts'));
      fs.mkdirSync(path.join(root, 'server/database'), { recursive: true });
      const database = path.join(root, 'server/database/users_auth.db');
      fs.writeFileSync(database, 'owned sentinel: must remain unchanged');
      const before = fs.readFileSync(database);
      const target = path.resolve(__dirname, '../scripts', script);
      const source = fs.readFileSync(target, 'utf8');
      for (const args of [[], ['--help']]) {
        const child = spawnSync(process.execPath, ['-', ...args], {
          input: source, cwd: root, env: {}, encoding: 'utf8', timeout: 5000,
        });
        assert.equal(child.status, args.length ? 0 : 1);
        assert.match(child.stdout + child.stderr, /retired/);
        assert.match(child.stdout + child.stderr, /\/admin\/exercises/);
        assert.match(child.stdout + child.stderr, /No database was opened or changed/);
        assert.deepEqual(fs.readFileSync(database), before);
        assert.deepEqual(fs.readdirSync(path.dirname(database)), ['users_auth.db']);
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
}
