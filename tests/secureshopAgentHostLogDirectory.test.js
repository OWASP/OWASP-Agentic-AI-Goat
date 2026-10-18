'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('agent-host bootstrap honors configured writable logs before database readiness', async () => {
  const entry = path.resolve(__dirname, '../agent-host/index.js');
  const source = fs.readFileSync(entry, 'utf8');
  for (const configured of ['/owned/runtime/logs', undefined]) {
    const created = [], exits = [];
    let databaseReached = false;
    const expected = configured || path.resolve(__dirname, '../server/logs');
    vm.runInNewContext(source, {
      __dirname: path.dirname(entry),
      require(name) {
        if (name === 'node:path') return path;
        if (name === '../server/services/applicationDatabaseEngine') return {
          assertApplicationDatabaseEngine() { return 'postgres'; },
        };
        if (name === 'node:fs') return {
          existsSync(value) { assert.equal(value, expected);return false; },
          mkdirSync(value, options) { assert.equal(value, expected);assert.equal(options.recursive, true);created.push(value); },
        };
        if (name === 'express') return () => { throw Error('Unexpected HTTP startup'); };
        if (name === '@modelcontextprotocol/sdk/server/sse.js') return {};
        if (name === '../server/database/postgres/secureshopInitialization') return {
          async verifySecureShopRuntime() { databaseReached = true;throw Error('Controlled readiness boundary'); },
        };
        throw Error('Unexpected import: ' + name);
      },
      process: { env: { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
          ...(configured ? { LOGS_DIR: configured } : {}) },
        stderr: { write() {} }, exit(code) { exits.push(code); } },
    }, { filename: entry });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(created, [expected]);assert.equal(databaseReached, true);assert.deepEqual(exits, [1]);
  }
});
