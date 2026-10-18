'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const runtime = require('../server/services/mcp/configSnapshotProgram');
const source = require('../sidecars/sandbox-runner/index');

test('backend-only compatibility artifact matches the runner implementation exactly', () => {
  for (const id of [randomUUID(), randomUUID().toUpperCase()]) {
    assert.equal(runtime.buildConfigSnapshotProgram(id), source.buildConfigSnapshotProgram(id),
      'regenerate with node scripts/generate-mcp-config-program.js after snapshot changes');
  }
  for (const id of [null, '', "'; process.exit(); //", 'not-a-uuid']) {
    assert.throws(() => runtime.buildConfigSnapshotProgram(id), TypeError);
  }
});
