'use strict';
// Inert shell/output contract: no guest, Docker or model calls.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const lease = require('./postgres/ownedV03ListingsLease');

const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
const header = 'set -eu\numask 077\nroot=$1\nnonce=$2\n';
const script = "printf 'absent\\n'";

test('all ordinary phase reads remain quiet and only artifact retirement groups fallback checks', () => {
  assert.deepEqual(Object.keys(lease.PHASES),
    ['build', 'settlement', 'startup', 'cohort', 'retirement', 'cleanup']);
  for (const phase of Object.keys(lease.PHASES)) {
    const read = lease.command('check', phase);
    const wrapped = lease.boundedPhase(script, phase);
    assert(wrapped.includes('remaining=$( (' + read + ') | /usr/bin/python3'), phase);
    assert(wrapped.includes(quote(header + read + ' >/dev/null\n' + script)), phase);
  }
  const read = lease.command('check', 'settlement') + ' 2>/dev/null || ' +
    lease.command('check', 'cleanup');
  const wrapped = lease.boundedPhase(script, 'artifact-retirement');
  assert(wrapped.includes('remaining=$( (' + read + ') | /usr/bin/python3'));
  assert(wrapped.includes(quote(header + '(' + read + ') >/dev/null\n' + script)));
  assert(!wrapped.includes(quote(header + read + ' >/dev/null\n' + script)));
});

test('composite check diagnostic stays off machine-readable stdout', () => {
  const run = body => spawnSync('/bin/sh', ['-c', body],
    { encoding: 'utf8', timeout: 2000, maxBuffer: 65536 });
  const success = run("(printf 'settlement-diagnostic\\n' || printf 'cleanup-diagnostic\\n') >/dev/null; printf 'absent\\n'");
  const fallback = run("(false || printf 'cleanup-diagnostic\\n') >/dev/null; printf 'absent\\n'");
  for (const after of [success, fallback]) {
    assert.equal(after.status, 0);
    assert.equal(after.stdout, 'absent\n');
  }
});
