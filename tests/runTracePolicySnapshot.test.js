'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { traceData } = require('../server/agent-runtime/runTraceStore');

const digest = 'a'.repeat(64);
const profiles = [
  ['guided_weak_policy', 'dpi-guided-weak-policy-v1'],
  ['trust_boundary', 'dpi-trust-boundary-v1'],
];

test('trace projection admits only the two exact policy triples defined by identity migration 0059', () => {
  const migration = fs.readFileSync(path.join(
    __dirname,
    '../db/postgres/identity-migrations/0059_dpi_policy_trace_metadata.sql',
  ), 'utf8');

  for (const [policyProfile, policyVersion] of profiles) {
    assert.match(migration, new RegExp(`metadata->>'policyProfile' = '${policyProfile}'.+metadata->>'policyVersion' = '${policyVersion}'`));
    assert.deepEqual(
      traceData({ policyProfile, policyVersion, policyDigest: digest }),
      { policyProfile, policyVersion, policyDigest: digest },
    );
  }
});

test('policy projection rejects partial, mismatched, malformed, and non-string triples atomically', () => {
  const invalid = [
    { policyProfile: 'guided_weak_policy' },
    { policyProfile: 'guided_weak_policy', policyVersion: 'dpi-guided-weak-policy-v1' },
    { policyProfile: 'guided_weak_policy', policyVersion: 'dpi-trust-boundary-v1', policyDigest: digest },
    { policyProfile: 'trust_boundary', policyVersion: 'dpi-trust-boundary-v1', policyDigest: 'A'.repeat(64) },
    { policyProfile: 'trust_boundary', policyVersion: 'dpi-trust-boundary-v1', policyDigest: 'a'.repeat(63) },
    { policyProfile: 'trust_boundary', policyVersion: 'dpi-trust-boundary-v1', policyDigest: 7 },
  ];

  for (const candidate of invalid) {
    assert.deepEqual(traceData({ decisionSource: 'model', ...candidate }), { decisionSource: 'model' });
  }
});
