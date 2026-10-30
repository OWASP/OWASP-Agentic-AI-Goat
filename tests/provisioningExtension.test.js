'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { provisioningExtension } = require('../db/postgres/provisioning-extension');
const row = (schema, prefix) => ({ schema, database: `owasp_ai_goat_${schema}`, runtimeRole: `dvaia_${schema}_runtime`,
  migrationRole: `dvaia_${schema}_migration`, runtimeVariable: `${prefix}_DATABASE_URL`, migrationVariable: `${prefix}_MIGRATION_DATABASE_URL` });
const previous = [row('identity', 'IDENTITY'), row('xss', 'XSS_WORKSHOP')];
const additional = row('session_disclosure', 'SESSION_DISCLOSURE');
test('additive provisioning preserves every existing identity and returns only new databases', () => {
  assert.deepEqual(provisioningExtension(previous, previous), []);
  const desired = [...previous, additional];
  const delta = provisioningExtension(previous, desired);
  assert.deepEqual(delta, [additional]);
  delta[0].schema = 'changed';
  assert.equal(desired[2].schema, 'session_disclosure');
});
test('plan extension rejects removal, reordering, rebinding, collisions and malformed identities', () => {
  const invalid = [[], [previous[0]], [...previous].reverse(),
    [previous[0], { ...previous[1], runtimeVariable: 'OTHER_DATABASE_URL', migrationVariable: 'OTHER_MIGRATION_DATABASE_URL' }],
    [...previous, previous[1]], [...previous, { ...additional, runtimeVariable: previous[0].runtimeVariable, migrationVariable: previous[0].migrationVariable }],
    [...previous, { ...additional, database: 'owasp_ai_goat_identity' }], [...previous, { ...additional, unreviewed: true }]];
  for (const desired of invalid) assert.throws(() => provisioningExtension(previous, desired), { code: 'PROVISIONING_EXTENSION_INVALID' });
  assert.throws(() => provisioningExtension([], [additional]), { code: 'PROVISIONING_EXTENSION_INVALID' });
});
