'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./helpers/assertDisposableIdentity');
const valid = {
  PG_TEST_DISPOSABLE: 'yes',
  IDENTITY_DATABASE_URL: 'postgresql://dvaia_identity_runtime@127.0.0.1:5432/owasp_ai_goat_test_rag',
  IDENTITY_MIGRATION_DATABASE_URL: 'postgresql://dvaia_identity_migration@127.0.0.1:5432/owasp_ai_goat_test_rag',
};
test('identity qualification accepts the paired disposable roles', () => guard(valid));
test('identity qualification rejects live, remote, unpaired, privileged and ambiguous URLs before initialization', () => {
  const invalid = [
    { PG_TEST_DISPOSABLE: '' },
    { IDENTITY_DATABASE_URL: valid.IDENTITY_DATABASE_URL.replace('owasp_ai_goat_test_rag', 'application') },
    { IDENTITY_DATABASE_URL: valid.IDENTITY_DATABASE_URL.replace('127.0.0.1', 'remote.invalid') },
    { IDENTITY_MIGRATION_DATABASE_URL: valid.IDENTITY_MIGRATION_DATABASE_URL.replace('5432', '5433') },
    { IDENTITY_DATABASE_URL: valid.IDENTITY_DATABASE_URL.replace('dvaia_identity_runtime', 'postgres') },
    { IDENTITY_DATABASE_URL: valid.IDENTITY_DATABASE_URL + '?options=x' },
    { IDENTITY_DATABASE_URL: 'malformed' },
  ];
  for (const override of invalid) assert.throws(() => guard({ ...valid, ...override }));
});
