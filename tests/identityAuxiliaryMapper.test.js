'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { COLUMNS, mapIdentityAuxiliary } = require('../db/postgres/map-identity-auxiliary');

const integer = value => ({ type: 'integer', value: String(value) });
const stamp = '2026-01-02 03:04:05.123456';
function row(table, values) {
  return Object.fromEntries(COLUMNS[table].split(' ').map(key => [key, Object.hasOwn(values, key) ? values[key] : null]));
}
function fixture() {
  return {
    archiveDigest: 'a'.repeat(64), naiveTimestamps: 'UTC', identityUserIds: [7],
    tables: {
      email_verification_tokens: [row('email_verification_tokens', {
        id: integer(10), user_id: integer(7), token: 'private-verification-token', expires_at: stamp,
        used: integer(0), created_at: stamp,
      })],
      email_agent_progress: [row('email_agent_progress', {
        id: integer(20), user_key: 'owner-7', objective_number: integer(3), completed: integer(1),
        user_email: 'learner@example.test', completed_at: stamp, created_at: stamp, updated_at: stamp,
      })],
      sent_emails_log: [row('sent_emails_log', {
        id: integer(30), user_key: 'owner-7', recipient_email: 'recipient@example.test', scenario_type: 'invoice',
        email_subject: '', sent_at: stamp, gmail_message_id: null,
      })],
      system_config: [row('system_config', {
        id: integer(40), config_key: 'allow_registration', config_value: 'true', config_type: 'boolean',
        description: 'Instructor setting', is_public: integer(0), updated_by: integer(7), updated_at: stamp,
      })],
    },
  };
}

test('maps exact native shapes, IDs and microsecond timestamps while hashing private tokens', () => {
  const source = fixture();
  const result = mapIdentityAuxiliary(source);
  assert.deepEqual(result.auxiliary.email_verification_tokens[0], {
    id: 10, user_id: 7,
    token_hash: createHash('sha256').update('private-verification-token').digest('hex'),
    expires_at: '2026-01-02T03:04:05.123456Z', used: false, created_at: '2026-01-02T03:04:05.123456Z',
  });
  assert.equal(result.auxiliary.sent_emails_log[0].id, 30);
  assert.equal(result.auxiliary.email_agent_progress[0].legacy_id, 20);
  assert.equal(result.auxiliary.email_agent_progress[0].completed, 1);
  assert.equal(result.auxiliary.system_config[0].legacy_id, 40);
  assert.equal(result.auxiliary.system_config[0].description, 'Instructor setting');
  assert.equal(result.auxiliary.system_config[0].source_updated_by, 7);
  assert.equal(result.auxiliary.system_config[0].source_updated_at, '2026-01-02T03:04:05.123456Z');
  assert.equal(result.auxiliary.system_config[0].is_public, false);
  assert.deepEqual(result.report.counts, {
    email_verification_tokens: 1, email_agent_progress: 1, sent_emails_log: 1, system_config: 1,
  });
  assert.equal(result.report.requiresReview, false);
  assert.equal(result.report.readyToApply, true);
});

test('reports every transformation and destination field loss without exposing values', () => {
  const result = mapIdentityAuxiliary(fixture());
  assert.deepEqual(result.report.transformations, [{
    table: 'email_verification_tokens', sourceId: 10, field: 'token', targetField: 'token_hash',
    policy: 'sha256_utf8', requiresReview: false,
  }]);
  assert.deepEqual(result.report.droppedColumns, []);
  const report = JSON.stringify(result.report);
  for (const secret of ['private-verification-token', 'learner@example.test', 'recipient@example.test', 'Instructor setting']) {
    assert.equal(report.includes(secret), false);
  }
});

test('rejects missing owners, ambiguous timestamps, unsafe flags, nullable native requirements and schema drift', () => {
  let source = fixture();
  source.identityUserIds = [];
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'UNRESOLVED_IDENTITY_AUXILIARY_OWNER' });

  source = fixture(); delete source.naiveTimestamps;
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'AMBIGUOUS_TIMESTAMP' });

  source = fixture(); source.tables.email_agent_progress[0].completed = integer(2);
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'UNSAFE_IDENTITY_AUXILIARY_INTEGER' });

  source = fixture(); source.tables.system_config[0].config_value = null;
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'INVALID_IDENTITY_AUXILIARY_TEXT' });

  source = fixture(); source.tables.sent_emails_log[0].unexpected = 'value';
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'UNMAPPED_IDENTITY_AUXILIARY_COLUMNS' });

  source = fixture(); source.tables.system_config[0].config_type = 'secret';
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'INVALID_SYSTEM_CONFIG_TYPE' });

  source = fixture(); source.extraPolicy = 'ignored typo';
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'INVALID_IDENTITY_AUXILIARY_INPUT' });
});

test('rejects duplicate native keys and duplicate plaintext tokens after hashing', () => {
  let source = fixture();
  source.tables.email_agent_progress.push({ ...source.tables.email_agent_progress[0], id: integer(21) });
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'DUPLICATE_EMAIL_AGENT_PROGRESS_SCOPE' });

  source = fixture();
  source.tables.email_verification_tokens.push({ ...source.tables.email_verification_tokens[0], id: integer(11) });
  assert.throws(() => mapIdentityAuxiliary(source), { code: 'DUPLICATE_VERIFICATION_TOKEN' });
});
