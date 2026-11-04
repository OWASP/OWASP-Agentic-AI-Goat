'use strict';

const { mapIdentityAuxiliary } = require('./map-identity-auxiliary');

// Must match a freshly-migrated identity.system_config read with ORDER BY config_key
// (see the guard query below). Keep entries in config_key alphabetical order.
const INITIAL_CONFIG = Object.freeze([
  { config_key: 'allow_registration', config_value: 'true', config_type: 'boolean', is_public: false },
  { config_key: 'enable_rate_limiting', config_value: 'false', config_type: 'boolean', is_public: false },
  { config_key: 'secureshop_visible', config_value: 'true', config_type: 'boolean', is_public: true },
  { config_key: 'workshop_signup_random_email_enabled', config_value: 'false', config_type: 'boolean', is_public: false },
]);

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/** Caller owns BEGIN/COMMIT/ROLLBACK. No source values are returned or logged. */
async function applyIdentityAuxiliary(client, raw) {
  const mapped = mapIdentityAuxiliary(raw);
  if (!mapped.report.readyToApply) reject('IDENTITY_AUXILIARY_IMPORT_REQUIRES_REVIEW');
  await client.query('SAVEPOINT identity_auxiliary_guard');
  await client.query(`LOCK TABLE identity.email_verification_tokens, identity.email_agent_progress,
    identity.sent_emails_log, identity.system_config IN ACCESS EXCLUSIVE MODE`);
  for (const table of ['email_verification_tokens', 'email_agent_progress', 'sent_emails_log']) {
    if ((await client.query(`SELECT EXISTS(SELECT 1 FROM identity.${table}) AS populated`)).rows[0].populated) {
      reject('IDENTITY_AUXILIARY_IMPORT_REQUIRES_EMPTY_TARGET');
    }
  }
  const currentConfig = (await client.query(`SELECT config_key,config_value,config_type,is_public
    FROM identity.system_config ORDER BY config_key`)).rows;
  if (JSON.stringify(currentConfig) !== JSON.stringify(INITIAL_CONFIG)) reject('IDENTITY_AUXILIARY_IMPORT_REQUIRES_DEFAULT_CONFIG');
  if ((await client.query(`SELECT EXISTS(SELECT 1 FROM identity.system_config
    WHERE legacy_id IS NOT NULL OR description IS NOT NULL OR source_updated_by IS NOT NULL OR source_updated_at IS NOT NULL) AS populated`)).rows[0].populated) {
    reject('IDENTITY_AUXILIARY_IMPORT_REQUIRES_DEFAULT_CONFIG');
  }

  for (const row of mapped.auxiliary.email_verification_tokens) await client.query(`INSERT INTO identity.email_verification_tokens
    (id,user_id,token_hash,expires_at,used,created_at) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6)`,
  [row.id, row.user_id, row.token_hash, row.expires_at, row.used, row.created_at]);
  for (const row of mapped.auxiliary.email_agent_progress) await client.query(`INSERT INTO identity.email_agent_progress
    (legacy_id,user_key,objective_number,completed,user_email,completed_at,created_at,updated_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [row.legacy_id, row.user_key, row.objective_number, row.completed, row.user_email, row.completed_at, row.created_at, row.updated_at]);
  for (const row of mapped.auxiliary.sent_emails_log) await client.query(`INSERT INTO identity.sent_emails_log
    (id,user_key,recipient_email,scenario_type,email_subject,sent_at,gmail_message_id)
    OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7)`,
  [row.id, row.user_key, row.recipient_email, row.scenario_type, row.email_subject, row.sent_at, row.gmail_message_id]);
  await client.query('DELETE FROM identity.system_config');
  for (const row of mapped.auxiliary.system_config) await client.query(`INSERT INTO identity.system_config
    (legacy_id,config_key,config_value,config_type,is_public,description,source_updated_by,source_updated_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [row.legacy_id, row.config_key, row.config_value, row.config_type, row.is_public, row.description, row.source_updated_by, row.source_updated_at]);

  const tokenNext = mapped.auxiliary.email_verification_tokens.reduce((max, row) => Math.max(max, row.id), 0) + 1;
  const sentNext = mapped.auxiliary.sent_emails_log.reduce((max, row) => Math.max(max, row.id), 0) + 1;
  await client.query(`ALTER TABLE identity.email_verification_tokens ALTER COLUMN id RESTART WITH ${tokenNext}`);
  await client.query(`ALTER TABLE identity.sent_emails_log ALTER COLUMN id RESTART WITH ${sentNext}`);
  await client.query('RELEASE SAVEPOINT identity_auxiliary_guard');
  return { applied: true, archiveDigest: raw.archiveDigest, counts: mapped.report.counts,
    transformations: mapped.report.transformations.map(({ requiresReview, ...record }) => record) };
}

module.exports = { INITIAL_CONFIG, applyIdentityAuxiliary };
