'use strict';

const { createHash } = require('node:crypto');
const { timestamp } = require('../../server/database/postgres/identityValidation');

const COLUMNS = Object.freeze({
  email_verification_tokens: 'id user_id token expires_at used created_at',
  email_agent_progress: 'id user_key objective_number completed user_email completed_at created_at updated_at',
  sent_emails_log: 'id user_key recipient_email scenario_type email_subject sent_at gmail_message_id',
  system_config: 'id config_key config_value config_type description is_public updated_by updated_at',
});

function reject(code, location) {
  const error = new Error(code);
  error.code = code;
  error.location = location;
  throw error;
}
function exactRecord(value, fields, location) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('INVALID_IDENTITY_AUXILIARY_ROW', location);
  if (Object.keys(value).sort().join(',') !== fields.slice().sort().join(',')) reject('UNMAPPED_IDENTITY_AUXILIARY_COLUMNS', location);
}
function integer(value, location, { min = 0, max = 2147483647 } = {}) {
  if (value && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).sort().join(',') === 'type,value' && value.type === 'integer'
      && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value) || value < min || value > max) reject('UNSAFE_IDENTITY_AUXILIARY_INTEGER', location);
  return value;
}
function flag(value, location) {
  value = integer(value, location, { max: 1 });
  if (value !== 0 && value !== 1) reject('INVALID_IDENTITY_AUXILIARY_FLAG', location);
  return value;
}
function text(value, location, { nullable = false, empty = false } = {}) {
  if (value === null && nullable) return null;
  if (typeof value !== 'string' || value.includes('\0') || (!empty && value.length === 0)) {
    reject('INVALID_IDENTITY_AUXILIARY_TEXT', location);
  }
  return value;
}
function instant(value, location, naiveTimestamps, nullable = false) {
  if (value === null && nullable) return null;
  value = text(value, location);
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && naiveTimestamps !== 'UTC') reject('AMBIGUOUS_TIMESTAMP', location);
  try { return timestamp(value, nullable); } catch { reject('INVALID_IDENTITY_AUXILIARY_TIMESTAMP', location); }
}
function addUnique(seen, value, code, location) {
  if (seen.has(value)) reject(code, location);
  seen.add(value);
}

/**
 * Maps verified users_auth.db archive rows without reading a database.
 * `auxiliary` may contain credentials and email addresses and must remain private.
 * The report contains identifiers and policies only; it is safe for operator review.
 */
function mapIdentityAuxiliary(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(field => !['tables', 'archiveDigest', 'identityUserIds', 'naiveTimestamps'].includes(field))) {
    reject('INVALID_IDENTITY_AUXILIARY_INPUT', 'input');
  }
  const { tables, archiveDigest, identityUserIds, naiveTimestamps = 'reject' } = raw;
  if (!tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_IDENTITY_AUXILIARY_INPUT', 'tables');
  if (typeof archiveDigest !== 'string' || !/^[a-f0-9]{64}$/.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  if (!['reject', 'UTC'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY', 'naiveTimestamps');
  if (!Array.isArray(identityUserIds)) reject('IDENTITY_USER_IDS_REQUIRED', 'identityUserIds');
  const owners = new Set(identityUserIds.map((value, index) => integer(value, `identityUserIds[${index}]`, { min: 1 })));
  if (owners.size !== identityUserIds.length) reject('DUPLICATE_IDENTITY_USER_ID', 'identityUserIds');
  for (const table of Object.keys(COLUMNS)) if (!Array.isArray(tables[table])) reject('MISSING_IDENTITY_AUXILIARY_TABLE', table);

  const auxiliary = Object.fromEntries(Object.keys(COLUMNS).map(table => [table, []]));
  const report = {
    archiveDigest,
    counts: {},
    transformations: [],
    droppedColumns: [],
    requiresReview: false,
    readyToApply: false,
  };
  const ids = Object.fromEntries(Object.keys(COLUMNS).map(table => [table, new Set()]));

  tables.email_verification_tokens.forEach((source, index) => {
    const at = `email_verification_tokens[${index}]`;
    exactRecord(source, COLUMNS.email_verification_tokens.split(' '), at);
    const id = integer(source.id, `${at}.id`, { min: 1 });
    const userId = integer(source.user_id, `${at}.user_id`, { min: 1 });
    addUnique(ids.email_verification_tokens, id, 'DUPLICATE_IDENTITY_AUXILIARY_ID', `${at}.id`);
    if (!owners.has(userId)) reject('UNRESOLVED_IDENTITY_AUXILIARY_OWNER', `${at}.user_id`);
    const token = text(source.token, `${at}.token`);
    const tokenHash = createHash('sha256').update(token).digest('hex');
    if (auxiliary.email_verification_tokens.some(row => row.token_hash === tokenHash)) reject('DUPLICATE_VERIFICATION_TOKEN', `${at}.token`);
    auxiliary.email_verification_tokens.push({
      id, user_id: userId, token_hash: tokenHash,
      expires_at: instant(source.expires_at, `${at}.expires_at`, naiveTimestamps),
      used: flag(source.used, `${at}.used`) === 1,
      created_at: instant(source.created_at, `${at}.created_at`, naiveTimestamps),
    });
    report.transformations.push({ table: 'email_verification_tokens', sourceId: id, field: 'token', targetField: 'token_hash', policy: 'sha256_utf8', requiresReview: false });
  });

  tables.email_agent_progress.forEach((source, index) => {
    const at = `email_agent_progress[${index}]`;
    exactRecord(source, COLUMNS.email_agent_progress.split(' '), at);
    const id = integer(source.id, `${at}.id`, { min: 1 });
    const userKey = text(source.user_key, `${at}.user_key`);
    const objective = integer(source.objective_number, `${at}.objective_number`, { min: 1, max: 5 });
    addUnique(ids.email_agent_progress, id, 'DUPLICATE_IDENTITY_AUXILIARY_ID', `${at}.id`);
    const key = JSON.stringify([userKey, objective]);
    if (auxiliary.email_agent_progress.some(row => JSON.stringify([row.user_key, row.objective_number]) === key)) {
      reject('DUPLICATE_EMAIL_AGENT_PROGRESS_SCOPE', at);
    }
    auxiliary.email_agent_progress.push({
      legacy_id: id, user_key: userKey, objective_number: objective, completed: flag(source.completed, `${at}.completed`),
      user_email: text(source.user_email, `${at}.user_email`, { nullable: true }),
      completed_at: instant(source.completed_at, `${at}.completed_at`, naiveTimestamps, true),
      created_at: instant(source.created_at, `${at}.created_at`, naiveTimestamps),
      updated_at: instant(source.updated_at, `${at}.updated_at`, naiveTimestamps),
    });
  });

  tables.sent_emails_log.forEach((source, index) => {
    const at = `sent_emails_log[${index}]`;
    exactRecord(source, COLUMNS.sent_emails_log.split(' '), at);
    const id = integer(source.id, `${at}.id`, { min: 1 });
    addUnique(ids.sent_emails_log, id, 'DUPLICATE_IDENTITY_AUXILIARY_ID', `${at}.id`);
    auxiliary.sent_emails_log.push({
      id,
      user_key: text(source.user_key, `${at}.user_key`),
      recipient_email: text(source.recipient_email, `${at}.recipient_email`),
      scenario_type: text(source.scenario_type, `${at}.scenario_type`, { nullable: true, empty: true }),
      email_subject: text(source.email_subject, `${at}.email_subject`, { nullable: true, empty: true }),
      sent_at: instant(source.sent_at, `${at}.sent_at`, naiveTimestamps),
      gmail_message_id: text(source.gmail_message_id, `${at}.gmail_message_id`, { nullable: true, empty: true }),
    });
  });

  const configKeys = new Set();
  tables.system_config.forEach((source, index) => {
    const at = `system_config[${index}]`;
    exactRecord(source, COLUMNS.system_config.split(' '), at);
    const id = integer(source.id, `${at}.id`, { min: 1 });
    const configKey = text(source.config_key, `${at}.config_key`);
    addUnique(ids.system_config, id, 'DUPLICATE_IDENTITY_AUXILIARY_ID', `${at}.id`);
    addUnique(configKeys, configKey, 'DUPLICATE_SYSTEM_CONFIG_KEY', `${at}.config_key`);
    const updatedBy = source.updated_by === null ? null : integer(source.updated_by, `${at}.updated_by`, { min: 1 });
    if (updatedBy !== null && !owners.has(updatedBy)) reject('UNRESOLVED_IDENTITY_AUXILIARY_OWNER', `${at}.updated_by`);
    text(source.description, `${at}.description`, { nullable: true, empty: true });
    instant(source.updated_at, `${at}.updated_at`, naiveTimestamps);
    const configType = text(source.config_type, `${at}.config_type`);
    if (!['string', 'boolean', 'number', 'json'].includes(configType)) reject('INVALID_SYSTEM_CONFIG_TYPE', `${at}.config_type`);
    auxiliary.system_config.push({
      legacy_id: id,
      config_key: configKey,
      config_value: text(source.config_value, `${at}.config_value`, { empty: true }),
      config_type: configType,
      is_public: flag(source.is_public, `${at}.is_public`) === 1,
      description: source.description,
      source_updated_by: updatedBy,
      source_updated_at: instant(source.updated_at, `${at}.updated_at`, naiveTimestamps),
    });
  });

  for (const table of Object.keys(COLUMNS)) report.counts[table] = auxiliary[table].length;
  report.requiresReview = report.transformations.some(row => row.requiresReview) || report.droppedColumns.length > 0;
  report.readyToApply = !report.requiresReview;
  return { auxiliary, report };
}

module.exports = { COLUMNS, mapIdentityAuxiliary };
