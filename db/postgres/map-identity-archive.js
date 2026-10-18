'use strict';

const { validateIdentityImport } = require('../../server/database/postgres/identityImport');
const { timestamp } = require('../../server/database/postgres/identityValidation');

const COLUMNS = Object.freeze({
  users: 'id username email password role admin_level full_name phone department profile_image email_verified is_active account_locked_until login_attempts last_login last_password_change password_reset_required two_factor_enabled two_factor_secret created_at updated_at created_by_ip last_login_ip',
  admin_permissions: 'id admin_id permission_name granted_by granted_at expires_at is_active',
  user_sessions: 'id user_id session_token device_info ip_address location is_active last_activity expires_at created_at revoked_at revoked_by revoke_reason',
  activity_logs: 'id user_id action_type action_details ip_address user_agent session_id risk_level success error_message timestamp',
});
const COLLECTIONS = { users: 'users', admin_permissions: 'permissions', user_sessions: 'sessions', activity_logs: 'audit' };
const NUMBERS = new Set('id admin_id user_id granted_by revoked_by admin_level email_verified is_active login_attempts password_reset_required two_factor_enabled success'.split(' '));
const TIMESTAMPS = new Set('account_locked_until last_login last_password_change created_at updated_at granted_at expires_at last_activity revoked_at timestamp'.split(' '));
const NULLABLE = new Set('full_name phone department profile_image account_locked_until last_login two_factor_secret created_by_ip last_login_ip granted_by expires_at revoked_at revoked_by revoke_reason device_info ip_address location user_agent session_id action_details error_message user_id'.split(' '));

function reject(code, location) {
  const error = new Error(code);
  error.code = code;
  error.location = location;
  throw error;
}
function record(value, location) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('INVALID_IDENTITY_ARCHIVE_INPUT', location);
}
function decode(value, column, location) {
  if (value === null) return null;
  if (NUMBERS.has(column)) {
    if (typeof value === 'object' && value && Object.keys(value).sort().join(',') === 'type,value'
        && value.type === 'integer' && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
    if (!Number.isSafeInteger(value) || value < 0 || value > 2147483647) reject('UNSAFE_IDENTITY_INTEGER', location);
    return value;
  }
  if (typeof value !== 'string' || value.includes('\0')) reject('UNSUPPORTED_IDENTITY_VALUE', location);
  return value;
}

/** Pure mapping. Returned identity contains secrets for the importer: never log or serialize it into reports. */
function mapIdentityArchive(raw) {
  record(raw, 'input');
  if (Object.keys(raw).some(key => !['tables', 'archiveDigest', 'naiveTimestamps'].includes(key))) reject('UNKNOWN_IDENTITY_ARCHIVE_FIELD', 'input');
  const { tables, archiveDigest, naiveTimestamps = 'reject' } = raw;
  record(tables, 'tables');
  if (typeof archiveDigest !== 'string' || !/^[a-f0-9]{64}$/.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  if (!['reject', 'UTC'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY', 'naiveTimestamps');
  const identity = { users: [], permissions: [], sessions: [], audit: [] };
  const report = { archiveDigest, requiresReview: false, normalizations: [], unknownPopulatedTables: [], counts: {} };
  for (const [table, rows] of Object.entries(tables)) {
    if (!Array.isArray(rows)) reject('INVALID_IDENTITY_ARCHIVE_TABLE', table);
    if (!Object.hasOwn(COLUMNS, table) && rows.length) report.unknownPopulatedTables.push({ table, rows: rows.length, disposition: 'outside_identity_scope' });
  }
  for (const [table, columns] of Object.entries(COLUMNS)) {
    if (!Object.hasOwn(tables, table)) reject('MISSING_IDENTITY_ARCHIVE_TABLE', table);
    const expected = columns.split(' ');
    tables[table].forEach((source, index) => {
      const location = `${table}[${index}]`;
      record(source, location);
      if (Object.keys(source).sort().join(' ') !== [...expected].sort().join(' ')) reject('UNMAPPED_IDENTITY_COLUMNS', location);
      const row = {};
      for (const column of expected) {
        const at = `${location}.${column}`;
        let value = decode(source[column], column, at);
        // Some nullable source fields would silently acquire native defaults. Refuse those
        // except JSON metadata, whose explicit normalization is separately reported below.
        const required = !NULLABLE.has(column) || (table === 'user_sessions' && ['user_id', 'expires_at'].includes(column));
        if (value === null && required) reject('NULL_IDENTITY_VALUE_REQUIRES_REVIEW', at);
        if (['role', 'risk_level'].includes(column) && value === '') reject('EMPTY_IDENTITY_VALUE_REQUIRES_REVIEW', at);
        if (TIMESTAMPS.has(column) && value !== null) {
          if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && naiveTimestamps !== 'UTC') reject('AMBIGUOUS_TIMESTAMP', at);
          value = timestamp(value);
        }
        row[column] = value;
      }
      identity[COLLECTIONS[table]].push(row);
    });
    report.counts[table] = tables[table].length;
  }
  // The validator enforces hash/role/permission/FK and duplicate-ID contracts.
  // Its transformed result is used for comparison only, never returned instead of raw tokens.
  const validated = validateIdentityImport(identity);
  function metadata(collection, field) {
    identity[collection].forEach((row, index) => {
      const rawValue = row[field];
      const targetValue = validated[collection][index][field];
      let decoded = rawValue;
      if (typeof rawValue === 'string') decoded = JSON.parse(rawValue); // validator already checked JSON
      const changed = JSON.stringify(decoded) !== JSON.stringify(targetValue);
      if (changed || typeof rawValue === 'string') report.normalizations.push({
        collection, sourceId: row.id, field,
        reason: changed ? 'native_allowlist_or_null_normalization' : 'text_json_to_jsonb',
        requiresReview: true,
      });
    });
  }
  metadata('sessions', 'device_info');
  metadata('audit', 'action_details');
  identity.audit.forEach(row => {
    if (row.error_message !== null) report.normalizations.push({ collection: 'audit', sourceId: row.id, field: 'error_message', reason: 'no_native_column', requiresReview: true });
  });
  report.requiresReview = report.normalizations.length > 0;
  report.transformations = ['session_token is hashed by the native importer; raw token is retained only in the private input DTO', 'timestamps use the explicitly selected timezone policy and retain fractional precision'];
  return { identity, report };
}

module.exports = { COLUMNS, mapIdentityArchive };
