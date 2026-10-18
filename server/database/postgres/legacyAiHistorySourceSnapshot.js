'use strict';

const EXPECTED_ROLE = 'dvaia_legacy_challenge_migration';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ROWS = 100000;
const MAX_PAYLOAD_BYTES = 256 * 1024 * 1024;
const ROW_OVERHEAD_BYTES = 64;
const INT4_MIN = -2147483648;
const INT4_MAX = 2147483647;

// This explicit inventory makes a new legacy migration a deliberate review
// boundary. The source adapter must be updated and requalified rather than
// silently accepting a later or altered ledger.
const EXPECTED_MIGRATIONS = Object.freeze([
  Object.freeze({ name: '0001_schema.sql',
    checksum: 'aea1b348cddc3e4186a87c1d23b1f0a6f580f5d2a7eb9ee8241b752c158e8d7e' }),
  Object.freeze({ name: '0002_import_provenance.sql',
    checksum: '19c4dc364672dd55d77c7896e04bb8710d4840daec8af7105396ec673e8410ba' }),
  Object.freeze({ name: '0003_student_deletion.sql',
    checksum: '4c37577e55c487ced16e902359661d02ce09983af30b168b3c127f4734994d41' }),
  Object.freeze({ name: '0004_private_history_source_cleanup.sql',
    checksum: '4da9a73dfb803029dca29091490d8314099160212a34ba7d69633228ef7ccf9d' }),
  Object.freeze({ name: '0005_private_history_boundary.sql',
    checksum: 'ac340e59fc5004754fe820cd0d22b24d88f94708dad28ec9b7a35a11b1b94ece' }),
]);

const TIMESTAMP_SQL = `CASE
  WHEN created_at IS NULL THEN NULL
  WHEN created_at='infinity'::timestamptz THEN 'infinity'
  WHEN created_at='-infinity'::timestamptz THEN '-infinity'
  WHEN extract(year FROM created_at AT TIME ZONE 'UTC')>0
    THEN to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ELSE to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US BC')
END`;

function unavailable(message) {
  return Object.assign(new Error(message || 'Legacy AI source snapshot is unavailable'), {
    code: 'LEGACY_AI_SOURCE_SNAPSHOT_UNAVAILABLE',
  });
}

function exactKeys(value, keys, label) {
  const actual = value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort() : [];
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`Exact ${label} fields required`);
  }
}

function boundedText(value, label, maximum) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value, 'utf8') > maximum
      || /[\0\r\n]/.test(value)) throw new TypeError(`Valid ${label} required`);
  return value;
}

function int4(value, label, nullable = false) {
  if (nullable && value === null) return null;
  const number = typeof value === 'string' && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isInteger(number) || number < INT4_MIN || number > INT4_MAX) {
    throw unavailable(`Invalid ${label} in legacy source snapshot`);
  }
  return number;
}

function nullableText(value, label) {
  if (value !== null && typeof value !== 'string') {
    throw unavailable(`Invalid ${label} in legacy source snapshot`);
  }
  return value;
}

function freezeRow(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    throw unavailable('Invalid legacy source row');
  }
  return Object.freeze({
    id: int4(row.id, 'conversation ID'),
    userId: int4(row.user_id, 'local user ID', true),
    prompt: typeof row.prompt === 'string' ? row.prompt : (() => {
      throw unavailable('Invalid prompt in legacy source snapshot');
    })(),
    response: nullableText(row.response, 'response'),
    modelUsed: nullableText(row.model_used, 'model'),
    createdAt: nullableText(row.created_at, 'timestamp'),
    // This is archived source data only. It is never interpreted as an owner
    // attestation by this capability.
    platformOwnerId: int4(row.platform_owner_id, 'mutable platform owner column', true),
  });
}

function payloadBytes(row) {
  let bytes = ROW_OVERHEAD_BYTES + Buffer.byteLength(String(row.id));
  for (const value of [row.userId, row.prompt, row.response, row.modelUsed,
    row.createdAt, row.platformOwnerId]) {
    if (value !== null) bytes += Buffer.byteLength(String(value), 'utf8');
  }
  return bytes;
}

function validIdentity(row, database) {
  return row?.database === database && row.role === EXPECTED_ROLE
    && row.session_role === EXPECTED_ROLE && row.rolsuper === false
    && row.rolcreaterole === false && row.rolcreatedb === false
    && row.rolreplication === false && row.rolbypassrls === false
    && row.runtime_member === false;
}

function validLedger(rows) {
  return Array.isArray(rows) && rows.length === EXPECTED_MIGRATIONS.length
    && rows.every((row, index) => row?.name === EXPECTED_MIGRATIONS[index].name
      && row.checksum === EXPECTED_MIGRATIONS[index].checksum);
}

function boundedCount(value, label, maximum) {
  if (typeof value !== 'string' && typeof value !== 'number') {
    throw unavailable(`Invalid ${label}`);
  }
  let number;
  try { number = BigInt(value); } catch { throw unavailable(`Invalid ${label}`); }
  if (number < 0n || number > BigInt(maximum)) {
    throw unavailable(`Legacy AI source snapshot exceeds ${label}`);
  }
  return Number(number);
}

function createLegacyAiHistorySourceSnapshot(pool, options) {
  exactKeys(options, ['batchId', 'database', 'sourceStoreIdentity'], 'source snapshot option');
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('Injected migration pool required');
  // Read caller-owned accessors once. Later mutation cannot redirect the
  // database identity, batch, or source-store binding used by this capability.
  const supplied = Object.freeze({ batchId: options.batchId, database: options.database,
    sourceStoreIdentity: options.sourceStoreIdentity });
  const database = boundedText(supplied.database, 'source database', 63);
  const sourceStoreIdentity = boundedText(supplied.sourceStoreIdentity, 'source store identity', 512);
  if (typeof supplied.batchId !== 'string' || !UUID_V4.test(supplied.batchId)) {
    throw new TypeError('Operator-issued version-4 batch ID required');
  }
  const batchId = supplied.batchId.toLowerCase();

  return Object.freeze({
    async readSnapshot() {
      const client = await pool.connect();
      let begun = false;
      let discard;
      try {
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        begun = true;
        const identity = (await client.query(`SELECT current_database() AS database,
          current_user AS role,session_user AS session_role,current_role AS current_role,
          runtime.rolsuper,runtime.rolcreaterole,runtime.rolcreatedb,runtime.rolreplication,
          runtime.rolbypassrls,
          pg_has_role(current_user,'dvaia_legacy_challenge_runtime','MEMBER') AS runtime_member
          FROM pg_roles runtime WHERE runtime.rolname=current_user`)).rows?.[0];
        if (!validIdentity(identity, database) || identity.current_role !== EXPECTED_ROLE) {
          throw unavailable('Legacy AI source migration authority is not ready');
        }

        const ledger = (await client.query(
          'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
        if (!validLedger(ledger)) throw unavailable('Legacy AI source migration ledger differs');

        const measured = (await client.query(`SELECT count(*)::text AS row_count,
          COALESCE(sum(${ROW_OVERHEAD_BYTES}+octet_length(id::text)
            +COALESCE(octet_length(user_id::text),0)+octet_length(prompt)
            +COALESCE(octet_length(response),0)+COALESCE(octet_length(model_used),0)
            +COALESCE(octet_length((${TIMESTAMP_SQL})),0)
            +COALESCE(octet_length(platform_owner_id::text),0)),0)::text AS payload_bytes
          FROM legacy_challenge.ai_conversations`)).rows?.[0];
        const rowCount = boundedCount(measured?.row_count, 'row count', MAX_ROWS);
        const measuredBytes = boundedCount(measured?.payload_bytes, 'payload byte limit', MAX_PAYLOAD_BYTES);

        const databaseRows = (await client.query(`SELECT id,user_id,prompt,response,model_used,
          ${TIMESTAMP_SQL} AS created_at,platform_owner_id
          FROM legacy_challenge.ai_conversations ORDER BY id`)).rows;
        if (!Array.isArray(databaseRows) || databaseRows.length !== rowCount) {
          throw unavailable('Legacy AI source snapshot row count changed');
        }
        const rows = databaseRows.map(freezeRow);
        if (new Set(rows.map(row => row.id)).size !== rows.length) {
          throw unavailable('Duplicate legacy AI source row ID');
        }
        const observedBytes = rows.reduce((total, row) => total + payloadBytes(row), 0);
        if (observedBytes !== measuredBytes || observedBytes > MAX_PAYLOAD_BYTES) {
          throw unavailable('Legacy AI source snapshot byte measurement differs');
        }
        await client.query('COMMIT');
        begun = false;
        return Object.freeze({ batchId, sourceStoreIdentity, rows: Object.freeze(rows) });
      } catch (error) {
        if (begun) {
          try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = rollbackError; }
        }
        throw error;
      } finally {
        client.release(discard);
      }
    },
  });
}

module.exports = {
  EXPECTED_MIGRATIONS,
  EXPECTED_ROLE,
  MAX_PAYLOAD_BYTES,
  MAX_ROWS,
  createLegacyAiHistorySourceSnapshot,
};
