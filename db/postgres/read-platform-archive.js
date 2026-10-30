'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { readArchiveFile, readVerifiedArchiveFile, createArchiveReadBudget } = require('./read-workshop-archive');
const { COLUMNS, mapPlatformSnapshot } = require('./map-platform-snapshot');

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function taggedValue(cell) {
  if (!cell || typeof cell !== 'object' || Array.isArray(cell)) reject('INVALID_TAGGED_VALUE');
  const keys = Object.keys(cell).sort().join(',');
  if (cell.type === 'null' && keys === 'type') return null;
  if (cell.type === 'text' && keys === 'type,value' && typeof cell.value === 'string') return cell.value;
  if (cell.type === 'integer' && keys === 'type,value' && typeof cell.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(cell.value)) return { type: 'integer', value: cell.value };
  if (cell.type === 'real' && keys === 'type,value' && (typeof cell.value === 'number' && Number.isFinite(cell.value) || ['-0', 'Infinity', '-Infinity'].includes(cell.value))) return { type: 'real', value: cell.value };
  if (cell.type === 'blob' && keys === 'base64,type' && typeof cell.base64 === 'string' && Buffer.from(cell.base64, 'base64').toString('base64') === cell.base64) return { type: 'blob', base64: cell.base64 };
  reject('INVALID_TAGGED_VALUE');
}
function mappedValue(decoded, column) {
  if (decoded === null || typeof decoded === 'string') return decoded;
  if (decoded.type !== 'integer') reject('UNSUPPORTED_MAPPED_VALUE');
  if (column === 'user_id' || column === 'updated_by') return decoded.value;
  const number = Number(decoded.value);
  if (!Number.isSafeInteger(number) || BigInt(number) !== BigInt(decoded.value)) reject('UNSAFE_MAPPED_INTEGER');
  return number;
}

/** Offline only. Unknown rows retain JSON-safe integer/real/blob tags without precision loss. */
async function readVerifiedLegacyArchive({ archive }) {
  const budget = createArchiveReadBudget();
  const root = await fs.realpath(archive);
  const incomplete = await fs.lstat(path.join(root, 'INCOMPLETE')).then(() => true, error => {
    if (error.code === 'ENOENT') return false;
    throw error;
  });
  if (incomplete) reject('INCOMPLETE_ARCHIVE');
  const manifestBytes = await readArchiveFile(root, 'manifest.json', { budget });
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  if (manifest.version !== 1 || manifest.format !== 'owasp-ai-goat-sqlite-archive-v1' || manifest.complete !== true || !Array.isArray(manifest.files)) reject('INVALID_ARCHIVE_MANIFEST');
  if (Object.keys(manifest).some(key => /wal|sidecar|journal/i.test(key))) reject('UNSUPPORTED_SIDECAR_METADATA');
  const sourceNames = new Set(), payloadNames = new Set(), sources = Object.create(null);
  for (const source of manifest.files) {
    if (!source || typeof source.name !== 'string' || !/^[a-z_]+\.db$/.test(source.name) || sourceNames.has(source.name) || !Array.isArray(source.tables)) reject('INVALID_ARCHIVE_SOURCE');
    if (Object.keys(source).some(key => /wal|sidecar|journal/i.test(key))) reject('UNSUPPORTED_SIDECAR_METADATA');
    sourceNames.add(source.name);
    if (!/^[a-f0-9]{64}$/.test(source.sourceSha256 || '')) reject('INVALID_SOURCE_DIGEST');
    if (payloadNames.has(source.schemaFile)) reject('DUPLICATE_ARCHIVE_FILE');
    payloadNames.add(source.schemaFile);
    const schema = JSON.parse(await readVerifiedArchiveFile(root, source.schemaFile, source.schema, budget, 'schema'));
    if (!Array.isArray(schema)) reject('INVALID_ARCHIVE_SCHEMA');
    const tableNames = new Set(), tables = Object.create(null);
    for (const table of source.tables) {
      if (!table || typeof table.name !== 'string' || tableNames.has(table.name) || !Array.isArray(table.columns) || table.columns.some(column => typeof column !== 'string') || new Set(table.columns).size !== table.columns.length || !Number.isSafeInteger(table.rows) || table.rows < 0) reject('INVALID_ARCHIVE_TABLE');
      if (payloadNames.has(table.file)) reject('DUPLICATE_ARCHIVE_FILE');
      payloadNames.add(table.file);
      tableNames.add(table.name);
      const content = await readVerifiedArchiveFile(root, table.file, table, budget, 'table');
      const lines = content ? content.split('\n') : [];
      if (lines.at(-1) === '') lines.pop();
      if (lines.length !== table.rows) reject('ARCHIVE_ROW_COUNT_MISMATCH');
      const decodedRows = lines.map(line => {
        const cells = JSON.parse(line);
        if (!Array.isArray(cells) || cells.length !== table.columns.length) reject('ARCHIVE_COLUMN_COUNT_MISMATCH');
        return Object.fromEntries(table.columns.map((column, index) => [column, taggedValue(cells[index])]));
      });
      tables[table.name] = decodedRows;
    }
    const declared = schema.filter(row => row.type === 'table').map(row => row.name);
    if (declared.length !== tableNames.size || new Set(declared).size !== declared.length || declared.some(name => !tableNames.has(name))) reject('ARCHIVE_SCHEMA_TABLE_MISMATCH');
    sources[source.name] = { tables };
  }
  const archiveDigest = require('node:crypto').createHash('sha256').update(manifestBytes).digest('hex');
  return { sources, archiveDigest };
}

/** Platform projection retains the existing mapping contract over one verified archive read. */
async function readPlatformArchive({ archive, identityMap, naiveTimestamps = 'reject' }) {
  const { sources, archiveDigest } = await readVerifiedLegacyArchive({ archive });
  return projectPlatformArchive({ sources, archiveDigest, identityMap, naiveTimestamps });
}

function projectPlatformArchive({ sources, archiveDigest, identityMap, naiveTimestamps = 'reject' }) {
  if (!sources['users_auth.db']) reject('PLATFORM_SOURCE_MISSING');
  const tables = Object.create(null), unmappedRows = Object.create(null);
  for (const [name, rows] of Object.entries(sources['users_auth.db'].tables)) {
    tables[name] = Object.hasOwn(COLUMNS, name)
      ? rows.map(row => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, mappedValue(value, column)])))
      : rows;
    if (!Object.hasOwn(COLUMNS, name)) unmappedRows[name] = rows;
  }
  const mapped = mapPlatformSnapshot({ tables, identityMap, archiveDigest, naiveTimestamps });
  return { ...mapped, tables, unmappedRows, report: { ...mapped.report, archiveDigest, retainedOtherSources: Object.keys(sources).filter(name => name !== 'users_auth.db'), integrityBoundary: 'Hashes verify declared archive bytes, not source quiescence. A quiesced source remains an exporter precondition.', unmappedEncoding: 'Text/null are decoded; integer/real/blob retain JSON-safe tags for exact values.' } };
}
module.exports = { readPlatformArchive, readVerifiedLegacyArchive, projectPlatformArchive };
