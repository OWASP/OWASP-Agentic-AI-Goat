'use strict';

// Owned-test reference snapshots only. Caller supplies the disposable NOVA
// runtime pool and the exact normal-search baseline query (operator operand,
// not the complete JSON attack, where the objective requires that comparison).
// Snapshot at the actual search-tool boundary: chat_history changes as a turn
// is persisted, so a post-response snapshot is not interchangeable with the
// metadata seen by the tool. A before-request snapshot is valid when the
// harness verifies every tool observation is the expected read-only search and
// excludes concurrent writers: graph history persistence follows all tools.
// Counts are never patched or inferred.
// This module imports no production store and invokes no vulnerable query.
const TABLES = Object.freeze(['papers', 'authors', 'reading_lists', 'chat_history']);
const BASELINE_SQL = "SELECT * FROM nova.papers WHERE access_level='public' AND (LOWER(title) LIKE $1 OR LOWER(abstract) LIKE $1 OR LOWER(authors) LIKE $1) ORDER BY citations DESC LIMIT 10";
const SCHEMA_SQL = `SELECT a.attname AS name, format_type(a.atttypid,a.atttypmod) AS data_type,
  EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND a.attnum=ANY(i.indkey)) AS indexed,
  EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisunique AND i.indnkeyatts=1 AND a.attnum=ANY(i.indkey)) AS unique
  FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='nova' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`;
const parse = value => { try { return JSON.parse(value); } catch { return []; } };
const paper = row => ({ ...row, authors: parse(row.authors), topics: parse(row.topics), cited_by: parse(row.cited_by) });
const author = row => ({ ...row, expertise: parse(row.expertise) });
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
async function readNovaNativeReferences({ pool, literalQuery } = {}) {
  if (typeof pool?.connect !== 'function' || typeof literalQuery !== 'string') {
    throw new TypeError('Explicit owned NOVA pool and literalQuery string required');
  }
  const client = await pool.connect();
  let begun = false;
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); begun = true;
    const identity = (await client.query('SELECT current_database() AS database, current_user AS role')).rows[0];
    if (!/^dvaia_test_[a-z0-9_]+$/.test(identity?.database || '') || identity?.role !== 'dvaia_nova_runtime') {
      throw new Error('Owned disposable NOVA runtime session required');
    }
    const papers = (await client.query('SELECT * FROM nova.papers ORDER BY citations DESC')).rows.map(paper);
    const authors = (await client.query('SELECT * FROM nova.authors ORDER BY paper_count DESC')).rows.map(author);
    const novaVersion = (await client.query("SELECT current_setting('server_version') AS version")).rows[0]?.version;
    if (typeof novaVersion !== 'string' || !novaVersion) throw new Error('Native PostgreSQL version required');
    const novaCollections = [];
    for (const table of TABLES) {
      const documents = (await client.query(`SELECT COUNT(*)::integer AS n FROM nova.${table}`)).rows[0]?.n;
      const indexes = (await client.query("SELECT COUNT(*)::integer AS n FROM pg_indexes WHERE schemaname='nova' AND tablename=$1", [table])).rows[0]?.n;
      if (![documents, indexes].every(value => Number.isInteger(value) && value >= 0)) throw new Error('Exact native collection counts required');
      novaCollections.push({ name: table, documents, indexes });
    }
    const novaSchema = [];
    for (const table of ['papers', 'authors']) {
      const columns = (await client.query(SCHEMA_SQL, [table])).rows;
      if (!columns.length || columns.some(column => typeof column.name !== 'string' || typeof column.data_type !== 'string'
          || typeof column.indexed !== 'boolean' || typeof column.unique !== 'boolean')) throw new Error('Exact native schema metadata required');
      novaSchema.push({ type: 'schema_info', collection: table, fields: columns.map(column => ({
        name: column.name, type: column.data_type === 'integer' ? 'Integer' : 'String', indexed: column.indexed, unique: column.unique,
      })) });
    }
    const literalBaseline = (await client.query(BASELINE_SQL, [`%${literalQuery.toLowerCase()}%`])).rows.map(paper);
    await client.query('COMMIT'); begun = false;
    return freeze({ papers, authors, novaVersion, novaCollections, novaSchema, literalBaseline });
  } catch (error) {
    if (begun) { try { await client.query('ROLLBACK'); } catch {} }
    throw error;
  } finally { client.release(); }
}
module.exports = { readNovaNativeReferences };
