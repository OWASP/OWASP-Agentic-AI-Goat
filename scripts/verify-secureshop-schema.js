#!/usr/bin/env node
'use strict';
const path = require('node:path');
const EXPECTED = {
  secureshop: {
    shop_users:       ['avatar_path','session_token','api_key','pii_json','banned_at'],
    products:         ['template_source','description_html'],
    chat_messages:    ['agent_trace_id'],
    product_images:   [],
    product_manuals:  [],
    reviews:          [],
    coupons:          [],
    support_tickets:  [],
    email_threads:    [],
    emails:           [],
    policies:         [],
  },
  secureshop_agents: {
    agent_sessions:        [],
    agent_trace:           [],
    mcp_registry:          [],
    mcp_tool_cache:        [],
    audit_events:          [],
    vector_documents:      ['corpus','generation','source_kind','source_id','chunk_index','text','embedding'],
    vector_corpora:        ['dimension','active_generation','revision','document_count','embedder_model','embedding_identity'],
    background_jobs:       [],
    agent_provider_state:  [],
    mcp_schema_history:    [],
  },
};

async function verifySchema(pool, schema, expected = EXPECTED[schema]) {
  if (!expected || !Object.hasOwn(EXPECTED, schema)) throw new TypeError('Known SecureShop schema required');
  const { rows } = await pool.query(`SELECT c.table_name,c.column_name
    FROM information_schema.columns c
    JOIN information_schema.tables t ON t.table_schema=c.table_schema AND t.table_name=c.table_name
    WHERE c.table_schema=$1 AND c.table_name=ANY($2::text[]) AND t.table_type='BASE TABLE'`,
  [schema, Object.keys(expected)]);
  const actual = new Map();
  for (const row of rows) {
    if (!actual.has(row.table_name)) actual.set(row.table_name, new Set());
    actual.get(row.table_name).add(row.column_name);
  }
  const errors = [];
  for (const [table, columns] of Object.entries(expected)) {
    if (!actual.has(table)) { errors.push(`${schema}: missing table ${table}`); continue; }
    for (const column of columns) if (!actual.get(table).has(column)) errors.push(`${schema}.${table}: missing column ${column}`);
  }
  return errors;
}
async function main() {
  require('dotenv').config({ path: path.resolve(__dirname, '../.env'), quiet: true });
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres' || process.env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw Object.assign(new Error('PostgreSQL configuration required'), { code: 'ERR_POSTGRES_REQUIRED' });
  }
  const { createPool, verifyServer } = require('../server/database/postgres');
  const stores = [['secureshop', 'SECURESHOP_DATABASE_URL'], ['secureshop_agents', 'SECURESHOP_AGENTS_DATABASE_URL']];
  const errors = [];
  for (const [schema, key] of stores) {
    const pool = createPool(process.env, key);
    try { await verifyServer(pool); errors.push(...await verifySchema(pool, schema)); }
    finally { await pool.end(); }
  }
  if (errors.length) {
    errors.forEach(error => console.error(error));
    process.exitCode = 1;
  } else console.log('SecureShop PostgreSQL schema verification passed.');
  return errors;
}
if (require.main === module) main().catch(error => {
  console.error(`SecureShop schema verification failed (${error.code || 'configuration_or_database_error'}). Check PostgreSQL configuration and migrations.`);
  process.exitCode = 1;
});
module.exports = { EXPECTED, verifySchema, main };
