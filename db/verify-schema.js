#!/usr/bin/env node
/**
 * db/verify-schema.js — generic DB drift detector for self-healing startup.
 *
 * Checks each expected SQLite database for: file present, non-empty,
 * `PRAGMA integrity_check = ok`, and a minimal set of boot-critical /
 * known-drift tables and columns. The column map is deliberately SMALL — only
 * things whose absence actually breaks boot or a smoke endpoint — so a healthy
 * install is never flagged (which would trigger an unnecessary re-init).
 *
 * Contract (consumed by scripts/lib/preflight.sh → ensure_databases):
 *   - stdout: newline-separated list of the DB *base names* that need healing
 *             (e.g. "secureshop_agents"). Empty stdout = everything healthy.
 *   - stderr: human-readable detail for each problem.
 *   - exit 0  → all healthy
 *   - exit 1  → at least one DB needs healing (names on stdout)
 *   - exit 2  → verifier itself could not run (e.g. better-sqlite3 missing)
 *
 * DB directory follows the same override as run-all.js.
 */

'use strict';

const path = require('path');
const fs = require('fs');

const ROOT = path.resolve(__dirname, '..');
const DB_DIR =
  process.env.DB_OUTPUT_DIR || path.join(ROOT, 'server', 'database');

// name → { table → [requiredColumns] }.  An empty column array means "the
// table must merely exist". Keep this minimal: boot-critical + known-drift.
const EXPECTED = {
  users_auth: {
    users: ['admin_level', 'email_verified'],
    // adminSchema.js seeds INSERTs referencing category; a pre-existing DB
    // without it throws on every boot ("no column named category").
    security_settings: ['category'],
  },
  dvaia: { users: ['admin_level', 'email_verified'] },
  // Platform auth/session/admin DB — required by the secure platform layer.
  platform_secure: { platform_users: [], admin_permissions: [] },
  secureshop: { products: [], reviews: [] },
  // SecureShop v2 agent DB. boot() only writes mcp_tool_cache, but the app
  // needs the rest at request time (agent_sessions per chat turn, mcp_registry
  // for the MCP-registry agent, vector_index_meta for RAG corpora) — so drift
  // in any of these breaks the storefront silently. Verify them all.
  secureshop_agents: {
    mcp_tool_cache: [],
    audit_events: [],
    vector_documents: [],
    agent_sessions: [],
    mcp_registry: [],
    vector_index_meta: [],
  },
};

let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  process.stderr.write(
    `[verify-schema] cannot load better-sqlite3 (${e.message}); ` +
      'skipping schema verification\n'
  );
  process.exit(2);
}

const needsHeal = [];

for (const [name, tables] of Object.entries(EXPECTED)) {
  const file = path.join(DB_DIR, `${name}.db`);
  const problems = [];

  // 1. exists + non-empty
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    problems.push('file missing');
  }
  if (stat && stat.size === 0) problems.push('file is empty (0 bytes)');

  // 2. open + integrity + tables/columns (only if the file looked usable)
  if (problems.length === 0) {
    let db;
    try {
      db = new Database(file, { readonly: true, fileMustExist: true });
      const integrity = db.pragma('integrity_check', { simple: true });
      if (integrity !== 'ok') problems.push(`integrity_check: ${integrity}`);

      for (const [table, cols] of Object.entries(tables)) {
        const info = db.pragma(`table_info(${table})`);
        if (!info || info.length === 0) {
          problems.push(`missing table: ${table}`);
          continue;
        }
        const present = new Set(info.map((c) => c.name));
        for (const col of cols) {
          if (!present.has(col)) {
            problems.push(`table ${table} missing column: ${col}`);
          }
        }
      }
    } catch (e) {
      problems.push(`open failed: ${e.message}`);
    } finally {
      try {
        if (db) db.close();
      } catch {
        /* ignore */
      }
    }
  }

  if (problems.length > 0) {
    needsHeal.push(name);
    process.stderr.write(`[verify-schema] ${name}.db: ${problems.join('; ')}\n`);
  }
}

if (needsHeal.length > 0) {
  process.stdout.write(needsHeal.join('\n') + '\n');
  process.exit(1);
}

process.exit(0);
