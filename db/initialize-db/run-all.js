#!/usr/bin/env node
/**
 * Run all DB schemas and seeds. Creates DBs under server/database/ (or DB_OUTPUT_DIR).
 * Usage: node db/initialize-db/run-all.js
 */

const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const ROOT = path.resolve(__dirname, '../..');
const DB_DIR = process.env.DB_OUTPUT_DIR || path.join(ROOT, 'server', 'database');
const SCHEMAS_DIR = path.join(__dirname, 'schemas');
const SEEDS_DIR = path.join(__dirname, 'seeds');

// DB_MAP: main schema (fresh CREATE TABLE) + optional seed
// extra_schemas: additive/idempotent schemas applied after main schema
// extra_seeds: additional seed files applied after main seed
const DB_MAP = [
  { name: 'users_auth', schema: '01_users_auth.sql', seed: '01_users_auth.js' },
  { name: 'owasp-ai-goat', schema: '02_owasp_ai_goat_workshop.sql', seed: '02_owasp_ai_goat_workshop.js' },
  {
    name: 'secureshop',
    schema: '03_secureshop.sql',
    seed: '03_secureshop.js',
    extra_schemas: ['17_secureshop_v2.sql', '19_secureshop_v2_admin.sql', '20_secureshop_v2_account.sql'],
    extra_seeds: [
      '17_secureshop_v2.js',
      '19_secureshop_v2_m5.js',
      '20_secureshop_v2_bulk_data.js',
      '21_secureshop_v2_account_and_images.js',
      '22_secureshop_v2_m14_identities.js',
    ],
  },
  { name: 'ctf', schema: '05_ctf.sql', seed: '05_ctf.js' },
  { name: 'sensitive_info', schema: '06_sensitive_info.sql', seed: '06_sensitive_info.js' },
  { name: 'sensitive_info_workshop', schema: '08_sensitive_info_workshop.sql', seed: '08_sensitive_info_workshop.js' },
  { name: 'platform_secure', schema: '07_platform_secure.sql', seed: '07_platform_secure.js' },
  { name: 'xss_challenge', schema: '09_challenge_xss.sql', seed: '09_challenge_xss.js' },
  { name: 'ctf_ai_challenge', schema: '10_ctf_ai_challenge.sql', seed: '10_ctf_ai_challenge.js' },
  { name: 'excessive_agency', schema: '11_excessive_agency.sql', seed: '11_excessive_agency.js' },
  { name: 'supply_chain_workshop', schema: '12_supply_chain_workshop.sql', seed: '12_supply_chain_workshop.js' },
  { name: 'sql_workshop', schema: '13_sql_workshop.sql', seed: '13_sql_workshop.js' },
  { name: 'nosql_workshop', schema: '14_nosql_workshop.sql', seed: '14_nosql_workshop.js' },
  { name: 'csrf_workshop', schema: '15_csrf_workshop.sql', seed: '15_csrf_workshop.js' },
  { name: 'mcp_workshop', schema: '16_mcp_workshop.sql', seed: '16_mcp_workshop.js' },
  { name: 'xss_email_challenge', schema: '22_xss_email_builder.sql', seed: '22_xss_email_builder.js' },
  {
    name: 'secureshop_agents',
    schema: '18_secureshop_agents.sql',
    seed: '18_secureshop_agents.js',
    extra_schemas: ['19_secureshop_agents_admin.sql', '21_secureshop_v2_rbac.sql'],
    extra_seeds: ['22_secureshop_v2_rbac.js'],
  },
];

function runSqlFile(db, sqlPath) {
  return new Promise((resolve, reject) => {
    const sql = fs.readFileSync(sqlPath, 'utf8');
    db.exec(sql, (err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Run SQL idempotently: swallow "duplicate column name" errors from
 * ALTER TABLE ADD COLUMN so schemas can be re-applied safely.
 */
function runSqlFileIdempotent(db, sqlPath) {
  return new Promise((resolve, reject) => {
    const raw = fs.readFileSync(sqlPath, 'utf8');
    // Naive split on `;` at end of line/file. Sufficient for our simple schemas
    // (no PL/SQL blocks, no BEGIN/END). Comments are kept with their statement
    // and re-run harmlessly.
    const statements = raw
      .split(/;\s*(?:\n|$)/)
      .map((s) => s.trim())
      .filter(Boolean);

    let i = 0;
    const next = () => {
      if (i >= statements.length) return resolve();
      const stmt = statements[i++];
      db.exec(stmt + ';', (err) => {
        if (err && !/duplicate column name/i.test(err.message)) {
          return reject(err);
        }
        next();
      });
    };
    next();
  });
}

function runSchema(dbPath, schemaFile) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(DB_DIR, dbPath);
    const sqlPath = path.join(SCHEMAS_DIR, schemaFile);
    if (!fs.existsSync(sqlPath)) {
      return reject(new Error(`Schema not found: ${sqlPath}`));
    }
    const db = new sqlite3.Database(fullPath, (err) => {
      if (err) return reject(err);
      runSqlFile(db, sqlPath)
        .then(() => db.close(resolve))
        .catch((e) => {
          db.close(() => reject(e));
        });
    });
  });
}

function runSeed(dbPath, seedFile) {
  const seedPath = path.join(SEEDS_DIR, seedFile);
  if (!fs.existsSync(seedPath)) return Promise.resolve();
  const fullDbPath = path.join(DB_DIR, dbPath);
  // require from project root so relative requires in seeds resolve
  const run = require(path.resolve(seedPath));
  if (typeof run.runSeed === 'function') {
    return run.runSeed(fullDbPath);
  }
  if (typeof run === 'function') {
    return run(fullDbPath);
  }
  return Promise.resolve();
}

/**
 * Run all schemas and seeds. Can be called from CLI or from API.
 * @param {object} options - { outputDir?: string } override DB output directory
 * @returns {Promise<{ success: boolean, output: string, error?: string }>}
 */
async function runInitializeDb(options = {}) {
  const outDir = options.outputDir || DB_DIR;
  const lines = [];
  const log = (msg) => {
    lines.push(msg);
    console.log(msg);
  };
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }
  log('DB output directory: ' + outDir);
  for (const entry of DB_MAP) {
    const { name, schema, seed, extra_schemas = [], extra_seeds = [] } = entry;
    const dbPath = `${name}.db`;
    const sqlPath = path.join(SCHEMAS_DIR, schema);
    if (!fs.existsSync(sqlPath)) {
      throw new Error(`Schema not found: ${sqlPath}`);
    }
    try {
      await runSchemaWithDir(dbPath, schema, outDir);
      log(`  schema: ${schema} ok`);

      for (const extraSchema of extra_schemas) {
        await runSchemaIdempotentWithDir(dbPath, extraSchema, outDir);
        log(`  schema+: ${extraSchema} ok`);
      }

      if (seed) {
        await runSeedWithDir(dbPath, seed, outDir);
        log(`  seed: ${seed} ok`);
      }

      for (const extraSeed of extra_seeds) {
        await runSeedWithDir(dbPath, extraSeed, outDir);
        log(`  seed+: ${extraSeed} ok`);
      }
    } catch (e) {
      log(`  error: ${e.message}`);
      throw e;
    }
  }
  log('All databases initialized.');
  return { success: true, output: lines.join('\n') };
}

function runSchemaWithDir(dbPath, schemaFile, outDir) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(outDir, dbPath);
    const sqlPath = path.join(SCHEMAS_DIR, schemaFile);
    const db = new sqlite3.Database(fullPath, (err) => {
      if (err) return reject(err);
      runSqlFile(db, sqlPath)
        .then(() => db.close(resolve))
        .catch((e) => {
          db.close(() => reject(e));
        });
    });
  });
}

function runSchemaIdempotentWithDir(dbPath, schemaFile, outDir) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(outDir, dbPath);
    const sqlPath = path.join(SCHEMAS_DIR, schemaFile);
    if (!fs.existsSync(sqlPath)) {
      return reject(new Error(`Schema not found: ${sqlPath}`));
    }
    const db = new sqlite3.Database(fullPath, (err) => {
      if (err) return reject(err);
      runSqlFileIdempotent(db, sqlPath)
        .then(() => db.close(resolve))
        .catch((e) => {
          db.close(() => reject(e));
        });
    });
  });
}

function runSeedWithDir(dbPath, seedFile, outDir) {
  if (!seedFile) return Promise.resolve();
  const seedPath = path.join(SEEDS_DIR, seedFile);
  if (!fs.existsSync(seedPath)) return Promise.resolve();
  const fullDbPath = path.join(outDir, dbPath);
  const run = require(path.resolve(seedPath));
  if (typeof run.runSeed === 'function') {
    return run.runSeed(fullDbPath);
  }
  if (typeof run === 'function') {
    return run(fullDbPath);
  }
  return Promise.resolve();
}

async function main() {
  try {
    await runInitializeDb();
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { runInitializeDb };
