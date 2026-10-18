'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { assertEmbeddingPrivileges } = require('../../server/services/secureshopBoundReviewComposition');
const enabled = process.env.EMBEDDING_READINESS_NATIVE === '1';
test('embedding readiness validates actual function signatures and rejects reversible runtime ACL drift',
  { skip: !enabled, timeout: 60000 }, async () => {
    assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
    const pools = [];
    const open = role => {
      const url = new URL(process.env[`EMBEDDING_FRESH_${role.toUpperCase()}_URL`]);
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/dvaia_test_embedding_fresh_[a-f0-9]+$/);
      assert.equal(url.username, `dvaia_secureshop_review_${role}`);
      const pool = new Pool({ connectionString: url.href, max: 2, statement_timeout: 10000 });
      pools.push(pool); return pool;
    };
    try {
      const migration = open('migration'), runtime = open('runtime');
      await migrate(migration, path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review'));
      await assertEmbeddingPrivileges(runtime);
      const appendArgs = 'uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb';
      const role = 'dvaia_secureshop_review_runtime';
      const drift = [
        `REVOKE SELECT ON secureshop_review.product_target_manual_runtime_receipts FROM ${role}`,
        ...['manual_runtime_receipts', 'embedding_revisions', 'embedding_vectors', 'embedding_heads', 'embedding_cleanup_receipts'].map(table =>
          `GRANT DELETE ON secureshop_review.product_target_${table} TO ${role}`),
        `GRANT UPDATE(revision_id) ON secureshop_review.product_target_embedding_heads TO ${role}`,
        ...[`append_product_manual_retrieval_attested(${appendArgs},bytea)`, 'manual_runtime_receipt_digest(uuid,bytea,bytea)',
          'publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb)',
          'product_embedding_source_digest(uuid,bigint)'].map(fn => `REVOKE EXECUTE ON FUNCTION secureshop_review.${fn} FROM ${role}`),
        `GRANT EXECUTE ON FUNCTION secureshop_review.append_product_manual_retrieval(${appendArgs}) TO ${role}`,
        `GRANT EXECUTE ON FUNCTION secureshop_review.cleanup_retired_product_embeddings(uuid) TO ${role}`,
      ];
      // Grants are committed only within this owned disposable database, then
      // restored in finally. Separate runtime connections see effective grants.
      for (const sql of drift) {
        const undo = sql.startsWith('GRANT') ? sql.replace(/^GRANT /, 'REVOKE ').replace(/ TO /, ' FROM ')
          : sql.replace(/^REVOKE /, 'GRANT ').replace(/ FROM /, ' TO ');
        await migration.query(sql);
        try { await assert.rejects(assertEmbeddingPrivileges(runtime), {
          code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE', message: 'SecureShop embedding runtime privileges are not ready',
        }); } finally { await migration.query(undo); }
        await assertEmbeddingPrivileges(runtime);
      }
    } finally { await Promise.allSettled(pools.map(pool => pool.end())); }
  });
