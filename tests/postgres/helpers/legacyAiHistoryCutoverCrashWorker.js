'use strict';
// Owned native qualification worker. Never accepts application database names.
const { Pool } = require('pg');
const { createLegacyAiHistoryCutoverCoordinator } = require('../../../server/database/postgres/legacyAiHistoryCutoverCoordinator');
process.once('message', async ({ sourceUrl, targetUrl, request }) => {
  try {
    for (const [value, role] of [[sourceUrl,'dvaia_legacy_challenge_migration'],[targetUrl,'dvaia_identity_migration']]) {
      const parsed = new URL(value);
      if (parsed.hostname !== '127.0.0.1' || !/^\/owasp_ai_goat_test_history_cleanup_[a-f0-9]+$/.test(parsed.pathname)
          || parsed.username !== role || parsed.search || parsed.hash) throw new Error('Disposable database required');
    }
    const source = new Pool({ connectionString: sourceUrl });
    const target = new Pool({ connectionString: targetUrl });
    const pausingSource = { async connect() {
      const client = await source.connect();
      return { async query(sql, values) {
        const result = await client.query(sql, values);
        if (sql === 'COMMIT') {
          process.send({ phase: 'source_committed', pid: process.pid });
          // Parent kills only this explicitly owned child. Target transaction
          // remains open, proving database rollback on real connection loss.
          await new Promise(() => {});
        }
        return result;
      }, release(error) { client.release(error); } };
    } };
    await createLegacyAiHistoryCutoverCoordinator({ sourcePool: pausingSource, targetPool: target,
      sourceDatabase: new URL(sourceUrl).pathname.slice(1), targetDatabase: new URL(targetUrl).pathname.slice(1),
    }).removeQuarantinedSource(request);
  } catch (error) {
    process.send?.({ phase: 'failed', code: error.code || 'WORKER_FAILED' });
    process.exitCode = 1;
    process.disconnect?.();
  }
});
