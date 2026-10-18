'use strict';

// Operator/migration capability only. Not mounted and not configured from app
// environment. Both schemas remain unregistered until cutover qualification.
const { canonicalRow, digest } = require('./legacyAiHistoryDraftImporter');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
function fail(message) { throw Object.assign(new Error(message), { code: 'LEGACY_AI_CUTOVER_UNAVAILABLE' }); }
async function assertIdentity(client, database, role) {
  const row = (await client.query(`SELECT current_database() AS database,current_user AS role,
    session_user AS session_role,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls
    FROM pg_roles WHERE rolname=current_user`)).rows[0];
  if (!row || row.database !== database || row.role !== role || row.session_role !== role
      || ['rolsuper','rolcreaterole','rolcreatedb','rolreplication','rolbypassrls'].some(key => row[key] !== false)) {
    fail('Exact migration database authority required');
  }
}
function createLegacyAiHistoryCutoverCoordinator({ sourcePool, targetPool, sourceDatabase, targetDatabase } = {}) {
  if (typeof sourcePool?.connect !== 'function' || typeof targetPool?.connect !== 'function'
      || ![sourceDatabase,targetDatabase].every(value => typeof value === 'string' && value.length && Buffer.byteLength(value) <= 63)
      || sourceDatabase === targetDatabase) throw new TypeError('Distinct configured migration stores required');
  return Object.freeze({
    async removeQuarantinedSource({ batchId, boundSourceStoreIdentity, aggregateDigest } = {}) {
      if (!UUID.test(batchId || '') || !HASH.test(aggregateDigest || '')
          || typeof boundSourceStoreIdentity !== 'string' || !boundSourceStoreIdentity.length
          || Buffer.byteLength(boundSourceStoreIdentity) > 512) throw new TypeError('Exact quarantine binding required');
      batchId = batchId.toLowerCase();
      let target, source, targetOpen = false, sourceOpen = false, discardTarget, discardSource;
      try {
        target = await targetPool.connect();
        await target.query('BEGIN'); targetOpen = true;
        await target.query("SET LOCAL lock_timeout='10s'");
        await assertIdentity(target, targetDatabase, 'dvaia_identity_migration');
        const batch = (await target.query(`SELECT * FROM legacy_ai_private.import_batches
          WHERE batch_id=$1 FOR UPDATE`, [batchId])).rows[0];
        if (!batch || !['verified','source_removed','blocked'].includes(batch.state)
            || batch.source_store_identity !== boundSourceStoreIdentity || batch.aggregate_digest !== aggregateDigest
            || batch.expected_count !== batch.copied_count || batch.expected_count > 100000) {
          fail('Current verified quarantine required');
        }
        const invalidated = batch.state === 'blocked';
        let serialized;
        if (invalidated) {
          const event = await target.query(`SELECT 1 FROM legacy_ai_private.import_batch_events
            WHERE batch_id=$1 AND event_kind='invalidated_by_deletion' AND event_digest=$2`, [batchId,aggregateDigest]);
          if (!event.rowCount) fail('Deletion invalidation receipt required');
        } else {
        const size = (await target.query(`SELECT count(*)::integer AS count,
          COALESCE(sum(octet_length(source_record::text)),0)::text AS bytes
          FROM legacy_ai_private.import_archive WHERE batch_id=$1`, [batchId])).rows[0];
        if (size.count !== batch.expected_count || BigInt(size.bytes) > 268435456n) fail('Bounded complete quarantine required');
        const archive = (await target.query(`SELECT source_row_id,source_record,source_digest
          FROM legacy_ai_private.import_archive WHERE batch_id=$1 ORDER BY source_row_id FOR SHARE`, [batchId])).rows;
        const records = archive.map(item => {
          const keys = ['createdAt','id','modelUsed','platformOwnerId','prompt','response','userId'];
          if (!item.source_record || typeof item.source_record !== 'object' || Array.isArray(item.source_record)
              || JSON.stringify(Object.keys(item.source_record).sort()) !== JSON.stringify(keys)) fail('Exact archive fields required');
          const record = canonicalRow(item.source_record);
          if (String(record.id) !== String(item.source_row_id) || digest(record) !== item.source_digest) fail('Quarantine bytes differ');
          return record;
        });
        const descriptors = records.map(record => ({ sourceRowId: record.id, sourceDigest: digest(record) }));
        if (records.length !== batch.expected_count || digest(descriptors) !== aggregateDigest) fail('Quarantine aggregate differs');
        serialized = JSON.stringify(records);
        if (Buffer.byteLength(serialized) > 268435456) fail('Quarantine payload exceeds limit');

        }
        source = await sourcePool.connect();
        await source.query('BEGIN'); sourceOpen = true;
        await source.query("SET LOCAL lock_timeout='10s'");
        // jsonb timestamp rendering must be identical across operator sessions.
        await source.query("SET LOCAL TIME ZONE 'UTC'");
        await assertIdentity(source, sourceDatabase, 'dvaia_legacy_challenge_migration');
        let replayed = true;
        if (!invalidated) {
          const removed = (await source.query(`SELECT * FROM legacy_ai_source_cleanup.cleanup_history_source($1,$2,$3,$4)`,
            [batchId, targetDatabase, aggregateDigest, serialized])).rows[0];
          if (!removed || removed.batch_id !== batchId || removed.removed_count !== batch.expected_count
              || typeof removed.replayed !== 'boolean' || !removed.created_at) fail('Exact source receipt required');
          replayed = removed.replayed;
        }
        // Recovery never repeats deletion against a partial archive. It reads
        // the original committed source journal and proves IDs remain absent.
        await source.query('LOCK TABLE legacy_challenge.ai_conversations IN SHARE ROW EXCLUSIVE MODE');
        const receipt = (await source.query(`SELECT to_jsonb(receipt) AS receipt
          FROM legacy_ai_source_cleanup.receipts receipt WHERE batch_id=$1 FOR SHARE`, [batchId])).rows[0]?.receipt;
        if (!receipt || receipt.batch_id !== batchId || receipt.target_identity !== targetDatabase
            || receipt.aggregate_digest !== aggregateDigest || receipt.removed_count !== batch.expected_count
            || !HASH.test(receipt.payload_digest || '') || !receipt.created_at
            || !Array.isArray(receipt.source_ids) || receipt.source_ids.length !== batch.expected_count
            || new Set(receipt.source_ids).size !== receipt.source_ids.length
            || receipt.source_ids.some(id => !Number.isInteger(id) || id < -2147483648 || id > 2147483647)) {
          fail('Durable source cleanup receipt required');
        }
        if ((await source.query('SELECT 1 FROM legacy_challenge.ai_conversations WHERE id=ANY($1::integer[]) LIMIT 1',
          [receipt.source_ids])).rowCount) fail('Removed source IDs reappeared');
        // Keep target archive locked through source COMMIT. If target COMMIT
        // subsequently fails, retry verifies the same archive and replays the
        // durable source receipt; never infer source removal from missing rows.
        await source.query('COMMIT'); sourceOpen = false;
        const receiptDigest = digest({ sourceDatabase, receipt });
        await target.query(`INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest)
          VALUES($1,'source_cleanup_committed',$2) ON CONFLICT DO NOTHING`, [batchId,receiptDigest]);
        const acknowledged = (await target.query(`SELECT event_digest FROM legacy_ai_private.import_batch_events
          WHERE batch_id=$1 AND event_kind='source_cleanup_committed'`, [batchId])).rows;
        if (acknowledged.length !== 1 || acknowledged[0].event_digest !== receiptDigest) fail('Source acknowledgement conflicts');
        if (!invalidated) {
          const updated = await target.query(`UPDATE legacy_ai_private.import_batches
            SET state='source_removed',source_removed_at=COALESCE(source_removed_at,clock_timestamp())
            WHERE batch_id=$1 AND state IN ('verified','source_removed') RETURNING batch_id`, [batchId]);
          if (updated.rowCount !== 1) fail('Quarantine acknowledgement unavailable');
        }
        await target.query('COMMIT'); targetOpen = false;
        return Object.freeze({ batchId, removedCount: receipt.removed_count, replayed, state: invalidated ? 'source_removed_archive_invalidated' : 'source_removed' });
      } catch (error) {
        if (sourceOpen) { try { await source.query('ROLLBACK'); } catch (rollbackError) { discardSource = rollbackError; } }
        if (targetOpen) { try { await target.query('ROLLBACK'); } catch (rollbackError) { discardTarget = rollbackError; } }
        throw error;
      } finally {
        source?.release(discardSource); target?.release(discardTarget);
      }
    },
  });
}
module.exports = { createLegacyAiHistoryCutoverCoordinator };
