'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { withTransaction } = require('./index');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function failure(code) { return Object.assign(new Error(code), { code }); }
function owner(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new TypeError('Valid owner required');
  return value;
}
function operation(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Valid reset operation required');
  return value.toLowerCase();
}
function digest(value) { return createHash('sha256').update(value).digest(); }

function createSecureShopOwnerResetRepository(pool) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function') throw new TypeError('PostgreSQL pool required');
  async function list(client, operationId, ownerId) {
    const rows = (await client.query(`SELECT m.operation_id,m.launch_id,m.reset_id,
        m.platform_session_id,m.from_generation,m.to_generation,m.reactivate,
        r.status AS reset_status,l.status AS launch_status,l.original_platform_owner_id
      FROM identity.secureshop_owner_reset_launches m
      JOIN identity.secureshop_launch_resets r
        ON r.reset_id=m.reset_id AND r.launch_id=m.launch_id
      JOIN identity.secureshop_launches l ON l.launch_id=m.launch_id
      WHERE m.operation_id=$1 ORDER BY m.launch_id`, [operationId])).rows;
    if (rows.length > 256 || rows.some(row => Number(row.original_platform_owner_id) !== ownerId)) {
      throw failure('SECURESHOP_OWNER_RESET_SCOPE_MISMATCH');
    }
    return rows.map(row => Object.freeze({ operationId: row.operation_id, launchId: row.launch_id,
      resetId: row.reset_id, platformSessionId: Number(row.platform_session_id),
      fromGeneration: Number(row.from_generation), toGeneration: Number(row.to_generation),
      reactivate: row.reactivate === true, resetStatus: row.reset_status, launchStatus: row.launch_status }));
  }
  return Object.freeze({
    async assertReady() {
      const row = (await pool.query(`SELECT to_regclass('identity.secureshop_owner_resets') IS NOT NULL AS operations,
        to_regclass('identity.secureshop_owner_reset_launches') IS NOT NULL AS launches,
        EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity.secureshop_launch_resets'::regclass
          AND conname='secureshop_launch_reset_identity_pair') AS reset_identity,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity.secureshop_owner_resets'::regclass
          AND tgname='secureshop_owner_reset_journal_guard' AND NOT tgisinternal) AS journal_guard,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity.secureshop_owner_reset_launches'::regclass
          AND tgname='secureshop_owner_reset_mapping_guard' AND NOT tgisinternal) AS mapping_guard,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity.secureshop_launches'::regclass
          AND tgname='secureshop_owner_reset_admission_guard' AND NOT tgisinternal) AS admission_guard`)).rows[0];
      if (!row || Object.values(row).some(value => value !== true)) throw failure('RESET_STORAGE_NOT_READY');
      return true;
    },
    async begin({ ownerId, operationId } = {}) {
      const explicit=operationId!==undefined;
      owner(ownerId); operationId = operation(operationId ?? randomUUID());
      return withTransaction(pool, async client => {
        const account = (await client.query(`SELECT id,is_active,account_locked_until
          FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE`, [ownerId])).rows[0];
        if (!account || account.is_active !== 1) throw failure('OWNER_UNAVAILABLE');
        const exact=(await client.query('SELECT owner_id,status FROM identity.secureshop_owner_resets WHERE operation_id=$1 FOR UPDATE',[operationId])).rows[0];
        if(exact&&Number(exact.owner_id)!==ownerId)throw failure('SECURESHOP_OWNER_RESET_SCOPE_MISMATCH');
        if(exact?.status==='completed')return Object.freeze({operationId,status:'completed',launches:Object.freeze(await list(client,operationId,ownerId)),replayed:true});
        const prior = (await client.query(`SELECT operation_id FROM identity.secureshop_owner_resets
          WHERE owner_id=$1 AND status='pending' FOR UPDATE`, [ownerId])).rows[0];
        if(prior&&explicit&&prior.operation_id!==operationId)throw failure('SECURESHOP_OWNER_RESET_OPERATION_CONFLICT');
        const sessions = (await client.query(`SELECT id,is_active,expires_at FROM identity.secureshop_authority_sessions
          WHERE user_id=$1 ORDER BY id FOR UPDATE`, [ownerId])).rows;
        const sessionById = new Map(sessions.map(row => [Number(row.id), row]));
        const launches = (await client.query(`SELECT * FROM identity.secureshop_launches
          WHERE original_platform_owner_id=$1 AND (NOT identity.secureshop_launch_is_retired(launch_id)
            OR EXISTS(SELECT 1 FROM identity.secureshop_owner_reset_launches mapped
              WHERE mapped.operation_id=$2 AND mapped.launch_id=identity.secureshop_launches.launch_id))
          ORDER BY launch_id FOR UPDATE`, [ownerId,prior?.operation_id ?? null])).rows;
        if (launches.length > 256) throw failure('SECURESHOP_OWNER_RESET_CAPACITY');
        const now = (await client.query('SELECT clock_timestamp() AS now')).rows[0].now;
        if (prior) {
          const mappings = await list(client, prior.operation_id, ownerId);
          const launchById = new Map(launches.map(row => [row.launch_id, row]));
          for (const item of mappings) {
            if (!item.reactivate) continue;
            const launch = launchById.get(item.launchId);
            const session = sessionById.get(item.platformSessionId);
            const unavailable = !launch || launch.expires_at <= now || session?.is_active !== 1
              || session.expires_at <= now;
            if (!unavailable || launch.status === 'revoked') continue;
            await client.query(`UPDATE identity.secureshop_launches SET status='revoked',
              revoked_at=COALESCE(revoked_at,clock_timestamp()),
              revoke_reason=COALESCE(revoke_reason,'owner_reset_unavailable'),updated_at=clock_timestamp()
              WHERE launch_id=$1`, [item.launchId]);
            if (item.resetStatus === 'fenced') await client.query(`UPDATE identity.secureshop_launch_resets
              SET status='aborted',aborted_at=clock_timestamp(),abort_reason='owner_reset_cleanup_only',
                updated_at=clock_timestamp() WHERE reset_id=$1 AND status='fenced'`, [item.resetId]);
          }
          return Object.freeze({ operationId: prior.operation_id,
            launches: Object.freeze(await list(client, prior.operation_id, ownerId)), replayed: true });
        }
        await client.query(`INSERT INTO identity.secureshop_owner_resets(operation_id,owner_id)
          VALUES($1,$2)`, [operationId,ownerId]);
        for (const launch of launches) {
          const session = sessionById.get(Number(launch.platform_session_id));
          const canReactivate = ['active','resetting'].includes(launch.status)
            && launch.expires_at > now && session?.is_active === 1 && session.expires_at > now;
          let reset;
          if (launch.status === 'resetting') {
            const rows = (await client.query(`SELECT reset_id,from_generation,to_generation
              FROM identity.secureshop_launch_resets WHERE launch_id=$1
                AND to_generation=$2 AND status='fenced' LIMIT 2`,
            [launch.launch_id,launch.generation])).rows;
            if (rows.length !== 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
            reset = rows[0];
            if (!canReactivate) {
              await client.query(`UPDATE identity.secureshop_launches SET status='revoked',
                revoked_at=COALESCE(revoked_at,clock_timestamp()),
                revoke_reason=COALESCE(revoke_reason,'owner_reset_unavailable'),updated_at=clock_timestamp()
                WHERE launch_id=$1`, [launch.launch_id]);
              await client.query(`UPDATE identity.secureshop_launch_resets SET status='aborted',
                aborted_at=clock_timestamp(),abort_reason='owner_reset_cleanup_only',updated_at=clock_timestamp()
                WHERE reset_id=$1 AND status='fenced'`, [reset.reset_id]);
            }
          } else if (launch.status === 'revoked') {
            const rows = (await client.query(`SELECT reset_id,from_generation,to_generation
              FROM identity.secureshop_launch_resets WHERE launch_id=$1
                AND to_generation=$2 AND status='aborted'
                AND NOT EXISTS(SELECT 1 FROM identity.secureshop_owner_reset_launches mapped
                  WHERE mapped.reset_id=identity.secureshop_launch_resets.reset_id) LIMIT 2`,
            [launch.launch_id,launch.generation])).rows;
            if (rows.length > 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
            reset = rows[0];
          }
          if (!reset) {
            const from = Number(launch.generation), to = from + 1, resetId = randomUUID();
            if (!Number.isSafeInteger(to) || to > Number.MAX_SAFE_INTEGER) throw failure('SECURESHOP_OWNER_RESET_CAPACITY');
            const reactivate = canReactivate && launch.status === 'active';
            const status = reactivate ? 'resetting' : 'revoked';
            const updated = await client.query(`UPDATE identity.secureshop_launches SET generation=$2,status=$3,
              revoked_at=CASE WHEN $3='revoked' THEN COALESCE(revoked_at,clock_timestamp()) ELSE NULL END,
              revoke_reason=CASE WHEN $3='revoked' THEN COALESCE(revoke_reason,'owner_reset_unavailable') ELSE NULL END,
              updated_at=clock_timestamp() WHERE launch_id=$1`, [launch.launch_id,to,status]);
            if (updated.rowCount !== 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
            reset = (await client.query(`INSERT INTO identity.secureshop_launch_resets
              (reset_id,launch_id,from_generation,to_generation,idempotency_hash,status,aborted_at,abort_reason)
              VALUES($1,$2,$3,$4,$5,$6,
                CASE WHEN $6='aborted' THEN clock_timestamp() ELSE NULL END,
                CASE WHEN $6='aborted' THEN 'owner_reset_cleanup_only' ELSE NULL END)
              RETURNING reset_id,from_generation,to_generation`, [resetId,launch.launch_id,from,to,
              digest(`${operationId}:${launch.launch_id}`),reactivate?'fenced':'aborted'])).rows[0];
          }
          await client.query(`INSERT INTO identity.secureshop_owner_reset_launches
            (operation_id,launch_id,reset_id,platform_session_id,from_generation,to_generation,reactivate)
            VALUES($1,$2,$3,$4,$5,$6,$7)`, [operationId,launch.launch_id,reset.reset_id,
            launch.original_platform_session_id,reset.from_generation,reset.to_generation,canReactivate]);
        }
        return Object.freeze({ operationId, launches: Object.freeze(await list(client,operationId,ownerId)), replayed: false });
      });
    },
    async read({ ownerId, operationId } = {}) {
      owner(ownerId); operationId = operation(operationId);
      const state = (await pool.query(`SELECT status FROM identity.secureshop_owner_resets
        WHERE operation_id=$1 AND owner_id=$2`, [operationId,ownerId])).rows[0];
      if (!state) throw failure('SECURESHOP_OWNER_RESET_UNAVAILABLE');
      return Object.freeze({ operationId, status: state.status,
        launches: Object.freeze(await list(pool,operationId,ownerId)) });
    },
    async complete({ ownerId, operationId } = {}) {
      owner(ownerId); operationId = operation(operationId);
      return withTransaction(pool, async client => {
        const state = (await client.query(`SELECT status FROM identity.secureshop_owner_resets
          WHERE operation_id=$1 AND owner_id=$2 FOR UPDATE`, [operationId,ownerId])).rows[0];
        if (!state) throw failure('SECURESHOP_OWNER_RESET_UNAVAILABLE');
        if(state.status==='completed')return Object.freeze({operationId,completed:true,launchCount:(await list(client,operationId,ownerId)).length});
        const rows = await list(client,operationId,ownerId);
        const mapped = new Set(rows.map(row => row.launchId));
        const all = (await client.query(`SELECT launch_id FROM identity.secureshop_launches
          WHERE original_platform_owner_id=$1 AND (NOT identity.secureshop_launch_is_retired(launch_id)
            OR EXISTS(SELECT 1 FROM identity.secureshop_owner_reset_launches mapped
              WHERE mapped.operation_id=$2 AND mapped.launch_id=identity.secureshop_launches.launch_id))
          ORDER BY launch_id FOR UPDATE`, [ownerId,operationId])).rows;
        if (all.length !== mapped.size || all.some(row => !mapped.has(row.launch_id))) {
          throw failure('SECURESHOP_OWNER_RESET_SCOPE_MISMATCH');
        }
        if (rows.some(row => row.reactivate
          ? !((row.resetStatus === 'committed' && row.launchStatus === 'active')
              || (row.resetStatus === 'committed' && row.launchStatus === 'revoked')
              || (row.resetStatus === 'aborted' && row.launchStatus === 'revoked'))
          : row.resetStatus !== 'aborted' || row.launchStatus !== 'revoked')) {
          throw failure('SECURESHOP_OWNER_RESET_INCOMPLETE');
        }
        const debt = await client.query(`SELECT 1 FROM identity.secureshop_launch_resets r
          JOIN identity.secureshop_owner_reset_launches m ON m.reset_id=r.reset_id
          WHERE m.operation_id=$1 AND (r.reconciliation_required OR
            r.conversation_reconciliation_required OR r.progress_reconciliation_required) LIMIT 1`, [operationId]);
        if (debt.rowCount) throw failure('SECURESHOP_OWNER_RESET_INCOMPLETE');
        if (state.status === 'pending') await client.query(`UPDATE identity.secureshop_owner_resets
          SET status='completed',completed_at=clock_timestamp() WHERE operation_id=$1`, [operationId]);
        return Object.freeze({ operationId, completed: true, launchCount: rows.length });
      });
    },
  });
}
module.exports = { createSecureShopOwnerResetRepository };
