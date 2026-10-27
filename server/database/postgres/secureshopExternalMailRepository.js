'use strict';
const { withTransaction } = require('./index');
const C = require('../../services/secureshopExternalMailContract');
const TABLE = 'secureshop_auth.external_mail_operations';
function createExternalMailRepository({ pool }) {
  if (typeof pool?.connect !== 'function' || typeof pool?.query !== 'function') throw TypeError('External mail identity store required');
  async function bounded(client) {
    await client.query("SET LOCAL statement_timeout='3000ms'");
    await client.query("SET LOCAL lock_timeout='3000ms'");
  }
  async function row(client, id, lock = false) {
    return (await client.query(`SELECT * FROM ${TABLE} WHERE operation_id=$1 ${lock ? 'FOR UPDATE' : ''}`, [id])).rows[0] || null;
  }
  function own(value, authority) {
    if (value && (value.principal_id !== authority.principalId
      || Number(value.auth_session_id) !== authority.authSessionId
      || value.scope_key !== authority.scopeKey)) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
    return value;
  }
  return Object.freeze({
    async assertReady() {
      const r = await pool.query(`SELECT
        COALESCE(has_table_privilege(current_user,to_regclass('${TABLE}'),'SELECT'),false)
        AND COALESCE(has_table_privilege(current_user,to_regclass('${TABLE}'),'INSERT'),false)
        AND NOT COALESCE(has_table_privilege(current_user,to_regclass('${TABLE}'),'DELETE,TRUNCATE'),true)
        AND COALESCE(has_column_privilege(current_user,to_regclass('${TABLE}'),'state','UPDATE'),false)
        AND COALESCE(has_column_privilege(current_user,to_regclass('${TABLE}'),'claimed_at','UPDATE'),false)
        AND COALESCE(has_column_privilege(current_user,to_regclass('${TABLE}'),'settled_at','UPDATE'),false)
        AND COALESCE(has_column_privilege(current_user,to_regclass('${TABLE}'),'smtp','UPDATE'),false)
        AND NOT COALESCE(has_column_privilege(current_user,to_regclass('${TABLE}'),'preview','UPDATE'),true)
        AND COALESCE(has_function_privilege(current_user,
          to_regprocedure('secureshop_auth.lock_external_mail_mode(integer,uuid,uuid)'),'EXECUTE'),false)
        AND NOT has_table_privilege(current_user,'secureshop_auth.tenant_modes','UPDATE') AS ready`);
      if (r.rows[0]?.ready !== true) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
    },
    async read(authority, id) {
      // Read-only recovery survives an authenticated owner's session/reset.
      // Mutation methods below still require the original exact authority.
      return withTransaction(pool, async client => {
        await bounded(client);
        // Serialize with claim/cancel before observing expiry. An unlocked
        // prepared snapshot may belong to a claim that is still committing.
        const value = await row(client,id,true);
        if (value && value.principal_id !== authority.principalId) throw C.error('EXTERNAL_MAIL_NOT_FOUND');
        if (!value) return null;
        const now = (await client.query('SELECT clock_timestamp() AS now')).rows[0]?.now;
        const clock = new Date(now).getTime(), expiry = new Date(value.expires_at).getTime();
        if (!Number.isFinite(clock) || !Number.isFinite(expiry)) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
        // Projection metadata only: never change persisted state or quota.
        return {...value,derivedExpired:value.state==='prepared' && expiry<=clock};
      });
    },
    async prepare(authority, preview, requestSha256) {
      return withTransaction(pool, async client => {
        await bounded(client);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`external-mail-owner:${authority.principalId}`]);
        const prior = own(await row(client, preview.operationId), authority);
        if (prior) {
          if (prior.request_sha256 !== requestSha256) throw C.error('EXTERNAL_MAIL_CONFLICT');
          return prior;
        }
        const limits = (await client.query(`SELECT
          count(*) FILTER(WHERE created_at>clock_timestamp()-interval '1 hour')::integer AS preparations,
          count(*) FILTER(WHERE state IN ('dispatching','unknown'))::integer AS unresolved
          FROM ${TABLE} WHERE principal_id=$1`, [authority.principalId])).rows[0];
        if (Number(limits.unresolved)) throw C.error('EXTERNAL_MAIL_RECOVERY_REQUIRED');
        if (Number(limits.preparations) >= 20) throw C.error('EXTERNAL_MAIL_RATE_LIMIT');
        return (await client.query(`INSERT INTO ${TABLE}
          (operation_id,principal_id,auth_session_id,scope_key,binding,request_sha256,preview,sender_key,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,statement_timestamp(),statement_timestamp()+interval '10 minutes') RETURNING *`,
        [preview.operationId,authority.principalId,authority.authSessionId,authority.scopeKey,
          authority.binding,requestSha256,preview,C.hash(['external-mail-sender-v1',preview.sender])])).rows[0];
      });
    },
    async claim(authority, input) {
      return withTransaction(pool, async client => {
        await bounded(client);
        // All claims use sender then principal; no lifecycle locks are held here.
        const current = own(await row(client, input.operationId), authority);
        if (!current || current.request_sha256 !== input.requestSha256) throw C.error('EXTERNAL_MAIL_CONFLICT');
        for (const key of [`external-mail-sender:${current.sender_key}`,`external-mail-owner:${authority.principalId}`])
          await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [key]);
        const locked = own(await row(client, input.operationId, true), authority);
        if (locked.state !== 'prepared') return { claimed: false, row: locked };
        const quota = (await client.query(`SELECT
          count(*) FILTER(WHERE principal_id=$1 AND claimed_at>clock_timestamp()-interval '1 hour')::integer AS owner_count,
          count(*) FILTER(WHERE sender_key=$2 AND claimed_at>clock_timestamp()-interval '1 hour')::integer AS sender_count,
          count(*) FILTER(WHERE principal_id=$1 AND state IN ('dispatching','unknown'))::integer AS unresolved,
          clock_timestamp() AS now FROM ${TABLE} WHERE principal_id=$1 OR sender_key=$2`,
        [authority.principalId,locked.sender_key])).rows[0];
        if (Number(quota.unresolved)) throw C.error('EXTERNAL_MAIL_RECOVERY_REQUIRED');
        if (new Date(locked.expires_at) <= new Date(quota.now)) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
        if (Number(quota.owner_count) >= C.OWNER_LIMIT || Number(quota.sender_count) >= C.SENDER_LIMIT)
          throw C.error('EXTERNAL_MAIL_RATE_LIMIT');
        return { claimed: true, row: (await client.query(`UPDATE ${TABLE}
          SET state='dispatching',claimed_at=clock_timestamp() WHERE operation_id=$1 RETURNING *`, [input.operationId])).rows[0] };
      });
    },
    async cancel(authority, input) {
      return withTransaction(pool, async client => {
        await bounded(client);
        const value = own(await row(client, input.operationId, true), authority);
        if (!value || value.request_sha256 !== input.requestSha256) throw C.error('EXTERNAL_MAIL_CONFLICT');
        if (value.state === 'cancelled') return value;
        if (value.state !== 'prepared') throw C.error('EXTERNAL_MAIL_RECOVERY_REQUIRED');
        return (await client.query(`UPDATE ${TABLE} SET state='cancelled',settled_at=clock_timestamp()
          WHERE operation_id=$1 RETURNING *`, [input.operationId])).rows[0];
      });
    },
    async settle(id, state, smtp = null) {
      if (!['smtp_accepted','unknown','rejected_before_dispatch'].includes(state)) throw C.error('INVALID_ARGUMENT');
      return withTransaction(pool, async client => {
        await bounded(client);
        const value = (await client.query(`UPDATE ${TABLE} SET state=$2,smtp=$3,settled_at=clock_timestamp()
          WHERE operation_id=$1 AND state='dispatching' RETURNING *`, [id,state,smtp])).rows[0];
        if (!value) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
        return value;
      });
    },
  });
}
module.exports = { createExternalMailRepository };
