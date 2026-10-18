'use strict';
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const SCHEMAS = Object.freeze({ agents: 'secureshop_agents', review: 'secureshop_review' });
const FETCH_ROWS = 4;

// pg pool acquisition itself does not accept AbortSignal. An abandoned waiter
// must release a client if the pool grants it later, without issuing any query.
function acquire(pool, signal, timeoutMs) {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, client) => {
      if (settled) { if (client) client.release(); return; }
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) reject(error); else resolve(client);
    };
    const abort = () => finish(signal.reason || Object.assign(new Error('Audit source cancelled'), { name: 'AbortError' }));
    const timer = setTimeout(() => finish(Object.assign(new Error('Audit source connection unavailable'), {
      code: 'AUDIT_SOURCE_CONNECTION_TIMEOUT',
    })), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    if (!settled) {
      // Promise.resolve also routes synchronous pool adapter errors through
      // the same timer/listener cleanup as asynchronous connection failures.
      Promise.resolve().then(() => pool.connect()).then(client => finish(null, client), error => finish(error));
    }
  });
}

// Streams complete requested-count teaching input without the normal UI page
// limit. Each store has its own repeatable-read snapshot; this is not a claim
// of an atomic transaction across the two independent databases.
function createSecureShopAuditSnapshot({ agentsPool, reviewPool, acquisitionTimeoutMs = 10000 } = {}) {
  if ([agentsPool, reviewPool].some(pool => typeof pool?.connect !== 'function')
      || !Number.isSafeInteger(acquisitionTimeoutMs) || acquisitionTimeoutMs < 1 || acquisitionTimeoutMs > 30000) {
    throw new TypeError('Both audit snapshot pools required');
  }
  return Object.freeze({
    async *rows({ scope, requestedCount, checkCurrent, signal } = {}) {
      const binding = createLaunchScope(scope);
      if (!Number.isSafeInteger(requestedCount) || requestedCount < 1
          || typeof checkCurrent !== 'function') throw new TypeError('Bound audit snapshot request required');
      const values = [binding.launchId, binding.scenarioId, binding.generation,
        binding.platformOwnerId, binding.platformSessionId, requestedCount];
      const opened = [];
      const check = async () => { signal?.throwIfAborted(); await checkCurrent(binding); signal?.throwIfAborted(); };
      const query = async (client, sql, args) => {
        await check();
        const result = await client.query(sql, args);
        await check();
        return result;
      };
      let failure;
      try {
        await check();
        for (const [store, pool] of [['agents', agentsPool], ['review', reviewPool]]) {
          const client = await acquire(pool, signal, acquisitionTimeoutMs);
          const source = { client, store, queue: [], done: false };
          opened.push(source);
          await query(client, 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
          await query(client, "SET LOCAL statement_timeout = '10s'");
          await query(client, "SET LOCAL idle_in_transaction_session_timeout = '30s'");
          await query(client, `DECLARE audit_snapshot NO SCROLL CURSOR FOR
            SELECT event_id::text AS event_id,
              to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,
              actor,action,target,params_json,outcome,source_kind,source_id
            FROM ${SCHEMAS[store]}.bound_audit_events
            WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3
              AND original_platform_owner_id=$4 AND original_platform_session_id=$5
            ORDER BY created_at DESC,event_id DESC LIMIT $6`, values);
        }
        async function head(source) {
          if (!source.queue.length && !source.done) {
            const result = await query(source.client, `FETCH FORWARD ${FETCH_ROWS} FROM audit_snapshot`);
            source.queue = result.rows.map(row => Object.freeze({ ...row,
              id: `${source.store}:${row.event_id}`, store: source.store }));
            source.done = result.rows.length < FETCH_ROWS;
          }
          return source.queue[0];
        }
        for (let count = 0; count < requestedCount; count++) {
          await check();
          const fetched = await Promise.allSettled(opened.map(head));
          const rejected = fetched.find(result => result.status === 'rejected');
          if (rejected) throw rejected.reason;
          const heads = fetched.map(result => result.value);
          const available = heads.map((row, index) => ({ row, index })).filter(item => item.row);
          available.sort((a, b) => b.row.ts.localeCompare(a.row.ts)
            || b.row.store.localeCompare(a.row.store) || b.row.id.localeCompare(a.row.id));
          if (!available.length) break;
          await check();
          const selected = available[0];
          opened[selected.index].queue.shift();
          yield selected.row;
        }
        await check();
      } catch (error) { failure = error; throw error; }
      finally {
        const errors = [];
        for (const { client } of opened) {
          let rollbackError;
          try { await client.query('ROLLBACK'); } catch (error) { rollbackError = error; errors.push(error); }
          try { client.release(rollbackError); } catch (error) { errors.push(error); }
        }
        if (errors.length && !failure) throw new AggregateError(errors, 'Audit snapshot cleanup failed');
      }
    },
  });
}
module.exports = { createSecureShopAuditSnapshot, FETCH_ROWS };
