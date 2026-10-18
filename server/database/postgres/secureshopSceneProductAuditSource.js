'use strict';

const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { executionScope, withSceneLease, assertSceneGrant } = require('../../services/secureshopSceneBinding');

const FETCH_ROWS = 4;
const FIELDS = Object.freeze(['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function unavailable() {
  return Object.assign(new Error('Scene audit source is unavailable'), { code: 'AUDIT_SOURCE_UNAVAILABLE' });
}

function sameScope(left, right) {
  return FIELDS.every(key => left[key] === right[key]);
}

function acquire(pool, signal, timeoutMs) {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, client) => {
      if (settled) { client?.release(); return; }
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) reject(error); else resolve(client);
    };
    const abort = () => finish(signal.reason || Object.assign(new Error('Scene audit source cancelled'), { name: 'AbortError' }));
    const timer = setTimeout(() => finish(Object.assign(new Error('Scene audit source connection unavailable'),
      { code: 'AUDIT_SOURCE_CONNECTION_TIMEOUT' })), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    if (!settled) Promise.resolve().then(() => pool.connect()).then(client => finish(null, client), error => finish(error));
  });
}

function sourceExecution(row) {
  return createLaunchScope({ launchId: row.source_launch_id, scenarioId: row.source_scenario_id,
    generation: Number(row.source_generation), platformOwnerId: Number(row.source_owner_id),
    platformSessionId: Number(row.source_session_id) });
}

function sourceRow(row, sceneBinding, consumer) {
  const scene = sceneBinding.scene;
  const original = sourceExecution(row);
  const birth = createLaunchScope(sceneBinding);
  const productId = Number(row.product_id);
  const merchantId = Number(row.merchant_id);
  let storage;
  try { storage = JSON.parse(row.params_json)?.storage; } catch { throw unavailable(); }
  if (!UUID.test(row.event_id || '') || !UUID.test(row.source_grant_id || '')
      || !Number.isSafeInteger(productId) || productId < 1
      || !Number.isSafeInteger(merchantId) || merchantId < 1
      || original.platformOwnerId !== consumer.platformOwnerId
      || row.target !== String(productId) || row.source_id !== String(productId)
      || row.actor !== 'merchant' || row.action !== 'listing_update' || row.source_kind !== 'product'
      || row.shop_role !== 'merchant' || row.outcome !== 'completed'
      || storage?.targetId !== sceneBinding.targetId || storage?.sceneId !== scene.sceneId
      || storage?.birthLaunchId !== birth.launchId || storage?.birthGeneration !== birth.generation) throw unavailable();
  const provenance = Object.freeze({ version: 2, kind: 'scene_product_listing_update',
    sourceExecution: original,
    sourceGrant: Object.freeze({ grantId: row.source_grant_id, sceneId: scene.sceneId,
      sceneGeneration: scene.sceneGeneration, targetId: sceneBinding.targetId }),
    consumerExecution: consumer,
    consumerGrant: Object.freeze({ grantId: scene.grantId, sceneId: scene.sceneId,
      sceneGeneration: scene.sceneGeneration, targetId: sceneBinding.targetId }),
    scene: Object.freeze({ sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration,
      targetId: sceneBinding.targetId, birth }),
    product: Object.freeze({ productId, merchantId }) });
  return Object.freeze({ id: `review:${row.event_id}`, store: 'review', ts: row.ts,
    actor: row.actor, action: row.action, target: row.target, params_json: row.params_json,
    outcome: row.outcome, source_kind: row.source_kind, source_id: row.source_id,
    sceneSource: provenance });
}

// Every row is from a single repeatable-read snapshot. Both source and consumer
// grants join their independently stored execution coordinates; the JSON field
// is compared only after those durable joins and never creates authority.
const DECLARE = `DECLARE scene_product_audit NO SCROLL CURSOR FOR
  SELECT e.event_id::text AS event_id,
    to_char(e.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,
    e.actor,e.action,e.target,e.params_json,e.outcome,e.source_kind,e.source_id,e.shop_role,
    e.launch_id::text AS source_launch_id,e.scenario_id::text AS source_scenario_id,
    e.generation::text AS source_generation,
    e.original_platform_owner_id AS source_owner_id,
    e.original_platform_session_id AS source_session_id,
    e.shop_user_id AS merchant_id,p.product_id AS product_id,
    original_grant.grant_id::text AS source_grant_id
  FROM secureshop_review.bound_audit_events e
  JOIN secureshop_review.product_targets target
    ON target.target_id=$3::uuid AND target.lifecycle='active'
    AND (target.launch_id,target.scenario_id,target.generation,
      target.original_platform_owner_id,target.original_platform_session_id)
      =($10::uuid,$11::uuid,$12::bigint,$8::integer,$13::integer)
  JOIN secureshop_review.scene_execution_grants consumer_grant
    ON (consumer_grant.grant_id,consumer_grant.scene_id,consumer_grant.scene_generation,
      consumer_grant.target_id,consumer_grant.launch_id,consumer_grant.scenario_id,
      consumer_grant.generation,consumer_grant.original_platform_owner_id,
      consumer_grant.original_platform_session_id)
      =($4::uuid,$1::uuid,$2::bigint,$3::uuid,$5::uuid,$6::uuid,
        $7::bigint,$8::integer,$9::integer)
  JOIN secureshop_review.scene_execution_grants original_grant
    ON (original_grant.scene_id,original_grant.scene_generation,original_grant.target_id,
      original_grant.launch_id,original_grant.scenario_id,original_grant.generation,
      original_grant.original_platform_owner_id,original_grant.original_platform_session_id)
      =($1::uuid,$2::bigint,$3::uuid,e.launch_id,e.scenario_id,e.generation,
        e.original_platform_owner_id,e.original_platform_session_id)
    AND original_grant.created_at<=e.created_at
  JOIN secureshop_review.product_target_products p
    ON p.target_id=target.target_id AND p.product_id::text=e.source_id
    AND p.retailer_id=target.own_merchant_id
  WHERE e.original_platform_owner_id=$8::integer
    AND e.shop_user_id=target.own_merchant_id
    AND e.shop_role='merchant' AND e.actor='merchant'
    AND e.action='listing_update' AND e.outcome='completed'
    AND e.source_kind='product' AND e.target=e.source_id
    AND e.params_json::jsonb#>>'{storage,targetId}'=target.target_id::text
    AND e.params_json::jsonb#>>'{storage,sceneId}'=$1::text
    AND e.params_json::jsonb#>>'{storage,birthLaunchId}'=target.launch_id::text
    AND e.params_json::jsonb#>>'{storage,birthGeneration}'=target.generation::text
  ORDER BY e.created_at DESC,e.event_id DESC LIMIT $14`;

function createSecureShopSceneProductAuditSource({ reviewPool, acquisitionTimeoutMs = 10000 } = {}) {
  if (typeof reviewPool?.connect !== 'function' || !Number.isSafeInteger(acquisitionTimeoutMs)
      || acquisitionTimeoutMs < 1 || acquisitionTimeoutMs > 30000) throw new TypeError('Scene audit source pool required');
  return Object.freeze({
    async *rows({ scope, sceneBinding, requestedCount, checkCurrent, signal } = {}) {
      const consumer = createLaunchScope(scope);
      if (!sceneBinding?.scene || !sameScope(executionScope(sceneBinding), consumer)
          || !Number.isSafeInteger(requestedCount) || requestedCount < 1
          || typeof checkCurrent !== 'function') throw unavailable();
      const scene = sceneBinding.scene;
      const birth = createLaunchScope(sceneBinding);
      const values = [scene.sceneId, scene.sceneGeneration, sceneBinding.targetId, scene.grantId,
        consumer.launchId, consumer.scenarioId, consumer.generation,
        consumer.platformOwnerId, consumer.platformSessionId,
        birth.launchId, birth.scenarioId, birth.generation, birth.platformSessionId, requestedCount];
      const ready = [];
      let wake, release, done = false, failure, pending = false, cancelled = false;
      const notify = () => { if (wake) { const next = wake; wake = null; next(); } };
      const offer = value => new Promise(resolve => {
        if (cancelled) return resolve();
        ready.push(value); pending = true; release = resolve; notify();
      });
      const check = async () => {
        signal?.throwIfAborted(); await checkCurrent(consumer); signal?.throwIfAborted();
      };
      const producer = withSceneLease(sceneBinding, async () => {
        let client, began = false;
        try {
          await check();
          client = await acquire(reviewPool, signal, acquisitionTimeoutMs);
          // Grant validation takes FOR SHARE row locks, which READ ONLY forbids.
          // Keep the repeatable snapshot and always roll it back after reading.
          await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ'); began = true;
          await client.query("SET LOCAL statement_timeout = '10s'");
          await client.query("SET LOCAL idle_in_transaction_session_timeout = '30s'");
          await assertSceneGrant(client, sceneBinding); await check();
          await client.query(DECLARE, values);
          let count = 0;
          while (!cancelled && count < requestedCount) {
            await assertSceneGrant(client, sceneBinding); await check();
            const fetched = await client.query(`FETCH FORWARD ${FETCH_ROWS} FROM scene_product_audit`);
            await assertSceneGrant(client, sceneBinding); await check();
            if (!fetched.rows.length) break;
            for (const raw of fetched.rows) {
              if (cancelled || count >= requestedCount) break;
              count++;
              await offer(sourceRow(raw, sceneBinding, consumer));
            }
          }
          await assertSceneGrant(client, sceneBinding); await check();
        } finally {
          if (client) {
            let rollbackError;
            try { if (began) await client.query('ROLLBACK'); } catch (error) { rollbackError = error; if (!failure) failure = error; }
            client.release(rollbackError);
          }
        }
      }).catch(error => { failure = error; }).finally(() => { done = true; notify(); });
      try {
        while (true) {
          if (!ready.length && !done) await new Promise(resolve => { wake = resolve; });
          if (ready.length) {
            const row = ready.shift();
            pending = false;
            const acknowledge = release; release = null; acknowledge?.();
            yield row;
          } else if (done) break;
        }
        if (failure) throw failure;
      } finally {
        cancelled = true;
        if (pending) { pending = false; release?.(); release = null; }
        await producer;
      }
    },
  });
}

// Existing own-session sources are already sorted. Preserve their unchanged
// query, merge one explicit scene stream and deduplicate matching event IDs.
async function* mergeAuditRows({ ordinary, scene, requestedCount, checkCurrent, signal } = {}) {
  if (!ordinary?.[Symbol.asyncIterator] || !scene?.[Symbol.asyncIterator]
      || !Number.isSafeInteger(requestedCount) || requestedCount < 1
      || typeof checkCurrent !== 'function') throw new TypeError('Audit source streams required');
  const iterators = [ordinary[Symbol.asyncIterator](), scene[Symbol.asyncIterator]()];
  const seen = new Set();
  try {
    const heads = await Promise.all(iterators.map(iterator => iterator.next()));
    for (let count = 0; count < requestedCount;) {
      signal?.throwIfAborted(); await checkCurrent(); signal?.throwIfAborted();
      const available = heads.map((item, index) => ({ item, index })).filter(value => !value.item.done);
      if (!available.length) break;
      available.sort((a, b) => b.item.value.ts.localeCompare(a.item.value.ts)
        || b.item.value.store.localeCompare(a.item.value.store)
        || b.item.value.id.localeCompare(a.item.value.id)
        || b.index - a.index);
      const selected = available[0];
      const row = selected.item.value;
      if (!seen.has(row.id)) { seen.add(row.id); count++; yield row; }
      heads[selected.index] = await iterators[selected.index].next();
    }
  } finally {
    await Promise.allSettled(iterators.map(iterator => iterator.return?.()));
  }
}

module.exports = { createSecureShopSceneProductAuditSource, mergeAuditRows, FETCH_ROWS };
