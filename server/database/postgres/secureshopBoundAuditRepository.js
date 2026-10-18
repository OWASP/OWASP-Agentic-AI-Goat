'use strict';

const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const { decodeAuditCursor, encodeAuditCursor } = require('../../services/secureshopAuditCursor');
const { executionScope, withSceneLease, assertSceneGrant } = require('../../services/secureshopSceneBinding');
const { createHash } = require('node:crypto');
const STORES = Object.freeze({ agents: 'secureshop_agents', review: 'secureshop_review' });
// Existing listing fields can JSON-escape to over 1.6 MB; logging must not
// narrow their teaching-input contract. Normal audit page byte budgets remain
// a separate read-path concern.
const MAX_PARAMS_BYTES = 2 * 1024 * 1024;
const PAGE_BYTES = 16 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function invalid() { throw Object.assign(new Error('Invalid audit request'), { code: 'INVALID_ARGUMENT' }); }
function boundedText(value, maximum, nullable = false) {
  if (nullable && value == null) return null;
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maximum) invalid();
  return value;
}
function scopeValues(input) {
  const scope = createLaunchScope(input);
  return [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId];
}
function day(value, next = false) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) invalid();
  const milliseconds = Date.parse(value + 'T00:00:00.000Z');
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 10) !== value) invalid();
  return new Date(milliseconds + (next ? 86400000 : 0)).toISOString();
}
function auditQuery(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).some(key => !['limit', 'actor', 'action', 'target', 'q', 'from', 'to', 'cursor'].includes(key))) invalid();
  const limit = input.limit ?? 200;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000) invalid();
  const result = { limit };
  if (input.cursor !== undefined) result.cursor = decodeAuditCursor(input.cursor);
  for (const key of ['actor', 'action', 'target', 'q']) {
    if (input[key] !== undefined && input[key] !== '') result[key] = boundedText(input[key], 512);
  }
  if (input.from !== undefined && input.from !== '') result.from = day(input.from);
  if (input.to !== undefined && input.to !== '') result.to = day(input.to, true);
  if (result.from && result.to && result.from >= result.to) invalid();
  return Object.freeze(result);
}
const COLUMNS = ['event_id', 'launch_id', 'scenario_id', 'generation', 'original_platform_owner_id',
  'original_platform_session_id', 'shop_user_id', 'shop_role', 'actor', 'action', 'target',
  'params_json', 'outcome', 'source_kind', 'source_id'];

// Candidate until both store migrations, effect writers and deletion receipts
// qualify. Never call append after committing an effect: use its transaction.
function createBoundAuditStore({ store, pool, checkCurrent }) {
  const schema = STORES[store];
  if (!schema || typeof pool?.query !== 'function') throw new TypeError('Owned audit store required');
  return Object.freeze({
    async append(transaction, input) {
      if (typeof transaction?.query !== 'function' || !input || !UUID.test(input.eventId)) invalid();
      const binding = createConversationBinding(input.scope, input.persona);
      if (!['completed', 'denied', 'failed'].includes(input.outcome)) invalid();
      const params = boundedText(input.paramsJson, MAX_PARAMS_BYTES);
      try { JSON.parse(params); } catch { invalid(); }
      const values = [input.eventId.toLowerCase(), ...scopeValues(binding), binding.shopUserId, binding.role,
        boundedText(input.actor, 128), boundedText(input.action, 128), boundedText(input.target, 1024, true),
        params, input.outcome, boundedText(input.sourceKind, 128), boundedText(input.sourceId, 256)];
      const inserted = await transaction.query(`INSERT INTO ${schema}.bound_audit_events (${COLUMNS.join(',')})
        VALUES (${values.map((_, index) => '$' + (index + 1)).join(',')})
        ON CONFLICT(event_id) DO NOTHING RETURNING event_id`, values);
      if (inserted.rowCount === 1) return Object.freeze({ eventId: values[0], replayed: false });
      // Exact replay is harmless; reusing an event identity with new content is
      // a failed effect transaction, not a silently lost event.
      const same = await transaction.query(`SELECT event_id FROM ${schema}.bound_audit_events
        WHERE (${COLUMNS.join(',')}) IS NOT DISTINCT FROM (${values.map((_, index) => '$' + (index + 1)).join(',')})`, values);
      if (same.rowCount !== 1) throw Object.assign(new Error('Audit event identity conflict'), { code: 'AUDIT_CONFLICT' });
      return Object.freeze({ eventId: values[0], replayed: true });
    },
    // V01: exact, protected checkout-audit source for one verified owned order.
    // The generic recent() filters are substring searches and cannot establish
    // a stable event/order join for an objective receipt.
    async checkoutForOrder(target, shopUserId, checkout, eventId = null) {
      if (store !== 'review' || typeof pool.connect !== 'function'
          || typeof checkCurrent !== 'function' || !target?.scene
          || !Number.isSafeInteger(shopUserId) || shopUserId < 1
          || !checkout || checkout.status !== 'completed'
          || !Number.isSafeInteger(checkout.order?.id) || checkout.order.id < 1
          || (eventId !== null && (typeof eventId !== 'string' || !UUID.test(eventId)))) invalid();
      const scope = createLaunchScope(executionScope(target));
      const orderId = checkout.order.id;
      const money = value => {
        if (!['number', 'string'].includes(typeof value)
            || !/^\d+(?:\.\d{1,2})?$/.test(String(value))) invalid();
        const cents = Math.round(Number(value) * 100);
        if (!Number.isSafeInteger(cents) || cents < 0) invalid();
        return cents;
      };
      await checkCurrent(scope);
      return withSceneLease(target, async () => {
        const client = await pool.connect();
        try {
          // assert_scene_execution_grant takes FOR SHARE locks; PostgreSQL
          // therefore requires a regular transaction even for this read path.
          await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          await assertSceneGrant(client, target);
          const values = [...scopeValues(scope), target.targetId, shopUserId, orderId,
            eventId === null ? null : eventId.toLowerCase(), target.scene.sceneId,
            target.scene.sceneGeneration, ...scopeValues(target)];
          const { rows } = await client.query(`SELECT e.event_id::text AS event_id,
            to_char(e.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,
            e.actor,e.action,e.outcome,e.target,e.source_kind,e.source_id,e.params_json,
            o.total_amount::text AS order_total,o.payment_method,o.shipping_address
            FROM secureshop_review.bound_audit_events e
            JOIN secureshop_review.product_targets t
              ON t.target_id=$6 AND t.lifecycle='active' AND t.launch_id=$12
              AND t.scenario_id=$13 AND t.generation=$14
              AND t.original_platform_owner_id=$15 AND t.original_platform_session_id=$16
            JOIN secureshop_review.product_target_orders o
              ON o.target_id=$6 AND o.shop_user_id=$7 AND o.order_id=$8
            WHERE e.launch_id=$1 AND e.scenario_id=$2 AND e.generation=$3
              AND e.original_platform_owner_id=$4 AND e.original_platform_session_id=$5
              AND e.shop_user_id=$7 AND e.shop_role='customer'
              AND e.actor='customer' AND e.action='checkout' AND e.outcome='completed'
              AND e.source_kind='order' AND e.source_id=$8::text AND e.target=$8::text
              AND e.params_json::jsonb->>'storageTargetId'=$6::text
              AND e.params_json::jsonb->>'sceneId'=$10::text
              AND e.params_json::jsonb->>'sceneGeneration'=$11::text
              AND ($9::uuid IS NULL OR e.event_id=$9::uuid)
            ORDER BY e.created_at DESC,e.event_id DESC LIMIT 2`, values);
          if (rows.length !== 1) invalid();
          const row = rows[0];
          let params;
          try { params = JSON.parse(row.params_json); } catch { invalid(); }
          if ((eventId !== null && row.event_id.toLowerCase() !== eventId.toLowerCase())
              || row.target !== String(orderId) || row.source_id !== String(orderId)
              || row.actor !== 'customer' || row.action !== 'checkout'
              || row.outcome !== 'completed' || row.source_kind !== 'order'
              || params.storageTargetId !== target.targetId
              || params.sceneId !== target.scene.sceneId
              || params.sceneGeneration !== target.scene.sceneGeneration
              || params.shippingAddress !== row.shipping_address
              || params.paymentMethod !== row.payment_method
              || money(params.total) !== money(row.order_total)
              || money(row.order_total) !== money(checkout.order.total)
              || typeof row.ts !== 'string' || !UUID.test(row.event_id)) invalid();
          const source = Object.freeze({ version: 1, scope, targetId: target.targetId,
            sceneId: target.scene.sceneId, sceneGeneration: target.scene.sceneGeneration,
            shopUserId, orderId, eventId: row.event_id.toLowerCase(), ts: row.ts,
            actor: row.actor, action: row.action, outcome: row.outcome,
            paramsJson: row.params_json, orderTotal: row.order_total,
            paymentMethod: row.payment_method });
          const sourceSha256 = createHash('sha256').update(JSON.stringify(source)).digest('hex');
          const observation = Object.freeze({ eventId: source.eventId, timestamp: row.ts,
            actor: row.actor, action: row.action, outcome: row.outcome,
            orderId, total: money(row.order_total) / 100 });
          await checkCurrent(scope);
          await assertSceneGrant(client, target);
          await client.query('COMMIT');
          await checkCurrent(scope);
          return Object.freeze({ eventId: source.eventId, sourceSha256, observation });
        } catch (error) {
          await client.query('ROLLBACK').catch(() => {});
          throw error;
        } finally { client.release(); }
      });
    },
    async recent(scope, rawQuery = {}) {
      const query = auditQuery(rawQuery);
      const values = scopeValues(scope);
      const clauses = ['launch_id=$1', 'scenario_id=$2', 'generation=$3',
        'original_platform_owner_id=$4', 'original_platform_session_id=$5'];
      for (const key of ['actor', 'action', 'target', 'q']) {
        if (!query[key]) continue;
        values.push(query[key]);
        const field = key === 'q' ? "concat_ws(' ',actor,action,target,params_json)" : key;
        // strpos makes % and _ literal search characters, not wildcard scope.
        clauses.push(`strpos(lower(${field}),lower($${values.length}))>0`);
      }
      if (query.from) { values.push(query.from); clauses.push(`created_at >= $${values.length}::timestamptz`); }
      if (query.to) { values.push(query.to); clauses.push(`created_at < $${values.length}::timestamptz`); }
      if (query.cursor) {
        values.push(query.cursor.ts, query.cursor.eventId);
        const ts = `$${values.length - 1}::timestamptz`, id = `$${values.length}::uuid`;
        // Global ordering is timestamp, store, UUID descending. A lower store
        // includes every equal-time row; a higher store includes none.
        const sameTime = store < query.cursor.store ? `TRUE AND ${id} IS NOT NULL`
          : store > query.cursor.store ? `FALSE AND ${id} IS NOT NULL` : `event_id < ${id}`;
        clauses.push(`(created_at < ${ts} OR (created_at = ${ts} AND ${sameTime}))`);
      }
      values.push(query.limit);
      const rows = (await pool.query(`WITH candidates AS MATERIALIZED (
        SELECT event_id,created_at,octet_length(params_json) AS params_bytes
        FROM ${schema}.bound_audit_events WHERE ${clauses.join(' AND ')}
        ORDER BY created_at DESC,event_id DESC LIMIT ($${values.length} + 1)
      ), sized AS (
        SELECT *,row_number() OVER w AS ordinal,
          sum(6::bigint*params_bytes+16384) OVER w AS page_bytes
        FROM candidates WINDOW w AS (ORDER BY created_at DESC,event_id DESC)
      ), selected AS (
        SELECT * FROM sized WHERE ordinal <= $${values.length} AND page_bytes <= ${PAGE_BYTES}
      ) SELECT e.event_id::text AS id,
        to_char(e.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,
        actor,action,target,params_json,outcome,source_kind,source_id,NULL::text AS ip,NULL::text AS user_agent,
        (SELECT count(*) FROM candidates) > (SELECT count(*) FROM selected) AS has_more
        FROM selected s JOIN ${schema}.bound_audit_events e USING(event_id)
        ORDER BY e.created_at DESC,e.event_id DESC`, values)).rows;
      const events = rows.map(({ has_more, ...row }) => Object.freeze({ ...row, event_id: row.id, id: `${store}:${row.id}`, store }));
      Object.defineProperty(events, 'hasMore', { value: rows[0]?.has_more === true });
      return events;
    },
  });
}
function createBoundAuditReader({ agents, review }) {
  if (typeof agents?.recent !== 'function' || typeof review?.recent !== 'function') {
    throw new TypeError('Both audit journals required');
  }
  return Object.freeze({
    async recent(scope, query = {}) {
      const normalized = auditQuery(query);
      // Validate trusted coordinates before starting either database read.
      const trusted = createLaunchScope(scope);
      const pages = await Promise.all([agents.recent(trusted, query), review.recent(trusted, query)]);
      const compare = (a, b) => b.ts.localeCompare(a.ts)
        || b.store.localeCompare(a.store) || b.id.localeCompare(a.id);
      // Stop at the first exhausted store prefix. Continuing into the other
      // store's older rows would skip unseen rows behind that prefix's cursor.
      const boundaries = pages.filter(page => page.hasMore && page.length).map(page => page.at(-1));
      const frontier = boundaries.sort(compare)[0];
      const merged = pages.flat().sort(compare);
      const events = []; let bytes = 1024;
      for (const row of merged) {
        if (frontier && compare(row, frontier) > 0) break;
        const size = Buffer.byteLength(JSON.stringify(row)) + 1;
        if (events.length === normalized.limit || bytes + size > PAGE_BYTES) break;
        events.push(row); bytes += size;
      }
      const hasMore = pages.some(page => page.hasMore) || events.length < merged.length;
      const last = events.at(-1);
      const nextCursor = hasMore && last ? encodeAuditCursor({ ts: last.ts, store: last.store,
        eventId: last.event_id || last.id.split(':').at(-1) }) : null;
      return Object.freeze({ count: events.length, events: Object.freeze(events), hasMore, nextCursor });
    },
  });
}
module.exports = { auditQuery, createBoundAuditStore, createBoundAuditReader };
