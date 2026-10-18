'use strict';

const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const { executionScope, withSceneLease, assertSceneGrant } = require('../../services/secureshopSceneBinding');
const { UUID, fail } = require('../../services/secureshopPricingContract');
const MAX_OBSERVATIONS = 512;

// Physical birth coordinates identify stored prices; the private current scene
// grant authorizes a retained practice read. No shared commerce data is read.
function createPricingHistoryRepository({ pool, checkCurrent } = {}) {
  if (typeof pool?.connect !== 'function' || typeof checkCurrent !== 'function') throw fail('PRICING_HISTORY_UNAVAILABLE');
  return Object.freeze({
    async read(target, { productId, persona } = {}) {
      if (!UUID.test(target?.targetId || '') || !Number.isInteger(productId) || productId < 1
          || productId > 2147483647) throw fail('PRICING_PRODUCT_UNAVAILABLE');
      const current = createLaunchScope(executionScope(target));
      const birth = createLaunchScope(target);
      const actor = createConversationBinding(current, persona);
      if (!['merchant','customer'].includes(actor.role)) throw fail('PRICING_ROLE_REQUIRED');
      await checkCurrent(current);
      return withSceneLease(target, async () => {
        const client = await pool.connect();
        try {
          await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          await assertSceneGrant(client, target);
          // Retirement/deletion takes the target's exclusive lock. Base rows
          // are immutable, so the repeatable-read snapshot needs no product
          // row lock (which would require deliberately withheld UPDATE rights).
          const row = (await client.query(`SELECT COALESCE(o.name,p.name) AS name,COALESCE(o.price,p.price) AS price
            FROM secureshop_review.product_target_products p
            JOIN secureshop_review.product_targets t ON t.target_id=p.target_id
            LEFT JOIN secureshop_review.product_target_listing_overlays o
              ON o.target_id=p.target_id AND o.product_id=p.product_id
            WHERE t.target_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4
              AND t.original_platform_owner_id=$5 AND t.original_platform_session_id=$6
              AND t.lifecycle='active' AND p.product_id=$7
              AND ($8='customer' OR p.retailer_id=$9)
              AND COALESCE(o.status,p.status)='active' AND o.archived_at IS NULL
              AND ($10 OR NOT EXISTS(SELECT 1 FROM secureshop_review.scene_execution_grants g
                WHERE g.target_id=t.target_id)) FOR SHARE OF t`,
          [target.targetId,birth.launchId,birth.scenarioId,birth.generation,birth.platformOwnerId,
            birth.platformSessionId,productId,actor.role,actor.shopUserId,target.scene !== undefined])).rows[0];
          if (!row) throw fail('PRICING_PRODUCT_UNAVAILABLE');
          const rows = (await client.query(`SELECT price,observed_at::text,source,observation_id::text
            FROM secureshop_review.product_target_price_history WHERE target_id=$1 AND product_id=$2
              AND observed_at >= transaction_timestamp()-interval '30 days'
            ORDER BY observed_at DESC,observation_id DESC LIMIT $3`,
          [target.targetId,productId,MAX_OBSERVATIONS+1])).rows;
          const historyTruncated = rows.length > MAX_OBSERVATIONS;
          const history = rows.slice(0,MAX_OBSERVATIONS).reverse().map(value => {
            const date = new Date(value.observed_at);
            if (!Number.isFinite(date.getTime()) || !['migration_baseline','product_insert','price_change'].includes(value.source)
                || !Number.isFinite(Number(value.price)) || Number(value.price)<0) throw fail('PRICING_HISTORY_UNAVAILABLE');
            return { date: date.toISOString(), price: Number(value.price), source: value.source };
          });
          if (!Number.isFinite(Number(row.price)) || Number(row.price)<0 || typeof row.name !== 'string') throw fail('PRICING_HISTORY_UNAVAILABLE');
          await checkCurrent(current);
          await assertSceneGrant(client, target);
          await client.query('COMMIT');
          await checkCurrent(current);
          return { product_id:productId,name:row.name,current_price:Number(row.price),grounded:true,
            historyAvailable:true,historySource:'owned_product_price_observations',periodDays:30,
            historyTruncated,history };
        } catch (error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
        finally { client.release(); }
      });
    }
  });
}
module.exports = { createPricingHistoryRepository, MAX_OBSERVATIONS };
