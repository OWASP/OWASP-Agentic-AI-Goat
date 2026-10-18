'use strict';

const {
  createLaunchScope,
  createConversationBinding
} = require('./secureshopConversationBinding');
const {
  createPersonaProductEffect
} = require('./secureshopPersonaProductEffect');
const {
  UUID,
  text,
  fail
} = require('./secureshopPricingContract');
const { executionScope, withSceneLease, assertSceneGrant } = require('./secureshopSceneBinding');
const { withTransaction } = require('../database/postgres');

// Existing product/manual stores remain the source of truth. Prepare happens
// before pricing's short agents transaction; capture does no provisioning and
// never re-enters a persona transaction while its original fence is held.
function createPricingTargetSource({
  catalog,
  productRepository,
  reviewPool,
  launches,
  personaAuthority,
  historyRepository
} = {}) {
  if (typeof catalog?.prepareTarget !== 'function' || typeof productRepository?.get !== 'function' || typeof reviewPool?.query !== 'function' || typeof launches?.readExistingProductsTarget !== 'function' || typeof launches?.assertCurrent !== 'function' || typeof personaAuthority?.capture !== 'function') throw fail('PRICING_TARGET_UNAVAILABLE');
  function targetFor(prepared, scope) {
    if (!UUID.test(prepared?.targetId)) throw fail('PRICING_TARGET_UNAVAILABLE');
    const current = executionScope(prepared);
    if (['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
      .some(key => current?.[key] !== scope[key])) throw fail('PRICING_TARGET_UNAVAILABLE');
    if (prepared.scene !== undefined && typeof reviewPool.connect !== 'function') {
      throw fail('PRICING_TARGET_UNAVAILABLE');
    }
    return prepared;
  }
  async function prepare(raw) {
    const input = structuredClone(raw),
      scope = createLaunchScope(input.scope);
    const binding = createConversationBinding(scope, input.persona);
    const fence = await personaAuthority.capture({
      scope,
      personaId: binding.shopUserId,
      role: binding.role,
      sessionId: input.personaSession?.sessionId,
      authorityVersion: input.personaSession?.authorityVersion
    });
    await fence.assertRemoteAdmission();
    const prepared = await catalog.prepareTarget({
      scope,
      persona: input.persona,
      personaEffect: createPersonaProductEffect(fence)
    });
    await fence.assertRemoteAdmission();
    return targetFor(prepared, scope);
  }
  async function capture(_agentsClient, raw, preparedTarget) {
    const input = structuredClone(raw),
      scope = createLaunchScope(input.scope);
    const actor = createConversationBinding(scope, input.persona);
    await launches.assertCurrent(scope);
    let target;
    if (preparedTarget !== undefined) {
      target = targetFor(preparedTarget, scope);
    } else {
      // Retained direct legacy fixture path. Production passes the exact
      // capability returned by prepare; a scene cannot be rebuilt from JSON.
      const reserved = await launches.readExistingProductsTarget(scope);
      if (reserved?.kind !== 'products' || !UUID.test(reserved?.targetId)
          || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
            .some(key => reserved[key] !== scope[key])) throw fail('PRICING_TARGET_UNAVAILABLE');
      target = Object.freeze({ ...scope, targetId: reserved.targetId });
    }
    const product = await productRepository.get(target, input.productId);
    if (!product || product.id !== input.productId || product.status !== 'active' || actor.role === 'merchant' && product.retailer_id !== actor.shopUserId) throw fail('PRICING_PRODUCT_UNAVAILABLE');
    // Read only this product's most recent admitted manual. No shared commerce
    // policy text or arbitrary host file is eligible as competitor evidence.
    const sql = `WITH latest AS (
      SELECT i.manual_source_id,i.filename,i.document_count FROM secureshop_review.product_target_manual_ingests i
      JOIN secureshop_review.product_targets t ON t.target_id=i.target_id
      WHERE i.target_id=$1 AND i.launch_id=$2 AND i.scenario_id=$3 AND i.generation=$4
        AND i.original_platform_owner_id=$5 AND i.original_platform_session_id=$6 AND i.product_id=$7
        AND t.lifecycle='active' AND t.launch_id=i.launch_id AND t.scenario_id=i.scenario_id
        AND t.generation=i.generation AND t.original_platform_owner_id=i.original_platform_owner_id
        AND t.original_platform_session_id=i.original_platform_session_id
      ORDER BY i.completed_at DESC,i.operation_id DESC LIMIT 1)
      SELECT l.filename,l.document_count,d.chunk_index,d.body FROM latest l
      LEFT JOIN secureshop_review.product_target_retrieval_documents d ON d.target_id=$1
        AND d.generation=$4 AND d.source_kind='manual' AND d.source_id=l.manual_source_id
      ORDER BY d.chunk_index LIMIT 130`;
    const params = [target.targetId, target.launchId, target.scenarioId, target.generation,
      target.platformOwnerId, target.platformSessionId, input.productId];
    const rows = target.scene === undefined
      ? (await reviewPool.query(sql, params)).rows
      : await withSceneLease(target, () => withTransaction(reviewPool, async client => {
        await assertSceneGrant(client, target);
        const found = (await client.query(sql, params)).rows;
        await assertSceneGrant(client, target);
        return found;
      }));
    if (rows.length > 129 || rows.some((row, i) => !Number.isInteger(row.document_count) || row.document_count !== rows.length || row.chunk_index === null || Number(row.chunk_index) !== i || row.filename !== rows[0].filename)) throw fail('PRICING_MANUAL_UNAVAILABLE');
    const markdown = rows.map(row => text(row.body, 16384, true)).join('');
    text(markdown, 16384, true);
    const manual = {
      name: rows.length ? text(rows[0].filename, 512) : 'No owned competitor manual',
      markdown
    };
    await launches.assertCurrent(scope);
    return {
      product: {
        id: product.id,
        name: text(product.name, 512),
        price: Number(product.price)
      },
      manual
    };
  }
  async function readHistory(raw, preparedTarget) {
    if (typeof historyRepository?.read !== 'function') throw fail('PRICING_HISTORY_UNAVAILABLE');
    const input = structuredClone(raw), scope = createLaunchScope(input.scope);
    const actor = createConversationBinding(scope,input.persona);
    const fence = await personaAuthority.capture({ scope,personaId:actor.shopUserId,role:actor.role,
      sessionId:input.personaSession?.sessionId,authorityVersion:input.personaSession?.authorityVersion });
    await fence.assertRemoteAdmission();
    const target = preparedTarget === undefined ? await prepare(input) : targetFor(preparedTarget,scope);
    const result = await historyRepository.read(target,{productId:input.productId,persona:input.persona});
    await fence.assertRemoteAdmission();
    return result;
  }
  return Object.freeze({
    prepare,
    capture,
    readHistory
  });
}
module.exports = {
  createPricingTargetSource
};
