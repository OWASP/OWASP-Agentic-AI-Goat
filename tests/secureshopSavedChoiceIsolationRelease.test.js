'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createConversationalCommerceRepository } = require('../server/database/postgres/secureshopConversationalCommerceRepository');

const launch = {
  launchId: '50000000-0000-4000-8000-000000000001',
  scenarioId: '60000000-0000-4000-8000-000000000001',
  generation: 1, platformOwnerId: 7, platformSessionId: 8,
};
const targetId = '70000000-0000-4000-8000-000000000001';
const sceneId = '80000000-0000-4000-8000-000000000001';
const grantId = '90000000-0000-4000-8000-000000000001';
const operationId = '10000000-0000-4000-8000-000000000001';
const personaSessionId = 'a0000000-0000-4000-8000-000000000001';

function fixture() {
  const targetFor = scope => createSceneBinding({ ...scope, targetId }, {
    sceneId, sceneGeneration: 1, grantId, execution: scope, withLease: work => work(),
  });
  const target = targetFor(launch);
  const actor = { shopUserId: 11, personaSession: { sessionId: personaSessionId, authorityVersion: '1' }, mode: 'vuln' };
  const product = { product_id: 3, name: 'Desk lamp', description: 'Synthetic', description_html: '',
    price: '12.00', stock_quantity: 4, status: 'active', archived: false };
  let savedChoice = null;
  let writes = 0;
  const client = { async query(sql, values = []) {
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('SELECT choice_id FROM secureshop_review.chat_commerce_choices')) return { rows: [] };
    if (sql.includes('SELECT count(*) AS count FROM secureshop_review.chat_commerce_choices')) return { rows: [{ count: '0' }] };
    if (sql.includes('INSERT INTO secureshop_review.chat_commerce_choices')) {
      savedChoice = { choice_id: values[0], target_id: values[1], shop_user_id: values[2],
        kind: values[3], context_json: values[4], snapshot_json: values[5],
        snapshot_sha256: values[6], state: 'active' };
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.chat_commerce_choices WHERE choice_id='))
      return { rows: savedChoice?.choice_id === values[0] ? [savedChoice] : [] };
    if (sql.includes('FROM secureshop_review.chat_commerce_operations WHERE operation_id='))
      return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_products p'))
      return { rows: [{ ...product, ...(sql.includes('matched_total') ? { matched_total: 1 } : {}) }] };
    throw new Error(`Unexpected controlled query: ${sql.slice(0, 80)}`);
  } };
  const repository = createConversationalCommerceRepository({
    guarded: async (value, work) => work(client, value),
    listCartWithClient: async () => ({ items: [] }),
    addCartWithClient: async () => { writes++; return { id: 1 }; },
    updateCartWithClient: async () => { writes++; return 1; },
    removeCartWithClient: async () => { writes++; return 1; },
    checkoutWithClient: async () => { writes++; return { orderId: 1 }; },
    durableCheckout: true,
  });
  return { target, targetFor, actor, repository, get writes() { return writes; } };
}

test('a saved customer product choice rejects a different platform owner and a rotated persona authority before cart preparation', async () => {
  const f = fixture();
  const search = await f.repository.search(f.target, { ...f.actor, search: 'lamp' });
  assert.equal(search.cards.length, 1);
  const choiceId = search.cards[0].choiceId;
  assert.deepEqual(await f.repository.resolveChoice(f.target, { ...f.actor, choiceId }),
    { kind: 'product', choiceId, scopeKey: search.scopeKey });

  const denied = [
    [f.targetFor({ ...launch, platformOwnerId: 12 }), f.actor],
    [f.target, { ...f.actor, personaSession: { ...f.actor.personaSession, authorityVersion: '2' } }],
  ];
  for (const [target, actor] of denied) {
    await assert.rejects(f.repository.resolveChoice(target, { ...actor, choiceId }),
      { code: 'COMMERCE_CHOICE_DENIED' });
    await assert.rejects(f.repository.prepareCart(target, { ...actor, operationId,
      action: 'add', choiceId, quantity: 1 }), { code: 'COMMERCE_CHOICE_DENIED' });
  }
  assert.equal(f.writes, 0);
});
