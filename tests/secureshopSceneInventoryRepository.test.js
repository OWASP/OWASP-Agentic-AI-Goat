'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createOwnedInventoryRepository } = require('../server/database/postgres/secureshopOwnedInventoryRepository');

const birth = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000095',
  launchId: '10000000-0000-4000-8000-000000000095',
  scenarioId: '20000000-0000-4000-8000-000000000095',
  generation: 2, platformOwnerId: 95, platformSessionId: 905 });
const current = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000096',
  scenarioId: '20000000-0000-4000-8000-000000000096',
  generation: 3, platformOwnerId: 95, platformSessionId: 906 });
const birthScope = Object.freeze({ launchId: birth.launchId, scenarioId: birth.scenarioId,
  generation: birth.generation, platformOwnerId: birth.platformOwnerId,
  platformSessionId: birth.platformSessionId });

test('inventory preserves a birth target across login while receipts and replay stay bound to current execution', async () => {
  const operations = new Map(), checks = [], calls = [];
  let active = birthScope, leased = false, quantity = 9, stockWrites = 0, grants = 0;
  const scene = createSceneBinding(birth, { sceneId: '40000000-0000-4000-8000-000000000095',
    sceneGeneration: 1, grantId: '50000000-0000-4000-8000-000000000095', execution: current,
    async withLease(work) { leased = true; try { return await work(); } finally { leased = false; } } });
  const client = { release() {}, async query(sql, args = []) {
    calls.push(sql);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.startsWith('SET LOCAL')
        || sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('assert_scene_execution_grant')) {
      assert.equal(leased, true); grants++; return { rows: [{ allowed: true }] };
    }
    if (sql.startsWith('SELECT lifecycle')) {
      assert.deepEqual(args, [birth.targetId, birth.launchId, birth.scenarioId,
        birth.generation, birth.platformOwnerId, birth.platformSessionId]);
      return { rows: [{ lifecycle: 'active' }] };
    }
    if (sql.startsWith('SELECT * FROM secureshop_review.owned_inventory_operations')) {
      return { rows: operations.has(args[0]) ? [operations.get(args[0])] : [] };
    }
    if (sql.startsWith('SELECT count')) return { rows: [{ count: operations.size }] };
    if (sql.startsWith('INSERT INTO secureshop_review.owned_inventory_operations')) {
      operations.set(args[0], { target_id: args[1], shop_user_id: args[2],
        persona_session_id: args[3], authority_version: args[4], mode: args[5],
        action: args[6], request_sha256: args[10], request_json: args[11], state: 'admitted' });
      return { rowCount: 1 };
    }
    if (sql.startsWith('UPDATE secureshop_review.owned_inventory_operations')) {
      Object.assign(operations.get(args[0]), { state: 'completed', result_json: args[1], result_sha256: args[2] });
      return { rowCount: 1 };
    }
    if (sql.startsWith('SELECT product_id FROM')) return { rows: [{ product_id: 7 }] };
    if (sql.startsWith('SELECT p.product_id,p.retailer_id')) return { rows: [{ product_id: 7,
      retailer_id: 8, stock_quantity: quantity, overlay: true, archived: false, status: 'active' }] };
    if (sql.startsWith('UPDATE secureshop_review.product_target_listing_overlays SET stock_quantity')) {
      assert.equal(args[0], birth.targetId);
      assert.equal(args[3], quantity);
      quantity = args[2]; stockWrites++; return { rowCount: 1 };
    }
    throw new Error(`unexpected inventory SQL: ${sql}`);
  } };
  const repository = createOwnedInventoryRepository({ pool: { connect: async () => client },
    checkCurrent: async scope => { checks.push(scope); assert.deepEqual(scope, active); } });
  const base = { persona: { id: 3, role: 'merchant' },
    personaSession: { sessionId: '60000000-0000-4000-8000-000000000095', authorityVersion: '1' },
    mode: 'vuln', action: 'set_stock', args: { productId: 7, quantity: 2 }, execution: null };
  const oldId = '70000000-0000-4000-8000-000000000095';
  const oldInput = { ...base, target: birth, operationId: oldId };
  const oldReceipt = await repository.execute(oldInput);
  assert.deepEqual(oldReceipt.binding.scope, birthScope);
  assert.equal(stockWrites, 1);

  active = current;
  const staleReplay = { ...base, target: scene, operationId: oldId };
  await assert.rejects(repository.recover(staleReplay), { code: 'INVENTORY_OPERATION_CONFLICT' });
  assert.equal(stockWrites, 1, 'the old receipt never becomes a current-session effect');
  const fresh = { ...base, target: scene, operationId: '70000000-0000-4000-8000-000000000096',
    args: { productId: 7, quantity: 4 } };
  const receipt = await repository.execute(fresh);
  assert.deepEqual(receipt.binding.scope, current);
  assert.equal(receipt.binding.targetId, birth.targetId);
  assert.equal(receipt.result.before, 2);
  assert.equal(receipt.result.after, 4);
  assert.equal(stockWrites, 2);
  assert.deepEqual(await repository.recover(fresh), receipt);
  assert.equal(stockWrites, 2);
  assert.equal(grants, 5, 'conflict checks the grant before read; effect and replay recheck before commit');
  assert(checks.every(scope => scope.launchId === birthScope.launchId || scope.launchId === current.launchId));
  assert(calls.includes('COMMIT'));
});
