'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const contract = require('../server/services/secureshopConversationalCommerceContract');
const { createCustomerCommerceTools, cards: toolCards } = require('../server/services/secureshopBoundCustomerCommerceTools');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createConversationalCommerceRepository } = require('../server/database/postgres/secureshopConversationalCommerceRepository');

const operationId = '10000000-0000-4000-8000-000000000001';
const choiceId = '20000000-0000-4000-8000-000000000001';
const addressChoiceId = '30000000-0000-4000-8000-000000000001';
const paymentChoiceId = '40000000-0000-4000-8000-000000000001';
const rejected = work => assert.throws(work, error => error?.code === 'INVALID_ARGUMENT');

test('commerce cards admit only bounded public choice fields', () => {
  const visible = { version: 1, kind: 'product', choiceId, title: 'Desk lamp', detail: '$12.00' };
  assert.deepEqual(contract.cards([visible]), [visible]);
  const currentCart = { ...visible, kind: 'cart_item', quantity: 3 };
  const historicalCart = { ...visible, kind: 'cart_item' };
  assert.deepEqual(contract.cards([currentCart]), [currentCart]);
  assert.deepEqual(contract.cards([historicalCart]), [historicalCart]);
  assert.deepEqual(toolCards([currentCart]), [currentCart]);
  assert.deepEqual(toolCards([historicalCart]), [historicalCart]);
  for (const extra of [
    { productId: 7 }, { shopUserId: 8 }, { priceCents: 1200 }, { targetId: operationId },
    { sessionId: operationId }, { stockQuantity: 4 }, { paymentToken: 'private' },
  ]) rejected(() => contract.cards([{ ...visible, ...extra }]));
  rejected(() => contract.cards([{ ...visible, choiceId: 'not-a-choice' }]));
  rejected(() => contract.cards([{ ...visible, kind: 'checkout' }]));
  rejected(() => contract.cards([{ ...visible, title: 'x'.repeat(257) }]));
  rejected(() => contract.cards([{ ...visible, quantity: 2 }]));
  for (const quantity of [0, 100, '2', 1.5, undefined, null]) {
    rejected(() => contract.cards([{ ...currentCart, quantity }]));
    assert.throws(() => toolCards([{ ...currentCart, quantity }]), TypeError);
  }
  assert.throws(() => toolCards([{ ...visible, quantity: 2 }]), TypeError);
  rejected(() => contract.cards(Array.from({ length: 13 }, () => visible)));
});

test('cart mutations cannot carry model-supplied owner, item ID, price, or total', () => {
  const add = { operationId, action: 'add', choiceId, quantity: 2 };
  assert.deepEqual(contract.mutation(add), add);
  for (const extra of [
    { shopUserId: 9 }, { productId: 9 }, { cartItemId: 9 }, { targetId: operationId },
    { price: 0.01 }, { totalCents: 1 }, { sessionId: operationId },
  ]) rejected(() => contract.mutation({ ...add, ...extra }));
  for (const quantity of [0, -1, 1.5, 100, '2', NaN, Infinity]) {
    rejected(() => contract.mutation({ ...add, quantity }));
  }
  rejected(() => contract.mutation({ operationId, action: 'remove', choiceId, quantity: 1 }));
  rejected(() => contract.mutation({ ...add, action: 'purchase' }));
  rejected(() => contract.mutation({ ...add, choiceId: 'unknown' }));
});

test('payment practice and checkout preparation accept references, not payment secrets or totals', () => {
  assert.deepEqual(contract.practice({ operationId, scenario: 'approved' }), { operationId, scenario: 'approved' });
  rejected(() => contract.practice({ operationId, scenario: 'approved', cardNumber: '4111111111111111' }));
  rejected(() => contract.practice({ operationId, scenario: 'arbitrary' }));
  const prepare = { operationId, addressChoiceId, paymentChoiceId };
  assert.deepEqual(contract.prepare(prepare), prepare);
  for (const extra of [
    { shippingAddress: 'forged' }, { paymentMethod: 'forged' }, { paymentToken: 'private' },
    { totalCents: 1 }, { discountCents: 999 }, { shopUserId: 9 }, { sceneId: operationId },
  ]) rejected(() => contract.prepare({ ...prepare, ...extra }));
  rejected(() => contract.prepare({ ...prepare, paymentChoiceId: 'unknown' }));
});

test('quoted money must be finite exact cents', () => {
  assert.equal(contract.money('12.34'), 1234);
  for (const amount of ['-1', '0.001', '1e3', 'Infinity', 'NaN', '1,000', '', null]) {
    assert.throws(() => contract.money(amount), error => error?.code === 'COMMERCE_STATE_INVALID');
  }
});

function repositoryFixture() {
  const launch = { launchId: '50000000-0000-4000-8000-000000000001',
    scenarioId: '60000000-0000-4000-8000-000000000001', generation: 1,
    platformOwnerId: 7, platformSessionId: 8 };
  const targetId = '70000000-0000-4000-8000-000000000001';
  const sceneId = '80000000-0000-4000-8000-000000000001';
  const makeTarget = ({ scope = launch, scene = sceneId } = {}) => createSceneBinding(
    { ...scope, targetId }, { sceneId: scene, sceneGeneration: 1,
      grantId: '90000000-0000-4000-8000-000000000001', execution: scope,
      withLease: work => work() });
  const target = makeTarget();
  const args = { shopUserId: 11, personaSession: { sessionId: 'a0000000-0000-4000-8000-000000000001',
    authorityVersion: '1' }, mode: 'vuln' };
  const product = { product_id: 3, name: 'Desk lamp', description: 'Synthetic', description_html: '',
    price: '12.00', stock_quantity: 4, status: 'active', archived: false };
  let savedChoice = null;
  let mutationCalls = 0;
  const client = { async query(sql, values = []) {
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.chat_commerce_choices WHERE choice_id=')) {
      return { rows: savedChoice && savedChoice.choice_id === values[0] ? [savedChoice] : [] };
    }
    if (sql.includes('SELECT choice_id FROM secureshop_review.chat_commerce_choices')) return { rows: [] };
    if (sql.includes('SELECT count(*) AS count FROM secureshop_review.chat_commerce_choices')) return { rows: [{ count: '0' }] };
    if (sql.includes('INSERT INTO secureshop_review.chat_commerce_choices')) {
      savedChoice = { choice_id: values[0], target_id: values[1], shop_user_id: values[2],
        kind: values[3], context_json: values[4], snapshot_json: values[5],
        snapshot_sha256: values[6], state: 'active' };
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.chat_commerce_operations WHERE operation_id=')) return { rows: [] };
    if (sql.startsWith('WITH catalog_matches AS')) return { rows: [{...product,matched_total:1}] };
    if (sql.includes('FROM secureshop_review.product_target_products p')) return { rows: [product] };
    throw new Error(`Unexpected controlled query: ${sql.slice(0, 80)}`);
  } };
  const repo = createConversationalCommerceRepository({
    guarded: async (value, work) => work(client, value),
    listCartWithClient: async () => ({ items: [] }),
    addCartWithClient: async () => { mutationCalls++; return { id: 1 }; },
    updateCartWithClient: async () => { mutationCalls++; return 1; },
    removeCartWithClient: async () => { mutationCalls++; return 1; },
    checkoutWithClient: async () => { mutationCalls++; return { orderId: 1 }; },
    durableCheckout: true,
  });
  return { repo, target, makeTarget, launch, args,
    setProductPrice: price => { product.price = price; },
    getMutationCalls: () => mutationCalls };
}

test('server-issued choice cannot cross customer, scene, launch generation, or persona session', async () => {
  const f = repositoryFixture();
  const issued = await f.repo.search(f.target, { ...f.args, search: 'lamp' });
  assert.equal(issued.cards.length, 1);
  assert.match(issued.scopeKey, /^[a-f0-9]{64}$/);
  const { choiceId: issuedChoice } = issued.cards[0];
  assert.deepEqual(await f.repo.resolveChoice(f.target, { ...f.args, choiceId: issuedChoice }),
    { kind: 'product', choiceId: issuedChoice, scopeKey: issued.scopeKey });
  const foreign = [
    [f.target, { ...f.args, shopUserId: 12 }],
    [f.makeTarget({ scene: '80000000-0000-4000-8000-000000000002' }), f.args],
    [f.makeTarget({ scope: { ...f.launch, generation: 2 } }), f.args],
    [f.target, { ...f.args, personaSession: { ...f.args.personaSession,
      sessionId: 'a0000000-0000-4000-8000-000000000002' } }],
  ];
  for (const [target, args] of foreign) {
    await assert.rejects(f.repo.resolveChoice(target, { ...args, choiceId: issuedChoice }),
      { code: 'COMMERCE_CHOICE_DENIED' });
    await assert.rejects(f.repo.prepareCart(target, { ...args, operationId, action: 'add',
      choiceId: issuedChoice, quantity: 1 }), { code: 'COMMERCE_CHOICE_DENIED' });
  }
  assert.equal(f.getMutationCalls(), 0);
});

test('unknown confirmation and receipt lookup cannot manufacture a purchase', async () => {
  const f = repositoryFixture();
  await assert.rejects(f.repo.confirmCheckout(f.target, { ...f.args, proposalId: operationId }),
    { code: 'COMMERCE_PROPOSAL_NOT_FOUND' });
  const { scopeKey, ...unknown } = await f.repo.readOperation(f.target, { ...f.args, operationId });
  assert.match(scopeKey, /^[a-f0-9]{64}$/);
  assert.deepEqual(unknown, { operationId, status: 'not_found' });
  assert.equal(f.getMutationCalls(), 0);
});

test('changed product quote makes its saved choice stale before cart mutation', async () => {
  const f = repositoryFixture();
  const issued = await f.repo.search(f.target, { ...f.args, search: 'lamp' });
  const choiceId = issued.cards[0].choiceId;
  f.setProductPrice('13.00');
  await assert.rejects(f.repo.resolveChoice(f.target, { ...f.args, choiceId }),
    { code: 'COMMERCE_CHOICE_STALE' });
  await assert.rejects(f.repo.prepareCart(f.target, { ...f.args, operationId,
    action: 'add', choiceId, quantity: 1 }), { code: 'COMMERCE_CHOICE_STALE' });
  assert.equal(f.getMutationCalls(), 0);
});

test('model tool arguments cannot replace the customer-selected choice or smuggle authority', async () => {
  let domainCalls = 0;
  let effectCalls = 0;
  const conversation = Object.fromEntries(['details', 'prepareCart', 'ordersList', 'orderDetails', 'resolveChoice',
    'addresses', 'paymentMethods', 'createPaymentMethod', 'prepareCheckout']
    .map(name => [name, async () => { domainCalls++; return { cards: [] }; }]));
  const tools = createCustomerCommerceTools({ conversation, target: {}, shopUserId: 11,
    personaSession: { sessionId: operationId, authorityVersion: '1' }, mode: 'vuln',
    sessionId: operationId, requestId: addressChoiceId, message: 'Add the selected product.',
    selection: { kind: 'product', choiceId }, check: async () => {},
    withEffect: async work => { effectCalls++; return work(); }, onCards: () => {} });
  const otherChoice = paymentChoiceId;
  const invocation = { step: 1, callId: 'model-call' };
  for (const [tool, args] of [
    ['catalog.details', { choiceId: otherChoice }],
    ['cart.add', { choiceId: otherChoice, quantity: 1 }],
    ['cart.add', { choiceId, quantity: 1, productId: 3 }],
    ['cart.add', { choiceId, quantity: 1, shopUserId: 11 }],
    ['cart.remove', { choiceId }],
    ['payment.create_method', { scenario: 'approved', cardNumber: '4111111111111111' }],
    ['checkout.prepare', { addressChoiceId, paymentChoiceId }],
  ]) await assert.rejects(tools.get(tool)(args, invocation), { code: 'INVALID_TOOL_ARGUMENTS' });
  await assert.rejects(tools.get('cart.add')({ choiceId, quantity: 1 },
    { step: 0, callId: 'model-call' }), { code: 'INVALID_TOOL_ARGUMENTS' });
  assert.equal(tools.has('checkout.confirm'), false, 'model cannot invoke the trusted purchase control');
  assert.equal(domainCalls, 0);
  assert.equal(effectCalls, 0);
});
