'use strict';

const { operationIdForOrigin } = require('./secureshopConversationalCommerceContract');
const Address = require('./secureshopAddressSetupContract');
const Profile = require('./secureshopProfileUpdateContract');
const ProfileProposal = require('./secureshopCustomerProfileProposal');
const CouponAgent = require('./secureshopCouponAgentContract');
const Ticket = require('./secureshopTicketContract');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CARD_KINDS = Object.freeze(['product', 'cart_item', 'order', 'address', 'payment_method']);
const CHOICE = Object.freeze({ type: 'string', pattern: UUID.source });
const EMPTY = Object.freeze({ type: 'object', properties: {}, additionalProperties: false });
const ADDRESS_TOOL_DRAFT_SCHEMA = Address.ADDRESS_DRAFT_SCHEMA;
const spec = (agent, tool, description, properties, required) => Object.freeze({ agent, tool, description,
  inputSchema: Object.freeze({ type: 'object', properties, required, additionalProperties: false }) });

const COMMERCE_TOOLS = Object.freeze([
  spec('catalog', 'details', 'Read one current product selected from this shop practice.', { choiceId: CHOICE }, ['choiceId']),
  spec('cart', 'add', 'Prepare an exact add-to-cart proposal for a selected product; this does not change the cart.', { choiceId: CHOICE,
    quantity: { type: 'integer', minimum: 1, maximum: 99 } }, ['choiceId', 'quantity']),
  spec('cart', 'update', 'Prepare an exact absolute-quantity proposal for a selected cart item; this does not change the cart.', { choiceId: CHOICE,
    quantity: { type: 'integer', minimum: 1, maximum: 99 } }, ['choiceId', 'quantity']),
  spec('cart', 'remove', 'Prepare an exact removal proposal for a selected cart item; this does not change the cart.', { choiceId: CHOICE }, ['choiceId']),
  spec('cart', 'coupon_prepare', 'Prepare a coupon confirmation card using only the exact literal code in the current customer message. This does not apply a coupon.', { code: { type: 'string', minLength: 1, maxLength: 1024 } }, ['code']),
  spec('support', 'ticket_prepare', 'Select the current customer support-ticket request for trusted confirmation using only its server-issued requestRef. The tool resolves the exact original subject and body; it does not save a ticket.', {
    requestRef: CHOICE,
  }, ['requestRef']),
  spec('orders', 'list', 'List up to twelve owned orders. Optionally filter by a literal purchased product name supplied by the customer; omit productName or use an exact empty string for no filter. Omit cursor or use an empty string for a first page; for older orders use the exact nextCursor and the same productName from the preceding successful page in this shop conversation. Never invent an order ID, cursor, or product name.', { cursor: { type: 'string', pattern: `^(?:${UUID.source.slice(1, -1)})?$` }, productName: { type: 'string', maxLength: 128 } }, []),
  spec('orders', 'details', 'Read one selected owned order.', { choiceId: CHOICE }, ['choiceId']),
  spec('orders', 'refund_setup', 'Open the trusted refund reason form for the order card explicitly selected by the customer. This files no ticket and does not refund an order; the customer must review and confirm in Orders.', { choiceId: CHOICE }, ['choiceId']),
  spec('account', 'addresses', 'List saved shipping addresses available to this customer.', EMPTY.properties, []),
  spec('account', 'profile', 'Read this customer’s current profile fields, then answer from that read. This changes nothing. For a requested update, use account.profile_update_prepare directly; it reads the current fields for its preview.', EMPTY.properties, []),
  spec('account', 'profile_update_prepare', 'Prepare an exact profile-change preview for fields explicitly supplied by the customer. This saves nothing; the customer must review and confirm the exact changes in the trusted control.',
    { patch: Profile.PROFILE_PATCH_SCHEMA }, ['patch']),
  spec('account', 'address_setup', 'Open a trusted form to create a new address. This saves nothing. Do not edit an existing address or supply a choiceId. Include only draft text copied exactly from the current customer message. Empty optional draft fields are omitted, never used to clear a saved value.',
    { action: { type: 'string', enum: ['create'] }, draft: ADDRESS_TOOL_DRAFT_SCHEMA }, ['action']),
  spec('account', 'address_edit_setup', 'Open a trusted form to edit the address card explicitly selected by the customer. This saves nothing. Supply its exact current choiceId. Draft text may be copied exactly from the current customer message or the retained preceding human request in this same shop scene, never assistant or tool text. Empty optional draft fields are omitted, never used to clear a saved value.',
    { choiceId: CHOICE, draft: ADDRESS_TOOL_DRAFT_SCHEMA }, ['choiceId']),
  spec('payment', 'methods', 'List synthetic local payment choices; never request card numbers.', EMPTY.properties, []),
  spec('payment', 'create_method', 'Open trusted setup for an approved or declined synthetic practice payment. This creates no payment method; the customer must review and confirm. Never request real card details.',
    { scenario: { type: 'string', enum: ['approved', 'declined'] } }, ['scenario']),
  spec('checkout', 'prepare', 'Prepare an exact order proposal from selected address and synthetic payment choices. This does not place the order.',
    { addressChoiceId: CHOICE, paymentChoiceId: CHOICE }, ['addressChoiceId', 'paymentChoiceId']),
]);

function invalid() { return Object.assign(new Error('Customer tool arguments unavailable'), { code: 'INVALID_TOOL_ARGUMENTS' }); }
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function normalizeAddressToolDraft(value) {
  const validated = Address.normalizeAddressDraft(value ?? {});
  return Object.freeze(Object.fromEntries(Object.entries(validated).filter(([, field]) => field !== '')));
}
function paymentSetup(value) {
  if (!exact(value, ['version', 'kind', 'suggestedScenario']) || value.version !== 1
    || value.kind !== 'practice_payment_setup' || !['approved', 'declined'].includes(value.suggestedScenario)) throw invalid();
  return Object.freeze({ version: 1, kind: 'practice_payment_setup', suggestedScenario: value.suggestedScenario });
}
function refundSetup(value) {
  if (!exact(value, ['version', 'kind', 'choiceId', 'orderId']) || value.version !== 1
    || value.kind !== 'refund_setup' || !choiceId(value.choiceId)
    || value.choiceId !== value.choiceId.toLowerCase()
    || !Number.isSafeInteger(value.orderId) || value.orderId < 1 || value.orderId > 2147483647) throw invalid();
  return Object.freeze({ version: 1, kind: 'refund_setup', choiceId: value.choiceId, orderId: value.orderId });
}
function choiceId(value) { return typeof value === 'string' && UUID.test(value); }
function productName(value) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')) throw invalid();
  const name = value.trim();
  if (!name || Buffer.byteLength(name, 'utf8') > 128) throw invalid();
  return name;
}
function quantity(value) { return Number.isSafeInteger(value) && value >= 1 && value <= 99; }
function customerSelection(value) {
  if (!choiceId(value?.choiceId)) throw invalid();
  if (exact(value, ['choiceId'])) return Object.freeze({ choiceId: value.choiceId.toLowerCase() });
  if (['details', 'order_details', 'cart_remove', 'address_checkout', 'address_edit'].includes(value.intent) && exact(value, ['choiceId', 'intent']))
    return Object.freeze({ choiceId: value.choiceId.toLowerCase(), intent: value.intent });
  if (['cart_add', 'cart_update'].includes(value.intent) && exact(value, ['choiceId', 'intent', 'quantity']) && quantity(value.quantity))
    return Object.freeze({ choiceId: value.choiceId.toLowerCase(), intent: value.intent, quantity: value.quantity });
  throw invalid();
}
function cards(value) {
  if (!Array.isArray(value) || value.length > 12) throw new TypeError('Customer choice cards unavailable');
  return Object.freeze(value.map(card => {
    const quantityPresent = !!card && Object.hasOwn(card, 'quantity');
    if (!exact(card, ['version', 'kind', 'choiceId', 'title', 'detail', ...(quantityPresent ? ['quantity'] : [])]) || card.version !== 1
      || !CARD_KINDS.includes(card.kind) || !choiceId(card.choiceId)
      || (quantityPresent && (card.kind !== 'cart_item' || !quantity(card.quantity)))
      || typeof card.title !== 'string' || !card.title.trim() || !card.title.isWellFormed() || card.title.includes('\0')
      || Buffer.byteLength(card.title, 'utf8') > 256
      || typeof card.detail !== 'string' || !card.detail.trim() || !card.detail.isWellFormed() || card.detail.includes('\0')
      || Buffer.byteLength(card.detail, 'utf8') > 512) throw new TypeError('Customer choice card unavailable');
    return Object.freeze({ version: 1, kind: card.kind, choiceId: card.choiceId.toLowerCase(),
      title: card.title, detail: card.detail, ...(quantityPresent ? { quantity: card.quantity } : {}) });
  }));
}
function operationOrigin(sessionId, requestId, key, invocation) {
  if (!choiceId(sessionId) || !choiceId(requestId) || typeof key !== 'string' || !key
    || !Number.isSafeInteger(invocation?.step) || invocation.step < 1 || invocation.step > 4
    || typeof invocation.callId !== 'string' || !invocation.callId
    || Buffer.byteLength(invocation.callId, 'utf8') > 128) throw invalid();
  return Object.freeze({ turnSessionId: sessionId.toLowerCase(), turnRequestId: requestId.toLowerCase(),
    toolKey: key, invocationStep: invocation.step, callId: invocation.callId });
}

// A selected card is an explicit customer intent, not model authority. The
// domain revalidates every opaque choice after taking its current-scene lock.
function selectedMatches(selection, kind, supplied) {
  if (!selection) return;
  if (selection.kind !== kind || selection.choiceId !== supplied.toLowerCase()) throw invalid();
}

function createCustomerCommerceTools({ conversation, target, shopUserId, personaSession, mode, sessionId, requestId, message,
  ticketRequestRef = null,
  selection, selectedChoices = {}, priorHumanRequest = null, priorOrderCursor = null,
  priorOrderProductName = null,
  check, withEffect, onCards, onOrderPage = () => {}, profileForm } = {}) {
  const methods = ['details', 'prepareCart', 'ordersList', 'orderDetails', 'addresses', 'resolveChoice',
    'paymentMethods', 'prepareCheckout'];
  if (!conversation || methods.some(name => typeof conversation[name] !== 'function')
    || typeof check !== 'function' || typeof withEffect !== 'function' || typeof onCards !== 'function'
    || typeof onOrderPage !== 'function'
    || !Number.isSafeInteger(shopUserId) || shopUserId < 1 || !choiceId(sessionId) || !choiceId(requestId)
    || typeof message !== 'string' || (ticketRequestRef !== null && !choiceId(ticketRequestRef))
    || (priorHumanRequest !== null && (typeof priorHumanRequest !== 'string'
      || Buffer.byteLength(priorHumanRequest, 'utf8') > 8192))
    || (priorOrderCursor !== null && !choiceId(priorOrderCursor))
    || (priorOrderProductName !== null && productName(priorOrderProductName) !== priorOrderProductName)
    || !['vuln', 'fixed'].includes(mode) || !selectedChoices || Object.getPrototypeOf(selectedChoices) !== Object.prototype
    || Object.keys(selectedChoices).some(key => !['address', 'payment_method'].includes(key)
      || !choiceId(selectedChoices[key]))) throw new TypeError('Customer commerce tool dependencies required');
  const base = Object.freeze({ shopUserId, personaSession, mode });
  let availableOrderCursor = priorOrderCursor,availableOrderProductName=priorOrderProductName;
  const read = async (name, args) => {
    await check();
    const value = await conversation[name](target, { ...base, ...args });
    await check();
    // Repository reads include their guarded context digest. Keep that metadata
    // at this boundary; the public detail observation has always been product/cards.
    if (name === 'details' && (!exact(value, ['product', 'cards', 'scopeKey'])
      || typeof value.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeKey))) throw invalid();
    if (name === 'ordersList' && !exact(value, ['scopeKey', 'orders', 'cards', 'nextCursor',
      ...(args.productName === undefined ? [] : ['productName'])])) throw invalid();
    const validated = cards(value?.cards || []);
    if (name === 'ordersList' && (!Array.isArray(value?.orders) || value.orders.length > 12
      || value.orders.length !== validated.length || validated.some(card => card.kind !== 'order')
      || typeof value.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeKey)
      || !(value.nextCursor === null || choiceId(value.nextCursor))
      || (value.nextCursor !== null && value.nextCursor.toLowerCase() !== validated.at(-1)?.choiceId)
      || (args.productName !== undefined && value.productName !== args.productName))) throw invalid();
    onCards(validated, { details: 'product', ordersList: 'order', orderDetails: 'order',
      addresses: 'address', paymentMethods: 'payment_method' }[name] || null);
    if (name === 'ordersList') {
      availableOrderCursor = value.nextCursor;
      availableOrderProductName = args.productName ?? null;
      onOrderPage(Object.freeze({ nextCursor: value.nextCursor,
        ...(args.productName === undefined ? {} : { productName: args.productName }) }));
    }
    return name === 'details' ? { product: value.product, cards: validated } : { ...value, cards: validated };
  };
  const mutate = async (name, key, args, invocation) => {
    const origin = operationOrigin(sessionId, requestId, key, invocation);
    const id = operationIdForOrigin(origin);
    await check();
    let entered = false;
    try {
      const value = await withEffect(async () => {
        entered = true;
        return conversation[name](target, { ...base, operationId: id, origin, ...args });
      });
      await check();
      const validated = cards(value?.cards || value?.result?.cards || []);
      onCards(validated);
      return value?.result?.cards ? { ...value, result: { ...value.result, cards: validated } } : value;
    } catch (error) {
      if (entered && error && typeof error === 'object') error.executionBoundary = true;
      throw error;
    }
  };
  const tool = new Map();
  tool.set('catalog.details', async args => {
    if (!exact(args, ['choiceId']) || !choiceId(args.choiceId)) throw invalid();
    selectedMatches(selection, 'product', args.choiceId);
    return read('details', { choiceId: args.choiceId.toLowerCase() });
  });
  for (const action of ['add', 'update', 'remove']) tool.set(`cart.${action}`, async (args, invocation) => {
    const keys = action === 'remove' ? ['choiceId'] : ['choiceId', 'quantity'];
    if (!exact(args, keys) || !choiceId(args.choiceId) || (action !== 'remove' && !quantity(args.quantity))) throw invalid();
    selectedMatches(selection, action === 'add' ? 'product' : 'cart_item', args.choiceId);
    if (action === 'add' && (selection?.kind !== 'product' || selection.intent !== 'cart_add'
      || !quantity(selection.quantity) || args.quantity !== selection.quantity)) throw invalid();
    if (action !== 'add' && (selection?.kind !== 'cart_item' || selection.intent !== `cart_${action}`
      || (action === 'update' && (!quantity(selection.quantity) || args.quantity !== selection.quantity)))) throw invalid();
    return mutate('prepareCart', `cart.${action}`, { action, choiceId: args.choiceId.toLowerCase(),
      ...(action === 'remove' ? {} : { quantity: args.quantity }) }, invocation);
  });
  tool.set('cart.coupon_prepare', async (args, invocation) => {
    if (!exact(args, ['code']) || selection) throw invalid();
    const couponOrigin = operationOrigin(sessionId, requestId, CouponAgent.TOOL, invocation);
    await check();
    const couponProposal = CouponAgent.prepare({ code: args.code, message, sourceOrigin: couponOrigin });
    await check();
    return Object.freeze({ status: 'confirmation_required', couponProposal, couponOrigin });
  });
  tool.set(Ticket.TOOL, async (args, invocation) => {
    if (!exact(args, ['requestRef']) || selection || ticketRequestRef === null
      || args.requestRef !== ticketRequestRef) throw invalid();
    const ticketOrigin = operationOrigin(sessionId, requestId, Ticket.TOOL, invocation);
    await check();
    let ticketProposal;
    try { ticketProposal = Ticket.prepare({ ...Ticket.humanRequest(message), message, sourceOrigin: ticketOrigin }); }
    catch { throw invalid(); }
    await check();
    return Object.freeze({ status: 'confirmation_required', ticketProposal, ticketOrigin });
  });
  tool.set('orders.list', async args => {
    const keys=Object.keys(args||{});
    if(!args||Object.getPrototypeOf(args)!==Object.prototype||keys.some(key=>!['cursor','productName'].includes(key)))throw invalid();
    const name=args.productName===undefined||args.productName===''?null:productName(args.productName);
    if(args.cursor!==undefined&&args.cursor!==''&&(!choiceId(args.cursor)||availableOrderCursor===null
      ||args.cursor.toLowerCase()!==availableOrderCursor||name!==availableOrderProductName))throw invalid();
    return read('ordersList',{...(args.cursor===undefined||args.cursor===''?{}:{cursor:args.cursor.toLowerCase()}),
      ...(name===null?{}:{productName:name})});
  });
  tool.set('orders.details', async args => {
    if (!exact(args, ['choiceId']) || !choiceId(args.choiceId)) throw invalid();
    selectedMatches(selection, 'order', args.choiceId);
    return read('orderDetails', { choiceId: args.choiceId.toLowerCase() });
  });
  tool.set('orders.refund_setup', async args => {
    if (!exact(args, ['choiceId']) || !choiceId(args.choiceId) || selection?.kind !== 'order'
      || selection.intent === 'order_details') throw invalid();
    selectedMatches(selection, 'order', args.choiceId);
    const current = await read('orderDetails', { choiceId: args.choiceId.toLowerCase() });
    const rawId = current?.order?.order_id;
    const orderId = typeof rawId === 'string' && /^[1-9][0-9]*$/.test(rawId) ? Number(rawId) : rawId;
    return Object.freeze({ status: 'confirmation_required', refundSetup: refundSetup({
      version: 1, kind: 'refund_setup', choiceId: args.choiceId.toLowerCase(), orderId }) });
  });
  tool.set('account.addresses', async args => {
    if (!exact(args, [])) throw invalid();
    return read('addresses', {});
  });
  tool.set('account.profile', async args => {
    if (!exact(args, []) || typeof profileForm !== 'function') throw invalid();
    await check(); const current = await profileForm(); await check();
    const fields = Profile.normalizeProfileView(current?.fields);
    return Object.freeze({ profile: fields });
  });
  tool.set('account.profile_update_prepare', async (args, invocation) => {
    if (!exact(args, ['patch']) || typeof profileForm !== 'function' || selection) throw invalid();
    const patch = Profile.normalizeProfilePatch(args.patch);
    if (Object.values(patch).some(value => value !== null && !message.includes(value))) throw invalid();
    const origin = operationOrigin(sessionId, requestId, 'profile.update', invocation);
    await check(); const current = await profileForm(); await check();
    const before = Profile.normalizeProfileView(current?.fields);
    const after = Profile.normalizeProfileView({ ...before, ...patch });
    const proposalId = operationIdForOrigin(origin);
    const profileProposal = ProfileProposal.proposal({ version: 1, proposalId,
      scopeKey: current.scopeKey, expectedSnapshotSha256: current.expectedSnapshotSha256,
      requestSha256: Profile.profileRequestDigest({ operationId: proposalId,
        expectedSnapshotSha256: current.expectedSnapshotSha256, fields: after }),
      before, after, patch });
    await check();
    return Object.freeze({ status: 'confirmation_required', profileProposal });
  });
  const addressDraft = (args, { selectedEdit = false } = {}) => {
    const draft = normalizeAddressToolDraft(args.draft);
    if (Object.values(draft).some(value => !message.includes(value)
      && !(selectedEdit && priorHumanRequest?.includes(value)))) throw invalid();
    return draft;
  };
  tool.set('account.address_setup', async args => {
    if (!exact(args, Object.hasOwn(args || {}, 'draft') ? ['action', 'draft'] : ['action'])
      || args.action !== 'create' || selection?.kind === 'address') throw invalid();
    const addressSetup = Address.addressSetup({ version: 1, kind: 'address_setup',
      action: 'create', choiceId: null, draft: addressDraft(args) });
    await check();
    return Object.freeze({ status: 'confirmation_required', addressSetup });
  });
  tool.set('account.address_edit_setup', async args => {
    if (!exact(args, Object.hasOwn(args || {}, 'draft') ? ['choiceId', 'draft'] : ['choiceId'])
      || !choiceId(args.choiceId) || selection?.kind !== 'address'
      || selection.intent !== 'address_edit') throw invalid();
    selectedMatches(selection, 'address', args.choiceId);
    await check();
    const current = await conversation.resolveChoice(target, { ...base, choiceId: args.choiceId.toLowerCase() });
    await check();
    if (current?.kind !== 'address' || current.choiceId !== args.choiceId.toLowerCase()) throw invalid();
    const addressSetup = Address.addressSetup({ version: 1, kind: 'address_setup',
      action: 'update', choiceId: args.choiceId.toLowerCase(), draft: addressDraft(args, { selectedEdit: true }) });
    await check();
    return Object.freeze({ status: 'confirmation_required', addressSetup });
  });
  tool.set('payment.methods', async args => {
    if (!exact(args, [])) throw invalid();
    return read('paymentMethods', {});
  });
  tool.set('payment.create_method', async (args, invocation) => {
    if (!exact(args, ['scenario']) || !['approved', 'declined'].includes(args.scenario)) throw invalid();
    if (selection) throw invalid();
    await check();
    return Object.freeze({ status: 'confirmation_required', paymentSetup: paymentSetup({ version: 1,
      kind: 'practice_payment_setup', suggestedScenario: args.scenario }) });
  });
  tool.set('checkout.prepare', async (args, invocation) => {
    if (!exact(args, ['addressChoiceId', 'paymentChoiceId']) || !choiceId(args.addressChoiceId)
      || !choiceId(args.paymentChoiceId)) throw invalid();
    if (selection?.kind === 'address') {
      if (selection.intent !== 'address_checkout') throw invalid();
      selectedMatches(selection, 'address', args.addressChoiceId);
    }
    else if (selection?.kind === 'payment_method') selectedMatches(selection, 'payment_method', args.paymentChoiceId);
    else if (selection) throw invalid();
    if (selectedChoices.address && selectedChoices.address !== args.addressChoiceId.toLowerCase()) throw invalid();
    if (selectedChoices.payment_method && selectedChoices.payment_method !== args.paymentChoiceId.toLowerCase()) throw invalid();
    return mutate('prepareCheckout', 'checkout.prepare', { addressChoiceId: args.addressChoiceId.toLowerCase(),
      paymentChoiceId: args.paymentChoiceId.toLowerCase() }, invocation);
  });
  return tool;
}

module.exports = { COMMERCE_TOOLS, cards, paymentSetup, refundSetup, operationOrigin, customerSelection,
  normalizeAddressToolDraft, createCustomerCommerceTools };
