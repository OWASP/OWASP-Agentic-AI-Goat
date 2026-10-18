import { compileOperation, matchOperationRequest } from './operations.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

test('catalog continuation sends only a saved request reference and excludes other choices', () => {
  const continuation = { intent: 'catalog_next', sourceRequestId: id };
  for (const [name, pathname] of [
    ['agent.customer.chat', '/api/secureshop/agents/customer/chat'],
    ['agent.merchant.assistant.chat', '/api/secureshop/agents/merchant/assistant/chat'],
  ]) {
    const body = { sessionId: id, requestId: id, message: 'Show more products',
      catalogContinuation: continuation };
    expect(compileOperation(name, { body }).body).toEqual(body);
    expect(matchOperationRequest({ pathname, method: 'POST', body })?.name).toBe(name);
    for (const invalid of [
      { ...body, catalogContinuation: { ...continuation, cursor: 'private' } },
      { ...body, catalogContinuation: { ...continuation, intent: 'orders_next' } },
      { ...body, catalogContinuation: { ...continuation, sourceRequestId: 'foreign' } },
      { ...body, selection: { choiceId: id } },
      { ...body, message: 'Search again' },
    ]) {
      expect(() => compileOperation(name, { body: invalid })).toThrow();
      expect(() => matchOperationRequest({ pathname, method: 'POST', body: invalid })).toThrow();
    }
  }
  expect(() => compileOperation('agent.admin.assistant.chat', { body: {
    sessionId: id, requestId: id, message: 'Show more products', catalogContinuation: continuation,
  } })).toThrow();
});

test('cart and listing confirmations require their complete closed ID bodies', () => {
  for (const [name, pathname, valid] of [
    ['customer.commerce.cart.confirm', '/api/secureshop/customer/commerce/cart/confirm',
      { proposalId: id }],
    ['agent.merchant.assistant.listingCreateConfirm',
      '/api/secureshop/agents/merchant/assistant/listing-create/confirm',
      { sessionId: id, requestId: id, proposalId: id }],
  ]) {
    expect(compileOperation(name, { body: valid }).body).toEqual(valid);
    expect(matchOperationRequest({ pathname, method: 'POST', body: valid })?.name).toBe(name);
    for (const invalid of [undefined, {}, null, [],
      ...Object.keys(valid).map(key => Object.fromEntries(Object.entries(valid).filter(([item]) => item !== key))),
      { ...valid, quantity: 2 }, { ...valid, productId: 7 }]) {
      const input = invalid === undefined ? {} : { body: invalid };
      expect(() => compileOperation(name, input)).toThrow();
      expect(() => matchOperationRequest({ pathname, method: 'POST', ...input })).toThrow();
    }
  }
});

test('bound customer session retains an empty JSON body before chat', () => {
  const path = '/api/secureshop/agents/customer/session';
  const matched = matchOperationRequest({ pathname: path, method: 'POST', body: {} });
  expect(matched.name).toBe('agent.customer.session');
  expect(compileOperation(matched.name, matched.input)).toEqual({
    path, method: 'POST', responseKind: 'json', body: {},
  });
  expect(compileOperation('agent.customer.session', { body: { userId: 7 } }).body)
    .toEqual({ userId: 7 });
  expect(() => compileOperation('agent.customer.session', { body: { tenantId: 7 } }))
    .toThrow();
});

test('customer chat admits only the closed opaque selection body', () => {
  const body = { sessionId: id, requestId: id, message: 'Use my selected option.',
    selection: { choiceId: id } };
  expect(compileOperation('agent.customer.chat', { body })).toMatchObject({
    path: '/api/secureshop/agents/customer/chat', method: 'POST', responseKind: 'sse', body,
  });
  expect(matchOperationRequest({ pathname: '/api/secureshop/agents/customer/chat',
    method: 'POST', body })).toMatchObject({ name: 'agent.customer.chat' });
  expect(() => compileOperation('agent.customer.chat', { body: {
    ...body, selection: { choiceId: id, productId: 7 },
  } })).toThrow();
  for (const selection of [
    { choiceId: id, intent: 'details' },
    { choiceId: id, intent: 'order_details' },
    { choiceId: id, intent: 'address_checkout' },
    { choiceId: id, intent: 'address_edit' },
    { choiceId: id, intent: 'cart_add', quantity: 1 },
    { choiceId: id, intent: 'cart_add', quantity: 99 },
    { choiceId: id, intent: 'cart_update', quantity: 1 },
    { choiceId: id, intent: 'cart_update', quantity: 99 },
    { choiceId: id, intent: 'cart_remove' },
  ]) {
    expect(compileOperation('agent.customer.chat', { body: { ...body, selection } }).body.selection)
      .toEqual(selection);
    expect(matchOperationRequest({ pathname: '/api/secureshop/agents/customer/chat',
      method: 'POST', body: { ...body, selection } })).toMatchObject({ name: 'agent.customer.chat' });
  }
  for (const selection of [
    { choiceId: id, intent: 'details', quantity: 1 },
    { choiceId: id, intent: 'order_details', quantity: 1 },
    { choiceId: id, intent: 'address_checkout', quantity: 1 },
    { choiceId: id, intent: 'address_edit', addressId: 7 },
    { choiceId: id, intent: 'cart_add' },
    { choiceId: id, intent: 'cart_add', quantity: 0 },
    { choiceId: id, intent: 'cart_add', quantity: 100 },
    { choiceId: id, intent: 'cart_add', quantity: 1.5 },
    { choiceId: id, intent: 'cart_update' },
    { choiceId: id, intent: 'cart_update', quantity: 0 },
    { choiceId: id, intent: 'cart_update', quantity: 100 },
    { choiceId: id, intent: 'cart_update', quantity: 1.5 },
    { choiceId: id, intent: 'cart_remove', quantity: 1 },
    { choiceId: id, intent: 'remove' },
    { choiceId: id, intent: 'cart_add', quantity: 1, productId: 7 },
  ]) expect(() => compileOperation('agent.customer.chat', { body: { ...body, selection } })).toThrow();
});

test('synthetic commerce routes accept only frozen bodies and exact operation path', () => {
  const cases = [
    ['customer.commerce.addresses', 'GET', '/api/secureshop/customer/commerce/addresses', undefined],
    ['customer.commerce.paymentMethods.list', 'GET', '/api/secureshop/customer/commerce/payment-methods', undefined],
    ['customer.commerce.paymentMethods.create', 'POST', '/api/secureshop/customer/commerce/payment-methods',
      { operationId: id, scenario: 'approved' }],
    ['customer.commerce.checkout.prepare', 'POST', '/api/secureshop/customer/commerce/checkout/prepare',
      { operationId: id, addressChoiceId: id, paymentChoiceId: id }],
    ['customer.commerce.checkout.confirm', 'POST', '/api/secureshop/customer/commerce/checkout/confirm',
      { proposalId: id }],
    ['customer.commerce.cart.confirm', 'POST', '/api/secureshop/customer/commerce/cart/confirm',
      { proposalId: id }],
    ['customer.commerce.operation', 'GET', `/api/secureshop/customer/commerce/operations/${id}`, undefined],
  ];
  for (const [name, method, path, body] of cases) {
    const input = name === 'customer.commerce.operation'
      ? { params: { operationId: id } } : body === undefined ? {} : { body };
    expect(compileOperation(name, input)).toMatchObject({ method, path });
    expect(matchOperationRequest({ pathname: path, method, ...(body === undefined ? {} : { body }) }))
      .toMatchObject({ name });
  }
  expect(() => compileOperation('customer.commerce.checkout.confirm', {
    body: { proposalId: id, totalCents: 1 },
  })).toThrow();
  expect(() => compileOperation('customer.commerce.cart.confirm', {
    body: { proposalId: id, productId: 7 },
  })).toThrow();
  expect(() => compileOperation('customer.commerce.paymentMethods.create', {
    body: { operationId: id, scenario: 'approved', cvv: '123' },
  })).toThrow();
});

test('trusted address form and save bridge accept only the closed Q17 request', () => {
  const form = '/api/secureshop/customer/commerce/address-form';
  for (const query of [{ action: 'create' }, { action: 'update', choiceId: id }]) {
    expect(matchOperationRequest({ pathname: form, method: 'GET', query }))
      .toMatchObject({ name: 'customer.commerce.addressForm' });
    expect(compileOperation('customer.commerce.addressForm', { query }).path)
      .toBe(`${form}?${Object.entries(query).map(([key, value]) => `${key}=${value}`).join('&')}`);
  }
  const path = '/api/secureshop/customer/commerce/addresses';
  const fields = { label: null, line1: '17 Practice Lane', line2: null, city: 'Oakland',
    state: null, zip: null, phone: null, isDefault: false };
  const body = { operationId: id, action: 'create', choiceId: null,
    expectedSnapshotSha256: null, defaultSetSha256: 'a'.repeat(64), fields };
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }))
    .toMatchObject({ name: 'customer.commerce.addresses.save' });
  expect(compileOperation('customer.commerce.addresses.save', { body }).body).toEqual(body);
  expect(() => compileOperation('customer.commerce.addresses.save', {
    body: { ...body, addressId: 7 },
  })).toThrow();
  expect(() => compileOperation('customer.commerce.addresses.save', {
    body: { ...body, fields: { ...fields, userId: 7 } },
  })).toThrow();
});

test('profile form, direct save and chat confirmation use only closed Q26 bodies', () => {
  const sha = 'a'.repeat(64);
  const form = '/api/secureshop/customer/commerce/profile-form';
  expect(matchOperationRequest({ pathname: form, method: 'GET' }).name)
    .toBe('customer.commerce.profileForm');
  const fields = { fullName: 'A Customer', email: 'customer@example.test', phone: null };
  const save = { operationId: id, expectedSnapshotSha256: sha, fields };
  const path = '/api/secureshop/customer/commerce/profile';
  expect(compileOperation('customer.commerce.profile.save', { body: save })).toMatchObject({ path, body: save });
  expect(matchOperationRequest({ pathname: path, method: 'POST', body: save }).name)
    .toBe('customer.commerce.profile.save');
  expect(() => compileOperation('customer.commerce.profile.save', {
    body: { ...save, fields: { ...fields, userId: 7 } },
  })).toThrow();
  expect(() => compileOperation('customer.commerce.profile.save', {
    body: { ...save, scopeKey: sha },
  })).toThrow();
  const confirm = { sessionId: id, requestId: id, proposalId: id };
  const confirmPath = '/api/secureshop/agents/customer/profile/confirm';
  expect(compileOperation('agent.customer.profile.confirm', { body: confirm }))
    .toMatchObject({ path: confirmPath, body: confirm });
  expect(() => compileOperation('agent.customer.profile.confirm', {
    body: { ...confirm, fields },
  })).toThrow();
});

test('new role assistants are closed and distinct from legacy agent paths', () => {
  for (const role of ['merchant', 'admin']) {
    const prefix = `/api/secureshop/agents/${role}/assistant`;
    const chat = { sessionId: id, requestId: id, message: 'Show owned records' };
    expect(matchOperationRequest({ pathname: `${prefix}/session`, method: 'POST', body: {} }))
      .toMatchObject({ name: `agent.${role}.assistant.session` });
    expect(matchOperationRequest({ pathname: `${prefix}/chat`, method: 'POST', body: chat }))
      .toMatchObject({ name: `agent.${role}.assistant.chat` });
    const selected = { ...chat, selection: { choiceId: id } };
    expect(compileOperation(`agent.${role}.assistant.chat`, { body: selected }).body)
      .toEqual(selected);
    const reviewSelected = { ...chat, selection: { choiceId: id, intent: 'review_reject' } };
    if (role === 'merchant') {
      expect(compileOperation(`agent.${role}.assistant.chat`, { body: reviewSelected }).body)
        .toEqual(reviewSelected);
    } else {
      expect(() => compileOperation(`agent.${role}.assistant.chat`, { body: reviewSelected })).toThrow();
    }
    expect(matchOperationRequest({ pathname: `${prefix}/operations/${id}/${id}`, method: 'GET' }))
      .toMatchObject({ name: `agent.${role}.assistant.operation` });
    expect(() => compileOperation(`agent.${role}.assistant.chat`, {
      body: { ...chat, selection: { choiceId: id, productId: 7 } },
    })).toThrow();
    expect(() => compileOperation(`agent.${role}.assistant.chat`, {
      body: { ...chat, selection: { choiceId: id, intent: 'approve' } },
    })).toThrow();
    expect(() => compileOperation(`agent.${role}.assistant.chat`, {
      body: { ...chat, userId: 7 },
    })).toThrow();
  }
});

test('merchant inventory confirmation admits only the exact saved proposal identity', () => {
  const path = '/api/secureshop/agents/merchant/assistant/inventory/confirm';
  const body = { sessionId: id, requestId: id, proposalId: id };
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }))
    .toMatchObject({ name: 'agent.merchant.assistant.inventoryConfirm' });
  expect(compileOperation('agent.merchant.assistant.inventoryConfirm', { body }).body).toEqual(body);
  expect(() => compileOperation('agent.merchant.assistant.inventoryConfirm', {
    body: { ...body, stockChange: { productId: 7, quantity: 0 } },
  })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.inventoryConfirm', {
    body: { sessionId: id, requestId: id },
  })).toThrow();
});

test('merchant pricing confirmation admits only the saved role turn and proposal identity', () => {
  const path = '/api/secureshop/agents/merchant/assistant/pricing/confirm';
  const body = { sessionId: id, requestId: id, proposalId: id };
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }))
    .toMatchObject({ name: 'agent.merchant.assistant.pricingConfirm' });
  expect(compileOperation('agent.merchant.assistant.pricingConfirm', { body }).body).toEqual(body);
  expect(() => compileOperation('agent.merchant.assistant.pricingConfirm', {
    body: { ...body, price: 0.01 },
  })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.pricingConfirm', {
    body: { sessionId: id, requestId: id },
  })).toThrow();
});

test('merchant listing confirmation admits only the saved role turn and proposal identity', () => {
  const body = { sessionId: id, requestId: id, proposalId: id };
  const confirmPath = '/api/secureshop/agents/merchant/assistant/listing/confirm';
  const readPath = `/api/secureshop/agents/merchant/assistant/listing/operations/${id}`;
  expect(matchOperationRequest({ pathname: confirmPath, method: 'POST', body }))
    .toMatchObject({ name: 'agent.merchant.assistant.listingConfirm' });
  expect(compileOperation('agent.merchant.assistant.listingConfirm', { body }).body).toEqual(body);
  expect(matchOperationRequest({ pathname: readPath, method: 'GET' }))
    .toMatchObject({ name: 'agent.merchant.assistant.listingOperation' });
  expect(compileOperation('agent.merchant.assistant.listingOperation', { params: { operationId: id } }))
    .toMatchObject({ path: readPath, method: 'GET' });
  expect(() => compileOperation('agent.merchant.assistant.listingConfirm', {
    body: { ...body, patch: { name: 'not admitted here' } },
  })).toThrow();
});

test('merchant listing-create assessment admits only its original operation and exact readback', () => {
  const assessPath = '/api/secureshop/agents/merchant/assistant/listing-create/assess';
  const outcomePath = `/api/secureshop/agents/merchant/assistant/listing-create/assessment/${id}`;
  const body = { operationId: id };
  expect(compileOperation('agent.merchant.assistant.listingCreateAssess', { body }))
    .toEqual(expect.objectContaining({ path: assessPath, method: 'POST', body }));
  expect(matchOperationRequest({ pathname: assessPath, method: 'POST', body }))
    .toMatchObject({ name: 'agent.merchant.assistant.listingCreateAssess' });
  expect(compileOperation('agent.merchant.assistant.listingCreateAssessment', { params: { operationId: id } }))
    .toEqual(expect.objectContaining({ path: outcomePath, method: 'GET' }));
  expect(matchOperationRequest({ pathname: outcomePath, method: 'GET' }))
    .toMatchObject({ name: 'agent.merchant.assistant.listingCreateAssessment' });
  expect(() => compileOperation('agent.merchant.assistant.listingCreateAssess', { body: { ...body, evaluationId: id } })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.listingCreateAssess', {})).toThrow();
  expect(() => matchOperationRequest({ pathname: assessPath, method: 'GET' })).toThrow();
  expect(() => compileOperation('agent.admin.assistant.listingCreateAssess', { body })).toThrow();
});

test('merchant review confirmation admits only the saved role turn and proposal identity', () => {
  const path = '/api/secureshop/agents/merchant/assistant/review/confirm';
  const body = { sessionId: id, requestId: id, proposalId: id };
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }))
    .toMatchObject({ name: 'agent.merchant.assistant.reviewConfirm' });
  expect(compileOperation('agent.merchant.assistant.reviewConfirm', { body }).body).toEqual(body);
  expect(() => compileOperation('agent.merchant.assistant.reviewConfirm', {
    body: { ...body, decision: 'approve' },
  })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.reviewConfirm', {
    body: { sessionId: id, requestId: id },
  })).toThrow();
});
