const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const cents = value => Number.isSafeInteger(value) && value >= 0;
const decimalCents = value => {
  const match = /^(\d{1,10})(?:\.(\d{1,2}))?$/.exec(String(value));
  return match ? Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0')) : null;
};
const text = (value, max) => typeof value === 'string' && !!value.trim()
  && !value.includes('\0') && encoder.encode(value).byteLength <= max;
const summary = value => exact(value, ['choiceId', 'title', 'detail'])
  && UUID.test(value.choiceId) && text(value.title, 256) && text(value.detail, 512);
const cartKinds = new Set(['cart.add', 'cart.update', 'cart.remove']);

export function decodeCartRejection(value, operationId) {
  if (!exact(value, ['version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || value.version !== 1 || value.operationId !== operationId
    || value.kind !== 'cart.add' || value.status !== 'rejected' || value.replayed !== true
    || !exact(value.result, ['code', 'choiceId', 'quantity'])
    || value.result.code !== 'INSUFFICIENT_STOCK'
    || typeof value.result.choiceId !== 'string'
    || !UUID.test(value.result.choiceId) || value.result.choiceId !== value.result.choiceId.toLowerCase()
    || !Number.isInteger(value.result.quantity)
    || value.result.quantity < 1 || value.result.quantity > 99) {
    throw new Error('Invalid saved cart rejection');
  }
  return Object.freeze({ code: value.result.code,
    choiceId: value.result.choiceId, quantity: value.result.quantity });
}

export function decodeCartProposal(value) {
  const choiceQuantityPresent = Object.hasOwn(value?.choice || {}, 'quantity');
  if (!exact(value, ['version', 'proposalId', 'status', 'kind', 'choice', 'quantity', 'quoteSha256'])
    || value.version !== 1 || !UUID.test(value.proposalId) || value.status !== 'prepared'
    || !cartKinds.has(value.kind) || !SHA.test(value.quoteSha256)
    || !exact(value.choice, ['version', 'kind', 'choiceId', 'title', 'detail',
      ...(choiceQuantityPresent ? ['quantity'] : [])])
    || value.choice.version !== 1 || value.choice.kind !== (value.kind === 'cart.add' ? 'product' : 'cart_item')
    || (choiceQuantityPresent && (value.choice.kind !== 'cart_item'
      || !Number.isSafeInteger(value.choice.quantity) || value.choice.quantity < 1 || value.choice.quantity > 99))
    || !summary({ choiceId: value.choice.choiceId, title: value.choice.title,
      detail: value.choice.detail })
    || (value.kind === 'cart.remove' ? value.quantity !== null
      : !Number.isSafeInteger(value.quantity) || value.quantity < 1 || value.quantity > 99)) {
    throw new Error('Invalid saved cart proposal');
  }
  return value;
}

export function decodeCheckoutProposal(value) {
  if (!exact(value, ['version', 'proposalId', 'status', 'currency', 'items', 'subtotalCents',
    'discountCents', 'totalCents', 'address', 'paymentMethod', 'quoteSha256'])
    || value.version !== 1 || !UUID.test(value.proposalId) || value.status !== 'prepared'
    || value.currency !== 'USD' || !SHA.test(value.quoteSha256) || !summary(value.address)
    || !summary(value.paymentMethod) || !Array.isArray(value.items)
    || value.items.length < 1 || value.items.length > 50) throw new Error('Invalid saved checkout proposal');
  let subtotal = 0;
  for (const item of value.items) {
    if (!exact(item, ['productId', 'name', 'quantity', 'unitPriceCents', 'lineTotalCents'])
      || !Number.isSafeInteger(item.productId) || item.productId < 1
      || !text(item.name, 256) || !Number.isSafeInteger(item.quantity)
      || item.quantity < 1 || item.quantity > 99 || !cents(item.unitPriceCents)
      || !cents(item.lineTotalCents)
      || item.lineTotalCents !== item.quantity * item.unitPriceCents) {
      throw new Error('Invalid saved checkout proposal');
    }
    subtotal += item.lineTotalCents;
  }
  if (!cents(value.subtotalCents) || !cents(value.discountCents) || !cents(value.totalCents)
    || subtotal !== value.subtotalCents
    || value.totalCents !== value.subtotalCents - value.discountCents) {
    throw new Error('Invalid saved checkout proposal');
  }
  return value;
}

export function decodeCustomerTurnOperations(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 4) throw new Error('Invalid saved customer actions');
  const seen = new Set();
  return value.map(row => {
    const keys = ['operationId', 'status', ...(Object.hasOwn(row || {}, 'proposal') ? ['proposal'] : []),
      ...(Object.hasOwn(row || {}, 'receipt') ? ['receipt'] : [])];
    if (!exact(row, keys) || !UUID.test(row.operationId)
      || !['prepared', 'completed'].includes(row.status) || seen.has(row.operationId.toLowerCase())) {
      throw new Error('Invalid saved customer actions');
    }
    seen.add(row.operationId.toLowerCase());
    const proposal = Object.hasOwn(row, 'proposal')
      ? (Object.hasOwn(row.proposal || {}, 'kind')
        ? decodeCartProposal(row.proposal) : decodeCheckoutProposal(row.proposal)) : null;
    if (proposal && proposal.proposalId.toLowerCase() !== row.operationId.toLowerCase()) {
      throw new Error('Saved checkout identity mismatch');
    }
    const rejection = row.receipt?.status === 'rejected'
      ? decodeCartRejection(row.receipt, row.operationId) : null;
    if (rejection && (row.status !== 'completed' || proposal)) {
      throw new Error('Invalid saved cart rejection');
    }
    // Other domain actions have their own typed receipts. Their existence is
    // projected here without rendering model or unvalidated receipt fields.
    return Object.freeze({ operationId: row.operationId.toLowerCase(), status: row.status,
      ...(proposal ? { proposal } : {}), ...(rejection ? { rejection } : {}),
      hasReceipt: Object.hasOwn(row, 'receipt') });
  });
}

export function decodeCartConfirmation(value) {
  if (!exact(value, ['version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || value.version !== 1 || !UUID.test(value.operationId) || !cartKinds.has(value.kind)
    || !['completed', 'stale'].includes(value.status) || value.replayed !== true) {
    throw new Error('Invalid saved cart receipt');
  }
  if (value.status === 'stale') {
    if (value.result !== null) throw new Error('Invalid saved cart receipt');
  } else if (value.kind === 'cart.add') {
    if (!exact(value.result, ['id']) || !Number.isSafeInteger(value.result.id) || value.result.id < 1) {
      throw new Error('Invalid saved cart receipt');
    }
  } else if (!exact(value.result, ['changed']) || !Number.isSafeInteger(value.result.changed)
    || value.result.changed < 0) {
    throw new Error('Invalid saved cart receipt');
  }
  return value;
}

export function decodeCartOperation(value, reference) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || value.scopeKey !== reference.scopeKey || !SHA.test(value.scopeKey)
    || value.operationId !== reference.operationId
    || !['prepared', 'completed'].includes(value.status)) {
    throw new Error('Saved cart change is not confirmed');
  }
  const proposal = decodeCartProposal(value.proposal);
  if (proposal.proposalId !== reference.operationId || proposal.quoteSha256 !== reference.intentDigest) {
    throw new Error('Saved cart proposal changed');
  }
  if (value.status === 'prepared') {
    if (value.receipt !== undefined) throw new Error('Invalid saved cart outcome');
    return { status: 'prepared', proposal };
  }
  const receipt = decodeCartConfirmation(value.receipt);
  if (receipt.operationId !== reference.operationId || receipt.kind !== proposal.kind) {
    throw new Error('Saved cart receipt mismatch');
  }
  return { status: 'completed', proposal, receipt };
}

export function decodeCheckoutConfirmation(value) {
  if (!exact(value, ['version', 'operationId', 'kind', 'status', 'currency', 'totalCents', 'order', 'replayed'])
    || value.version !== 1 || !UUID.test(value.operationId) || value.kind !== 'checkout.confirm'
    || !['approved', 'declined', 'stale'].includes(value.status) || value.currency !== 'USD'
    || !cents(value.totalCents) || value.replayed !== true) {
    throw new Error('Invalid saved checkout receipt');
  }
  if (value.status !== 'approved' && value.order !== null) throw new Error('Invalid saved checkout receipt');
  if (value.status === 'approved' && (!exact(value.order, ['orderId', 'total', 'subtotal', 'discount'])
    || !Number.isSafeInteger(value.order.orderId) || value.order.orderId < 1
    || decimalCents(value.order.total) !== value.totalCents
    || decimalCents(value.order.subtotal) === null || decimalCents(value.order.discount) === null
    || decimalCents(value.order.total) !== decimalCents(value.order.subtotal)
      - decimalCents(value.order.discount))) {
    throw new Error('Invalid saved checkout receipt');
  }
  return value;
}

export function decodeCheckoutOperation(value, reference) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || !SHA.test(value.scopeKey) || value.scopeKey !== reference.scopeKey
    || value.operationId !== reference.operationId
    || !['prepared', 'completed'].includes(value.status)) {
    throw new Error('Saved checkout outcome is not confirmed');
  }
  const proposal = decodeCheckoutProposal(value.proposal);
  if (proposal.proposalId !== reference.operationId || proposal.quoteSha256 !== reference.intentDigest) {
    throw new Error('Saved checkout quote changed');
  }
  if (value.status === 'prepared') {
    if (value.receipt !== undefined) throw new Error('Invalid saved checkout outcome');
    return { status: 'prepared', proposal };
  }
  const receipt = decodeCheckoutConfirmation(value.receipt);
  if (receipt.operationId !== reference.operationId || receipt.totalCents !== proposal.totalCents) {
    throw new Error('Saved checkout receipt mismatch');
  }
  return { status: 'completed', proposal, receipt };
}
