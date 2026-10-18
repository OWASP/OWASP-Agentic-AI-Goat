import { decodeCustomerCards } from './customerCards.mjs';
import { trustedTurnMode } from './turnModeCapability.mjs';

const SHA = /^[a-f0-9]{64}$/;
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(?:\d{3}|\d{6})Z$/;
const STATUSES = new Set(['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']);
const PAYMENTS = new Set(['pending', 'approved', 'declined', 'refunded']);
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const boundedText = (value, bytes) => typeof value === 'string' && !!value.trim()
  && encoder.encode(value).byteLength <= bytes;
const id = (value, maximum = Number.MAX_SAFE_INTEGER) => {
  if (!(typeof value === 'number' || typeof value === 'string') || !/^[1-9]\d{0,15}$/.test(String(value))) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= maximum ? String(number) : null;
};
const amount = value => {
  if (!(typeof value === 'number' || typeof value === 'string')) return null;
  const match = /^(\d{1,13})(?:\.(\d{1,2}))?$/.exec(String(value));
  if (!match) return null;
  const cents = Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0'));
  return Number.isSafeInteger(cents)
    ? `$${Math.trunc(cents / 100)}.${String(cents % 100).padStart(2, '0')}` : null;
};
const mode = value => exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
  && !!trustedTurnMode(value) && value.featureId === 'customer_chat'
  && exact(value.scope, ['kind', 'id']) && value.scope.kind === 'launch_feature'
  && value.scope.id === 'customer_chat';
const sameMode = (left, right) => mode(left) && mode(right)
  && left.version === right.version && left.featureId === right.featureId
  && left.policyVersion === right.policyVersion && left.effectiveMode === right.effectiveMode
  && left.scope.kind === right.scope.kind && left.scope.id === right.scope.id;

// The turn and hop arrive only from the protected, exact saved-turn GET. The
// model reply and streamed cards never provide authority for this detail view.
export function decodeSelectedOrderDetails(turn) {
  if (turn?.status !== 'done' || turn.stopReason !== 'end_turn' || !mode(turn.modeCapability)
    || !Array.isArray(turn.cards) || turn.cards.length !== 1 || turn.cards[0]?.kind !== 'order'
    || !Array.isArray(turn.hops)) return null;
  let savedCards;
  try { savedCards = decodeCustomerCards(turn.cards); } catch { return null; }
  const savedCard = savedCards[0];
  const reads = turn.hops.filter(hop => hop?.tool === 'orders.details');
  if (reads.length !== 1) return null;
  const hop = reads[0];
  if (hop.status !== 'ok' || hop.error || !sameMode(hop.modeCapability, turn.modeCapability)
    || !exact(hop.params, ['choiceId']) || hop.params.choiceId !== savedCard.choiceId) return null;
  const envelope = hop.result;
  if (!exact(envelope, ['content']) || !Array.isArray(envelope.content) || envelope.content.length !== 1) return null;
  const part = envelope.content[0];
  if (!exact(part, ['type', 'text']) || part.type !== 'text' || typeof part.text !== 'string') return null;
  let result;
  try { result = JSON.parse(part.text); } catch { return null; }
  if (!exact(result, ['cards', 'order', 'scopeKey']) || !SHA.test(result.scopeKey)
    || !Array.isArray(result.cards) || result.cards.length !== 1) return null;
  let resultCards;
  try { resultCards = decodeCustomerCards(result.cards); } catch { return null; }
  if (!exact(resultCards[0], ['version', 'kind', 'choiceId', 'title', 'detail'])
    || Object.keys(savedCard).some(key => resultCards[0][key] !== savedCard[key])) return null;
  const order = result.order;
  if (!exact(order, ['order_id', 'total_amount', 'status', 'payment_status', 'order_date', 'shipping_address', 'items'])
    || !id(order.order_id) || savedCard.title !== `Order #${id(order.order_id)}`
    || !STATUSES.has(order.status) || !PAYMENTS.has(order.payment_status)
    || typeof order.order_date !== 'string' || !DATE.test(order.order_date)
    || !Number.isFinite(Date.parse(order.order_date))
    || !boundedText(order.shipping_address, 4096) || !amount(order.total_amount)
    || !Array.isArray(order.items)) return null;
  const items = [];
  for (const item of order.items) {
    if (!exact(item, ['product_id', 'product_name', 'quantity', 'price'])
      || !id(item.product_id, 2147483647) || !boundedText(item.product_name, 4096)
      || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 99
      || !amount(item.price)) return null;
    items.push({ name: item.product_name, quantity: item.quantity, unitPrice: amount(item.price) });
  }
  return { orderNumber: id(order.order_id), date: order.order_date.slice(0, 10),
    status: order.status, paymentStatus: order.payment_status, total: amount(order.total_amount),
    shippingAddress: order.shipping_address, items };
}
