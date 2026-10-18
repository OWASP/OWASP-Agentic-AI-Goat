const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KINDS = new Set(['product', 'cart_item', 'order', 'address', 'payment_method']);
const encoder = new TextEncoder();

export function decodeCustomerCards(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 12) throw new Error('Invalid customer choices');
  const seen = new Set();
  return value.map(card => {
    const quantityPresent = Object.hasOwn(card || {}, 'quantity');
    if (!card || Object.getPrototypeOf(card) !== Object.prototype
      || Object.keys(card).sort().join(',') !== ['choiceId', 'detail', 'kind', 'title', 'version',
        ...(quantityPresent ? ['quantity'] : [])].sort().join(',')
      || card.version !== 1 || !KINDS.has(card.kind)
      || (quantityPresent && (card.kind !== 'cart_item' || !Number.isSafeInteger(card.quantity)
        || card.quantity < 1 || card.quantity > 99))
      || typeof card.choiceId !== 'string' || !UUID.test(card.choiceId)
      || seen.has(card.choiceId.toLowerCase())
      || typeof card.title !== 'string' || !card.title.trim()
      || encoder.encode(card.title).byteLength > 256
      || typeof card.detail !== 'string' || !card.detail.trim()
      || encoder.encode(card.detail).byteLength > 512) {
      throw new Error('Invalid customer choices');
    }
    seen.add(card.choiceId.toLowerCase());
    return Object.freeze({ ...card, choiceId: card.choiceId.toLowerCase() });
  });
}
