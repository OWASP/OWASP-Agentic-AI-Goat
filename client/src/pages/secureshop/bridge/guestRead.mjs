import { compileBridgeOperation } from './compiler.mjs';

// Anonymous frames can ask the parent for these catalog reads only.
// The server's public router makes the same distinction independently.
const READS = Object.freeze({
  'catalog.list': /^\/api\/secureshop\/products(?:\?|$)/,
  'catalog.categories': /^\/api\/secureshop\/categories(?:\?|$)/,
  'catalog.product.get': /^\/api\/secureshop\/products\/[1-9]\d*(?:\?|$)/,
  'catalog.product.reviews.list': /^\/api\/secureshop\/products\/[1-9]\d*\/reviews(?:\?|$)/,
  'catalog.product.similar': /^\/api\/secureshop\/products\/[1-9]\d*\/similar(?:\?|$)/,
});

export const isGuestReadOperation = name => typeof name === 'string' && Object.hasOwn(READS, name);

export function compileGuestRead(name, input) {
  if (!isGuestReadOperation(name)) throw new TypeError('Guest catalog read unavailable');
  const request = compileBridgeOperation(name, input);
  if (request.method !== 'GET' || request.body !== undefined || !READS[name].test(request.path)) {
    throw new TypeError('Guest catalog read unavailable');
  }
  const path = request.path.replace('/api/secureshop/', '/api/secureshop/public/')
    .replace(/\/similar(?=\?|$)/, '/related');
  return Object.freeze({ ...request, path });
}
