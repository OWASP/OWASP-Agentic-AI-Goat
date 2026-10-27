import { compileOperation, matchOperationRequest } from './operations.mjs';

const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const listing = { name: 'Merchant title', description: 'Literal <em>text</em>', price: 12.34,
  category: 'Books', images: ['https://images.test/one.png'], templateSource: '{{ title }}' };
const preview = { version: 1, origin: 'manual', kind: 'create', listing, currency: 'USD',
  initialStock: 0, status: 'active', scopeKey: 'a'.repeat(64), requestSha256: 'b'.repeat(64) };
const base = '/api/secureshop/merchant/listings/manual';

test('closed bridge registers manual readiness, full-field previews, confirm, and GET-only recovery', () => {
  for (const [name, path, method, body] of [
    ['merchant.listings.manualReadiness', `${base}/readiness`, 'GET'],
    ['merchant.listings.manualCreatePreview', `${base}/create/preview`, 'POST', { listing }],
    ['merchant.listings.manualEditPreview', `${base}/edit/preview`, 'POST', { productId: 7, listing }],
    ['merchant.listings.manualCreateConfirm', `${base}/create/confirm`, 'POST', { operationId, preview }],
    ['merchant.listings.manualEditConfirm', `${base}/edit/confirm`, 'POST', { operationId, preview: { ...preview, kind: 'edit' } }],
    ['merchant.listings.manualCreateOperation', `${base}/create/operations/${operationId}`, 'GET'],
    ['merchant.listings.manualEditOperation', `${base}/edit/operations/${operationId}`, 'GET'],
  ]) {
    const matched = matchOperationRequest({ pathname: path, method, ...(body ? { body } : {}) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method });
  }
  expect(() => matchOperationRequest({ pathname: `${base}/create/preview`, method: 'POST',
    body: { listing: { ...listing, supplierToken: 'not allowed' } } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/create/confirm`, method: 'POST',
    body: { operationId, preview, retry: true } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/create/operations/${operationId}`, method: 'POST' })).toThrow();
});
