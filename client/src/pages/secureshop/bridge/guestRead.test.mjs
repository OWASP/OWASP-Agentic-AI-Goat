import { compileGuestRead } from './guestRead.mjs';
import { safeShopRoute, guestNavigationIntent } from './guestRouting.mjs';

test('guest operation catalog remaps only public GETs', () => {
  expect(compileGuestRead('catalog.list', { query: { search: 'camera', limit: '8' } }))
    .toMatchObject({ method: 'GET', path: '/api/secureshop/public/products?search=camera&limit=8' });
  expect(compileGuestRead('catalog.list', { query: { minRating: '5', maxPrice: '200' } }).path)
    .toBe('/api/secureshop/public/products?minRating=5&maxPrice=200');
  expect(compileGuestRead('catalog.categories', {}).path).toBe('/api/secureshop/public/categories');
  expect(compileGuestRead('catalog.product.get', { params: { id: '7' } }).path)
    .toBe('/api/secureshop/public/products/7');
  expect(compileGuestRead('catalog.product.reviews.list', { params: { id: '7' }, query: { limit: '20', offset: '20' } }).path)
    .toBe('/api/secureshop/public/products/7/reviews?limit=20&offset=20');
  expect(compileGuestRead('catalog.product.similar', { params: { id: '7' } }).path)
    .toBe('/api/secureshop/public/products/7/related');
  expect(() => compileGuestRead('catalog.product.summary', { params: { id: '7' } })).toThrow();
  expect(() => compileGuestRead('cart.add', { body: { product_id: 7 } })).toThrow();
  expect(() => compileGuestRead('catalog.product.get', { params: { id: '../admin' } })).toThrow();
});

test('guest route contract preserves product deep links and rejects authority paths', () => {
  expect(safeShopRoute('/secureshop/product/7?color=blue')).toBe('/secureshop/product/7?color=blue');
  expect(guestNavigationIntent('/secureshop/catalog?q=Disposable+QA+notebook'))
    .toEqual({ kind: 'route', route: '/secureshop/catalog?q=Disposable+QA+notebook' });
  expect(compileGuestRead('catalog.list', { query: { search: 'Disposable QA notebook', limit: '24' } }).path)
    .toBe('/api/secureshop/public/products?search=Disposable%20QA%20notebook&limit=24');
  expect(safeShopRoute('/secureshop/admin')).toBeNull();
  expect(safeShopRoute('//evil.example/secureshop/product/7')).toBeNull();
  expect(guestNavigationIntent('/secureshop/login?next=%2Fsecureshop%2Fadmin', '/secureshop/product/7'))
    .toEqual({ kind: 'auth', route: '/secureshop/product/7' });
  expect(guestNavigationIntent('/secureshop/register', '/secureshop/product/7'))
    .toEqual({ kind: 'register', route: '/secureshop/product/7' });
  expect(guestNavigationIntent('/secureshop/register?next=https%3A%2F%2Fevil.example', '/secureshop/cart'))
    .toEqual({ kind: 'register', route: '/secureshop/cart' });
  expect(guestNavigationIntent('/secureshop/checkout', '/secureshop/cart'))
    .toEqual({ kind: 'auth', route: '/secureshop/checkout' });
});
