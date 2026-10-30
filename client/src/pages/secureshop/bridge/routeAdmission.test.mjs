import { guestNavigationIntent, safeShopRoute } from './guestRouting.mjs';
import { safeLoginDestination } from '../utils/loginDestination.mjs';

const customer = { role: 'customer' };
const merchant = { role: 'merchant' };
const admin = { role: 'admin' };

describe('OWASP AI SecureShop mounted route admission', () => {
  test('keeps mounted public product and catalog routes and exact customer destinations', () => {
    expect(safeShopRoute('/secureshop/product/7?color=blue')).toBe('/secureshop/product/7?color=blue');
    expect(safeShopRoute('/secureshop/v2/catalog?q=book')).toBe('/secureshop/v2/catalog?q=book');
    for (const route of ['/secureshop/home', '/secureshop/orders', '/secureshop/account',
      '/secureshop/v2/orders', '/secureshop/v2/account']) {
      expect(safeShopRoute(route, { publicOnly: false })).toBe(route);
      expect(safeLoginDestination(route, customer)).toBe(route);
    }
    expect(safeLoginDestination('/secureshop/product/7?color=blue', customer))
      .toBe('/secureshop/product/7?color=blue');
  });

  test('preserves only the finite storefront fragments used by mounted links', () => {
    for (const fragment of ['#about', '#how', '#agent-lane', '#lab-notes']) {
      expect(safeShopRoute(`/secureshop${fragment}`)).toBe(`/secureshop${fragment}`);
    }
    expect(safeShopRoute('/secureshop/merchant/listings#new', { publicOnly: false }))
      .toBe('/secureshop/merchant/listings#new');
    expect(safeShopRoute('/secureshop/merchant/listings#p12', { publicOnly: false }))
      .toBe('/secureshop/merchant/listings#p12');
    for (const route of ['/secureshop#other', '/secureshop#%61bout',
      '/secureshop/merchant/listings#p0', '/secureshop/merchant/listings#javascript',
      '/secureshop/admin/users#new']) {
      expect(safeShopRoute(route, { publicOnly: false })).toBeNull();
      expect(safeLoginDestination(route, admin)).toBe('/secureshop/admin');
    }
  });

  test('maps legacy home and order-detail intentions to mounted pages without admitting missing routes', () => {
    expect(safeShopRoute('/secureshop/v2/home', { publicOnly: false })).toBe('/secureshop/v2');
    expect(safeLoginDestination('/secureshop/v2/home?tab=orders', customer))
      .toBe('/secureshop/v2?tab=orders');
    expect(guestNavigationIntent('/secureshop/v2/home')).toEqual({ kind: 'auth', route: '/secureshop/v2' });
    for (const [missing, mounted] of [
      ['/secureshop/orders/123', '/secureshop/orders'],
      ['/secureshop/v2/orders/123', '/secureshop/v2/orders'],
    ]) {
      expect(safeShopRoute(missing, { publicOnly: false })).toBeNull();
      expect(safeLoginDestination(missing, customer)).toBe(mounted);
      expect(safeLoginDestination(missing, merchant)).toBe('/secureshop/merchant');
    }
  });

  test('rejects malformed prefixes and unsupported account, product and role routes', () => {
    for (const route of ['/secureshop/account-typo', '/secureshop/account/keys',
      '/secureshop/orders-later', '/secureshop/product/not-a-number',
      '/secureshop/catalog-extra', '/secureshop/v2/home-extra',
      '/secureshop/merchant/unknown', '/secureshop/admin/unknown']) {
      expect(safeShopRoute(route, { publicOnly: false })).toBeNull();
      expect(safeLoginDestination(route, customer)).toBe('/secureshop/home');
    }
  });

  test('preserves exact protected and role destinations without crossing roles', () => {
    expect(safeShopRoute('/secureshop/checkout')).toBeNull();
    expect(guestNavigationIntent('/secureshop/checkout', '/secureshop/product/7'))
      .toEqual({ kind: 'auth', route: '/secureshop/checkout' });
    expect(safeLoginDestination('/secureshop/checkout', customer)).toBe('/secureshop/checkout');
    expect(safeLoginDestination('/secureshop/checkout', admin)).toBe('/secureshop/admin');
    expect(safeShopRoute('/secureshop/merchant/listings', { publicOnly: false }))
      .toBe('/secureshop/merchant/listings');
    expect(safeShopRoute('/secureshop/admin/audit', { publicOnly: false }))
      .toBe('/secureshop/admin/audit');
    expect(safeShopRoute('/secureshop/admin/tickets', { publicOnly: false }))
      .toBe('/secureshop/admin/tickets');
    expect(safeLoginDestination('/secureshop/merchant/listings', merchant))
      .toBe('/secureshop/merchant/listings');
    expect(safeLoginDestination('/secureshop/merchant/listings#new', merchant))
      .toBe('/secureshop/merchant/listings#new');
    expect(safeLoginDestination('/secureshop/admin/audit', admin))
      .toBe('/secureshop/admin/audit');
    expect(safeLoginDestination('/secureshop/merchant/listings', customer))
      .toBe('/secureshop/home');
    expect(safeLoginDestination('/secureshop/admin/audit', merchant))
      .toBe('/secureshop/merchant');
  });
});
