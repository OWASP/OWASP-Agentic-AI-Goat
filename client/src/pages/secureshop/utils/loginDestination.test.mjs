import { safeLoginDestination } from './loginDestination.mjs';

describe('safeLoginDestination', () => {
  const customer = { role: 'customer' };
  const merchant = { role: 'merchant' };
  const admin = { role: 'admin' };

  test('preserves mounted local paths and finite fragments', () => {
    expect(safeLoginDestination('/secureshop#about', customer))
      .toBe('/secureshop#about');
    expect(safeLoginDestination('/secureshop/merchant/listings#new', merchant))
      .toBe('/secureshop/merchant/listings#new');
    expect(safeLoginDestination('/secureshop/v2/catalog?sort=price', merchant))
      .toBe('/secureshop/v2/catalog?sort=price');
    expect(safeLoginDestination('/secureshop/product/7?color=blue', merchant))
      .toBe('/secureshop/product/7?color=blue');
  });

  test('preserves the standalone password destination only for an authenticated shop role', () => {
    expect(safeLoginDestination('/secureshop/password?tab=change#form', customer))
      .toBe('/secureshop/password?tab=change#form');
    expect(safeLoginDestination('/secureshop/password', merchant))
      .toBe('/secureshop/password');
    expect(safeLoginDestination('/secureshop/password', admin))
      .toBe('/secureshop/password');
    expect(safeLoginDestination('/secureshop/password', null)).toBe('/secureshop/home');
    expect(safeLoginDestination('/secureshop/password', { role: 'unknown' })).toBe('/secureshop/home');
  });

  test('uses a role-owned default and avoids customer-only pages for staff', () => {
    expect(safeLoginDestination('/secureshop/home', merchant)).toBe('/secureshop/merchant');
    expect(safeLoginDestination('/secureshop/orders', admin)).toBe('/secureshop/admin');
    expect(safeLoginDestination('/secureshop/cart', merchant)).toBe('/secureshop/merchant');
    expect(safeLoginDestination('/secureshop/v2', merchant)).toBe('/secureshop/merchant');
    expect(safeLoginDestination('', admin)).toBe('/secureshop/admin');
  });

  test('allows only the matching role area', () => {
    expect(safeLoginDestination('/secureshop/merchant/listings', merchant))
      .toBe('/secureshop/merchant/listings');
    expect(safeLoginDestination('/secureshop/admin/policies', admin))
      .toBe('/secureshop/admin/policies');
    expect(safeLoginDestination('/secureshop/merchant/listings', customer))
      .toBe('/secureshop/home');
    expect(safeLoginDestination('/secureshop/admin', merchant))
      .toBe('/secureshop/merchant');
  });

  test('rejects external, parser-confusing, and auth-loop destinations', () => {
    for (const destination of [
      'https://evil.example/secureshop/admin',
      '//evil.example/secureshop/admin',
      '/secureshop\\/admin',
      '/secureshop/%0d%0aadmin',
      '/secureshop/login?next=/secureshop/admin',
      '/secureshop/register',
      '/secureshop/unknown',
      '/secureshop/admin/users#new',
      '/secureshop#other',
      '/secureshop#%61bout',
    ]) expect(safeLoginDestination(destination, admin)).toBe('/secureshop/admin');
  });
});
