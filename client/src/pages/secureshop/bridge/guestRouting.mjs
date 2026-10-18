const PRODUCT = /^\/secureshop\/(?:v2\/)?product\/([1-9]\d*)\/?$/;
const CATALOG = /^\/secureshop\/(?:v2\/)?catalog\/?$/;
const CART = /^\/secureshop\/(?:v2\/)?cart\/?$/;
const ROOT = /^\/secureshop\/?$/;
const V2_HOME = /^\/secureshop\/v2\/?$/;
const LEGACY_V2_HOME = /^\/secureshop\/v2\/home\/?$/;
const CUSTOMER = /^\/secureshop\/(?:v2\/)?(?:checkout|orders|account|inbox)\/?$/;
const HOME = /^\/secureshop\/home\/?$/;
const MERCHANT = /^\/secureshop\/(?:v2\/)?merchant(?:\/(?:listings|reviews|pricing|analytics|inbox))?\/?$/;
const ADMIN = /^\/secureshop\/(?:v2\/)?admin(?:\/(?:users|audit|tickets|policies|mcp|system|access-control))?\/?$/;
const LISTINGS = /^\/secureshop\/(?:v2\/)?merchant\/listings\/?$/;
const LANDING_FRAGMENTS = new Set(['#about', '#how', '#agent-lane', '#lab-notes']);
const LISTINGS_FRAGMENT = /^#(?:new|p[1-9]\d*)$/;

function allowedFragment(path, hash) {
  if (!hash) return '';
  if (ROOT.test(path) && LANDING_FRAGMENTS.has(hash)) return hash;
  if (LISTINGS.test(path) && LISTINGS_FRAGMENT.test(hash)) return hash;
  return null;
}

export function safeShopRoute(value, { publicOnly = true } = {}) {
  if (typeof value !== 'string' || !value || value.length > 2048 || !value.startsWith('/')
    || value.startsWith('//') || /[\\\u0000-\u001f\u007f]/.test(value)
    || /%(?:2f|5c|00|0[0-9a-f]|1[0-9a-f]|7f)/i.test(value)) return null;
  let parsed;
  try { parsed = new URL(value, 'https://shop.invalid'); } catch { return null; }
  if (parsed.origin !== 'https://shop.invalid') return null;
  const path = parsed.pathname;
  if (!(ROOT.test(path) || CATALOG.test(path) || CART.test(path) || PRODUCT.test(path)
    || (!publicOnly && (V2_HOME.test(path) || LEGACY_V2_HOME.test(path) || HOME.test(path)
      || CUSTOMER.test(path) || MERCHANT.test(path) || ADMIN.test(path))))) return null;
  if (parsed.searchParams.size > 12 || [...parsed.searchParams].some(([key, val]) =>
    key.length > 40 || val.length > 1024)) return null;
  const fragment = allowedFragment(path, parsed.hash);
  if (fragment === null) return null;
  return `${LEGACY_V2_HOME.test(path) ? '/secureshop/v2' : path}${parsed.search}${fragment}`;
}

export function guestNavigationIntent(value, fallback = '/secureshop') {
  const route = safeShopRoute(value);
  if (route) return Object.freeze({ kind: 'route', route });
  if (typeof value !== 'string' || !value.startsWith('/secureshop/')) return null;
  let parsed;
  try { parsed = new URL(value, 'https://shop.invalid'); } catch { return null; }
  if (parsed.origin !== 'https://shop.invalid' || /[\\\u0000-\u001f\u007f]/.test(value)) return null;
  const register = /^\/secureshop\/(?:v2\/)?register\/?$/.test(parsed.pathname);
  if (register || /^\/secureshop\/(?:v2\/)?login\/?$/.test(parsed.pathname)
    || safeShopRoute(parsed.pathname, { publicOnly: false })) {
    return Object.freeze({ kind: register ? 'register' : 'auth', route: safeShopRoute(value, { publicOnly: false })
      || safeShopRoute(fallback) || '/secureshop' });
  }
  return null;
}
