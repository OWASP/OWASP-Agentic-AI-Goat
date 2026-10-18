import { safeShopRoute } from '../bridge/guestRouting.mjs';

const FALLBACK = '/secureshop/home';
const PASSWORD_ROUTE = '/secureshop/password';
const SHOP_ROLES = new Set(['customer', 'merchant', 'admin']);
const ROLE_FALLBACK = Object.freeze({ customer: FALLBACK, merchant: '/secureshop/merchant', admin: '/secureshop/admin' });

const ROLE_ROOTS = Object.freeze({
  merchant: ['/secureshop/merchant', '/secureshop/v2/merchant'],
  admin: ['/secureshop/admin', '/secureshop/v2/admin'],
});

function hasPrefix(pathname, prefix) {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function isRolePath(pathname, role) {
  return (ROLE_ROOTS[role] || []).some(root => hasPrefix(pathname, root));
}

export function safeLoginDestination(next, user) {
  const role = typeof user?.role === 'string' ? user.role.toLowerCase() : '';
  const fallback = ROLE_FALLBACK[role] || FALLBACK;
  if (typeof next !== 'string' || !next || next.length > 2048) return fallback;
  if (/[\\\u0000-\u001F\u007F]/.test(next)
    || /%(?:5c|2f|00|0[0-9a-f]|1[0-9a-f]|7f)/i.test(next)
    || !next.startsWith('/') || next.startsWith('//')) {
    return fallback;
  }
  let parsed;
  try {
    parsed = new URL(next, 'https://shop.invalid');
  } catch {
    return fallback;
  }
  if (parsed.origin !== 'https://shop.invalid') {
    return fallback;
  }
  if (parsed.pathname === PASSWORD_ROUTE) {
    // The standalone password screen is outside the mounted frame routes. It
    // is a post-login destination only; never admit it through guest routing.
    if (!SHOP_ROLES.has(role) || parsed.searchParams.size > 12
      || [...parsed.searchParams].some(([key, val]) => key.length > 40 || val.length > 1024)) {
      return fallback;
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  }
  if (hasPrefix(parsed.pathname, '/secureshop/login') || hasPrefix(parsed.pathname, '/secureshop/register')) {
    return fallback;
  }
  // Orders show details in a dialog on the mounted list route.
  const orderDetail = /^\/secureshop\/(v2\/)?orders\/[1-9]\d*\/?$/.exec(parsed.pathname);
  const intendedPath = orderDetail ? `/secureshop/${orderDetail[1] || ''}orders` : parsed.pathname;
  const admitted = safeShopRoute(`${intendedPath}${parsed.search}${parsed.hash}`, { publicOnly: false });
  if (!admitted) return fallback;
  const admittedPath = new URL(admitted, 'https://shop.invalid').pathname;
  if (isRolePath(admittedPath, 'merchant') || isRolePath(admittedPath, 'admin')) {
    return isRolePath(admittedPath, role) ? admitted : fallback;
  }
  if (role !== 'customer' && (admittedPath === '/secureshop/v2'
    || /^\/secureshop\/(?:v2\/)?(?:home|cart|checkout|orders)\/?$/.test(admittedPath))) return fallback;
  return admitted;
}

export { FALLBACK as LOGIN_FALLBACK };
