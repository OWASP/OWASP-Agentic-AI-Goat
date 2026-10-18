'use strict';

const HEADER = 'x-dvaia-secureshop-launch';

// Install before every legacy shop mount. Even an empty or invalid launch
// header selects the bound boundary; it must never select shared-state routes.
function createSecureShopBoundDispatch({ getGateway }) {
  if (typeof getGateway !== 'function') throw new TypeError('Bound gateway resolver required');
  return (req, res, next) => {
    const present = Object.hasOwn(req.headers || {}, HEADER)
      || (req.rawHeaders || []).some((value, index) => index % 2 === 0
        && String(value).toLowerCase() === HEADER);
    if (!present) return next();
    res.set('Cache-Control', 'no-store');
    const fail = () => {
      if (!res.headersSent) return res.status(503).json({ error: 'Bound SecureShop application unavailable' });
      if (!res.writableEnded) res.end();
    };
    try {
      const gateway = getGateway();
      if (typeof gateway !== 'function') return fail();
      const result = gateway(req, res, error => {
        if (error) return fail();
        if (!res.headersSent) return res.status(404).json({ error: 'Bound SecureShop operation unavailable' });
      });
      if (result && typeof result.catch === 'function') return result.catch(fail);
      return result;
    } catch { return fail(); }
  };
}

module.exports = { createSecureShopBoundDispatch };
