'use strict';
const HEADER = 'x-dvaia-secureshop-launch';
const LAUNCH_STATE_HEADER = 'X-DVAIA-SecureShop-Launch-State';
const LAUNCH_UNAVAILABLE = 'unavailable';
const BEARER = /^[A-Za-z0-9_-]{43}$/;
const { createLaunchScope } = require('../services/secureshopConversationBinding');

function markSecureShopLaunchUnavailable(res) {
  res.setHeader(LAUNCH_STATE_HEADER, LAUNCH_UNAVAILABLE);
  return res;
}

// Use only on the isolated launch route tree, never as a fallback for legacy
// shop authentication. The shop persona remains a separate teaching identity.
function requireSecureShopLaunch({ launches }) {
  if (!launches || typeof launches.resolveCapability !== 'function') throw new TypeError('Launch resolver required');
  return async function launchAuthority(req, res, next) {
    res.setHeader('Cache-Control', 'no-store');
    delete req.ssLaunch;
    const value = req.headers[HEADER];
    let occurrences = 0;
    for (let i = 0; i < (req.rawHeaders || []).length; i += 2) {
      if (String(req.rawHeaders[i]).toLowerCase() === HEADER) occurrences++;
    }
    if (occurrences > 1 || typeof value !== 'string' || !BEARER.test(value)) {
      return markSecureShopLaunchUnavailable(res).status(401)
        .json({ error: 'SecureShop launch unavailable' });
    }
    try {
      const binding = await launches.resolveCapability(value);
      if (!binding) return markSecureShopLaunchUnavailable(res).status(401)
        .json({ error: 'SecureShop launch unavailable' });
      // Only these DB-derived coordinates enter later authorization. Do not
      // retain the bearer, spread caller fields or publish this object as a DTO.
      req.ssLaunch = createLaunchScope(binding);
    } catch {
      return res.status(503).json({ error: 'SecureShop launch verification unavailable' });
    }
    return next();
  };
}
module.exports = { requireSecureShopLaunch, markSecureShopLaunchUnavailable,
  LAUNCH_STATE_HEADER, LAUNCH_UNAVAILABLE };
