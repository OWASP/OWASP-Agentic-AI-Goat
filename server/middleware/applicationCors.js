'use strict';
const cors = require('cors');

const DEFAULT_SECURESHOP_ORIGINS = Object.freeze([
  'http://localhost:3000', 'http://localhost:3001',
  'http://127.0.0.1:3000', 'http://127.0.0.1:3001',
  'http://127.0.0.1:8081', 'http://localhost:8081',
]);
function effectiveSecureShopOrigins(environment = process.env) {
  return environment.SS_ALLOWED_ORIGINS
    ? environment.SS_ALLOWED_ORIGINS.split(',').map(value => value.trim()).filter(Boolean)
    : DEFAULT_SECURESHOP_ORIGINS;
}

const PLATFORM_ORIGIN_PREFIXES = Object.freeze([
  '/api/auth', '/api/admin', '/api/agent-runs', '/api/changes',
  '/api/workshop/config', '/api/workshop/student', '/api/workshop/progress',
  '/api/workshop/challenges', '/api/workshop/instructor', '/api/workshop/objective',
  '/api/workshop/user-activity', '/api/workshop/time', '/api/solutions', '/api/hints',
  '/api/ctf/admin', '/api/monitoring', '/event-gate/login',
  '/api/workshop/csrf/browser-attempt', '/api/workshop/prompt-injection/mode',
]);
const matchesPrefix = (pathname, prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`);
const TRUSTED_METHODS = Object.freeze(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const TRUSTED_HEADERS = Object.freeze(['authorization', 'content-type', 'accept', 'x-request-id']);
const SHOP_HEADERS = Object.freeze([...TRUSTED_HEADERS, 'x-owasp-ai-goat-secureshop-launch', 'x-api-key']);

// Select one policy before cors can end an OPTIONS request or set response
// headers. Other challenge routes retain their intentional reflective policy.
function createApplicationCors({ secureShopOrigins = DEFAULT_SECURESHOP_ORIGINS,
  platformOrigins = secureShopOrigins } = {}) {
  const shopAllowed = new Set(secureShopOrigins);
  const platformAllowed = new Set(platformOrigins);
  const legacy = cors({ origin: true, credentials: true });
  const trusted = cors({ origin: true, credentials: true,
    methods: TRUSTED_METHODS, allowedHeaders: TRUSTED_HEADERS });
  const trustedShop = cors({ origin: true, credentials: true,
    methods: TRUSTED_METHODS, allowedHeaders: SHOP_HEADERS });
  return (req, res, next) => {
    const pathname = req.path.toLowerCase();
    const platform = PLATFORM_ORIGIN_PREFIXES.some(prefix => matchesPrefix(pathname, prefix));
    if (!platform && !matchesPrefix(pathname, '/api/secureshop')) {
      return legacy(req, res, next);
    }
    const allowed = platform ? platformAllowed : shopAllowed;
    const allowedHeaders = platform ? TRUSTED_HEADERS : SHOP_HEADERS;
    res.vary('Origin');
    const origin = req.get('Origin');
    // Missing Origin remains supported for same-origin/server clients. Opaque
    // browser origins are not trusted, even if accidentally configured.
    if (origin && (origin === 'null' || !allowed.has(origin))) {
      return res.status(403).json({ error: `Origin not allowed by ${platform ? 'platform' : 'SecureShop'} CORS policy` });
    }
    if (origin && req.method === 'OPTIONS') {
      res.vary('Access-Control-Request-Method');
      res.vary('Access-Control-Request-Headers');
      const method = req.get('Access-Control-Request-Method');
      const requestedHeaders = req.get('Access-Control-Request-Headers');
      if ((method && !TRUSTED_METHODS.includes(method)) ||
          (requestedHeaders && requestedHeaders.split(',').some(header => !allowedHeaders.includes(header.trim().toLowerCase())))) {
        return res.status(403).json({ error: 'CORS request method or headers are not allowed' });
      }
    }
    return (platform ? trusted : trustedShop)(req, res, next);
  };
}

module.exports = { createApplicationCors, DEFAULT_SECURESHOP_ORIGINS, effectiveSecureShopOrigins, PLATFORM_ORIGIN_PREFIXES };
