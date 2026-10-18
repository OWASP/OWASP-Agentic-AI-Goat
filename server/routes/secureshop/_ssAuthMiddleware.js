/**
 * SecureShop v2 — shared JWT auth middleware.
 *
 * M8 Wave 5A F2: the admin and merchant REST routers previously mounted every
 * endpoint with zero auth. This middleware verifies HS256 JWTs (issued by the
 * v2 auth router) and enforces a role match. Attach with:
 *
 *   router.use(requireRole('admin'))
 *
 * before any route handler. Unauthenticated callers get 401; authenticated
 * callers with a mismatched role get 403.
 *
 * Notes:
 *   - JWT_SECRET is read from process.env. If it is not set, we refuse to
 *     verify (500) — the SS v2 boot path in server/services/secureshop/index.js
 *     also refuses to start without JWT_SECRET.
 *   - This is HS256-only. The intentional alg=none bypass lives only at
 *     /admin/whoami (see admin.js) and is scoped to that endpoint alone.
 *   - Bearer token OR the `secureshop_v2_token` cookie is accepted.
 *   - Intentional-vuln endpoints under /admin/* and /merchant/* stay
 *     reachable AFTER this middleware. The goal is to keep unauthenticated
 *     attackers OUT while still letting authenticated + role-matched users
 *     fire the teaching sinks (RCE, SSTI, SSRF, XXE, etc.).
 */

const jwt = require('jsonwebtoken');

function _readToken(req) {
  const auth = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (m) return m[1].trim();
  const cookieToken = req.cookies && req.cookies.secureshop_v2_token;
  if (cookieToken) return String(cookieToken);
  return null;
}

function requireRole(requiredRole) {
  return function requireRoleMiddleware(req, res, next) {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      // Boot-time guard already refuses to start without JWT_SECRET, so this
      // path is defensive only.
      return res.status(500).json({ ok: false, error: 'server misconfigured: JWT_SECRET not set' });
    }
    const token = _readToken(req);
    if (!token) return res.status(401).json({ ok: false, error: 'missing bearer token' });
    let decoded;
    try {
      decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    } catch (e) {
      return res.status(401).json({ ok: false, error: 'invalid token' });
    }
    if (!decoded || decoded.role !== requiredRole) {
      return res.status(403).json({
        ok: false,
        error: `forbidden: this endpoint requires role=${requiredRole}`,
        actual_role: decoded && decoded.role,
      });
    }
    req.ssUser = decoded;
    next();
  };
}

/**
 * Verify a JWT and return the decoded payload, or null if invalid. Used by
 * routes that need to know the caller identity but don't want to hard-refuse
 * (e.g., role rehearsal in auth.switch-role).
 */
function verifyJwt(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret || !token) return null;
  try {
    return jwt.verify(token, secret, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

module.exports = { requireRole, verifyJwt };
