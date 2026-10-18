/**
 * Rate Limiting Middleware for Authentication Routes
 * ==================================================
 * Protects authentication endpoints from brute force attacks
 *
 * SECURITY MEASURES:
 * - Login: 1,000 attempts/IP plus 20 failed or in-flight attempts/account+IP per 15 minutes
 * - Registration attempts: 3 per hour per IP
 * - Password reset: 3 per hour per IP
 * - Prevents credential stuffing attacks
 * - Prevents account enumeration
 *
 * ADMIN CONTROL:
 * - Enable/disable via Admin → System Settings → "Enable Rate Limiting"
 * - Disabled by default (workshop-friendly: students won't get locked out)
 * - Toggle takes effect immediately without server restart
 */

const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = rateLimit;
const { createHash } = require('node:crypto');

// In-memory config cache — loaded from DB on startup, refreshed after admin toggle
let _enabled = false; // default: disabled

/**
 * Refresh rate limit config from system_config table.
 * Called once on module load and after every admin toggle.
 */
const refreshRateLimitConfig = () =>
  require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().repository
    .getConfig('enable_rate_limiting')
    .then(value => { _enabled = value === 'true'; })
    .catch(() => {});

// Lazy load on first request to avoid DB startup race condition
setImmediate(refreshRateLimitConfig);

function recordRateLimitEvent(event) {
  const details = typeof event.actionDetails === 'string'
    ? JSON.parse(event.actionDetails)
    : (event.actionDetails || {});
  return require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().repository.recordAudit({
    userId: event.userId ?? null,
    actionType: event.actionType,
    details,
    ipAddress: event.ipAddress || null,
    userAgent: event.userAgent || null,
    sessionId: event.sessionId || null,
    riskLevel: event.riskLevel,
    success: event.success,
  });
}

function logExceeded(req, endpoint, riskLevel, limits = req.rateLimit) {
  void recordRateLimitEvent({
    userId: req.user?.id ?? null,
    actionType: 'rate_limit_exceeded',
    actionDetails: JSON.stringify({
      method: req.method || 'POST',
      url: endpoint,
      attempts: limits.current,
      limit: limits.limit,
    }),
    ipAddress: req.ip,
    userAgent: req.get?.('User-Agent') || null,
    riskLevel,
    success: 0,
    errorMessage: 'Too many login attempts',
  }).catch((error) => console.error('[RateLimiter] Failed to record limit event:', error.message));
}

/**
 * Internal rate limiter instances (not exported directly)
 */
// Identity lookup preserves case and whitespace. Do not merge distinct usernames
// with trim/case folding, and never keep credentials in store keys or audit logs.
function loginAccountKey(req) {
  const username = req.body?.username;
  const account = typeof username === 'string' && username.length > 0 && username.length <= 50
    ? ['username', username] : ['invalid'];
  return `${ipKeyGenerator(req.ip, 56)}:${createHash('sha256').update(JSON.stringify(account)).digest('hex')}`;
}
function loginLimitHandler(property) {
  return (req, res) => {
    const limits = req[property];
    logExceeded(req, '/api/auth/login', 'high', limits);
    res.status(429).json({ error: 'Too many login attempts',
      message: 'Please try again after 15 minutes',
      retryAfter: Math.max(0, Math.ceil((limits.resetTime - Date.now()) / 1000)) });
  };
}
// Shared workshop NAT: 200 learners × five attempts. This is an abuse budget,
// not a claim that 200 concurrent bcrypt operations have been capacity tested.
const _loginIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 1000,
  standardHeaders: true, legacyHeaders: false,
  requestPropertyName: 'rateLimitLoginIp',
  handler: loginLimitHandler('rateLimitLoginIp'),
});
const _loginAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20,
  keyGenerator: loginAccountKey,
  standardHeaders: true, legacyHeaders: false,
  requestPropertyName: 'rateLimitLoginAccount',
  // The library reserves before next(): outstanding requests count even when
  // they eventually succeed. Only a finished login HTTP200 releases its slot.
  skipSuccessfulRequests: true,
  requestWasSuccessful: (_req, res) => res.statusCode === 200,
  handler: loginLimitHandler('rateLimitLoginAccount'),
});

const _registerLimiterInstance = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Maximum 3 registrations per hour per IP
  message: {
    error: 'Too many registration attempts',
    message: 'Please try again after 1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only count failed registrations
  handler: (req, res) => {
    logExceeded(req, '/api/auth/register', 'high');

    res.status(429).json({
      error: 'Too many registration attempts',
      message: 'Please try again after 1 hour',
      retryAfter: Math.ceil(req.rateLimit.resetTime - Date.now()) / 1000
    });
  }
});

const _passwordResetLimiterInstance = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Maximum 3 reset attempts per hour per IP
  message: {
    error: 'Too many password reset attempts',
    message: 'Please try again after 1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logExceeded(req, '/api/auth/reset-password', 'medium');

    res.status(429).json({
      error: 'Too many password reset attempts',
      message: 'Please try again after 1 hour',
      retryAfter: Math.ceil(req.rateLimit.resetTime - Date.now()) / 1000
    });
  }
});

const _generalLimiterInstance = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Maximum 100 requests per window
  message: {
    error: 'Too many requests',
    message: 'Please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Exported middleware wrappers — bypass the limiter when rate limiting is disabled
 */
const loginRateLimiter = (req, res, next) =>
  _enabled ? _loginIpLimiter(req, res, error => error ? next(error) : _loginAccountLimiter(req, res, next)) : next();

const registerRateLimiter = (req, res, next) =>
  _enabled ? _registerLimiterInstance(req, res, next) : next();

const passwordResetRateLimiter = (req, res, next) =>
  _enabled ? _passwordResetLimiterInstance(req, res, next) : next();

const generalRateLimiter = (req, res, next) =>
  _enabled ? _generalLimiterInstance(req, res, next) : next();

module.exports = {
  loginRateLimiter,
  registerRateLimiter,
  passwordResetRateLimiter,
  generalRateLimiter,
  refreshRateLimitConfig,
  recordRateLimitEvent,
};
