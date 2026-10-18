'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
// A non-authenticating cost-12 digest keeps absent accounts on the password
// comparison path. Its matching value is discarded and cannot grant authority.
const DUMMY_LOGIN_HASH = '$2b$12$kjpt6RR2WeohckbQYwQC7uYzMlgnuN5h0N5GiMBTgO9TkkLYI2WO6';
const validation = require('../services/authValidation');
const {
  createPostgresAdminAuth, hasAdminLevel
} = require('../middleware/postgresAdminAuth');
function createPostgresAuthRouter({
  adapter,
  limiters,
  loginRuntime = require('../services/loginAuthenticationProduction').createLoginAuthenticationProduction()
}) {
  if (!adapter || !limiters) throw new Error('Identity adapter and rate limit middleware required');
  const router = express.Router(),
    repo = adapter.repository,
    auth = createPostgresAdminAuth(adapter);
  const wrap = handler => (req, res, next) => Promise.resolve().then(() => handler(req, res, next)).catch(error => {
    if (res.destroyed || res.writableEnded) return;
    if (['LOGIN_QUEUE_FULL', 'LOGIN_RUNTIME_CLOSED', 'LOGIN_WORKER_FAILED'].includes(error.code)) {
      res.set('Retry-After', '1');
      return res.status(503).json({ error: 'Identity service unavailable' });
    }
    if (error.code === '23505') return res.status(409).json({
      error: 'Account already exists',
      message: 'Username or email already registered'
    });
    return res.status(503).json({
      error: 'Identity service unavailable'
    });
  });
  const captchas = new Map(),
    registrations = new Map();
  const required = ip => (registrations.get(ip) || []).filter(t => Date.now() - t < 3600000).length >= 5;
  const timer = setInterval(() => {
    for (const [id, row] of captchas) if (row.expiresAt < Date.now()) captchas.delete(id);
    for (const [ip, rows] of registrations) {
      const fresh = rows.filter(t => Date.now() - t < 3600000);
      if (fresh.length) registrations.set(ip, fresh);else registrations.delete(ip);
    }
  }, 600000);
  timer.unref();
  router.close = () => { clearInterval(timer); return loginRuntime.close(); };
  router.loginRuntimeSnapshot = () => loginRuntime.snapshot();
  router.get('/captcha', (req, res) => {
    const a = crypto.randomInt(1, 21),
      b = crypto.randomInt(1, 21),
      captchaId = crypto.randomBytes(16).toString('hex');
    captchas.set(captchaId, {
      answer: a + b,
      expiresAt: Date.now() + 300000
    });
    res.json({
      captchaId,
      question: `What is ${a} + ${b}?`
    });
  });
  router.get('/signup-config', wrap(async (req, res) => res.json({
    randomEmailEnabled: (await repo.getConfig('workshop_signup_random_email_enabled')) === 'true',
    registrationEnabled: (await repo.getConfig('allow_registration')) !== 'false',
    captchaRequired: required(req.ip)
  })));
  router.get('/feature-flags', wrap(async (req, res) => res.json({
    flags: Object.fromEntries((await repo.getPublicConfig()).map(r => [r.config_key, r.config_type === 'boolean' ? r.config_value === 'true' : r.config_value]))
  })));
  function login(durationMs, comparison = false) {
    return wrap(async (req, res) => {
      const {
        username,
        password
      } = req.body || {};
      if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) return res.status(400).json({
        error: 'Missing credentials',
        message: 'Username and password are required'
      });
      // Match the identity repository boundary before its validation exception
      // can be mistaken for a storage outage by the route's error wrapper.
      if (username.length > 50) return res.status(400).json({
        error: 'Invalid credentials',
        message: 'Username must be at most 50 characters'
      });
      const controller = new AbortController();
      const abort = () => controller.abort(Object.assign(new Error('Login cancelled'), { name: 'AbortError' }));
      const disconnected = () => { if (!res.writableFinished) abort(); };
      req.once('aborted', abort);
      res.once('close', disconnected);
      if (req.aborted || res.destroyed) abort();
      try {
        return await loginRuntime.run(controller.signal, async ({ compare, check }) => {
          check();
          // Platform identity is parameterized. Intentionally vulnerable challenge auth remains separate.
          const user = await repo.findCredentialByUsername(username);
          check();
          const passwordMatches = await compare(password, user?.password || DUMMY_LOGIN_HASH);
          check();
          const locked = Boolean(user?.account_locked_until && new Date(user.account_locked_until) > new Date());
          if (!user || !user.is_active || locked || !passwordMatches) {
            // Keep lockout accounting private; login responses must not identify
            // existing, disabled or locked accounts. Authenticated status is separate.
            if (user && !locked) await repo.recordFailedLogin(user.id);
            check();
            return res.status(401).json({ error: 'Invalid credentials' });
          }
          // The challenge cookie can remain readable for its teaching sinks, but
          // platform login must never promote a pre-authentication session ID.
          if (req.session) {
            await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
          }
          check();
          const session = await adapter.createSession(user, req, {
            durationMs
          });
          try {
            check();
            if (req.session) {
              req.session.userId = user.id;
              req.session.platformOwnerId = user.id;
              req.session.platformSessionId = session.internalSessionId;
              req.session.username = user.username;
              // The readable teaching cookie remains separate from platform
              // authority, but login must not advertise a longer lifetime.
              const canonicalExpiry = Date.parse(session.expiresAt);
              if (!Number.isFinite(canonicalExpiry) || canonicalExpiry <= Date.now()) throw new Error('Invalid platform session expiry');
              const teachingExpiry = req.session.cookie.expires?.getTime();
              req.session.cookie.expires = new Date(Math.min(canonicalExpiry,
                Number.isFinite(teachingExpiry) ? teachingExpiry : canonicalExpiry));
            }
            const profile = await repo.getUserById(user.id),
              permissions = await repo.getUserPermissions(user.id);
            check();
            // Commit the teaching cookie before success headers are visible. Express
            // otherwise begins streaming the response while its automatic save waits.
            if (req.session) {
              await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
            }
            check();
            await repo.recordAudit({
              userId: user.id,
              actionType: 'user_login',
              details: {
                method: req.method,
                url: '/api/auth/login'
              },
              ipAddress: req.ip
            });
            check();
            if (comparison) return res.json({
              success: true,
              user: {
                id: user.id,
                username: user.username,
                role: user.role
              },
              token: session.token
            });
            res.json({
              success: true,
              message: 'Login successful',
              token: session.token,
              user: adapter.userDto(profile, permissions),
              sessionInfo: session.sessionInfo
            });
          } catch (error) {
            // No successful login was published. Retire the newly minted token and
            // prevent Express from automatically retrying a failed cookie save.
            try { await adapter.logout(session.token); } catch { /* storage may still be unavailable */ }
            try {
              if (req.session?.destroy) await new Promise(resolve => req.session.destroy(() => resolve()));
            } finally { req.session = undefined; }
            throw error;
          }
        });
      } finally {
        req.removeListener('aborted', abort);
        res.removeListener('close', disconnected);
      }
    });
  }
  router.post('/login', limiters.loginRateLimiter, login(86400000));
  router.post('/secure-login', limiters.loginRateLimiter, login(3600000, true));
  router.post('/register', limiters.registerRateLimiter, wrap(async (req, res) => {
    if ((await repo.getConfig('allow_registration')) === 'false') return res.status(403).json({
      error: 'Registration is currently disabled.'
    });
    const body = req.body || {};
    if (required(req.ip)) {
      const captcha = captchas.get(body.captchaId);
      captchas.delete(body.captchaId);
      if (!captcha || captcha.expiresAt < Date.now() || Number(body.captchaAnswer) !== captcha.answer) return res.status(400).json({
        error: 'Captcha required',
        message: 'Please solve a new captcha.',
        captchaRequired: true
      });
    }
    const username = validation.validateUsername(body.username),
      email = validation.validateEmail(body.email),
      password = validation.validatePassword(body.password);
    for (const [name, result] of [['username', username], ['email', email], ['password', password]]) if (!result.valid) return res.status(400).json({
      error: `Invalid ${name}`,
      message: result.error
    });
    const user = await repo.registerUser({
      username: username.sanitized,
      email: email.sanitized,
      passwordHash: await validation.secureHashPassword(body.password),
      fullName: body.fullName,
      department: body.department,
      phone: body.phone,
      ipAddress: req.ip
    });
    registrations.set(req.ip, [...(registrations.get(req.ip) || []).filter(t => Date.now() - t < 3600000), Date.now()]);
    res.status(201).json({
      success: true,
      message: 'User registered successfully in SECURE authentication database',
      userId: user.id,
      emailVerificationRequired: false,
      emailVerificationAvailable: false,
      emailVerificationMode: 'local-instructor-managed',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: 'student',
        fullName: user.full_name,
        emailVerified: false
      },
      security: {
        database: 'PostgreSQL identity',
        passwordHashed: true,
        isolatedFromVulnerableDBs: true
      }
    });
  }));
  // Local workshop accounts do not establish ownership of an external mailbox.
  // Never consume previously exposed tokens or enumerate addresses here.
  for (const endpoint of ['/verify-email', '/resend-verification']) {
    router.post(endpoint, (_req, res) => res.status(409).json({
      success: false,
      code: 'EMAIL_VERIFICATION_UNAVAILABLE',
      message: 'Email ownership verification is unavailable for local workshop accounts.',
      emailVerificationAvailable: false
    }));
  }
  router.post('/reset-password', limiters.passwordResetRateLimiter, wrap(async (req, res) => {
    const email = validation.validateEmail(req.body?.email);
    if (!email.valid) return res.status(400).json({
      error: email.error
    });
    // Supported workshop recovery is the authenticated instructor password
    // change flow. No delivery provider is configured by this endpoint.
    res.status(409).json({
      success: false,
      code: 'PASSWORD_RESET_INSTRUCTOR_MANAGED',
      error: 'Contact your workshop instructor to reset your password. Self-service email recovery is not configured.'
    });
  }));
  router.get('/status', (req, res) => auth.authenticateToken(req, {
    status(code) {
      return {
        json() {
          return code >= 500 ? res.status(code).json({
            authenticated: false,
            reason: 'session_store_unavailable'
          }) : res.json({
            authenticated: false,
            reason: 'no_valid_session'
          });
        }
      };
    }
  }, () => wrap(async () => res.json({
    authenticated: true,
    user: adapter.userDto(req.user, await repo.getUserPermissions(req.user.id)),
    sessionInfo: {
      expiresAt: req.identitySession.expires_at,
      lastActivity: req.identitySession.last_activity
    }
  }))(req, res)));
  router.post('/logout', wrap(async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) await adapter.logout(token);
    if (req.session?.destroy) await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
    res.clearCookie('connect.sid');
    res.clearCookie('token');
    res.json({
      success: true,
      message: 'Logged out successfully',
      timestamp: new Date().toISOString()
    });
  }));
  router.get('/profile/:userId', auth.authenticateToken, wrap(async (req, res) => {
    if (!/^\d+$/.test(req.params.userId)) return res.status(400).json({
      error: 'Invalid user ID'
    });
    const id = Number(req.params.userId),
      admin = hasAdminLevel(req.user);
    if (id !== req.user.id && !admin) return res.status(403).json({
      error: 'Access denied',
      message: 'You can only view your own profile'
    });
    const user = await repo.getUserById(id);
    if (!user || !user.is_active) return res.status(404).json({
      error: 'User not found'
    });
    const profile = Object.fromEntries(['id', 'username', 'email', 'role', 'full_name', 'department', 'phone', 'created_at', 'last_login', 'email_verified', ...(admin ? ['admin_level'] : [])].map(k => [k, user[k]]));
    res.json({
      success: true,
      user: profile
    });
  }));
  router.put('/profile', auth.authenticateToken, wrap(async (req, res) => {
    const email = validation.validateEmail(req.body?.email);
    if (!email.valid) return res.status(400).json({
      error: email.error
    });
    const fullName = typeof req.body?.fullName === 'string' ? req.body.fullName.replace(/<[^>]*>/g, '').trim().slice(0, 100) : '';
    try {
      const user = await repo.updateProfile(req.user.id, email.sanitized, fullName);
      res.json({
        success: true,
        message: 'Profile updated successfully',
        user
      });
    } catch (error) {
      if (error.code === '23505') return res.status(400).json({
        error: 'Email already exists'
      });
      throw error;
    }
  }));
  router.put('/password', auth.authenticateToken, wrap(async (req, res) => {
    const {
      currentPassword,
      newPassword
    } = req.body || {};
    if (typeof currentPassword !== 'string' || !currentPassword) return res.status(400).json({
      error: 'Current and new passwords are required'
    });
    const valid = validation.validatePassword(newPassword);
    if (!valid.valid) return res.status(400).json({
      error: valid.error
    });
    const user = await repo.findCredentialById(req.user.id);
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) return res.status(400).json({
      error: 'Current password is incorrect'
    });
    await repo.rotatePasswordAndRevoke(user.id, user.password, await validation.secureHashPassword(newPassword));
    res.json({
      success: true,
      message: 'Password updated successfully'
    });
  }));
  router.get('/activity', auth.authenticateToken, wrap(async (req, res) => {
    const entries = await adapter.progress.getUserProgress(req.user.id);
    res.json({
      success: true,
      activities: entries.filter(e => e.completed).sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt)).slice(0, 10).map(e => ({
        id: `challenge_completed_${e.workshopKey}`,
        type: 'challenge_completed',
        text: `Completed ${e.workshopKey} challenge`,
        time: new Date(e.completedAt).toLocaleString(),
        icon: 'FiCheckCircle',
        color: '#e8f5e8',
        timestamp: e.completedAt
      }))
    });
  }));
  return router;
}
module.exports = {
  createPostgresAuthRouter
};
