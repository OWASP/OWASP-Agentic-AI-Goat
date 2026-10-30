/**
 * Event Gate Middleware
 *
 * A single shared-password barrier that blocks all app traffic unless the
 * visitor has authenticated. Designed for short-duration public events where
 * the goal is to keep bots and script-kiddies out while letting legitimate
 * attendees through with a password announced live at the event.
 *
 * Controlled by two env vars:
 *   EVENT_GATE_ENABLED   "true" to activate (default: "false")
 *   EVENT_GATE_PASSWORD  The explicit shared event password when enabled
 *
 * ECS health-check paths are always whitelisted so ALB never loses the target.
 */

'use strict';

const crypto = require('crypto');

const COOKIE_NAME = 'owasp_ai_goat_event_auth';
const COOKIE_MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6 h — outlasts any 2-h event
const COOKIE_MAX_AGE_SECONDS = COOKIE_MAX_AGE_MS / 1000;
const HISTORICAL_SAMPLE_PASSWORD = 'DefconHack2026!';
const PASSWORD_MIN_BYTES = 12;
const PASSWORD_MAX_BYTES = 256;
const REDIRECT_MAX_BYTES = 2048;

// Paths that bypass the gate entirely (ALB / ECS health checks)
const ALWAYS_ALLOWED = [
  '/api/monitoring/ping',
  '/api/monitoring/health',
  '/event-gate',
  '/event-gate/login',
];

/**
 * Derive a deterministic signing key from the event password so the cookie
 * is valid across container restarts without a shared secret store.
 */
function signingKey(password) {
  return crypto.createHash('sha256').update(`event-gate:${password}`).digest();
}

function assertEventGateConfiguration(environment = process.env) {
  if (environment?.EVENT_GATE_ENABLED !== 'true') {
    return Object.freeze({ enabled: false, password: null });
  }
  const password = environment.EVENT_GATE_PASSWORD;
  const bytes = typeof password === 'string' ? Buffer.byteLength(password, 'utf8') : 0;
  if (typeof password !== 'string' || bytes < PASSWORD_MIN_BYTES || bytes > PASSWORD_MAX_BYTES
      || password.trim() !== password || password === HISTORICAL_SAMPLE_PASSWORD) {
    throw Object.assign(new Error(
      'EVENT_GATE_ENABLED=true requires an explicit 12-256 byte password without surrounding whitespace; the historical sample is rejected.'
    ), { code: 'INVALID_EVENT_GATE_CONFIGURATION' });
  }
  return Object.freeze({ enabled: true, password });
}

function seconds(value) {
  const result = Math.floor(Number(value) / 1000);
  if (!Number.isSafeInteger(result) || result < 0) throw new TypeError('A valid clock is required');
  return result;
}

function makeCookieValue(password, { now = Date.now } = {}) {
  const issuedAt = seconds(now());
  const expiresAt = issuedAt + COOKIE_MAX_AGE_SECONDS;
  const payload = `v1.${issuedAt}.${expiresAt}`;
  const sig = crypto
    .createHmac('sha256', signingKey(password))
    .update(payload)
    .digest('hex');
  return `${payload}.${sig}`;
}

function verifyCookie(value, password, { now = Date.now } = {}) {
  if (typeof value !== 'string' || value.length > 256) return false;
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1'
      || !/^(0|[1-9]\d{0,12})$/.test(parts[1])
      || !/^(0|[1-9]\d{0,12})$/.test(parts[2])
      || !/^[a-f0-9]{64}$/.test(parts[3])) return false;
  const issuedAt = Number(parts[1]);
  const expiresAt = Number(parts[2]);
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt)) return false;
  const payload = parts.slice(0, 3).join('.');
  const expected = crypto.createHmac('sha256', signingKey(password)).update(payload).digest('hex');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(parts[3], 'hex'), Buffer.from(expected, 'hex'))) return false;
  } catch {
    return false;
  }
  const current = seconds(now());
  return issuedAt <= current && expiresAt > current
    && expiresAt > issuedAt && expiresAt - issuedAt <= COOKIE_MAX_AGE_SECONDS;
}

function safeLocalRedirect(value) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > REDIRECT_MAX_BYTES
      || /[\u0000-\u001f\u007f\\]/.test(value) || !value.startsWith('/') || value.startsWith('//')) return '/';
  try {
    const base = new URL('https://event-gate.invalid/');
    const target = new URL(value, base);
    if (target.origin !== base.origin || target.username || target.password || target.pathname.startsWith('//')) return '/';
    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return '/';
  }
}

// Self-contained login page — no external assets, works before React loads.
// Styled to match the OWASP Agentic AI GOAT platform brand (indigo→purple gradient, frosted
// white card, gradient shield mark) used across the app's login screens.
function loginPage({ error } = {}) {
  const errorHtml = error
    ? `<p class="err">${error}</p>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>DEF CON Workshop 2026 — Event Access</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         min-height:100vh;padding:2rem;color:#333;
         display:flex;align-items:center;justify-content:center;
         background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);position:relative}
    body::before{content:"";position:absolute;inset:0;pointer-events:none;
         background-image:radial-gradient(circle at 25% 25%,rgba(255,255,255,.1) 0%,transparent 50%),
                          radial-gradient(circle at 75% 75%,rgba(255,255,255,.1) 0%,transparent 50%)}
    .card{position:relative;background:rgba(255,255,255,.97);backdrop-filter:blur(20px);
          border:1px solid rgba(255,255,255,.2);border-radius:24px;
          box-shadow:0 20px 60px rgba(0,0,0,.2);
          padding:3rem;width:100%;max-width:440px;text-align:center}
    .icon{width:80px;height:80px;border-radius:20px;margin:0 auto 1.5rem;
          display:flex;align-items:center;justify-content:center;
          background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
          box-shadow:0 10px 30px rgba(102,126,234,.3)}
    .icon svg{width:40px;height:40px;stroke:#fff;fill:none;stroke-width:2;
          stroke-linecap:round;stroke-linejoin:round}
    h1{font-size:1.75rem;font-weight:700;color:#333;margin-bottom:.4rem}
    .brand{font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
           color:#764ba2;margin-bottom:.75rem}
    .sub{font-size:1rem;color:#666;line-height:1.6;margin-bottom:2rem}
    form{display:flex;flex-direction:column;gap:1rem;text-align:left}
    label{display:block;font-size:.95rem;font-weight:600;color:#333;margin-bottom:.5rem}
    input[type=password]{width:100%;padding:1.1rem 1.25rem;background:#fafafa;
          border:2px solid #e9ecef;border-radius:16px;color:#333;
          font-size:1rem;outline:none;transition:all .3s ease}
    input[type=password]:focus{border-color:#667eea;background:#fff;
          box-shadow:0 0 0 3px rgba(102,126,234,.1)}
    input[type=password]::placeholder{color:#999}
    button{margin-top:.5rem;width:100%;padding:1.15rem;color:#fff;border:none;
           border-radius:16px;font-size:1.1rem;font-weight:700;cursor:pointer;
           background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
           box-shadow:0 8px 25px rgba(102,126,234,.3);transition:all .3s ease}
    button:hover{transform:translateY(-2px);box-shadow:0 12px 35px rgba(102,126,234,.4)}
    .err{color:#dc2626;font-size:.9rem;font-weight:500;margin-top:1.25rem;
         background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:.75rem}
    .foot{margin-top:1.75rem;padding-top:1.5rem;border-top:1px solid #e5e7eb;
          font-size:.8rem;color:#9ca3af}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon" aria-hidden="true">
      <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <div class="brand">OWASP Agentic AI GOAT · Secure Access</div>
    <h1>DEF CON Workshop 2026</h1>
    <p class="sub">Enter the event password to continue</p>
    <form method="POST" action="/event-gate/login">
      <label for="pw">Event Password</label>
      <input id="pw" name="password" type="password" autofocus
             autocomplete="current-password" placeholder="••••••••••••"/>
      <button type="submit">Enter Workshop</button>
    </form>
    ${errorHtml}
    <div class="foot">OWASP Agentic AI GOAT · Authorized attendees only</div>
  </div>
</body>
</html>`;
}

function gateRequest(req, res, next, { environment, now }) {
  const configuration = assertEventGateConfiguration(environment);
  if (!configuration.enabled) {
    return next();
  }

  // Always allow health-check + gate endpoints
  if (ALWAYS_ALLOWED.some((p) => req.path === p || req.path.startsWith(p + '/'))) {
    return next();
  }

  // Check auth cookie
  const cookieValue = req.cookies?.[COOKIE_NAME];
  if (cookieValue && verifyCookie(cookieValue, configuration.password, { now })) {
    return next();
  }

  // Unauthenticated — respond based on request type
  const wantsBrowser = req.accepts('html') && !req.path.startsWith('/api/');
  if (wantsBrowser) {
    return res.status(401).send(loginPage());
  }
  return res.status(401).json({ error: 'Event authentication required' });
}

// POST /event-gate/login handler — mounted in index.js alongside the middleware
function loginRequest(req, res, { environment, now }) {
  const configuration = assertEventGateConfiguration(environment);
  if (!configuration.enabled) {
    return res.redirect('/');
  }
  const submitted = req.body?.password;

  let valid = false;
  try {
    const supplied = typeof submitted === 'string' ? Buffer.from(submitted, 'utf8') : Buffer.alloc(0);
    const expected = Buffer.from(configuration.password, 'utf8');
    valid = typeof submitted === 'string' && supplied.length === expected.length
      && crypto.timingSafeEqual(supplied, expected);
  } catch {
    valid = false;
  }

  if (!valid) {
    return res.status(401).send(loginPage({ error: 'Incorrect password — try again.' }));
  }

  res.cookie(COOKIE_NAME, makeCookieValue(configuration.password, { now }), {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE_MS,
  });

  return res.redirect(safeLocalRedirect(req.query?.next));
}

function createEventGateHandlers({ environment = process.env, now = Date.now } = {}) {
  if (!environment || typeof now !== 'function') throw new TypeError('Event gate environment and clock are required');
  return Object.freeze({
    eventGate: (req, res, next) => gateRequest(req, res, next, { environment, now }),
    loginHandler: (req, res) => loginRequest(req, res, { environment, now }),
  });
}

function eventGate(req, res, next) {
  return gateRequest(req, res, next, { environment: process.env, now: Date.now });
}

function loginHandler(req, res) {
  return loginRequest(req, res, { environment: process.env, now: Date.now });
}

module.exports = {
  COOKIE_NAME,
  COOKIE_MAX_AGE_MS,
  assertEventGateConfiguration,
  createEventGateHandlers,
  eventGate,
  loginHandler,
  makeCookieValue,
  safeLocalRedirect,
  verifyCookie,
};
