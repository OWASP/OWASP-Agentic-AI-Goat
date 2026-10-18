'use strict';

const { createHash, createHmac, randomBytes: cryptoRandomBytes, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const USERNAME = /^[a-z][a-z0-9_]{2,31}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const { SHOP_DEFAULT_SECONDS, validateSessionLifetimeSeconds } = require('./sessionLifetimeConfiguration');
const DUMMY_HASH = '$2b$12$Lb7ZNghYLnE8hlO/ERYzFuMP/9iUqy6V3ibYldFSE73Z1A/GMiEJG';
const trustedAuth = new WeakSet();
const trustedExecution = new WeakSet();
function failure(code) { return Object.assign(new Error('Shop authentication unavailable'), { code }); }
function hashToken(token) { return createHash('sha256').update(token, 'utf8').digest('hex'); }
function publicUser(context) {
  return Object.freeze({ id: context.shopUserId, principalId: context.principalId,
    username: context.username, email: context.email, role: context.role });
}
function brandAuth(value, token) {
  if (!value || typeof value !== 'object' || !Number.isSafeInteger(value.ownerId)
      || !Number.isSafeInteger(value.sessionId) || !Number.isSafeInteger(value.shopUserId)
      || !['customer', 'merchant', 'admin'].includes(value.role)
      || typeof value.principalId !== 'string' || typeof value.username !== 'string'
      || typeof value.email !== 'string' || typeof value.credentialVersion !== 'string'
      || typeof value.authorityVersion !== 'string'
      || !Number.isFinite(Date.parse(value.expiresAt)) || !TOKEN.test(token)) {
    throw failure('SHOP_AUTH_INVALID');
  }
  const launchBearer = createHmac('sha256', token)
    .update('secureshop-standalone-launch-v1').digest('base64url');
  const context = Object.freeze({ principalId: value.principalId, ownerId: value.ownerId,
    sessionId: value.sessionId, shopUserId: value.shopUserId, username: value.username,
    email: value.email, role: value.role, credentialVersion: value.credentialVersion,
    authorityVersion: value.authorityVersion, expiresAt: value.expiresAt,
    launchBearer });
  trustedAuth.add(context);
  return context;
}
function assertSecureShopStandaloneAuthPrincipal(value) {
  if (!trustedAuth.has(value)) throw failure('SHOP_AUTH_INVALID');
  return value;
}
function brandExecution(value, base) {
  if (!value || value.principalId !== base.principalId
      || value.principalOwnerId !== base.ownerId
      || value.authSessionId !== base.sessionId
      || value.shopUserId !== base.shopUserId
      || value.username !== base.username || value.email !== base.email
      || value.credentialVersion !== base.credentialVersion
      || value.authorityVersion !== base.authorityVersion
      || !Number.isSafeInteger(value.ownerId) || value.ownerId < 1
      || !Number.isSafeInteger(value.sessionId) || value.sessionId < 1
      || typeof value.tenantId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.tenantId)
      || typeof value.membershipVersion !== 'string'
      || !/^[1-9]\d*$/.test(value.membershipVersion)
      || !['customer', 'merchant', 'admin'].includes(value.role)
      || !Number.isFinite(Date.parse(value.expiresAt))
      || Date.parse(value.expiresAt) > Date.parse(base.expiresAt)) throw failure('SHOP_AUTH_INVALID');
  const launchBearer = createHmac('sha256', base.launchBearer)
    .update(JSON.stringify(['secureshop-tenant-launch-v1', value.tenantId, value.sessionId]))
    .digest('base64url');
  const execution = Object.freeze({ principalId: value.principalId,
    principalOwnerId: value.principalOwnerId, ownerId: value.ownerId,
    authSessionId: value.authSessionId, sessionId: value.sessionId,
    tenantId: value.tenantId, membershipVersion: value.membershipVersion,
    shopUserId: value.shopUserId, username: value.username, email: value.email,
    role: value.role, credentialVersion: value.credentialVersion,
    authorityVersion: value.authorityVersion, expiresAt: value.expiresAt,
    launchBearer });
  trustedExecution.add(execution);
  return execution;
}
function assertSecureShopStandalonePrincipal(value) {
  if (!trustedExecution.has(value)) throw failure('SHOP_AUTH_INVALID');
  return value;
}
function canonicalUsername(value) {
  if (typeof value !== 'string') throw failure('INVALID_ARGUMENT');
  const normalized = value.trim().toLowerCase();
  if (!USERNAME.test(normalized)) throw failure('INVALID_ARGUMENT');
  return normalized;
}
function canonicalEmail(value) {
  if (typeof value !== 'string') throw failure('INVALID_ARGUMENT');
  const normalized = value.trim().toLowerCase();
  if (Buffer.byteLength(normalized, 'utf8') > 320 || !EMAIL.test(normalized)) {
    throw failure('INVALID_ARGUMENT');
  }
  return normalized;
}
function validPassword(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 8
      || Buffer.byteLength(value, 'utf8') > 72 || value.includes('\0')) {
    throw failure('INVALID_ARGUMENT');
  }
  return value;
}
function sessionToken(randomBytes) {
  const bytes = randomBytes(32);
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw failure('SHOP_AUTH_INVALID');
  return bytes.toString('base64url');
}
function result(token, context) {
  return Object.freeze({ token, user: publicUser(context), context, expiresAt: context.expiresAt });
}

function createSecureShopStandaloneAuthService({ repository, now = Date.now,
  sessionTtlSeconds = SHOP_DEFAULT_SECONDS,
  randomBytes = cryptoRandomBytes, hashPassword = value => bcrypt.hash(value, 12),
  comparePassword = (value, digest) => bcrypt.compare(value, digest) } = {}) {
  const required = ['registerWithSession', 'findCredential', 'recordFailedLogin',
    'createSession', 'readCurrentSession', 'rotateSession', 'revokeSession',
    'readCredentialForSession', 'changePassword', 'revokeAll',
    'readOrCreateDefaultExecutionSession'];
  if (required.some(name => typeof repository?.[name] !== 'function')
      || typeof now !== 'function' || typeof randomBytes !== 'function'
      || typeof hashPassword !== 'function' || typeof comparePassword !== 'function') {
    throw new TypeError('Standalone shop authentication dependencies required');
  }
  const sessionMs = validateSessionLifetimeSeconds(sessionTtlSeconds, SHOP_DEFAULT_SECONDS,
    'SS_SESSION_TTL_SECONDS') * 1000;
  const expiresAt = () => new Date(now() + sessionMs).toISOString();
  async function authenticate(token) {
    if (typeof token !== 'string' || !TOKEN.test(token)) return null;
    const context = await repository.readCurrentSession(hashToken(token));
    return context ? brandAuth(context, token) : null;
  }
  return Object.freeze({
    async register({ username, email, password, role } = {}) {
      const normalizedUsername = canonicalUsername(username);
      const normalizedEmail = canonicalEmail(email);
      validPassword(password);
      if (!['customer', 'merchant'].includes(role)) throw failure('INVALID_ARGUMENT');
      const token = sessionToken(randomBytes);
      const context = brandAuth(await repository.registerWithSession({ principalId: randomUUID(),
        username: normalizedUsername, email: normalizedEmail,
        passwordHash: await hashPassword(password), role,
        tokenHash: hashToken(token), expiresAt: expiresAt() }), token);
      return result(token, context);
    },
    async login({ username, password } = {}) {
      if (typeof username !== 'string' || Buffer.byteLength(username, 'utf8') > 256
          || typeof password !== 'string' || !password
          || Buffer.byteLength(password, 'utf8') > 72) throw failure('SHOP_CREDENTIALS_INVALID');
      const normalizedUsername = username.trim().toLowerCase();
      const credential = USERNAME.test(normalizedUsername)
        ? await repository.findCredential(normalizedUsername) : null;
      const matched = await comparePassword(password, credential?.passwordHash || DUMMY_HASH);
      if (!credential || !matched || credential.isActive !== true
          || (credential.lockedUntil && new Date(credential.lockedUntil).getTime() > now())) {
        if (credential) await repository.recordFailedLogin(credential.principalId);
        throw failure('SHOP_CREDENTIALS_INVALID');
      }
      const token = sessionToken(randomBytes);
      let context;
      try { context = brandAuth(await repository.createSession({ principalId: credential.principalId,
        credentialVersion: String(credential.credentialVersion),
        authorityVersion: String(credential.authorityVersion),
        tokenHash: hashToken(token), expiresAt: expiresAt() }), token); }
      catch (error) { if (error?.code === 'SHOP_AUTH_INVALID') throw failure('SHOP_CREDENTIALS_INVALID'); throw error; }
      return result(token, context);
    },
    authenticate,
    async establishTenantContext(basePrincipal) {
      const base = assertSecureShopStandaloneAuthPrincipal(basePrincipal);
      const execution = await repository.readOrCreateDefaultExecutionSession({
        principalId: base.principalId, authSessionId: base.sessionId,
        credentialVersion: base.credentialVersion,
        authorityVersion: base.authorityVersion });
      return brandExecution(execution, base);
    },
    async renew(token) {
      if (typeof token !== 'string' || !TOKEN.test(token)) throw failure('SHOP_AUTH_INVALID');
      const replacement = sessionToken(randomBytes);
      const context = await repository.rotateSession({ tokenHash: hashToken(token),
        newTokenHash: hashToken(replacement), expiresAt: expiresAt() });
      if (!context) throw failure('SHOP_AUTH_INVALID');
      return result(replacement, brandAuth(context, replacement));
    },
    async logout(token) {
      if (typeof token !== 'string' || !TOKEN.test(token)) return false;
      return repository.revokeSession(hashToken(token));
    },
    async changePassword(token, { currentPassword, newPassword } = {}) {
      validPassword(newPassword);
      if (typeof token !== 'string' || !TOKEN.test(token)
          || typeof currentPassword !== 'string') throw failure('SHOP_AUTH_INVALID');
      const credential = await repository.readCredentialForSession(hashToken(token));
      if (!credential) throw failure('SHOP_AUTH_INVALID');
      if (!await comparePassword(currentPassword, credential.passwordHash)) {
        throw failure('SHOP_CREDENTIALS_INVALID');
      }
      await repository.changePassword({ tokenHash: hashToken(token),
        credentialVersion: String(credential.credentialVersion),
        passwordHash: await hashPassword(newPassword) });
      return Object.freeze({ ok: true, passwordChanged: true });
    },
    async revokeAll(token) {
      const context = await authenticate(token);
      if (!context) throw failure('SHOP_AUTH_INVALID');
      return repository.revokeAll(context.principalId);
    },
  });
}

module.exports = { createSecureShopStandaloneAuthService,
  assertSecureShopStandalonePrincipal, assertSecureShopStandaloneAuthPrincipal };
