'use strict';

const jwt = require('jsonwebtoken');
const { hasAdminLevel } = require('../middleware/postgresAdminAuth');
const crypto = require('node:crypto');
const {
  createPool
} = require('../database/postgres');
const {
  createIdentityRepository,
  initializeIdentityRepository
} = require('../database/postgres/identityRepository');
const {
  createWorkshopProgressRepository
} = require('../database/postgres/workshopProgressRepository');
const { assertPlatformSigningConfiguration } = require('./platformSigningConfiguration');
const { PLATFORM_DEFAULT_SECONDS, validateSessionLifetimeSeconds,
  readSessionLifetimeConfiguration } = require('./sessionLifetimeConfiguration');
function userDto(user, permissions = []) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    adminLevel: user.admin_level || 0,
    fullName: user.full_name,
    emailVerified: user.email_verified || 0,
    isAdmin: hasAdminLevel(user),
    permissions,
    lastLogin: user.last_login
  };
}
function createPostgresIdentityAdapter({
  repository,
  progress,
  jwtSecret,
  sessionTtlSeconds = PLATFORM_DEFAULT_SECONDS
}) {
  if (!repository || typeof jwtSecret !== 'string' || !jwtSecret.length) throw new Error('Identity repository and JWT secret required');
  const sessionLimitMs = validateSessionLifetimeSeconds(sessionTtlSeconds, PLATFORM_DEFAULT_SECONDS,
    'PLATFORM_SESSION_TTL_SECONDS') * 1000;
  return {
    repository,
    progress,
    jwtSecret,
    userDto,
    async createSession(user, req, {
      durationMs = 24 * 60 * 60 * 1000
    } = {}) {
      if (!Number.isSafeInteger(durationMs) || durationMs < 1000) throw new TypeError('Positive platform session duration required');
      // A trusted endpoint may select a shorter lifetime (secure-login uses one
      // hour). Configuration only caps it; JWT and database share one instant.
      const issuedAt = Math.floor(Date.now() / 1000);
      const lifetimeSeconds = Math.floor(Math.min(durationMs, sessionLimitMs) / 1000);
      const expiresAt = new Date((issuedAt + lifetimeSeconds) * 1000);
      const token = jwt.sign({
        iat: issuedAt,
        userId: user.id,
        username: user.username,
        role: user.role,
        adminLevel: user.admin_level || 0,
        emailVerified: user.email_verified || 0
      }, jwtSecret, {
        expiresIn: lifetimeSeconds,
        jwtid: crypto.randomUUID()
      });
      const session = await repository.createSession({
        userId: user.id,
        token,
        expiresAt,
        expectedPasswordHash: user.password,
        deviceInfo: {
          userAgent: req.get?.('User-Agent'),
          acceptLanguage: req.get?.('Accept-Language')
        },
        ipAddress: req.ip || null
      });
      const result = {
        token,
        expiresAt: session.expires_at.toISOString(),
        sessionInfo: {
          expiresAt: session.expires_at.toISOString(),
          tokenType: 'Bearer'
        }
      };
      Object.defineProperty(result, 'internalSessionId', { value: session.id });
      return result;
    },
    async validateSession(token) {
      const decoded = jwt.verify(token, jwtSecret, {
        algorithms: ['HS256']
      });
      if (!Number.isInteger(decoded.userId) || decoded.userId <= 0) throw new jwt.JsonWebTokenError('Invalid user ID');
      const lock = await repository.checkAccountLockout(decoded.userId);
      if (lock.locked) throw Object.assign(new Error('Account locked'), {
        name: 'AccountLocked',
        lockedUntil: lock.lockedUntil
      });
      const found = await repository.findActiveSession(token, decoded.userId);
      if (!found) return null;
      return {
        ...found,
        decoded
      };
    },
    async logout(token) {
      // Signature verification still permits revocation of an expired JWT; no new session is created.
      let decoded;
      try {
        decoded = jwt.verify(token, jwtSecret, {
          ignoreExpiration: true,
          algorithms: ['HS256']
        });
      } catch {
        return 0;
      }
      return repository.revokeSession(token, decoded.userId);
    }
  };
}
let singleton;
function getPostgresIdentityAdapter() {
  if (!singleton) {
    const { jwtSecret } = assertPlatformSigningConfiguration(process.env);
    const { platformSessionTtlSeconds } = readSessionLifetimeConfiguration(process.env);
    const pool = createPool(process.env, 'IDENTITY_DATABASE_URL');
    singleton = createPostgresIdentityAdapter({
      repository: createIdentityRepository(pool),
      progress: createWorkshopProgressRepository(pool),
      jwtSecret,
      sessionTtlSeconds: platformSessionTtlSeconds
    });
    singleton.pool = pool;
  }
  return singleton;
}
async function initializePostgresIdentity() {
  const adapter = getPostgresIdentityAdapter(),
    migration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try {
    await initializeIdentityRepository(adapter.pool, migration);
    await require('../database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  } finally {
    await migration.end();
  }
}
module.exports = {
  createPostgresIdentityAdapter,
  getPostgresIdentityAdapter,
  initializePostgresIdentity,
  userDto
};
