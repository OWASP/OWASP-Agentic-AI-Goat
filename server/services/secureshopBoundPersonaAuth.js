'use strict';

const { randomBytes, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { markSecureShopLaunchUnavailable } = require('../middleware/secureshopLaunch');

const apiAuthorities = new WeakSet();
function resolveBoundApiKeyAuthority(fence,{scope,persona}={}) {
 const trusted=createLaunchScope(scope);
 if(!apiAuthorities.has(fence)||Object.keys(trusted).some(k=>fence.binding[k]!==trusted[k])
   ||fence.binding.personaId!==persona?.id||fence.binding.role!==persona?.role)throw fail('SHOP_API_KEY_INVALID');
 return fence;
}

const ISSUER = 'dvaia-secureshop-bound';
const AUDIENCE = 'dvaia-secureshop-bound-persona';
const ROLES = new Set(['customer', 'merchant', 'admin']);
const PERSONAS = Object.freeze({ student_customer: 'customer', student_merchant: 'merchant',
  student_admin: 'admin' });
const MAX_TOKEN_BYTES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_IP_BYTES = 128;
const MAX_USER_AGENT_BYTES = 1024;
const MIN_PASSWORD_CHARACTERS = 8;
// bcrypt compares at most 72 input bytes. Reject larger inputs instead of
// accepting two distinct strings that share the same bcrypt prefix.
const MAX_PASSWORD_BYTES = 72;
const API_KEY = /^sk_ss_live_[0-9a-f]{32}$/;

function fail(code, message = 'Shop authentication unavailable') {
  return Object.assign(new Error(message), { code });
}
function publicUser(row) {
  return Object.freeze({ id: Number(row.id), username: row.username, email: row.email,
    role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null });
}
function bearer(req) {
  const value = req.get?.('authorization') || req.headers?.authorization || '';
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match && Buffer.byteLength(match[1], 'utf8') <= MAX_TOKEN_BYTES ? match[1] : null;
}
function metadata(value, maximum) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= maximum ? value : null;
}
function sessionId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw fail('SHOP_AUTH_INVALID');
  return value.toLowerCase();
}
function persona(value) {
  if (!value || !Number.isSafeInteger(value.id) || value.id < 1 || !ROLES.has(value.role)) {
    throw fail('SHOP_AUTH_INVALID');
  }
  return Object.freeze({ id: value.id, role: value.role });
}
function apiKey(value) {
  if (typeof value !== 'string' || !API_KEY.test(value)) throw fail('SHOP_API_KEY_INVALID');
  return value;
}
function publicSession(row, currentSessionId) {
  const id = sessionId(row?.id);
  const createdAt = new Date(row.created_at).toISOString();
  const lastSeenAt = new Date(row.last_seen_at).toISOString();
  if (typeof row.is_current !== 'boolean' || row.is_current !== (id === currentSessionId)
      || (row.ip !== null && (typeof row.ip !== 'string'
        || Buffer.byteLength(row.ip, 'utf8') > MAX_IP_BYTES))
      || (row.user_agent !== null && (typeof row.user_agent !== 'string'
        || Buffer.byteLength(row.user_agent, 'utf8') > MAX_USER_AGENT_BYTES))) {
    throw fail('SHOP_AUTH_INVALID');
  }
  return Object.freeze({ id, user_agent: row.user_agent, ip: row.ip,
    created_at: createdAt, last_seen_at: lastSeenAt, is_current: row.is_current });
}

function createSecureShopBoundPersonaAuth({ repository, launches, jwtSecret, personaAuthority,
  randomId = randomUUID, randomKeyBytes = randomBytes, now = () => Date.now() } = {}) {
  if (!repository || ['findCredential', 'createSession', 'readSession', 'extendSession', 'revokeSession',
    'listSessions', 'revokeOwnedSession', 'changePassword', 'readApiKey', 'rotateApiKey',
    'authenticateApiKey']
    .some(name => typeof repository[name] !== 'function')
    || typeof launches?.assertCurrent !== 'function'
    || typeof jwtSecret !== 'string' || Buffer.byteLength(jwtSecret, 'utf8') < 32
    || typeof randomId !== 'function' || typeof randomKeyBytes !== 'function'
    || typeof now !== 'function') {
    throw new TypeError('Bound persona authentication dependencies required');
  }
  if (personaAuthority && (typeof personaAuthority.read !== 'function' || typeof repository.findCredentialById !== 'function' || repository.candidatePersonaAuthority !== personaAuthority)) throw new TypeError('Candidate persona authority required');
  async function authority(scope,id,expected) { return personaAuthority ? personaAuthority.read(scope,id,expected) : null; }
  async function originalCredential(scope,owner,currentSessionId,authorityVersion) {
    if(!personaAuthority)return undefined;
    if(typeof authorityVersion!=='string'||!/^[1-9]\d*$/.test(authorityVersion))throw fail('SHOP_AUTH_INVALID');
    const fence=await personaAuthority.capture({scope,personaId:owner.id,role:owner.role,sessionId:sessionId(currentSessionId),authorityVersion});
    if(typeof fence?.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
    await fence.assertRemoteAdmission();return fence;
  }
  function decode(token, scope) {
    if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
      throw fail('SHOP_AUTH_INVALID');
    }
    let claims;
    try {
      claims = jwt.verify(token, jwtSecret, { algorithms: ['HS256'], issuer: ISSUER,
        audience: AUDIENCE });
    } catch { throw fail('SHOP_AUTH_INVALID'); }
    const trusted = createLaunchScope(scope);
    if (claims.ss_launch_id !== trusted.launchId || claims.ss_scenario_id !== trusted.scenarioId
      || claims.ss_generation !== trusted.generation || claims.ss_owner_id !== trusted.platformOwnerId
      || claims.ss_platform_session_id !== trusted.platformSessionId
      || typeof claims.jti !== 'string' || typeof claims.sub !== 'string'
      || !/^[1-9][0-9]*$/.test(claims.sub) || !ROLES.has(claims.role)) {
      throw fail('SHOP_AUTH_INVALID');
    }
    if (personaAuthority && (typeof claims.ss_authority_version !== 'string' || !/^[1-9]\d*$/.test(claims.ss_authority_version))) throw fail('SHOP_AUTH_INVALID');
    const shopUserId = Number(claims.sub);
    if (!Number.isSafeInteger(shopUserId) || shopUserId > 2147483647) throw fail('SHOP_AUTH_INVALID');
    return Object.freeze({ claims, scope: trusted, shopUserId });
  }
  async function authenticate(token, scope) {
    const decoded = decode(token, scope);
    await launches.assertCurrent(decoded.scope);
    const session = await repository.readSession({ jti: decoded.claims.jti, scope: decoded.scope });
    if (!session || Number(session.shop_user_id) !== decoded.shopUserId
      || session.role !== decoded.claims.role) throw fail('SHOP_AUTH_INVALID');
    const currentSessionId = sessionId(session.session_id);
    const user = { id: Number(session.shop_user_id), username: session.username,
      email: session.email, role: session.role, full_name: session.full_name, phone: session.phone };
    if ((!personaAuthority && PERSONAS[user.username] !== user.role) || !ROLES.has(user.role)) {
      throw fail('SHOP_AUTH_INVALID');
    }
    if (personaAuthority) await authority(decoded.scope,user.id,{role:user.role,version:decoded.claims.ss_authority_version});
    await launches.assertCurrent(decoded.scope);
    return Object.freeze({ user: publicUser(user), jti: decoded.claims.jti,
      sessionId: currentSessionId,
      ...(personaAuthority?{authorityVersion:decoded.claims.ss_authority_version}:{}),
      expiresAt: new Date(session.expires_at).toISOString() });
  }
  function tokenFor(row, trusted, { jti, expiresAtMs, currentTime }) {
    return jwt.sign({ role: row.role, username: row.username,
      ...(personaAuthority ? {ss_authority_version:row.authority_version} : {}),
      ss_launch_id: trusted.launchId, ss_scenario_id: trusted.scenarioId,
      ss_generation: trusted.generation, ss_owner_id: trusted.platformOwnerId,
      ss_platform_session_id: trusted.platformSessionId }, jwtSecret, {
      algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, subject: String(row.id),
      jwtid: jti, expiresIn: Math.max(1, Math.floor((expiresAtMs - currentTime) / 1000)),
    });
  }
  async function issueStandaloneSession({ scope, shopPrincipal, ip = null, userAgent = null }, additional = null) {
      // Only the standalone auth service can mint this private-branded context.
      // A request body with the same fields must never become shop authority.
      const principal = require('./secureshopStandaloneAuth').assertSecureShopStandalonePrincipal(shopPrincipal);
      const trusted = createLaunchScope(scope);
      if (!personaAuthority || principal.ownerId !== trusted.platformOwnerId
        || principal.sessionId !== trusted.platformSessionId
        || !Number.isSafeInteger(principal.shopUserId)
        || principal.shopUserId < 1000000000
        || !ROLES.has(principal.role)) throw fail('SHOP_AUTH_INVALID');
      const currentLaunch = await launches.assertCurrent(trusted);
      const actor = await repository.ensureStandaloneActor({ scope: trusted, shopPrincipal: principal });
      const effective = await authority(trusted, actor.id);
      const currentTime = now();
      const expiresAtMs = Math.min(currentTime + 4 * 60 * 60 * 1000,
        new Date(currentLaunch?.expiresAt).getTime(), new Date(principal.expiresAt).getTime());
      if (!Number.isFinite(currentTime) || !Number.isFinite(expiresAtMs)
        || expiresAtMs <= currentTime) throw fail('STALE_LAUNCH');
      const boundSessionId = randomId();
      const jti = randomId();
      const expiresAt = new Date(expiresAtMs).toISOString();
      const sessionActor = { ...actor, role: effective.role };
      const row = { ...sessionActor, authority_version: effective.authority_version };
      const established = await repository.createSession({ sessionId: boundSessionId, jti, scope: trusted,
        persona: sessionActor, expiresAt, ip: metadata(ip, MAX_IP_BYTES),
        userAgent: metadata(userAgent, MAX_USER_AGENT_BYTES), credentialVersion: 1,
        authorityVersion: effective.authority_version,
        additionalSession: Boolean(additional), sourceJti: additional?.jti,
        bootstrap: { principalId: principal.principalId,
          authSessionId: principal.authSessionId,
          executionSessionId: principal.sessionId,
          membershipVersion: principal.membershipVersion,
          credentialVersion: principal.credentialVersion,
          authorityVersion: principal.authorityVersion } });
      const actualExpiryMs = new Date(established.expiresAt).getTime();
      if (!Number.isFinite(actualExpiryMs) || actualExpiryMs > expiresAtMs
        || actualExpiryMs <= currentTime) throw fail('SHOP_AUTH_INVALID');
      const token = tokenFor(row, trusted,
        { jti: established.jti, expiresAtMs: actualExpiryMs, currentTime });
      try { await launches.assertCurrent(trusted); }
      catch (error) {
        if (!established.reused) await repository.revokeSession({ jti, scope: trusted }).catch(() => {});
        throw error;
      }
      return Object.freeze({ ok: true, token, user: publicUser(sessionActor),
        expiresAt: established.expiresAt });
  }
  const service = {
    async establishSession(input = {}) { return issueStandaloneSession(input); },
    async establishAdditionalSession({ scope, shopPrincipal, token, ip = null, userAgent = null } = {}) {
      const principal = require('./secureshopStandaloneAuth').assertSecureShopStandalonePrincipal(shopPrincipal);
      const current = await authenticate(token, scope);
      if (current.user.id !== principal.shopUserId || current.user.username !== principal.username)
        throw fail('SHOP_AUTH_INVALID');
      return issueStandaloneSession({ scope, shopPrincipal: principal, ip, userAgent }, current);
    },
    async login({ scope, username, password, ip = null, userAgent = null } = {}) {
      const trusted = createLaunchScope(scope);
      if (typeof username !== 'string' || !username || Buffer.byteLength(username, 'utf8') > 256
        || typeof password !== 'string' || !password
        || Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
        throw fail('SHOP_CREDENTIALS_INVALID', 'Invalid shop credentials');
      }
      const currentLaunch = await launches.assertCurrent(trusted);
      const row = await repository.findCredential(username, trusted);
      if (!row || row.banned_at || (!personaAuthority && PERSONAS[row.username] !== row.role)
        || typeof row.password !== 'string' || !await bcrypt.compare(password, row.password)) {
        throw fail('SHOP_CREDENTIALS_INVALID', 'Invalid shop credentials');
      }
      const currentTime = now();
      const launchExpiry = new Date(currentLaunch?.expiresAt).getTime();
      const expiresAtMs = Math.min(currentTime + 4 * 60 * 60 * 1000, launchExpiry);
      if (!Number.isFinite(currentTime) || !Number.isFinite(expiresAtMs) || expiresAtMs <= currentTime) {
        throw fail('STALE_LAUNCH');
      }
      const sessionId = randomId();
      const jti = randomId();
      const expiresAt = new Date(expiresAtMs).toISOString();
      const token = tokenFor(row, trusted, { jti, expiresAtMs, currentTime });
      await repository.createSession({ sessionId, jti, scope: trusted,
        persona: { id: Number(row.id), username: row.username, email: row.email,
          role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null }, expiresAt,
          ip: metadata(ip, MAX_IP_BYTES), userAgent: metadata(userAgent, MAX_USER_AGENT_BYTES),
          credentialVersion: Number(row.credential_version || 1), ...(personaAuthority?{authorityVersion:row.authority_version}:{}) });
      try { await launches.assertCurrent(trusted); }
      catch (error) {
        await repository.revokeSession({ jti, scope: trusted }).catch(() => {});
        throw error;
      }
      return Object.freeze({ ok: true, token, user: publicUser(row), expiresAt });
    },
    async renew({ scope, token } = {}) {
      const decoded = decode(token, scope); // Expired JWTs must sign in again.
      const currentLaunch = await launches.assertCurrent(decoded.scope);
      const session = await repository.readSession({ jti: decoded.claims.jti, scope: decoded.scope });
      if (!session || Number(session.shop_user_id) !== decoded.shopUserId
        || session.role !== decoded.claims.role || session.username !== decoded.claims.username) {
        throw fail('SHOP_AUTH_INVALID');
      }
      const currentTime = now();
      const launchExpiry = new Date(currentLaunch?.expiresAt).getTime();
      const expiresAtMs = Math.min(currentTime + 4 * 60 * 60 * 1000, launchExpiry);
      if (!Number.isFinite(currentTime) || !Number.isFinite(expiresAtMs) || expiresAtMs <= currentTime) {
        throw fail('STALE_LAUNCH');
      }
      const effective = await authority(decoded.scope,decoded.shopUserId,{role:session.role,version:decoded.claims.ss_authority_version});
      const extended = await repository.extendSession({ jti: decoded.claims.jti,
        scope: decoded.scope, expiresAt: new Date(expiresAtMs).toISOString() });
      if (!extended || Number(extended.shop_user_id) !== decoded.shopUserId
        || extended.role !== decoded.claims.role || extended.username !== decoded.claims.username) {
        throw fail('SHOP_AUTH_INVALID');
      }
      try { await launches.assertCurrent(decoded.scope); }
      catch (error) {
        await repository.revokeSession({ jti: decoded.claims.jti, scope: decoded.scope }).catch(() => {});
        throw error;
      }
      const expiresAt = new Date(extended.expires_at).toISOString();
      const refreshed = { id: Number(extended.shop_user_id), username: extended.username,
        email: extended.email, role: extended.role, full_name: extended.full_name, phone: extended.phone, ...(effective?{authority_version:effective.authority_version}:{}) };
      return Object.freeze({ ok: true,
        token: tokenFor(refreshed, decoded.scope, { jti: decoded.claims.jti,
          expiresAtMs: new Date(expiresAt).getTime(), currentTime }),
        user: publicUser(refreshed), expiresAt });
    },
    async logout({ scope, token } = {}) {
      let decoded;
      try { decoded = decode(token, scope); } catch { return Object.freeze({ ok: true }); }
      await repository.revokeSession({ jti: decoded.claims.jti, scope: decoded.scope });
      return Object.freeze({ ok: true });
    },
    async listSessions({ scope, shopPersona, currentSessionId, authorityVersion } = {}) {
      const trusted = createLaunchScope(scope);
      const owner = persona(shopPersona);
      const current = sessionId(currentSessionId);
      await launches.assertCurrent(trusted);
      const fence=await originalCredential(trusted,owner,current,authorityVersion);
      const rows = await repository.listSessions({ scope: trusted, shopUserId: owner.id,
        currentSessionId: current });
      await launches.assertCurrent(trusted);
      await fence?.assertRemoteAdmission();
      if (!Array.isArray(rows) || rows.length > 20) throw fail('SHOP_AUTH_INVALID');
      const projected = Object.freeze(rows.map(row => publicSession(row, current)));
      if (projected.filter(row => row.is_current).length !== 1) throw fail('SHOP_AUTH_INVALID');
      return projected;
    },
    async revokeOwnedSession({ scope, shopPersona, currentSessionId, authorityVersion, sessionId: selectedId } = {}) {
      const trusted = createLaunchScope(scope);
      const owner = persona(shopPersona);
      const current=sessionId(currentSessionId);
      if(personaAuthority&&(typeof authorityVersion!=='string'||! /^[1-9]\d*$/.test(authorityVersion)))throw fail('SHOP_AUTH_INVALID');
      const selected = sessionId(selectedId);
      await launches.assertCurrent(trusted);
      const revoked = await repository.revokeOwnedSession({ scope: trusted, shopUserId: owner.id,
        sessionId: selected,...(personaAuthority?{actingCredential:Object.freeze({sessionId:current,role:owner.role,authorityVersion})}:{}) });
      await launches.assertCurrent(trusted);
      return revoked === true;
    },
    async changePassword({ scope, shopPersona, currentSessionId, currentPassword,
      newPassword } = {}) {
      const trusted = createLaunchScope(scope);
      const owner = persona(shopPersona);
      const current = sessionId(currentSessionId);
      if (typeof currentPassword !== 'string' || !currentPassword
          || Buffer.byteLength(currentPassword, 'utf8') > MAX_PASSWORD_BYTES
          || typeof newPassword !== 'string'
          || [...newPassword].length < MIN_PASSWORD_CHARACTERS
          || Buffer.byteLength(newPassword, 'utf8') > MAX_PASSWORD_BYTES) {
        throw fail('SHOP_PASSWORD_INVALID', 'Invalid shop password');
      }
      await launches.assertCurrent(trusted);
      const effective = await authority(trusted,owner.id,{role:owner.role});
      const row = personaAuthority ? await repository.findCredentialById(owner.id,trusted) : await repository.findCredential(Object.keys(PERSONAS)
        .find(username => PERSONAS[username] === owner.role), trusted);
      if (!row || Number(row.id) !== owner.id || !await bcrypt.compare(currentPassword, row.password)) {
        throw fail('SHOP_PASSWORD_MISMATCH', 'Current shop password is incorrect');
      }
      const nextHash = await bcrypt.hash(newPassword, 10);
      const changed = await repository.changePassword({ scope: trusted, shopUserId: owner.id,
        currentSessionId: current, expectedHash: row.password, nextHash, ...(effective?{expectedRole:owner.role,authorityVersion:effective.authority_version}:{}) });
      if (!changed) throw fail('SHOP_PASSWORD_MISMATCH', 'Current shop password is incorrect');
      await launches.assertCurrent(trusted);
      return Object.freeze({ ok: true });
    },
    async listApiKey({ scope, shopPersona, currentSessionId, authorityVersion } = {}) {
      const trusted = createLaunchScope(scope);
      const owner = persona(shopPersona);
      await launches.assertCurrent(trusted);
      const fence=await originalCredential(trusted,owner,currentSessionId,authorityVersion);
      const row = await repository.readApiKey({ scope: trusted, shopUserId: owner.id });
      await launches.assertCurrent(trusted);
      await fence?.assertRemoteAdmission();
      if (!row) return Object.freeze({ api_key: null, created_at: null, version: null });
      return Object.freeze({ api_key: apiKey(row.apiKey),
        created_at: new Date(row.createdAt).toISOString(),
        version: Number(row.version) });
    },
    async rotateApiKey({ scope, shopPersona, currentSessionId } = {}) {
      const trusted = createLaunchScope(scope);
      const owner = persona(shopPersona);
      await launches.assertCurrent(trusted);
      if (personaAuthority) sessionId(currentSessionId);
      const effective = await authority(trusted,owner.id,{role:owner.role});
      const bytes = randomKeyBytes(16);
      if (!Buffer.isBuffer(bytes) || bytes.length !== 16) throw fail('SHOP_API_KEY_INVALID');
      const row = await repository.rotateApiKey({ scope: trusted, shopUserId: owner.id,
        nextKey: `sk_ss_live_${bytes.toString('hex')}`, ...(effective?{expectedRole:owner.role,authorityVersion:effective.authority_version,currentSessionId}:{}) });
      await launches.assertCurrent(trusted);
      return Object.freeze({ ok: true, api_key: apiKey(row.apiKey),
        created_at: new Date(row.createdAt).toISOString(), version: Number(row.version) });
    },
    async authenticateApiKey({ scope, presentedKey } = {}) {
      const trusted = createLaunchScope(scope);
      const key = apiKey(presentedKey);
      await launches.assertCurrent(trusted);
      const row = await repository.authenticateApiKey({ scope: trusted, presentedKey: key });
      if (!row) throw fail('SHOP_API_KEY_INVALID');
      await launches.assertCurrent(trusted);
      return Object.freeze({ user: publicUser(row), apiKeyVersion: Number(row.apiKeyVersion) });
    },
    async captureApiKeyAuthority({scope,presentedKey}={}) {
      const trusted=createLaunchScope(scope),key=apiKey(presentedKey);
      const original=await service.authenticateApiKey({scope:trusted,presentedKey:key});
      if(!Number.isSafeInteger(original.apiKeyVersion)||original.apiKeyVersion<1)throw fail('SHOP_API_KEY_INVALID');
      const binding=Object.freeze({...trusted,personaId:original.user.id,role:original.user.role,apiKeyVersion:original.apiKeyVersion});
      const fence=Object.freeze({binding,async assertRemoteAdmission(){
        const current=await service.authenticateApiKey({scope:trusted,presentedKey:key});
        if(current.user.id!==binding.personaId||current.user.role!==binding.role||current.apiKeyVersion!==binding.apiKeyVersion)throw fail('SHOP_API_KEY_INVALID');
      }});
      apiAuthorities.add(fence);return fence;
    },
    authenticateBoundToken({token,scope}) { return authenticate(token,scope); },
    authenticatePersona(req, res, next) {
      const token = bearer(req);
      if (!token || !req.ssLaunch) return res.status(401).json({ error: 'Shop authentication required' });
      authenticate(token, req.ssLaunch).then(value => {
        req.ssUser = value.user;
        req.ssPersonaSession = Object.freeze({ sessionId: value.sessionId, expiresAt: value.expiresAt,
          ...(value.authorityVersion?{authorityVersion:value.authorityVersion}:{}) });
        next();
      }, error => {
        if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE'].includes(error?.code)) {
          return markSecureShopLaunchUnavailable(res).status(401)
            .json({ error: 'SecureShop launch unavailable' });
        }
        if (error?.code === 'OWNER_MISMATCH') {
          return res.status(401).json({ error: 'SecureShop launch unavailable' });
        }
        if (error?.code === 'SHOP_AUTH_INVALID') return res.status(401).json({ error: 'Shop authentication required' });
        return res.status(503).json({ error: 'Shop authentication unavailable' });
      });
    },
  };
  return Object.freeze(service);
}

module.exports = { createSecureShopBoundPersonaAuth, resolveBoundApiKeyAuthority, ISSUER, AUDIENCE,
  MAX_IP_BYTES, MAX_USER_AGENT_BYTES, MIN_PASSWORD_CHARACTERS, MAX_PASSWORD_BYTES };
