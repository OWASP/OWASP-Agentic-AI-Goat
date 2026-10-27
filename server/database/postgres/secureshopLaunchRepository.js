'use strict';

const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { withTransaction } = require('./index');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER = /^[A-Za-z0-9_-]{43}$/;
const MAX_SAFE_GENERATION = Number.MAX_SAFE_INTEGER;
const MAX_OWNER_FILES_TARGETS = 256;
const MAX_OWNER_PRODUCT_TARGETS = 256;
const MAX_OWNER_REVIEW_TARGETS = 256;
const MAX_OWNER_LAUNCHES = 256;

function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
function positiveId(value, label) {
  if (!Number.isInteger(value) || value < 1 || value > 2147483647) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw failure('INVALID_ARGUMENT', 'launch expiry is invalid');
  return date.toISOString();
}
function boundedText(value, label, max) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value) > max) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function generation(value, label = 'generation') {
  if (!Number.isSafeInteger(value) || value < 1) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function digest(value) { return crypto.createHash('sha256').update(value).digest(); }
function binding(row) {
  const rowGeneration = Number(row.generation);
  const credentialVersion = Number(row.credential_version);
  if (!Number.isSafeInteger(rowGeneration) || rowGeneration < 1
    || !Number.isSafeInteger(credentialVersion) || credentialVersion < 1) {
    throw failure('INVALID_STORED_AUTHORITY', 'stored launch authority is invalid');
  }
  return Object.freeze({
    launchId: row.launch_id,
    platformSessionId: Number(row.platform_session_id),
    platformOwnerId: Number(row.platform_owner_id),
    scenarioId: row.scenario_id,
    generation: rowGeneration,
    status: row.status,
    expiresAt: row.expires_at,
    credentialVersion,
  });
}

function createSecureShopLaunchRepository(pool, dependencies = {}) {
  if (!pool || typeof pool.query !== 'function' || typeof pool.connect !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'PostgreSQL pool is required');
  }
  // Private to this repository instance; only the purpose-specific settlement
  // method can establish a held identity transaction context.
  const recoveryIdentity = new AsyncLocalStorage();
  const randomBytes = dependencies.randomBytes || crypto.randomBytes;
  const randomUUID = dependencies.randomUUID || crypto.randomUUID;

  function makeBearer() {
    const bytes = randomBytes(32);
    if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw failure('INVALID_CONFIGURATION', 'launch entropy source is invalid');
    return bytes.toString('base64url');
  }
  function makeUuid(label) { return uuid(randomUUID(), label); }

  async function lockTrustedContext(client, platformSessionId, platformOwnerId, { requireActive = true } = {}) {
    const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
    const sessionId = positiveId(platformSessionId, 'platformSessionId');
    const user = (await client.query('SELECT id,realm,is_active,account_locked_until FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE', [ownerId])).rows[0];
    if (!user) throw failure('OWNER_MISMATCH', 'trusted platform owner is unavailable');
    const session = (await client.query('SELECT id,user_id,realm,is_active,expires_at FROM identity.secureshop_authority_sessions WHERE id=$1 FOR UPDATE', [sessionId])).rows[0];
    if (!session || Number(session.user_id) !== ownerId) throw failure('OWNER_MISMATCH', 'trusted platform session does not belong to the owner');
    const now = (await client.query('SELECT clock_timestamp() AS now')).rows[0].now;
    if (requireActive && (!user.is_active || (user.account_locked_until && user.account_locked_until > now)
      || !session.is_active || session.expires_at <= now)) {
      throw failure('SESSION_UNAVAILABLE', 'trusted platform session is unavailable');
    }
    return { user, session, now };
  }

  async function requireFreshActiveContext(client, context) {
    const now = (await client.query('SELECT clock_timestamp() AS now')).rows[0].now;
    if (!context.user.is_active || (context.user.account_locked_until && context.user.account_locked_until > now)
      || !context.session.is_active || context.session.expires_at <= now) {
      throw failure('SESSION_UNAVAILABLE', 'trusted platform session is unavailable');
    }
    return now;
  }

  async function lockLaunch(client, launchId, platformSessionId) {
    const row = (await client.query(
      `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
       LEFT JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
       WHERE l.launch_id=$1 FOR UPDATE OF l`, [uuid(launchId, 'launchId')]
    )).rows[0];
    if (!row || Number(row.platform_session_id) !== platformSessionId) throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
    return row;
  }

  return Object.freeze({
    // Purpose-specific private dependency, never a caller-supplied callback.
    // Agents grant may commit first; a failed identity COMMIT leaves a durable
    // unresolved obligation but never returns a dispatchable capability.
    async admitOwnedMcpRegistration(prepared) {
      const journal=dependencies.ownedMcpRegistrationJournal;
      if(typeof journal?.scopeOf!=='function'||typeof journal?.admitPrepared!=='function')
        throw failure('INVALID_CONFIGURATION','Owned registration admission unavailable');
      const scope=journal.scopeOf(prepared);
      return withTransaction(pool,async client=>{
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL lock_timeout='3000ms'");
        const context=await lockTrustedContext(client,scope.platformSessionId,scope.platformOwnerId);
        const launch=await lockLaunch(client,scope.launchId,scope.platformSessionId);
        const now=await requireFreshActiveContext(client,context);
        if(launch.status!=='active'||launch.expires_at<=now||Number(launch.generation)!==scope.generation||launch.scenario_id!==scope.scenarioId)
          throw failure('STALE_GENERATION','Registration launch unavailable');
        return journal.admitPrepared(prepared);
      });
    },
    async admitOwnedMcpInvocation(prepared) {
      const journal = dependencies.ownedMcpInvocationJournal;
      if (typeof journal?.scopeOf !== 'function' || typeof journal?.admitPrepared !== 'function') {
        throw failure('INVALID_CONFIGURATION', 'Owned invocation admission unavailable');
      }
      const scope = journal.scopeOf(prepared);
      return withTransaction(pool, async client => {
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL lock_timeout='3000ms'");
        const context = await lockTrustedContext(client, scope.platformSessionId, scope.platformOwnerId);
        const launch = await lockLaunch(client, scope.launchId, scope.platformSessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== scope.generation
          || launch.scenario_id !== scope.scenarioId) throw failure('STALE_GENERATION', 'Invocation launch unavailable');
        return journal.admitPrepared(prepared);
      });
    },
    async settleOwnedMcpRecovery(handle, receipt) {
      const recovery = dependencies.ownedMcpInvocationRecovery;
      if (typeof recovery?.scopeOf !== 'function' || typeof recovery?.settlePrepared !== 'function')
        throw failure('INVALID_CONFIGURATION', 'Owned recovery unavailable');
      const scope = recovery.scopeOf(handle);
      let settlementEntered = false;
      try {
        return await withTransaction(pool, async client => {
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          const context = await lockTrustedContext(client, scope.platformSessionId, scope.platformOwnerId);
          const launch = await lockLaunch(client, scope.launchId, scope.platformSessionId);
          const now = await requireFreshActiveContext(client, context);
          if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== scope.generation
            || launch.scenario_id !== scope.scenarioId) throw failure('STALE_GENERATION', 'Recovery launch unavailable');
          settlementEntered = true;
          const held = {client, scope, active:true};
          try { return await recoveryIdentity.run(held, () => recovery.settlePrepared(handle, receipt)); }
          finally { held.active = false; }
        });
      } catch (cause) {
        if (!settlementEntered) throw cause;
        const error = failure('MCP_RECOVERY_SETTLEMENT_UNCERTAIN', 'Recovery settlement requires authoritative status readback');
        Object.defineProperty(error, 'cause', { value: cause });
        throw error;
      }
    },
    // Recovery is a separate, explicitly authenticated operation. Metadata is
    // not a capability and must never authorize a shop request or tool effect.
    async readActiveMetadata({ platformSessionId, platformOwnerId }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const row = (await pool.query(
        `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
         JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
         JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
         WHERE l.platform_session_id=$1 AND s.user_id=$2
           AND l.status='active' AND l.expires_at>clock_timestamp()
           AND s.is_active=1 AND s.expires_at>clock_timestamp()
           AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`,
        [sessionId, ownerId]
      )).rows[0];
      return row ? binding(row) : null;
    },

    async recoverCredential({ platformSessionId, platformOwnerId, launchId, expectedCredentialVersion }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const version = generation(expectedCredentialVersion, 'expectedCredentialVersion');
      const bearer = makeBearer();
      const recovered = await withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        if (Number(launch.credential_version) !== version || version >= MAX_SAFE_GENERATION) {
          throw failure('STALE_HANDLE', 'launch credential version is no longer current');
        }
        const row = (await client.query(
          `UPDATE identity.secureshop_launches SET handle_hash=$1,
           credential_version=credential_version+1,updated_at=clock_timestamp()
           WHERE launch_id=$2 AND credential_version=$3 AND status='active'
             AND expires_at>clock_timestamp() RETURNING *`, [digest(bearer), launch.launch_id, version]
        )).rows[0];
        if (!row) throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        row.platform_owner_id = ownerId;
        return binding(row);
      });
      return Object.freeze({ bearer, binding: recovered });
    },

    // Each reservation remains cleanup debt until canonical receipt reconciliation.
    // Shop tenants admit one unresolved target per immutable principal across
    // login sessions, within the tenant's aggregate ceiling. Platform owners
    // retain their existing one-unresolved-target admission contract.
    async reserveFilesTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        let existing;
        if (context.user.realm === 'shop') {
          // These immutable coordinates come from the authenticated execution
          // session, never from an HTTP persona or caller-selected principal.
          const principal = (await client.query(`SELECT e.tenant_id::text AS tenant_id,
            e.principal_id::text AS principal_id
            FROM identity.secureshop_authority_sessions s
            JOIN secureshop_auth.execution_sessions e
              ON e.session_id=s.shop_execution_session_id AND e.session_id=s.id
            JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id AND t.owner_id=s.user_id
            WHERE s.id=$1 AND s.user_id=$2 AND s.realm='shop'`, [sessionId, ownerId])).rows[0];
          if (!principal || !UUID.test(principal.tenant_id) || !UUID.test(principal.principal_id)) {
            throw failure('CLEANUP_REQUIRED', 'files target principal authority is unavailable');
          }
          // 0151 derives these immutable columns from the original birth
          // session. Never reclassify debt through a nullable current session.
          existing = (await client.query(`SELECT r.*
            FROM identity.secureshop_target_reservations r
            JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
            WHERE l.original_platform_owner_id=$1 AND r.target_kind='files'`, [ownerId])).rows;
          // Never erase or discount unclassified historical debt. Original
          // execution identity remains authoritative after logout or revocation.
          if (existing.some(row => row.files_tenant_id !== principal.tenant_id
              || !UUID.test(row.files_principal_id)
              || Number(row.original_platform_owner_id) !== ownerId)) {
            throw failure('CLEANUP_REQUIRED', 'files target cleanup scope is unavailable');
          }
          const own = existing.filter(row => row.files_principal_id === principal.principal_id);
          if (own.some(row => row.launch_id !== launch.launch_id || Number(row.generation) !== expected)
              || existing.some(row => row.launch_id === launch.launch_id
                && Number(row.generation) === expected && row.files_principal_id !== principal.principal_id)) {
            throw failure('CLEANUP_REQUIRED', 'prior principal target cleanup remains required');
          }
          if (!own.length && existing.length >= MAX_OWNER_FILES_TARGETS) {
            throw failure('FILES_TARGET_CAPACITY', 'SecureShop has reached its retained files target limit; existing targets remain available');
          }
        } else {
          existing = (await client.query(
            `SELECT r.* FROM identity.secureshop_target_reservations r
             JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
             WHERE l.original_platform_owner_id=$1 AND r.target_kind='files'`, [ownerId]
          )).rows;
          if (existing.some(row => row.launch_id !== launch.launch_id || Number(row.generation) !== expected)) {
            throw failure('CLEANUP_REQUIRED', 'prior target cleanup remains required');
          }
        }
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,'files',$4) RETURNING *`, [makeUuid('targetId'), launch.launch_id, expected, ownerId]
        )).rows[0];
        return Object.freeze({ targetId: row.target_id, launchId: launch.launch_id,
          scenarioId: launch.scenario_id, generation: expected, kind: 'files' });
      });
    },

    async readExistingFilesTarget({ launchId, platformSessionId, platformOwnerId, scenarioId, generation: expectedGeneration }) {
      const values = [uuid(launchId, 'launchId'), positiveId(platformSessionId, 'platformSessionId'),
        positiveId(platformOwnerId, 'platformOwnerId'), uuid(scenarioId, 'scenarioId'), generation(expectedGeneration)];
      const row = (await pool.query(`SELECT r.target_id FROM identity.secureshop_target_reservations r
        JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
        JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
        JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
        WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3
          AND l.original_platform_owner_id=$3 AND r.original_platform_owner_id=$3
          AND l.scenario_id=$4 AND l.generation=$5 AND r.generation=$5 AND r.target_kind='files'
          AND l.status='active' AND l.expires_at>clock_timestamp()
          AND s.is_active=1 AND s.expires_at>clock_timestamp()
          AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`, values)).rows[0];
      if (!row) throw failure('FILE_TARGET_UNAVAILABLE', 'Existing file target unavailable');
      return Object.freeze({ targetId: uuid(row.target_id, 'targetId'), launchId: values[0],
        scenarioId: values[3], generation: values[4], kind: 'files' });
    },

    // Draft-only review-lab allocator. The forward target-kind migration is
    // intentionally not registered yet, so no startup path calls this method.
    // A reservation is cleanup debt, not provisioning or cleanup evidence.
    async readExistingReviewsTarget({ launchId, platformSessionId, platformOwnerId, scenarioId, generation: expectedGeneration }) {
      const values = [uuid(launchId, 'launchId'), positiveId(platformSessionId, 'platformSessionId'),
        positiveId(platformOwnerId, 'platformOwnerId'), uuid(scenarioId, 'scenarioId'), generation(expectedGeneration)];
      const row = (await pool.query(`SELECT r.target_id FROM identity.secureshop_target_reservations r
        JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
        JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
        JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
        WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3
          AND l.original_platform_owner_id=$3 AND r.original_platform_owner_id=$3
          AND l.scenario_id=$4 AND l.generation=$5 AND r.generation=$5 AND r.target_kind='reviews'
          AND l.status='active' AND l.expires_at>clock_timestamp()
          AND s.is_active=1 AND s.expires_at>clock_timestamp()
          AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`, values)).rows[0];
      if (!row) throw failure('REVIEW_TARGET_UNAVAILABLE', 'Existing review target unavailable');
      return Object.freeze({ targetId: uuid(row.target_id, 'targetId'), launchId: values[0],
        scenarioId: values[3], generation: values[4], kind: 'reviews' });
    },

    async readExistingProductsTarget({ launchId, platformSessionId, platformOwnerId, scenarioId, generation: expectedGeneration }) {
      const values = [uuid(launchId, 'launchId'), positiveId(platformSessionId, 'platformSessionId'),
        positiveId(platformOwnerId, 'platformOwnerId'), uuid(scenarioId, 'scenarioId'), generation(expectedGeneration)];
      const row = (await pool.query(`SELECT r.target_id FROM identity.secureshop_target_reservations r
        JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
        JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
        JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
        WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3
          AND l.original_platform_owner_id=$3 AND r.original_platform_owner_id=$3
          AND l.scenario_id=$4 AND l.generation=$5 AND r.generation=$5 AND r.target_kind='products'
          AND l.status='active' AND l.expires_at>clock_timestamp()
          AND s.is_active=1 AND s.expires_at>clock_timestamp()
          AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`, values)).rows[0];
      if (!row) return null;
      return Object.freeze({ targetId: uuid(row.target_id, 'targetId'), launchId: values[0],
        scenarioId: values[3], generation: values[4], kind: 'products' });
    },

    async readExistingSsrfTarget({ launchId, platformSessionId, platformOwnerId, scenarioId, generation: expectedGeneration }) {
      const values = [uuid(launchId, 'launchId'), positiveId(platformSessionId, 'platformSessionId'),
        positiveId(platformOwnerId, 'platformOwnerId'), uuid(scenarioId, 'scenarioId'), generation(expectedGeneration)];
      const row = (await pool.query(`SELECT r.target_id FROM identity.secureshop_target_reservations r
        JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
        JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
        JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
        WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3
          AND l.original_platform_owner_id=$3 AND r.original_platform_owner_id=$3
          AND l.scenario_id=$4 AND l.generation=$5 AND r.generation=$5 AND r.target_kind='controlled_ssrf'
          AND l.status='active' AND l.expires_at>clock_timestamp()
          AND s.is_active=1 AND s.expires_at>clock_timestamp()
          AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`, values)).rows[0];
      if (!row) throw failure('SSRF_TARGET_UNAVAILABLE', 'Existing SSRF target unavailable');
      return Object.freeze({ targetId: uuid(row.target_id, 'targetId'), launchId: values[0],
        scenarioId: values[3], generation: values[4], kind: 'controlled_ssrf' });
    },

    async reserveReviewsTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        const existing = (await client.query(
          `SELECT r.* FROM identity.secureshop_target_reservations r
           JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
           WHERE l.original_platform_owner_id=$1 AND r.target_kind='reviews'`, [ownerId]
        )).rows;
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        // A previous launch retains its review target and teaching evidence.
        // Reopening the current launch still works when the owner is at capacity.
        if (!current && existing.length >= MAX_OWNER_REVIEW_TARGETS) {
          throw failure('REVIEW_TARGET_CAPACITY', 'SecureShop has reached its retained review session limit; existing sessions remain available');
        }
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,'reviews',$4) RETURNING *`, [makeUuid('targetId'), launch.launch_id, expected, ownerId]
        )).rows[0];
        return Object.freeze({ targetId: row.target_id, launchId: launch.launch_id,
          scenarioId: launch.scenario_id, generation: expected, kind: 'reviews' });
      });
    },

    // Launch-bound product allocator. Product rows are provisioned
    // in the dedicated review-lab store from trusted commerce source records;
    // this reservation is only immutable cleanup debt.
    async reserveProductsTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        const existing = (await client.query(
          `SELECT r.* FROM identity.secureshop_target_reservations r
           JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
           WHERE l.original_platform_owner_id=$1 AND r.target_kind='products'`, [ownerId]
        )).rows;
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        // A prior session retains its own snapshot and evidence. It must not
        // prevent a new launch from opening, or be silently reset on login.
        // Reopening this launch remains possible when the owner is at capacity.
        if (!current && existing.length >= MAX_OWNER_PRODUCT_TARGETS) {
          throw failure('PRODUCT_TARGET_CAPACITY', 'SecureShop has reached its retained product session limit; existing sessions remain available');
        }
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,'products',$4) RETURNING *`, [makeUuid('targetId'), launch.launch_id, expected, ownerId]
        )).rows[0];
        return Object.freeze({ targetId: row.target_id, launchId: launch.launch_id,
          scenarioId: launch.scenario_id, generation: expected, kind: 'products' });
      });
    },

    // Candidate-only allocator. The identity kind remains unavailable until
    // its reviewed forward migration is promoted; no default composition calls
    // this method while the persona-inbox feature switch is off.
    async reservePersonaInboxTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        const existing = (await client.query(
          `SELECT r.* FROM identity.secureshop_target_reservations r
           JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
           WHERE l.original_platform_owner_id=$1 AND r.target_kind='persona_inbox'`, [ownerId]
        )).rows;
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        if (existing.some(row => row !== current)) throw failure('CLEANUP_REQUIRED', 'prior target cleanup remains required');
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,'persona_inbox',$4) RETURNING *`, [makeUuid('targetId'), launch.launch_id, expected, ownerId]
        )).rows[0];
        return Object.freeze({ targetId: row.target_id, launchId: launch.launch_id,
          scenarioId: launch.scenario_id, generation: expected, kind: 'persona_inbox' });
      });
    },

    // Candidate-only MCP trust allocator. Its two kinds intentionally separate
    // unapproved-server registration from approved-server schema rotation.
    async reserveMcpTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }, trustScenario, options = {}) {
      if (!options || typeof options !== 'object' || Array.isArray(options)
        || Object.getPrototypeOf(options) !== Object.prototype || Object.keys(options).some(key => key !== 'bounded')) {
        throw failure('INVALID_ARGUMENT', 'Invalid reservation options');
      }
      const { bounded = false } = options;
      if (typeof bounded !== 'boolean') throw failure('INVALID_ARGUMENT', 'Invalid reservation deadline');
      const kinds = Object.freeze({ rogue_registration: 'mcp_rogue', rug_pull: 'mcp_rug_pull' });
      const targetKind = kinds[trustScenario];
      if (!targetKind) throw failure('INVALID_ARGUMENT', 'MCP trust scenario is invalid');
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        if (bounded) await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        const existing = (await client.query(
          `SELECT r.* FROM identity.secureshop_target_reservations r
           JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
           WHERE l.original_platform_owner_id=$1 AND r.target_kind=$2`, [ownerId, targetKind]
        )).rows;
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        if (existing.some(row => row !== current)) throw failure('CLEANUP_REQUIRED', 'prior target cleanup remains required');
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,$4,$5) RETURNING *`, [makeUuid('targetId'),launch.launch_id,expected,targetKind,ownerId]
        )).rows[0];
        return Object.freeze({ targetId: row.target_id, launchId: launch.launch_id,
          scenarioId: launch.scenario_id, generation: expected, kind: targetKind, trustScenario });
      });
    },

    // Unwired controlled-SSRF allocator. The target kind remains unavailable
    // until its separately reviewed forward identity migration is promoted.
    async reserveSsrfTarget({ platformSessionId, platformOwnerId, launchId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const now = await requireFreshActiveContext(client, context);
        if (launch.status !== 'active' || launch.expires_at <= now || Number(launch.generation) !== expected) {
          throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        }
        const existing = (await client.query(
          `SELECT r.* FROM identity.secureshop_target_reservations r
           JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
           WHERE l.original_platform_owner_id=$1 AND r.target_kind='controlled_ssrf'`, [ownerId]
        )).rows;
        const current = existing.find(row => row.launch_id === launch.launch_id && Number(row.generation) === expected);
        if (existing.some(row => row !== current)) throw failure('CLEANUP_REQUIRED', 'prior target cleanup remains required');
        const row = current || (await client.query(
          `INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id)
           VALUES($1,$2,$3,'controlled_ssrf',$4) RETURNING *`, [makeUuid('targetId'),launch.launch_id,expected,ownerId]
        )).rows[0];
        return Object.freeze({ targetId:row.target_id,launchId:launch.launch_id,scenarioId:launch.scenario_id,
          generation:expected,kind:'controlled_ssrf' });
      });
    },

    async issueOrRenew({ platformSessionId, platformOwnerId, expiresAt, expectedBearer, shopPrincipal }) {
      const requestedExpiry = timestamp(expiresAt);
      const principal = shopPrincipal === undefined ? null
        : require('../../services/secureshopStandaloneAuth').assertSecureShopStandalonePrincipal(shopPrincipal);
      if (principal && (principal.ownerId !== platformOwnerId || principal.sessionId !== platformSessionId
        || !BEARER.test(principal.launchBearer) || expectedBearer !== undefined)) throw failure('OWNER_MISMATCH', 'Shop execution authority is invalid');
      const bearer = principal ? principal.launchBearer : makeBearer();
      const result = await withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, platformSessionId, platformOwnerId);
        if (principal && (context.user.realm !== 'shop' || context.session.realm !== 'shop')) {
          throw failure('OWNER_MISMATCH', 'Shop execution realm is invalid');
        }
        const current = (await client.query(
          `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
           JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
           WHERE l.platform_session_id=$1 FOR UPDATE OF l`, [platformSessionId]
        )).rows[0];
        const freshNow = await requireFreshActiveContext(client, context);
        if (new Date(requestedExpiry) <= freshNow) throw failure('INVALID_EXPIRY', 'launch expiry must be in the future');
        const expiry = new Date(Math.min(new Date(requestedExpiry).getTime(), context.session.expires_at.getTime())).toISOString();
        if (current && current.status !== 'active') throw failure('LAUNCH_SESSION_TERMINAL', 'launch cannot be renewed in its current lifecycle');
        if (current && current.expires_at <= freshNow) throw failure(principal ? 'SHOP_LAUNCH_EXPIRED' : 'LAUNCH_SESSION_TERMINAL', 'expired launch cannot be renewed');
        if (current) {
          const presented = principal ? principal.launchBearer : expectedBearer;
          if (presented === undefined) throw failure('LAUNCH_EXISTS', 'an active launch already exists');
          const expectedValid = typeof presented === 'string' && Buffer.byteLength(presented) <= 64
            && BEARER.test(presented);
          const stored = current.handle_hash;
          if (!expectedValid || !Buffer.isBuffer(stored) || stored.length !== 32
            || !crypto.timingSafeEqual(digest(presented), stored)) {
            throw failure('STALE_HANDLE', 'the expected launch handle is no longer current');
          }
        } else if (expectedBearer !== undefined) {
          throw failure('STALE_HANDLE', 'the expected launch handle is no longer current');
        }
        if (!current) {
          // Historical migration qualification can issue under pre-retirement
          // schemas. Conservatively count every launch until 0134 is present.
          const capacity = (await client.query(`SELECT
            to_regprocedure('identity.secureshop_launch_is_retired(uuid)') IS NOT NULL AS ready,
            to_regprocedure('identity.secureshop_launch_consumes_capacity(uuid)') IS NOT NULL AS live_capacity`)).rows[0];
          const predicate = capacity.live_capacity
            ? ' AND identity.secureshop_launch_consumes_capacity(launch_id)'
            : capacity.ready ? ' AND NOT identity.secureshop_launch_is_retired(launch_id)' : '';
          const retained = (await client.query(`SELECT count(*)::int AS count FROM identity.secureshop_launches
            WHERE original_platform_owner_id=$1${predicate}`, [platformOwnerId])).rows[0];
          if (retained.count >= MAX_OWNER_LAUNCHES) {
            throw failure('LAUNCH_CAPACITY', 'SecureShop has reached its retained session limit; existing sessions remain available');
          }
        }
        const row = current
          ? (await client.query(
            `UPDATE identity.secureshop_launches SET handle_hash=$1,expires_at=$2,
             credential_version=credential_version+1,updated_at=clock_timestamp()
             WHERE launch_id=$3 RETURNING *`, [digest(bearer), expiry, current.launch_id]
          )).rows[0]
          : (await client.query(
            `INSERT INTO identity.secureshop_launches
             (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
              handle_hash,scenario_id,expires_at)
             VALUES($1,$2,$2,$3,$4,$5,$6) RETURNING *`,
            [makeUuid('launchId'), platformSessionId, platformOwnerId, digest(bearer), makeUuid('scenarioId'), expiry]
          )).rows[0];
        row.platform_owner_id = platformOwnerId;
        return { binding: binding(row), renewed: Boolean(current) };
      });
      return Object.freeze({ bearer, ...result });
    },

    // Dedicated launch capability resolution for the parent-owned transport.
    // Derive identity from durable joins, never shop JWTs or caller/model IDs.
    // This read is not an operation reservation or atomic effect fence.
    async resolveCapability(bearer) {
      if (typeof bearer !== 'string' || Buffer.byteLength(bearer) > 64 || !BEARER.test(bearer)) return null;
      const row = (await pool.query(
        `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
         JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
         JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
         WHERE l.handle_hash=$1
           AND l.status='active' AND l.expires_at>clock_timestamp()
           AND s.is_active=1 AND s.expires_at>clock_timestamp()
           AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`,
        [digest(bearer)]
      )).rows[0];
      return row ? binding(row) : null;
    },

    async resolve({ bearer, platformSessionId, platformOwnerId }) {
      if (typeof bearer !== 'string' || Buffer.byteLength(bearer) > 64 || !BEARER.test(bearer)) return null;
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const row = (await pool.query(
        `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
         JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
         JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
         WHERE l.handle_hash=$1 AND l.platform_session_id=$2 AND s.user_id=$3
           AND l.status='active' AND l.expires_at>clock_timestamp()
           AND s.is_active=1 AND s.expires_at>clock_timestamp()
           AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`,
        [digest(bearer), sessionId, ownerId]
      )).rows[0];
      return row ? binding(row) : null;
    },

    async assertCurrent({ launchId, platformSessionId, platformOwnerId, scenarioId, generation: expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const held = recoveryIdentity.getStore();
      if (held && (!held.active || held.scope.launchId !== launchId || held.scope.platformSessionId !== sessionId
        || held.scope.platformOwnerId !== ownerId || held.scope.scenarioId !== scenarioId
        || held.scope.generation !== expectedGeneration)) throw failure('STALE_LAUNCH', 'Recovery scope changed');
      const reader = held ? held.client : pool;
      const row = (await reader.query(
        `SELECT l.*,s.user_id AS platform_owner_id FROM identity.secureshop_launches l
         JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id
         JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
         WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3
           AND l.scenario_id=$4 AND l.generation=$5 AND l.status='active'
           AND l.expires_at>clock_timestamp() AND s.is_active=1 AND s.expires_at>clock_timestamp()
           AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`,
        [uuid(launchId, 'launchId'), sessionId, ownerId, uuid(scenarioId, 'scenarioId'), generation(expectedGeneration)]
      )).rows[0];
      if (!row) throw failure('STALE_LAUNCH', 'launch authority is no longer current');
      return binding(row);
    },

    async beginReset({ launchId, platformSessionId, platformOwnerId, expectedGeneration, idempotencyKey }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      const keyHash = digest(boundedText(idempotencyKey, 'idempotencyKey', 256));
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const freshNow = await requireFreshActiveContext(client, context);
        if (launch.expires_at <= freshNow) throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        const existing = (await client.query(
          'SELECT * FROM identity.secureshop_launch_resets WHERE launch_id=$1 AND idempotency_hash=$2',
          [launch.launch_id, keyHash]
        )).rows[0];
        if (existing) {
          if (Number(existing.from_generation) !== expected || existing.status === 'aborted'
            || Number(launch.generation) !== Number(existing.to_generation)) {
            throw failure('STALE_GENERATION', 'reset request is no longer current');
          }
          return Object.freeze({ resetId: existing.reset_id, fromGeneration: Number(existing.from_generation),
            toGeneration: Number(existing.to_generation), status: existing.status, binding: binding(launch) });
        }
        if (launch.status !== 'active' || Number(launch.generation) !== expected || expected >= MAX_SAFE_GENERATION) {
          throw failure('STALE_GENERATION', 'reset request is no longer current');
        }
        const resetId = makeUuid('resetId');
        const next = expected + 1;
        const operation = (await client.query(
          `INSERT INTO identity.secureshop_launch_resets
           (reset_id,launch_id,from_generation,to_generation,idempotency_hash)
           VALUES($1,$2,$3,$4,$5) RETURNING *`, [resetId, launch.launch_id, expected, next, keyHash]
        )).rows[0];
        const updated = (await client.query(
          `UPDATE identity.secureshop_launches SET generation=$2,status='resetting',updated_at=clock_timestamp()
           WHERE launch_id=$1 RETURNING *`, [launch.launch_id, next]
        )).rows[0];
        updated.platform_owner_id = ownerId;
        return Object.freeze({ resetId: operation.reset_id, fromGeneration: expected, toGeneration: next,
          status: operation.status, binding: binding(updated) });
      });
    },

    async commitReset({ resetId, launchId, platformSessionId, platformOwnerId, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const expected = generation(expectedGeneration, 'expectedGeneration');
      return withTransaction(pool, async client => {
        const context = await lockTrustedContext(client, sessionId, ownerId);
        const launch = await lockLaunch(client, launchId, sessionId);
        const freshNow = await requireFreshActiveContext(client, context);
        if (launch.expires_at <= freshNow) throw failure('LAUNCH_UNAVAILABLE', 'launch is unavailable');
        const operation = (await client.query(
          'SELECT * FROM identity.secureshop_launch_resets WHERE reset_id=$1 AND launch_id=$2 FOR UPDATE',
          [uuid(resetId, 'resetId'), launch.launch_id]
        )).rows[0];
        if (!operation || Number(operation.to_generation) !== expected || operation.status === 'aborted') {
          throw failure('STALE_GENERATION', 'reset operation is no longer current');
        }
        // This column is introduced by the conversation-cleanup checkpoint
        // migration. Keeping the comparison strict preserves rollout against
        // a pre-migration schema while making every migrated reset fail closed.
        if (operation.conversation_reconciliation_required === true) {
          throw failure('CLEANUP_REQUIRED', 'conversation cleanup must be verified before reset completes');
        }
        if (operation.progress_reconciliation_required === true) {
          throw failure('CLEANUP_REQUIRED', 'canonical progress cleanup must be verified before reset completes');
        }
        // Durable scenes may own mail, product, and review targets born in
        // another launch. The local reservation query below cannot prove
        // their cleanup; only the canonical receipt coordinator can.
        if (operation.reconciliation_required === true) {
          const sharedScene = await client.query(`SELECT 1
            FROM identity.secureshop_scenes s
            WHERE (s.birth_launch_id=$1 AND s.birth_generation=$2) OR EXISTS (
              SELECT 1 FROM identity.secureshop_scene_execution_grants g
              WHERE g.scene_id=s.scene_id AND g.launch_id=$1 AND g.generation=$2)
            LIMIT 1`, [launch.launch_id, operation.from_generation]);
          if (sharedScene.rowCount) throw failure('CLEANUP_REQUIRED', 'scene cleanup must be verified before reset completes');
        }
        // Reservation rows are unresolved target cleanup obligations. Do not
        // announce a completed reset or reactivate a generation while effects
        // from the previous generation remain unreconciled.
        const unresolved = await client.query(
          `SELECT 1 FROM identity.secureshop_target_reservations
           WHERE launch_id=$1 AND generation<=$2 LIMIT 1`,
          [launch.launch_id, operation.from_generation]
        );
        if (unresolved.rowCount) throw failure('CLEANUP_REQUIRED', 'target cleanup must be verified before reset completes');
        if (operation.status === 'committed') {
          if (launch.status !== 'active' || Number(launch.generation) !== expected) throw failure('STALE_GENERATION', 'reset operation is no longer current');
          return binding(launch);
        }
        if (launch.status !== 'resetting' || Number(launch.generation) !== expected) throw failure('STALE_GENERATION', 'reset operation is no longer current');
        await client.query(
          `UPDATE identity.secureshop_launch_resets SET status='committed',committed_at=clock_timestamp(),updated_at=clock_timestamp()
           WHERE reset_id=$1`, [operation.reset_id]
        );
        const updated = (await client.query(
          `UPDATE identity.secureshop_launches SET status='active',updated_at=clock_timestamp()
           WHERE launch_id=$1 RETURNING *`, [launch.launch_id]
        )).rows[0];
        updated.platform_owner_id = ownerId;
        return binding(updated);
      });
    },

    async revoke({ launchId, platformSessionId, platformOwnerId, reason, expectedGeneration }) {
      const sessionId = positiveId(platformSessionId, 'platformSessionId');
      const ownerId = positiveId(platformOwnerId, 'platformOwnerId');
      const safeReason = boundedText(reason, 'revoke reason', 200);
      const expected = expectedGeneration === undefined ? null : generation(expectedGeneration, 'expectedGeneration');
      const invalidatedHash = digest(makeBearer());
      return withTransaction(pool, async client => {
        await lockTrustedContext(client, sessionId, ownerId, { requireActive: false });
        const launch = await lockLaunch(client, launchId, sessionId);
        if (expected !== null && Number(launch.generation) !== expected) throw failure('STALE_GENERATION', 'launch authority is no longer current');
        if (launch.status === 'revoked') return Object.freeze({ revoked: true, generation: Number(launch.generation) });
        await client.query(
          `UPDATE identity.secureshop_launch_resets SET status='aborted',aborted_at=clock_timestamp(),abort_reason=$2,updated_at=clock_timestamp()
           WHERE launch_id=$1 AND status='fenced'`, [launch.launch_id, safeReason]
        );
        await client.query(
          `UPDATE identity.secureshop_launches SET status='revoked',revoked_at=clock_timestamp(),revoke_reason=$2,
           handle_hash=$3,updated_at=clock_timestamp() WHERE launch_id=$1`,
          [launch.launch_id, safeReason, invalidatedHash]
        );
        return Object.freeze({ revoked: true, generation: Number(launch.generation) });
      });
    },
  });
}

module.exports = { createSecureShopLaunchRepository };
