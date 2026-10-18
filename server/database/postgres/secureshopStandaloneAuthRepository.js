'use strict';

const { withTransaction } = require('./index');

const MAX_ACTIVE_SESSIONS = 16;
const PRINCIPAL_COLUMNS = `p.principal_id::text AS "principalId",p.owner_id AS "ownerId",
  p.shop_user_id AS "shopUserId",p.username,p.email,p.role,
  p.credential_version::text AS "credentialVersion",
  p.authority_version::text AS "authorityVersion",p.is_active AS "isActive",
  p.locked_until AS "lockedUntil",p.failed_login_count AS "failedLoginCount"`;
const TENANT_PRINCIPAL_COLUMNS = PRINCIPAL_COLUMNS.replace('p.role', 'm.role');
function failure(code) { return Object.assign(new Error('Shop authentication unavailable'), { code }); }
function context(row) {
  if (!row) return null;
  return Object.freeze({ principalId: row.principalId, ownerId: Number(row.ownerId),
    sessionId: Number(row.sessionId), shopUserId: Number(row.shopUserId),
    username: row.username, email: row.email, role: row.role,
    credentialVersion: String(row.credentialVersion),
    authorityVersion: String(row.authorityVersion),
    expiresAt: new Date(row.expiresAt).toISOString() });
}
function tenantContext(row) {
  if (!row) return null;
  return Object.freeze({ principalId: row.principalId,
    principalOwnerId: Number(row.principalOwnerId), ownerId: Number(row.ownerId),
    authSessionId: Number(row.authSessionId), sessionId: Number(row.sessionId),
    tenantId: row.tenantId, membershipVersion: String(row.membershipVersion),
    shopUserId: Number(row.shopUserId), username: row.username, email: row.email,
    role: row.role, credentialVersion: String(row.credentialVersion),
    authorityVersion: String(row.authorityVersion),
    expiresAt: new Date(row.expiresAt).toISOString() });
}
function duplicate(error) {
  return error?.code === '23505' && /^(principals_|secureshop_auth_principals)/.test(error.constraint || '');
}

function createSecureShopStandaloneAuthRepository({ pool, executionTenantSlug = 'default' } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function') {
    throw new TypeError('Standalone shop auth database required');
  }
  if (typeof executionTenantSlug !== 'string'
      || !/^[a-z][a-z0-9_-]{0,63}$/.test(executionTenantSlug)) {
    throw new TypeError('Trusted shop execution tenant slug required');
  }
  async function insertPrincipal(client, input, defaultOnly) {
    const sql = `INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,$5)
      ${defaultOnly ? 'ON CONFLICT DO NOTHING' : ''}
      RETURNING principal_id::text AS "principalId",owner_id AS "ownerId",
        shop_user_id AS "shopUserId",username,email,role,
        credential_version::text AS "credentialVersion",
        authority_version::text AS "authorityVersion"`;
    try { return (await client.query(sql, [input.principalId, input.username,
      input.email, input.passwordHash, input.role])).rows[0] || null; }
    catch (error) { if (duplicate(error)) throw failure('SHOP_ACCOUNT_EXISTS'); throw error; }
  }
  async function enrollDefaultTenant(client, principal) {
    const tenant = (await client.query(`SELECT tenant_id,owner_id,seed_merchant_id
      FROM secureshop_auth.tenants WHERE slug='default' AND is_active=true FOR SHARE`)).rows[0];
    if (!tenant) throw failure('SHOP_AUTH_INVALID');
    await client.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2::uuid,$3,$4)
      ON CONFLICT(tenant_id,principal_id) DO NOTHING`,
    [tenant.tenant_id, principal.principalId, principal.shopUserId, principal.role]);
    const member = (await client.query(`SELECT shop_user_id,role,is_active
      FROM secureshop_auth.tenant_memberships
      WHERE tenant_id=$1 AND principal_id=$2::uuid`,
    [tenant.tenant_id, principal.principalId])).rows[0];
    if (!member || Number(member.shop_user_id) !== Number(principal.shopUserId)
        || !['customer','merchant','admin'].includes(member.role)) throw failure('SHOP_AUTH_INVALID');
    return { tenant, member };
  }
  async function insertSession(client, principal, { tokenHash, expiresAt, renewedFromSessionId = null }) {
    const count = Number((await client.query(`SELECT count(*)::integer AS count
      FROM secureshop_auth.sessions WHERE principal_id=$1 AND revoked_at IS NULL
        AND expires_at>clock_timestamp()`, [principal.principalId])).rows[0].count);
    if (count >= MAX_ACTIVE_SESSIONS) throw failure('SHOP_SESSION_CAPACITY');
    const session = (await client.query(`INSERT INTO secureshop_auth.sessions
      (principal_id,token_hash,credential_version,authority_version,expires_at,renewed_from_session_id)
      VALUES($1,$2,$3::bigint,$4::bigint,$5::timestamptz,$6::integer)
      RETURNING session_id AS "sessionId",expires_at AS "expiresAt"`,
    [principal.principalId, tokenHash, principal.credentialVersion,
      principal.authorityVersion, expiresAt, renewedFromSessionId])).rows[0];
    if (!session) throw failure('SHOP_AUTH_INVALID');
    const member = (await client.query(`SELECT m.role FROM secureshop_auth.tenant_memberships m
      JOIN secureshop_auth.tenants t USING(tenant_id)
      JOIN secureshop_auth.session_membership_snapshots v ON v.tenant_id=m.tenant_id
        AND v.membership_version=m.membership_version AND v.session_id=$2
      WHERE m.principal_id=$1::uuid AND t.slug=$3 AND m.is_active AND t.is_active
      FOR SHARE OF m,t`, [principal.principalId, session.sessionId, executionTenantSlug])).rows[0];
    if (!member) throw failure('SHOP_AUTH_INVALID');
    return context({ ...principal, ...session, role: member.role });
  }
  return Object.freeze({
    async registerWithSession(input) {
      return withTransaction(pool, async client => {
        const principal = await insertPrincipal(client, input, false);
        const enrollment = await enrollDefaultTenant(client, principal);
        if (!enrollment.member.is_active) throw failure('SHOP_AUTH_INVALID');
        return insertSession(client, principal, input);
      });
    },
    async seedDefaultsOnce({ defaultsSha256, principals } = {}) {
      if (!/^[a-f0-9]{64}$/.test(defaultsSha256 || '')
          || !Array.isArray(principals) || principals.length !== 3
          || new Set(principals.map(item => item?.role)).size !== 3
          || principals.some(item => !['customer', 'merchant', 'admin'].includes(item?.role))) {
        throw failure('INVALID_ARGUMENT');
      }
      return withTransaction(pool, async client => {
        await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('secureshop-auth-defaults-v1',0))`);
        const prior = (await client.query(`SELECT defaults_sha256 AS "defaultsSha256"
          FROM secureshop_auth.default_seed_state WHERE seed_key='fresh-install-v1'`)).rows[0];
        if (prior) {
          if (prior.defaultsSha256 !== defaultsSha256) throw failure('SHOP_SEED_VERSION_CONFLICT');
          return Object.freeze({ seeded: false });
        }
        for (const input of principals) {
          const inserted = await insertPrincipal(client, input, true);
          const existing = inserted || (await client.query(`SELECT ${PRINCIPAL_COLUMNS}
            FROM secureshop_auth.principals p WHERE p.username=$1`, [input.username])).rows[0];
          if (!existing || existing.email !== input.email || existing.role !== input.role) {
            throw failure('SHOP_ACCOUNT_EXISTS');
          }
          await enrollDefaultTenant(client, existing);
        }
        const merchant = (await client.query(`SELECT shop_user_id
          FROM secureshop_auth.principals WHERE username=$1 AND role='merchant'`,
        [principals.find(item => item.role === 'merchant').username])).rows[0];
        if (!merchant) throw failure('SHOP_AUTH_INVALID');
        const result = await client.query(`UPDATE secureshop_auth.tenants SET seed_merchant_id=$1
          WHERE slug='default' AND seed_merchant_id IS NULL`, [merchant.shop_user_id]);
        if (result.rowCount !== 1) {
          const existing = (await client.query(`SELECT seed_merchant_id
            FROM secureshop_auth.tenants WHERE slug='default'`)).rows[0];
          if (!existing?.seed_merchant_id) throw failure('SHOP_AUTH_INVALID');
        }
        await client.query(`INSERT INTO secureshop_auth.default_seed_state
          (seed_key,defaults_sha256) VALUES('fresh-install-v1',$1)`, [defaultsSha256]);
        return Object.freeze({ seeded: true });
      });
    },
    async findCredential(username) {
      return (await pool.query(`SELECT ${PRINCIPAL_COLUMNS},p.password_hash AS "passwordHash"
        FROM secureshop_auth.principals p WHERE p.username=$1`, [username])).rows[0] || null;
    },
    async recordFailedLogin(principalId) {
      await pool.query(`UPDATE secureshop_auth.principals
        SET failed_login_count=LEAST(failed_login_count+1,1000000),
          locked_until=CASE WHEN failed_login_count+1>=10
            THEN clock_timestamp()+interval '15 minutes' ELSE locked_until END,
          updated_at=clock_timestamp()
        WHERE principal_id=$1::uuid AND is_active=true`, [principalId]);
    },
    async createSession({ principalId, credentialVersion, authorityVersion, tokenHash, expiresAt }) {
      return withTransaction(pool, async client => {
        const principal = (await client.query(`SELECT ${PRINCIPAL_COLUMNS}
          FROM secureshop_auth.principals p WHERE p.principal_id=$1::uuid FOR UPDATE`,
        [principalId])).rows[0];
        if (!principal || !principal.isActive || (principal.lockedUntil
          && new Date(principal.lockedUntil).getTime() > Date.now())
          || principal.credentialVersion !== credentialVersion
          || principal.authorityVersion !== authorityVersion) throw failure('SHOP_AUTH_INVALID');
        const result = await insertSession(client, principal, { tokenHash, expiresAt });
        await client.query(`UPDATE secureshop_auth.principals
          SET failed_login_count=0,locked_until=NULL,updated_at=clock_timestamp()
          WHERE principal_id=$1::uuid`, [principalId]);
        return result;
      });
    },
    async readCurrentSession(tokenHash) {
      const row = (await pool.query(`SELECT ${TENANT_PRINCIPAL_COLUMNS},
          s.session_id AS "sessionId",s.expires_at AS "expiresAt"
        FROM secureshop_auth.sessions s
        JOIN secureshop_auth.principals p USING(principal_id)
        JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
        JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
        JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
          AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
        WHERE s.token_hash=$1 AND t.slug=$2 AND t.is_active AND m.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND p.is_active=true AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
          AND s.credential_version=p.credential_version
          AND s.authority_version=p.authority_version`, [tokenHash, executionTenantSlug])).rows[0];
      return context(row);
    },
    async readOrCreateDefaultExecutionSession({ principalId, authSessionId,
      credentialVersion, authorityVersion }) {
      return withTransaction(pool, async client => {
        const source = (await client.query(`SELECT p.principal_id::text AS "principalId",
          p.owner_id AS "principalOwnerId",t.owner_id AS "ownerId",
          s.session_id AS "authSessionId",t.tenant_id::text AS "tenantId",
          m.membership_version::text AS "membershipVersion",
          p.shop_user_id AS "shopUserId",p.username,p.email,m.role,
          p.credential_version::text AS "credentialVersion",
          p.authority_version::text AS "authorityVersion",
          s.expires_at AS "expiresAt"
          FROM secureshop_auth.sessions s
          JOIN secureshop_auth.principals p USING(principal_id)
          JOIN secureshop_auth.tenant_memberships m USING(principal_id)
          JOIN secureshop_auth.tenants t USING(tenant_id)
          JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
            AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
          WHERE s.session_id=$1 AND p.principal_id=$2::uuid AND t.slug=$5
            AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
            AND p.is_active=true AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
            AND s.credential_version=p.credential_version
            AND s.authority_version=p.authority_version
            AND p.credential_version=$3::bigint AND p.authority_version=$4::bigint
            AND m.is_active=true AND t.is_active=true
          FOR SHARE OF s,p,m,t`,
        [authSessionId, principalId, credentialVersion, authorityVersion,
          executionTenantSlug])).rows[0];
        if (!source) throw failure('SHOP_AUTH_INVALID');
        // One selected execution per cookie/tenant, with immutable older executions retained.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-practice-selection:'||$1::text||':'||$2::text,0))",
          [source.authSessionId, source.tenantId]);
        let execution = (await client.query(`SELECT e.session_id AS "sessionId",
          e.expires_at AS "expiresAt",e.revoked_at AS "revokedAt"
          FROM secureshop_auth.practice_selections x JOIN secureshop_auth.execution_sessions e
            ON e.session_id=x.execution_session_id
          WHERE x.auth_session_id=$1 AND x.tenant_id=$2::uuid AND x.principal_id=$3::uuid
            AND e.auth_session_id=x.auth_session_id AND e.tenant_id=x.tenant_id
            AND e.principal_id=x.principal_id AND e.membership_version=$4::bigint FOR SHARE OF e`,
        [source.authSessionId, source.tenantId, source.principalId, source.membershipVersion])).rows[0];
        if (!execution) {
          // Renewal inherits only a scene choice, never the revoked execution identity.
          const choice = (await client.query(`SELECT scene.scene_id
            FROM secureshop_auth.sessions s
            LEFT JOIN secureshop_auth.practice_selections prior ON prior.auth_session_id=s.renewed_from_session_id
              AND prior.tenant_id=$2 AND prior.principal_id=$3
            LEFT JOIN secureshop_auth.practice_preferences pref ON pref.tenant_id=$2 AND pref.principal_id=$3
            LEFT JOIN secureshop_auth.tenants tenant ON tenant.tenant_id=$2
            LEFT JOIN identity.secureshop_scenes fallback ON fallback.original_platform_owner_id=tenant.owner_id
              AND fallback.status='active' AND fallback.is_default
            LEFT JOIN identity.secureshop_scenes scene ON scene.scene_id=COALESCE(prior.scene_id,pref.scene_id,fallback.scene_id)
              AND scene.status='active' AND scene.original_platform_owner_id=tenant.owner_id
            WHERE s.session_id=$1`, [source.authSessionId, source.tenantId, source.principalId])).rows[0];
          execution = (await client.query(`INSERT INTO secureshop_auth.execution_sessions
            (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
            VALUES($1,$2::uuid,$3::uuid,$4::bigint,$5::timestamptz)
            RETURNING session_id AS "sessionId",expires_at AS "expiresAt",revoked_at AS "revokedAt"`,
          [source.authSessionId, source.tenantId, source.principalId,
            source.membershipVersion, source.expiresAt])).rows[0];
          await client.query(`INSERT INTO secureshop_auth.practice_selections
            (auth_session_id,tenant_id,principal_id,execution_session_id,scene_id)
            VALUES($1,$2,$3,$4,$5)`, [source.authSessionId, source.tenantId, source.principalId,
            execution.sessionId, choice?.scene_id || null]);
          await client.query(`INSERT INTO secureshop_auth.practice_preferences(tenant_id,principal_id,scene_id)
            VALUES($1,$2,$3) ON CONFLICT(tenant_id,principal_id) DO NOTHING`,
          [source.tenantId,source.principalId,choice?.scene_id || null]);
        }
        if (!execution || execution.revokedAt || new Date(execution.expiresAt).getTime() <= Date.now()) {
          throw failure('SHOP_AUTH_INVALID');
        }
        return tenantContext({ ...source, ...execution });
      });
    },
    async rotateSession({ tokenHash, newTokenHash, expiresAt }) {
      return withTransaction(pool, async client => {
        const principal = (await client.query(`SELECT ${TENANT_PRINCIPAL_COLUMNS},s.session_id AS "renewedFromSessionId"
          FROM secureshop_auth.sessions s
          JOIN secureshop_auth.principals p USING(principal_id)
        JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
        JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
        JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
          AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
          WHERE s.token_hash=$1 AND t.slug=$2 AND t.is_active AND m.is_active
            AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
            AND p.is_active=true AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
            AND s.credential_version=p.credential_version
            AND s.authority_version=p.authority_version
          FOR UPDATE OF p,s FOR SHARE OF m,t`, [tokenHash, executionTenantSlug])).rows[0];
        if (!principal) return null;
        const old = (await client.query(`UPDATE secureshop_auth.sessions
          SET revoked_at=clock_timestamp()
          WHERE token_hash=$1 AND revoked_at IS NULL RETURNING expires_at AS "expiresAt"`,
        [tokenHash])).rows[0];
        if (!old) return null;
        return insertSession(client, principal, { tokenHash: newTokenHash,
          expiresAt, renewedFromSessionId: principal.renewedFromSessionId });
      });
    },
    async revokeSession(tokenHash) {
      const result = await pool.query(`UPDATE secureshop_auth.sessions
        SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND revoked_at IS NULL`, [tokenHash]);
      return result.rowCount === 1;
    },
    async readCredentialForSession(tokenHash) {
      return (await pool.query(`SELECT ${TENANT_PRINCIPAL_COLUMNS},p.password_hash AS "passwordHash",
        s.session_id AS "sessionId",s.expires_at AS "expiresAt"
        FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id)
        JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
        JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
        JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
          AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
        WHERE s.token_hash=$1 AND t.slug=$2 AND t.is_active AND m.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND p.is_active=true AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
          AND s.credential_version=p.credential_version
          AND s.authority_version=p.authority_version`, [tokenHash, executionTenantSlug])).rows[0] || null;
    },
    async changePassword({ tokenHash, credentialVersion, passwordHash }) {
      return withTransaction(pool, async client => {
        const row = (await client.query(`SELECT p.principal_id::text AS "principalId"
          FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id)
        JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
        JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
        JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
          AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
          WHERE s.token_hash=$1 AND t.slug=$3 AND t.is_active AND m.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
            AND p.is_active=true
            AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
            AND p.credential_version=$2::bigint
            AND s.credential_version=p.credential_version
            AND s.authority_version=p.authority_version
          FOR UPDATE OF p,s`, [tokenHash, credentialVersion, executionTenantSlug])).rows[0];
        if (!row) throw failure('SHOP_AUTH_INVALID');
        await client.query(`UPDATE secureshop_auth.principals
          SET password_hash=$2,credential_version=credential_version+1,
            authority_version=authority_version+1,failed_login_count=0,
            locked_until=NULL,updated_at=clock_timestamp()
          WHERE principal_id=$1::uuid`, [row.principalId, passwordHash]);
        await client.query(`UPDATE secureshop_auth.sessions SET revoked_at=clock_timestamp()
          WHERE principal_id=$1::uuid AND revoked_at IS NULL`, [row.principalId]);
        return true;
      });
    },
    async revokeAll(principalId) {
      const result = await pool.query(`UPDATE secureshop_auth.sessions
        SET revoked_at=clock_timestamp() WHERE principal_id=$1::uuid AND revoked_at IS NULL`, [principalId]);
      return result.rowCount;
    },
  });
}

module.exports = { createSecureShopStandaloneAuthRepository };
