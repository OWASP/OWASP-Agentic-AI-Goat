'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { createConversationBinding, createLaunchScope } = require('../../services/secureshopConversationBinding');

const MAX_ACTIVE = 16;
const MAX_RETAINED = 256;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TEMPLATE_ROLES = Object.freeze({ student_customer: 'customer', student_merchant: 'merchant',
  student_admin: 'admin' });
const CANONICAL_TEMPLATES = Object.freeze(require('../../../db/postgres/seeds/secureshop.json').shop_users
  .filter(row => Object.hasOwn(TEMPLATE_ROLES, row.username)).sort((a, b) => a.username.localeCompare(b.username))
  .map(row => Object.freeze({ id: row.id, username: row.username, email: row.email,
    password: row.password, role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null })));
function digest(value) { return createHash('sha256').update(value, 'utf8').digest(); }
function values(scope, persona) {
  const binding = createConversationBinding(scope, persona);
  return [binding.launchId, binding.scenarioId, binding.generation, binding.platformOwnerId,
    binding.platformSessionId, binding.shopUserId, binding.role];
}
function unavailable(code = 'SHOP_PERSONA_UNAVAILABLE') {
  return Object.assign(new Error('Shop persona unavailable'), { code });
}
function positiveInteger(value, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw unavailable(`SHOP_PERSONA_${label.toUpperCase()}_INVALID`);
  }
  return value;
}
function sessionUuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw unavailable('SHOP_PERSONA_SESSION_INVALID');
  return value.toLowerCase();
}
function passwordHash(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 128
      || !/^\$2[aby]\$\d\d\$/.test(value)) throw unavailable('SHOP_PERSONA_PASSWORD_INVALID');
  return value;
}
function apiKey(value) {
  if (typeof value !== 'string' || !/^sk_ss_live_[0-9a-f]{32}$/.test(value)) {
    throw unavailable('SHOP_API_KEY_INVALID');
  }
  return value;
}
function template(row) {
  if (!row || TEMPLATE_ROLES[row.username] !== row.role || !Number.isSafeInteger(Number(row.id))
      || Number(row.id) < 1 || typeof row.email !== 'string' || typeof row.password !== 'string'
      || !/^\$2[aby]\$\d\d\$/.test(row.password)) throw unavailable('SHOP_PERSONA_TEMPLATE_INVALID');
  const value = Object.freeze({ id: Number(row.id), username: row.username, email: row.email,
    password: row.password, role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null });
  return Object.freeze({ ...value, sourceSha256: digest(JSON.stringify([
    value.id, value.username, value.email, value.password, value.role, value.full_name, value.phone,
  ])) });
}
const CANONICAL_TEMPLATE_SHA256 = Object.freeze(CANONICAL_TEMPLATES.map(row =>
  template(row).sourceSha256.toString('hex')));

function createSecureShopBoundPersonaRepository({ commercePool, agentsPool, auditStore, personaAuthority } = {}) {
  if (typeof commercePool?.query !== 'function' || typeof agentsPool?.query !== 'function'
      || typeof agentsPool?.connect !== 'function') throw new TypeError('Bound persona stores required');
  if (personaAuthority && typeof personaAuthority.resolve !== 'function') throw new TypeError('Candidate persona authority required');
  if (auditStore && typeof auditStore.append !== 'function') throw new TypeError('Audit store required');
  async function audit(client, binding, shopUserId, action, sourceId, params) {
    if (!auditStore) return;
    const canonical = personaAuthority ? await personaAuthority.resolve(client,binding,Number(shopUserId)) : (await client.query('SELECT base_role AS role FROM secureshop_agents.bound_actor_identities WHERE shop_user_id=$1 AND (original_platform_owner_id IS NULL OR original_platform_owner_id=$2)', [shopUserId,binding.platformOwnerId])).rows[0];
    if (!canonical || !Object.values(TEMPLATE_ROLES).includes(canonical.role)) throw unavailable('SHOP_PERSONA_UNAVAILABLE');
    await auditStore.append(client, { eventId: randomUUID(), scope: binding,
      persona: { id: Number(shopUserId), role: canonical.role }, actor: canonical.role, action,
      target: String(sourceId), paramsJson: JSON.stringify(params), outcome: 'completed',
      sourceKind: action.startsWith('session_') ? 'persona_session' : 'persona_credential', sourceId: String(sourceId) });
  }
  function expectedAuthorityVersion(value) { if (personaAuthority && (typeof value !== 'string' || !/^[1-9]\d*$/.test(value))) throw unavailable('SHOP_AUTH_INVALID'); }
  function snapshotActingCredential(value) {
    if(value===undefined)return undefined;
    expectedAuthorityVersion(value.authorityVersion);
    if(!personaAuthority||!Object.values(TEMPLATE_ROLES).includes(value.role))throw unavailable('SHOP_AUTH_INVALID');
    return Object.freeze({sessionId:sessionUuid(value.sessionId),role:value.role,authorityVersion:value.authorityVersion});
  }
  async function assertActor(client,binding,owner,actor) {
    if(!actor)return;
    await personaAuthority.resolve(client,binding,owner,{role:actor.role,version:actor.authorityVersion});
    const live=(await client.query(`SELECT 1 FROM secureshop_agents.bound_persona_sessions s
      WHERE s.session_id=$1 AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
        AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5
        AND s.original_platform_session_id=$6 AND s.shop_user_id=$7 AND s.role=$8
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
          WHERE c.platform_launch_id=s.platform_launch_id AND c.platform_scenario_id=s.platform_scenario_id
          AND c.platform_launch_generation=s.platform_launch_generation AND c.original_platform_owner_id=s.original_platform_owner_id
          AND c.original_platform_session_id=s.original_platform_session_id AND c.shop_user_id=s.shop_user_id),1)`,
      [actor.sessionId,binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId,owner,actor.role])).rowCount;
    if(live!==1)throw unavailable('SHOP_AUTH_INVALID');
  }
  let preparing;
  async function withLaunchLock(binding, work) {
    const client = await agentsPool.connect();
    try {
      await client.query('BEGIN');
      if (personaAuthority) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`secureshop-bound-audit-owner:${binding.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
        [`secureshop-conversation-admission:${binding.launchId}`]);
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      throw error;
    } finally { client.release(); }
  }
  async function ensureTemplates() {
    if (preparing) return preparing;
    preparing = (async () => {
      const catalog = (await agentsPool.query(`SELECT template_count,template_sha256
        FROM secureshop_agents.bound_persona_template_catalog WHERE singleton=true`)).rows[0];
      if (catalog) {
        const rows = (await agentsPool.query(`SELECT shop_user_id AS id,username,email,
          password_hash AS password,role,full_name,phone,source_sha256
          FROM secureshop_agents.bound_persona_templates ORDER BY username`)).rows;
        const aggregate = createHash('sha256');
        for (const row of rows) {
          const normalized = template(row);
          if (!Buffer.isBuffer(row.source_sha256) || !row.source_sha256.equals(normalized.sourceSha256)) {
            throw unavailable('SHOP_PERSONA_TEMPLATE_MISMATCH');
          }
          aggregate.update(normalized.sourceSha256);
        }
        if (rows.length !== 3 || Number(catalog.template_count) !== 3
            || !Buffer.isBuffer(catalog.template_sha256)
            || !catalog.template_sha256.equals(aggregate.digest())) {
          throw unavailable('SHOP_PERSONA_TEMPLATE_PARTIAL');
        }
        return;
      }
      const source = (await commercePool.query(`SELECT id,username,email,password,role,full_name,phone
        FROM secureshop.shop_users WHERE username=ANY($1::text[]) ORDER BY username`,
      [Object.keys(TEMPLATE_ROLES)])).rows.map(template);
      if (source.length !== 3) throw unavailable('SHOP_PERSONA_TEMPLATE_INVALID');
      if (source.some((row, index) => row.sourceSha256.toString('hex') !== CANONICAL_TEMPLATE_SHA256[index])) {
        throw unavailable('SHOP_PERSONA_TEMPLATE_MISMATCH');
      }
      const aggregate = createHash('sha256'); source.forEach(row => aggregate.update(row.sourceSha256));
      const sourceSha256 = aggregate.digest();
      const client = await agentsPool.connect();
      try {
        await client.query('BEGIN');
        const inserted = await client.query(`INSERT INTO secureshop_agents.bound_persona_template_catalog
          (singleton,version,template_count,template_sha256) VALUES(true,1,3,$1)
          ON CONFLICT(singleton) DO NOTHING`, [sourceSha256]);
        const stored = (await client.query(`SELECT template_count,template_sha256
          FROM secureshop_agents.bound_persona_template_catalog WHERE singleton=true`)).rows[0];
        if (Number(stored?.template_count) !== 3 || !Buffer.isBuffer(stored?.template_sha256)
            || !stored.template_sha256.equals(sourceSha256)) throw unavailable('SHOP_PERSONA_TEMPLATE_MISMATCH');
        if (inserted.rowCount === 1) {
          for (const row of source) await client.query(`INSERT INTO secureshop_agents.bound_persona_templates
            (username,shop_user_id,email,password_hash,role,full_name,phone,source_sha256)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [row.username, row.id, row.email, row.password,
            row.role, row.full_name, row.phone, row.sourceSha256]);
        }
        const count = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_agents.bound_persona_templates`)).rows[0].count);
        if (count !== 3) throw unavailable('SHOP_PERSONA_TEMPLATE_PARTIAL');
        await client.query('COMMIT');
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        throw error;
      } finally { client.release(); }
    })();
    try { await preparing; } finally { preparing = undefined; }
  }
  return Object.freeze({
    ensureTemplates,
    ...(personaAuthority ? {candidatePersonaAuthority:personaAuthority} : {}),
    async ensureStandaloneActor({scope,shopPrincipal}) {
      const binding=createLaunchScope(scope);
      const actor=shopPrincipal;
      if(!actor||!UUID.test(actor.principalId)||!Number.isSafeInteger(actor.shopUserId)
        ||actor.shopUserId<1000000000||actor.shopUserId>2147483647
        ||actor.ownerId!==binding.platformOwnerId||actor.sessionId!==binding.platformSessionId
        ||!Number.isSafeInteger(actor.principalOwnerId)||actor.principalOwnerId<1
        ||!Number.isSafeInteger(actor.authSessionId)||actor.authSessionId<1
        ||!UUID.test(actor.tenantId)
        ||typeof actor.membershipVersion!=='string'||!/^[1-9]\d*$/.test(actor.membershipVersion)
        ||!['customer','merchant','admin'].includes(actor.role)
        ||typeof actor.username!=='string'||!actor.username
        ||typeof actor.email!=='string'||!actor.email)throw unavailable('SHOP_AUTH_INVALID');
      return withLaunchLock(binding,async client=>{
        await client.query(`INSERT INTO secureshop_agents.bound_actor_identities
          (shop_user_id,username,email,base_role,principal_id,original_platform_owner_id)
          VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (shop_user_id) DO NOTHING`,
        [actor.shopUserId,actor.username,actor.email,actor.role,actor.principalId,actor.principalOwnerId]);
        const row=(await client.query(`SELECT shop_user_id,username,base_role,principal_id,
          original_platform_owner_id FROM secureshop_agents.bound_actor_identities
          WHERE shop_user_id=$1`,[actor.shopUserId])).rows[0];
        if(!row||row.username!==actor.username
          ||row.principal_id!==actor.principalId
          ||Number(row.original_platform_owner_id)!==actor.principalOwnerId)throw unavailable('SHOP_AUTH_INVALID');
        const admitted=(await client.query(`SELECT tenant_id,principal_id,principal_owner_id,
          role,is_active FROM secureshop_agents.bound_actor_tenant_memberships
          WHERE tenant_owner_id=$1 AND shop_user_id=$2 AND membership_version=$3`,
        [binding.platformOwnerId,actor.shopUserId,actor.membershipVersion])).rows[0];
        if(!admitted) await client.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
          (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,
           membership_version,role,is_active) VALUES($1,$2,$3,$4,$5,$6,$7,true)`,
        [binding.platformOwnerId,actor.tenantId,actor.shopUserId,actor.principalId,
          actor.principalOwnerId,actor.membershipVersion,actor.role]);
        else if(admitted.tenant_id!==actor.tenantId||admitted.principal_id!==actor.principalId
          ||Number(admitted.principal_owner_id)!==actor.principalOwnerId
          ||admitted.role!==actor.role||admitted.is_active!==true)throw unavailable('SHOP_AUTH_INVALID');
        return Object.freeze({id:actor.shopUserId,username:actor.username,email:actor.email,
          role:actor.role,full_name:null,phone:null});
      });
    },
    async findCredential(username, scope) {
      await ensureTemplates();
      const binding = createLaunchScope(scope);
      const credential = (await agentsPool.query(`SELECT t.shop_user_id AS id,t.username,t.email,
        COALESCE(c.password_hash,t.password_hash) AS password,t.role,t.full_name,t.phone,
        COALESCE(c.credential_version,1)::bigint AS credential_version
        FROM secureshop_agents.bound_persona_templates t
        LEFT JOIN secureshop_agents.bound_persona_credentials c
          ON c.platform_launch_id=$2 AND c.platform_scenario_id=$3
          AND c.platform_launch_generation=$4 AND c.original_platform_owner_id=$5
          AND c.original_platform_session_id=$6 AND c.shop_user_id=t.shop_user_id
        WHERE t.username=$1`, [username, binding.launchId, binding.scenarioId, binding.generation,
        binding.platformOwnerId, binding.platformSessionId])).rows[0] || null;
      if (!credential || !personaAuthority) return credential;
      return withLaunchLock(binding, async client => ({...credential,...await personaAuthority.resolve(client,binding,Number(credential.id))}));
    },
    async findCredentialById(id, scope) {
      const template = await this.readPersona(id);
      return template ? this.findCredential(template.username,scope) : null;
    },
    async readPersona(id, scope) {
      await ensureTemplates();
      if(scope){const binding=createLaunchScope(scope);
        const row=(await agentsPool.query(`SELECT a.shop_user_id AS id,a.username,a.email,
          COALESCE(m.role,a.base_role) AS role,t.full_name,t.phone
          FROM secureshop_agents.bound_actor_identities a
          LEFT JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=a.shop_user_id
          LEFT JOIN LATERAL (SELECT role FROM secureshop_agents.bound_actor_tenant_memberships
            WHERE tenant_owner_id=$2 AND shop_user_id=a.shop_user_id AND is_active
            ORDER BY membership_version DESC LIMIT 1) m ON true
          WHERE a.shop_user_id=$1 AND secureshop_agents.bound_actor_in_owner(
            a.shop_user_id,$2)`,
        [id,binding.platformOwnerId])).rows[0];
        return row||null;}
      return (await agentsPool.query(`SELECT shop_user_id AS id,username,email,role,full_name,phone
        FROM secureshop_agents.bound_persona_templates WHERE shop_user_id=$1`, [id])).rows[0] || null;
    },
    async listPersonas() {
      await ensureTemplates();
      const rows = (await agentsPool.query(`SELECT shop_user_id AS id,username,email,role,full_name,phone
        FROM secureshop_agents.bound_persona_templates ORDER BY role,shop_user_id`)).rows;
      if (rows.length !== 3 || new Set(rows.map(row => row.role)).size !== 3
          || rows.some(row => !Number.isSafeInteger(Number(row.id)) || Number(row.id) < 1
            || !['customer','merchant','admin'].includes(row.role))) {
        throw unavailable('SHOP_PERSONA_TEMPLATE_PARTIAL');
      }
      return Object.freeze(rows.map(row => Object.freeze({ id: Number(row.id), username: row.username,
        email: row.email, role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null })));
    },
    async listActors(scope) {
      const binding=createLaunchScope(scope);
      await ensureTemplates();
      const rows=(await agentsPool.query(`SELECT a.shop_user_id AS id,a.username,a.email,
          COALESCE(m.role,a.base_role) AS role,t.full_name,t.phone,
          CASE WHEN a.principal_id IS NULL THEN 'teaching_persona' ELSE 'registered_account' END AS identity_kind
        FROM secureshop_agents.bound_actor_identities a
        LEFT JOIN secureshop_agents.bound_persona_templates t
          ON t.shop_user_id=a.shop_user_id
        LEFT JOIN LATERAL (SELECT role FROM secureshop_agents.bound_actor_tenant_memberships
          WHERE tenant_owner_id=$1 AND shop_user_id=a.shop_user_id AND is_active
          ORDER BY membership_version DESC LIMIT 1) m ON true
        WHERE secureshop_agents.bound_actor_in_owner(a.shop_user_id,$1)
        ORDER BY a.shop_user_id`,[binding.platformOwnerId])).rows;
      if(rows.length<3||rows.some(row=>!Number.isSafeInteger(Number(row.id))
        ||Number(row.id)<1||!Object.values(TEMPLATE_ROLES).includes(row.role)
        ||!['teaching_persona','registered_account'].includes(row.identity_kind)))
        throw unavailable('SHOP_PERSONA_UNAVAILABLE');
      return Object.freeze(rows.map(row=>Object.freeze({id:Number(row.id),
        username:row.username,email:row.email,role:row.role,
        full_name:row.full_name??null,phone:row.phone??null,identity_kind:row.identity_kind})));
    },
    async listMailActors(scope) {
      const binding = createLaunchScope(scope);
      await ensureTemplates();
      const rows = (await agentsPool.query(`SELECT a.shop_user_id AS id,a.username,a.email,
          COALESCE(st.effective_role,m.role,a.base_role) AS role
        FROM secureshop_agents.bound_actor_identities a
        LEFT JOIN secureshop_agents.bound_persona_state st
          ON st.platform_launch_id=$1 AND st.platform_scenario_id=$2
          AND st.platform_launch_generation=$3 AND st.original_platform_owner_id=$4
          AND st.original_platform_session_id=$5 AND st.shop_user_id=a.shop_user_id
        LEFT JOIN LATERAL (SELECT role FROM secureshop_agents.bound_actor_tenant_memberships
          WHERE tenant_owner_id=$4 AND shop_user_id=a.shop_user_id
          ORDER BY membership_version DESC LIMIT 1) m ON true
        WHERE secureshop_agents.bound_actor_in_owner(a.shop_user_id,$4)
          AND st.banned_at IS NULL
        ORDER BY a.shop_user_id LIMIT 129`,
      [binding.launchId,binding.scenarioId,binding.generation,
        binding.platformOwnerId,binding.platformSessionId])).rows;
      if (rows.length < 3 || rows.length > 128
          || new Set(rows.map(row => Number(row.id))).size !== rows.length
          || new Set(rows.map(row => row.email)).size !== rows.length
          || rows.some(row => !Number.isSafeInteger(Number(row.id)) || Number(row.id) < 1
            || typeof row.username !== 'string' || !row.username
            || typeof row.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(row.email)
            || !Object.values(TEMPLATE_ROLES).includes(row.role))) {
        throw unavailable('SHOP_MAIL_ACTORS_UNAVAILABLE');
      }
      return Object.freeze(rows.map(row => Object.freeze({ id: Number(row.id),
        username: row.username, email: row.email, role: row.role })));
    },
    async countActiveSessions({ scope }) {
      const binding = createLaunchScope(scope);
      const row = (await agentsPool.query(`SELECT count(*)::integer AS count
        FROM secureshop_agents.bound_persona_sessions s
        WHERE s.platform_launch_id=$1 AND s.platform_scenario_id=$2
          AND s.platform_launch_generation=$3 AND s.original_platform_owner_id=$4
          AND s.original_platform_session_id=$5 AND s.revoked_at IS NULL
          AND s.expires_at>clock_timestamp()
          AND s.last_seen_at>=clock_timestamp()-interval '15 minutes'
          AND s.credential_version=COALESCE((SELECT c.credential_version
            FROM secureshop_agents.bound_persona_credentials c
            WHERE c.platform_launch_id=$1 AND c.platform_scenario_id=$2
              AND c.platform_launch_generation=$3 AND c.original_platform_owner_id=$4
              AND c.original_platform_session_id=$5 AND c.shop_user_id=s.shop_user_id),1)`,
      [binding.launchId, binding.scenarioId, binding.generation,
        binding.platformOwnerId, binding.platformSessionId])).rows[0];
      const rawCount = row?.count;
      const count = typeof rawCount === 'number'
        || (typeof rawCount === 'string' && /^(0|[1-9]\d*)$/.test(rawCount))
        ? Number(rawCount) : Number.NaN;
      if (!Number.isSafeInteger(count) || count < 0) {
        throw unavailable('SHOP_PERSONA_ACTIVE_SESSION_COUNT_INVALID');
      }
      return count;
    },
    async createSession({ sessionId, jti, scope, persona, expiresAt, ip = null, userAgent = null,
      credentialVersion = 1, authorityVersion, bootstrap = null }) {
      const binding = createLaunchScope(scope);
      expectedAuthorityVersion(authorityVersion);
      const coordinates = values(scope, persona);
      if (bootstrap && (!UUID.test(bootstrap.principalId)
        || !Number.isSafeInteger(bootstrap.authSessionId) || bootstrap.authSessionId<1
        || !Number.isSafeInteger(bootstrap.executionSessionId)
        || bootstrap.executionSessionId!==binding.platformSessionId
        || typeof bootstrap.membershipVersion!=='string'
        || !/^[1-9]\d*$/.test(bootstrap.membershipVersion)
        || !/^[1-9]\d*$/.test(bootstrap.credentialVersion)
        || !/^[1-9]\d*$/.test(bootstrap.authorityVersion)
        || persona.id<1000000000)) throw unavailable('SHOP_AUTH_INVALID');
      if (persona.id < 1000000000) await ensureTemplates();
      const client = await agentsPool.connect();
      try {
        await client.query('BEGIN');
        if (personaAuthority) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`secureshop-bound-audit-owner:${binding.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-conversation-admission:${coordinates[0]}`]);
        await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET revoked_at=clock_timestamp() WHERE platform_launch_id=$1
            AND platform_launch_generation=$2 AND revoked_at IS NULL AND expires_at<=clock_timestamp()`,
        [coordinates[0], coordinates[2]]);
        if (personaAuthority) await personaAuthority.resolve(client, scope, persona.id, {role:persona.role,version:authorityVersion});
        const currentCredentialVersion = Number((await client.query(`SELECT
            COALESCE(c.credential_version,1)::bigint AS credential_version
          FROM secureshop_agents.bound_actor_identities t
          LEFT JOIN secureshop_agents.bound_persona_credentials c
            ON c.platform_launch_id=$1 AND c.platform_scenario_id=$2
            AND c.platform_launch_generation=$3 AND c.original_platform_owner_id=$4
            AND c.original_platform_session_id=$5 AND c.shop_user_id=t.shop_user_id
          WHERE t.shop_user_id=$6`, coordinates.slice(0, 6))).rows[0]?.credential_version);
        const suppliedCredentialVersion = positiveInteger(Number(credentialVersion), 'credential_version');
        if (currentCredentialVersion !== suppliedCredentialVersion) {
          throw unavailable('SHOP_CREDENTIALS_INVALID');
        }
        if (bootstrap) {
          const existing=(await client.query(`SELECT session_id,bootstrap_jti,expires_at
            FROM secureshop_agents.bound_persona_sessions
            WHERE platform_launch_id=$1 AND platform_scenario_id=$2
              AND platform_launch_generation=$3 AND original_platform_owner_id=$4
              AND original_platform_session_id=$5 AND shop_user_id=$6 AND role=$7
              AND standalone_principal_id=$8 AND standalone_session_id=$9
              AND standalone_credential_version=$10 AND standalone_authority_version=$11
              AND bootstrap_persona_authority_version=$12
              AND credential_version=$13 AND bootstrap_membership_version=$14
              AND revoked_at IS NULL
              AND expires_at>clock_timestamp() FOR UPDATE`,
          [...coordinates,bootstrap.principalId,bootstrap.authSessionId,
            bootstrap.credentialVersion,bootstrap.authorityVersion,
            authorityVersion,suppliedCredentialVersion,bootstrap.membershipVersion])).rows[0];
          if(existing){await client.query('COMMIT');
            return Object.freeze({sessionId:existing.session_id,jti:existing.bootstrap_jti,
              expiresAt:new Date(existing.expires_at).toISOString(),reused:true});}
        }
        const count = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1
            AND platform_launch_generation=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()`,
        [coordinates[0], coordinates[2]])).rows[0].count);
        if (count >= MAX_ACTIVE) throw unavailable('SHOP_PERSONA_CAPACITY');
        const retained = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1`,
        [coordinates[0]])).rows[0].count);
        if (retained >= MAX_RETAINED) throw unavailable('SHOP_PERSONA_CAPACITY');
        await client.query(`INSERT INTO secureshop_agents.bound_persona_sessions
          (session_id,jti_sha256,platform_launch_id,platform_scenario_id,
           platform_launch_generation,original_platform_owner_id,original_platform_session_id,
           shop_user_id,username,role,email,full_name,phone,expires_at,ip,user_agent,credential_version,
           standalone_principal_id,standalone_session_id,bootstrap_jti,
           standalone_credential_version,standalone_authority_version,
           bootstrap_persona_authority_version,bootstrap_membership_version)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
        [sessionId, digest(jti), ...coordinates.slice(0, 5), persona.id, persona.username,
          persona.role, persona.email, persona.full_name ?? null, persona.phone ?? null, expiresAt,
          ip, userAgent, suppliedCredentialVersion,bootstrap?.principalId??null,
          bootstrap?.authSessionId??null,bootstrap?jti:null,
          bootstrap?.credentialVersion??null,bootstrap?.authorityVersion??null,
          bootstrap?authorityVersion:null,bootstrap?.membershipVersion??null]);
        await audit(client, scope, persona.id, 'session_create', sessionId, { credentialVersion: suppliedCredentialVersion });
        await client.query('COMMIT');
        return Object.freeze(bootstrap?{sessionId,jti,expiresAt,reused:false}:{sessionId});
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        throw error;
      } finally { client.release(); }
    },
    async readSession({ jti, scope }) {
      const binding = createLaunchScope(scope);
      return withLaunchLock(binding, async client => {const found=(await client.query(
        `UPDATE secureshop_agents.bound_persona_sessions
          SET last_seen_at=GREATEST(last_seen_at,clock_timestamp()) WHERE jti_sha256=$1
            AND platform_launch_id=$2 AND platform_scenario_id=$3
            AND platform_launch_generation=$4 AND original_platform_owner_id=$5
            AND original_platform_session_id=$6 AND revoked_at IS NULL
            AND expires_at>clock_timestamp()
            AND credential_version=COALESCE((SELECT c.credential_version
              FROM secureshop_agents.bound_persona_credentials c
              WHERE c.platform_launch_id=$2 AND c.platform_scenario_id=$3
                AND c.platform_launch_generation=$4 AND c.original_platform_owner_id=$5
                AND c.original_platform_session_id=$6
                AND c.shop_user_id=bound_persona_sessions.shop_user_id),1)
          RETURNING session_id,shop_user_id,username,email,role,full_name,phone,expires_at,
            ip,user_agent,created_at,last_seen_at`, [digest(jti), binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0] || null;
        if (found && personaAuthority) await personaAuthority.resolve(client,binding,Number(found.shop_user_id),{role:found.role});
        return found;
      });
    },
    async extendSession({ jti, scope, expiresAt }) {
      const binding = createLaunchScope(scope);
      const client = await agentsPool.connect();
      try {
        await client.query('BEGIN');
        if (personaAuthority) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`secureshop-bound-audit-owner:${binding.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-conversation-admission:${binding.launchId}`]);
        const result = await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET expires_at=$1::timestamptz,last_seen_at=GREATEST(last_seen_at,clock_timestamp())
          WHERE jti_sha256=$2 AND platform_launch_id=$3 AND platform_scenario_id=$4
            AND platform_launch_generation=$5 AND original_platform_owner_id=$6
            AND original_platform_session_id=$7 AND revoked_at IS NULL
            AND expires_at>clock_timestamp() AND $1::timestamptz>expires_at
            AND credential_version=COALESCE((SELECT c.credential_version
              FROM secureshop_agents.bound_persona_credentials c
              WHERE c.platform_launch_id=$3 AND c.platform_scenario_id=$4
                AND c.platform_launch_generation=$5 AND c.original_platform_owner_id=$6
                AND c.original_platform_session_id=$7
                AND c.shop_user_id=bound_persona_sessions.shop_user_id),1)
          RETURNING session_id,shop_user_id,username,email,role,full_name,phone,expires_at,
            ip,user_agent,created_at,last_seen_at`,
        [expiresAt, digest(jti), binding.launchId, binding.scenarioId, binding.generation,
          binding.platformOwnerId, binding.platformSessionId]);
        const current = result.rows[0] || (await client.query(`SELECT session_id,shop_user_id,username,
          email,role,full_name,phone,expires_at,ip,user_agent,created_at,last_seen_at
          FROM secureshop_agents.bound_persona_sessions
          WHERE jti_sha256=$1 AND platform_launch_id=$2 AND platform_scenario_id=$3
            AND platform_launch_generation=$4 AND original_platform_owner_id=$5
            AND original_platform_session_id=$6 AND revoked_at IS NULL
            AND expires_at>clock_timestamp()
            AND credential_version=COALESCE((SELECT c.credential_version
              FROM secureshop_agents.bound_persona_credentials c
              WHERE c.platform_launch_id=$2 AND c.platform_scenario_id=$3
                AND c.platform_launch_generation=$4 AND c.original_platform_owner_id=$5
                AND c.original_platform_session_id=$6
                AND c.shop_user_id=bound_persona_sessions.shop_user_id),1)`, [digest(jti), binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0] || null;
        if (current && personaAuthority) await personaAuthority.resolve(client,binding,Number(current.shop_user_id),{role:current.role});
        if (result.rowCount === 1 && auditStore) await audit(client, binding, current.shop_user_id,
          'session_extend', current.session_id, { expiresAt: current.expires_at });
        await client.query('COMMIT');
        return current;
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        throw error;
      } finally { client.release(); }
    },
    async revokeSession({ jti, scope }) {
      const binding = createLaunchScope(scope);
      return withLaunchLock(binding, async client => {
        const result = await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET revoked_at=clock_timestamp() WHERE jti_sha256=$1 AND platform_launch_id=$2
            AND platform_scenario_id=$3 AND platform_launch_generation=$4
            AND original_platform_owner_id=$5 AND original_platform_session_id=$6
            AND revoked_at IS NULL RETURNING session_id,shop_user_id`, [digest(jti), binding.launchId,
          binding.scenarioId, binding.generation, binding.platformOwnerId, binding.platformSessionId]);
        if (result.rowCount === 1 && auditStore) await audit(client, binding, result.rows[0].shop_user_id,
          'session_revoke', result.rows[0].session_id, {});
        return result.rowCount === 1;
      });
    },
    async listSessions({ scope, shopUserId, currentSessionId }) {
      const binding = createLaunchScope(scope);
      const owner = positiveInteger(shopUserId, 'user');
      const current = sessionUuid(currentSessionId);
      const rows = (await agentsPool.query(`SELECT session_id AS id,user_agent,ip,created_at,
          last_seen_at,session_id=$7::uuid AS is_current
        FROM secureshop_agents.bound_persona_sessions
        WHERE platform_launch_id=$1 AND platform_scenario_id=$2
          AND platform_launch_generation=$3 AND original_platform_owner_id=$4
          AND original_platform_session_id=$5 AND shop_user_id=$6
          AND revoked_at IS NULL AND expires_at>clock_timestamp()
        ORDER BY last_seen_at DESC,session_id LIMIT 20`, [binding.launchId, binding.scenarioId,
        binding.generation, binding.platformOwnerId, binding.platformSessionId, owner, current])).rows;
      return Object.freeze(rows.map(row => Object.freeze({ id: row.id, user_agent: row.user_agent,
        ip: row.ip, created_at: row.created_at, last_seen_at: row.last_seen_at,
        is_current: row.is_current === true })));
    },
    async revokeOwnedSession({ scope, shopUserId, sessionId, actingCredential }) {
      const actor=snapshotActingCredential(actingCredential);
      const binding = createLaunchScope(scope);
      const owner = positiveInteger(shopUserId, 'user');
      const id = sessionUuid(sessionId);
      return withLaunchLock(binding, async client => {
        await assertActor(client,binding,owner,actor);
        const result = await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET revoked_at=clock_timestamp() WHERE session_id=$1 AND platform_launch_id=$2
            AND platform_scenario_id=$3 AND platform_launch_generation=$4
            AND original_platform_owner_id=$5 AND original_platform_session_id=$6
            AND shop_user_id=$7 AND revoked_at IS NULL AND expires_at>clock_timestamp()`,
        [id, binding.launchId, binding.scenarioId, binding.generation, binding.platformOwnerId,
          binding.platformSessionId, owner]);
        if (result.rowCount === 1) await audit(client, binding, owner, 'session_revoke', id, {});
        return result.rowCount === 1;
      });
    },
    async changePassword({ scope, shopUserId, currentSessionId, expectedHash, nextHash, expectedRole, authorityVersion }) {
      expectedAuthorityVersion(authorityVersion);
      const binding = createLaunchScope(scope);
      const owner = positiveInteger(shopUserId, 'user');
      const current = sessionUuid(currentSessionId);
      const expected = passwordHash(expectedHash);
      const replacement = passwordHash(nextHash);
      return withLaunchLock(binding, async client => {
        if (personaAuthority) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`secureshop-bound-audit-owner:${binding.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-persona-credential:${binding.launchId}:${owner}`]);
        if (personaAuthority) await personaAuthority.resolve(client,binding,owner,{role:expectedRole,version:authorityVersion});
        const row = (await client.query(`SELECT t.password_hash AS template_hash,
            c.password_hash,c.credential_version
          FROM secureshop_agents.bound_persona_templates t
          LEFT JOIN secureshop_agents.bound_persona_credentials c
            ON c.platform_launch_id=$1 AND c.platform_scenario_id=$2
            AND c.platform_launch_generation=$3 AND c.original_platform_owner_id=$4
            AND c.original_platform_session_id=$5 AND c.shop_user_id=t.shop_user_id
          WHERE t.shop_user_id=$6`, [binding.launchId, binding.scenarioId, binding.generation,
          binding.platformOwnerId, binding.platformSessionId, owner])).rows[0];
        if (!row || (row.password_hash || row.template_hash) !== expected) return null;
        const version = Number(row.credential_version || 1) + 1;
        await require('./secureshopPersonaCredentialWrite').writePersonaCredential(client,{scope:binding,shopUserId:owner,passwordHash:replacement,credentialVersion:version});
        const rebound = await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET credential_version=$1 WHERE session_id=$2 AND platform_launch_id=$3
            AND platform_scenario_id=$4 AND platform_launch_generation=$5
            AND original_platform_owner_id=$6 AND original_platform_session_id=$7
            AND shop_user_id=$8 AND revoked_at IS NULL AND expires_at>clock_timestamp()`,
        [version, current, binding.launchId, binding.scenarioId, binding.generation,
          binding.platformOwnerId, binding.platformSessionId, owner]);
        if (rebound.rowCount !== 1) throw unavailable('SHOP_AUTH_INVALID');
        await client.query(`UPDATE secureshop_agents.bound_persona_sessions
          SET revoked_at=clock_timestamp() WHERE platform_launch_id=$1
            AND platform_scenario_id=$2 AND platform_launch_generation=$3
            AND original_platform_owner_id=$4 AND original_platform_session_id=$5
            AND shop_user_id=$6 AND session_id<>$7 AND revoked_at IS NULL`,
        [binding.launchId, binding.scenarioId, binding.generation, binding.platformOwnerId,
          binding.platformSessionId, owner, current]);
        await audit(client, binding, owner, 'password_change', owner, { credentialVersion: version });
        return Object.freeze({ credentialVersion: version });
      });
    },
    async readApiKey({ scope, shopUserId }) {
      const binding = createLaunchScope(scope);
      const owner = positiveInteger(shopUserId, 'user');
      return withLaunchLock(binding, async client => {
        const row = (await client.query(`SELECT api_key_plaintext,api_key_version,created_at,rotated_at
          FROM secureshop_agents.bound_persona_api_keys
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5 AND shop_user_id=$6`, [binding.launchId,
          binding.scenarioId, binding.generation, binding.platformOwnerId,
          binding.platformSessionId, owner])).rows[0];
        if (!row) return null;
        return Object.freeze({ apiKey: apiKey(row.api_key_plaintext),
          version: positiveInteger(Number(row.api_key_version), 'api_key_version'),
          createdAt: new Date(row.created_at).toISOString(),
          rotatedAt: new Date(row.rotated_at).toISOString() });
      });
    },
    async rotateApiKey({ scope, shopUserId, nextKey, expectedRole, authorityVersion, currentSessionId }) {
      expectedAuthorityVersion(authorityVersion);
      const binding = createLaunchScope(scope);
      const owner = positiveInteger(shopUserId, 'user');
      const key = apiKey(nextKey);
      return withLaunchLock(binding, async client => {
        if (personaAuthority) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`secureshop-bound-audit-owner:${binding.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-persona-api-key:${binding.launchId}:${owner}`]);
        if (personaAuthority) await personaAuthority.resolve(client,binding,owner,{role:expectedRole,version:authorityVersion});
        if (personaAuthority) {
          const current=sessionUuid(currentSessionId);
          const live=(await client.query(`SELECT 1 FROM secureshop_agents.bound_persona_sessions WHERE session_id=$1
            AND platform_launch_id=$2 AND platform_scenario_id=$3 AND platform_launch_generation=$4
            AND original_platform_owner_id=$5 AND original_platform_session_id=$6 AND shop_user_id=$7
            AND role=$8 AND revoked_at IS NULL AND expires_at>clock_timestamp()`,[current,binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId,owner,expectedRole])).rowCount;
          if(live!==1)throw unavailable('SHOP_AUTH_INVALID');
        }
        const template = (await client.query(`SELECT base_role AS role FROM secureshop_agents.bound_actor_identities
          WHERE shop_user_id=$1 AND secureshop_agents.bound_actor_in_owner(shop_user_id,$2)`,
        [owner,binding.platformOwnerId])).rows[0];
        if (!template || !Object.values(TEMPLATE_ROLES).includes(template.role)) {
          throw unavailable('SHOP_PERSONA_UNAVAILABLE');
        }
        const current = (await client.query(`SELECT api_key_version
          FROM secureshop_agents.bound_persona_api_keys
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5 AND shop_user_id=$6 FOR UPDATE`, [binding.launchId,
          binding.scenarioId, binding.generation, binding.platformOwnerId,
          binding.platformSessionId, owner])).rows[0];
        const version = current ? positiveInteger(Number(current.api_key_version), 'api_key_version') + 1 : 1;
        const values = [binding.launchId, binding.scenarioId, binding.generation,
          binding.platformOwnerId, binding.platformSessionId, owner, key, digest(key), version];
        const row = (await client.query(current
          ? `UPDATE secureshop_agents.bound_persona_api_keys
            SET api_key_plaintext=$7,api_key_sha256=$8,api_key_version=$9
            WHERE platform_launch_id=$1 AND platform_scenario_id=$2
              AND platform_launch_generation=$3 AND original_platform_owner_id=$4
              AND original_platform_session_id=$5 AND shop_user_id=$6
            RETURNING api_key_plaintext,api_key_version,created_at,rotated_at`
          : `INSERT INTO secureshop_agents.bound_persona_api_keys
            (platform_launch_id,platform_scenario_id,platform_launch_generation,
             original_platform_owner_id,original_platform_session_id,shop_user_id,
             api_key_plaintext,api_key_sha256,api_key_version)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING api_key_plaintext,api_key_version,created_at,rotated_at`, values)).rows[0];
        await audit(client, binding, owner, 'api_key_rotate', owner, { version });
        return Object.freeze({ apiKey: apiKey(row.api_key_plaintext),
          version: positiveInteger(Number(row.api_key_version), 'api_key_version'),
          createdAt: new Date(row.created_at).toISOString(),
          rotatedAt: new Date(row.rotated_at).toISOString() });
      });
    },
    async authenticateApiKey({ scope, presentedKey }) {
      const binding = createLaunchScope(scope);
      const key = apiKey(presentedKey);
      return withLaunchLock(binding, async client => {
        const row = (await client.query(`SELECT t.shop_user_id AS id,t.username,t.email,
            t.base_role AS role,NULL::text AS full_name,NULL::text AS phone,
            t.original_platform_owner_id,k.api_key_version
          FROM secureshop_agents.bound_persona_api_keys k
          JOIN secureshop_agents.bound_actor_identities t ON t.shop_user_id=k.shop_user_id
          WHERE k.platform_launch_id=$1 AND k.platform_scenario_id=$2
            AND k.platform_launch_generation=$3 AND k.original_platform_owner_id=$4
            AND k.original_platform_session_id=$5 AND k.api_key_sha256=$6
            AND secureshop_agents.bound_actor_in_owner(t.shop_user_id,$7)`, [binding.launchId,
          binding.scenarioId, binding.generation, binding.platformOwnerId,
          binding.platformSessionId, digest(key), binding.platformOwnerId])).rows[0];
        if (!row) return null;
        if (personaAuthority) Object.assign(row,await personaAuthority.resolve(client,binding,Number(row.id)));
        return Object.freeze({ id: positiveInteger(Number(row.id), 'user'), username: row.username,
          email: row.email, role: row.role, full_name: row.full_name ?? null,
          phone: row.phone ?? null,
          apiKeyVersion: positiveInteger(Number(row.api_key_version), 'api_key_version') });
      });
    },
    async readApiKeyCleanupReceipt(scope) {
      const binding = createLaunchScope(scope);
      return withLaunchLock(binding, async client => {
        const row = (await client.query(`SELECT deleted_api_key_count,
            encode(receipt_sha256,'hex') AS receipt_sha256,completed_at
          FROM secureshop_agents.bound_persona_api_key_cleanup_receipts
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5`, [binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0];
        if (!row) return null;
        const remaining = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_agents.bound_persona_api_keys
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5`, [binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0].count);
        if (remaining !== 0 || !/^[0-9a-f]{64}$/.test(row.receipt_sha256)) {
          throw unavailable('SHOP_PERSONA_CLEANUP_INVALID');
        }
        return Object.freeze({ deletedApiKeyCount: Number(row.deleted_api_key_count),
          receiptSha256: row.receipt_sha256,
          completedAt: new Date(row.completed_at).toISOString() });
      });
    },
    async readCredentialCleanupReceipt(scope) {
      const binding = createLaunchScope(scope);
      return withLaunchLock(binding, async client => {
        const row = (await client.query(`SELECT deleted_credential_count,
            encode(receipt_sha256,'hex') AS receipt_sha256,completed_at
          FROM secureshop_agents.bound_persona_credential_cleanup_receipts
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5`, [binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0];
        if (!row) return null;
        const remaining = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_agents.bound_persona_credentials
          WHERE platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5`, [binding.launchId, binding.scenarioId,
          binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0].count);
        if (remaining !== 0 || !/^[0-9a-f]{64}$/.test(row.receipt_sha256)) {
          throw unavailable('SHOP_PERSONA_CLEANUP_INVALID');
        }
        return Object.freeze({ deletedCredentialCount: Number(row.deleted_credential_count),
          receiptSha256: row.receipt_sha256,
          completedAt: new Date(row.completed_at).toISOString() });
      });
    },
  });
}

module.exports = { createSecureShopBoundPersonaRepository, MAX_ACTIVE, MAX_RETAINED };
