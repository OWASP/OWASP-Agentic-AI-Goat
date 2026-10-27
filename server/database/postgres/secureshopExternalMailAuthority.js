'use strict';
const { withTransaction } = require('./index');
const { assertSecureShopStandaloneAuthPrincipal } = require('../../services/secureshopStandaloneAuth');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const C = require('../../services/secureshopExternalMailContract');

// The source account rows are read, not row-locked after the mirrored lifecycle
// rows. Source revocation synchronously updates those mirrors before commit.
// Taking source locks here would invert password/reset's source→mirror order.
const CURRENT = `SELECT e.tenant_id,e.membership_version::text,p.credential_version::text,
 p.authority_version::text,x.revision::text AS selection_revision,x.scene_id,
 sc.scene_generation::text,g.grant_id,mo.mode,mo.revision::text AS mode_revision,
 l.credential_version::text AS launch_credential_version,
 LEAST(s.expires_at,e.expires_at,l.expires_at) AS expires_at
 FROM secureshop_auth.execution_sessions e
 JOIN secureshop_auth.execution_authority_state live ON live.session_id=e.session_id
 JOIN secureshop_auth.sessions s ON s.session_id=e.auth_session_id
 JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id AND p.principal_id=s.principal_id
 JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=p.principal_id
 JOIN secureshop_auth.practice_selections x ON x.auth_session_id=s.session_id AND x.tenant_id=e.tenant_id
   AND x.principal_id=p.principal_id AND x.execution_session_id=e.session_id
 JOIN secureshop_auth.tenant_modes mo ON mo.tenant_id=e.tenant_id AND mo.principal_id=p.principal_id
 JOIN identity.secureshop_launches l ON l.platform_session_id=e.session_id
 JOIN identity.secureshop_authority_sessions a ON a.id=e.session_id AND a.user_id=$4
 JOIN identity.secureshop_authority_owners o ON o.id=a.user_id
 JOIN identity.secureshop_scenes sc ON sc.scene_id=x.scene_id AND sc.original_platform_owner_id=$4
 JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=sc.scene_id AND g.launch_id=l.launch_id
   AND g.scenario_id=l.scenario_id AND g.generation=l.generation
   AND g.scene_generation=sc.scene_generation AND g.original_platform_owner_id=$4
   AND g.original_platform_session_id=e.session_id
 WHERE l.launch_id=$1 AND l.scenario_id=$2 AND l.generation=$3
 AND l.original_platform_owner_id=$4 AND e.session_id=$5
 AND p.principal_id=$6 AND s.session_id=$7 AND p.shop_user_id=$8
 AND live.is_active=1 AND live.owner_id=$4 AND m.role='merchant'
 AND s.expires_at>clock_timestamp() AND e.expires_at>clock_timestamp()
 AND l.status='active' AND l.expires_at>clock_timestamp()
 AND a.is_active=1 AND a.expires_at>clock_timestamp() AND o.is_active=1
 AND (o.account_locked_until IS NULL OR o.account_locked_until<=clock_timestamp())
 AND sc.status='active'`;

function createExternalMailAuthority({ pool, personaAuthority, sender }) {
  if (typeof pool?.connect !== 'function' || typeof personaAuthority?.capture !== 'function')
    throw TypeError('External mail authority stores required');
  const trusted = new WeakMap();
  async function current(client, a) {
    const s = a.scope;
    const rows = (await client.query(CURRENT, [s.launchId,s.scenarioId,s.generation,
      s.platformOwnerId,s.platformSessionId,a.principalId,a.authSessionId,a.personaId])).rows;
    if (rows.length !== 1) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
    const row = rows[0];
    const binding = Object.freeze({ ...s, principalId:a.principalId,authSessionId:a.authSessionId,
      personaId:a.personaId,personaSessionId:a.personaSessionId,personaAuthorityVersion:a.personaAuthorityVersion,
      tenantId:row.tenant_id,membershipVersion:row.membership_version,
      credentialVersion:row.credential_version,authorityVersion:row.authority_version,
      sceneId:row.scene_id,sceneGeneration:row.scene_generation,grantId:row.grant_id,
      selectionRevision:row.selection_revision,mode:row.mode,modeRevision:row.mode_revision,
      launchCredentialVersion:row.launch_credential_version });
    const expiresAt = Math.min(Date.parse(row.expires_at),a.personaExpiresAt,a.cookieExpiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
    return { binding, expiresAt,
      scopeKey:C.hash({version:1,domain:'manual-external-test',sender,templateVersion:C.TEMPLATE_VERSION,binding}) };
  }
  function checked(a) {
    const privateValue = trusted.get(a);
    if (!privateValue) throw C.error('SHOP_AUTH_INVALID');
    return privateValue;
  }
  async function assertCurrent(a, client=pool) {
    const privateValue = checked(a), now = await current(client,privateValue);
    if (now.scopeKey !== a.scopeKey) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
    return now;
  }
  return Object.freeze({
    async capture({ principal, scope, persona, personaSession }) {
      const p = assertSecureShopStandaloneAuthPrincipal(principal);
      if (p.role !== 'merchant' || persona?.role !== 'merchant' || persona.id !== p.shopUserId)
        throw C.error('SHOP_AUTH_INVALID');
      const s = createLaunchScope(scope);
      const fence = personaAuthority.capture({scope:s,personaId:persona.id,role:'merchant',
        sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
      if (typeof fence.withExternalMailDispatch !== 'function') throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
      const privateValue = {scope:s,principalId:p.principalId,authSessionId:p.sessionId,
        personaId:persona.id,personaSessionId:personaSession.sessionId,
        personaAuthorityVersion:personaSession.authorityVersion,
        personaExpiresAt:Date.parse(personaSession.expiresAt),cookieExpiresAt:Date.parse(p.expiresAt),fence};
      await fence.assertRemoteAdmission();
      const value = await current(pool,privateValue);
      const a = Object.freeze({principalId:p.principalId,authSessionId:p.sessionId,...value});
      trusted.set(a,privateValue);
      return a;
    },
    async assertCurrent(a) {
      const value = await assertCurrent(a);
      await checked(a).fence.assertRemoteAdmission();
      return value;
    },
    async withDispatch(a, work, {deadlineAt}) {
      const v = checked(a), b = a.binding;
      // Match registered-user administration: agents owner/launch first, then
      // identity locks. Reset fences identity and releases it before agents cleanup.
      return v.fence.withExternalMailDispatch(() => withTransaction(pool, async c => {
        await c.query("SET LOCAL statement_timeout='3000ms'");
        await c.query("SET LOCAL lock_timeout='3000ms'");
        await c.query("SET LOCAL idle_in_transaction_session_timeout='25000ms'");
        await c.query('SELECT id FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE',[b.platformOwnerId]);
        await c.query('SELECT id FROM identity.secureshop_authority_sessions WHERE id=$1 FOR UPDATE',[b.platformSessionId]);
        await c.query('SELECT launch_id FROM identity.secureshop_launches WHERE launch_id=$1 FOR SHARE',[b.launchId]);
        await c.query('SELECT scene_id FROM identity.secureshop_scenes WHERE scene_id=$1 FOR SHARE',[b.sceneId]);
        await c.query(`SELECT scene_id FROM secureshop_auth.practice_selections
          WHERE auth_session_id=$1 AND tenant_id=$2 FOR SHARE`,[a.authSessionId,b.tenantId]);
        await c.query('SELECT secureshop_auth.lock_external_mail_mode($1,$2,$3)',
          [b.platformSessionId,b.tenantId,a.principalId]);
        const fresh = await assertCurrent(a,c);
        if (Date.now() >= Math.min(deadlineAt,fresh.expiresAt)) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
        return work({deadlineAt:Math.min(deadlineAt,fresh.expiresAt)});
      }),{deadlineAt});
    },
  });
}
module.exports = { createExternalMailAuthority };
