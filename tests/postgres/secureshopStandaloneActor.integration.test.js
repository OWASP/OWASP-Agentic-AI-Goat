'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { Module, createRequire } = require('node:module');
const bcrypt = require('bcryptjs');
const { migrate } = require('../../db/postgres/migrate');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopBoundPersonaRepository, MAX_ACTIVE } = require('../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuthority } = require('../../server/database/postgres/secureshopBoundPersonaAuthority');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopStandaloneBootstrap } = require('../../server/services/secureshopStandaloneBootstrap');
const { projectBootstrap } = require('../../server/routes/secureshopStandaloneAuth');
const { createV11RecoveryAuthority } = require('../fixtures/secureshopMailAgentReadRenderedScenario');
const { createV11HttpCounters } = require('../fixtures/secureshopMailAgentReadRenderedAssembler');

const prefix = 'PG_SECURESHOP_STANDALONE_ACTOR_';
const keys = ['IDENTITY_RUNTIME_URL','IDENTITY_MIGRATION_URL','AGENTS_RUNTIME_URL','AGENTS_MIGRATION_URL'];
const enabled = process.env.SECURESHOP_STANDALONE_ACTOR_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && keys.every(key => process.env[prefix + key]);
const identityDirectory = path.resolve(__dirname,'../../db/postgres/identity-migrations');
const agentsDirectory = path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
function disposableUrl(key) {
  const url = new URL(process.env[prefix + key]);
  assert.equal(url.protocol,'postgresql:');
  assert.equal(url.hostname,'127.0.0.1');
  assert.match(url.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  assert.equal(url.password,''); assert.equal(url.search,''); assert.equal(url.hash,'');
  return url.href;
}
// In-memory directory filter: applied files keep their original paths and bytes.
function historicalMigrator(directory, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
        || Number(name.slice(0,4)) <= ceiling) : names;
  } };
  const loaded = new Module(filename,module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtual : local(name);
  loaded._compile(require('node:fs').readFileSync(filename,'utf8'),filename);
  return loaded.exports.migrate;
}

test('standalone shop principals preserve demo evidence and fence cross-owner sessions',
  { skip: !enabled, timeout: 180000 }, async t => {
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'),process.cwd());
    const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH || '';
    require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath, {
      root: process.cwd(), dockerHost: process.env.DOCKER_HOST,
      basename: 'standalone-actor.json' });
    const identityMigration = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    const agentsMigration = new Pool({ connectionString: disposableUrl('AGENTS_MIGRATION_URL'), max: 2 });
    const agents = new Pool({ connectionString: disposableUrl('AGENTS_RUNTIME_URL'), max: 8 });
    t.after(() => Promise.allSettled([identity.end(),identityMigration.end(),agents.end(),agentsMigration.end()]));
    await historicalMigrator(identityDirectory,137)(identityMigration,identityDirectory);
    const historicalPassword = await bcrypt.hash('historical-platform-fixture',4);
    const historicalExpiry = new Date(Date.now()+3600000).toISOString();
    const historical = [];
    for (const kind of ['active','revoked','deleted']) {
      const label = `${kind}-${randomUUID().slice(0,8)}`;
      const user=(await identityMigration.query(`INSERT INTO identity.users
        (username,email,password) VALUES($1,$2,$3) RETURNING id`,
      [label,`${label}@platform.invalid`,historicalPassword])).rows[0];
      const token=randomUUID();
      const session=(await identityMigration.query(`INSERT INTO identity.user_sessions
        (user_id,session_token_hash,expires_at) VALUES($1,$2,$3) RETURNING id`,
      [user.id,createHash('sha256').update(token).digest('hex'),historicalExpiry])).rows[0];
      const launchId=randomUUID(),scenarioId=randomUUID();
      await identityMigration.query(`INSERT INTO identity.secureshop_launches
        (launch_id,platform_session_id,original_platform_session_id,
         original_platform_owner_id,handle_hash,scenario_id,expires_at)
        VALUES($1,$2,$2,$3,$4,$5,$6)`,
      [launchId,session.id,user.id,createHash('sha256').update(launchId).digest(),
        scenarioId,historicalExpiry]);
      historical.push({kind,userId:user.id,sessionId:session.id,token,launchId,scenarioId});
      if(kind==='revoked') await identityMigration.query(`UPDATE identity.user_sessions
        SET is_active=0,revoked_at=clock_timestamp(),revoke_reason='fixture'
        WHERE id=$1`,[session.id]);
      if(kind==='deleted') await identityMigration.query(`DELETE FROM identity.users WHERE id=$1`,[user.id]);
    }
    const historicalLaunches=(await identityMigration.query(`SELECT * FROM identity.secureshop_launches
      WHERE launch_id=ANY($1::uuid[]) ORDER BY launch_id`,[historical.map(row=>row.launchId)])).rows;
    assert.equal(historicalLaunches.filter(row=>row.platform_session_id===null).length,1);
    assert.deepEqual((await migrate(identityMigration,identityDirectory)),[
      '0138_secureshop_authority_registry.sql',
      '0139_secureshop_store_tenancy.sql',
      '0140_secureshop_tenant_execution_capacity.sql',
      '0141_secureshop_tenant_modes.sql',
      '0142_secureshop_assessments.sql',
      '0143_secureshop_assessment_recovery.sql',
      '0144_secureshop_registered_admin_reset.sql',
      '0145_secureshop_mail_scenes.sql',
      '0146_secureshop_shop_progress_cleanup.sql',
      '0147_secureshop_scene_target_cleanup.sql',
      '0148_secureshop_tenant_administration.sql',
      '0149_secureshop_admin_operation_kinds.sql',
      '0150_secureshop_practice_admission.sql',
      '0151_secureshop_files_principal_admission.sql',
      '0152_secureshop_scene_assessment_cleanup.sql',
      '0153_secureshop_external_test_mail.sql',
      '0154_ctf_global_reset_adaptive_memory.sql',
      '0155_ctf_authenticated_publication_stale.sql']);
    assert.deepEqual((await identityMigration.query(`SELECT * FROM identity.secureshop_launches
      WHERE launch_id=ANY($1::uuid[]) ORDER BY launch_id`,[historical.map(row=>row.launchId)])).rows,
      historicalLaunches);
    const activeHistory=historical.find(row=>row.kind==='active');
    const revokedHistory=historical.find(row=>row.kind==='revoked');
    const deletedHistory=historical.find(row=>row.kind==='deleted');
    assert.equal((await createIdentityRepository(identity).findActiveSession(
      activeHistory.token,activeHistory.userId)).session.id,activeHistory.sessionId);
    const registry=(await identity.query(`SELECT id,user_id,is_active,source_deleted
      FROM identity.secureshop_authority_sessions WHERE id=ANY($1::integer[])`,
    [historical.map(row=>row.sessionId)])).rows;
    assert.equal(registry.find(row=>row.id===activeHistory.sessionId).is_active,1);
    assert.equal(registry.find(row=>row.id===revokedHistory.sessionId).is_active,0);
    assert.equal(registry.find(row=>row.id===deletedHistory.sessionId).source_deleted,true);
    const deletedOwner=(await identity.query(`SELECT is_active,source_deleted
      FROM identity.secureshop_authority_owners WHERE id=$1`,[deletedHistory.userId])).rows[0];
    assert.deepEqual(deletedOwner,{is_active:0,source_deleted:true});
    await historicalMigrator(agentsDirectory,44)(agentsMigration,agentsDirectory);

    // Execute the actor and policy-admission successors on an empty catalog,
    // then roll back before qualifying the populated canonical ledger path.
    // Then populate historical rows and apply the same on-disk migration through
    // the canonical ledger. This qualifies both paths in one disposable store.
    const actorSql = await fs.readFile(path.join(agentsDirectory,'0045_standalone_shop_actor_identities.sql'),'utf8');
    const tenantSql = await fs.readFile(path.join(agentsDirectory,'0046_secureshop_tenant_actor_memberships.sql'),'utf8');
    const mailSql = await fs.readFile(path.join(agentsDirectory,'0047_bound_mail_tenant_actors.sql'),'utf8');
    const toolPolicySql = await fs.readFile(path.join(agentsDirectory,'0048_bound_tool_registered_actor_admission.sql'),'utf8');
    const promptPolicySql = await fs.readFile(path.join(agentsDirectory,'0049_bound_prompt_registered_actor_admission.sql'),'utf8');
    const mailResolutionSql = await fs.readFile(path.join(agentsDirectory,'0050_bound_mail_uncertain_resolution.sql'),'utf8');
    const mailSceneSql = await fs.readFile(path.join(agentsDirectory,'0051_mail_scene_execution.sql'),'utf8');
    const analyticsSql = await fs.readFile(path.join(agentsDirectory,'0052_analytics_registered_actor_admission.sql'),'utf8');
    const effectGuardSql = await fs.readFile(path.join(agentsDirectory,'0053_registered_actor_effect_guards.sql'),'utf8');
    const preview = await agentsMigration.connect();
    try {
      await preview.query('BEGIN');
      await preview.query(actorSql);
      await preview.query(tenantSql);
      await preview.query(mailSql);
      await preview.query(toolPolicySql);
      await preview.query(promptPolicySql);
      await preview.query(mailResolutionSql);
      await preview.query(mailSceneSql);
      await preview.query(analyticsSql);
      await preview.query(effectGuardSql);
      assert.equal((await preview.query(`SELECT count(*)::int n FROM secureshop_agents.bound_actor_identities`)).rows[0].n,0);
      await preview.query('ROLLBACK');
    } catch(error) { await preview.query('ROLLBACK').catch(()=>{}); throw error; }
    finally { preview.release(); }

    const standalone = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({pool:identity}),
    });
    const suffix = randomUUID().slice(0,8);
    const firstAuth = await standalone.register({ username:`actor_${suffix}`,email:`${suffix}@actor.invalid`,
      password:'disposable actor password',role:'customer' });
    const secondAuth = await standalone.register({ username:`sibling_${suffix}`,email:`sibling-${suffix}@actor.invalid`,
      password:'disposable actor password',role:'merchant' });
    const first = { ...firstAuth, context: await standalone.establishTenantContext(firstAuth.context) };
    const second = { ...secondAuth, context: await standalone.establishTenantContext(secondAuth.context) };
    assert.notEqual(first.context.shopUserId,second.context.shopUserId);
    assert.ok(first.context.shopUserId>=1000000000 && second.context.shopUserId>=1000000000);
    const launches = createSecureShopLaunchRepository(identity);
    const expiresAt = new Date(Date.now()+30*60*1000).toISOString();
    const firstLaunch = await launches.issueOrRenew({platformOwnerId:first.context.ownerId,
      platformSessionId:first.context.sessionId,expiresAt,shopPrincipal:first.context});
    const secondLaunch = await launches.issueOrRenew({platformOwnerId:second.context.ownerId,
      platformSessionId:second.context.sessionId,expiresAt,shopPrincipal:second.context});
    const templates = require('../../db/postgres/seeds/secureshop.json').shop_users
      .filter(row => ['student_customer','student_merchant','student_admin'].includes(row.username));
    for (const row of templates) {
      const source = [row.id,row.username,row.email,row.password,row.role,row.full_name??null,row.phone??null];
      await agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_templates
        (username,shop_user_id,email,password_hash,role,full_name,phone,source_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[row.username,row.id,row.email,row.password,row.role,
        row.full_name??null,row.phone??null,createHash('sha256').update(JSON.stringify(source)).digest()]);
    }
    const oldSession = randomUUID();
    await agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_sessions
      (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
       original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,11,'student_customer','customer',$8,$9)`,
    [oldSession,createHash('sha256').update(randomUUID()).digest(),
      firstLaunch.binding.launchId,firstLaunch.binding.scenarioId,firstLaunch.binding.generation,
      first.context.ownerId,first.context.sessionId,templates.find(row=>row.id===11).email,expiresAt]);
    const oldRow=(await agentsMigration.query(`SELECT * FROM secureshop_agents.bound_persona_sessions
      WHERE session_id=$1`,[oldSession])).rows[0];
    const applied=await migrate(agentsMigration,agentsDirectory);
    assert.deepEqual(applied,[
      '0045_standalone_shop_actor_identities.sql',
      '0046_secureshop_tenant_actor_memberships.sql',
      '0047_bound_mail_tenant_actors.sql',
      '0048_bound_tool_registered_actor_admission.sql',
      '0049_bound_prompt_registered_actor_admission.sql',
      '0050_bound_mail_uncertain_resolution.sql',
      '0051_mail_scene_execution.sql',
      '0052_analytics_registered_actor_admission.sql',
      '0053_registered_actor_effect_guards.sql',
      '0054_bound_mail_exact_sent_projection.sql',
      '0055_listing_template_conversation_purpose.sql',
      '0056_customer_chat_turn_binding.sql',
      '0057_pricing_experiment_request_v2.sql',
      '0058_role_chat_turn_binding.sql',
      '0059_bound_tool_registry_successor.sql',
      '0060_inventory_prepare_registry_successor.sql',
      '0061_pricing_prepare_registry_successor.sql',
      '0062_listing_edit_prepare_registry_successor.sql',
      '0063_listing_create_prepare_registry_successor.sql',
      '0064_address_setup_registry_successor.sql',
      '0065_address_edit_setup_registry_successor.sql',
      '0066_refund_setup_registry_successor.sql',
      '0067_merchant_orders_registry_successor.sql',
      '0068_merchant_reviews_registry_successor.sql',
      '0069_registry_denial_canonical_order.sql',
      '0070_customer_profile_registry_successor.sql',
      '0071_admin_user_prepare_registry_successor.sql',
      '0072_admin_password_reset_setup_registry_successor.sql',
      '0073_admin_policy_registry_successor.sql',
      '0074_admin_mcp_registry_successor.sql',
      '0075_admin_audit_system_read_registry_successor.sql',
      '0076_admin_management_prepare_registry_successor.sql',
      '0077_admin_management_successor_cardinality_repair.sql',
      '0078_pricing_compare_request_v3.sql',
      '0079_pricing_compare_prepare_registry_successor.sql',
      '0080_merchant_manual_search_registry_successor.sql',
      '0081_pricing_blocked_denial_outcome.sql',
      '0082_merchant_mail_reads_registry_successor.sql',
      '0083_bound_lab_mail_read_projection.sql',
      '0084_merchant_mail_prepare_registry_successor.sql',
      '0085_merchant_listing_setup_registry_successor.sql',
      '0086_idor_lesson_conversation_purpose.sql',
      '0087_customer_coupon_prepare_registry_successor.sql',
      '0088_customer_ticket_prepare_registry_successor.sql',
      '0089_admin_system_diagnostic_prepare_registry_successor.sql',
      '0090_bound_mail_inline_binding.sql',
      '0091_mail_summary_conversation_purpose.sql',
      '0092_mail_summary_registry_successor.sql',
      '0093_audit_unbounded_and_timing_purposes.sql',
      '0094_bound_mail_inline_generation_zero.sql',
      '0095_coupon_probe_conversation_purpose.sql',
      '0096_coupon_probe_registry_successor.sql',
      '0097_product_search_union_conversation_purpose.sql',
      '0098_product_search_union_registry_successor.sql',
      '0099_order_status_error_conversation_purpose.sql',
      '0100_coupon_probe_guided_v2_registry_successor.sql',
      '0101_checkout_audit_jwt_conversation_purpose.sql',
      '0102_avatar_upload_conversation_purpose.sql',
      '0103_avatar_upload_registry_successor.sql',
      '0104_avatar_upload_registry_guard_repair.sql',
      '0105_listing_optimize_conversation_purpose.sql',
      '0106_listing_optimize_registry_successor.sql',
      '0107_file_summary_conversation_purpose.sql',
      '0108_file_summary_registry_successor.sql',
      '0109_file_path_summary_conversation_purpose.sql',
      '0110_policy_final_html.sql',
      '0111_admin_user_lookup_registry_successor.sql',
      '0112_upload_preview_registry_successor.sql',
      '0113_owned_agency_role_state.sql',
      '0114_customer_agency_role_registry_successor.sql',
      '0115_owned_mcp_registration_journal.sql',
      '0116_mcp_registration_registry_successor.sql',
      '0117_mcp_describe_tools_registry_successor.sql',
      '0118_mcp_list_servers_registry_successor.sql',
      '0119_bound_additional_authenticated_sessions.sql']);
    assert.deepEqual((await agentsMigration.query(`SELECT * FROM secureshop_agents.bound_persona_sessions
      WHERE session_id=$1`,[oldSession])).rows[0],{
      ...oldRow,standalone_principal_id:null,standalone_session_id:null,bootstrap_jti:null,
      standalone_credential_version:null,standalone_authority_version:null,
      bootstrap_persona_authority_version:null,bootstrap_membership_version:null,
      additional_session:false });
    assert.deepEqual(await migrate(agentsMigration,agentsDirectory),[]);
    assert.deepEqual(await migrate(identityMigration,identityDirectory),[]);

    const personaAuthority = createSecureShopBoundPersonaAuthority({pool:agents,
      checkCurrent: scope => launches.assertCurrent(scope)});
    const personas = createSecureShopBoundPersonaRepository({commercePool:agents,
      agentsPool:agents,personaAuthority});
    const bound = createSecureShopBoundPersonaAuth({repository:personas,personaAuthority,
      launches,jwtSecret:'disposable-standalone-actor-fixture-secret-at-least-32-bytes'});
    const bootstrap = createSecureShopStandaloneBootstrap({launches,personaAuth:bound,
      authService:standalone});
    await assert.rejects(bound.establishSession({scope:firstLaunch.binding,
      shopPrincipal:{...first.context}}),{code:'SHOP_AUTH_INVALID'});
    await assert.rejects(bound.establishSession({scope:firstLaunch.binding,
      shopPrincipal:second.context}),{code:'SHOP_AUTH_INVALID'});
    const firstBound=await bound.establishSession({scope:firstLaunch.binding,shopPrincipal:first.context});
    const bootstraps=[];
    for(let i=0;i<20;i++) {
      const repeated=projectBootstrap(await bootstrap(firstAuth.context));
      assert.equal(repeated.persona.user.id,first.context.shopUserId);
      assert.equal(repeated.launch.launchId,firstLaunch.binding.launchId);
      bootstraps.push(repeated);
    }
    // Concurrent canonical bootstrap remains one physical session; extra sessions
    // are issued only through reauthentication, never this idempotent path.
    const firstBoundSessionId=(await bound.authenticateBoundToken({token:firstBound.token,scope:firstLaunch.binding})).sessionId;
    const concurrent=await Promise.all(Array.from({length:8},()=>bootstrap(firstAuth.context)));
    const originalBootstrap=bootstraps[0];
    for(const result of concurrent) assert.equal(
      (await bound.authenticateBoundToken({token:result.persona.token,
        scope:firstLaunch.binding})).sessionId,firstBoundSessionId);

    let refreshedBootstrap=bootstraps.find(value=>
      value.persona.token!==originalBootstrap.persona.token);
    if(!refreshedBootstrap) {
      // Production JWTs use second-resolution iat values. Cross one boundary
      // only when the initial bounded bootstrap calls share the same token.
      await new Promise(resolve=>setTimeout(resolve,1010-(Date.now()%1000)));
      refreshedBootstrap=projectBootstrap(await bootstrap(firstAuth.context));
    }
    assert.notEqual(refreshedBootstrap.persona.token,originalBootstrap.persona.token);
    assert.equal(refreshedBootstrap.bearer,originalBootstrap.bearer);
    const personaRows=(await agents.query(`SELECT session_id,jti_sha256
      FROM secureshop_agents.bound_persona_sessions
      WHERE standalone_principal_id=$1 ORDER BY session_id`,[first.context.principalId])).rows;
    assert.equal(personaRows.length,1);
    const siblingBound=await bound.establishSession({scope:secondLaunch.binding,shopPrincipal:second.context});
    const firstVerified=await bound.authenticateBoundToken({
      token:originalBootstrap.persona.token,scope:firstLaunch.binding});
    const refreshedVerified=await bound.authenticateBoundToken({
      token:refreshedBootstrap.persona.token,scope:firstLaunch.binding});
    assert.equal(firstVerified.sessionId,personaRows[0].session_id);
    assert.equal(refreshedVerified.sessionId,personaRows[0].session_id);
    assert.equal(refreshedVerified.authorityVersion,firstVerified.authorityVersion);
    assert.equal((await bound.authenticateBoundToken({
      token:firstBound.token,scope:firstLaunch.binding})).sessionId,personaRows[0].session_id);
    assert.equal(firstVerified.user.id,
      first.context.shopUserId);
    // Native real-service proof: wrong password cannot issue, a selected
    // additional session is distinct, and the canonical/sibling survive revoke.
    const issueAdditional=(password='disposable actor password')=>
      standalone.withReauthenticatedExecution({token:firstAuth.token,
        username:firstAuth.context.username,password}, shopPrincipal=>
        bound.establishAdditionalSession({scope:firstLaunch.binding,shopPrincipal,
          token:originalBootstrap.persona.token}));
    await assert.rejects(issueAdditional('incorrect password'),
      {code:'SHOP_CREDENTIALS_INVALID'});
    const extras=[await issueAdditional(),await issueAdditional()];
    const extraIds=[];
    for(const extra of extras) {
      const verified=await bound.authenticateBoundToken({token:extra.token,scope:firstLaunch.binding});
      assert.notEqual(verified.sessionId,firstVerified.sessionId);
      extraIds.push(verified.sessionId);
    }
    assert.notEqual(extraIds[0],extraIds[1]);
    const flags=(await agents.query(`SELECT session_id,additional_session
      FROM secureshop_agents.bound_persona_sessions
      WHERE session_id=ANY($1::uuid[])`,[[firstVerified.sessionId,...extraIds]])).rows;
    assert.equal(flags.find(row=>row.session_id===firstVerified.sessionId).additional_session,false);
    for(const id of extraIds) assert.equal(flags.find(row=>row.session_id===id).additional_session,true);
    // Capacity is per owned launch, including its canonical row and the
    // populated historical row. Query the real store, not a mocked counter.
    let active=(await agents.query(`SELECT count(*)::int n
      FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1
      AND platform_launch_generation=$2 AND revoked_at IS NULL
      AND expires_at>clock_timestamp()`,[firstLaunch.binding.launchId,
        firstLaunch.binding.generation])).rows[0].n;
    assert.ok(active<MAX_ACTIVE);
    while(active++<MAX_ACTIVE) extras.push(await issueAdditional());
    await assert.rejects(issueAdditional(),{code:'SHOP_PERSONA_CAPACITY'});
    assert.equal(await bound.revokeOwnedSession({scope:firstLaunch.binding,
      shopPersona:firstVerified.user,currentSessionId:firstVerified.sessionId,
      authorityVersion:firstVerified.authorityVersion,sessionId:extraIds[0]}),true);
    await assert.rejects(bound.authenticateBoundToken({token:extras[0].token,
      scope:firstLaunch.binding}));
    assert.equal((await bound.authenticateBoundToken({token:extras[1].token,
      scope:firstLaunch.binding})).sessionId,extraIds[1]);
    assert.equal((await bound.authenticateBoundToken({token:originalBootstrap.persona.token,
      scope:firstLaunch.binding})).sessionId,firstVerified.sessionId);
    assert.equal((await bound.authenticateBoundToken({token:siblingBound.token,
      scope:secondLaunch.binding})).user.id,second.context.shopUserId);
    for(const extra of extras) await bound.logout({scope:firstLaunch.binding,token:extra.token});
    const originalHeaders=Object.freeze({authorization:`Bearer ${originalBootstrap.persona.token}`,
      'x-owasp-ai-goat-secureshop-launch':originalBootstrap.bearer});
    const originalHeadersSnapshot={...originalHeaders};
    const refreshedHeaders=Object.freeze({authorization:`Bearer ${refreshedBootstrap.persona.token}`,
      'x-owasp-ai-goat-secureshop-launch':refreshedBootstrap.bearer});
    const recoveryDependencies={composition:{launches,personaAuth:bound},auth:standalone,
      systemAuthByLaunch:new Map([[firstLaunch.binding.launchId,firstAuth.context]]),
      username:originalBootstrap.persona.user.username,scope:firstLaunch.binding,
      persona:{id:firstVerified.user.id,role:firstVerified.user.role},
      personaSession:{sessionId:firstVerified.sessionId,
        authorityVersion:firstVerified.authorityVersion},principal:first.context};
    const identicalBootstraps=[{username:originalBootstrap.persona.user.username,
      authorization:originalHeaders.authorization,launch:originalHeaders['x-owasp-ai-goat-secureshop-launch']}];
    const identicalAuthority=createV11RecoveryAuthority({...recoveryDependencies,
      browserBootstraps:identicalBootstraps});
    identicalAuthority.arm();
    identicalBootstraps.push({username:originalBootstrap.persona.user.username,
      authorization:originalHeaders.authorization,launch:originalHeaders['x-owasp-ai-goat-secureshop-launch']});
    assert.deepEqual(await identicalAuthority.authorize({headers:()=>originalHeaders}),originalHeaders);
    const refreshedBootstraps=[{username:originalBootstrap.persona.user.username,
      authorization:originalHeaders.authorization,launch:originalHeaders['x-owasp-ai-goat-secureshop-launch']}];
    const refreshedAuthority=createV11RecoveryAuthority({...recoveryDependencies,
      browserBootstraps:refreshedBootstraps});
    refreshedAuthority.arm();
    refreshedBootstraps.push({username:originalBootstrap.persona.user.username,
      authorization:refreshedHeaders.authorization,launch:refreshedHeaders['x-owasp-ai-goat-secureshop-launch']});
    assert.deepEqual(await refreshedAuthority.authorize({headers:()=>refreshedHeaders}),refreshedHeaders);
    const requestLog=[],assessmentIds={sessionId:randomUUID(),requestId:randomUUID()};
    const savedPath=`/agents/merchant/assistant/mail-read/assessment/${assessmentIds.sessionId}/${assessmentIds.requestId}`;
    const siblingHeaders={authorization:`Bearer ${siblingBound.token}`,
      'x-owasp-ai-goat-secureshop-launch':secondLaunch.bearer};
    const httpCounters=createV11HttpCounters({requestLog,headers:originalHeaders,
      siblingHeaders,scope:firstLaunch.binding,siblingScope:secondLaunch.binding,
      getIds:()=>assessmentIds});
    assert.equal(httpCounters.registerOwner(originalHeaders),true);
    requestLog.push({method:'GET',path:savedPath,status:200,
      authorization:originalHeaders.authorization,launch:originalHeaders['x-owasp-ai-goat-secureshop-launch']});
    assert.deepEqual(httpCounters(),{assessmentPosts:0,savedAssessmentGets:1,
      deniedAssessmentPosts:0,deniedSourceGets:0,deniedSavedAssessmentGets:0});
    assert.equal(httpCounters.registerOwner(refreshedHeaders),true);
    assert.equal(httpCounters.registerOwner(refreshedHeaders),true);
    requestLog.push({method:'GET',path:savedPath,status:200,
      authorization:refreshedHeaders.authorization,launch:refreshedHeaders['x-owasp-ai-goat-secureshop-launch']});
    assert.deepEqual(httpCounters(),{assessmentPosts:0,savedAssessmentGets:2,
      deniedAssessmentPosts:0,deniedSourceGets:0,deniedSavedAssessmentGets:0});
    assert.equal(requestLog.length,2);
    assert.deepEqual(originalHeaders,originalHeadersSnapshot);
    assert.equal((await bound.authenticateBoundToken({token:siblingBound.token,scope:secondLaunch.binding})).user.id,
      second.context.shopUserId);
    assert.notEqual(firstBound.user.id,11);
    assert.notEqual(siblingBound.user.id,12);
    const firstActor=(await agents.query(`SELECT principal_id,original_platform_owner_id
      FROM secureshop_agents.bound_actor_identities WHERE shop_user_id=$1`,
    [first.context.shopUserId])).rows[0];
    assert.equal(firstActor.principal_id,first.context.principalId);
    assert.equal(Number(firstActor.original_platform_owner_id),first.context.principalOwnerId);
    const mirrorInsert=`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
      (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,
        membership_version,role)
      VALUES($1,$2,$3,$4,$5,$6,$7)`;
    const mirrorArgs=[first.context.ownerId,first.context.tenantId,
      first.context.shopUserId,first.context.principalId,
      first.context.principalOwnerId,Number(first.context.membershipVersion)+1,
      first.context.role];
    await assert.rejects(agents.query(mirrorInsert,
      [mirrorArgs[0],randomUUID(),...mirrorArgs.slice(2)]),{code:'55000'});
    await assert.rejects(agents.query(mirrorInsert,
      [mirrorArgs[0]+1000000,...mirrorArgs.slice(1)]),{code:'23505'});
    assert.equal((await agents.query(`SELECT count(*)::int n
      FROM secureshop_agents.bound_actor_tenant_memberships WHERE shop_user_id=$1`,
    [first.context.shopUserId])).rows[0].n,1);
    const { REGISTRY_SHA256 }=require('../../server/services/secureshopBoundAclRegistry');
    const audit=require('../../server/database/postgres/secureshopBoundAuditRepository')
      .createBoundAuditStore({store:'agents',pool:agents});
    const policy=require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({personaAuthority,audit});
    const policyContext={scope:firstLaunch.binding,
      persona:{id:first.context.shopUserId,role:'customer'},
      personaSession:{sessionId:firstVerified.sessionId,
        authorityVersion:firstVerified.authorityVersion}};
    const policyCall={...policyContext,runId:randomUUID(),invocationId:'1:product-summary',
      workflow:'product-summary',declaredTools:[{agent:'summarizer',tool:'summarize_product'}],
      agent:'summarizer',tool:'summarize_product',args:{product_id:125}};
    const receipt=await policy.admitTool(policyCall);
    assert.equal(receipt.action,'dispatch');
    assert.equal(receipt.allowed,true);
    assert.equal(receipt.toolKey,'summarizer.summarize_product');
    assert.deepEqual(await policy.admitTool(policyCall),receipt);
    const storedPolicy=(await agents.query(`SELECT persona_id,persona_session_id,
      authority_version,action FROM secureshop_agents.bound_tool_admissions
      WHERE admission_id=$1`,[receipt.admissionId])).rows[0];
    assert.equal(storedPolicy.persona_id,first.context.shopUserId);
    assert.equal(storedPolicy.persona_session_id,firstVerified.sessionId);
    assert.equal(String(storedPolicy.authority_version),firstVerified.authorityVersion);
    assert.equal(storedPolicy.action,'dispatch');
    const coords=[firstLaunch.binding.launchId,firstLaunch.binding.scenarioId,
      firstLaunch.binding.generation,firstLaunch.binding.platformOwnerId,
      firstLaunch.binding.platformSessionId];
    const directAdmission=async({personaId=first.context.shopUserId,
      sessionId=firstVerified.sessionId,role='customer',authorityVersion=firstVerified.authorityVersion}={})=>
      agents.query(`INSERT INTO secureshop_agents.bound_tool_admissions
        (platform_launch_id,platform_scenario_id,platform_launch_generation,
         original_platform_owner_id,original_platform_session_id,
         admission_id,run_id,invocation_id,persona_id,persona_session_id,
         persona_role,authority_version,tool_key,args_sha256,registry_sha256,
         policy_version,enforcement_enabled,allowed,action)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
          'summarizer.summarize_product',decode($13,'hex'),decode($14,'hex'),1,false,true,'dispatch')`,
      [...coords,randomUUID(),randomUUID(),`1:${randomUUID()}`,
        personaId,sessionId,role,authorityVersion,
        createHash('sha256').update('owned-fixture').digest('hex'),REGISTRY_SHA256]);
    // The historical template continues to satisfy the same guard.
    await directAdmission({personaId:11,sessionId:oldSession});
    for(const invalid of [
      {sessionId:randomUUID()},
      {role:'admin'},
      {authorityVersion:'2'},
      {personaId:second.context.shopUserId,sessionId:(await bound.authenticateBoundToken({
        token:siblingBound.token,scope:secondLaunch.binding})).sessionId,role:'merchant'},
    ])await assert.rejects(directAdmission(invalid),{code:'55000'});
    assert.deepEqual(await seedSecureShopStandaloneDefaults(identity),{seeded:true});
    const adminAuth=await standalone.login({username:'student_admin',password:'student123'});
    const adminPrincipal=await standalone.establishTenantContext(adminAuth.context);
    const adminLaunch=await launches.issueOrRenew({platformOwnerId:adminPrincipal.ownerId,
      platformSessionId:adminPrincipal.sessionId,expiresAt,shopPrincipal:adminPrincipal});
    const adminBound=await bound.establishSession({scope:adminLaunch.binding,
      shopPrincipal:adminPrincipal});
    const adminVerified=await bound.authenticateBoundToken({token:adminBound.token,
      scope:adminLaunch.binding});
    const adminContext={scope:adminLaunch.binding,
      persona:{id:adminPrincipal.shopUserId,role:'admin'},
      personaSession:{sessionId:adminVerified.sessionId,
        authorityVersion:adminVerified.authorityVersion}};
    const systemConfig=require('../../server/database/postgres/secureshopSystemConfigReadRepository')
      .createSystemConfigReadRepository({pool:agents,personaAuthority,audit});
    const systemDiagnostic=require('../../server/database/postgres/secureshopSystemDiagnosticRepository')
      .createSystemDiagnosticRepository({pool:agents,personaAuthority,audit});
    const mcpRegistry=require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository')
      .createOwnedMcpRegistryRepository({pool:agents,personaAuthority});
    assert.deepEqual(await systemConfig.checkReadiness(),{ready:true});
    assert.deepEqual(await systemDiagnostic.checkReadiness(),{ready:true,candidate:true});
    await require('../../server/database/postgres/secureshopPricingReadiness')
      .assertPricingReadiness(agents);
    const database=(await agents.query('SELECT current_database() AS name')).rows[0].name;
    assert.deepEqual(await require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository')
      .assertOwnedMcpRegistryReady({pool:agents,expectedDatabase:database}),
    {ready:true,database});
    const configInput={...adminContext,operationId:randomUUID(),path:'fixture-config.txt'};
    const diagnosticInput={...adminContext,operationId:randomUUID(),cmd_template:'printf',args:'FIXTURE_ONLY'};
    assert.equal((await systemConfig.begin(configInput)).state,'admitted');
    assert.equal((await systemDiagnostic.begin(diagnosticInput)).state,'admitted');
    const registryInput={...adminContext,request:{version:1,action:'register',
      operationId:randomUUID(),expectedVersion:'0',name:'fixture-only',transport:'sse',
      url:'http://127.0.0.1:8099/fixture',stdio_cmd:''}};
    const registryAdmission=await mcpRegistry.beginPrepared(mcpRegistry.prepare(registryInput),{mode:'vuln'});
    assert.equal(registryAdmission.operation.state,'admitted');
    const pricingInput=async({scope=firstLaunch.binding,persona=policyContext.persona,
      personaSession=policyContext.personaSession}={})=>{
      const operationId=randomUUID();
      return agents.query(`INSERT INTO secureshop_agents.bound_pricing_admissions
        (platform_launch_id,platform_scenario_id,platform_launch_generation,
         original_platform_owner_id,original_platform_session_id,operation_id,run_id,target_id,
         target_snapshot_json,persona_id,persona_session_id,persona_role,authority_version,
         request_sha256,binding_sha256,request_json)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'{}'::jsonb,$9,$10,$11,$12,
          decode($13,'hex'),decode($14,'hex'),$15::jsonb)`,
      [scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,
        scope.platformSessionId,operationId,randomUUID(),randomUUID(),persona.id,
        personaSession.sessionId,persona.role,personaSession.authorityVersion,
        createHash('sha256').update(operationId).digest('hex'),
        createHash('sha256').update('fixture-binding').digest('hex'),
        JSON.stringify({operationId,productId:125,task:persona.role==='customer'
          ?'price-advisor':'pricing-strategy',message:'Controlled pricing guard admission'})]);
    };
    await pricingInput();
    const secondVerified=await bound.authenticateBoundToken({token:siblingBound.token,
      scope:secondLaunch.binding});
    const secondContext={scope:secondLaunch.binding,
      persona:{id:second.context.shopUserId,role:'merchant'},
      personaSession:{sessionId:secondVerified.sessionId,
        authorityVersion:secondVerified.authorityVersion}};
    await pricingInput(secondContext);
    await assert.rejects(pricingInput({...secondContext,scope:firstLaunch.binding}),{code:'55000'});
    await assert.rejects(systemConfig.begin({...configInput,operationId:randomUUID(),
      persona:secondContext.persona,personaSession:secondContext.personaSession}),
    {code:'ADMIN_REQUIRED'});
    await assert.rejects(systemDiagnostic.begin({...diagnosticInput,operationId:randomUUID(),
      persona:secondContext.persona,personaSession:secondContext.personaSession}),
    {code:'ADMIN_REQUIRED'});
    await assert.rejects(agents.query(`SELECT secureshop_agents.assert_owned_mcp_registry_actor_current(
      $1,$2,$3,$4,$5,$6,$7,$8)`,[...coords,adminPrincipal.shopUserId,
      adminVerified.sessionId,adminVerified.authorityVersion]),{code:'42501'});
    assert.equal((await policy.readPolicy(adminContext)).version,'1');
    const operationId=randomUUID();
    const changed=await policy.mutate({...adminContext,operationId,
      expectedVersion:'1',change:{kind:'enforcement',enabled:true}});
    assert.equal(changed.version,'2');
    assert.deepEqual(await policy.readOperation({...adminContext,operationId}),changed);
    assert.equal((await agents.query(`SELECT count(*)::int n
      FROM secureshop_agents.bound_tool_policy_operations
      WHERE operation_id=$1 AND persona_id=$2 AND persona_role='admin'`,
    [operationId,adminPrincipal.shopUserId])).rows[0].n,1);
    const promptAudit=require('../../server/database/postgres/secureshopBoundAuditRepository')
      .createBoundAuditStore({store:'agents',pool:agents});
    const promptRepository=require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
      .createBoundPromptPolicyRepository({pool:agents,personaAuthority,audit:promptAudit,
        checkRunBinding:require('../../server/services/secureshopPromptPolicyRunBinding')
          .createPromptPolicyRunBinding({identityPool:identity})});
    assert.deepEqual(await promptRepository.checkReadiness(),{ready:true});
    const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository')
      .createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
    const conversationId=randomUUID();
    const mailPurpose=require('../../server/services/secureshopConversationPurpose')
      .SECURESHOP_CONVERSATION_PURPOSES.mailReply;
    const conversationBinding=require('../../server/services/secureshopConversationBinding')
      .createConversationBinding(firstLaunch.binding,policyContext.persona);
    await conversationRepository.acquireBoundSession({id:conversationId,binding:conversationBinding,
      purpose:mailPurpose});
    assert.equal(await conversationRepository.activateBoundSession(conversationId,
      conversationBinding,mailPurpose),true);
    const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({
      family:'SecureShopBoundConversation',
      ledger:require('../../server/agent-runtime/postgresRunLedger')
        .createPostgresRunLedger(identity,{leasePool:identity})});
    let promptRunId;
    await coordinator.run(conversationId,{},async execution=>{
      promptRunId=execution.runId;
      const input={...policyContext,runId:execution.runId};
      const snapshot=await promptRepository.admitRunSnapshot(input);
      assert.equal(snapshot.version,1);
      assert.deepEqual(await promptRepository.admitRunSnapshot(input),snapshot);
      await execution.check();
      return {};
    });
    const promptReceipt=(await agents.query(`SELECT persona_id,persona_session_id,
      authority_version,persona_role,payload_json FROM secureshop_agents.bound_prompt_policy_snapshots
      WHERE run_id=$1`,[promptRunId])).rows[0];
    assert.equal(promptReceipt.persona_id,first.context.shopUserId);
    assert.equal(promptReceipt.persona_session_id,firstVerified.sessionId);
    assert.equal(String(promptReceipt.authority_version),firstVerified.authorityVersion);
    assert.equal(promptReceipt.persona_role,'customer');
    assert.equal(promptReceipt.payload_json.version,1);
    await assert.rejects(promptRepository.admitRunSnapshot({
      ...policyContext,runId:promptRunId}),
    {code:'POLICY_RUN_AUTHORITY_UNAVAILABLE'});
    const directPromptSnapshot=async({personaId=first.context.shopUserId,
      sessionId=firstVerified.sessionId,role='customer',authorityVersion=firstVerified.authorityVersion}={})=>
      agents.query(`INSERT INTO secureshop_agents.bound_prompt_policy_snapshots
        (platform_launch_id,platform_scenario_id,platform_launch_generation,
         original_platform_owner_id,original_platform_session_id,run_id,
         persona_id,persona_session_id,authority_version,persona_role,policy_version,
         payload_json,payload_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,'{}'::jsonb,decode($11,'hex'))`,
      [...coords,randomUUID(),personaId,sessionId,authorityVersion,role,
        createHash('sha256').update('{}').digest('hex')]);
    // The historical template still qualifies; foreign and forged actors do not.
    await directPromptSnapshot({personaId:11,sessionId:oldSession});
    for(const invalid of [
      {sessionId:randomUUID()},
      {role:'admin'},
      {authorityVersion:'2'},
      {personaId:second.context.shopUserId,sessionId:(await bound.authenticateBoundToken({
        token:siblingBound.token,scope:secondLaunch.binding})).sessionId,role:'merchant'},
    ])await assert.rejects(directPromptSnapshot(invalid),{code:'55000'});
    const promptMutation={...adminContext,action:'preview',expectedVersion:'1',
      request:{operationId:randomUUID(),name:'actor-guard-check',
        markdown:'Controlled owned prompt policy text',targets:['admin']}};
    assert.equal((await promptRepository.beginRender(promptMutation)).state,'admitted');
    const promptContract=require('../../server/services/secureshopPromptPolicyContract');
    const previewReceipt=await promptRepository.publish({...promptMutation,renderResult:{
      version:1,operationId:promptMutation.request.operationId,
      requestSha256:promptContract.requestDigest(promptMutation.request),
      isolation:promptContract.ISOLATION,
      rendered:promptMutation.request.markdown,
      renderedSha256:createHash('sha256').update(promptMutation.request.markdown).digest('hex'),
      exitCode:0,timedOut:false,truncated:false,drained:true}});
    assert.equal(previewReceipt.version,'1');
    assert.equal((await agents.query(`SELECT count(*)::int n
      FROM secureshop_agents.bound_prompt_policy_operations
      WHERE operation_id=$1 AND persona_id=$2 AND persona_role='admin' AND result_json IS NOT NULL`,
    [promptMutation.request.operationId,adminPrincipal.shopUserId])).rows[0].n,1);
    // A newer mirrored membership invalidates the old session's exact
    // bootstrap version; it cannot mint a second policy receipt.
    await agentsMigration.query(mirrorInsert,mirrorArgs);
    await assert.rejects(directAdmission(),{code:'55000'});
    await assert.rejects(directPromptSnapshot(),{code:'55000'});
    await assert.rejects(pricingInput(),{code:'55000'});
    assert.equal((await agents.query(`SELECT count(*)::int n
      FROM secureshop_agents.bound_tool_admissions WHERE admission_id=$1`,
    [receipt.admissionId])).rows[0].n,1);
    assert.equal(await standalone.logout(adminAuth.token),true);
    await assert.rejects(launches.assertCurrent(adminLaunch.binding),{code:'STALE_LAUNCH'});
    await assert.rejects(systemConfig.begin({...configInput,operationId:randomUUID()}),
      {code:'STALE_LAUNCH'});
    await assert.rejects(systemDiagnostic.begin({...diagnosticInput,operationId:randomUUID()}),
      {code:'STALE_LAUNCH'});
    await assert.rejects(mcpRegistry.beginPrepared(mcpRegistry.prepare({...registryInput,
      request:{...registryInput.request,operationId:randomUUID()}}),{mode:'vuln'}),
    {code:'STALE_LAUNCH'});
    assert.equal(await standalone.logout(first.token),true);
    await assert.rejects(launches.assertCurrent(firstLaunch.binding));
    await assert.rejects(bound.authenticateBoundToken({token:firstBound.token,scope:firstLaunch.binding}));
    assert.equal((await bound.authenticateBoundToken({token:siblingBound.token,scope:secondLaunch.binding})).user.id,
      second.context.shopUserId);
    assert.equal((await agents.query(`SELECT count(*)::int n FROM secureshop_agents.bound_persona_sessions
      WHERE session_id=$1`,[oldSession])).rows[0].n,1);
    assert.deepEqual(await seedSecureShopStandaloneDefaults(identity),{seeded:false});
    assert.equal((await identity.query(`SELECT count(*)::int n FROM secureshop_auth.default_seed_state`)).rows[0].n,1);
    assert.equal((await identity.query(`SELECT count(*)::int n FROM secureshop_auth.principals
      WHERE username IN ('student_customer','student_merchant','student_admin')`)).rows[0].n,3);
    assert.deepEqual(await seedSecureShopStandaloneDefaults(identity),{seeded:false});
    const demoFirst=await standalone.login({username:'student_customer',password:'student123'});
    const demoSibling=await standalone.login({username:'student_customer',password:'student123'});
    const demoExecution=await standalone.establishTenantContext(demoFirst.context);
    assert.equal((await standalone.establishTenantContext(demoFirst.context)).sessionId,
      demoExecution.sessionId);
    const secondTenantId=randomUUID(),secondTenantSlug=`fixture_${suffix}`;
    await identityMigration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2)`,[secondTenantId,secondTenantSlug]);
    await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [secondTenantId,demoSibling.context.principalId,demoSibling.context.shopUserId]);
    const isolated= createSecureShopStandaloneAuthService({
      repository:createSecureShopStandaloneAuthRepository({pool:identity,
        executionTenantSlug:secondTenantSlug}),
    });
    // A membership added after login cannot extend an old session's authority.
    assert.equal(await isolated.authenticate(demoSibling.token),null);
    // Obtain a fresh supported session whose immutable membership snapshot
    // contains both tenants, then project that same session through each one.
    const secondTenantAuth=await standalone.login({username:'student_customer',password:'student123'});
    const sameCookie=await isolated.authenticate(secondTenantAuth.token);
    const secondTenantExecution=await isolated.establishTenantContext(sameCookie);
    const defaultSiblingExecution=await standalone.establishTenantContext(secondTenantAuth.context);
    assert.equal(secondTenantExecution.authSessionId,defaultSiblingExecution.authSessionId);
    assert.notEqual(secondTenantExecution.ownerId,defaultSiblingExecution.ownerId);
    assert.notEqual(secondTenantExecution.sessionId,defaultSiblingExecution.sessionId);
    assert.notEqual(secondTenantExecution.launchBearer,defaultSiblingExecution.launchBearer);
    assert.equal(secondTenantExecution.tenantId,secondTenantId);
    assert.equal((await identity.query(`SELECT user_id,is_active
      FROM identity.secureshop_authority_sessions WHERE id=$1`,
    [secondTenantExecution.sessionId])).rows[0].user_id,secondTenantExecution.ownerId);
    const demoRenewed=await standalone.renew(demoFirst.token);
    assert.notEqual(demoRenewed.context.sessionId,demoFirst.context.sessionId);
    assert.notEqual(demoRenewed.context.launchBearer,demoFirst.context.launchBearer);
    assert.equal(await standalone.authenticate(demoFirst.token),null);
    assert.equal((await standalone.authenticate(demoSibling.token)).sessionId,demoSibling.context.sessionId);
    assert.equal((await identity.query(`SELECT is_active FROM identity.secureshop_authority_sessions
      WHERE id=$1`,[demoFirst.context.sessionId])).rows[0].is_active,0);
    assert.equal((await identity.query(`SELECT is_active FROM identity.secureshop_authority_sessions
      WHERE id=$1`,[demoExecution.sessionId])).rows[0].is_active,0);
    assert.equal((await identity.query(`SELECT is_active FROM identity.secureshop_authority_sessions
      WHERE id=$1`,[demoRenewed.context.sessionId])).rows[0].is_active,1);
    const renewedExecution=await standalone.establishTenantContext(demoRenewed.context);
    assert.notEqual(renewedExecution.sessionId,demoExecution.sessionId);
    assert.equal((await identity.query(`SELECT is_active FROM identity.secureshop_authority_sessions
      WHERE id=$1`,[renewedExecution.sessionId])).rows[0].is_active,1);
    assert.deepEqual(await standalone.changePassword(demoRenewed.token,
      {currentPassword:'student123',newPassword:'changed-default-password'}),
    {ok:true,passwordChanged:true});
    assert.equal(await standalone.authenticate(demoRenewed.token),null);
    assert.equal(await standalone.authenticate(demoSibling.token),null);
    assert.equal((await identity.query(`SELECT is_active FROM identity.secureshop_authority_sessions
      WHERE id=$1`,[renewedExecution.sessionId])).rows[0].is_active,0);
    assert.deepEqual(await seedSecureShopStandaloneDefaults(identity),{seeded:false});
    await assert.rejects(standalone.login({username:'student_customer',password:'student123'}),
      {code:'SHOP_CREDENTIALS_INVALID'});
    const changedDefault=await standalone.login({username:'student_customer',
      password:'changed-default-password'});
    assert.ok(changedDefault.context.sessionId>demoRenewed.context.sessionId);
    await identity.query(`UPDATE secureshop_auth.principals SET is_active=false
      WHERE username='student_merchant'`);
    assert.deepEqual(await seedSecureShopStandaloneDefaults(identity),{seeded:false});
    assert.equal((await identity.query(`SELECT is_active FROM secureshop_auth.principals
      WHERE username='student_merchant'`)).rows[0].is_active,false);
    await fs.writeFile(evidencePath,JSON.stringify({passed:true,
      scope:'Controlled disposable standalone shop identity and bound actor authority; no browser or model qualification',
      freshMigration:true,populatedMigrationPreserved:true,secondRunNoop:true,
      distinctRegisteredActors:true,crossOwnerDenied:true,sessionRevocationFenced:true,
      siblingPreserved:true,defaultSeedDurable:true,renewalNewSession:true,
      passwordRevocationFenced:true,secondTenantIsolated:true,
      registeredToolPolicyAdmission:true,registeredPromptPolicyAdmission:true}), { flag: 'wx', mode: 0o600 });
  });
