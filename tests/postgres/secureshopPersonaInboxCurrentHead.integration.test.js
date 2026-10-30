'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopPersonaInboxRepository } = require('../../server/database/postgres/secureshopPersonaInboxRepository');
const { createSecureShopPersonaInboxAvailability } = require('../../server/services/secureshopPersonaInboxAvailability');
const { assertPersonaInboxReadiness } = require('../../server/services/secureshopBoundReviewComposition');

const PREFIX = 'PG_SECURESHOP_PERSONA_CURRENT_';
const VARIANTS = ['FRESH', 'POPULATED'];
const ROLES = ['customer', 'merchant', 'admin'];
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVES = ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && VARIANTS.every(variant =>
  ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'AGENTS_MIGRATION_URL', 'AGENTS_RUNTIME_URL']
    .every(key => process.env[`${PREFIX}${variant}_${key}`]));
const passwordHash = bcrypt.hashSync('owned-persona-current-head', 4);

function checked(variant, key) {
  const value = new URL(process.env[`${PREFIX}${variant}_${key}`]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_secureshop_persona_current_(fresh|populated)_(identity|agents)$/);
  return value.href;
}
function digest(value) { return crypto.createHash('sha256').update(value).digest(); }
function fixtures(offset) {
  return ROLES.map((role, index) => ({ fixtureKey: `${role}-note`,
    owner: { id: offset + index + 1, role }, subject: `${role} subject`, body: `${role} owned fixture` }));
}
async function ledger(pool) {
  return (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}
async function atomicCopy(source, target) {
  const pending = `${target}.pending-${process.pid}`;
  await fs.copyFile(source, pending); await fs.rename(pending, target);
}

test('current-head persona inbox drafts preserve hidden fresh and populated stores through actual loaders', {
  skip: !enabled, timeout: 90000,
}, async () => {
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-secureshop-persona-current-/);
  const identityDir = path.join(workspace, 'db/postgres/identity-migrations');
  const agentsDir = path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents');
  const identityTarget = path.join(identityDir, '0045_secureshop_persona_inbox_identity.sql');
  const agentsTarget = path.join(agentsDir, '0010_secureshop_persona_inbox.sql');
  await assert.rejects(fs.stat(identityTarget), { code: 'ENOENT' });
  await assert.rejects(fs.stat(agentsTarget), { code: 'ENOENT' });

  const stores = VARIANTS.map(variant => ({
    variant,
    identityMigration: new Pool({ connectionString: checked(variant, 'IDENTITY_MIGRATION_URL'), max: 2 }),
    identity: new Pool({ connectionString: checked(variant, 'IDENTITY_RUNTIME_URL'), max: 6 }),
    agentsMigration: new Pool({ connectionString: checked(variant, 'AGENTS_MIGRATION_URL'), max: 2 }),
    agents: new Pool({ connectionString: checked(variant, 'AGENTS_RUNTIME_URL'), max: 6 }),
  }));
  try {
    for (const store of stores) {
      await initializeIdentityRepository(store.identity, store.identityMigration);
      await seedWorkshopPlatform(store.identityMigration);
      await initializeSecureShopAgentsDb({ runtimePool: store.agents, migrationPool: store.agentsMigration });
      const identityLedger = await ledger(store.identityMigration);
      const agentsLedger = await ledger(store.agentsMigration);
      assert.equal(identityLedger.length, 43); assert.equal(identityLedger.at(-1).name, '0044_sensitive_info_aggregate_reset.sql');
      assert.equal(agentsLedger.length, 9); assert.equal(agentsLedger.at(-1).name, '0009_secureshop_bound_persona_renewal.sql');
      store.prior = { identityLedger, agentsLedger };

      const suffix = store.variant.toLowerCase();
      const identities = createIdentityRepository(store.identity);
      const user = await identities.createUser({ username: `persona-${suffix}`,
        email: `persona-${suffix}@owned.invalid`, passwordHash, fullName: `Owned ${suffix}` });
      await store.identity.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
        VALUES($1,$2,7)`, [user.id, WORKSHOP]);
      if (store.variant === 'POPULATED') {
        await store.identityMigration.query(`UPDATE workshop_platform.exercises SET is_visible=false,
          show_hints=true,show_solutions=false WHERE workshop_key=$1`, [WORKSHOP]);
        await store.identityMigration.query(`UPDATE workshop_platform.objectives SET label='Instructor preserved ACL label',
          is_enabled=false,hint_enabled=true,solution_enabled=false WHERE workshop_key=$1 AND objective_id=$2`,
        [WORKSHOP, OBJECTIVES[1]]);
        await store.agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_templates
          (username,shop_user_id,email,password_hash,role,full_name,source_sha256)
          VALUES('preserved_persona',9001,'preserved@owned.invalid',$1,'customer','Instructor persona',$2)`,
        [passwordHash, digest('preserved-template')]);
      }
      store.preserved = {
        platform: (await store.identityMigration.query(`SELECT e.is_visible,e.show_hints,e.show_solutions,
          o.label,o.is_enabled,o.hint_enabled,o.solution_enabled
          FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
          WHERE e.workshop_key=$1 AND o.objective_id=$2`, [WORKSHOP, OBJECTIVES[1]])).rows[0],
        state: (await store.identity.query(`SELECT user_id,workshop_key,generation FROM workshop_platform.user_state
          WHERE user_id=$1 AND workshop_key=$2`, [user.id, WORKSHOP])).rows[0],
        templates: (await store.agentsMigration.query(`SELECT username,shop_user_id,email,role,full_name
          FROM secureshop_agents.bound_persona_templates ORDER BY username`)).rows,
      };
      store.user = user;
    }

    const identityDraft = path.join(workspace, 'docs/modernization/drafts/secureshop-persona-inbox-identity.sql');
    const agentsDraft = path.join(workspace, 'docs/modernization/drafts/secureshop-persona-inbox-agents.sql');
    assert.equal(crypto.createHash('sha256').update(await fs.readFile(identityDraft)).digest('hex'),
      'a7736a4dfa7277b713f19c2842418eefba376f221b94702b8bab661ed70c824c');
    assert.equal(crypto.createHash('sha256').update(await fs.readFile(agentsDraft)).digest('hex'),
      '3855742f3a716f8498611a7fce8b442c8759706974dc0a45a14a810dc968ec45');
    await atomicCopy(identityDraft, identityTarget); await atomicCopy(agentsDraft, agentsTarget);

    for (const [index, store] of stores.entries()) {
      assert.deepEqual(await migrate(store.identityMigration, identityDir), ['0045_secureshop_persona_inbox_identity.sql']);
      assert.deepEqual(await migrate(store.agentsMigration, agentsDir), ['0010_secureshop_persona_inbox.sql']);
      assert.deepEqual((await ledger(store.identityMigration)).slice(0, -1), store.prior.identityLedger);
      assert.deepEqual((await ledger(store.agentsMigration)).slice(0, -1), store.prior.agentsLedger);
      assert.deepEqual(await initializeIdentityRepository(store.identity, store.identityMigration), []);
      await initializeSecureShopAgentsDb({ runtimePool: store.agents, migrationPool: store.agentsMigration });
      assert.deepEqual(await migrate(store.identityMigration, identityDir), []);
      assert.deepEqual(await migrate(store.agentsMigration, agentsDir), []);
      assert.equal((await ledger(store.identityMigration)).at(-1).checksum,
        'a7736a4dfa7277b713f19c2842418eefba376f221b94702b8bab661ed70c824c');
      assert.equal((await ledger(store.agentsMigration)).at(-1).checksum,
        '3855742f3a716f8498611a7fce8b442c8759706974dc0a45a14a810dc968ec45');
      assert.equal(await assertPersonaInboxReadiness({ identityPool: store.identity, agentsPool: store.agents }), true);
      const availability = createSecureShopPersonaInboxAvailability(store.identity);
      const hidden = await availability.read();
      assert.equal(hidden.registered, true); assert.equal(hidden.visible, false); assert.equal(hidden.enabled.size, 0);
      await assert.rejects(availability.assertObjectives(OBJECTIVES), { code: 'PERSONA_INBOX_EXERCISE_UNAVAILABLE' });

      const current = {
        platform: (await store.identityMigration.query(`SELECT e.is_visible,e.show_hints,e.show_solutions,
          o.label,o.is_enabled,o.hint_enabled,o.solution_enabled
          FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
          WHERE e.workshop_key=$1 AND o.objective_id=$2`, [WORKSHOP, OBJECTIVES[1]])).rows[0],
        state: (await store.identity.query(`SELECT user_id,workshop_key,generation FROM workshop_platform.user_state
          WHERE user_id=$1 AND workshop_key=$2`, [store.user.id, WORKSHOP])).rows[0],
        templates: (await store.agentsMigration.query(`SELECT username,shop_user_id,email,role,full_name
          FROM secureshop_agents.bound_persona_templates ORDER BY username`)).rows,
      };
      assert.deepEqual(current, store.preserved);

      const identities = createIdentityRepository(store.identity);
      const launches = createSecureShopLaunchRepository(store.identity);
      const makeTarget = async label => {
        const user = await identities.createUser({ username: `${store.variant.toLowerCase()}-${label}`,
          email: `${store.variant.toLowerCase()}-${label}@owned.invalid`, passwordHash });
        const session = await identities.createSession({ userId: user.id, token: crypto.randomUUID(),
          expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
        const issued = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id,
          expiresAt: new Date(Date.now() + 3600000) });
        const target = { targetId: crypto.randomUUID(), ...issued.binding,
          platformOwnerId: user.id, platformSessionId: session.id };
        await store.identity.query(`INSERT INTO identity.secureshop_target_reservations
          (target_id,launch_id,generation,target_kind,original_platform_owner_id)
          VALUES($1,$2,$3,'persona_inbox',$4)`, [target.targetId,target.launchId,target.generation,user.id]);
        return target;
      };
      const owner = await makeTarget(`owner-${index}`); const sibling = await makeTarget(`sibling-${index}`);
      const rows = fixtures(10000 + index * 10);
      for (const fixture of rows) await store.agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_templates
        (username,shop_user_id,email,password_hash,role,full_name,source_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [`${store.variant.toLowerCase()}_${fixture.owner.role}`,
        fixture.owner.id,`${fixture.owner.role}-${index}@owned.invalid`,passwordHash,fixture.owner.role,
        `Owned ${fixture.owner.role}`,digest(`${store.variant}-${fixture.owner.role}`)]);
      const repository = createSecureShopPersonaInboxRepository(store.agents, {
        checkCurrent: value => launches.assertCurrent(value), checkAclTransition: async () => {}, checkCleanup: async () => {},
      });
      await repository.provision(owner, { fixtures: rows }); await repository.provision(sibling, { fixtures: rows });
      const operationId = crypto.randomUUID();
      const receipt = await repository.cleanup(owner, { operationId });
      assert.equal(receipt.deletedMessageCount, 3);
      assert.deepEqual(await repository.cleanup(owner, { operationId }), receipt);
      await assert.rejects(repository.provision(owner, { fixtures: rows }),
        { code: 'PERSONA_INBOX_TARGET_MISMATCH' });
      assert.equal((await repository.list(sibling)).length, 3);

      const publicAcl = (await store.agentsMigration.query(`SELECT
        EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL
          aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
          WHERE c.oid='secureshop_agents.persona_inbox_messages'::regclass
            AND a.grantee=0 AND a.privilege_type='SELECT') AS table_public,
        EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL
          aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid='secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer)'::regprocedure
            AND a.grantee=0 AND a.privilege_type='EXECUTE') AS function_public`)).rows[0];
      assert.deepEqual(publicAcl, { table_public: false, function_public: false });
    }
  } finally {
    await Promise.allSettled(stores.flatMap(store => [store.identity.end(), store.identityMigration.end(),
      store.agents.end(), store.agentsMigration.end()]));
  }
});
