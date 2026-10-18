'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_MCP_INTEGRATION_IDENTITY_RUNTIME_URL
  && process.env.PG_MCP_INTEGRATION_IDENTITY_MIGRATION_URL
  && process.env.PG_MCP_INTEGRATION_RUNTIME_URL
  && process.env.PG_MCP_INTEGRATION_MIGRATION_URL;

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const exactRows = (pool, sql, params = []) => pool.query(sql, params).then(result => result.rows);

test('reserved identity0050 and MCP0004 load normally, preserve populated state and replay empty', {
  skip: !enabled,
}, async t => {
  for (const key of ['PG_MCP_INTEGRATION_IDENTITY_RUNTIME_URL','PG_MCP_INTEGRATION_IDENTITY_MIGRATION_URL',
    'PG_MCP_INTEGRATION_RUNTIME_URL','PG_MCP_INTEGRATION_MIGRATION_URL']) {
    const url = new URL(process.env[key]); assert.match(url.pathname, /^\/dvaia_test_mcp_integration_[a-z0-9_]+$/);
  }
  const identityRuntime = new Pool({ connectionString: process.env.PG_MCP_INTEGRATION_IDENTITY_RUNTIME_URL, max: 4 });
  const identityMigration = new Pool({ connectionString: process.env.PG_MCP_INTEGRATION_IDENTITY_MIGRATION_URL, max: 2 });
  const mcpRuntime = new Pool({ connectionString: process.env.PG_MCP_INTEGRATION_RUNTIME_URL, max: 4 });
  const mcpMigration = new Pool({ connectionString: process.env.PG_MCP_INTEGRATION_MIGRATION_URL, max: 2 });
  const identityCandidate = path.resolve(__dirname, '../../db/postgres/identity-migrations/0050_mcp_conversation_history.sql');
  const mcpCandidate = path.resolve(__dirname, '../../db/postgres/workshop-migrations/mcp/0004_mcp_owned_resources.sql');
  const predecessors = [
    ['0047_secureshop_persona_inbox_catalog.sql', 'secureshop-persona-inbox-catalog-transition.sql', 'e12496c0ebf7c3927ab2d967afa286b3e5774d88f4223527444c222c19ed3e64'],
    ['0048_workshop_catalog_field_provenance.sql', 'workshop-catalog-field-provenance.sql', '96ea10297e339cc277a0c76db8dad7028f5683b1dbc1db46a3d913889fe24de2'],
    ['0049_workshop_catalog_persona_adoption.sql', 'workshop-catalog-field-provenance-persona-adoption.sql', 'aa22efe7d731bbb378f6cc9d7954f109af34573773f2f0f6ade10098b02abccb'],
  ];
  const stagedIdentity = [...predecessors.map(([name]) => path.resolve(__dirname, '../../db/postgres/identity-migrations', name)), identityCandidate];
  const staging = require('./helpers/ownedMigrationStaging').createOwnedMigrationStaging();
  t.after(() => staging.cleanup());
  try {
    await staging.assertAbsent([...stagedIdentity, mcpCandidate]);
    const identityApi = require('../../server/database/postgres/identityRepository');
    const mcpApi = require('../../server/database/postgres/mcpWorkshopDb');
    const initialIdentityApplied = await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    assert.equal(initialIdentityApplied.at(-1), '0046_graph_judge_validation_code.sql');
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    assert.deepEqual(await mcpApi.createMcpWorkshopDb(mcpRuntime).initialize(mcpMigration), undefined);
    const identityPrefix = await exactRows(identityMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
    const mcpPrefix = await exactRows(mcpMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
    assert.equal(identityPrefix.at(-1).name, '0046_graph_judge_validation_code.sql');
    assert.equal(mcpPrefix.at(-1).name, '0003_owner_binding.sql');

    const repository = identityApi.createIdentityRepository(identityRuntime);
    const user = await repository.createUser({ username: `mcp-loader-${crypto.randomUUID().slice(0, 8)}`,
      email: `${crypto.randomUUID()}@example.invalid`, passwordHash: await bcrypt.hash('fixture', 4) });
    await mcpRuntime.query("INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,'mcp_recon')", [String(user.id)]);
    const catalogBefore = await exactRows(identityRuntime, `SELECT objective_id,label,is_enabled,catalog_active
      FROM workshop_platform.objectives WHERE workshop_key='mcp_workshop' ORDER BY objective_id`);
    assert.equal(catalogBefore.length, 11);
    const totalsBefore = await exactRows(identityRuntime, `SELECT workshop_key,
      count(*) FILTER (WHERE catalog_active AND is_enabled)::integer AS enabled_total,
      count(*) FILTER (WHERE catalog_active)::integer AS catalog_total
      FROM workshop_platform.objectives GROUP BY workshop_key ORDER BY workshop_key`);
    const progressBefore = await exactRows(mcpRuntime, 'SELECT * FROM mcp.progress WHERE user_key=$1 ORDER BY objective_id', [String(user.id)]);

    const identityDraft = await fs.readFile(path.resolve(__dirname, '../../docs/modernization/drafts/0050_mcp_conversation_history.sql'));
    const mcpDraft = await fs.readFile(path.resolve(__dirname, '../../docs/modernization/drafts/0004_mcp_owned_resources.sql'));
    for (const [name, draftName, expected] of predecessors) {
      const bytes = await fs.readFile(path.resolve(__dirname, '../../docs/modernization/drafts', draftName));
      assert.equal(sha(bytes), expected);
      await staging.write(path.resolve(__dirname, '../../db/postgres/identity-migrations', name), bytes);
    }
    await staging.write(identityCandidate, identityDraft);
    await staging.write(mcpCandidate, mcpDraft);
    assert.deepEqual(await identityApi.initializeIdentityRepository(identityRuntime, identityMigration), [
      ...predecessors.map(([name]) => name), '0050_mcp_conversation_history.sql',
    ]);
    assert.deepEqual(await mcpApi.createMcpWorkshopDb(mcpRuntime).initialize(mcpMigration), undefined);

    const identityLedger = await exactRows(identityMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
    const mcpLedger = await exactRows(mcpMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
    assert.equal(identityLedger.length, identityPrefix.length + predecessors.length + 1);
    assert.equal(mcpLedger.length, mcpPrefix.length + 1);
    assert.deepEqual(identityLedger.slice(0, identityPrefix.length), identityPrefix);
    assert.deepEqual(mcpLedger.slice(0, mcpPrefix.length), mcpPrefix);
    for (const [name, , checksum] of predecessors) {
      assert.deepEqual(identityLedger.find(row => row.name === name), { name, checksum });
    }
    assert.deepEqual(identityLedger.at(-1), { name: '0050_mcp_conversation_history.sql', checksum: sha(identityDraft) });
    assert.deepEqual(mcpLedger.at(-1), { name: '0004_mcp_owned_resources.sql', checksum: sha(mcpDraft) });
    assert.deepEqual(await exactRows(identityRuntime, `SELECT objective_id,label,is_enabled,catalog_active
      FROM workshop_platform.objectives WHERE workshop_key='mcp_workshop' ORDER BY objective_id`), catalogBefore);
    assert.deepEqual(await exactRows(identityRuntime, `SELECT workshop_key,
      count(*) FILTER (WHERE catalog_active AND is_enabled)::integer AS enabled_total,
      count(*) FILTER (WHERE catalog_active)::integer AS catalog_total
      FROM workshop_platform.objectives GROUP BY workshop_key ORDER BY workshop_key`), totalsBefore);
    assert.deepEqual(await exactRows(mcpRuntime, 'SELECT * FROM mcp.progress WHERE user_key=$1 ORDER BY objective_id', [String(user.id)]), progressBefore);

    const identityPrivileges = (await exactRows(identityMigration, `SELECT
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.turns','SELECT') AS turns_select,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.turns','INSERT') AS turns_insert,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.turns','DELETE') AS turns_delete,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.turns','UPDATE') AS turns_update,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.requests','SELECT') AS requests_select,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.requests','INSERT') AS requests_insert,
      has_table_privilege('dvaia_identity_runtime','workshop_conversations.requests','DELETE') AS requests_delete,
      has_column_privilege('dvaia_identity_runtime','workshop_conversations.requests','user_text','UPDATE') AS user_text_update,
      has_column_privilege('dvaia_identity_runtime','workshop_conversations.requests','response_json','UPDATE') AS response_update`))[0];
    assert.deepEqual(identityPrivileges, {
      turns_select: true, turns_insert: true, turns_delete: true, turns_update: false,
      requests_select: true, requests_insert: true, requests_delete: false,
      user_text_update: true, response_update: true,
    });
    const mcpPrivileges = (await exactRows(mcpMigration, `SELECT
      bool_and(has_table_privilege('dvaia_mcp_runtime',format('mcp.%I',name),'SELECT')) AS can_select,
      bool_and(has_table_privilege('dvaia_mcp_runtime',format('mcp.%I',name),'INSERT')) AS can_insert,
      bool_and(has_table_privilege('dvaia_mcp_runtime',format('mcp.%I',name),'UPDATE')) AS can_update,
      bool_or(has_table_privilege('dvaia_mcp_runtime',format('mcp.%I',name),'DELETE')) AS can_delete
      FROM unnest(ARRAY['runner_targets','runner_target_cleanups','mail_intents','mail_cleanups']) AS name`))[0];
    assert.deepEqual(mcpPrivileges, { can_select: true, can_insert: true, can_update: true, can_delete: false });
    assert.equal(Number((await exactRows(identityMigration, `SELECT count(*) AS n FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
      WHERE acl.grantee=0 AND n.nspname='workshop_conversations'
        AND c.relname=ANY($1::text[])`, [['turns','requests']]))[0].n), 0);
    assert.equal(Number((await exactRows(mcpMigration, `SELECT count(*) AS n FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
      WHERE acl.grantee=0 AND n.nspname='mcp'
        AND c.relname=ANY($1::text[])`,
      [['runner_targets','runner_target_cleanups','mail_intents','mail_cleanups']]))[0].n), 0);

    const ownerKey = JSON.stringify(['MCP', String(user.id)]), runId = crypto.randomUUID(), requestId = crypto.randomUUID();
    await identityMigration.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [ownerKey]);
    await identityMigration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')", [runId, ownerKey]);
    const execution = { ownerKey, runId, durableGeneration: 0, async check() {} };
    const requests = require('../../server/database/postgres/mcpRequestRepository').createMcpRequestRepository(identityRuntime);
    const conversations = require('../../server/database/postgres/mcpConversationRepository').createMcpConversationRepository(identityRuntime);
    assert.deepEqual(await requests.admit({ userId: user.id, requestId, userText: 'owned loader request', execution }), { state: 'admitted' });
    await requests.complete({ userId: user.id, requestId, execution, response: { response: 'owned loader response' } });
    await identityMigration.query("UPDATE graph_runtime.runs SET status='completed',finished_at=clock_timestamp() WHERE run_id=$1", [runId]);
    assert.equal((await conversations.list(user.id))[0].assistantText, 'owned loader response');

    const resources = require('../../server/database/postgres/mcpResourceRepository').createMcpResourceRepository(mcpRuntime);
    const scope = { targetId: crypto.randomUUID(), platformOwnerId: user.id, platformSessionId: 1, generation: 0 };
    assert.deepEqual(await resources.reserveRunnerTarget(scope), { replayed: false });
    assert.deepEqual(await resources.readActiveRunnerTarget(scope), scope);

    const identityAdapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
      repository, progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime),
      jwtSecret: 'mcp-loader-qualified-secret',
    });
    // Match the canonical singleton assembly used by production startup: its
    // validated adapter publishes the same runtime pool used by repositories.
    identityAdapter.pool = identityRuntime;
    const session = await identityAdapter.createSession(await repository.findCredentialById(user.id), { get: () => null, ip: '127.0.0.1' });
    const validated = await identityAdapter.validateSession(session.token);
    assert.equal(validated.user.id, user.id);
    assert.equal(validated.session.user_id, user.id);
    assert.equal(validated.session.id, session.internalSessionId);
    assert.equal(validated.decoded.userId, user.id);
    const sessionResolver = require('../../server/services/mcp/platformSessionBinding')
      .createMcpPlatformSessionResolver({ validateSession: token => identityAdapter.validateSession(token) });
    const resolved = await sessionResolver.resolveRequest({
      headers: { authorization: `Bearer ${session.token}` }, user: { id: user.id },
      session: { sessionData: { id: session.internalSessionId } },
    });
    assert.deepEqual({ platformOwnerId: resolved.platformOwnerId, platformSessionId: resolved.platformSessionId },
      { platformOwnerId: user.id, platformSessionId: session.internalSessionId });
    assert.equal(await resolved.assertCurrent(), true);
    let installed = 0;
    let targetEffects = 0;
    const targets = {
      async readiness() { return { ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
        isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)' }; },
      async admit() { targetEffects += 1; throw new Error('PG-only gate must not admit a target'); },
      async retire() { targetEffects += 1; throw new Error('PG-only gate must not retire a target'); },
    };
    const activation = await require('../../server/services/mcp/ownedResourceProduction').installMcpOwnedResourceProduction({
      env: { MCP_OWNED_RESOURCES_ENABLED: 'true', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' },
      route: { installOwnedRuntime() { installed += 1; } }, identityAdapter, resourcePool: mcpRuntime,
      targets,
      mailReadiness: async () => ({ ready: true }),
    });
    assert.equal(activation.installed, true); assert.equal(installed, 1); assert.equal(targetEffects, 0);
    assert.deepEqual(await identityApi.initializeIdentityRepository(identityRuntime, identityMigration), []);
    assert.deepEqual(await mcpApi.createMcpWorkshopDb(mcpRuntime).initialize(mcpMigration), undefined);
    assert.deepEqual(await exactRows(identityMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name'), identityLedger);
    assert.deepEqual(await exactRows(mcpMigration, 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name'), mcpLedger);
  } finally {
    await Promise.all([identityRuntime.end(), identityMigration.end(), mcpRuntime.end(), mcpMigration.end()]);
  }
});
