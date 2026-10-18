'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  createHash,
  randomUUID
} = require('node:crypto');
const {
  createPool
} = require('../server/database/postgres');
const {
  migrate,
  readMigrations
} = loadMigrationWithVirtualDirectories();
const { poolBudget } = require('../server/database/postgres/poolBudget');
const ROOT = path.resolve(__dirname, '..'),
  IDENTITY = path.join(ROOT, 'db/postgres/identity-migrations');
const TENANT_ADMIN_MIGRATION = '0148_secureshop_tenant_administration.sql';
const ADMIN_OPERATION_KIND_MIGRATION = '0149_secureshop_admin_operation_kinds.sql';
const TAIL = ['0059_dpi_policy_trace_metadata.sql', '0060_finflow_description_default.sql', '0061_mcp_supply_chain_curriculum_defaults.sql', '0065_ipi_email_artifacts.sql', '0066_dpi_teaching_copy_alignment.sql', '0067_graph_observability_metadata.sql'];
const MIGRATION_POOL_OPTIONS = Object.freeze({ purpose: 'migration' });
const RUNTIME_POOL_OPTIONS = Object.freeze({ purpose: 'control' });
function qualifiedUrl(value, role) {
  if (!value) return null;
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  const url = new URL(value);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && Number(url.port) > 0 && Number(url.port) < 65536);
  assert.equal(url.password, '');
  assert.equal(decodeURIComponent(url.username), role);
  const database = decodeURIComponent(url.pathname.slice(1));
  assert.match(database, /^dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url.href;
}
function pair(prefix) {
  const migration = qualifiedUrl(process.env[`${prefix}_MIGRATION_URL`], 'dvaia_identity_migration');
  const runtime = qualifiedUrl(process.env[`${prefix}_RUNTIME_URL`], 'dvaia_identity_runtime');
  if (!migration || !runtime) return null;
  const a = new URL(migration),
    b = new URL(runtime);
  assert.equal(a.hostname, b.hostname);
  assert.equal(a.port, b.port);
  assert.equal(a.pathname, b.pathname);
  return {
    migration,
    runtime
  };
}
async function assertRolePair(runtime, migration) {
  const r = (await runtime.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  const m = (await migration.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  assert.equal(r.role, 'dvaia_identity_runtime');
  assert.equal(m.role, 'dvaia_identity_migration');
  assert.equal(r.database, m.database);
}
async function assertRuntimeBoundary(runtime) {
  await assert.rejects(
    () => runtime.query('CREATE TABLE identity.__runtime_must_not_create (id integer)'),
    error => error.code === '42501'
  );
  await assert.rejects(
    () => runtime.query('SELECT name,checksum FROM dvaia_migrations.ledger'),
    error => error.code === '42501'
  );
}
async function snapshot(client) {
  const tables = [
    'identity.users',
    'graph_runtime.events',
    'workshop_platform.exercises',
    'workshop_platform.objectives',
    'workshop_platform.catalog_field_defaults',
    'workshop_platform.config_revision',
    'workshop_platform.user_state',
    'workshop_platform.completions',
    'workshop_platform.time_tracking',
    'identity.ipi_email_artifacts',
    'workshop_platform.audit_judge_stage_checkpoints'
  ];
  const result = {};
  for (const table of tables) {
    let rows;
    try {
      rows = (await client.query(`SELECT md5(COALESCE(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')) AS digest,count(*)::integer AS count FROM ${table} t`)).rows;
    } catch (error) {
      if (error.code === '42P01') {
        result[table] = {
          exists: false
        };
        continue;
      }
      throw error;
    }
    result[table] = {
      exists: true,
      ...rows[0]
    };
  }
  return result;
}
function learnerProjection(value) {
  return Object.fromEntries([
    'identity.users',
    'workshop_platform.user_state',
    'workshop_platform.completions',
    'workshop_platform.time_tracking'
  ].map(table => [table, value[table]]));
}
async function seedCustomRows(client) {
  const marker = `identity-tail-custom-${process.pid}`;
  const saved = [];
  const owner = (await client.query('SELECT id FROM identity.users ORDER BY id LIMIT 1')).rows[0];
  assert.ok(owner, 'populated fixture requires an existing instructor/user row');
  const exercise = (await client.query("SELECT workshop_key,challenge_description,updated_by FROM workshop_platform.exercises WHERE workshop_key='sensitive_info_disclosure'")).rows[0];
  if (exercise) {
    saved.push(['exercise', exercise]);
    await client.query("UPDATE workshop_platform.exercises SET is_visible=false,updated_by=$1 WHERE workshop_key=$2", [owner.id, exercise.workshop_key]);
  }
  const objective = (await client.query("SELECT workshop_key,objective_id,solution_content,hint_content,updated_by FROM workshop_platform.objectives WHERE workshop_key='mcp_workshop' AND objective_id='mcp_supply_chain'")).rows[0];
  if (objective) saved.push(['objective', objective]);
  const provenance = (await client.query("SELECT * FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective' AND workshop_key='direct_prompt_injection' AND objective_id='jailbreak' AND field_name='hint_content'")).rows[0];
  if (provenance) {
    saved.push(['provenance', provenance]);
    await client.query("UPDATE workshop_platform.catalog_field_defaults SET provenance_state='custom',source_version=$1 WHERE entity_kind='objective' AND workshop_key='direct_prompt_injection' AND objective_id='jailbreak' AND field_name='hint_content'", [marker]);
  }
  return {
    marker,
    saved
  };
}
async function assertPolicyContract(pool, cleanup = pool) {
  const id = randomUUID();
  const owner = JSON.stringify(['identity-tail', id]);
  await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [owner]);
  await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')", [id, owner]);
  let sequence = 1;
  const insert = metadata => pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'judge_validate','decision',$4)", [id, owner, sequence++, JSON.stringify(metadata)]);
  await insert({
    policyProfile: 'guided_weak_policy',
    policyVersion: 'dpi-guided-weak-policy-v1',
    policyDigest: 'a'.repeat(64)
  });
  await insert({ comparisonStage: 'effect' });
  await insert({
    reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry',
    reviewerProfileVersion: 'structured-artifact-v1',
    reviewerPolicyDigest: 'b'.repeat(64)
  });
  for (const bad of [{
    policyProfile: 'guided_weak_policy',
    policyVersion: 'dpi-guided-weak-policy-v1'
  }, {
    policyProfile: 'unknown',
    policyVersion: 'dpi-guided-weak-policy-v1',
    policyDigest: 'a'.repeat(64)
  }, {
    policyProfile: 'guided_weak_policy',
    policyVersion: 'dpi-guided-weak-policy-v1',
    policyDigest: 'z'.repeat(64)
  }, {
    policyProfile: 'guided_weak_policy',
    policyVersion: 'dpi-guided-weak-policy-v1',
    policyDigest: 3
  }, {
    comparisonStage: 'final'
  }, {
    comparisonStage: null
  }, {
    reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry',
    reviewerProfileVersion: 'structured-artifact-v2',
    reviewerPolicyDigest: 'b'.repeat(64)
  }, {
    reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry',
    reviewerProfileVersion: 'structured-artifact-v1',
    reviewerPolicyDigest: null
  }, {
    reviewerProfileId: null,
    reviewerProfileVersion: null,
    reviewerPolicyDigest: null
  }, {
    reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry'
  }]) {
    try {
      await insert(bad);
      assert.fail('invalid policy snapshot accepted');
    } catch (error) {
      assert.equal(error.code, '23514');
    }
  }
  await cleanup.query('DELETE FROM graph_runtime.events WHERE run_id=$1', [id]);
  await cleanup.query('DELETE FROM graph_runtime.runs WHERE run_id=$1', [id]);
  await cleanup.query('DELETE FROM graph_runtime.owners WHERE owner_key=$1', [owner]);
}
async function assertIpiArtifactContract(runtime, cleanup = runtime) {
  const user = (await runtime.query('SELECT id FROM identity.users ORDER BY id LIMIT 1')).rows[0];
  assert.ok(user);
  const ownerKey = JSON.stringify(['IndirectEmail', String(user.id)]),
    runId = randomUUID(),
    artifactId = randomUUID(),
    body = 'controlled identity-tail message',
    model = 'controlled model projection';
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0) ON CONFLICT(owner_key) DO UPDATE SET generation=0', [ownerKey]);
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')", [runId, ownerKey]);
  const digest = createHash('sha256').update(body).digest('hex'),
    modelDigest = createHash('sha256').update(model).digest('hex');
  await runtime.query(`INSERT INTO identity.ipi_email_artifacts(artifact_id,owner_id,owner_key,generation,run_id,ingestion_kind,provider,provider_message_id,sent_receipt_id,sender,recipient,subject,body_text,body_bytes,body_sha256,model_body_text,model_body_bytes,model_body_sha256,model_body_truncated) VALUES($1,$2,$3,0,$4,'manual_entry','manual_entry',NULL,NULL,'','student@example.test','qualification',$5,$6,$7,$8,$9,$10,false)`, [artifactId, user.id, ownerKey, runId, body, Buffer.byteLength(body), digest, model, Buffer.byteLength(model), modelDigest]);
  await assert.rejects(() => runtime.query(`INSERT INTO identity.ipi_email_artifacts(artifact_id,owner_id,owner_key,generation,run_id,ingestion_kind,provider,sender,recipient,subject,body_text,body_bytes,body_sha256,model_body_text,model_body_bytes,model_body_sha256,model_body_truncated) VALUES($1,$2,$3,0,$4,'manual_entry','manual_entry','','student@example.test','bad',$5,999,$6,$7,$8,$9,false)`, [randomUUID(), user.id, ownerKey, runId, body, digest, model, Buffer.byteLength(model), modelDigest]), /violates check constraint/);
  await runtime.query('DELETE FROM identity.ipi_email_artifacts WHERE artifact_id=$1', [artifactId]).catch(error => {
    if (error.code !== '42501') throw error;
  });
  await cleanup.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1", [runId]);
  await cleanup.query('DELETE FROM graph_runtime.runs WHERE run_id=$1', [runId]);
  await cleanup.query('DELETE FROM graph_runtime.owners WHERE owner_key=$1', [ownerKey]);
}
async function ledger(pool) {
  return (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}
// Only registered handles are virtual; actual directories (including fresh native
// IDENTITY qualification) retain the production filesystem behavior.
const virtualDirectories = new Map();
const virtualFs = {
  async readdir(directory, ...args) {
    const entries = virtualDirectories.get(directory);
    return entries ? [...entries.keys()] : fsp.readdir(directory, ...args);
  },
  async readFile(file, encoding) {
    const entries = virtualDirectories.get(path.dirname(file));
    if (!entries) return fsp.readFile(file, encoding);
    assert.equal(encoding, 'utf8');
    if (!entries.has(path.basename(file))) throw Object.assign(Error('Missing virtual migration'), { code: 'ENOENT' });
    return entries.get(path.basename(file));
  }
};
function loadMigrationWithVirtualDirectories() {
  const { Module, createRequire } = require('node:module');
  const filename = require.resolve('../db/postgres/migrate');
  const localRequire = createRequire(filename), loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? {
    readdir: (...args) => virtualFs.readdir(...args),
    readFile: (...args) => virtualFs.readFile(...args)
  } : localRequire(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
async function stage(dir) {
  return stageThrough(dir, '\uffff');
}
async function stageThrough(dir, last) {
  const handle = path.join('/virtual-identity-qualification', randomUUID());
  const entries = new Map();
  for (const name of await virtualFs.readdir(dir)) {
    if (/^\d{4}_[a-z0-9_]+\.sql$/.test(name) && name <= last)
      entries.set(name, await virtualFs.readFile(path.join(dir, name), 'utf8'));
  }
  virtualDirectories.set(handle, entries);
  return handle;
}
function disposeStage(directory) {
  assert.equal(virtualDirectories.delete(directory), true);
}
function appendFailure(directory) {
  const entries = virtualDirectories.get(directory);
  assert.ok(entries);
  const name = '9999_qualification_failure.sql';
  assert.equal(entries.has(name), false);
  entries.set(name, 'CREATE TABLE identity.__qualification_failure (id integer);\nSELECT 1 / 0;\n');
  return path.join(directory, name);
}
function removeFailure(file) {
  assert.equal(virtualDirectories.get(path.dirname(file)).delete(path.basename(file)), true);
}
async function bootstrapPopulated(pool) {
  const baseline = await stageThrough(IDENTITY, '0058_finflow_durable_log_overlay_tip.sql');
  try {
    await migrate(pool, baseline);
    const user = (await pool.query(`INSERT INTO identity.users(username,email,password,role,admin_level) VALUES('identity_tail_owner_${process.pid}','identity_tail_${process.pid}@example.test','$2b$04$${'A'.repeat(53)}','admin',1) RETURNING id`)).rows[0];
    await pool.query(`INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal) VALUES('sensitive_info_disclosure','sensitive_info_disclosure','FinFlow','Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.','ai','advanced','/workshop/sensitive-info',1),('mcp_workshop','mcp_workshop','MCP','MCP training','ai','advanced','/workshop/mcp',2),('direct_prompt_injection','direct_prompt_injection','DPI','DPI training','ai','advanced','/workshop/prompt-injection',3)`);
    const mcp = fs.readFileSync(path.join(IDENTITY, '0061_mcp_supply_chain_curriculum_defaults.sql'), 'utf8');
    const oldSolution = JSON.parse(mcp.match(/\$old_0\$(.*?)\$old_0\$::jsonb/s)[1]);
    const oldHint = JSON.parse(mcp.match(/\$old_1\$(.*?)\$old_1\$::jsonb/s)[1]);
    await pool.query(
      `INSERT INTO workshop_platform.objectives
         (workshop_key,objective_id,label,category,ordinal,hint_content,solution_content,updated_by)
       VALUES
         ('mcp_workshop','mcp_supply_chain','Supply chain','training',1,$1::jsonb,$2::jsonb,$3),
         ('direct_prompt_injection','jailbreak','Instructor-owned jailbreak','training',1,'{}'::jsonb,'{}'::jsonb,$3),
         ('direct_prompt_injection','interact','Interact with the AI assistant','training',2,NULL,NULL,NULL)`,
      [oldHint, oldSolution, user.id]
    );
    await pool.query(
      `INSERT INTO identity.users(username,email,password,role)
       VALUES('identity_tail_sibling_${process.pid}','identity_tail_sibling_${process.pid}@example.test','$2b$04$${'B'.repeat(53)}','student')`
    );
    await pool.query(
      `INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation,started_at)
       VALUES($1,'direct_prompt_injection',3,'2026-09-18T00:00:00Z')`,
      [user.id]
    );
    await pool.query(
      `INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id,completed_at,updated_at)
       VALUES($1,'direct_prompt_injection','interact','2026-09-18T00:01:00Z','2026-09-18T00:01:00Z')`,
      [user.id]
    );
    await pool.query(
      `INSERT INTO workshop_platform.time_tracking
         (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
       VALUES($1,'direct_prompt_injection','2026-09-18T00:00:00Z','2026-09-18T00:05:00Z',300)`,
      [user.id]
    );
    await pool.query(`INSERT INTO workshop_platform.catalog_field_defaults(entity_kind,workshop_key,objective_id,field_name,provenance_state,observed_document) VALUES('exercise','sensitive_info_disclosure','','challenge_description','legacy_unknown',jsonb_build_object('present',true,'value',$1::text)),('objective','mcp_workshop','mcp_supply_chain','solution_content','legacy_unknown',jsonb_build_object('present',true,'value',$2::jsonb)),('objective','mcp_workshop','mcp_supply_chain','hint_content','legacy_unknown',jsonb_build_object('present',true,'value',$3::jsonb)),('objective','direct_prompt_injection','jailbreak','hint_content','legacy_unknown',jsonb_build_object('present',true,'value','{}'::jsonb))`, ['Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.', oldSolution, oldHint]);
    const priorRunId = randomUUID();
    const priorOwner = JSON.stringify(['identity-tail-retained', priorRunId]);
    await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [priorOwner]);
    await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')", [priorRunId, priorOwner]);
    await pool.query(`INSERT INTO graph_runtime.events
      (run_id,owner_key,sequence,node,event_type,metadata)
      VALUES($1,$2,1,'judge_validate','decision',$3::jsonb)`,
    [priorRunId, priorOwner, JSON.stringify({ evidenceSummary: 'retained_before_0067', verdict: 'fail' })]);
    return priorRunId;
  } finally {
    disposeStage(baseline);
  }
}

async function seedTenantAdministrationPredecessor(pool) {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 10);
  const principalId = randomUUID(), tenantId = randomUUID(), siblingTenantId = randomUUID();
  const expiresAt = new Date(Date.now() + 3600000).toISOString();
  const principal = (await pool.query(`INSERT INTO secureshop_auth.principals
    (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
    RETURNING principal_id,owner_id,shop_user_id,role`, [principalId, `tenant_${suffix}`,
    `tenant_${suffix}@example.invalid`, '$2b$04$' + 'C'.repeat(53)])).rows[0];
  await pool.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2),($3,$4)`,
    [tenantId, `tenant-${suffix}`, siblingTenantId, `sibling-${suffix}`]);
  await pool.query(`INSERT INTO secureshop_auth.tenant_memberships
    (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin'),($4,$2,$3,'merchant')`,
    [tenantId, principalId, principal.shop_user_id, siblingTenantId]);
  const authSession = (await pool.query(`INSERT INTO secureshop_auth.sessions
    (principal_id,token_hash,credential_version,authority_version,expires_at)
    VALUES($1,$2,1,1,$3) RETURNING session_id`,
  [principalId, createHash('sha256').update(randomUUID()).digest('hex'), expiresAt])).rows[0];
  const oldExecution = (await pool.query(`INSERT INTO secureshop_auth.execution_sessions
    (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
    VALUES($1,$2,$3,1,$4) RETURNING session_id`,
  [authSession.session_id, tenantId, principalId, expiresAt])).rows[0];
  await pool.query(`UPDATE secureshop_auth.tenant_memberships SET role='customer',membership_version=2
    WHERE tenant_id=$1 AND principal_id=$2`, [tenantId, principalId]);
  await pool.query(`UPDATE secureshop_auth.tenant_memberships SET role='admin',membership_version=2
    WHERE tenant_id=$1 AND principal_id=$2`, [siblingTenantId, principalId]);
  const memberships = (await pool.query(`SELECT tenant_id,principal_id,shop_user_id,role,
    membership_version,is_active,created_at FROM secureshop_auth.tenant_memberships
    WHERE principal_id=$1 ORDER BY tenant_id`, [principalId])).rows;
  const tenants = (await pool.query(`SELECT tenant_id,owner_id,slug,seed_merchant_id,is_active,created_at
    FROM secureshop_auth.tenants WHERE tenant_id=ANY($1::uuid[]) ORDER BY tenant_id`,
  [[tenantId, siblingTenantId]])).rows;
  return {suffix,principal,principalId,tenantId,siblingTenantId,expiresAt,authSession,oldExecution,memberships,tenants};
}

async function assertTenantAdministrationUpgrade(runtime, migration, fixture, noOp) {
  const {principal,principalId,tenantId,siblingTenantId,expiresAt,authSession,oldExecution} = fixture;
  const privilege = (await runtime.query(`SELECT
    has_table_privilege(current_user,'secureshop_auth.session_membership_snapshots','SELECT') AS snapshot_read,
    has_table_privilege(current_user,'secureshop_auth.session_membership_snapshots','INSERT') AS snapshot_insert,
    has_table_privilege(current_user,'secureshop_auth.session_membership_snapshots','UPDATE') AS snapshot_update,
    has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','SELECT') AS operation_read,
    has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','INSERT') AS operation_insert,
    has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','UPDATE') AS operation_update`)).rows[0];
  assert.deepEqual(privilege, {snapshot_read:true,snapshot_insert:false,snapshot_update:false,
    operation_read:true,operation_insert:true,operation_update:false});
  assert.deepEqual((await migration.query(`SELECT tenant_id,membership_version
    FROM secureshop_auth.session_membership_snapshots WHERE session_id=$1 ORDER BY tenant_id`,
  [authSession.session_id])).rows, [
    {tenant_id:[tenantId,siblingTenantId].sort()[0],membership_version:
      [tenantId,siblingTenantId].sort()[0]===tenantId?'1':'2'},
    {tenant_id:[tenantId,siblingTenantId].sort()[1],membership_version:
      [tenantId,siblingTenantId].sort()[1]===tenantId?'1':'2'},
  ]);
  assert.deepEqual((await migration.query(`SELECT tenant_id,principal_id,shop_user_id,role,
    membership_version,is_active,created_at FROM secureshop_auth.tenant_memberships
    WHERE principal_id=$1 ORDER BY tenant_id`, [principalId])).rows, fixture.memberships);
  assert.deepEqual((await migration.query(`SELECT tenant_id,owner_id,slug,seed_merchant_id,is_active,created_at
    FROM secureshop_auth.tenants WHERE tenant_id=ANY($1::uuid[]) ORDER BY tenant_id`,
  [[tenantId,siblingTenantId]])).rows, fixture.tenants);
  assert.equal((await migration.query(`SELECT role FROM secureshop_auth.principals
    WHERE principal_id=$1`, [principalId])).rows[0].role, principal.role);
  await runtime.query(`UPDATE secureshop_auth.sessions SET revoked_at=clock_timestamp()
    WHERE session_id=$1`, [authSession.session_id]);
  const renewedAuth = (await runtime.query(`INSERT INTO secureshop_auth.sessions
    (principal_id,token_hash,credential_version,authority_version,expires_at,renewed_from_session_id)
    VALUES($1,$2,1,1,$3,$4) RETURNING session_id`,
  [principalId,createHash('sha256').update(randomUUID()).digest('hex'),expiresAt,
    authSession.session_id])).rows[0];
  assert.deepEqual((await runtime.query(`SELECT tenant_id,membership_version
    FROM secureshop_auth.session_membership_snapshots WHERE session_id=$1 ORDER BY tenant_id`,
  [renewedAuth.session_id])).rows.map(row=>[row.tenant_id,row.membership_version]),
  [[tenantId,'1'],[siblingTenantId,'2']].sort(([a],[b])=>a.localeCompare(b)));
  await assert.rejects(migration.query(`UPDATE secureshop_auth.sessions
    SET renewed_from_session_id=NULL WHERE session_id=$1`, [renewedAuth.session_id]),
  error=>error.code==='55000');
  const newAuth = (await runtime.query(`INSERT INTO secureshop_auth.sessions
    (principal_id,token_hash,credential_version,authority_version,expires_at)
    VALUES($1,$2,1,1,$3) RETURNING session_id`,
  [principalId, createHash('sha256').update(randomUUID()).digest('hex'), expiresAt])).rows[0];
  assert.deepEqual((await runtime.query(`SELECT tenant_id,membership_version
    FROM secureshop_auth.session_membership_snapshots WHERE session_id=$1 ORDER BY tenant_id`,
  [newAuth.session_id])).rows.map(row => [row.tenant_id,row.membership_version]),
  [[tenantId,'2'],[siblingTenantId,'2']].sort(([a],[b])=>a.localeCompare(b)));
  await assert.rejects(runtime.query(`INSERT INTO secureshop_auth.execution_sessions
    (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
    VALUES($1,$2,$3,2,$4)`, [renewedAuth.session_id,tenantId,principalId,expiresAt]),
  error => error.code === '28000');
  const siblingExecution = (await runtime.query(`INSERT INTO secureshop_auth.execution_sessions
    (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
    VALUES($1,$2,$3,2,$4) RETURNING session_id`,
  [renewedAuth.session_id,siblingTenantId,principalId,expiresAt])).rows[0];
  const currentExecution = (await runtime.query(`INSERT INTO secureshop_auth.execution_sessions
    (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
    VALUES($1,$2,$3,2,$4) RETURNING session_id`,
  [newAuth.session_id,tenantId,principalId,expiresAt])).rows[0];
  assert.equal((await migration.query(`SELECT count(*)::integer n FROM secureshop_auth.execution_sessions
    WHERE session_id=ANY($1::integer[])`, [[oldExecution.session_id,siblingExecution.session_id,currentExecution.session_id]])).rows[0].n, 3);
  const platformUser = (await migration.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`, [`tenant_platform_${fixture.suffix}`,
    `tenant_platform_${fixture.suffix}@example.invalid`, '$2b$04$' + 'D'.repeat(53)])).rows[0];
  const platformSession = (await migration.query(`INSERT INTO identity.user_sessions
    (user_id,session_token_hash,expires_at) VALUES($1,$2,$3) RETURNING id`,
  [platformUser.id,createHash('sha256').update(randomUUID()).digest('hex'),expiresAt])).rows[0];
  const launchId=randomUUID(),scenarioId=randomUUID(),operationId=randomUUID();
  await migration.query(`INSERT INTO identity.secureshop_launches
    (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
     handle_hash,scenario_id,expires_at) VALUES($1,$2,$2,$3,$4,$5,$6)`,
  [launchId,platformSession.id,platformUser.id,createHash('sha256').update(launchId).digest(),scenarioId,expiresAt]);
  await runtime.query(`INSERT INTO secureshop_auth.tenant_admin_operations
    (launch_id,scenario_id,generation,owner_id,execution_session_id,operation_id,tenant_id,
     actor_id,actor_session_id,target_id,request_sha256,result_json)
    VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$7,$9,$10)`,
  [launchId,scenarioId,fixture.tenants.find(row=>row.tenant_id===tenantId).owner_id,
    currentExecution.session_id,operationId,tenantId,principal.shop_user_id,randomUUID(),
    createHash('sha256').update('tenant-admin-'+operationId).digest(),JSON.stringify({status:'complete'})]);
  const operation = (await runtime.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
    WHERE launch_id=$1 AND generation=1 AND operation_id=$2`, [launchId,operationId])).rows[0];
  assert.ok(operation);
  await assert.rejects(runtime.query(`UPDATE secureshop_auth.tenant_admin_operations
    SET result_json='{}'::jsonb WHERE launch_id=$1`, [launchId]), error=>error.code==='42501');
  await assert.rejects(migration.query(`DELETE FROM secureshop_auth.tenant_admin_operations
    WHERE launch_id=$1`, [launchId]), error=>error.code==='55000');
  await assert.rejects(runtime.query(`INSERT INTO secureshop_auth.session_membership_snapshots
    (session_id,tenant_id,membership_version) VALUES($1,$2,2)`,
  [newAuth.session_id,tenantId]), error=>error.code==='42501');
  await assert.rejects(migration.query(`UPDATE secureshop_auth.session_membership_snapshots
    SET membership_version=3 WHERE session_id=$1 AND tenant_id=$2`,
  [newAuth.session_id,tenantId]), error=>error.code==='55000');
  await migration.query(`UPDATE secureshop_auth.tenant_memberships SET role='customer',is_active=false,
    banned_at=clock_timestamp(),ban_reason='controlled tenant-only ban',membership_version=3
    WHERE tenant_id=$1 AND principal_id=$2`, [tenantId,principalId]);
  const sibling = (await migration.query(`SELECT role,membership_version,is_active,banned_at,ban_reason
    FROM secureshop_auth.tenant_memberships WHERE tenant_id=$1 AND principal_id=$2`,
  [siblingTenantId,principalId])).rows[0];
  assert.deepEqual(sibling,{role:'admin',membership_version:'2',is_active:true,banned_at:null,ban_reason:null});
  assert.equal((await migration.query(`SELECT role FROM secureshop_auth.principals
    WHERE principal_id=$1`, [principalId])).rows[0].role, principal.role);
  await assert.rejects(runtime.query(`INSERT INTO secureshop_auth.execution_sessions
    (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
    VALUES($1,$2,$3,3,$4)`, [newAuth.session_id,tenantId,principalId,expiresAt]),
  error=>error.code==='55000'||error.code==='28000');
  const beforeReplay = {
    snapshots:(await migration.query(`SELECT * FROM secureshop_auth.session_membership_snapshots
      WHERE session_id=ANY($1::integer[]) ORDER BY session_id,tenant_id`,
    [[authSession.session_id,renewedAuth.session_id,newAuth.session_id]])).rows,
    operation:(await migration.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
      WHERE launch_id=$1`, [launchId])).rows,
    memberships:(await migration.query(`SELECT * FROM secureshop_auth.tenant_memberships
      WHERE principal_id=$1 ORDER BY tenant_id`, [principalId])).rows,
  };
  assert.deepEqual(await noOp(), []);
  assert.deepEqual({
    snapshots:(await migration.query(`SELECT * FROM secureshop_auth.session_membership_snapshots
      WHERE session_id=ANY($1::integer[]) ORDER BY session_id,tenant_id`,
    [[authSession.session_id,renewedAuth.session_id,newAuth.session_id]])).rows,
    operation:(await migration.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
      WHERE launch_id=$1`, [launchId])).rows,
    memberships:(await migration.query(`SELECT * FROM secureshop_auth.tenant_memberships
      WHERE principal_id=$1 ORDER BY tenant_id`, [principalId])).rows,
  }, beforeReplay);
  return {
    qualification:{backfillPreservedStaleVersion:true,renewalPreservedOriginalSnapshots:true,
      freshLoginCapturedCurrentSnapshots:true,siblingTenantPreserved:true,newSessionCaptured:true,
      staleExecutionDenied:true,operationImmutable:true,replayNoOp:true},
    kindFixture:{launchId,scenarioId,ownerId:operation.owner_id,
      executionSessionId:currentExecution.session_id,actorId:operation.actor_id,
      targetId:operation.target_id,operation}
  };
}

async function assertAdminOperationKindPrivileges(runtime, migration) {
  const privileges = (await runtime.query(`SELECT
    has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','SELECT') AS read,
    has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','INSERT') AS append,
    has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','UPDATE') AS rewrite,
    has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','DELETE') AS remove,
    has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','TRUNCATE') AS truncate`)).rows[0];
  assert.deepEqual(privileges,{read:true,append:true,rewrite:false,remove:false,truncate:false});
  assert.equal((await migration.query(`SELECT count(*)::integer n
    FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
    WHERE c.oid='secureshop_auth.admin_operation_kinds'::regclass AND a.grantee=0`)).rows[0].n,0);
}

async function assertAdminOperationKinds(runtime, migration, fixture, noOp) {
  await assertAdminOperationKindPrivileges(runtime,migration);
  const keyColumns='launch_id,generation,operation_id,scenario_id,owner_id,execution_session_id,operation_kind,actor_id,target_id,request_sha256';
  const exactClaim=async(operationId,kind,requestSha256,conflict='')=>runtime.query(`INSERT INTO secureshop_auth.admin_operation_kinds
    (${keyColumns}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ${conflict} RETURNING ${keyColumns}`,
  [fixture.launchId,fixture.operation.generation,operationId,fixture.scenarioId,fixture.ownerId,
    fixture.executionSessionId,kind,fixture.actorId,fixture.targetId,requestSha256]);
  assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id])).rows[0],fixture.operation);
  assert.equal((await migration.query(`SELECT count(*)::integer n FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1`,[fixture.launchId])).rows[0].n,0,'0149 must not invent claims for prior journals');

  const adopted=(await exactClaim(fixture.operation.operation_id,'registered',fixture.operation.request_sha256)).rows[0];
  assert.deepEqual(adopted,{
    launch_id:fixture.launchId,generation:fixture.operation.generation,
    operation_id:fixture.operation.operation_id,scenario_id:fixture.scenarioId,
    owner_id:fixture.ownerId,execution_session_id:fixture.executionSessionId,
    operation_kind:'registered',actor_id:fixture.actorId,target_id:fixture.targetId,
    request_sha256:fixture.operation.request_sha256
  });
  await assert.rejects(()=>exactClaim(fixture.operation.operation_id,'teaching',fixture.operation.request_sha256),
    error=>error.code==='23505');
  await assert.rejects(runtime.query(`UPDATE secureshop_auth.admin_operation_kinds
    SET operation_kind='teaching' WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id]),error=>error.code==='42501');
  await assert.rejects(runtime.query(`DELETE FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id]),error=>error.code==='42501');
  await assert.rejects(migration.query(`UPDATE secureshop_auth.admin_operation_kinds
    SET operation_kind='teaching' WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id]),error=>error.code==='55000');
  await assert.rejects(migration.query(`DELETE FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id]),error=>error.code==='55000');

  const reservedOperationId=randomUUID();
  const requestSha256=createHash('sha256').update('opposing-kind-'+reservedOperationId).digest();
  const attempts=await Promise.all([
    exactClaim(reservedOperationId,'registered',requestSha256,'ON CONFLICT DO NOTHING'),
    exactClaim(reservedOperationId,'teaching',requestSha256,'ON CONFLICT DO NOTHING')
  ]);
  assert.equal(attempts.reduce((total,result)=>total+result.rowCount,0),1);
  const reserved=(await runtime.query(`SELECT ${keyColumns} FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,reservedOperationId])).rows;
  assert.equal(reserved.length,1);
  assert.ok(['registered','teaching'].includes(reserved[0].operation_kind));
  assert.equal((await runtime.query(`SELECT count(*)::integer n FROM secureshop_auth.tenant_admin_operations
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,reservedOperationId])).rows[0].n,0,
  'a reserved kind without an outcome receipt must remain distinguishable');
  const beforeReplay=(await migration.query(`SELECT * FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1 ORDER BY operation_id`,[fixture.launchId])).rows;
  assert.deepEqual(await noOp(),[]);
  assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.admin_operation_kinds
    WHERE launch_id=$1 ORDER BY operation_id`,[fixture.launchId])).rows,beforeReplay);
  assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
    WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
  [fixture.launchId,fixture.operation.generation,fixture.operation.operation_id])).rows[0],fixture.operation);
  return {priorJournalPreserved:true,noBulkBackfill:true,exactLegacyAdoption:true,
    opposingKindsSerialized:true,reservationWithoutReceiptPreserved:true,immutable:true,
    leastPrivilege:true,replayNoOp:true};
}
test('identity qualification staging is bounded and fail-closed without a database', async () => {
  assert.deepEqual(poolBudget({}, 'PG_MIGRATION_DATABASE_URL', MIGRATION_POOL_OPTIONS.purpose), {
    purpose: 'migration', max: 1, budget: 78
  });
  assert.deepEqual(poolBudget({}, 'PG_RUNTIME_DATABASE_URL', RUNTIME_POOL_OPTIONS.purpose), {
    purpose: 'control', max: 8, budget: 78
  });
  assert.deepEqual(poolBudget({ PG_POOL_BUDGET: '60' }, 'PG_MIGRATION_DATABASE_URL', MIGRATION_POOL_OPTIONS.purpose), { purpose: 'migration', max: 1, budget: 60 });
  assert.throws(
    () => poolBudget({}, 'PG_RUNTIME_DATABASE_URL', 'identity-live-tail-runtime'),
    /Unknown PostgreSQL pool purpose/
  );
  const temp = await fsp.mkdtemp(path.join(fs.realpathSync(os.tmpdir()), 'dvaia-identity-fixture-'));
  try {
    await fsp.writeFile(path.join(temp, '0001_valid.sql'), 'SELECT 1;');
    await fsp.writeFile(path.join(temp, 'bad.sql'), 'SELECT 2;');
    const staged = await stage(temp);
    assert.deepEqual(await virtualFs.readdir(staged), ['0001_valid.sql']);
    const failure = appendFailure(staged);
    assert.match(await virtualFs.readFile(failure, 'utf8'), /CREATE TABLE identity\.__qualification_failure[^\n]*\nSELECT 1 \/ 0;/);
    assert.throws(() => appendFailure(staged));
    removeFailure(failure);
    assert.deepEqual((await readMigrations(staged)).map(row => row.name), ['0001_valid.sql']);
    disposeStage(staged);
    assert.equal(virtualDirectories.has(staged), false);
  } finally {
    await fsp.rm(temp, {
      recursive: true,
      force: true
    });
  }
  const baseline = await stageThrough(IDENTITY, '0058_finflow_durable_log_overlay_tip.sql');
  try {
    const names = (await virtualFs.readdir(baseline)).sort();
    assert.equal(names.at(-1), '0058_finflow_durable_log_overlay_tip.sql');
    assert.equal(names.some(name => TAIL.includes(name)), false);
    const actual = await readMigrations(IDENTITY);
    const staged = await readMigrations(baseline);
    assert.deepEqual(staged, actual.filter(row => row.name <= '0058_finflow_durable_log_overlay_tip.sql'));
    for (const row of staged) {
      assert.equal(row.sql, fs.readFileSync(path.join(IDENTITY, row.name), 'utf8'));
      assert.equal(row.checksum, createHash('sha256').update(row.sql).digest('hex'));
    }
  } finally {
    disposeStage(baseline);
  }
  const complete = await stage(IDENTITY);
  const historical = await stageThrough(IDENTITY, '0067_graph_observability_metadata.sql');
  try {
    const canonical = await readMigrations(IDENTITY);
    assert.deepEqual(await readMigrations(complete), canonical);
    const historicalRows = await readMigrations(historical);
    assert.deepEqual(historicalRows, canonical.filter(row => row.name <= '0067_graph_observability_metadata.sql'));
    assert.deepEqual(historicalRows.filter(row => row.name > '0058_finflow_durable_log_overlay_tip.sql').map(row => row.name), TAIL);
    assert.deepEqual([...historicalRows, ...canonical.filter(row => row.name > '0067_graph_observability_metadata.sql')], canonical);
  } finally { disposeStage(historical); disposeStage(complete); }
  const prior = process.env.PG_TEST_DISPOSABLE;
  process.env.PG_TEST_DISPOSABLE = 'yes';
  try {
    assert.throws(() => qualifiedUrl('postgresql://u@example.test/dvaia_test_bad', 'dvaia_identity_migration'), /127\.0\.0\.1/);
    assert.throws(() => qualifiedUrl('postgresql://dvaia_identity_migration@127.0.0.1:5432/application', 'dvaia_identity_migration'), /dvaia_test_/);
  } finally {
    if (prior === undefined) delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE = prior;
  }
});

// Storage qualification only: synthetic disposable rows never earn objective credit
// and never invoke a provider or the application's Judge continuation service.
async function assertAuditCheckpointStorage(runtime, migration, noOp) {
  const table = 'workshop_platform.audit_judge_stage_checkpoints';
  const marker = 'checkpoint_' + randomUUID().replaceAll('-', '').slice(0, 12);
  const evaluations = [randomUUID(), randomUUID()];
  const runId = randomUUID(), hash = 'a'.repeat(64);
  const before = await snapshot(migration);
  const exercise = marker;
  let users = [];
  try {
    const privileges = (await runtime.query(`SELECT
      has_table_privilege(current_user,$1,'SELECT') AS read,
      has_table_privilege(current_user,$1,'INSERT') AS append,
      has_table_privilege(current_user,$1,'DELETE') AS retire,
      has_table_privilege(current_user,$1,'UPDATE') AS rewrite,
      has_function_privilege(current_user,'workshop_platform.remove_audit_checkpoints_with_packet()','EXECUTE') AS execute`, [table])).rows[0];
    assert.deepEqual(privileges, {read:true, append:true, retire:true, rewrite:false, execute:false});
    assert.equal((await migration.query(`SELECT count(*)::integer n
      FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
      WHERE c.oid=$1::regclass AND a.grantee=0`, [table])).rows[0].n, 0);
    await migration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal)
      VALUES($1,$1,'Controlled checkpoint storage','Disposable schema qualification','training','advanced','/qualification',9999)`, [exercise]);
    await migration.query(`INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,category,ordinal)
      VALUES($1,'audit_stage_fixture','Controlled checkpoint storage','training',1)`, [exercise]);
    for (const suffix of ['owner','sibling']) {
      const row = (await migration.query(`INSERT INTO identity.users(username,email,password)
        VALUES($1,$2,$3) RETURNING id`, [marker+'_'+suffix,marker+'_'+suffix+'@example.invalid','$2b$04$'+'A'.repeat(53)])).rows[0];
      users.push(row.id);
    }
    for (let i=0;i<users.length;i++) {
      await runtime.query(`INSERT INTO workshop_platform.objective_judgments
        (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation)
        VALUES($1,$2,$3,'audit_stage_fixture','SecureShop','audit','controlled-storage-v1',$4,$5,0)`, [users[i],evaluations[i],exercise,hash,runId]);
      await runtime.query(`INSERT INTO workshop_platform.grade_packets(user_id,evaluation_id,packet,judge_version,mode_stamp)
        VALUES($1,$2,'{}','controlled-storage-v1','vuln')`, [users[i],evaluations[i]]);
    }
    const columns = ['user_id','evaluation_id','stage','version','run_id','evidence_digest','packet_sha256','judge_version','comparison_version','policy_digest','canonical_input_sha256','actual_request_sha256','source_checkpoint_sha256','provider','model','raw_response','response_sha256','checkpoint_sha256'];
    const values = (index,stage='source') => [users[index],evaluations[index],stage,'audit-stage-checkpoint-v1',runId,hash,hash,'controlled-storage-v1','source-only-obligation-verified-v6',hash,hash,hash,stage==='effect'?hash:null,'controlled','storage-only','{"observed":true}',hash,hash];
    const insert = data => runtime.query(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')})`,data);
    await insert(values(0));await insert(values(0,'effect'));await insert(values(1));
    await assert.rejects(()=>insert(values(0)),error=>error.code==='23505');
    await assert.rejects(()=>runtime.query(`UPDATE ${table} SET raw_response='changed' WHERE user_id=$1`,[users[0]]),error=>error.code==='42501');
    for(const [column,value,code] of [['stage','judge','23514'],['version','other','23514'],['evidence_digest','bad','23514'],['comparison_version','v5','23514'],['raw_response','','23514'],['raw_response','x'.repeat(16385),'23514'],['source_checkpoint_sha256',hash,'23514']]) {
      const data=values(0);data[1]=randomUUID();
      await runtime.query(`INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation)
        VALUES($1,$2,$3,'audit_stage_fixture','SecureShop','audit','controlled-storage-v1',$4,0)`,[users[0],data[1],exercise,hash]);
      await runtime.query(`INSERT INTO workshop_platform.grade_packets(user_id,evaluation_id,packet,judge_version,mode_stamp) VALUES($1,$2,'{}','controlled-storage-v1','vuln')`,[users[0],data[1]]);
      data[columns.indexOf(column)]=value;await assert.rejects(()=>insert(data),error=>error.code===code);
    }
    const wrongOwner=values(0);wrongOwner[0]=users[1];await assert.rejects(()=>insert(wrongOwner),error=>error.code==='23503');
    const missingSource=values(0,'effect');missingSource[1]=evaluations[1];missingSource[0]=users[1];missingSource[12]=null;
    await assert.rejects(()=>insert(missingSource),error=>error.code==='23514');
    const rows=async()=> (await runtime.query(`SELECT * FROM ${table} WHERE user_id=ANY($1::integer[]) ORDER BY user_id,evaluation_id,stage`,[users])).rows;
    const saved=await rows();assert.equal(saved.length,3);assert.deepEqual(await noOp(),[]);assert.deepEqual(await rows(),saved);
    const sibling=saved.filter(row=>row.user_id===users[1]);
    await runtime.query(`UPDATE workshop_platform.grade_packets SET packet=NULL WHERE user_id=$1 AND evaluation_id=$2`,[users[0],evaluations[0]]);
    assert.deepEqual(await rows(),sibling);
    await runtime.query(`DELETE FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2`,[users[1],evaluations[1]]);
    assert.deepEqual(await rows(),[]);
    return {scope:'audit_checkpoint_storage_only',constraints:true,appendOnly:true,packetPruneRetires:true,parentDeleteCascades:true,siblingPreserved:true,noOpPreserves:true,modelCalls:0,creditWrites:0};
  } finally {
    if(users.length){await migration.query('DELETE FROM workshop_platform.grade_packets WHERE user_id=ANY($1::integer[])',[users]);await migration.query('DELETE FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::integer[])',[users]);await migration.query('DELETE FROM identity.users WHERE id=ANY($1::integer[])',[users]);}
    await migration.query('DELETE FROM workshop_platform.objectives WHERE workshop_key=$1',[exercise]);
    await migration.query('DELETE FROM workshop_platform.exercises WHERE workshop_key=$1',[exercise]);
    assert.deepEqual(await snapshot(migration),before);
  }
}

test('identity live tail qualifies exact 0058-to-current tail transactionally', {
  timeout: 120000
}, async t => {
  const urls = pair('DVAIA_IDENTITY_QUALIFICATION');
  if (!urls) return t.skip('DVAIA_IDENTITY_QUALIFICATION_MIGRATION_URL/RUNTIME_URL are not set; no disposable database action performed');
  const migration = createPool({
    PG_MIGRATION_DATABASE_URL: urls.migration
  }, 'PG_MIGRATION_DATABASE_URL', MIGRATION_POOL_OPTIONS);
  const runtime = createPool({
    PG_RUNTIME_DATABASE_URL: urls.runtime
  }, 'PG_RUNTIME_DATABASE_URL', RUNTIME_POOL_OPTIONS);
  const pool = migration;
  await assertRolePair(runtime, migration);
  const successor = await stage(IDENTITY);
  const historical = await stageThrough(IDENTITY, '0067_graph_observability_metadata.sql');
  const tenantAdminPredecessor = await stageThrough(IDENTITY, '0147_secureshop_scene_target_cleanup.sql');
  const adminKindPredecessor = await stageThrough(IDENTITY, TENANT_ADMIN_MIGRATION);
  let failure = appendFailure(successor);
  let fixture;
  try {
    const files = await readMigrations(IDENTITY);
    assert.ok(files.length > 0);
    const policySql = fs.readFileSync(path.join(IDENTITY, '0059_dpi_policy_trace_metadata.sql'), 'utf8');
    assert.match(policySql, /events_policy_snapshot_check/);
    assert.match(policySql, /policyProfile.*policyVersion.*policyDigest/s);
    assert.match(policySql, /\^\[a-f0-9\]\{64\}\$/);
    const observabilitySql = fs.readFileSync(path.join(IDENTITY, '0067_graph_observability_metadata.sql'), 'utf8');
    assert.match(observabilitySql, /events_comparison_stage_check/);
    assert.match(observabilitySql, /events_reviewer_profile_check/);
    const byName = new Map(files.map(row => [row.name, row]));
    const exact = TAIL.map(name => byName.get(name));
    assert.ok(exact.every(Boolean));
    assert.deepEqual(exact.map(row => row.name), TAIL);
    const priorRunId = await bootstrapPopulated(pool);
    const beforeLedger = await ledger(pool);
    assert.equal(beforeLedger.at(-1)?.name, '0058_finflow_durable_log_overlay_tip.sql');
    fixture = await seedCustomRows(pool);
    assert.ok(fixture.saved.some(row => row[0] === 'exercise'), 'populated FinFlow fixture is required');
    assert.ok(fixture.saved.some(row => row[0] === 'objective'), 'populated MCP fixture is required');
    assert.ok(fixture.saved.some(row => row[0] === 'provenance'), 'custom provenance fixture is required');
    const beforeRevision = Number((await pool.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1'
    )).rows[0].revision);
    const instructorDpiBefore = (await pool.query(
      "SELECT label,solution_content,updated_by FROM workshop_platform.objectives WHERE workshop_key='direct_prompt_injection' AND objective_id='jailbreak'"
    )).rows[0];
    const beforeRows = await snapshot(pool);
    await assert.rejects(() => migrate(pool, successor), /division by zero/);
    assert.deepEqual(await ledger(pool), beforeLedger);
    assert.deepEqual(await snapshot(pool), beforeRows);
    assert.equal((await pool.query(
      "SELECT to_regclass('identity.__qualification_failure') AS relation"
    )).rows[0].relation, null);
    assert.equal((await pool.query(
      "SELECT to_regclass('identity.ipi_email_artifacts') AS relation"
    )).rows[0].relation, null);
    removeFailure(failure);
    failure = null;
    const applied = await migrate(pool, historical);
    assert.deepEqual(applied, TAIL);
    const afterLedger = await ledger(pool);
    for (const row of exact) assert.equal(afterLedger.find(item => item.name === row.name)?.checksum, row.checksum);
    assert.deepEqual((await pool.query(
      'SELECT node,event_type,metadata FROM graph_runtime.events WHERE run_id=$1 ORDER BY sequence',
      [priorRunId]
    )).rows, [{
      node: 'judge_validate',
      event_type: 'decision',
      metadata: { evidenceSummary: 'retained_before_0067', verdict: 'fail' }
    }]);
    const customExercise = (await pool.query("SELECT challenge_description,is_visible FROM workshop_platform.exercises WHERE workshop_key='sensitive_info_disclosure'")).rows[0];
    assert.equal(customExercise.challenge_description, 'Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources.');
    assert.equal(customExercise.is_visible, false);
    const customObjective = (await pool.query("SELECT solution_content,hint_content,updated_by FROM workshop_platform.objectives WHERE workshop_key='mcp_workshop' AND objective_id='mcp_supply_chain'")).rows[0];
    assert.notDeepEqual(customObjective.solution_content, fixture.saved.find(row => row[0] === 'objective')[1].solution_content);
    assert.equal(customObjective.updated_by, fixture.saved.find(row => row[0] === 'objective')[1].updated_by);
    const customProvenance = (await pool.query("SELECT provenance_state FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective' AND workshop_key='direct_prompt_injection' AND objective_id='jailbreak' AND field_name='hint_content'")).rows[0];
    assert.equal(customProvenance.provenance_state, 'custom');
    const managedDpi = (await pool.query(
      "SELECT label,updated_by FROM workshop_platform.objectives WHERE workshop_key='direct_prompt_injection' AND objective_id='interact'"
    )).rows[0];
    assert.deepEqual(managedDpi, {
      label: 'Baseline: ask the AWS-only assistant a normal question',
      updated_by: null
    });
    const instructorDpiAfter = (await pool.query(
      "SELECT label,solution_content,updated_by FROM workshop_platform.objectives WHERE workshop_key='direct_prompt_injection' AND objective_id='jailbreak'"
    )).rows[0];
    assert.deepEqual(instructorDpiAfter, instructorDpiBefore);
    const afterRevision = Number((await pool.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1'
    )).rows[0].revision);
    assert.equal(afterRevision, beforeRevision + 3);
    assert.equal((await snapshot(pool))['identity.ipi_email_artifacts'].exists, true);
    await assertRuntimeBoundary(runtime);
    await assertPolicyContract(runtime, pool);
    await assertIpiArtifactContract(runtime, pool);
    const afterRows = await snapshot(pool);
    assert.notDeepEqual(afterRows, beforeRows);
    assert.deepEqual(learnerProjection(afterRows), learnerProjection(beforeRows));
    assert.deepEqual(await migrate(pool, historical), []);
    assert.deepEqual(await snapshot(pool), afterRows);
    const predecessorRemainder = files.filter(row => row.name > '0067_graph_observability_metadata.sql'
      && row.name <= '0147_secureshop_scene_target_cleanup.sql');
    const appliedPredecessor = await migrate(pool, tenantAdminPredecessor);
    assert.deepEqual(appliedPredecessor, predecessorRemainder.map(row => row.name));
    const tenantAdminFixture = await seedTenantAdministrationPredecessor(pool);
    const appliedTenantAdmin = await migrate(pool, adminKindPredecessor);
    assert.deepEqual(appliedTenantAdmin, [TENANT_ADMIN_MIGRATION]);
    const suffixRows = await snapshot(pool);
    assert.deepEqual(learnerProjection(suffixRows), learnerProjection(afterRows));
    assert.deepEqual(suffixRows['graph_runtime.events'], afterRows['graph_runtime.events']);
    assert.deepEqual((await pool.query(
      "SELECT label,solution_content,updated_by FROM workshop_platform.objectives WHERE workshop_key='direct_prompt_injection' AND objective_id='jailbreak'"
    )).rows[0], instructorDpiBefore);
    assert.equal((await pool.query("SELECT is_visible FROM workshop_platform.exercises WHERE workshop_key='sensitive_info_disclosure'")).rows[0].is_visible, false);
    assert.equal((await pool.query("SELECT provenance_state FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective' AND workshop_key='direct_prompt_injection' AND objective_id='jailbreak' AND field_name='hint_content'")).rows[0].provenance_state, 'custom');
    const tenantAdminResult = await assertTenantAdministrationUpgrade(runtime,pool,
      tenantAdminFixture,()=>migrate(pool,adminKindPredecessor));
    const priorOperation = (await pool.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
      WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
    [tenantAdminResult.kindFixture.launchId,tenantAdminResult.kindFixture.operation.generation,
      tenantAdminResult.kindFixture.operation.operation_id])).rows[0];
    const appliedRemainder = await migrate(pool, successor);
    assert.deepEqual(appliedRemainder, [ADMIN_OPERATION_KIND_MIGRATION]);
    assert.deepEqual(await ledger(pool), files.map(({name,checksum}) => ({name,checksum})));
    assert.deepEqual((await pool.query(`SELECT * FROM secureshop_auth.tenant_admin_operations
      WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,
    [tenantAdminResult.kindFixture.launchId,tenantAdminResult.kindFixture.operation.generation,
      tenantAdminResult.kindFixture.operation.operation_id])).rows[0],priorOperation);
    const adminOperationKinds=await assertAdminOperationKinds(runtime,pool,
      tenantAdminResult.kindFixture,()=>migrate(pool,successor));
    const auditCheckpointStorage=await assertAuditCheckpointStorage(runtime,pool,()=>migrate(pool,successor));
    const currentRows = await snapshot(pool);
    assert.deepEqual(await migrate(pool, successor), []);
    assert.deepEqual(await snapshot(pool), currentRows);
    t.diagnostic(JSON.stringify({
      scope: 'identity_live_tail_qualification',
      status: 'pass',
      applied: [...applied, ...appliedPredecessor, ...appliedTenantAdmin, ...appliedRemainder],
      historicalApplied: TAIL,
      auditCheckpointStorage,
      tenantAdministration:tenantAdminResult.qualification,
      adminOperationKinds,
      customPreservation: true,
      policyBoundary: true,
      rolePair: true
    }));
  } finally {
    if (failure) removeFailure(failure);
    await Promise.allSettled([runtime.end(), migration.end()]);
    disposeStage(historical);
    disposeStage(tenantAdminPredecessor);
    disposeStage(adminKindPredecessor);
    disposeStage(successor);
  }
});
test('identity live tail fresh exact ledger and replay', {
  timeout: 120000
}, async t => {
  const urls = pair('DVAIA_IDENTITY_FRESH');
  if (!urls) return t.skip('DVAIA_IDENTITY_FRESH_MIGRATION_URL/RUNTIME_URL are not set; no disposable database action performed');
  const migration = createPool({
    PG_MIGRATION_DATABASE_URL: urls.migration
  }, 'PG_MIGRATION_DATABASE_URL', MIGRATION_POOL_OPTIONS);
  const runtime = createPool({
    PG_RUNTIME_DATABASE_URL: urls.runtime
  }, 'PG_RUNTIME_DATABASE_URL', RUNTIME_POOL_OPTIONS);
  try {
    await assertRolePair(runtime, migration);
    const applied = await migrate(migration, IDENTITY);
    assert.ok(Array.isArray(applied));
    const files = await readMigrations(IDENTITY);
    assert.deepEqual(applied, files.map(row => row.name));
    assert.deepEqual(await ledger(migration), files.map(({name,checksum}) => ({name,checksum})));
    for (const name of TAIL) assert.ok(applied.includes(name));
    assert.ok(applied.includes(TENANT_ADMIN_MIGRATION));
    assert.ok(applied.includes(ADMIN_OPERATION_KIND_MIGRATION));
    assert.deepEqual((await migration.query(`SELECT
      (SELECT count(*)::integer FROM secureshop_auth.session_membership_snapshots) AS snapshots,
      (SELECT count(*)::integer FROM secureshop_auth.tenant_admin_operations) AS operations,
      (SELECT count(*)::integer FROM secureshop_auth.admin_operation_kinds) AS operation_kinds`)).rows[0],
    {snapshots:0,operations:0,operation_kinds:0});
    await assertAdminOperationKindPrivileges(runtime,migration);
    const auditCheckpointStorage=await assertAuditCheckpointStorage(runtime,migration,()=>migrate(migration,IDENTITY));
    assert.deepEqual(await migrate(migration, IDENTITY), []);
    t.diagnostic(JSON.stringify({
      scope: 'identity_live_tail_fresh',
      status: 'pass',
      foundationBootstrap: true,
      auditCheckpointStorage,
      appliedTail: applied.filter(name => name > '0058_finflow_durable_log_overlay_tip.sql')
    }));
  } finally {
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});
