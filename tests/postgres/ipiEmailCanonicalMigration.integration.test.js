'use strict';

// Isolated qualification for registered identity0065. The native branch
// accepts only three newly created, explicitly named local databases.
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const syncFs = require('node:fs');
const { Module, createRequire } = require('node:module');
const { Pool } = require('pg');

const sourceRoot = path.resolve(process.env.IPI_EMAIL_0065_SOURCE_ROOT
  || path.join(__dirname, '../..'));
const canonicalDirectory = path.join(sourceRoot, 'db/postgres/identity-migrations');
const candidateName = '0065_ipi_email_artifacts.sql';
const originalDraftPath = path.join(sourceRoot, 'docs/modernization/drafts', candidateName);
const originalDraftSha256 = '17d5be381dc1f050a0b278793ab42e3afc4b0abbaf439d30a56a44bd3c46e346';
const candidatePath = path.join(sourceRoot, 'docs/modernization/drafts/0065_ipi_email_artifacts_v2.sql');
const expectedCandidateSha256 = '9dc6820b56a261e648f2aa1d5eb7635bb61f3f91530f8251c93bdbe45a1fa30c';
assert.equal(sourceRoot, path.resolve(__dirname, '../..'), 'Only the canonical main source root is supported');
function migrationView(ceiling, failCandidate = false) {
  assert.ok([61,65].includes(ceiling), 'Closed identity migration view');
  const virtualFs = { ...fs,
    async readdir(directory, ...args) {
      const names = await fs.readdir(directory, ...args);
      return path.resolve(directory) === canonicalDirectory
        ? names.filter(name => !/^\d{4}_.*\.sql$/.test(name) || Number(name.slice(0,4)) <= ceiling) : names;
    },
    async readFile(filename, ...args) {
      const value = await fs.readFile(filename, ...args);
      if (!failCandidate || path.resolve(filename) !== path.join(canonicalDirectory,candidateName)) return value;
      const suffix = "\nDO $$ BEGIN RAISE EXCEPTION 'owned identity0065 rollback qualification'; END $$;\n";
      return typeof value === 'string' ? value + suffix : Buffer.concat([value,Buffer.from(suffix)]);
    },
  };
  const filename = path.join(sourceRoot,'db/postgres/migrate.js');
  const local = createRequire(filename), loaded = new Module(filename,module);
  loaded.filename = filename;
  loaded.require = name => ['node:fs/promises','fs/promises'].includes(name) ? virtualFs : local(name);
  loaded._compile(syncFs.readFileSync(filename,'utf8'),filename);
  return Object.freeze({ ...loaded.exports, directory:canonicalDirectory });
}
const bounded65 = migrationView(65);
const readMigrations = view => {
  if (typeof view === 'string') {
    assert.equal(view, canonicalDirectory, 'Only canonical identity migration directory is admitted');
    return bounded65.readMigrations(canonicalDirectory);
  }
  return view.readMigrations(canonicalDirectory);
};
const migrate = (poolValue, view) => view.migrate(poolValue,canonicalDirectory);
const { createEmailArtifactRepository } = require(path.join(
  sourceRoot, 'server/database/postgres/emailArtifactRepository'));

const databaseByKind = Object.freeze({
  FRESH: 'dvaia_test_ipi_email_0065_fresh',
  POPULATED: 'dvaia_test_ipi_email_0065_populated',
  ROLLBACK: 'dvaia_test_ipi_email_0065_rollback',
});
const urlVariables = Object.keys(databaseByKind).flatMap(kind => [
  `PG_IPI_EMAIL_0065_${kind}_MIGRATION_URL`,
  `PG_IPI_EMAIL_0065_${kind}_RUNTIME_URL`,
]);
const qualificationRequested = process.env.IPI_EMAIL_0065_ISOLATED === '1'
  || urlVariables.some(name => process.env[name]);
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.IPI_EMAIL_0065_ISOLATED === '1'
  && urlVariables.every(name => process.env[name]);
const passwordHash = `$2b$04$${'A'.repeat(53)}`;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function checkedUrl(kind, role) {
  const variable = `PG_IPI_EMAIL_0065_${kind}_${role}_URL`;
  const value = new URL(process.env[variable]);
  assert.equal(value.protocol, 'postgresql:', `${variable} must use PostgreSQL`);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname),
    `${variable} must be local`);
  assert.equal(value.password, '', `${variable} must not embed credentials`);
  assert.equal(value.search, '', `${variable} must not contain query options`);
  assert.equal(value.hash, '', `${variable} must not contain a fragment`);
  assert.ok(value.port !== '' && Number.isSafeInteger(Number(value.port))
    && Number(value.port) >= 1 && Number(value.port) <= 65535,
  `${variable} must use an explicit valid port`);
  assert.equal(value.pathname, `/${databaseByKind[kind]}`,
    `${variable} must name the owned disposable database`);
  assert.equal(decodeURIComponent(value.username), role === 'MIGRATION'
    ? 'dvaia_identity_migration' : 'dvaia_identity_runtime');
  return value;
}

function pool(url, suffix) {
  return new Pool({
    connectionString: url.href,
    max: 2,
    connectionTimeoutMillis: 5000,
    statement_timeout: 30000,
    lock_timeout: 5000,
    application_name: `dvaia-ipi-email-0065-${suffix}`,
  });
}

function checkedUrls() {
  const urls = {};
  for (const kind of Object.keys(databaseByKind)) {
    const migration = checkedUrl(kind, 'MIGRATION');
    const runtime = checkedUrl(kind, 'RUNTIME');
    assert.equal(runtime.hostname, migration.hostname);
    assert.equal(runtime.port, migration.port);
    assert.equal(runtime.pathname, migration.pathname);
    urls[kind] = { migration, runtime };
  }
  return urls;
}

function makePools(urls) {
  const output = {};
  for (const kind of Object.keys(databaseByKind)) {
    output[kind] = {
      migration: pool(urls[kind].migration, `${kind.toLowerCase()}-migration`),
      runtime: pool(urls[kind].runtime, `${kind.toLowerCase()}-runtime`),
    };
  }
  return output;
}

async function buildPrivateDirectories() {
  const configuredRoot = process.env.IPI_EMAIL_0065_RUNTIME_ROOT;
  assert.ok(configuredRoot, 'isolated qualification requires a private runtime root');
  const base = path.resolve(configuredRoot);
  assert.equal(path.isAbsolute(configuredRoot), true);
  const source = await fs.realpath(sourceRoot);
  const runtimeRoot = await fs.realpath(base);
  assert.equal(runtimeRoot === source || runtimeRoot.startsWith(`${source}${path.sep}`), false,
    'private runtime root must remain outside the canonical source');
  const rootStat = await fs.stat(runtimeRoot);
  assert.equal(rootStat.isDirectory(), true);
  assert.equal(rootStat.mode & 0o077, 0, 'private runtime root must not be group/world accessible');
  const baseline = migrationView(61), full = bounded65, failing = migrationView(65,true);
  const canonical = await readMigrations(canonicalDirectory);
  assert.equal(canonical.at(-1)?.name, candidateName);
  assert.equal(canonical.some(row => /^006[234]_/.test(row.name)), false,
    'retired 0062-0064 coordination numbers remain absent');
  const registered = canonical.filter(row => row.name === candidateName);
  assert.equal(registered.length, 1);
  assert.equal(registered[0].checksum, expectedCandidateSha256);
  const baselineMigrations = canonical.filter(row => row.name < candidateName);
  assert.equal(baselineMigrations.at(-1)?.name,
    '0061_mcp_supply_chain_curriculum_defaults.sql');
  const candidateSql = registered[0].sql;
  assert.equal(candidateSql, await fs.readFile(candidatePath, 'utf8'));
  return { baseline, full, failing, baselineMigrations, candidateSql };

}

async function ledger(poolValue) {
  return (await poolValue.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}

async function assertEmptyDatabase(poolValue, expectedDatabase) {
  const state = (await poolValue.query(`SELECT current_database() AS database,
    (SELECT count(*)::integer FROM pg_namespace
      WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_') AS private_schemas,
    (SELECT count(*)::integer FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')) AS public_relations`)).rows[0];
  assert.deepEqual(state, { database: expectedDatabase, private_schemas: 0, public_relations: 0 },
    `${expectedDatabase} must be empty before qualification`);
}

async function assertExactLedger(poolValue, directory) {
  const expected = (await readMigrations(directory)).map(({ name, checksum }) => ({ name, checksum }));
  assert.deepEqual(await ledger(poolValue), expected);
}

async function seedPreservedState(poolValue, label) {
  const owner = (await poolValue.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`,
  [`ipi-${label}-owner`, `ipi-${label}-owner@example.invalid`, passwordHash])).rows[0];
  const sibling = (await poolValue.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`,
  [`ipi-${label}-sibling`, `ipi-${label}-sibling@example.invalid`, passwordHash])).rows[0];
  for (const [user, suffix] of [[owner, 'a'], [sibling, 'b']]) {
    await poolValue.query(`INSERT INTO identity.user_sessions(
      user_id,session_token_hash,device_info,expires_at)
      VALUES($1,$2,$3::jsonb,clock_timestamp()+interval '1 hour')`,
    [user.id, sha256(`${label}-${suffix}`), JSON.stringify({ fixture: label, owner: suffix })]);
  }
  await poolValue.query(`INSERT INTO workshop_platform.exercises(
    workshop_key,challenge_key,challenge_name,challenge_description,ordinal)
    VALUES($1,$2,$3,$4,991)`,
  [`ipi_email_qualification_${label}`, `ipi_email_qualification_${label}`,
    `IPI email ${label}`, 'Preserved qualification catalog row']);
  await poolValue.query(`INSERT INTO workshop_platform.objectives(
    workshop_key,objective_id,label,category,ordinal,hint_content,solution_content)
    VALUES($1,'preserved','Preserved objective','qualification',1,$2::jsonb,$3::jsonb)`,
  [`ipi_email_qualification_${label}`, JSON.stringify({ instructor: 'hint' }),
    JSON.stringify({ instructor: 'solution' })]);

  for (const [user, suffix] of [[owner, 'a'], [sibling, 'b']]) {
    const evaluationId = randomUUID();
    await poolValue.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
      VALUES($1,$2,$3)`, [user.id, `ipi_email_qualification_${label}`, suffix === 'a' ? 4 : 9]);
    await poolValue.query(`INSERT INTO workshop_platform.completions(
      user_id,workshop_key,objective_id) VALUES($1,$2,'preserved')`,
    [user.id, `ipi_email_qualification_${label}`]);
    await poolValue.query(`INSERT INTO workshop_platform.objective_judgments(
      user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,
      evidence_digest,generation,disposition)
      VALUES($1,$2,$3,'preserved','IPIEmail','qualification','fixture-v1',$4,$5,'pending')`,
    [user.id, evaluationId, `ipi_email_qualification_${label}`,
      sha256(`${label}-${suffix}-evidence`), suffix === 'a' ? 4 : 9]);
  }

  const ownerKey = JSON.stringify(['IndirectEmail', String(owner.id)]);
  const siblingKey = JSON.stringify(['IndirectEmail', String(sibling.id)]);
  const ownerRunId = randomUUID();
  const siblingRunId = randomUUID();
  await poolValue.query(`INSERT INTO graph_runtime.owners(owner_key,generation)
    VALUES($1,4),($2,9)`, [ownerKey, siblingKey]);
  await poolValue.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
    VALUES($1,$2,4,'running'),($3,$4,9,'running')`,
  [ownerRunId, ownerKey, siblingRunId, siblingKey]);
  return { ownerId: owner.id, siblingId: sibling.id, ownerKey, siblingKey,
    ownerRunId, siblingRunId };
}

async function preservedSnapshot(poolValue, fixture) {
  const ids = [fixture.ownerId, fixture.siblingId];
  const [users, sessions, exercises, objectives, states, completions, judgments, owners, runs] =
    await Promise.all([
      poolValue.query(`SELECT id,username,email,role,admin_level,is_active FROM identity.users
        WHERE id=ANY($1::integer[]) ORDER BY id`, [ids]),
      poolValue.query(`SELECT user_id,session_token_hash,device_info,is_active,expires_at
        FROM identity.user_sessions WHERE user_id=ANY($1::integer[]) ORDER BY user_id`, [ids]),
      poolValue.query(`SELECT workshop_key,challenge_key,challenge_name,challenge_description,
        is_visible,show_hints,show_solutions,catalog_active,ordinal
        FROM workshop_platform.exercises WHERE workshop_key=$1`,
      [`ipi_email_qualification_${fixture.label || 'populated'}`]),
      poolValue.query(`SELECT workshop_key,objective_id,label,category,ordinal,is_enabled,
        catalog_active,hint_enabled,solution_enabled,hint_content,solution_content
        FROM workshop_platform.objectives WHERE workshop_key=$1`,
      [`ipi_email_qualification_${fixture.label || 'populated'}`]),
      poolValue.query(`SELECT user_id,workshop_key,generation FROM workshop_platform.user_state
        WHERE user_id=ANY($1::integer[]) ORDER BY user_id`, [ids]),
      poolValue.query(`SELECT user_id,workshop_key,objective_id FROM workshop_platform.completions
        WHERE user_id=ANY($1::integer[]) ORDER BY user_id`, [ids]),
      poolValue.query(`SELECT user_id,evaluation_id,workshop_key,objective_id,family,scenario,
        rubric_version,evidence_digest,generation,verdict,result_json,result_digest,disposition
        FROM workshop_platform.objective_judgments
        WHERE user_id=ANY($1::integer[]) ORDER BY user_id,evaluation_id`, [ids]),
      poolValue.query(`SELECT owner_key,generation FROM graph_runtime.owners
        WHERE owner_key=ANY($1::text[]) ORDER BY owner_key`, [[fixture.ownerKey, fixture.siblingKey]]),
      poolValue.query(`SELECT run_id,owner_key,generation,status FROM graph_runtime.runs
        WHERE owner_key=ANY($1::text[]) ORDER BY owner_key,run_id`, [[fixture.ownerKey, fixture.siblingKey]]),
    ]);
  return [users, sessions, exercises, objectives, states, completions, judgments, owners, runs]
    .map(result => result.rows);
}

async function assertPrivileges(migration, runtime) {
  assert.equal((await migration.query('SELECT current_user AS role')).rows[0].role,
    'dvaia_identity_migration');
  assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,
    'dvaia_identity_runtime');
  const permissions = (await migration.query(`SELECT
    has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','SELECT')
      AND has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','INSERT')
      AND has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','UPDATE')
      AND has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','DELETE') AS runtime_dml,
    has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','TRUNCATE') AS runtime_truncate,
    has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','REFERENCES') AS runtime_references,
    has_table_privilege('dvaia_identity_runtime','identity.ipi_email_artifacts','TRIGGER') AS runtime_trigger,
    NOT EXISTS (SELECT 1 FROM pg_class c,
      LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
      WHERE c.oid='identity.ipi_email_artifacts'::regclass AND acl.grantee=0
        AND acl.privilege_type=ANY(ARRAY['SELECT','INSERT','UPDATE','DELETE'])) AS public_no_dml,
    NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
      LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE n.nspname='identity'
        AND p.proname IN ('guard_ipi_email_artifact_insert','guard_ipi_email_artifact_update')
        AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_no_function_execute`)).rows[0];
  assert.deepEqual(permissions, {
    runtime_dml: true,
    runtime_truncate: false,
    runtime_references: false,
    runtime_trigger: false,
    public_no_dml: true,
    public_no_function_execute: true,
  });
  assert.deepEqual((await migration.query(`SELECT tgname,tgenabled FROM pg_trigger
    WHERE tgrelid='identity.ipi_email_artifacts'::regclass AND NOT tgisinternal
    ORDER BY tgname`)).rows, [
    { tgname: 'ipi_email_artifact_current_run', tgenabled: 'O' },
    { tgname: 'ipi_email_artifact_immutable', tgenabled: 'O' },
  ]);
  await assert.rejects(runtime.query('SELECT name FROM dvaia_migrations.ledger'),
    { code: '42501' });
  await assert.rejects(runtime.query(
    'ALTER TABLE identity.ipi_email_artifacts ADD COLUMN forbidden integer'), { code: '42501' });
}

function manualArtifact(body, recipient) {
  return { ingestionKind: 'manual_entry', provider: 'manual_entry', providerMessageId: null,
    sentReceiptId: null, sender: '', recipient, subject: 'Qualification artifact', body };
}

async function assertUnsupportedCrossOwnerReceipt(runtime, fixture) {
  const receiptId = (await runtime.query(`INSERT INTO identity.sent_emails_log(
    user_key,recipient_email,scenario_type,email_subject)
    VALUES($1,$2,'qualification','unsupported binding') RETURNING id`,
  [String(fixture.siblingId), 'sibling@example.invalid'])).rows[0].id;
  const artifactId = randomUUID();
  const body = 'unsupported cross-owner receipt body';
  const bodyDigest = sha256(body);
  await assert.rejects(runtime.query(`INSERT INTO identity.ipi_email_artifacts(
    artifact_id,owner_id,owner_key,generation,run_id,ingestion_kind,provider,
    provider_message_id,sent_receipt_id,sender,recipient,subject,body_text,
    body_bytes,body_sha256,model_body_text,model_body_bytes,model_body_sha256,
    model_body_truncated)
    VALUES($1,$2,$3,4,$4,'inbox_provider','mailpit','foreign-receipt',$5,
      'sender@example.invalid','owner@example.invalid','Unsupported receipt',$6,$7,$8,$6,$7,$8,false)`,
  [artifactId, fixture.ownerId, fixture.ownerKey, fixture.ownerRunId, receiptId,
    body, Buffer.byteLength(body), bodyDigest]), { code: '23514' });
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM identity.ipi_email_artifacts WHERE artifact_id=$1`, [artifactId])).rows[0].count, 0);
}

async function waitForLockWait(observer, backendPid, blockerPid) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    // The observer remains inside the reset transaction; refresh its cached
    // activity snapshot so an early observation cannot mask the later wait.
    await observer.query('SELECT pg_stat_clear_snapshot()');
    const row = (await observer.query(`SELECT state,wait_event_type,wait_event,
        pg_blocking_pids(pid) AS blockers
      FROM pg_stat_activity WHERE pid=$1`, [backendPid])).rows[0];
    if (row?.state === 'active' && row.wait_event_type === 'Lock'
        && row.blockers.includes(blockerPid)) return row;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('repository insert did not enter a PostgreSQL lock wait');
}

async function assertResetSerialization(runtime, fixture) {
  const resetClient = await runtime.connect();
  const insertClient = await runtime.connect();
  let resetOpen = false;
  let pending;
  try {
    const resetPid = (await resetClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    const insertPid = (await insertClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await resetClient.query('BEGIN');
    resetOpen = true;
    assert.equal((await resetClient.query(`UPDATE graph_runtime.owners SET generation=5
      WHERE owner_key=$1 AND generation=4`, [fixture.ownerKey])).rowCount, 1);

    const artifactId = randomUUID();
    pending = createEmailArtifactRepository(insertClient).createMany({
      ownerId: fixture.ownerId,
      ownerKey: fixture.ownerKey,
      generation: 4,
      runId: fixture.ownerRunId,
      artifacts: [{ ...manualArtifact('blocked by owner reset', 'blocked@example.invalid'),
        artifactId }],
    }).then(value => ({ value }), error => ({ error }));
    const wait = await waitForLockWait(resetClient, insertPid, resetPid);
    assert.equal(wait.wait_event_type, 'Lock');
    assert.ok(wait.wait_event);
    assert.ok(wait.blockers.includes(resetPid));
    assert.equal((await resetClient.query(`SELECT count(*)::integer AS count
      FROM identity.ipi_email_artifacts WHERE artifact_id=$1`, [artifactId])).rows[0].count, 0);

    await resetClient.query('COMMIT');
    resetOpen = false;
    const outcome = await pending;
    assert.equal(outcome.value, undefined);
    assert.equal(outcome.error?.code, 'EMAIL_ARTIFACT_RUN_STALE');
    assert.equal((await resetClient.query(`SELECT count(*)::integer AS count
      FROM identity.ipi_email_artifacts WHERE artifact_id=$1`, [artifactId])).rows[0].count, 0);
    assert.deepEqual((await resetClient.query(`SELECT generation::text,status FROM graph_runtime.runs
      WHERE run_id=$1`, [fixture.ownerRunId])).rows, [{ generation: '4', status: 'running' }],
    'owner reset authority, rather than run status alone, makes the blocked insert stale');
  } finally {
    if (resetOpen) await resetClient.query('ROLLBACK').catch(() => {});
    if (pending) await pending;
    insertClient.release();
    resetClient.release();
  }
}

async function assertRepositoryLifecycle(runtime, fixture) {
  const repository = createEmailArtifactRepository(runtime);
  assert.equal(await repository.assertReady(), true);
  const [owned] = await repository.createMany({
    ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey,
    generation: 4,
    runId: fixture.ownerRunId,
    artifacts: [manualArtifact('owner private qualification body', 'owner@example.invalid')],
  });
  const [sibling] = await repository.createMany({
    ownerId: fixture.siblingId,
    ownerKey: fixture.siblingKey,
    generation: '9',
    runId: fixture.siblingRunId,
    artifacts: [manualArtifact('sibling private qualification body', 'sibling@example.invalid')],
  });
  assert.equal((await repository.resolveCurrent({ artifactId: owned.artifactId,
    ownerId: fixture.ownerId, ownerKey: fixture.ownerKey, generation: 4 })).body,
  'owner private qualification body');
  await assert.rejects(repository.resolveCurrent({ artifactId: owned.artifactId,
    ownerId: fixture.siblingId, ownerKey: fixture.siblingKey, generation: 9 }),
  { code: 'EMAIL_ARTIFACT_UNAVAILABLE' });
  await assert.rejects(repository.createMany({ ownerId: fixture.ownerId,
    ownerKey: fixture.siblingKey, generation: 4, runId: fixture.ownerRunId,
    artifacts: [manualArtifact('foreign', 'foreign@example.invalid')] }), TypeError);
  await assert.rejects(repository.createMany({ ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey, generation: 5, runId: fixture.ownerRunId,
    artifacts: [manualArtifact('stale', 'stale@example.invalid')] }),
  { code: 'EMAIL_ARTIFACT_RUN_STALE' });
  await assertUnsupportedCrossOwnerReceipt(runtime, fixture);
  await assert.rejects(runtime.query(`UPDATE identity.ipi_email_artifacts
    SET subject='mutated' WHERE artifact_id=$1`, [owned.artifactId]), { code: '55000' });

  const beforeGenerationReset = (await runtime.query(`SELECT count(*)::integer AS count
    FROM identity.ipi_email_artifacts WHERE owner_id=$1`, [fixture.ownerId])).rows[0].count;
  await assertResetSerialization(runtime, fixture);
  await assert.rejects(repository.createMany({ ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey, generation: 4, runId: fixture.ownerRunId,
    artifacts: [manualArtifact('stale after owner reset', 'stale-reset@example.invalid')] }),
  { code: 'EMAIL_ARTIFACT_RUN_STALE' });
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM identity.ipi_email_artifacts WHERE owner_id=$1`, [fixture.ownerId])).rows[0].count,
  beforeGenerationReset, 'a stale running run cannot persist an artifact after owner reset');

  assert.equal(await repository.retireOwner({ ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey }), 1);
  assert.equal(await repository.retireOwner({ ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey }), 0);
  await assert.rejects(repository.resolveCurrent({ artifactId: owned.artifactId,
    ownerId: fixture.ownerId, ownerKey: fixture.ownerKey, generation: 4 }),
  { code: 'EMAIL_ARTIFACT_UNAVAILABLE' });
  assert.equal((await repository.resolveCurrent({ artifactId: sibling.artifactId,
    ownerId: fixture.siblingId, ownerKey: fixture.siblingKey, generation: 9 })).body,
  'sibling private qualification body');
  assert.equal(await repository.destroyOwner({ ownerId: fixture.ownerId,
    ownerKey: fixture.ownerKey }), 1);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM identity.ipi_email_artifacts WHERE owner_id=$1`, [fixture.ownerId])).rows[0].count, 0);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM identity.ipi_email_artifacts WHERE owner_id=$1`, [fixture.siblingId])).rows[0].count, 1);
}

test('registered identity0065 is exact reviewed v2 after canonical through 0061',
  async () => {
    if (qualificationRequested) {
      assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
      assert.equal(process.env.IPI_EMAIL_0065_ISOLATED, '1');
      for (const name of urlVariables) assert.ok(process.env[name], `${name} is required`);
      assert.ok(process.env.IPI_EMAIL_0065_RUNTIME_ROOT,
        'IPI_EMAIL_0065_RUNTIME_ROOT is required');
    }
    const canonical = await readMigrations(canonicalDirectory);
    assert.equal(canonical.at(-1)?.name, candidateName);
    assert.equal(canonical.some(row => /^006[234]_/.test(row.name)), false);
    const registered = canonical.filter(row => row.name === candidateName);
    assert.equal(registered.length, 1);
    assert.equal(registered[0].checksum, expectedCandidateSha256);
    assert.equal(canonical.filter(row => row.name < candidateName).at(-1)?.name,
      '0061_mcp_supply_chain_curriculum_defaults.sql');
    assert.equal(sha256(await fs.readFile(originalDraftPath)), originalDraftSha256,
      'the superseded draft remains preserved byte-for-byte');
    const reviewed = await fs.readFile(candidatePath, 'utf8');
    assert.equal(sha256(reviewed), expectedCandidateSha256);
    assert.equal(registered[0].sql, reviewed);
  });

test('identity0065 canonical migration qualifies fresh, populated, replay and rollback lifecycle', {
  skip: !enabled ? 'requires three root-owned disposable PostgreSQL URL pairs' : false,
  timeout: 180000,
}, async t => {
  const urls = checkedUrls();
  const directories = await buildPrivateDirectories();
  const pools = makePools(urls);
  t.after(async () => {
    await Promise.allSettled(Object.values(pools).flatMap(pair =>
      [pair.runtime.end(), pair.migration.end()]));
  });
  const baselineNames = directories.baselineMigrations.map(row => row.name);
  const fullNames = [...baselineNames, candidateName];

  for (const [kind, pair] of Object.entries(pools)) {
    await assertEmptyDatabase(pair.migration, databaseByKind[kind]);
  }

  assert.deepEqual(await migrate(pools.FRESH.migration, directories.full), fullNames);
  assert.deepEqual(await migrate(pools.FRESH.migration, directories.full), []);
  await assertExactLedger(pools.FRESH.migration, directories.full);
  await assertPrivileges(pools.FRESH.migration, pools.FRESH.runtime);
  const freshFixture = await seedPreservedState(pools.FRESH.migration, 'fresh');
  freshFixture.label = 'fresh';
  await assertRepositoryLifecycle(pools.FRESH.runtime, freshFixture);

  assert.deepEqual(await migrate(pools.POPULATED.migration, directories.baseline), baselineNames);
  await assert.rejects(createEmailArtifactRepository(pools.POPULATED.runtime).assertReady(),
    { code: 'EMAIL_ARTIFACT_STORAGE_NOT_READY' },
    'the canonical through-0061 schema must fail closed before 0065');
  const populatedFixture = await seedPreservedState(pools.POPULATED.migration, 'populated');
  populatedFixture.label = 'populated';
  const populatedBefore = await preservedSnapshot(pools.POPULATED.runtime, populatedFixture);
  assert.deepEqual(await migrate(pools.POPULATED.migration, directories.full), [candidateName]);
  assert.deepEqual(await preservedSnapshot(pools.POPULATED.runtime, populatedFixture), populatedBefore,
    '0065 preserves users, sessions, instructor catalog, progress, judgments and graph rows');
  assert.deepEqual(await migrate(pools.POPULATED.migration, directories.full), []);
  assert.deepEqual(await preservedSnapshot(pools.POPULATED.runtime, populatedFixture), populatedBefore);
  await assertExactLedger(pools.POPULATED.migration, directories.full);
  await assertPrivileges(pools.POPULATED.migration, pools.POPULATED.runtime);
  await assertRepositoryLifecycle(pools.POPULATED.runtime, populatedFixture);

  assert.deepEqual(await migrate(pools.ROLLBACK.migration, directories.baseline), baselineNames);
  await assert.rejects(createEmailArtifactRepository(pools.ROLLBACK.runtime).assertReady(),
    { code: 'EMAIL_ARTIFACT_STORAGE_NOT_READY' });
  const rollbackFixture = await seedPreservedState(pools.ROLLBACK.migration, 'rollback');
  rollbackFixture.label = 'rollback';
  const rollbackBefore = await preservedSnapshot(pools.ROLLBACK.runtime, rollbackFixture);
  const rollbackLedger = await ledger(pools.ROLLBACK.migration);
  await assert.rejects(migrate(pools.ROLLBACK.migration, directories.failing),
    /owned identity0065 rollback qualification/);
  assert.equal((await pools.ROLLBACK.migration.query(
    "SELECT to_regclass('identity.ipi_email_artifacts') AS relation")).rows[0].relation, null);
  assert.equal((await pools.ROLLBACK.migration.query(`SELECT count(*)::integer AS count
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='identity' AND p.proname LIKE 'guard_ipi_email_artifact_%'`)).rows[0].count, 0);
  assert.deepEqual(await ledger(pools.ROLLBACK.migration), rollbackLedger);
  assert.deepEqual(await preservedSnapshot(pools.ROLLBACK.runtime, rollbackFixture), rollbackBefore);
  assert.deepEqual(await migrate(pools.ROLLBACK.migration, directories.full), [candidateName]);
  assert.deepEqual(await migrate(pools.ROLLBACK.migration, directories.full), []);
  await assertExactLedger(pools.ROLLBACK.migration, directories.full);
  assert.deepEqual(await preservedSnapshot(pools.ROLLBACK.runtime, rollbackFixture), rollbackBefore);
  await assertRepositoryLifecycle(pools.ROLLBACK.runtime, rollbackFixture);
});
