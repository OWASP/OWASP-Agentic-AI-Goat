'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const C = require('../../server/services/secureshopExternalMailContract');
const { createExternalMailRepository } = require('../../server/database/postgres/secureshopExternalMailRepository');

const DIRECTORY = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const TAIL = '0153_secureshop_external_test_mail.sql';
const PREFIX = 'PG_EXTERNAL_MAIL_';
const ENABLED = process.env.PG_TEST_DISPOSABLE === 'yes' && ['FRESH', 'POPULATED'].every(store =>
  ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

// The production migrator still owns ledger/checksum/transaction behavior. Only
// its fixture-local directory listing is filtered to construct an actual 0152 store.
function through0152() {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const visible = { ...fsp, async readdir(directory, ...args) {
    const names = await fsp.readdir(directory, ...args);
    return path.resolve(directory) === DIRECTORY
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name) || name < TAIL)
      : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => ['node:fs/promises', 'fs/promises'].includes(name) ? visible : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

function ownedUrl(store, role) {
  const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
  assert.equal(value.protocol, 'postgresql:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.username, `dvaia_identity_${role.toLowerCase()}`);
  assert.equal(value.password, '');
  assert.equal(value.search, '');
  assert.equal(value.hash, '');
  assert.match(value.pathname, new RegExp(`^/dvaia_test_external_mail_${store.toLowerCase()}_[a-f0-9]{12}$`));
  return value;
}

function authority() {
  return { principalId: randomUUID(), authSessionId: 1042,
    scopeKey: 'a'.repeat(64), binding: { version: 1, source: 'owned-repository-test' } };
}
function preview(sender, recipient = 'synthetic@sharklasers.com') {
  return C.makeExternalMailPreview({ operationId: randomUUID(), sender, recipient });
}

test('identity0153 fresh and populated migration preserve history, runtime grants and retained mail claims',
  { skip: !ENABLED, timeout: 150000 }, async t => {
    assert.equal(process.cwd(), path.resolve(__dirname, '../..'));
    const urls = Object.fromEntries(['FRESH', 'POPULATED'].flatMap(store =>
      ['MIGRATION', 'RUNTIME'].map(role => [`${store}_${role}`, ownedUrl(store, role)])));
    assert.equal(new Set(Object.values(urls).map(url => url.port)).size, 1);
    assert.equal(new Set(Object.values(urls).map(url => url.pathname)).size, 2);
    const pools = Object.fromEntries(Object.entries(urls).map(([name, url]) =>
      [name, new Pool({ connectionString: url.href, max: 5, statement_timeout: 10000,
        lock_timeout: 3000, application_name: 'dvaia-external-mail-repository-native' })]));
    t.after(async () => {
      const results = await Promise.allSettled(Object.values(pools).map(pool => pool.end()));
      assert.ok(results.every(value => value.status === 'fulfilled'), 'all owned connections close');
    });

    const names = (await readMigrations(DIRECTORY)).map(value => value.name);
    assert.equal(names.at(-1), TAIL);
    assert.deepEqual(await migrate(pools.FRESH_MIGRATION, DIRECTORY), names);
    assert.deepEqual(await migrate(pools.FRESH_MIGRATION, DIRECTORY), []);
    assert.deepEqual((await pools.FRESH_MIGRATION.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name'))
      .rows.map(row => row.name), names);

    assert.deepEqual(await through0152()(pools.POPULATED_MIGRATION, DIRECTORY), names.slice(0, -1));
    await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.default_seed_state
      (seed_key, defaults_sha256) VALUES ('fresh-install-v1',$1)`, ['b'.repeat(64)]);
    const passwordHash = await bcrypt.hash('synthetic-owned-password', 4);
    const principal = randomUUID(), tenant = randomUUID(), until = new Date(Date.now() + 600000);
    const created = (await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,'external_mail_fixture',
      'external-mail-fixture@example.invalid',$2,'merchant') RETURNING shop_user_id`,
    [principal, passwordHash])).rows[0];
    await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.tenants
      (tenant_id,slug) VALUES($1,'external-mail-fixture')`, [tenant]);
    await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
    [tenant, principal, created.shop_user_id]);
    // 0148 snapshots membership at login. The authenticated session must be
    // born after the tenant membership, never retroactively attached to it.
    const session = (await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.sessions
      (principal_id,token_hash,credential_version,authority_version,expires_at)
      VALUES($1,$2,1,1,$3) RETURNING session_id`, [principal, '1'.repeat(64), until])).rows[0].session_id;
    assert.deepEqual((await pools.POPULATED_MIGRATION.query(`SELECT tenant_id,membership_version::text
      FROM secureshop_auth.session_membership_snapshots WHERE session_id=$1`, [session])).rows,
    [{ tenant_id: tenant, membership_version: '1' }],
    'the original login captured the current tenant membership');
    const execution = (await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_auth.execution_sessions
      (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
      VALUES($1,$2,$3,1,$4) RETURNING session_id`, [session, tenant, principal, until])).rows[0].session_id;
    const retainedTables = ['default_seed_state', 'principals', 'sessions', 'tenants',
      'tenant_memberships', 'execution_sessions', 'tenant_modes'];
    const snapshot = async () => Object.fromEntries(await Promise.all(retainedTables.map(async table =>
      [table, (await pools.POPULATED_MIGRATION.query(`SELECT to_jsonb(t) AS row
        FROM secureshop_auth.${table} t ORDER BY to_jsonb(t)::text`)).rows])));
    const before = await snapshot();
    const ledgerBefore = (await pools.POPULATED_MIGRATION.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await migrate(pools.POPULATED_MIGRATION, DIRECTORY), [TAIL]);
    assert.deepEqual(await migrate(pools.POPULATED_MIGRATION, DIRECTORY), []);
    assert.deepEqual(await snapshot(), before, '0153 retains prior account/session/mode and seed rows');
    const ledgerAfter = (await pools.POPULATED_MIGRATION.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(ledgerAfter.slice(0, -1), ledgerBefore);
    assert.deepEqual(ledgerAfter, (await readMigrations(DIRECTORY)).map(
      ({ name, checksum }) => ({ name, checksum })));

    const runtime = pools.POPULATED_RUNTIME, migration = pools.POPULATED_MIGRATION;
    const grants = (await runtime.query(`SELECT
      has_table_privilege(current_user,'secureshop_auth.external_mail_operations','SELECT') AS selected,
      has_table_privilege(current_user,'secureshop_auth.external_mail_operations','INSERT') AS inserted,
      has_table_privilege(current_user,'secureshop_auth.external_mail_operations','DELETE') AS deleted,
      has_table_privilege(current_user,'secureshop_auth.external_mail_operations','TRUNCATE') AS truncated,
      has_column_privilege(current_user,'secureshop_auth.external_mail_operations','state','UPDATE') AS state_update,
      has_column_privilege(current_user,'secureshop_auth.external_mail_operations','preview','UPDATE') AS preview_update,
      has_table_privilege(current_user,'secureshop_auth.tenant_modes','UPDATE') AS mode_update,
      has_function_privilege(current_user,
        'secureshop_auth.lock_external_mail_mode(integer,uuid,uuid)','EXECUTE') AS mode_lock`)).rows[0];
    assert.deepEqual(grants, { selected: true, inserted: true, deleted: false,
      truncated: false, state_update: true, preview_update: false, mode_update: false, mode_lock: true });
    await runtime.query('SELECT secureshop_auth.lock_external_mail_mode($1,$2,$3)',
      [execution, tenant, principal]);
    await assert.rejects(runtime.query('SELECT secureshop_auth.lock_external_mail_mode(1,$1,$2)',
      [randomUUID(), randomUUID()]), error => error.code === '28000');

    const repo = createExternalMailRepository({ pool: runtime });
    await repo.assertReady();
    const actor = authority(), sender = 'synthetic@gmail.com';
    // A historic prepared draft is inserted as controlled seed data. The
    // original schema forbids changing expiry after preparation, including for
    // the migration role. GET projects expiry without mutating the ledger.
    const expiredActor = authority(), expiredDraft = preview(sender);
    const expiredHash = C.externalMailRequestSha256(expiredDraft, expiredActor.scopeKey);
    await migration.query(`INSERT INTO secureshop_auth.external_mail_operations
      (operation_id,principal_id,auth_session_id,scope_key,binding,request_sha256,
       preview,sender_key,created_at,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()-interval '2 minutes',
        clock_timestamp()-interval '1 minute')`,
    [expiredDraft.operationId,expiredActor.principalId,expiredActor.authSessionId,
      expiredActor.scopeKey,expiredActor.binding,expiredHash,expiredDraft,
      C.hash(['external-mail-sender-v1',expiredDraft.sender])]);
    const expiredStored = async () => (await migration.query(`SELECT to_jsonb(t) AS row
      FROM secureshop_auth.external_mail_operations t WHERE operation_id=$1`,
    [expiredDraft.operationId])).rows[0].row;
    const expiredBefore = await expiredStored();
    const expiredRead = await repo.read(expiredActor,expiredDraft.operationId);
    assert.equal(expiredRead.state,'prepared');assert.equal(expiredRead.derivedExpired,true);
    const readApplication = require('../../server/services/secureshopExternalMail').createExternalMailApplication({
      repository:repo,authority:{capture:async()=>expiredActor,assertCurrent:async()=>{},withDispatch:async()=>{}},
      transport:{isAvailable:()=>true,send:async()=>{throw Error('No transport in expiry read');}},sender});
    const expiredProjection = await readApplication.read({},expiredDraft.operationId);
    assert.equal(expiredProjection.state,'expired');assert.equal(expiredProjection.smtp,null);
    assert.deepEqual(await expiredStored(),expiredBefore,'GET expiry never updates evidence or quota');
    await assert.rejects(repo.claim(expiredActor,{operationId:expiredDraft.operationId,
      requestSha256:expiredHash}),error=>error.code==='EXTERNAL_MAIL_SCOPE_STALE');
    assert.deepEqual(await expiredStored(),expiredBefore,'expired claim cannot make a dispatch');

    const racingActor=authority(),racingDraft=preview(sender);
    const racingHash=C.externalMailRequestSha256(racingDraft,racingActor.scopeKey);
    await repo.prepare(racingActor,racingDraft,racingHash);
    const lock=await migration.connect();let locked=false;
    try{
      await lock.query('BEGIN');locked=true;
      const lockerPid=(await lock.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      await lock.query(`SELECT operation_id FROM secureshop_auth.external_mail_operations
        WHERE operation_id=$1 FOR UPDATE`,[racingDraft.operationId]);
      const pendingRead=repo.read(racingActor,racingDraft.operationId);
      pendingRead.catch(()=>{});
      const deadline=Date.now()+2000;let waiter=false;
      while(Date.now()<deadline){
        // Observe the runtime reader from another connection of that same
        // role. Cross-role pg_stat_activity fields are redacted by PostgreSQL.
        const observed=(await runtime.query(`SELECT 1 FROM pg_stat_activity
          WHERE usename=current_user AND pid<>pg_backend_pid()
            AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))
          LIMIT 1`,[lockerPid])).rowCount;
        if(observed){waiter=true;break;}
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      assert.equal(waiter,true,'GET is held behind the claim row lock');
      await lock.query(`UPDATE secureshop_auth.external_mail_operations
        SET state='dispatching',claimed_at=clock_timestamp() WHERE operation_id=$1`,
      [racingDraft.operationId]);
      await lock.query('COMMIT');locked=false;
      const racedRead=await pendingRead;
      assert.equal(racedRead.state,'dispatching');assert.equal(racedRead.derivedExpired,false);
    }finally{if(locked)await lock.query('ROLLBACK');lock.release();}
    const draft = preview(sender), digest = C.externalMailRequestSha256(draft, actor.scopeKey);
    const prepared = await repo.prepare(actor, draft, digest);
    assert.equal(prepared.state, 'prepared');
    assert.deepEqual(await repo.prepare(actor, draft, digest), prepared, 'same ID and bytes replay the draft');
    await assert.rejects(repo.prepare(actor, draft, 'c'.repeat(64)),
      error => error.code === 'EXTERNAL_MAIL_CONFLICT');
    const input = { version: 1, operationId: draft.operationId, requestSha256: digest };
    const claims = await Promise.all([repo.claim(actor, input), repo.claim(actor, input)]);
    assert.deepEqual(claims.map(value => value.claimed).sort(), [false, true]);
    assert.ok(claims.every(value => value.row.state === 'dispatching'));
    assert.deepEqual(await repo.claim(actor, input), { claimed: false,
      row: claims[0].row }, 'retained claim never creates a second dispatch');
    await assert.rejects(runtime.query(`UPDATE secureshop_auth.external_mail_operations
      SET preview=preview WHERE operation_id=$1`, [draft.operationId]),
    error => error.code === '42501');
    await assert.rejects(migration.query(`UPDATE secureshop_auth.external_mail_operations
      SET request_sha256=$2 WHERE operation_id=$1`, [draft.operationId, 'd'.repeat(64)]),
    error => error.code === 'P0001');
    await assert.rejects(migration.query(`DELETE FROM secureshop_auth.external_mail_operations
      WHERE operation_id=$1`, [draft.operationId]), error => error.code === 'P0001');
    await assert.rejects(repo.prepare(actor, preview(sender), 'e'.repeat(64)),
      error => error.code === 'EXTERNAL_MAIL_RECOVERY_REQUIRED');
    const unknown = await repo.settle(draft.operationId, 'unknown');
    assert.equal(unknown.state, 'unknown');
    await assert.rejects(repo.prepare(actor, preview(sender), 'e'.repeat(64)),
      error => error.code === 'EXTERNAL_MAIL_RECOVERY_REQUIRED');
    const newScope = { ...actor, scopeKey: 'f'.repeat(64) };
    assert.equal((await repo.read(newScope, draft.operationId)).state, 'unknown',
      'historical principal read survives a changed scope');
    await assert.rejects(repo.claim(newScope, input), error => error.code === 'EXTERNAL_MAIL_SCOPE_STALE');
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_auth.external_mail_operations
      WHERE operation_id=$1`, [draft.operationId])).rows[0].n, 1);

    await migration.query(`UPDATE secureshop_auth.sessions SET revoked_at=clock_timestamp()
      WHERE session_id=$1`, [session]);
    await assert.rejects(runtime.query('SELECT secureshop_auth.lock_external_mail_mode($1,$2,$3)',
      [execution, tenant, principal]), error => error.code === '28000',
    'a revoked real shop session cannot acquire a mode read lock');
    assert.equal((await repo.read(newScope, draft.operationId)).state, 'unknown',
      'identity lifecycle revocation does not erase independent mail evidence');

    const other = authority();
    await assert.rejects(repo.read(other, draft.operationId),
      error => error.code === 'EXTERNAL_MAIL_NOT_FOUND');
    const cancelledDraft = preview(sender), cancelledDigest = C.externalMailRequestSha256(cancelledDraft, other.scopeKey);
    await repo.prepare(other, cancelledDraft, cancelledDigest);
    const cancelledInput = { version: 1, operationId: cancelledDraft.operationId, requestSha256: cancelledDigest };
    assert.equal((await repo.cancel(other, cancelledInput)).state, 'cancelled');
    assert.equal((await repo.cancel(other, cancelledInput)).state, 'cancelled');
    assert.deepEqual((await repo.claim(other, cancelledInput)).claimed, false);

    const ownerQuota = authority();
    for (let i = 0; i < C.OWNER_LIMIT; i++) {
      const item = preview('owner-quota@gmail.com');
      const hash = C.externalMailRequestSha256(item, ownerQuota.scopeKey);
      await repo.prepare(ownerQuota, item, hash);
      assert.equal((await repo.claim(ownerQuota, { operationId: item.operationId,
        requestSha256: hash })).claimed, true);
      await repo.settle(item.operationId, 'rejected_before_dispatch');
    }
    const ownerExtra = preview('owner-quota@gmail.com');
    const ownerExtraHash = C.externalMailRequestSha256(ownerExtra, ownerQuota.scopeKey);
    await repo.prepare(ownerQuota, ownerExtra, ownerExtraHash);
    await assert.rejects(repo.claim(ownerQuota, { operationId: ownerExtra.operationId,
      requestSha256: ownerExtraHash }), error => error.code === 'EXTERNAL_MAIL_RATE_LIMIT');

    for (let i = 0; i < C.SENDER_LIMIT; i++) {
      const senderActor = authority(), item = preview('sender-quota@gmail.com');
      const hash = C.externalMailRequestSha256(item, senderActor.scopeKey);
      await repo.prepare(senderActor, item, hash);
      assert.equal((await repo.claim(senderActor, { operationId: item.operationId,
        requestSha256: hash })).claimed, true);
      await repo.settle(item.operationId, 'rejected_before_dispatch');
    }
    const senderActor = authority(), senderExtra = preview('sender-quota@gmail.com');
    const senderExtraHash = C.externalMailRequestSha256(senderExtra, senderActor.scopeKey);
    await repo.prepare(senderActor, senderExtra, senderExtraHash);
    await assert.rejects(repo.claim(senderActor, { operationId: senderExtra.operationId,
      requestSha256: senderExtraHash }), error => error.code === 'EXTERNAL_MAIL_RATE_LIMIT');

    const prepareActor = authority();
    for (let i = 0; i < 20; i++) {
      const item = preview('prepare-quota@gmail.com');
      await repo.prepare(prepareActor, item, C.externalMailRequestSha256(item, prepareActor.scopeKey));
    }
    const prepareExtra = preview('prepare-quota@gmail.com');
    await assert.rejects(repo.prepare(prepareActor, prepareExtra,
      C.externalMailRequestSha256(prepareExtra, prepareActor.scopeKey)),
    error => error.code === 'EXTERNAL_MAIL_RATE_LIMIT');
  });
