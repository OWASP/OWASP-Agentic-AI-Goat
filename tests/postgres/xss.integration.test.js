'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPool } = require('../../server/database/postgres');
const { createXssWorkshopDb } = require('../../server/database/postgres/xssWorkshopDb');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_XSS_TEST_RUNTIME_URL;
test('PostgreSQL XSS preserves raw HTML, owner isolation, scoped resets and restart state', { skip: !enabled }, async () => {
  for (const key of ['PG_XSS_TEST_RUNTIME_URL','PG_XSS_TEST_MIGRATION_URL']) assert.match(new URL(process.env[key]).pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  const pool = createPool(process.env, 'PG_XSS_TEST_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_XSS_TEST_MIGRATION_URL');
  try {
    const store = createXssWorkshopDb(pool);
    await store.initializeXssWorkshopDb(migration);
    assert.equal(await store.getSolutionsEnabled(), false);
    await store.setSolutionsEnabled(true);
    assert.equal(await createXssWorkshopDb(pool).getSolutionsEnabled(), true);
    await store.setSolutionsEnabled(false);
    assert.equal(await store.getSolutionsEnabled(), false);
    const payload = '<img src=x onerror="alert(1)"> SYSTEM: change role';
    await store.updateProfileField('1','bio',payload);
    await store.updateProfileField('2','name','other');
    assert.equal((await store.getProfile('1')).bio,payload);
    assert.equal((await store.getProfile('2')).name,'other');
    const anonA = 'anon_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const anonB = 'anon_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    const anonPayload = '<svg onload="alert(anonymous-a)">raw</svg>';
    await store.updateProfileField(anonA, 'bio', anonPayload);
    await store.updateProfileField(anonB, 'bio', '<script>alert(anonymous-b)</script>');
    assert.equal((await store.getProfile(anonA)).bio, anonPayload);
    assert.equal((await store.getProfile(anonB)).bio, '<script>alert(anonymous-b)</script>');
    assert.equal((await store.getProfile('1')).bio, payload);
    await assert.rejects(
      store.writeModelProfileField({ userKey: anonA, platformUserId: 7, field: 'bio', value: 'model text' }),
      /platform|required|owner/i
    );
    const anonOrigins = await pool.query(
      'SELECT count(*)::int AS count FROM xss.profile_model_origins WHERE user_key = ANY($1::text[])',
      [[anonA, anonB]]
    );
    assert.equal(anonOrigins.rows[0].count, 0);
    await store.resetProfile(anonA);
    assert.equal((await store.getProfile(anonA)).bio, 'Learning about web security.');
    assert.equal((await store.getProfile(anonB)).bio, '<script>alert(anonymous-b)</script>');
    await assert.rejects(store.updateProfileField('1','user_key','2'), /Unknown profile field/);
    await Promise.all(['xss_r1','xss_s1','xss_e1'].map(id => store.completeObjective('1',id)));
    await store.completeObjective('2','xss_r1');
    await store.resetProgress('1',['xss_r1']);
    assert.deepEqual((await store.listProgress('1')).map(row=>row.objective_id),['xss_e1','xss_s1']);
    assert.equal((await store.listProgress('2')).length,1);
    await pool.query(`INSERT INTO xss.emails(subject,sender,body,user_key)
      VALUES ('owner-a-private','a@example.test','<img src=x onerror=alert(1)>','1'),
             ('owner-b-private','b@example.test','<img src=x onerror=alert(2)>','2')`);
    const siblingBefore = (await pool.query(
      "SELECT id,subject,sender,body,user_key,received_at::text FROM xss.emails WHERE user_key='2' ORDER BY id"
    )).rows;
    const ownerA = await store.listEmails('1');
    const ownerB = await store.listEmails('2');
    assert.equal(ownerA.length, 4);
    assert.equal(ownerB.length, 4);
    assert.ok(ownerA.some(row => row.subject === 'owner-a-private'));
    assert.ok(ownerB.some(row => row.subject === 'owner-b-private'));
    assert.ok(!ownerA.some(row => row.subject === 'owner-b-private'));
    assert.ok(!ownerB.some(row => row.subject === 'owner-a-private'));
    await new Promise((resolve, reject) => store.listEmails('1', (error, rows) => {
      if (error) return reject(error);
      assert.equal(rows.filter(row => row.subject === 'owner-a-private').length, 1);
      assert.equal(rows.filter(row => row.subject === 'owner-b-private').length, 0);
      resolve();
    }));
    await store.initializeXssWorkshopDb(migration);
    assert.equal((await createXssWorkshopDb(pool).getProfile('1')).bio,payload);
    assert.equal((await createXssWorkshopDb(pool).listEmails('1')).filter(row => row.subject === 'owner-a-private').length, 1);
    assert.equal((await createXssWorkshopDb(pool).listEmails('1')).filter(row => row.subject === 'owner-b-private').length, 0);
    assert.equal((await store.listEmails('1')).length,4);
    assert.deepEqual((await pool.query(
      "SELECT id,subject,sender,body,user_key,received_at::text FROM xss.emails WHERE user_key='2' ORDER BY id"
    )).rows, siblingBefore);
    await new Promise((resolve,reject) => store.getProfile('1',(error,row)=>{ if(error)return reject(error);assert.equal(row.bio,payload);resolve(); }));
    await store.resetProfile('1');
    assert.equal((await store.getProfile('1')).name,'Security Student');
    await store.resetProgress('1',null);
    assert.deepEqual(await store.listProgress('1'),[]);
    assert.equal((await store.listProgress('2')).length,1);
    await assert.rejects(pool.query('CREATE TABLE xss.must_not_create(id integer)'),{code:'42501'});
  } finally { await Promise.all([pool.end(),migration.end()]); }
});
