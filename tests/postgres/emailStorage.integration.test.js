'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPool } = require('../../server/database/postgres');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createEmailWorkshopRepository } = require('../../server/database/postgres/emailWorkshopRepository');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_EMAIL_TEST_RUNTIME_URL;
test('PostgreSQL attendee email config/progress/audit persist without cross-owner reset', { skip: !enabled }, async () => {
  for (const key of ['PG_EMAIL_TEST_RUNTIME_URL','PG_EMAIL_TEST_MIGRATION_URL']) assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  const pool=createPool(process.env,'PG_EMAIL_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_EMAIL_TEST_MIGRATION_URL');
  try {
    await initializeIdentityRepository(pool,migration);
    const store=createEmailWorkshopRepository(pool);
    assert.equal(await store.getConfiguredEmail('one'),null);
    await store.saveConfiguredEmail('one','one@example.test');
    assert.equal(await store.getConfiguredEmail('one'),'one@example.test');
    assert.equal((await store.listProgress('one'))[0].completed,0);
    assert.equal((await store.listProgress('one'))[0].completed_at,null);
    await store.completeObjective('one',1,'one@example.test');
    const first=(await store.listProgress('one'))[0].completed_at;
    await store.completeObjective('one',1,null);
    await store.completeObjective('two',1,'two@example.test');
    assert.equal(await store.getConfiguredEmail('one'),'one@example.test');
    assert.equal((await store.listProgress('one'))[0].completed_at.getTime(),first.getTime());
    await store.saveConfiguredEmail('one','updated@example.test');
    assert.equal((await store.listProgress('one'))[0].completed_at.getTime(),first.getTime());
    assert.equal(await store.getConfiguredEmail('one'),'updated@example.test');
    await assert.rejects(store.completeObjective('one',6,null),{code:'23514'});
    const sent=await store.logSentEmail('one','one@example.test','custom','teaching fixture','message-fixture');
    assert.ok(sent.id);
    await store.resetProgress('one');
    assert.equal(await store.getConfiguredEmail('one'),null);
    assert.equal(await createEmailWorkshopRepository(pool).getConfiguredEmail('two'),'two@example.test');
    assert.equal((await pool.query('SELECT count(*)::integer AS n FROM identity.sent_emails_log WHERE user_key=$1',['one'])).rows[0].n,1);
  } finally { await Promise.all([pool.end(),migration.end()]); }
});
