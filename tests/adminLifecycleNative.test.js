'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');

test('administrator continuity and concurrent deactivation use a disposable native store',
  { skip: !process.env.ADMIN_TEST_DATABASE_URL }, async () => {
    const target = new URL(process.env.ADMIN_TEST_DATABASE_URL);
    const database = decodeURIComponent(target.pathname.slice(1));
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) ||
        !/^dvaia_admin_disposable_[a-f0-9]{12}$/.test(database) ||
        process.env.ADMIN_TEST_OWNED_DATABASE !== database) {
      throw new Error('Administrator native test requires an explicitly owned disposable localhost database');
    }
    const pool = new Pool({ connectionString: process.env.ADMIN_TEST_DATABASE_URL, max: 4 });
    try {
      const existing = await pool.query(`SELECT count(*)::integer AS count FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema')
          AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S')`);
      if (existing.rows[0].count !== 0) throw new Error('Administrator native test database is not empty');
      await pool.query('CREATE ROLE dvaia_identity_runtime');
      await pool.query(fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0001_identity.sql'), 'utf8'));
      await pool.query(`CREATE TABLE identity.student_deletion_jobs
        (subject_user_id integer NOT NULL, state text NOT NULL)`);
      const hash = '$2a$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZa';
      const add = async name => {
        const user = (await pool.query(`INSERT INTO identity.users(username,email,password,role,admin_level)
          VALUES($1,$2,$3,'admin',2) RETURNING id`, [name, `${name}@example.test`, hash])).rows[0];
        await pool.query(`INSERT INTO identity.admin_permissions(admin_id,permission_name)
          VALUES($1,'user_management')`, [user.id]);
        const session = (await pool.query(`INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at)
          VALUES($1,$2,clock_timestamp()+interval '1 day') RETURNING id`,
        [user.id, user.id.toString(16).padStart(64, '0')])).rows[0];
        return { id: user.id, sessionId: session.id, level: 2 };
      };
      const first = await add('first-admin');
      const repo = createPostgresAdminRepository(pool);
      await assert.rejects(repo.deactivateAdministrator({ userId: first.id, actorId: first.id,
        sessionId: first.sessionId }), { code: 'LAST_ADMIN' });
      assert.equal((await pool.query('SELECT is_active FROM identity.users WHERE id=$1', [first.id])).rows[0].is_active, 1);
      await assert.rejects(repo.updateUser(first.id, { adminLevel: 1 }, first), { code: 'LAST_ADMIN' });
      const permission = (await pool.query('SELECT id FROM identity.admin_permissions WHERE admin_id=$1', [first.id])).rows[0];
      await assert.rejects(repo.revokePermissionById(permission.id, first), { code: 'LAST_ADMIN' });
      await assert.rejects(repo.setUserLock({ userId: first.id, locked: true, actorId: first.id,
        sessionId: first.sessionId }), { code: 'LAST_ADMIN' });
      const second = await add('second-admin');
      const results = await Promise.allSettled([first, second].map(actor =>
        repo.deactivateAdministrator({ userId: actor.id, actorId: actor.id, sessionId: actor.sessionId })));
      assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
      assert.equal(results.filter(result => result.status === 'rejected').length, 1);
      assert.equal((await pool.query(`SELECT count(*)::integer AS count FROM identity.users
        WHERE is_active=1 AND admin_level=2`)).rows[0].count, 1);
      assert.equal((await pool.query(`SELECT count(*)::integer AS count FROM identity.user_sessions
        WHERE is_active=1`)).rows[0].count, 1);
    } finally { await pool.end(); }
  });
