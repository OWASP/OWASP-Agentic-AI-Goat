'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

// Only an explicitly owned cluster with this marker may run this test.
const adminUrl = process.env.PG_BRANDING_TEST_ADMIN_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && Boolean(adminUrl);
const stores = ['session_disclosure', 'mcp', 'xss'];
const root = path.resolve(__dirname, '../../db/postgres/workshop-migrations');

test('branding migrations preserve old rows, accept new formats, and replay without changes', { skip: !enabled }, async t => {
  const parsed = new URL(adminUrl);
  assert.ok(['localhost', '127.0.0.1'].includes(parsed.hostname));
  assert.equal(parsed.pathname, '/postgres');
  const admin = new Pool({ connectionString: adminUrl, max: 1 });
  const roles = [];
  t.after(async () => {
    try { for (const role of roles) await admin.query(`DROP ROLE ${role}`); }
    finally { await admin.end(); }
  });
  assert.equal((await admin.query("SELECT current_setting('cluster_name') AS name")).rows[0].name,
    'owasp-ai-goat-branding-test');

  for (const store of stores) {
    for (const kind of ['runtime', 'migration']) {
      const role = `dvaia_${store}_${kind}`;
      await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
      roles.push(role);
    }
  }

  for (const store of stores) for (const populated of [false, true]) {
    await t.test(`${store}: ${populated ? 'populated' : 'fresh'} and second-run no-op`, async () => {
      const database = `goat_branding_${randomUUID().replaceAll('-', '')}`;
      await admin.query(`CREATE DATABASE ${database} OWNER dvaia_${store}_migration`);
      const url = new URL(adminUrl); url.pathname = '/' + database; url.username = `dvaia_${store}_migration`;
      const pool = new Pool({ connectionString: url.href, max: 1 });
      const original = path.join(root, store);
      const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'goat-branding-migrations-'));
      try {
        let before;
        if (populated) {
          const files = (await fs.readdir(original)).filter(name => name.endsWith('.sql')).sort();
          for (const file of files.slice(0, -1)) await fs.copyFile(path.join(original, file), path.join(scratch, file));
          await migrate(pool, scratch);
          if (store === 'session_disclosure') {
            for (const owner of [1, 2]) await pool.query(`INSERT INTO session_disclosure.labs
              (platform_owner_id,generation,lab_session_id,lab_cookie,csrf_token,lab_user_id,lab_role)
              VALUES($1,1,$2,$3,$4,$5,'lab_admin')`, [owner, randomUUID(),
              'dvaia_lab_' + String(owner).repeat(43), 'A'.repeat(32), 'lab-' + randomUUID()]);
            before = (await pool.query('SELECT * FROM session_disclosure.labs ORDER BY platform_owner_id')).rows;
          } else if (store === 'mcp') {
            const target = randomUUID();
            await pool.query("INSERT INTO mcp.runner_targets(target_id,user_key,platform_session_id,generation) VALUES($1,'1',1,0)", [target]);
            await pool.query(`INSERT INTO mcp.mail_intents(intent_id,target_id,user_key,platform_session_id,generation,
              assigned_message_id,recipient_sha256,payload_sha256) VALUES($1,$2,'1',1,0,$3,$4,$4)`,
              [randomUUID(), target, 'mcp-' + randomUUID() + '@dvaia.local', 'a'.repeat(64)]);
            before = (await pool.query('SELECT * FROM mcp.mail_intents')).rows;
          } else {
            await pool.query("UPDATE xss.emails SET body='Instructor-edited newsletter' WHERE id=3");
            before = (await pool.query('SELECT * FROM xss.emails ORDER BY id')).rows;
          }
        }
        const applied = await migrate(pool, original);
        assert.ok(applied.length > 0);
        if (store === 'session_disclosure') {
          if (before) assert.deepEqual((await pool.query('SELECT * FROM session_disclosure.labs ORDER BY platform_owner_id')).rows, before);
          await pool.query(`INSERT INTO session_disclosure.labs
            (platform_owner_id,generation,lab_session_id,lab_cookie,csrf_token,lab_user_id,lab_role)
            VALUES(3,1,$1,$2,$3,$4,'lab_admin')`, [randomUUID(), 'owasp_ai_goat_lab_' + 'C'.repeat(43), 'B'.repeat(32), 'lab-' + randomUUID()]);
          await assert.rejects(pool.query("UPDATE session_disclosure.labs SET lab_cookie='invalid' WHERE platform_owner_id=3"), { code: '23514' });
        } else if (store === 'mcp') {
          if (before) assert.deepEqual((await pool.query('SELECT * FROM mcp.mail_intents')).rows, before);
          const target = randomUUID();
          await pool.query("INSERT INTO mcp.runner_targets(target_id,user_key,platform_session_id,generation) VALUES($1,'2',2,0)", [target]);
          await pool.query(`INSERT INTO mcp.mail_intents(intent_id,target_id,user_key,platform_session_id,generation,
            assigned_message_id,recipient_sha256,payload_sha256) VALUES($1,$2,'2',2,0,$3,$4,$4)`,
            [randomUUID(), target, 'mcp-' + randomUUID() + '@owasp-ai-goat.local', 'b'.repeat(64)]);
          await assert.rejects(pool.query("UPDATE mcp.mail_intents SET assigned_message_id='invalid' WHERE user_key='2'"), { code: '23514' });
        } else if (before) {
          assert.deepEqual((await pool.query('SELECT * FROM xss.emails ORDER BY id')).rows, before);
        } else {
          assert.equal((await pool.query('SELECT sender FROM xss.emails WHERE id=3')).rows[0].sender, 'newsletter@owasp-ai-goat.local');
        }
        const table = store === 'session_disclosure' ? 'session_disclosure.labs' : store === 'mcp' ? 'mcp.mail_intents' : 'xss.emails';
        const snapshot = (await pool.query(`SELECT * FROM ${table} ORDER BY 1`)).rows;
        assert.deepEqual(await migrate(pool, original), []);
        assert.deepEqual((await pool.query(`SELECT * FROM ${table} ORDER BY 1`)).rows, snapshot);
      } finally {
        await pool.end();
        await admin.query(`DROP DATABASE ${database}`);
        await fs.rm(scratch, { recursive: true, force: true });
      }
    });
  }
});
