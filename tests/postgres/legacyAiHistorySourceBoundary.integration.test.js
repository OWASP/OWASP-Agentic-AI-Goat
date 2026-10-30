'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const prefix = 'PG_HISTORY_BOUNDARY_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env[prefix+'MIGRATION_URL'] && process.env[prefix+'RUNTIME_URL'];
function url(kind) {
  const value = new URL(process.env[prefix+kind+'_URL']);
  assert.equal(value.hostname,'127.0.0.1');
  assert.match(value.pathname,/^\/owasp_ai_goat_test_history_boundary_[a-f0-9]+$/);
  assert.equal(value.username,'dvaia_legacy_challenge_'+kind.toLowerCase());
  assert.equal(value.search,''); assert.equal(value.hash,'');
  return value.href;
}
test('populated source is preserved and isolated while synthetic SQL injection stays demonstrable', {skip: !enabled, timeout:30000}, async () => {
  const migration = new Pool({connectionString:url('MIGRATION')});
  const runtime = new Pool({connectionString:url('RUNTIME')});
  const prior = await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-history-boundary-'));
  const directory = path.resolve(__dirname,'../../db/postgres/workshop-migrations/legacy_challenge');
  const payload = pool => pool.query('SELECT jsonb_agg(to_jsonb(source) ORDER BY id) AS rows FROM legacy_challenge.ai_conversations source');
  try {
    await fs.cp(directory,prior,{recursive:true});
    await fs.unlink(path.join(prior,'0005_private_history_boundary.sql'));
    await migrate(migration,prior);
    await runtime.query(`INSERT INTO legacy_challenge.ai_conversations
      (id,user_id,prompt,response,model_used,created_at,platform_owner_id) VALUES
      (100,8,$1,NULL,NULL,'2026-01-02T03:04:05.123456Z',41),
      (101,NULL,'unknown owner','exact response','fixture','infinity',NULL),
      (102,9,'null timestamp','',NULL,NULL,42)`,['private\nUnicode 🎓']);
    // Exercise both column ACL and PUBLIC grants left by older installations.
    await migration.query('GRANT SELECT(prompt),UPDATE(response) ON legacy_challenge.ai_conversations TO PUBLIC,dvaia_legacy_challenge_runtime');
    const before = (await payload(migration)).rows;
    assert.deepEqual(await migrate(migration,directory),['0005_private_history_boundary.sql']);
    assert.deepEqual(await migrate(migration,directory),[]);
    assert.deepEqual((await payload(migration)).rows,before);
    const denied = [
      'SELECT * FROM legacy_challenge.ai_conversations',
      'SELECT prompt FROM legacy_challenge.ai_conversations',
      'SELECT prompt FROM legacy_challenge.synthetic_ai_conversations UNION ALL SELECT prompt FROM legacy_challenge.ai_conversations',
      "UPDATE legacy_challenge.ai_conversations SET response='overwrite'",
      "INSERT INTO legacy_challenge.ai_conversations(prompt) VALUES('leak')",
      'DELETE FROM legacy_challenge.ai_conversations',
      'TRUNCATE legacy_challenge.ai_conversations',
      "SELECT nextval('legacy_challenge.ai_conversations_id_seq')",
      "DELETE FROM legacy_challenge.synthetic_ai_conversations",
      "INSERT INTO legacy_challenge.synthetic_ai_conversations(id,user_id,username,prompt) VALUES(3,3,'forged','private')"
    ];
    for (const sql of denied) await assert.rejects(runtime.query(sql),{code:'42501'},sql);
    // Existing raw security-definer capability must not bypass the boundary.
    assert.equal((await runtime.query('SELECT legacy_challenge.destroy_student_owner(41,ARRAY[]::uuid[]) AS removed')).rows[0].removed,0);
    assert.deepEqual((await payload(migration)).rows,before);
    const own = await runtime.query('SELECT * FROM legacy_challenge.synthetic_ai_conversations WHERE user_id = 1');
    assert.equal(own.rows.length,1);
    const injected = await runtime.query('SELECT * FROM legacy_challenge.synthetic_ai_conversations WHERE user_id = 1 OR 1=1');
    assert.equal(injected.rows.length,2);
    assert.deepEqual(injected.rows.map(row=>row.username).sort(),['synthetic-customer','synthetic-support']);
    assert.ok(injected.rows.every(row=>row.platform_owner_id===null && row.model_used==='synthetic-fixture'));
    const privileges = await migration.query(`SELECT
      has_table_privilege('dvaia_legacy_challenge_runtime','legacy_challenge.ai_conversations','SELECT') AS table_read,
      has_any_column_privilege('dvaia_legacy_challenge_runtime','legacy_challenge.ai_conversations','SELECT,INSERT,UPDATE,REFERENCES') AS column_access,
      has_sequence_privilege('dvaia_legacy_challenge_runtime','legacy_challenge.ai_conversations_id_seq','USAGE,SELECT,UPDATE') AS sequence_access`);
    assert.deepEqual(privileges.rows,[{table_read:false,column_access:false,sequence_access:false}]);
    await require('../../server/services/legacyAiTeachingHistoryReadiness').assertLegacyAiTeachingHistoryReadiness({pool:runtime,expectedDatabase:new URL(url('RUNTIME')).pathname.slice(1)});
    await qualifyTeachingHttp(runtime);
  } finally { await Promise.all([runtime.end(),migration.end()]); await fs.rm(prior,{recursive:true,force:true}); }
});


async function qualifyTeachingHttp(runtime) {
  const express=require('express'), vm=require('node:vm');
  const {createLegacyChallengeDb}=require('../../server/database/postgres/legacyChallengeDb');
  const database=createLegacyChallengeDb(runtime);
  const store={engine:'postgres',readConversations(sql,callback){
    database.readConversations(sql).then(rows=>callback(null,rows),error=>callback(error));
  }};
  const dependencies={express,'../database/legacyChallengeStore':store,
    '../services/ollamaService':{getStats:()=>({model:'synthetic-fixture'})},
    '../middleware/workshopMode':{checkVulnerabilityAccess:()=>((req,res,next)=>next())}};
  const filename=path.resolve(__dirname,'../../server/routes/ai.js');
  const exported={exports:{}};
  vm.runInNewContext(await fs.readFile(filename,'utf8'),{module:exported,console,
    require(name){assert.ok(Object.hasOwn(dependencies,name),name);return dependencies[name];}},{filename});
  const app=express();app.use('/api/ai',exported.exports);
  const server=await new Promise(resolve=>{const listener=app.listen(0,'127.0.0.1',()=>resolve(listener));});
  const base=`http://127.0.0.1:${server.address().port}/api/ai`;
  try {
    const own=await fetch(base+'/conversations/1');assert.equal(own.status,200);
    assert.equal((await own.json()).conversations.length,1);
    const injected=await fetch(base+'/conversations/'+encodeURIComponent('1 OR 1=1'));
    assert.equal(injected.status,200);assert.equal((await injected.json()).conversations.length,2);
    const privateRead=await fetch(base+'/conversations/'+encodeURIComponent('1 AND EXISTS (SELECT 1 FROM legacy_challenge.ai_conversations)'));
    assert.equal(privateRead.status,500);assert.deepEqual(await privateRead.json(),{error:'Database error'});
    const admin=await fetch(base+'/admin/conversations');assert.equal(admin.status,200);
    const rows=(await admin.json()).conversations;assert.equal(rows.length,2);
    assert.ok(rows.every(row=>row.username.startsWith('synthetic-')));
  } finally {await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});}
}
