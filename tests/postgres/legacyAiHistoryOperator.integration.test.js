'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const prefix='PG_HISTORY_OPERATOR_';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env[prefix+'SOURCE_URL']&&process.env[prefix+'TARGET_URL'];
function url(key,role){const value=new URL(process.env[prefix+key]);assert.equal(value.hostname,'127.0.0.1');assert.match(value.pathname,/^\/dvaia_test_history_operator_[a-f0-9]+$/);assert.equal(value.username,role);assert.equal(value.search,'');assert.equal(value.hash,'');return value.href;}
test('operator plan, archive and cleanup preserve unknown history and support explicit replay', {skip:!enabled,timeout:30000},async()=>{
 const sourceUrl=url('SOURCE_URL','dvaia_legacy_challenge_migration'),targetUrl=url('TARGET_URL','dvaia_identity_migration');
 const source=new Pool({connectionString:sourceUrl}),target=new Pool({connectionString:targetUrl});
 const directory=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-operator-native-')));
 try{
  await migrate(source,path.resolve(__dirname,'../../db/postgres/workshop-migrations/legacy_challenge'));
  await migrate(target,path.resolve(__dirname,'../../db/postgres/identity-migrations'));
  await source.query("INSERT INTO legacy_challenge.ai_conversations(id,user_id,prompt,response,created_at,platform_owner_id) VALUES(41,7,$1,NULL,'2026-01-02T03:04:05.123456Z',7),(42,NULL,'unknown owner','retained',NULL,NULL)",['private operator qualification 🎓']);
  const before=(await source.query('SELECT jsonb_agg(to_jsonb(row) ORDER BY id) rows FROM legacy_challenge.ai_conversations row')).rows;
  const execFile=require('node:util').promisify(require('node:child_process').execFile);
  const operator={async execute({command,planPath,receiptPath}){
    const args=[path.resolve(__dirname,'../../scripts/legacy-ai-history-cutover.js'),command,'--plan-file',planPath];
    if(receiptPath)args.push('--receipt-file',receiptPath);
    const result=await execFile(process.execPath,args,{timeout:15000,maxBuffer:65536,
      env:{PATH:'/usr/bin:/bin',LEGACY_CHALLENGE_MIGRATION_DATABASE_URL:sourceUrl,IDENTITY_MIGRATION_DATABASE_URL:targetUrl}});
    assert.equal(result.stderr,'');return JSON.parse(result.stdout);
  }};
  const planPath=path.join(directory,'plan.json'),receiptPath=path.join(directory,'receipt.json');
  await operator.execute({command:'plan',planPath});
  assert.equal((await fs.stat(planPath)).mode&0o777,0o600);
  assert.doesNotMatch(await fs.readFile(planPath,'utf8'),/private operator qualification|retained/);
  assert.equal((await target.query('SELECT count(*)::int n FROM legacy_ai_private.import_archive')).rows[0].n,0);
  await source.query("UPDATE legacy_challenge.ai_conversations SET prompt='changed since review' WHERE id=41");
  await assert.rejects(operator.execute({command:'quarantine',planPath,receiptPath}),error=>{
    assert.doesNotMatch(error.stderr||'',/changed since review|postgresql:\/\//);return true;
  });
  assert.equal((await target.query('SELECT count(*)::int n FROM legacy_ai_private.import_archive')).rows[0].n,0);
  await source.query('UPDATE legacy_challenge.ai_conversations SET prompt=$1 WHERE id=41',['private operator qualification 🎓']);
  await operator.execute({command:'quarantine',planPath,receiptPath});
  assert.deepEqual((await source.query('SELECT jsonb_agg(to_jsonb(row) ORDER BY id) rows FROM legacy_challenge.ai_conversations row')).rows,before);
  assert.equal((await target.query('SELECT count(*)::int n FROM legacy_ai_private.import_archive')).rows[0].n,2);
  assert.equal((await target.query('SELECT count(*)::int n FROM legacy_ai_private.history')).rows[0].n,0);
  const receipt=await fs.readFile(receiptPath,'utf8');
  await operator.execute({command:'quarantine',planPath,receiptPath});
  assert.equal(await fs.readFile(receiptPath,'utf8'),receipt);
  await operator.execute({command:'cleanup',planPath,receiptPath});
  assert.equal((await source.query('SELECT count(*)::int n FROM legacy_challenge.ai_conversations')).rows[0].n,0);
  await operator.execute({command:'cleanup',planPath,receiptPath});
  assert.equal((await source.query('SELECT count(*)::int n FROM legacy_ai_source_cleanup.receipts')).rows[0].n,1);
  assert.equal((await target.query('SELECT count(*)::int n FROM legacy_ai_private.import_archive')).rows[0].n,2);
  assert.equal((await source.query('SELECT count(*)::int n FROM legacy_challenge.synthetic_ai_conversations')).rows[0].n,2);
 }finally{await Promise.all([source.end(),target.end()]);await fs.rm(directory,{recursive:true,force:true});}
});
