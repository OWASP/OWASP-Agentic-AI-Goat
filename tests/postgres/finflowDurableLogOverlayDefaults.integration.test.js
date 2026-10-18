'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createHash}=require('node:crypto');

const sourceRoot=path.resolve(process.env.FINFLOW_LOG_OVERLAY_DEFAULTS_SOURCE_ROOT||path.join(__dirname,'../..'));
const migrationDirectory=path.join(sourceRoot,'db/postgres/identity-migrations');
const name='0058_finflow_durable_log_overlay_tip.sql';
const sql=fs.readFileSync(path.join(migrationDirectory,name),'utf8');
const snapshots=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/finflow-log-overlay-default-snapshots.json'),'utf8'));
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.FINFLOW_LOG_OVERLAY_DEFAULTS_ISOLATED==='1';
const native=enabled?test:test.skip;
const sha=value=>createHash('sha256').update(value).digest('hex');
const clone=value=>JSON.parse(JSON.stringify(value));

function tagged(tag){const marker=`$${tag}$`,start=sql.indexOf(marker),end=sql.indexOf(marker,start+marker.length);
  assert.notEqual(start,-1);assert.notEqual(end,-1);return JSON.parse(sql.slice(start+marker.length,end));}
function url(name,database){const value=new URL(process.env[name]);assert.equal(value.protocol,'postgresql:');
  assert.equal(value.hostname,'127.0.0.1');assert.equal(value.pathname,`/${database}`);return value.href;}
function pool(Pool,value){return new Pool({connectionString:value,max:1,connectionTimeoutMillis:5000,
  statement_timeout:30000,lock_timeout:5000,application_name:'dvaia-finflow-log-overlay-defaults-0058'});}
function migrationCopy(through,corrupt=false){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'finflow-0058-'));
  for(const file of fs.readdirSync(migrationDirectory).filter(file=>/^\d{4}_[a-z0-9_]+\.sql$/.test(file)&&file<=through).sort())
    fs.copyFileSync(path.join(migrationDirectory,file),path.join(directory,file));
  if(corrupt){const copied=path.join(directory,name);fs.chmodSync(copied,0o600);
    fs.writeFileSync(copied,`${sql}\nSELECT * FROM workshop_platform.deliberately_missing_0058;\n`);}
  return directory;}
async function objective(poolValue){return (await poolValue.query(`SELECT solution_content,hint_content,is_enabled,
  catalog_active,hint_enabled,solution_enabled,updated_by FROM workshop_platform.objectives
  WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_modify_logs'`)).rows[0];}
async function revision(poolValue){return Number((await poolValue.query(
  'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);}
async function provenance(poolValue){return (await poolValue.query(`SELECT field_name,provenance_state,source_version,
  source_hash,source_document,applied_default_version,applied_default_hash,applied_default_document,observed_document
  FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective'
   AND workshop_key='sensitive_info_disclosure' AND objective_id='admin_modify_logs'
  ORDER BY field_name`)).rows;}
async function fixturePassword(username){
  return require('bcryptjs').hash(`finflow-0058-${username}`,4);
}
async function seed(poolValue,{solution,hint,username}){
  await poolValue.query(`INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,
    challenge_description,category,difficulty,route,ordinal) VALUES('sensitive_info_disclosure','sensitive-info',
    'Sensitive Information Disclosure','0058 fixture','ai','intermediate','/workshop/sensitive-info',0)`);
  const password=await fixturePassword(username);
  const user=(await poolValue.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`,[username,`${username}@fixture.invalid`,password])).rows[0].id;
  await poolValue.query(`INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,category,ordinal,
    solution_content,hint_content,is_enabled,catalog_active,hint_enabled,solution_enabled,updated_by)
    VALUES('sensitive_info_disclosure','admin_modify_logs','Modify Logs','admin',0,$1::jsonb,$2::jsonb,
    false,true,false,true,$3)`,[solution===null?null:JSON.stringify(solution),hint===null?null:JSON.stringify(hint),user]);
  for(const [field,value] of [['solution_content',solution],['hint_content',hint]])await poolValue.query(`INSERT INTO
    workshop_platform.catalog_field_defaults(entity_kind,workshop_key,objective_id,field_name,provenance_state,
      observed_document) VALUES('objective','sensitive_info_disclosure','admin_modify_logs',$1,'legacy_unknown',$2::jsonb)`,
    [field,JSON.stringify({present:value!==null,value})]);
}

test('0058 is exact-old guarded and matches the server default snapshot',async()=>{
  assert.deepEqual(tagged('prior_default'),snapshots.old);assert.deepEqual(tagged('old_default'),snapshots.expected);
  assert.deepEqual(require(path.join(sourceRoot,'server/data/sensitiveInfoSolutions')).solutions.admin_modify_logs,
    snapshots.expected);
  assert.match(sql,/AND solution_content=\$prior_default\$/);
  assert.match(await fixturePassword('contract'),/^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/);
  const set=sql.match(/SET([\s\S]*?)WHERE workshop_key/)[1];
  assert.doesNotMatch(set,/\b(?:hint_content|is_enabled|catalog_active|hint_enabled|solution_enabled|updated_by)\s*=/);
  assert.match(sql,/EXISTS\(SELECT 1 FROM changed\)/);assert.doesNotMatch(sql,/\b(?:DELETE|TRUNCATE|DROP)\b/);
  const corrupt=migrationCopy(name,true);
  try{assert.match(fs.readFileSync(path.join(corrupt,name),'utf8'),
    /workshop_platform\.deliberately_missing_0058/);}
  finally{fs.rmSync(corrupt,{recursive:true,force:true});}
});

native('0058 real loader preserves custom/NULL fields, toggles and provenance; replay is a no-op and failure rolls back',
  {timeout:180000},async t=>{
  const {Pool}=require('pg'),migrate=require(path.join(sourceRoot,'db/postgres/migrate')).migrate;
  const values=[
    ['POPULATED','dvaia_test_finflow_log_overlay_defaults_populated'],
    ['CUSTOM','dvaia_test_finflow_log_overlay_defaults_custom'],
    ['ROLLBACK','dvaia_test_finflow_log_overlay_defaults_rollback'],
  ];
  const pools={};
  for(const [kind,database] of values){pools[`${kind}R`]=pool(Pool,url(`FINFLOW_LOG_OVERLAY_DEFAULTS_${kind}_DATABASE_URL`,database));
    pools[`${kind}M`]=pool(Pool,url(`FINFLOW_LOG_OVERLAY_DEFAULTS_${kind}_MIGRATION_DATABASE_URL`,database));}
  const directories=[migrationCopy('0057_zzzz.sql'),migrationCopy(name),migrationCopy(name,true)];
  t.after(async()=>{directories.forEach(directory=>fs.rmSync(directory,{recursive:true,force:true}));
    await Promise.allSettled(Object.values(pools).map(value=>value.end()));});

  await migrate(pools.POPULATEDM,directories[0]);
  const customHint={title:'Instructor hint',hints:['Keep exactly.']};
  await seed(pools.POPULATEDM,{solution:snapshots.old,hint:customHint,username:'finflow-0058-populated'});
  const before=await objective(pools.POPULATEDR),beforeProvenance=await provenance(pools.POPULATEDR);
  const beforeRevision=await revision(pools.POPULATEDR);
  assert.deepEqual(await migrate(pools.POPULATEDM,directories[1]),[name]);
  const after=await objective(pools.POPULATEDR);
  assert.deepEqual(after.solution_content,snapshots.expected);assert.deepEqual(after.hint_content,customHint);
  for(const field of ['is_enabled','catalog_active','hint_enabled','solution_enabled','updated_by'])
    assert.equal(after[field],before[field]);
  assert.deepEqual(await provenance(pools.POPULATEDR),beforeProvenance);
  assert.equal(await revision(pools.POPULATEDR),beforeRevision+1);
  const replayRevision=await revision(pools.POPULATEDR);
  assert.deepEqual(await migrate(pools.POPULATEDM,directories[1]),[]);
  assert.equal(await revision(pools.POPULATEDR),replayRevision);

  await migrate(pools.CUSTOMM,directories[0]);
  const customSolution={title:'Instructor custom',tips:['retain']};
  await seed(pools.CUSTOMM,{solution:customSolution,hint:null,username:'finflow-0058-custom'});
  const customBefore=await objective(pools.CUSTOMR),customProvenance=await provenance(pools.CUSTOMR);
  const customRevision=await revision(pools.CUSTOMR);
  assert.deepEqual(await migrate(pools.CUSTOMM,directories[1]),[name]);
  assert.deepEqual(await objective(pools.CUSTOMR),customBefore);assert.deepEqual(await provenance(pools.CUSTOMR),customProvenance);
  assert.equal(await revision(pools.CUSTOMR),customRevision);

  await migrate(pools.ROLLBACKM,directories[0]);
  await seed(pools.ROLLBACKM,{solution:snapshots.old,hint:null,username:'finflow-0058-rollback'});
  const rollbackBefore=await objective(pools.ROLLBACKR),rollbackProvenance=await provenance(pools.ROLLBACKR);
  const rollbackRevision=await revision(pools.ROLLBACKR);
  await assert.rejects(migrate(pools.ROLLBACKM,directories[2]));
  assert.deepEqual(await objective(pools.ROLLBACKR),rollbackBefore);
  assert.deepEqual(await provenance(pools.ROLLBACKR),rollbackProvenance);
  assert.equal(await revision(pools.ROLLBACKR),rollbackRevision);
  assert.equal((await pools.ROLLBACKM.query('SELECT count(*)::integer count FROM dvaia_migrations.ledger WHERE name=$1',[name])).rows[0].count,0);
});
