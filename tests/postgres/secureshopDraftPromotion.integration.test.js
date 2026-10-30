'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {createHash,randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const bcrypt=require('bcryptjs');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const PREFIX='PG_SECURESHOP_DRAFT_PROMOTION_';
const variants=['FRESH','POPULATED'],stores=['IDENTITY','AGENTS','REVIEW'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&variants.every(v=>stores.every(s=>
 process.env[`${PREFIX}${v}_${s}_MIGRATION_URL`]&&process.env[`${PREFIX}${v}_${s}_RUNTIME_URL`]));
const root=path.join(__dirname,'../..');
async function sql(relative){return fs.readFile(path.join(root,relative),'utf8');}
const digest=value=>createHash('sha256').update(value).digest('hex');
function pools(variant){return Object.fromEntries(stores.map(store=>[store.toLowerCase(),{
 migration:new Pool({connectionString:process.env[`${PREFIX}${variant}_${store}_MIGRATION_URL`],max:2}),
 runtime:new Pool({connectionString:process.env[`${PREFIX}${variant}_${store}_RUNTIME_URL`],max:4})}]));}
const storeDefinition={
 identity:{baseline:'db/postgres/identity-migrations',manifestStore:'identity'},
 agents:{baseline:'db/postgres/workshop-migrations/secureshop_agents',manifestStore:'secureshop_agents'},
 review:{baseline:'db/postgres/workshop-migrations/secureshop_review',manifestStore:'secureshop_review'},
};
async function stageMigrations(manifest){
 const stage=await fs.mkdtemp(path.join(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE||os.tmpdir(),'secureshop-promotion-migrations-'));
 for(const [store,definition] of Object.entries(storeDefinition)){
  const destination=path.join(stage,store);await fs.mkdir(destination);
  for(const name of await fs.readdir(path.join(root,definition.baseline))){
   if(name.endsWith('.sql'))await fs.copyFile(path.join(root,definition.baseline,name),path.join(destination,name));
  }
  for(const entry of manifest.order.filter(row=>row.store===definition.manifestStore)){
   assert.match(entry.promotionName,/^\d{4}_[a-z0-9_]+\.sql$/);
   await fs.copyFile(path.join(root,'docs/modernization/drafts',entry.file),path.join(destination,entry.promotionName));
  }
 }
 return stage;
}
async function assertLedger(pool,directory){
 const expected=await readMigrations(directory);
 const actual=(await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(actual,expected.map(({name,checksum})=>({name,checksum})));
}

test('draft promotion order preserves fresh and populated store state',{skip:!enabled,timeout:60000},async()=>{
 const manifest=JSON.parse(await sql('docs/modernization/drafts/secureshop-promotion-manifest-2026-09-13.json'));
 for(const entry of manifest.order){const body=await sql(`docs/modernization/drafts/${entry.file}`);assert.equal(digest(body),entry.sha256);}
 const stage=await stageMigrations(manifest);
 try{for(const variant of variants){
  const db=pools(variant),populated=variant==='POPULATED';
  try{
   if(populated)for(const [store,definition] of Object.entries(storeDefinition)){
    const applied=await migrate(db[store].migration,path.join(root,definition.baseline));
    assert.deepEqual(applied,(await readMigrations(path.join(root,definition.baseline))).map(row=>row.name));
   }
   let legacy;
   if(populated){
    legacy={user:101,session:randomUUID(),target:randomUUID(),launch:randomUUID(),scenario:randomUUID()};
    await db.identity.migration.query(`INSERT INTO identity.users(id,username,email,password)
      VALUES($1,$2,$3,$4)`,[legacy.user,`legacy-${randomUUID()}`,`${randomUUID()}@legacy.invalid`,
      await bcrypt.hash('owned-promotion-fixture',4)]);
    await db.identity.migration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal) VALUES('legacy_fixture','legacy-fixture','Legacy fixture',990)`);
    await db.identity.migration.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,ordinal) VALUES('legacy_fixture','legacy-objective','Legacy objective',1)`);
    await db.identity.migration.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key)
      VALUES($1,'legacy_fixture')`,[legacy.user]);
    await db.identity.migration.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
      VALUES($1,'legacy_fixture','legacy-objective')`,[legacy.user]);
    await db.identity.migration.query(`INSERT INTO workshop_platform.time_tracking
      (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
      VALUES($1,'legacy_fixture',now(),now(),37)`,[legacy.user]);
    await db.identity.migration.query(`INSERT INTO workshop_platform.activity_counters
      (user_id,workshop_key,activity_key,activity_count) VALUES($1,'legacy_fixture','legacy',4)`,[legacy.user]);
    await db.agents.migration.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,messages_json,token_budget_used) VALUES($1,77,'customer',$2,9)`,
    [legacy.session,JSON.stringify([{role:'user',content:'preserve me'}])]);
    await db.agents.migration.query(`INSERT INTO secureshop_agents.agent_trace
      (session_id,step,actor,kind,result_json) VALUES($1,1,'fixture','final',$2)`,[legacy.session,'{"ok":true}']);
    await db.review.migration.query(`INSERT INTO secureshop_review.review_targets
      (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
       original_platform_session_id,seed_count,seed_sha256)
      VALUES($1,$2,$3,1,101,201,1,decode($4,'hex'))`,[legacy.target,legacy.launch,legacy.scenario,'11'.repeat(32)]);
    await db.review.migration.query(`INSERT INTO secureshop_review.reviews
      (target_id,product_id,author_id,body,rating) VALUES($1,1,9,'legacy review bytes',5)`,[legacy.target]);
   }
   for(const [store,definition] of Object.entries(storeDefinition)){
    const expected=(await readMigrations(path.join(stage,store))).map(row=>row.name);
    const baselineCount=populated?(await readMigrations(path.join(root,definition.baseline))).length:0;
    assert.deepEqual(await migrate(db[store].migration,path.join(stage,store)),expected.slice(baselineCount));
    assert.deepEqual(await migrate(db[store].migration,path.join(stage,store)),[],'second migration pass is a no-op');
    await assertLedger(db[store].migration,path.join(stage,store));
   }
   for(const [store,names] of Object.entries({identity:['secureshop_target_cleanup_history','secureshop_progress_cleanup_history','secureshop_conversation_cleanup_history'],
    agents:['turn_requests','conversation_generation_retirements'],review:['reviews']})){
    const schema=store==='identity'?'identity':`secureshop_${store}`;
    for(const name of names)assert.equal((await db[store].runtime.query('SELECT to_regclass($1) IS NOT NULL AS ready',[`${schema}.${name}`])).rows[0].ready,true);
   }
   assert.equal((await db.identity.runtime.query(`SELECT 1 FROM workshop_platform.exercises
     WHERE workshop_key='secureshop_agent_security'`)).rowCount,0,'catalog activation remains explicit');
   if(!populated){
    const catalog={hidden_fixture:[{id:'hidden-objective',text:'Hidden objective',defaultEnabled:false}]};
    const challenges=[{key:'hidden_fixture',name:'Hidden fixture',defaultVisible:false}];
    await seedWorkshopPlatform(db.identity.runtime,{catalog,hints:{},solutions:{},challenges});
    assert.deepEqual((await db.identity.runtime.query(`SELECT e.is_visible,o.is_enabled FROM workshop_platform.exercises e
      JOIN workshop_platform.objectives o USING(workshop_key) WHERE e.workshop_key='hidden_fixture'`)).rows[0],
    {is_visible:false,is_enabled:false});
    await db.identity.runtime.query(`UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='hidden_fixture'`);
    await db.identity.runtime.query(`UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='hidden_fixture'`);
    await seedWorkshopPlatform(db.identity.runtime,{catalog,hints:{},solutions:{},challenges});
    assert.deepEqual((await db.identity.runtime.query(`SELECT e.is_visible,o.is_enabled FROM workshop_platform.exercises e
      JOIN workshop_platform.objectives o USING(workshop_key) WHERE e.workshop_key='hidden_fixture'`)).rows[0],
    {is_visible:true,is_enabled:true},'reseed preserves instructor choices');
   }
   if(populated){
    assert.deepEqual((await db.identity.runtime.query(`SELECT c.objective_id,t.duration_seconds,a.activity_count
      FROM workshop_platform.completions c JOIN workshop_platform.time_tracking t USING(user_id,workshop_key)
      JOIN workshop_platform.activity_counters a USING(user_id,workshop_key)
      WHERE c.user_id=$1`,[legacy.user])).rows[0],
    {objective_id:'legacy-objective',duration_seconds:37,activity_count:4});
    const session=(await db.agents.runtime.query(`SELECT authority_mode,binding_state,messages_json,
      token_budget_used FROM secureshop_agents.agent_sessions WHERE id=$1`,[legacy.session])).rows[0];
    assert.deepEqual(session,{authority_mode:'legacy',binding_state:'active',messages_json:JSON.stringify([{role:'user',content:'preserve me'}]),token_budget_used:9});
    const review=(await db.review.runtime.query(`SELECT body,source_kind,submission_id
      FROM secureshop_review.reviews WHERE target_id=$1`,[legacy.target])).rows[0];
    assert.deepEqual(review,{body:'legacy review bytes',source_kind:'fixture',submission_id:null});
    await db.identity.runtime.query(`INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id) VALUES($1,'legacy_fixture','legacy-objective') ON CONFLICT DO NOTHING`,[legacy.user]);
   }
  }finally{await Promise.all(Object.values(db).flatMap(value=>[value.runtime.end(),value.migration.end()]));}
 }}finally{await fs.rm(stage,{recursive:true,force:true});}
});
