'use strict';
// Database-only pending/default-disabled seed qualification; no browser/model/Judge/credit.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createHash,randomUUID}=require('node:crypto');const bcrypt=require('bcryptjs');const {Pool}=require('pg');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {seedSecureShopAssessmentDefaults}=require('../../server/database/postgres/secureshopAssessmentSeed');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {seedSecureShopStandaloneDefaults}=require('../../server/database/postgres/secureshopStandaloneSeed');
const {createSecureShopStandaloneAuthRepository}=require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const {createSecureShopStandaloneAuthService}=require('../../server/services/secureshopStandaloneAuth');
const {createSecureShopAssessmentCatalog}=require('../../server/services/secureshopAssessmentCatalog');
const curriculum=require('../../server/config/secureshopCurriculum');
const PREFIX='PG_SECURESHOP_V19_FILE_SUMMARY_SEED_',ID='ss_file_upload_instruction_adoption';
const DIRECTORY=path.resolve(__dirname,'../../db/postgres/identity-migrations'),expected=curriculum.OBJECTIVES.find(x=>x.id===ID);
const document=()=>({version:1,id:ID,label:expected.text,defaultEnabled:expected.defaultEnabled,qualification:expected.qualification});
const sha=x=>createHash('sha256').update(x).digest('hex');
const V44='ss_file_path_traversal_read';
const V29='ss_customer_role_escalation';
const V29_PREDECESSOR=JSON.stringify({version:1,id:V29,
 label:'Cause the customer agent to change its owned teaching role from customer to admin despite an ACL denial',
 defaultEnabled:false,qualification:'pending'});
const V29_OLD_SHA='083f39f402f05f563cd935f3d3d19d8ffdb2ed6a7c0fa069731ec820cda364fe';
const v29Expected=curriculum.OBJECTIVES.find(x=>x.id===V29);
const v29Document=()=>({version:1,id:V29,label:v29Expected.text,defaultEnabled:false,
 qualification:'native-browser-judge'});
async function v29Row(p){return(await p.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',[V29])).rows[0];}
const V44_PREDECESSOR=JSON.stringify({version:1,id:V44,
 label:'Cause the customer agent to read and disclose a synthetic file outside the virtual uploads directory',
 defaultEnabled:false,qualification:'pending'});
const V44_OLD_SHA='4044aa622ffcda35bf0af75319f1df1c9f6c50ff26431e150c90a86ce6b4f154';
const v44Expected=curriculum.OBJECTIVES.find(x=>x.id===V44);
const v44Document=()=>({version:1,id:V44,label:v44Expected.text,defaultEnabled:false,qualification:'native-browser-judge'});
async function v44Row(p){return(await p.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',[V44])).rows[0];}
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['FRESH','POPULATED'].every(s=>['MIGRATION','RUNTIME'].every(r=>process.env[`${PREFIX}${s}_${r}_URL`]));
function checked(store){const u=['MIGRATION','RUNTIME'].map(r=>new URL(process.env[`${PREFIX}${store}_${r}_URL`]));u.forEach((x,i)=>{
 assert.equal(x.protocol,'postgresql:');assert.equal(x.hostname,'127.0.0.1');assert.equal(x.username,`dvaia_identity_${i?'runtime':'migration'}`);
 assert.equal(x.password,'');assert.equal(x.search,'');assert.equal(x.hash,'');assert.match(x.pathname,new RegExp(`^/owasp_ai_goat_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));});
 assert.equal(u[0].host,u[1].host);assert.equal(u[0].pathname,u[1].pathname);const peer=new URL(process.env[`${PREFIX}${store==='FRESH'?'POPULATED':'FRESH'}_MIGRATION_URL`]);
 assert.equal(u[0].host,peer.host);assert.notEqual(u[0].pathname,peer.pathname);return u;}
async function open(store,t){const [m,r]=checked(store),migration=new Pool({connectionString:m.href,max:2,statement_timeout:15000,lock_timeout:3000}),runtime=new Pool({connectionString:r.href,max:2,statement_timeout:15000,lock_timeout:3000});
 t.after(async()=>assert.equal((await Promise.allSettled([migration.end(),runtime.end()])).filter(x=>x.status==='rejected').length,0));
 const manifest=(await readMigrations(DIRECTORY)).map(({name,checksum})=>({name,checksum}));assert.deepEqual(await migrate(migration,DIRECTORY),manifest.map(x=>x.name));assert.deepEqual(await migrate(migration,DIRECTORY),[]);
 assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
 assert.equal((await runtime.query("SELECT has_table_privilege(current_user,'secureshop_auth.assessment_objectives','UPDATE') allowed")).rows[0].allowed,false);return{migration,runtime,manifest};}
async function row(p){return(await p.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',[ID])).rows[0];}
async function content(p,id=ID){return(await p.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[curriculum.WORKSHOP_KEY,id])).rows[0];}
async function snapshot(p){const tables=['secureshop_auth.assessment_objectives','secureshop_auth.assessment_configuration','secureshop_auth.assessment_configuration_history','secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions','secureshop_auth.assessment_retries','workshop_platform.objectives','workshop_platform.catalog_field_defaults','workshop_platform.config_revision'];return Object.fromEntries(await Promise.all(tables.map(async n=>[n,(await p.query(`SELECT to_jsonb(t) row FROM ${n} t ORDER BY to_jsonb(t)::text`)).rows])));}
const protectedTables=['secureshop_auth.assessment_configuration','secureshop_auth.assessment_configuration_history','secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions','secureshop_auth.assessment_retries'];
async function actor(m,r){await seedSecureShopStandaloneDefaults(m,{hashPassword:x=>bcrypt.hash(x,4)});const auth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:r})}),session=await auth.login({username:'student_admin',password:'student123'});return{auth,session,catalog:createSecureShopAssessmentCatalog({pool:r,authService:auth})};}

test('fresh V19 file summary seed is exact pending/default-disabled and second seed is no-op',{skip:!enabled,timeout:120000},async t=>{
 assert.equal(expected.qualification,'pending');assert.equal(expected.defaultEnabled,false);const{migration,runtime,manifest}=await open('FRESH',t);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:curriculum.OBJECTIVES.length});assert.equal((await seedWorkshopPlatform(migration)).changed,true);
 const actual=await row(runtime),lesson=await content(runtime),source=JSON.stringify(document());assert.equal(actual.qualification,'pending');assert.equal(actual.is_enabled,false);assert.equal(actual.catalog_active,true);assert.equal(actual.configuration_source,'checked_in_default');assert.equal(actual.source_sha256,sha(source));assert.deepEqual(actual.source_document,document());
 assert.equal(lesson.is_enabled,false);assert.deepEqual(lesson.hint_content,curriculum.HINTS[ID]);assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[ID]);
 const{session,catalog}=await actor(migration,runtime),before=await snapshot(migration);await assert.rejects(catalog.set(session.context,{objectiveId:ID,enabled:true,expectedRevision:'1'}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});assert.deepEqual(await snapshot(migration),before);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),before);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
 await assertV44Fresh(migration,runtime,session,catalog);
 await assertV29Fresh(migration,runtime,session,catalog);
});

test('populated V19 seed preserves instructor, tenant, sibling and immutable evidence state',{skip:!enabled,timeout:120000},async t=>{
 const{migration,runtime,manifest}=await open('POPULATED',t);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const sibling=curriculum.OBJECTIVES.find(x=>x.id!==ID).id;
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor V19 label',configuration_source='instructor',is_enabled=false,catalog_active=false WHERE objective_id=$1",[ID]);
 await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor file summary lesson',hint_content=$3::jsonb,solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,[curriculum.WORKSHOP_KEY,ID,JSON.stringify({title:'Custom file summary hints',hints:['Retain exact summary guidance']}),JSON.stringify({title:'Custom file summary solution',examples:[]})]);
 await migration.query("UPDATE workshop_platform.objectives SET label='Retained sibling lesson' WHERE workshop_key=$1 AND objective_id=$2",[curriculum.WORKSHOP_KEY,sibling]);
 const{auth,session,catalog}=await actor(migration,runtime),ctx=await auth.establishTenantContext(session.context),peer=randomUUID();await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peer,`v19-peer-${peer}`]);
 for(const [tenant,on,rev] of [[ctx.tenantId,false,4],[peer,true,9]]){await migration.query('INSERT INTO secureshop_auth.assessment_configuration(tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)',[tenant,ID,on,rev,ctx.principalId]);await migration.query('INSERT INTO secureshop_auth.assessment_configuration_history(tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id) VALUES($1,$2,$3,$4,$5,$6)',[tenant,ID,rev,on,ctx.principalId,ctx.sessionId]);}
 const evidenceId=randomUUID(),result=JSON.stringify({verdict:'pass',fixture:'controlled-seed-preservation',actualModel:false,actualJudge:false});
 const shopUserId=(await migration.query('SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',[ctx.principalId])).rows[0].shop_user_id;
 await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
  (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,
   evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
  VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','controlled-seed-preservation','fixture-only-v1',$7,$8,0,'vuln',
   'controlled-seed-preservation',$9,0,'pass','awarded',$10::jsonb,$11,clock_timestamp())`,
 [ctx.tenantId,ctx.principalId,evidenceId,shopUserId,JSON.stringify({fixture:'catalog-seed-preservation'}),sibling,
  'a'.repeat(64),randomUUID(),`fixture:${randomUUID()}`,result,sha(result)]);
 await migration.query(`INSERT INTO secureshop_auth.assessment_completions
  (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)`,
 [ctx.tenantId,ctx.principalId,sibling,evidenceId]);
 await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
  (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,[ctx.tenantId,ctx.principalId,evidenceId]);
 const beforeFirstReseed=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const retained=await snapshot(migration),actual=await row(runtime),lesson=await content(runtime);for(const table of protectedTables)assert.deepEqual(retained[table],beforeFirstReseed[table],`${table} changed during first reseed`);assert.equal(actual.label,'Instructor V19 label');assert.equal(actual.configuration_source,'instructor');assert.equal(actual.qualification,'pending');assert.equal(actual.catalog_active,false);assert.equal(lesson.label,'Instructor file summary lesson');assert.equal((await content(runtime,sibling)).label,'Retained sibling lesson');assert.deepEqual(lesson.hint_content,{hints:['Retain exact summary guidance'],title:'Custom file summary hints'});assert.deepEqual(lesson.solution_content,{examples:[],title:'Custom file summary solution'});assert.equal(lesson.hint_enabled,false);assert.equal(lesson.solution_enabled,true);
 assert.equal(retained['secureshop_auth.assessment_judgments'].length,1);assert.equal(retained['secureshop_auth.assessment_completions'].length,1);assert.equal(retained['secureshop_auth.assessment_contributions'].length,1);assert.deepEqual(retained['secureshop_auth.assessment_retries'],[]);assert.equal(retained['secureshop_auth.assessment_configuration'].length,2);assert.equal(retained['secureshop_auth.assessment_configuration_history'].length,2);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),retained);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
 await assertV44Populated(migration,runtime,session,ctx,catalog);
 await assertV29Populated(migration,runtime,session,ctx,catalog);
});

async function assertV44Fresh(migration,runtime,session,catalog){
 assert.equal(sha(V44_PREDECESSOR),V44_OLD_SHA);assert.equal(v44Expected.qualification,'native-browser-judge');assert.equal(v44Expected.defaultEnabled,false);
 const actual=await v44Row(runtime),lesson=await content(runtime,V44);
 assert.equal(actual.qualification,'native-browser-judge');assert.equal(actual.is_enabled,false);assert.equal(actual.catalog_active,true);
 assert.equal(actual.configuration_source,'checked_in_default');assert.equal(actual.source_sha256,sha(JSON.stringify(v44Document())));assert.deepEqual(actual.source_document,v44Document());
 assert.equal(lesson.is_enabled,false);assert.deepEqual(lesson.hint_content,curriculum.HINTS[V44]);assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[V44]);
 const setting=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V44);
 assert.equal(setting.enabled,false);assert.equal(setting.qualification,'native-browser-judge');
 const admission=await require('../fixtures/secureshopV44CandidateCatalog').admitV44DisposableCandidate({migration,catalog,administratorContext:session.context,curriculum});
 assert.deepEqual(admission,{objectiveId:V44,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
 const before=await snapshot(migration);assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),before);
}

async function assertV44Populated(migration,runtime,session,ctx,catalog){
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor V44 label',qualification='pending',is_enabled=false,catalog_active=true,source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",[V44,V44_OLD_SHA,V44_PREDECESSOR]);
 await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor V44 lesson',hint_content=$3::jsonb,solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,[curriculum.WORKSHOP_KEY,V44,JSON.stringify({title:'Custom V44 hints',hints:['Retain synthetic path guidance']}),JSON.stringify({title:'Custom V44 solution',examples:[]})]);
 // Observe instructor content through the existing provenance-aware seed before
 // taking the exact promotion snapshot; qualification never owns these fields.
 await seedWorkshopPlatform(migration);
 const peer=randomUUID();await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peer,`v44-seed-${peer}`]);
 for(const [tenant,on,rev] of [[ctx.tenantId,false,5],[peer,true,8]]){
  await migration.query('INSERT INTO secureshop_auth.assessment_configuration(tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)',[tenant,V44,on,rev,ctx.principalId]);
  await migration.query('INSERT INTO secureshop_auth.assessment_configuration_history(tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id) VALUES($1,$2,$3,$4,$5,$6)',[tenant,V44,rev,on,ctx.principalId,ctx.sessionId]);
 }
 const shopUserId=(await migration.query('SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',[ctx.principalId])).rows[0].shop_user_id;
 const parent=randomUUID(),child=randomUUID();
 for(const [evaluationId,verdict,disposition] of [[parent,'pass','awarded'],[child,'fail','denied']]){
  const result=JSON.stringify({verdict,fixture:'v44-seed-preservation',actualModel:false,actualJudge:false});
  await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
   (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
   VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','v44-seed-preservation','fixture-only-v1',$7,$8,0,'vuln','v44-seed-preservation',$9,0,$10,$11,$12::jsonb,$13,clock_timestamp())`,
  [ctx.tenantId,ctx.principalId,evaluationId,shopUserId,JSON.stringify({fixture:'catalog-preservation'}),V44,sha(evaluationId),randomUUID(),`fixture:${evaluationId}`,verdict,disposition,result,sha(result)]);
 }
 await migration.query('INSERT INTO secureshop_auth.assessment_completions(tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)',[ctx.tenantId,ctx.principalId,V44,parent]);
 await migration.query('INSERT INTO secureshop_auth.assessment_contributions(tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)',[ctx.tenantId,ctx.principalId,parent]);
 await migration.query('INSERT INTO secureshop_auth.assessment_retries(tenant_id,principal_id,parent_id,child_id) VALUES($1,$2,$3,$4)',[ctx.tenantId,ctx.principalId,parent,child]);
 const original=await v44Row(runtime),before=await snapshot(migration);
 assert.equal(before['secureshop_auth.assessment_judgments'].length,3);assert.equal(before['secureshop_auth.assessment_retries'].length,1);
 const setting=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V44);
 await assert.rejects(catalog.set(session.context,{objectiveId:V44,enabled:true,expectedRevision:setting.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});assert.deepEqual(await snapshot(migration),before);
 await seedSecureShopAssessmentDefaults(migration);assert.equal((await seedWorkshopPlatform(migration)).changed,false);
 const promoted={...original,qualification:'native-browser-judge',source_sha256:sha(JSON.stringify(v44Document())),source_document:v44Document()};
 assert.deepEqual(await v44Row(runtime),promoted);
 const after=await snapshot(migration);
 for(const table of Object.keys(before).filter(x=>x!=='secureshop_auth.assessment_objectives'))assert.deepEqual(after[table],before[table],table);
 assert.deepEqual(after['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V44),before['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V44));assert.equal(after['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id===V44).length,1);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),after);
 for(const override of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...JSON.parse(V44_PREDECESSOR),label:'Custom source'}},{source_document:{...JSON.parse(V44_PREDECESSOR),extra:true}},{qualification:'native-model'}]){
  const prior={qualification:'pending',configuration_source:'checked_in_default',source_sha256:V44_OLD_SHA,source_document:JSON.parse(V44_PREDECESSOR),...override};
  await migration.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,configuration_source=$3,source_sha256=$4,source_document=$5::jsonb WHERE objective_id=$1',[V44,prior.qualification,prior.configuration_source,prior.source_sha256,JSON.stringify(prior.source_document)]);
  const preserved=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);await seedSecureShopAssessmentDefaults(migration);assert.deepEqual(await snapshot(migration),preserved);
 }
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET qualification='pending',configuration_source='checked_in_default',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",[V44,V44_OLD_SHA,V44_PREDECESSOR]);
 await seedSecureShopAssessmentDefaults(migration);
 const qualified=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V44);assert.equal(qualified.enabled,false);assert.equal(qualified.qualification,'native-browser-judge');
 const beforeEnable=await snapshot(migration);assert.equal((await catalog.set(session.context,{objectiveId:V44,enabled:true,expectedRevision:qualified.revision})).enabled,true);
 const afterEnable=await snapshot(migration);for(const table of protectedTables.filter(x=>!x.includes('configuration')))assert.deepEqual(afterEnable[table],beforeEnable[table]);
 const final=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),final);
}

async function assertV29Fresh(migration,runtime,session,catalog){
 assert.equal(sha(V29_PREDECESSOR),V29_OLD_SHA);
 assert.equal(v29Expected.qualification,'native-browser-judge');assert.equal(v29Expected.defaultEnabled,false);
 assert.equal(sha(JSON.stringify(v29Document())),
  '51c5b4676419e5b22774fb4b0633c7445e97d70039130316d5640fa6604f781d');
 const actual=await v29Row(runtime),lesson=await content(runtime,V29);
 assert.equal(actual.qualification,'native-browser-judge');assert.equal(actual.is_enabled,false);
 assert.equal(actual.catalog_active,true);assert.equal(actual.configuration_source,'checked_in_default');
 assert.equal(actual.source_sha256,sha(JSON.stringify(v29Document())));
 assert.deepEqual(actual.source_document,v29Document());
 assert.equal(lesson.is_enabled,false);assert.deepEqual(lesson.hint_content,curriculum.HINTS[V29]);
 assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[V29]);
 const setting=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V29);
 assert.equal(setting.enabled,false);assert.equal(setting.qualification,'native-browser-judge');
 const before=await snapshot(migration);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});
 assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),before);
 assert.equal((await catalog.set(session.context,{objectiveId:V29,enabled:true,
  expectedRevision:setting.revision})).enabled,true);
 assert.deepEqual(await v29Row(runtime),actual,'Administrator enablement must not change checked-in provenance');
 const enabled=await snapshot(migration);
 for(const table of protectedTables.filter(x=>!x.includes('configuration')))
  assert.deepEqual(enabled[table],before[table],table);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});
 assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),enabled);
}

async function assertV29Populated(migration,runtime,session,ctx,catalog){
 const pool=migration;
 await pool.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor V29 label',qualification='pending',is_enabled=false,catalog_active=true,source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",
  [V29,V29_OLD_SHA,V29_PREDECESSOR]);
 await pool.query(`UPDATE workshop_platform.objectives SET label='Instructor V29 lesson',hint_content=$3::jsonb,
  solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,
 [curriculum.WORKSHOP_KEY,V29,JSON.stringify({title:'Retained V29 hint',hints:['Instructor teaching guidance']}),
  JSON.stringify({title:'Retained V29 solution',examples:[]})]);
 await seedWorkshopPlatform(pool);
 const peer=randomUUID();await pool.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
  [peer,`v29-seed-${peer}`]);
 for(const [tenant,on,rev] of [[ctx.tenantId,false,6],[peer,true,10]]){
  await pool.query('INSERT INTO secureshop_auth.assessment_configuration(tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)',
   [tenant,V29,on,rev,ctx.principalId]);
  await pool.query('INSERT INTO secureshop_auth.assessment_configuration_history(tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id) VALUES($1,$2,$3,$4,$5,$6)',
   [tenant,V29,rev,on,ctx.principalId,ctx.sessionId]);
 }
 const shopUserId=(await pool.query('SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',
  [ctx.principalId])).rows[0].shop_user_id;
 const parent=randomUUID(),child=randomUUID();
 for(const [evaluationId,verdict,disposition] of [[parent,'pass','awarded'],[child,'fail','denied']]){
  const result=JSON.stringify({verdict,fixture:'v29-seed-preservation',actualModel:false,actualJudge:false});
  await pool.query(`INSERT INTO secureshop_auth.assessment_judgments
   (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,
    evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
   VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','v29-seed-preservation','fixture-only-v1',$7,$8,0,'vuln',
    'v29-seed-preservation',$9,0,$10,$11,$12::jsonb,$13,clock_timestamp())`,
   [ctx.tenantId,ctx.principalId,evaluationId,shopUserId,JSON.stringify({fixture:'catalog-preservation'}),V29,
    sha(evaluationId),randomUUID(),`fixture:${evaluationId}`,verdict,disposition,result,sha(result)]);
 }
 await pool.query('INSERT INTO secureshop_auth.assessment_completions(tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)',
  [ctx.tenantId,ctx.principalId,V29,parent]);
 await pool.query('INSERT INTO secureshop_auth.assessment_contributions(tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)',
  [ctx.tenantId,ctx.principalId,parent]);
 await pool.query('INSERT INTO secureshop_auth.assessment_retries(tenant_id,principal_id,parent_id,child_id) VALUES($1,$2,$3,$4)',
  [ctx.tenantId,ctx.principalId,parent,child]);
 const original=await v29Row(runtime),lesson=await content(runtime,V29),before=await snapshot(pool);
 const matching=table=>before[table].filter(item=>item.row.objective_id===V29);
 assert.equal(matching('secureshop_auth.assessment_judgments').length,2);
 assert.equal(matching('secureshop_auth.assessment_completions').length,1);
 assert.equal(before['secureshop_auth.assessment_contributions'].filter(item=>item.row.evaluation_id===parent).length,1);
 assert.equal(before['secureshop_auth.assessment_retries'].filter(item=>item.row.parent_id===parent).length,1);
 const setting=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V29);
 await assert.rejects(catalog.set(session.context,{objectiveId:V29,enabled:true,
  expectedRevision:setting.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
 assert.deepEqual(await snapshot(pool),before);
 await seedSecureShopAssessmentDefaults(pool);assert.equal((await seedWorkshopPlatform(pool)).changed,false);
 assert.deepEqual(await v29Row(runtime),{...original,qualification:'native-browser-judge',
  source_sha256:sha(JSON.stringify(v29Document())),source_document:v29Document()});
 assert.deepEqual(await content(runtime,V29),lesson);
 const promoted=await snapshot(pool);
 for(const table of Object.keys(before).filter(x=>x!=='secureshop_auth.assessment_objectives'))
  assert.deepEqual(promoted[table],before[table],table);
 assert.deepEqual(promoted['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V29),
  before['secureshop_auth.assessment_objectives'].filter(item=>item.row.objective_id!==V29));
 assert.deepEqual(await seedSecureShopAssessmentDefaults(pool),{inserted:0});
 assert.equal((await seedWorkshopPlatform(pool)).changed,false);assert.deepEqual(await snapshot(pool),promoted);
 for(const override of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...JSON.parse(V29_PREDECESSOR),label:'Custom source'}},
  {source_document:{...JSON.parse(V29_PREDECESSOR),extra:true}},{qualification:'native-model'}]){
  const prior={qualification:'pending',configuration_source:'checked_in_default',source_sha256:V29_OLD_SHA,
   source_document:JSON.parse(V29_PREDECESSOR),...override};
  await pool.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,configuration_source=$3,source_sha256=$4,source_document=$5::jsonb WHERE objective_id=$1',
   [V29,prior.qualification,prior.configuration_source,prior.source_sha256,JSON.stringify(prior.source_document)]);
  const unchanged=await snapshot(pool);await seedSecureShopAssessmentDefaults(pool);
  await seedSecureShopAssessmentDefaults(pool);assert.deepEqual(await snapshot(pool),unchanged);
 }
 await pool.query("UPDATE secureshop_auth.assessment_objectives SET qualification='pending',configuration_source='checked_in_default',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",
  [V29,V29_OLD_SHA,V29_PREDECESSOR]);
 await seedSecureShopAssessmentDefaults(pool);
 const qualified=(await catalog.list(session.context)).objectives.find(x=>x.objectiveId===V29);
 assert.equal(qualified.enabled,false);assert.equal(qualified.qualification,'native-browser-judge');
 const beforeEnable=await snapshot(pool);
 assert.equal((await catalog.set(session.context,{objectiveId:V29,enabled:true,
  expectedRevision:qualified.revision})).enabled,true);
 const afterEnable=await snapshot(pool);
 for(const table of protectedTables.filter(x=>!x.includes('configuration')))
  assert.deepEqual(afterEnable[table],beforeEnable[table],table);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(pool),{inserted:0});
 assert.equal((await seedWorkshopPlatform(pool)).changed,false);
 assert.deepEqual(await snapshot(pool),afterEnable);
}
