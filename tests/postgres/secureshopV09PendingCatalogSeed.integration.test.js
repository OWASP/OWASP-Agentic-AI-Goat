'use strict';
// Database-only qualified/default-disabled seed qualification; no browser/model/Judge/credit.
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
const PREFIX='PG_SECURESHOP_V09_MAIL_HTML_SEED_',ID='ss_mail_agent_html_injection';
const DIRECTORY=path.resolve(__dirname,'../../db/postgres/identity-migrations'),expected=curriculum.OBJECTIVES.find(x=>x.id===ID);
const document=()=>({version:1,id:ID,label:expected.text,defaultEnabled:expected.defaultEnabled,qualification:expected.qualification});
const sha=x=>createHash('sha256').update(x).digest('hex');
const PREDECESSOR='{"version":1,"id":"ss_mail_agent_html_injection","label":"Cause the merchant assistant to send raw HTML that is structurally mounted in the owned Inbox component","defaultEnabled":false,"qualification":"pending"}';
const PREDECESSOR_SHA='64dfcfe0bfadf473b17e4c71fe848fa2252ce334560ccccb14194ea2786531f2';
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
function assertFirstReseedPreserved(before,after,sibling){
 const ledger='workshop_platform.catalog_field_defaults';
 assert.deepEqual(Object.keys(after).sort(),Object.keys(before).sort());
 for(const table of Object.keys(before))if(table!==ledger)assert.equal(sha(JSON.stringify(after[table])),sha(JSON.stringify(before[table])),`${table} changed on first reseed`);
 const key=row=>JSON.stringify([row.entity_kind,row.workshop_key,row.objective_id,row.field_name]);
 const prior=new Map(before[ledger].map(({row})=>[key(row),row])),current=new Map(after[ledger].map(({row})=>[key(row),row]));
 assert.equal(prior.size,before[ledger].length);assert.equal(current.size,after[ledger].length);assert.deepEqual([...current.keys()].sort(),[...prior.keys()].sort());
 const changed=new Set([[ID,'label'],[ID,'hint_content'],[ID,'solution_content'],[sibling,'label']].map(([objective,field])=>JSON.stringify(['objective',curriculum.WORKSHOP_KEY,objective,field])));
 for(const [identity,previous] of prior){const actual=current.get(identity);
  if(!changed.has(identity)){assert.equal(sha(JSON.stringify(actual)),sha(JSON.stringify(previous)),`Unexpected provenance change ${identity}`);continue;}
  assert.equal(previous.provenance_state,'managed');assert.equal(actual.provenance_state,'custom');
  const lesson=before['workshop_platform.objectives'].find(({row})=>row.workshop_key===previous.workshop_key&&row.objective_id===previous.objective_id)?.row;
  assert.ok(lesson);assert.ok(Number.isFinite(Date.parse(actual.updated_at))&&Date.parse(actual.updated_at)>=Date.parse(previous.updated_at));
  const expected={...previous,provenance_state:'custom',observed_document:{present:true,value:lesson[previous.field_name]},updated_at:actual.updated_at};
  assert.deepEqual(actual,expected,`Unexpected managed-to-custom provenance transition ${identity}`);changed.delete(identity);
 }
 assert.equal(changed.size,0,'All four edited field provenance records must reconcile');
}
function assertQualifiedPromotion(before,after){
 const table='secureshop_auth.assessment_objectives';
 assert.deepEqual(Object.keys(after).sort(),Object.keys(before).sort());
 for(const name of Object.keys(before))if(name!==table)assert.equal(sha(JSON.stringify(after[name])),sha(JSON.stringify(before[name])),`${name} changed during qualification promotion`);
 const prior=before[table].find(({row})=>row.objective_id===ID)?.row;
 assert.ok(prior);assert.equal(prior.qualification,'pending');assert.equal(prior.configuration_source,'checked_in_default');
 assert.equal(prior.source_sha256,PREDECESSOR_SHA);assert.deepEqual(prior.source_document,JSON.parse(PREDECESSOR));
 const expectedRow={...prior,qualification:'native-browser-judge',source_sha256:sha(JSON.stringify(document())),source_document:document()};
 assert.deepEqual(after[table].filter(({row})=>row.objective_id===ID),[{row:expectedRow}]);
 assert.equal(sha(JSON.stringify(after[table].filter(({row})=>row.objective_id!==ID))),sha(JSON.stringify(before[table].filter(({row})=>row.objective_id!==ID))),'sibling assessment rows changed during qualification promotion');
}
async function actor(m,r){await seedSecureShopStandaloneDefaults(m,{hashPassword:x=>bcrypt.hash(x,4)});const auth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:r})}),session=await auth.login({username:'student_admin',password:'student123'});return{auth,session,catalog:createSecureShopAssessmentCatalog({pool:r,authService:auth})};}

test('fresh V09 mail HTML injection seed is exact native-browser-Judge/default-disabled and second seed is no-op',{skip:!enabled,timeout:120000},async t=>{
 assert.equal(sha(PREDECESSOR),PREDECESSOR_SHA);assert.equal(expected.qualification,'native-browser-judge');assert.equal(expected.defaultEnabled,false);const{migration,runtime,manifest}=await open('FRESH',t);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:curriculum.OBJECTIVES.length});assert.equal((await seedWorkshopPlatform(migration)).changed,true);
 const actual=await row(runtime),lesson=await content(runtime),source=JSON.stringify(document());assert.equal(actual.qualification,'native-browser-judge');assert.equal(actual.is_enabled,false);assert.equal(actual.catalog_active,true);assert.equal(actual.configuration_source,'checked_in_default');assert.equal(actual.source_sha256,sha(source));assert.deepEqual(actual.source_document,document());
 assert.equal(lesson.is_enabled,false);assert.deepEqual(lesson.hint_content,curriculum.HINTS[ID]);assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[ID]);
 const{session,catalog}=await actor(migration,runtime),setting=(await catalog.list(session.context)).objectives.find(row=>row.objectiveId===ID);assert.equal(setting.qualification,'native-browser-judge');assert.equal(setting.enabled,false);const permitted=await catalog.set(session.context,{objectiveId:ID,enabled:true,expectedRevision:setting.revision});assert.equal(permitted.enabled,true);assert.equal(permitted.qualification,'native-browser-judge');const before=await snapshot(migration);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),before);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
});

test('populated V09 seed preserves instructor, tenant, sibling and immutable evidence state',{skip:!enabled,timeout:120000},async t=>{
 const{migration,runtime,manifest}=await open('POPULATED',t);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const sibling='ss_mail_stored_browser_execution';assert.ok(curriculum.OBJECTIVES.some(x=>x.id===sibling));
 // Model qualification was established separately. This owned-store predecessor
 // fixture proves only the exact supported seed upgrade and preservation boundary.
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET label='Retained recognized V09 instructor label',qualification='pending',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",[ID,PREDECESSOR_SHA,PREDECESSOR]);
 const pendingBefore=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);assertQualifiedPromotion(pendingBefore,await snapshot(migration));
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor V09 mail HTML label',configuration_source='instructor',is_enabled=false,catalog_active=false,qualification='pending',source_sha256=$2,source_document=$3::jsonb WHERE objective_id=$1",[ID,PREDECESSOR_SHA,PREDECESSOR]);
 await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor mail HTML injection lesson',hint_content=$3::jsonb,solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,[curriculum.WORKSHOP_KEY,ID,JSON.stringify({title:'Custom mail HTML injection hints',hints:['Retain exact raw HTML guidance']}),JSON.stringify({title:'Custom mail HTML injection solution',examples:[]})]);
 await migration.query("UPDATE workshop_platform.objectives SET label='Retained sibling lesson' WHERE workshop_key=$1 AND objective_id=$2",[curriculum.WORKSHOP_KEY,sibling]);
 const{auth,session}=await actor(migration,runtime),ctx=await auth.establishTenantContext(session.context),peer=randomUUID();await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peer,`v09-peer-${peer}`]);
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
 const beforeFirstReseed=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const retained=await snapshot(migration),actual=await row(runtime),lesson=await content(runtime);assertFirstReseedPreserved(beforeFirstReseed,retained,sibling);for(const table of protectedTables)assert.deepEqual(retained[table],beforeFirstReseed[table],`${table} changed during first reseed`);assert.equal(actual.label,'Instructor V09 mail HTML label');assert.equal(actual.configuration_source,'instructor');assert.equal(actual.qualification,'pending');assert.equal(actual.catalog_active,false);assert.equal(lesson.label,'Instructor mail HTML injection lesson');assert.equal((await content(runtime,sibling)).label,'Retained sibling lesson');assert.deepEqual(lesson.hint_content,{hints:['Retain exact raw HTML guidance'],title:'Custom mail HTML injection hints'});assert.deepEqual(lesson.solution_content,{examples:[],title:'Custom mail HTML injection solution'});assert.equal(lesson.hint_enabled,false);assert.equal(lesson.solution_enabled,true);
 assert.equal(retained['secureshop_auth.assessment_judgments'].length,1);assert.equal(retained['secureshop_auth.assessment_completions'].length,1);assert.equal(retained['secureshop_auth.assessment_contributions'].length,1);assert.deepEqual(retained['secureshop_auth.assessment_retries'],[]);assert.equal(retained['secureshop_auth.assessment_configuration'].length,2);assert.equal(retained['secureshop_auth.assessment_configuration_history'].length,2);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),retained);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
 // Fail closed for source-only near matches and instructor-owned rows.
 for(const override of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...JSON.parse(PREDECESSOR),label:'Different source'}},
  {source_document:{...JSON.parse(PREDECESSOR),extra:true}}]){
  const value={qualification:'pending',configuration_source:'checked_in_default',source_sha256:PREDECESSOR_SHA,source_document:JSON.parse(PREDECESSOR),...override};
  await migration.query('UPDATE secureshop_auth.assessment_objectives SET qualification=$2,configuration_source=$3,source_sha256=$4,source_document=$5::jsonb WHERE objective_id=$1',[ID,value.qualification,value.configuration_source,value.source_sha256,JSON.stringify(value.source_document)]);
  const unchanged=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);await seedSecureShopAssessmentDefaults(migration);
  const unchangedAfter=await snapshot(migration);for(const name of Object.keys(unchanged))assert.equal(sha(JSON.stringify(unchangedAfter[name])),sha(JSON.stringify(unchanged[name])),`${name}: near-match predecessor changed`);
 }

});
