'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {createSystemConfigReadRepository}=require('../server/database/postgres/secureshopSystemConfigReadRepository');
const sql=fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/schema.candidate.sql','utf8');
const scope=['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id','operation_id'];
// Read the candidate CHECK clauses independently; simulate catalog formatting
// only. Native PostgreSQL remains the required parser/privilege qualification.
function expressions(table){
 const start=sql.indexOf('CREATE TABLE secureshop_agents.bound_system_config_'+table+' (');
 const text=sql.slice(start,sql.indexOf('\n);',start));const found=[];let at=0;
 while((at=text.indexOf('CHECK(',at))!==-1){at+=6;let end=at,depth=1;for(;depth;end++){if(text[end]==='(')depth++;if(text[end]===')')depth--;}
  found.push(text.slice(at,end-1).replace(/\bIN\s*\(([^()]+)\)/g,'= ANY (ARRAY[$1])'));at=end;
 }return found;
}
function fixture(change=()=>{}){
 const calls=[];
 const pool={async query(query,args=[]){calls.push({query,args});const table=args[0]?.replace?.('secureshop_agents.bound_system_config_','');let rows;
  if(query==='SELECT current_user AS role')rows=[{role:'dvaia_secureshop_agents_runtime'}];
  else if(query.includes('has_table_privilege'))rows=[{allowed:args[1]==='SELECT'||args[1]==='INSERT'&&table!=='cleanup_receipts'}];
  else if(query.includes('has_column_privilege'))rows=[{attname:'request_json',writable:false}];
  else if(query.includes('jsonb_to_recordset')||query.includes('FROM pg_proc'))rows=[{ready:true}];
  else if(query.includes('pg_get_expr'))rows=expressions(table).map(expression=>({expression,ready:true}));
  else if(query.includes('AND attnotnull'))rows=(table==='cleanup_receipts'?['cleanup_id','cleanup_kind','original_platform_owner_id','admission_count','outcome_count','receipt_sha256']:[...scope,'persona_id','persona_session_id','persona_role','authority_version','request_sha256','binding_sha256',...(table==='outcomes'?['state']:[])]).map(attname=>({attname}));
  else if(query.includes("contype IN ('p','f')")){assert.equal((query.match(/SELECT attname::text FROM unnest/g)||[]).length,2);rows=[{contype:'p',ready:true,columns:table==='cleanup_receipts'?['cleanup_id']:scope}];if(table==='outcomes')rows.push({contype:'f',ready:true,target:'secureshop_agents.bound_system_config_admissions',columns:scope,target_columns:scope,confdeltype:'a',confupdtype:'a'});}
  else throw Error('Unexpected readiness query');
  change({query,args,rows});return {rows};
 }};
 return {calls,repo:createSystemConfigReadRepository({pool,personaAuthority:{capture(){}},audit:{append(){}}})};
}
test('candidate readiness requires all declared constraints, keys, authority triggers and private functions',async()=>{
 const f=fixture();assert.deepEqual(await f.repo.checkReadiness(),{ready:true});
 assert.equal(f.calls.filter(x=>x.query.includes('has_table_privilege')).length,21);
 for(const match of ['jsonb_to_recordset','FROM pg_proc','pg_get_expr','AND attnotnull',"contype IN ('p','f')"]){
  const bad=fixture(({query,rows})=>{if(query.includes(match)){if(match==='AND attnotnull')rows.pop();else if(match==='pg_get_expr')rows[0].expression='true';else rows[0].ready=false;}});
  await assert.rejects(bad.repo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});
 }
});
test('each required or forbidden table privilege and column update drift fails closed',async()=>{
 for(const table of ['admissions','outcomes','cleanup_receipts'])for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']){
  const f=fixture(({query,args,rows})=>{if(query.includes('has_table_privilege')&&args[0].endsWith('_'+table)&&args[1]===privilege)rows[0].allowed=!rows[0].allowed;});
  await assert.rejects(f.repo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});
 }
 await assert.rejects(fixture(({query,rows})=>{if(query.includes('has_column_privilege'))rows[0].writable=true;}).repo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});
 await assert.rejects(fixture(({query,rows})=>{if(query==='SELECT current_user AS role')rows[0].role='dvaia_secureshop_agents_migration';}).repo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});
});

test('readiness pins the forward guard body while preserving the original candidate bytes',async()=>{
 const {createHash}=require('node:crypto');
 const correction=fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/retirement-guard.correction.sql','utf8');
 const bodyHash=createHash('sha256').update(correction.split('$$')[1]).digest('hex');
 const f=fixture();await f.repo.checkReadiness();assert.ok(f.calls.find(x=>x.query.includes('FROM pg_proc')).query.includes(bodyHash));
 assert.equal(createHash('sha256').update(sql).digest('hex'),'763f74019607563acff42399add166a5e9f5bbf4e70276c34404795b13416ee9');
 assert.match(correction,/IF TG_TABLE_NAME='bound_system_config_admissions' THEN\s+IF NEW.request_json/);
 assert.match(correction,/ELSIF TG_TABLE_NAME='bound_system_config_outcomes' THEN\s+IF NEW.receipt_json/);
});

test('registered migration files preserve both qualified SQL byte sequences',()=>{
 for(const [draft,name] of [['schema.candidate.sql','0028_system_config_candidate.sql'],['retirement-guard.correction.sql','0029_system_config_retirement_guard.sql']])assert.deepEqual(fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/'+draft),fs.readFileSync('db/postgres/workshop-migrations/secureshop_agents/'+name));
});
