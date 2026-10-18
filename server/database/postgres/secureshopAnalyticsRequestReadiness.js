'use strict';
const fs=require('node:fs'),path=require('node:path');
const fail=()=>Object.assign(Error('Owned Analytics request store unavailable'),{code:'ANALYTICS_NOT_READY'});
const TABLE='secureshop_agents.analytics_request_admissions';
const fields=[['launch_id','uuid'],['scenario_id','uuid'],['generation','bigint'],['platform_owner_id','integer'],['platform_session_id','bigint'],['persona_id','integer'],['role','text'],['request_id','uuid'],['persona_session_id','uuid'],['authority_version','bigint'],['session_id','text'],['question_sha256','text'],['question','text'],['created_at','timestamp with time zone'],['redacted_at','timestamp with time zone']];
const normalized=value=>value.replace(/::text/g,'').replace(/[\s()]/g,'').toLowerCase();
const checks=['generation>0','platform_owner_id>0','platform_session_id>0','persona_id>0',"role=ANYARRAY['merchant','admin']",'authority_version>0',"question_sha256~'^[a-f0-9]{64}$'",'question IS NULL OR octet_length(question)>0 AND octet_length(question)<=8192','question IS NULL = redacted_at IS NOT NULL'].map(normalized).sort();
async function assertAnalyticsRequestReadiness(pool,{requiredVersion=1}={}){
 if(![1,2].includes(requiredVersion))throw TypeError('Unsupported Analytics request schema version');
 const activeFields=requiredVersion===2?[...fields,['mode_snapshot','jsonb']]:fields;
 if(typeof pool?.query!=='function')throw TypeError('Analytics request pool required');
 const identity=(await pool.query('SELECT current_user AS role')).rows[0];if(identity?.role!=='dvaia_secureshop_agents_runtime')throw fail();
 for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])if((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[TABLE,privilege])).rows[0]?.allowed!==['SELECT','INSERT'].includes(privilege))throw fail();
 const columns=(await pool.query(`SELECT attname,format_type(atttypid,atttypmod) AS type,attnotnull,has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum`,[TABLE])).rows;
 if(columns.length!==activeFields.length||columns.some((c,i)=>c.attname!==activeFields[i][0]||c.type!==activeFields[i][1]||c.writable||c.attnotnull!==!['question','redacted_at','mode_snapshot'].includes(c.attname)))throw fail();
 const constraints=(await pool.query(`SELECT conname,contype,pg_get_expr(conbin,conrelid) AS expression,convalidated,ARRAY(SELECT attname::text FROM unnest(conkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=conrelid AND a.attnum=k.num ORDER BY k.ord) AS columns,confrelid::regclass::text AS referenced FROM pg_constraint WHERE conrelid=$1::regclass`,[TABLE])).rows;
 if(constraints.some(c=>!c.convalidated)||JSON.stringify(constraints.filter(c=>c.contype==='c'&&!(requiredVersion===2&&c.conname==='analytics_admission_mode_shape')).map(c=>normalized(c.expression)).sort())!==JSON.stringify(checks))throw fail();
 const key=type=>constraints.filter(c=>c.contype===type);
 if(key('p').length!==1||JSON.stringify(key('p')[0].columns)!==JSON.stringify(fields.slice(0,8).map(f=>f[0]))||key('u').length!==1||JSON.stringify(key('u')[0].columns)!==JSON.stringify(['session_id','request_id'])||key('f').length!==1||JSON.stringify(key('f')[0].columns)!==JSON.stringify(['session_id'])||key('f')[0].referenced!=='secureshop_agents.agent_sessions')throw fail();
 const names=['analytics_request_admission_guard','analytics_request_retirement','analytics_request_owner_delete'];
 const triggers=(await pool.query(`SELECT tgname,tgrelid::regclass::text AS relation,tgenabled,tgtype,p.proname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE NOT tgisinternal AND tgname=ANY($1::text[]) ORDER BY tgname`,[names])).rows;
 const expected=[['analytics_request_admission_guard',TABLE,'guard_analytics_request_admission',31],['analytics_request_owner_delete','secureshop_agents.bound_audit_owner_deletion_receipts','cleanup_analytics_request_admissions',5],['analytics_request_retirement','secureshop_agents.conversation_generation_retirements','cleanup_analytics_request_admissions',5]];
 if(triggers.length!==3||triggers.some((t,i)=>t.tgname!==expected[i][0]||t.relation!==expected[i][1]||t.proname!==expected[i][2]||t.tgtype!==expected[i][3]||!['O','A'].includes(t.tgenabled)))throw fail();
 for(const name of ['guard_analytics_request_admission','cleanup_analytics_request_admissions']){
  const successor=name==='guard_analytics_request_admission';
  const sql=fs.readFileSync(path.join(__dirname,`../../../db/postgres/workshop-migrations/secureshop_agents/${successor?'0052_analytics_registered_actor_admission.sql':'0032_analytics_request_admission.sql'}`),'utf8');
  const marker=`CREATE${successor?' OR REPLACE':''} FUNCTION secureshop_agents.${name}()`,start=sql.indexOf(marker);
  if(start<0)throw fail();
  const body=sql.slice(sql.indexOf('$$',start)+2,sql.indexOf('$$;',sql.indexOf('$$',start)+2)).trim();
  const row=(await pool.query(`SELECT p.prosrc,p.prosecdef,p.proconfig,r.rolname AS owner,has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime,EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=$1::regprocedure`,[`secureshop_agents.${name}()`])).rows[0];
  if(row?.prosrc.trim()!==body||!row.prosecdef||JSON.stringify(row.proconfig)!==JSON.stringify(['search_path=pg_catalog'])||row.owner!=='dvaia_secureshop_agents_migration'||row.runtime||row.public)throw fail();
 }
 if(requiredVersion===2){
  const candidate=path.join(__dirname,'../../../docs/modernization/drafts/secureshop-bound-analytics/0034_analytics_mode_admission.sql'),canonical=path.join(__dirname,'../../../db/postgres/workshop-migrations/secureshop_agents/0034_analytics_mode_admission.sql'),modeSQL=fs.readFileSync(fs.existsSync(canonical)?canonical:candidate,'utf8');
  const shape=constraints.filter(c=>c.contype==='c'&&c.conname==='analytics_admission_mode_shape');
  const normalMode=value=>normalized(value.replace(/::(?:jsonb|integer)/g,'').replace(/IN \('vuln','fixed'\)/g,"=ANYARRAY['vuln','fixed']").replace(/BETWEEN 1 AND 128/g,'>=1 AND octet_length(mode_snapshot->>\'modeStamp\')<=128'));
  const expectedShape=modeSQL.slice(modeSQL.indexOf('CHECK(')+6,modeSQL.indexOf('));')+1);
  if(shape.length!==1||normalMode(shape[0].expression)!==normalMode(expectedShape))throw fail();
  const guard=(await pool.query("SELECT t.tgenabled,t.tgtype,p.prosrc,p.prosecdef,p.proconfig,has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime,EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=$1::regclass AND t.tgname='analytics_mode_admission_guard' AND p.oid='secureshop_agents.guard_analytics_mode_admission()'::regprocedure",[TABLE])).rows;
  const body=modeSQL.slice(modeSQL.indexOf('$$')+2,modeSQL.indexOf('$$;')).trim();
  if(guard.length!==1||!['O','A'].includes(guard[0].tgenabled)||guard[0].tgtype!==7||guard[0].prosrc.trim()!==body||guard[0].prosecdef||JSON.stringify(guard[0].proconfig)!==JSON.stringify(['search_path=pg_catalog'])||guard[0].runtime||guard[0].public)throw fail();
 }
 const publicGrant=(await pool.query(`SELECT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=$1::regclass AND a.grantee=0) AS allowed`,[TABLE])).rows[0]?.allowed;if(publicGrant!==false)throw fail();
 return Object.freeze({ready:true});
}
module.exports={assertAnalyticsRequestReadiness};
