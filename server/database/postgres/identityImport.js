'use strict';
const {withTransaction}=require('./index');
const v=require('./identityValidation');
const USER_COLUMNS=['id','username','email','password','role','admin_level','full_name','phone','department','profile_image','email_verified','is_active','account_locked_until','login_attempts','last_login','last_password_change','password_reset_required','two_factor_enabled','two_factor_secret','created_at','updated_at','created_by_ip','last_login_ip'];
const PERMISSION_COLUMNS=['id','admin_id','permission_name','granted_by','granted_at','expires_at','is_active'];
const SESSION_COLUMNS=['id','user_id','session_token_hash','device_info','ip_address','location','is_active','last_activity','expires_at','created_at','revoked_at','revoked_by','revoke_reason'];
const AUDIT_COLUMNS=['id','user_id','action_type','action_details','ip_address','user_agent','session_id','risk_level','success','timestamp'];
function allowed(row,fields) {if(!row||typeof row!=='object'||Array.isArray(row)||Object.keys(row).some(key=>!fields.includes(key)))throw new Error('Unexpected identity import fields');}
function optionalText(value,max=1000) {if(value==null)return null;if(typeof value!=='string'||value.length>max)throw new Error('Invalid identity import text');return value;}
function integer(value,fallback=0) {value??=fallback;if(!Number.isInteger(value)||value<0||value>2147483647)throw new Error('Invalid identity import integer');return value;}
function json(value) {if(value==null)return {};if(typeof value==='string'){try{return JSON.parse(value);}catch{throw new Error('Invalid identity import JSON');}}return value;}
function validateIdentityImport(input) {
  allowed(input,['users','permissions','sessions','audit']);
  const result={};
  for(const table of ['users','permissions','sessions','audit']) {
    if(!Array.isArray(input[table]||[]))throw new Error('Identity import collections must be arrays');
    result[table]=[];
    const seen=new Set();
    for(const row of input[table]||[]) {
      v.id(row.id);if(seen.has(row.id))throw new Error('Duplicate identity import ID');seen.add(row.id);
      if(table==='users') {
        allowed(row,USER_COLUMNS);
        const created=v.timestamp(row.created_at,false);
        const user={...row,id:v.id(row.id),username:v.text(row.username,'username',50),email:v.text(row.email,'email',320),password:v.hash(row.password),role:row.role||'student',admin_level:integer(row.admin_level),login_attempts:integer(row.login_attempts),created_at:created,updated_at:v.timestamp(row.updated_at??created,false),last_password_change:v.timestamp(row.last_password_change??created,false)};
        if(user.username.length<3||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email)||!['student','admin','super_admin'].includes(user.role)||user.admin_level>2)throw new Error('Invalid identity user DTO');
        for(const [field,def] of [['email_verified',0],['is_active',1],['password_reset_required',0],['two_factor_enabled',0]])user[field]=v.flag(row[field],def);
        for(const field of ['last_login','account_locked_until'])user[field]=v.timestamp(row[field]);
        for(const field of ['full_name','phone','department','profile_image','two_factor_secret','created_by_ip','last_login_ip'])user[field]=optionalText(row[field]);
        result.users.push(user);
      } else if(table==='permissions') {
        allowed(row,PERMISSION_COLUMNS);
        if(!v.PERMISSIONS.has(row.permission_name))throw new Error('Unknown imported permission');
        result.permissions.push({...row,id:v.id(row.id),admin_id:v.id(row.admin_id),granted_by:row.granted_by==null?null:v.id(row.granted_by),granted_at:v.timestamp(row.granted_at,false),expires_at:v.timestamp(row.expires_at),is_active:v.flag(row.is_active,1)});
      } else if(table==='sessions') {
        allowed(row,[...SESSION_COLUMNS.filter(name=>name!=='session_token_hash'),'session_token']);
        result.sessions.push({id:v.id(row.id),user_id:v.id(row.user_id),session_token_hash:v.tokenHash(row.session_token),device_info:v.deviceInfo(row.device_info),ip_address:optionalText(row.ip_address),location:optionalText(row.location),is_active:v.flag(row.is_active,1),last_activity:v.timestamp(row.last_activity??row.created_at,false),expires_at:v.timestamp(row.expires_at,false),created_at:v.timestamp(row.created_at,false),revoked_at:v.timestamp(row.revoked_at),revoked_by:row.revoked_by==null?null:v.id(row.revoked_by),revoke_reason:optionalText(row.revoke_reason)});
      } else {
        allowed(row,[...AUDIT_COLUMNS,'error_message']);
        const action=v.text(row.action_type,'audit action',100);
        if(!/^[a-z][a-z0-9_:.]*$/.test(action))throw new Error('Invalid imported audit action');
        const risk=row.risk_level||'low';if(!['low','medium','high','critical'].includes(risk))throw new Error('Invalid imported audit risk');
        result.audit.push({id:v.id(row.id),user_id:row.user_id==null?null:v.id(row.user_id),action_type:action,action_details:v.auditDetails(json(row.action_details)),ip_address:optionalText(row.ip_address),user_agent:optionalText(row.user_agent),session_id:optionalText(row.session_id),risk_level:risk,success:v.flag(row.success,1),timestamp:v.timestamp(row.timestamp,false)});
      }
    }
  }
  const users=new Set(result.users.map(row=>row.id));
  for(const row of result.permissions)for(const id of [row.admin_id,row.granted_by])if(id!=null&&!users.has(id))throw new Error('Imported permission references a missing user');
  for(const row of result.sessions)for(const id of [row.user_id,row.revoked_by])if(id!=null&&!users.has(id))throw new Error('Imported session references a missing user');
  for(const row of result.audit)if(row.user_id!=null&&!users.has(row.user_id))throw new Error('Imported audit references a missing user');
  return result;
}
const IMPORT_TABLES = [
  ['users', 'users', USER_COLUMNS],
  ['permissions', 'admin_permissions', PERMISSION_COLUMNS],
  ['sessions', 'user_sessions', SESSION_COLUMNS],
  ['audit', 'activity_logs', AUDIT_COLUMNS],
];
function importCounts(data) {
  return Object.fromEntries(IMPORT_TABLES.map(([key]) => [key, data[key].length]));
}

/** Caller owns BEGIN/COMMIT/ROLLBACK. Allows identities and platform state to commit together. */
async function importIdentityInTransaction(client, input) {
  const data = validateIdentityImport(input);
  const nextIds = Object.fromEntries(IMPORT_TABLES.map(([key]) => {
    const next = data[key].reduce((value, row) => Math.max(value, row.id + 1), 1);
    if (next > 2147483647) throw new Error('Imported identity ID exhausts destination sequence');
    return [key, next];
  }));
  await client.query('SELECT pg_advisory_xact_lock(1886610804,3)');
  await client.query('LOCK TABLE identity.users,identity.admin_permissions,identity.user_sessions,identity.activity_logs IN ACCESS EXCLUSIVE MODE');
  for (const [, table] of IMPORT_TABLES) {
    if ((await client.query(`SELECT 1 FROM identity.${table} LIMIT 1`)).rowCount) {
      throw new Error('Identity import destination must be empty');
    }
  }
  // Identifiers come only from fixed contracts, never archive column names.
  for (const [key, table, columns] of IMPORT_TABLES) {
    for (const row of data[key]) {
      const values = columns.map(column => ['device_info', 'action_details'].includes(column)
        ? JSON.stringify(row[column]) : row[column]);
      await client.query(`INSERT INTO identity.${table} (${columns.join(',')}) VALUES (${columns.map((_, i) => '$' + (i + 1)).join(',')})`, values);
    }
    // Unlike setval(), identity RESTART rolls back if a later table fails.
    await client.query(`ALTER TABLE identity.${table} ALTER COLUMN id RESTART WITH ${nextIds[key]}`);
  }
  return importCounts(data);
}

async function importIdentity(migrationPool, input, { dryRun = true } = {}) {
  const data = validateIdentityImport(input);
  if (!migrationPool) {
    if (!dryRun) throw new Error('Identity import requires a migration database connection');
    return { ...importCounts(data), dryRun: true, validationOnly: true };
  }
  return withTransaction(migrationPool, async client => {
    if (dryRun) await client.query('SAVEPOINT identity_import_dry_run');
    const counts = await importIdentityInTransaction(client, input);
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
    if (dryRun) await client.query('ROLLBACK TO SAVEPOINT identity_import_dry_run');
    return { ...counts, dryRun, validationOnly: false };
  });
}
module.exports = { validateIdentityImport, importIdentity, importIdentityInTransaction };
