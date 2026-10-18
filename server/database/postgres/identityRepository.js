'use strict';
const path=require('node:path');
const {withTransaction,verifyServer}=require('./index');
const {migrate}=require('../../../db/postgres/migrate');
const v=require('./identityValidation');
const PUBLIC_USER='id,username,email,role,admin_level,full_name,phone,department,profile_image,email_verified,is_active,account_locked_until,login_attempts,last_login,last_password_change,password_reset_required,two_factor_enabled,created_at,updated_at';
const ACTIVE_USER="is_active=1 AND (account_locked_until IS NULL OR account_locked_until<=clock_timestamp())";
async function initializeIdentityRepository(runtimePool,migrationPool) {
  await verifyServer(runtimePool);
  const runtime=(await runtimePool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  const migration=(await migrationPool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  if(runtime.role!=='dvaia_identity_runtime'||runtime.role===migration.role||runtime.database!==migration.database)throw new Error('Identity requires a dedicated runtime role and separate migration role on the same database');
  return migrate(migrationPool,path.join(__dirname,'../../../db/postgres/identity-migrations'));
}
function createIdentityRepository(pool) {
  const get=async(sql,params=[])=>(await pool.query(sql,params)).rows[0]||null;
  const lockUser=async(client,userId)=>(await client.query('SELECT * FROM identity.users WHERE id=$1 FOR UPDATE',[v.id(userId)])).rows[0];
  const audit=async(client,event)=>{
    const action=v.text(event.actionType,'audit action',100);
    if(!/^[a-z][a-z0-9_:.]*$/.test(action))throw new Error('Audit action must be a stable event name');
    const details=v.auditDetails(event.details);
    const result=await client.query('INSERT INTO identity.activity_logs (user_id,action_type,action_details,ip_address,user_agent,session_id,risk_level,success) VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8) RETURNING id',[
      event.userId==null?null:v.id(event.userId),action,JSON.stringify(details),event.ipAddress||null,event.userAgent||null,event.sessionId||null,event.riskLevel||'low',v.flag(event.success,1),
    ]);
    return result.rows[0];
  };
  return {
    // Credentials are exposed only by this deliberately named method for bcrypt verification.
    findCredentialByUsername:username=>get('SELECT id,username,password,role,admin_level,is_active,account_locked_until,email_verified FROM identity.users WHERE username=$1',[v.text(username,'username',50)]),
    findCredentialById:userId=>get('SELECT id,username,password,role,admin_level,is_active,account_locked_until,email_verified FROM identity.users WHERE id=$1',[v.id(userId)]),
    findUserByEmail:email=>get(`SELECT ${PUBLIC_USER} FROM identity.users WHERE email=$1`,[v.text(email,'email',320)]),
    getConfig:async key=>(await get('SELECT config_value FROM identity.system_config WHERE config_key=$1',[key]))?.config_value,
    getPublicConfig:async()=>(await pool.query('SELECT config_key,config_value,config_type FROM identity.system_config WHERE is_public=true')).rows,
    async updateProfile(userId,email,fullName){
      const id=v.id(userId),address=v.text(email,'email',320);
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,id);if(!user)return null;
        const changed=user.email!==address;
        if(changed)await client.query('UPDATE identity.email_verification_tokens SET used=true WHERE user_id=$1',[id]);
        return (await client.query('UPDATE identity.users SET email=$1,full_name=$2,email_verified=CASE WHEN $4 THEN 0 ELSE email_verified END,updated_at=now() WHERE id=$3 RETURNING id,username,email,full_name',[address,fullName,id,changed])).rows[0]||null;
      });
    },
    async registerUser({username,email,passwordHash,fullName=null,department=null,phone=null,ipAddress=null,verificationToken}){
      v.text(username,'username',50);v.text(email,'email',320);v.hash(passwordHash);
      return withTransaction(pool,async client=>{
        const user=(await client.query(`INSERT INTO identity.users(username,email,password,full_name,department,phone,created_by_ip) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING ${PUBLIC_USER}`,[username,email,passwordHash,fullName,department,phone,ipAddress])).rows[0];
        if(verificationToken!==undefined)await client.query("INSERT INTO identity.email_verification_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '24 hours')",[user.id,v.tokenHash(verificationToken)]);
        await audit(client,{userId:user.id,actionType:'user_registration',ipAddress,details:{}});
        return user;
      });
    },
    async issueVerificationToken(userId,token){
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,userId);if(!user||user.email_verified)return false;
        await client.query('UPDATE identity.email_verification_tokens SET used=true WHERE user_id=$1',[userId]);
        await client.query("INSERT INTO identity.email_verification_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '24 hours')",[userId,v.tokenHash(token)]);return true;
      });
    },
    async verifyEmail(token){
      return withTransaction(pool,async client=>{
        const pending=(await client.query('SELECT user_id FROM identity.email_verification_tokens WHERE token_hash=$1',[v.tokenHash(token)])).rows[0];if(!pending)return null;
        await lockUser(client,pending.user_id);
        const used=await client.query('UPDATE identity.email_verification_tokens SET used=true WHERE token_hash=$1 AND used=false AND expires_at>clock_timestamp() RETURNING user_id',[v.tokenHash(token)]);if(!used.rowCount)return null;
        return (await client.query('UPDATE identity.users SET email_verified=1,updated_at=now() WHERE id=$1 RETURNING id,username,email',[pending.user_id])).rows[0];
      });
    },
    getUserById:userId=>get(`SELECT ${PUBLIC_USER} FROM identity.users WHERE id=$1`,[v.id(userId)]),
    async createUser({username,email,passwordHash,fullName=null}) {
      v.text(username,'username',50);v.text(email,'email',320);v.hash(passwordHash);
      const result=await pool.query(`INSERT INTO identity.users (username,email,password,full_name) VALUES ($1,$2,$3,$4) RETURNING ${PUBLIC_USER}`,[username,email,passwordHash,fullName]);
      return result.rows[0];
    },
    async getUserPermissions(userId) {
      const result=await pool.query(`SELECT p.permission_name FROM identity.admin_permissions p JOIN identity.users u ON u.id=p.admin_id
        WHERE p.admin_id=$1 AND p.is_active=1 AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())
        AND u.role IN ('admin','super_admin') AND u.admin_level>=1 AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) ORDER BY p.permission_name`,[v.id(userId)]);
      return result.rows.map(row=>row.permission_name);
    },
    async hasPermission(userId,permission) {
      if(!v.PERMISSIONS.has(permission))return false;
      return Boolean(await get(`SELECT 1 FROM identity.admin_permissions p JOIN identity.users u ON u.id=p.admin_id WHERE p.admin_id=$1 AND p.permission_name=$2 AND p.is_active=1 AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) AND u.role IN ('admin','super_admin') AND u.admin_level>=1 AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())`,[v.id(userId),permission]));
    },
    async grantPermission({userId,permission,grantedBy,expiresAt=null}) {
      if(!v.PERMISSIONS.has(permission))throw new Error('Unknown identity permission');
      // Authorization for this administrative operation belongs to its caller.
      return (await pool.query('INSERT INTO identity.admin_permissions (admin_id,permission_name,granted_by,expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT (admin_id,permission_name) DO UPDATE SET granted_by=EXCLUDED.granted_by,expires_at=EXCLUDED.expires_at,is_active=1,granted_at=now() RETURNING id',[v.id(userId),permission,grantedBy==null?null:v.id(grantedBy),v.timestamp(expiresAt)])).rows[0];
    },
    async revokePermission(userId,permission) {return (await pool.query('UPDATE identity.admin_permissions SET is_active=0 WHERE admin_id=$1 AND permission_name=$2',[v.id(userId),permission])).rowCount;},
    async createSession({userId,token,expiresAt,expectedPasswordHash,deviceInfo,ipAddress=null,location=null}) {
      const digest=v.tokenHash(token),expiry=v.timestamp(expiresAt,false);v.hash(expectedPasswordHash);
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,userId);
        if(!user||user.password!==expectedPasswordHash)throw new Error('Credentials changed before session issuance');
        const valid=(await client.query(`SELECT id FROM identity.users WHERE id=$1 AND ${ACTIVE_USER} AND $2::timestamptz>clock_timestamp()`,[userId,expiry])).rowCount;
        if(!valid)throw new Error('Account unavailable or session already expired');
        const session=(await client.query('INSERT INTO identity.user_sessions (user_id,session_token_hash,device_info,ip_address,location,expires_at) VALUES ($1,$2,$3::jsonb,$4,$5,$6) RETURNING id,user_id,expires_at,created_at,last_activity',[userId,digest,JSON.stringify(v.deviceInfo(deviceInfo)),ipAddress,location,expiry])).rows[0];
        await client.query('UPDATE identity.users SET login_attempts=0,account_locked_until=NULL,last_login=now(),last_login_ip=$1 WHERE id=$2',[ipAddress,userId]);
        await client.query('DELETE FROM identity.user_sessions WHERE user_id=$1 AND id NOT IN (SELECT id FROM identity.user_sessions WHERE user_id=$1 AND is_active=1 AND expires_at>clock_timestamp() ORDER BY id DESC LIMIT 5)',[userId]);
        return session;
      });
    },
    async findActiveSession(token,userId) {
      // The caller verifies JWT signature/claims first, then binds decoded owner here.
      const result=await pool.query(`SELECT row_to_json(u) AS user,row_to_json(s) AS session FROM
        (SELECT ${PUBLIC_USER} FROM identity.users WHERE id=$1 AND ${ACTIVE_USER}) u
        JOIN (SELECT id,user_id,device_info,ip_address,location,expires_at,created_at,last_activity FROM identity.user_sessions
          WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1 AND expires_at>clock_timestamp()) s ON s.user_id=u.id`,[v.id(userId),v.tokenHash(token)]);
      return result.rows[0]||null;
    },
    async touchSession(token,userId) {return (await pool.query('UPDATE identity.user_sessions SET last_activity=clock_timestamp() WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1 AND expires_at>clock_timestamp()',[v.id(userId),v.tokenHash(token)])).rowCount;},
    async revokeSession(token,userId,reason='logout') {
      return (await pool.query('UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason=$3 WHERE session_token_hash=$1 AND user_id=$2 AND is_active=1',[v.tokenHash(token),v.id(userId),v.text(reason,'revocation reason',200)])).rowCount;
    },
    async revokeAllUserSessions(userId,reason='account_change') {
      return withTransaction(pool,async client=>{
        await lockUser(client,userId);
        return (await client.query('UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason=$2 WHERE user_id=$1 AND is_active=1',[userId,v.text(reason,'revocation reason',200)])).rowCount;
      });
    },
    async rotatePasswordAndRevoke(userId,expectedPasswordHash,newPasswordHash) {
      v.id(userId);v.hash(expectedPasswordHash);v.hash(newPasswordHash);
      if(expectedPasswordHash===newPasswordHash)throw new Error('New password hash must differ');
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,userId);
        const deleting=user&&(await client.query(
          'SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[userId])).rowCount;
        if(!user||user.password!==expectedPasswordHash||deleting)throw new Error('Password changed concurrently or user missing');
        const updated=await client.query('UPDATE identity.users SET password=$1,last_password_change=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$2 AND password=$3 RETURNING id',[newPasswordHash,userId,expectedPasswordHash]);
        if(updated.rowCount!==1)throw new Error('Password changed concurrently or user missing');
        const revoked=await client.query("UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason='password_change' WHERE user_id=$1 AND is_active=1",[userId]);
        await audit(client,{userId,actionType:'password_changed',details:{},success:1});
        return {userId,sessionsRevoked:revoked.rowCount};
      });
    },
    async rotateStudentPasswordAndRevoke(userId,newPasswordHash) {
      v.id(userId);v.hash(newPasswordHash);
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,userId);
        if(!user || user.role!=='student' || user.admin_level!==0)return null;
        if((await client.query('SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[userId])).rowCount)return null;
        await client.query('UPDATE identity.users SET password=$1,last_password_change=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$2',[newPasswordHash,userId]);
        const revoked=await client.query("UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason='password_change' WHERE user_id=$1 AND is_active=1",[userId]);
        await audit(client,{userId,actionType:'password_changed',details:{administrative:true},success:1});
        return {userId,sessionsRevoked:revoked.rowCount};
      });
    },
    async recoverAccount(username,newPasswordHash) {
      const exactUsername=v.text(username,'username',50);v.hash(newPasswordHash);
      return withTransaction(pool,async client=>{
        const user=(await client.query(
          'SELECT id FROM identity.users WHERE username=$1 FOR UPDATE',[exactUsername])).rows[0];
        if(!user)throw Object.assign(new Error('Identity account unavailable'),{code:'IDENTITY_ACCOUNT_UNAVAILABLE'});
        await client.query(`UPDATE identity.users SET password=$1,login_attempts=0,
          account_locked_until=NULL,last_password_change=clock_timestamp(),updated_at=clock_timestamp()
          WHERE id=$2`,[newPasswordHash,user.id]);
        const revoked=await client.query(`UPDATE identity.user_sessions SET is_active=0,
          revoked_at=clock_timestamp(),revoke_reason='administrative_recovery'
          WHERE user_id=$1 AND is_active=1`,[user.id]);
        await audit(client,{userId:user.id,actionType:'administrative_account_recovery',details:{},success:1});
        return {userId:user.id,sessionsRevoked:revoked.rowCount};
      });
    },
    async recordFailedLogin(userId) {
      return withTransaction(pool,async client=>{
        const user=await lockUser(client,userId);if(!user)return null;
        const result=await client.query(`UPDATE identity.users SET
          login_attempts=CASE WHEN account_locked_until>clock_timestamp() THEN login_attempts WHEN account_locked_until IS NOT NULL THEN 1 ELSE login_attempts+1 END,
          account_locked_until=CASE WHEN account_locked_until>clock_timestamp() THEN account_locked_until
            WHEN (CASE WHEN account_locked_until IS NOT NULL THEN 1 ELSE login_attempts+1 END)>=5 THEN clock_timestamp()+interval '30 minutes' ELSE NULL END
          WHERE id=$1 RETURNING login_attempts,account_locked_until`,[userId]);
        return result.rows[0];
      });
    },
    async checkAccountLockout(userId) {
      const row=await get('SELECT account_locked_until,login_attempts,(account_locked_until>clock_timestamp()) AS locked FROM identity.users WHERE id=$1',[v.id(userId)]);
      return row?{locked:row.locked===true,lockedUntil:row.account_locked_until,attempts:row.login_attempts}:{locked:false};
    },
    async revokeAllActiveSessions(reason='administrative_reset'){return (await pool.query('UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason=$1 WHERE is_active=1',[v.text(reason,'revocation reason',200)])).rowCount;},
    async pruneUserSessions(userId){return (await pool.query('DELETE FROM identity.user_sessions WHERE user_id=$1 AND id NOT IN (SELECT id FROM identity.user_sessions WHERE user_id=$1 AND is_active=1 AND expires_at>clock_timestamp() ORDER BY id DESC LIMIT 5)',[v.id(userId)])).rowCount;},
    async cleanupExpiredSessions() {return (await pool.query('DELETE FROM identity.user_sessions WHERE expires_at<=clock_timestamp() OR is_active=0')).rowCount;},
    async listActiveSessions(userId) {return (await pool.query('SELECT id,device_info,ip_address,location,created_at,last_activity,expires_at FROM identity.user_sessions WHERE user_id=$1 AND is_active=1 AND expires_at>clock_timestamp() ORDER BY last_activity DESC,id DESC',[v.id(userId)])).rows;},
    recordAudit:event=>audit(pool,event),
  };
}
module.exports={createIdentityRepository,initializeIdentityRepository};
