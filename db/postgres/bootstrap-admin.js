'use strict';
const BOOTSTRAP_PERMISSIONS=Object.freeze(['user_management','challenge_management','system_config','view_analytics','manage_progress','send_notifications','export_data','system_logs']);
async function ensurePermissions(client,id){
 await client.query('INSERT INTO identity.admin_permissions(admin_id,permission_name,granted_by) SELECT $1,permission,$1 FROM unnest($2::text[]) AS permission ON CONFLICT(admin_id,permission_name) DO NOTHING',[id,BOOTSTRAP_PERMISSIONS]);
}
async function bootstrapAdmin({pool,username,email,password,initialTrainingProfile=false}){
 const trainingCredential=initialTrainingProfile===true&&username==='admin'&&email==='admin@owasp-ai-goat.local'&&password==='admin123';
 if(typeof initialTrainingProfile!=='boolean'||typeof username!=='string'||username.length<3||username.length>50||typeof email!=='string'||!email.includes('@')||typeof password!=='string'||(!trainingCredential&&password.length<12)||Buffer.byteLength(password)>72)throw new Error('Explicit valid administrator username, email and 12–72 byte password required (fresh training profile permits its exact default)');
 return require('../../server/database/postgres').withTransaction(pool,async client=>{
  await client.query('LOCK TABLE identity.users IN SHARE ROW EXCLUSIVE MODE');
  const count=(await client.query('SELECT count(*)::integer AS count FROM identity.users')).rows[0].count;
  if(count){
   const existing=(await client.query('SELECT id,username,email,role,admin_level,password,is_active FROM identity.users WHERE username=$1',[username])).rows[0];
   if(!existing||existing.email!==email||existing.role!=='super_admin'||existing.admin_level!==2||existing.is_active!==1||!await require('bcryptjs').compare(password,existing.password))throw new Error('BOOTSTRAP_ADMIN_CREDENTIAL_MISMATCH');
   await ensurePermissions(client,existing.id);
   return{status:'already_created',created:false,user:{id:existing.id,username:existing.username,email:existing.email,role:existing.role}};
  }
  const hash=await require('bcryptjs').hash(password,12);
  const user=(await client.query("INSERT INTO identity.users(username,email,password,role,admin_level,email_verified,is_active) VALUES($1,$2,$3,'super_admin',2,1,1) RETURNING id,username,email,role",[username,email,hash])).rows[0];
  await ensurePermissions(client,user.id);
  // This opt-in is used only by fresh setup. Never backfill or reset an account
  // once the locked identity store contains users, including on setup retries.
  if(initialTrainingProfile){
   const studentHash=await require('bcryptjs').hash('student 123',12);
   const student=(await client.query("INSERT INTO identity.users(username,email,password,role,admin_level,email_verified,is_active) VALUES($1,$2,$3,'student',0,1,1) RETURNING id,username,email,role",['student','student@owasp-ai-goat.local',studentHash])).rows[0];
   return{status:'created',created:true,user,student};
  }
  return{status:'created',created:true,user};
 });
}
module.exports={bootstrapAdmin,BOOTSTRAP_PERMISSIONS};
