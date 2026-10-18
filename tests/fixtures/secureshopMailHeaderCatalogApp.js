'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const key='secureshop_agent_security',id='ss_mail_header_construction';
async function prepareMailHeaderCatalog({identity,migration,users,config,user,sibling,passwordHash,launches,siblingBinding,jwtSecret}){
 assert.equal(require('../../server/config/secureshopCurriculum').isQualifiedObjective(id),true);
 const initial=(await identity.query('SELECT is_enabled,label,hint_content,solution_content FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[key,id])).rows[0];assert.equal(initial.is_enabled,false);assert.ok(initial.hint_content&&initial.solution_content);
 const admin=await users.createUser({username:'mail-header-admin-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash});await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);for(const permission of ['user_management','challenge_management','system_config','manage_progress','system_logs','view_analytics'])await users.grantPermission({userId:admin.id,permission,grantedBy:admin.id});
 await config.setObjectiveVisibility(key,id,true);await config.setMasterHintVisibility(key,true);await config.setMasterSolutionVisibility(key,true);await config.setObjectiveHintVisibility(key,id,true);await config.setObjectiveSolutionVisibility(key,id,true);
 const hint={...initial.hint_content,title:'Instructor header hint',hints:['Compare an original field newline with the stored raw header; storage does not prove delivery.']};await config.updateHintContent(key,id,hint);
 const snapshot=async()=>(await identity.query('SELECT objective_id,label,hint_content,solution_content,is_enabled FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[key])).rows;
 const customized=await snapshot();await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),customized);
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 // Display setup is administrative fixture data, never a Judge contribution.
 const scopeOf=require('../../server/services/secureshopConversationBinding').createLaunchScope;
 async function seedOne(binding){const scope=scopeOf(binding);await launches.assertCurrent(scope);const inserted=await migration.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
 SELECT s.user_id,$6,$7 FROM identity.secureshop_launches l JOIN identity.user_sessions s ON s.id=l.platform_session_id
 WHERE l.launch_id=$1 AND l.platform_session_id=$2 AND s.user_id=$3 AND l.scenario_id=$4 AND l.generation=$5
 AND l.status='active' AND l.expires_at>clock_timestamp() AND s.is_active=1 AND s.expires_at>clock_timestamp()
 RETURNING user_id`,[scope.launchId,scope.platformSessionId,scope.platformOwnerId,scope.scenarioId,scope.generation,key,id]);assert.equal(inserted.rowCount,1);await launches.assertCurrent(scope);return scope;}
 let seeded=false;
 return{admin,label:initial.label,async seedDisplay({token,launch}){
  assert.equal(seeded,false);const binding=await resolveBrowserBinding({token,launch,userId:user.id,jwtSecret,users,launches});
  const scope=await seedOne(binding);assert.equal(siblingBinding.platformOwnerId,sibling.id);await seedOne(siblingBinding);
  await progress.recordHeartbeat({userId:user.id,workshopKey:key,instanceScope:scope});await new Promise(r=>setTimeout(r,1200));await progress.recordHeartbeat({userId:user.id,workshopKey:key,instanceScope:scope});
  const projection=await progress.getWorkshopProgress(user.id,key);assert.equal(projection.completedObjectiveCount,1);assert.equal(projection.objectiveCount,1);assert.ok(projection.timeSpentSeconds>0);seeded=true;return {...projection,displayScope:scope};
 },async verifyReset(){assert.equal(seeded,true);assert.equal((await progress.getWorkshopProgress(user.id,key)).completedObjectiveCount,0);assert.equal((await progress.getWorkshopProgress(sibling.id,key)).completedObjectiveCount,1);assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::integer[])',[[user.id,sibling.id]])).rows[0].n,0);}};

}
async function resolveBrowserBinding({token,launch,userId,jwtSecret,users,launches}){
 const decoded=require('jsonwebtoken').verify(token,jwtSecret,{algorithms:['HS256']});assert.equal(decoded.userId,userId);
 const session=await users.findActiveSession(token,userId);assert.ok(session);assert.equal(Number(session.user.id),userId);assert.equal(Number(session.session.user_id),userId);
 const binding=await launches.readActiveMetadata({platformOwnerId:userId,platformSessionId:Number(session.session.id)});assert.ok(binding);
 assert.equal(binding.platformOwnerId,userId);assert.equal(binding.platformSessionId,Number(session.session.id));
 for(const field of ['launchId','generation','credentialVersion'])assert.equal(binding[field],launch[field]);assert.equal(new Date(binding.expiresAt).toISOString(),new Date(launch.expiresAt).toISOString());
 await launches.assertCurrent(require('../../server/services/secureshopConversationBinding').createLaunchScope(binding));return binding;
}
module.exports={prepareMailHeaderCatalog,resolveBrowserBinding};
